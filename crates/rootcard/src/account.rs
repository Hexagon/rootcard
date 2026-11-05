//! High-level flows built from the parts (feature `vault`): registration ([CLT-1]), new instances ([KT-3], [KT-4],
//! [KT-8]) and recovery-key rotation ([KT-5]). Every random draw comes from the `random` callback, in the documented
//! order.

use crate::encoding::base64url_encode;
use crate::error::{Error, Result};
use crate::id::inception;
use crate::json::{Map, Value};
use crate::log::{
    Home, LogState, Reason, VerifyOptions, event_hash, pending_instance, rotate_recovery_event, verify_log,
};
use crate::profile::sign_public;
use crate::recovery::{RecoveryKeys, check_new_recovery_key, derive_recovery_keys};
use crate::vault::{Contents, InstanceVault, NewSlot, Random, Unlocked, carried_locks, check_password, instance_vault};
use zeroize::Zeroizing;

/// What a registration submits to the host ([HST-3]), plus the recovery card for the user.
pub struct Registration {
    /// `[inception, pending instance]`.
    pub log: Vec<Value>,
    /// The vault.
    pub vault: Value,
    /// The empty public profile (`rev` 1).
    pub public: Value,
    /// The recovery card ([CRD-1]).
    pub card: Value,
    /// The account id.
    pub account: String,
}

/// The account seed of a new instance: 32 random bytes, drawn again while unusable ([CRY-9]). → `bad_key` only for a
/// broken generator ([`crate::crypto::DRAW_ATTEMPTS`]).
fn draw_account_seed(random: Random<'_>) -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    for _ in 0..crate::crypto::DRAW_ATTEMPTS {
        random(seed.as_mut());
        if crate::crypto::usable_seed(&seed) {
            return Ok(seed);
        }
    }
    Err(crate::Error::BadKey)
}

/// Build a registration ([CLT-1]) from a recovery key the caller generated ([RK-3], usable by [CRY-9], see
/// [`crate::recovery::new_recovery_key`]). Draws: the account seed (32, again while unusable, [CRY-9]), then
/// [`instance_vault`] with one new slot. → `bad_realm`, `bad_username`, `weak_password`, `kdf_params`, `bad_field`,
/// `bad_key`
#[allow(clippy::too_many_arguments)]
pub fn register(
    recovery_key: &[u8; 32],
    realm: &str,
    username: &str,
    password: &str,
    label: &str,
    home: &Home,
    time: i64,
    kdf: crate::vault::Kdf,
    random: Random<'_>,
) -> Result<Registration> {
    check_password(password, username)?;
    let keys = derive_recovery_keys(recovery_key, realm, username);
    check_new_recovery_key(&keys)?;
    let inc = inception(&keys, realm, username)?;
    let state = verify_log(&[Value::Object(inc.clone())], &VerifyOptions::new([realm]))?;
    let seed = draw_account_seed(random)?;
    let pending = pending_instance(&state, &keys.sign_seed, &seed, home, Reason::Register, time)?;
    let instance = base64url_encode(&event_hash(&pending));
    let vault = instance_vault(
        InstanceVault {
            account: &state.account,
            instance: &instance,
            recovery: &keys,
            contents: Contents {
                account_seed: seed.clone(),
                data: Map::new(),
                known: None,
            },
            keep: Vec::new(),
            add: Some(NewSlot {
                label,
                password,
                username,
                kdf,
            }),
        },
        random,
    )?;
    let public = sign_public(&state.account, &instance, 1, &Map::new(), &seed)?;
    let card = crate::file::recovery_card(realm, username, &state.account, recovery_key, None);
    Ok(Registration {
        log: vec![Value::Object(inc), Value::Object(pending)],
        vault,
        public,
        card,
        account: state.account,
    })
}

/// How a new instance treats the old vault ([KT-3], [KT-4], [KT-8]).
pub enum InstanceMode<'a> {
    /// Carry the data and every password over (`restore`).
    Restore,
    /// Carry the data over without the named slots (`revoke`).
    Revoke(&'a [&'a str]),
    /// Carry the data over with only one new password (`revoke`, [KT-8]).
    Reset(NewSlot<'a>),
    /// Start empty with one new password (`fresh`).
    Fresh(NewSlot<'a>),
}

/// What a new instance submits to its host ([HST-5]).
pub struct NewInstance {
    /// The pending instance.
    pub event: Map,
    /// The vault of the new instance.
    pub vault: Value,
    /// The public profile of the new instance (`rev` 1).
    pub public: Value,
}

/// Build a new instance on top of `state` ([KT-3]). `old` is the current vault unlocked with the recovery lock (needed
/// except for `Fresh`), `old_public` the current profile data to carry over. Draws: the account seed (32, again while
/// unusable, [CRY-9]), then [`instance_vault`]. → `wrong_recovery_key`, `bad_locks`
#[allow(clippy::too_many_arguments)]
pub fn new_instance(
    state: &LogState,
    recovery: &RecoveryKeys,
    old: Option<&Unlocked>,
    old_public: Option<&Map>,
    mode: InstanceMode<'_>,
    home: &Home,
    time: i64,
    random: Random<'_>,
) -> Result<NewInstance> {
    crate::log::check_recovery_key(state, &recovery.sign_seed)?;
    if let InstanceMode::Reset(slot) | InstanceMode::Fresh(slot) = &mode {
        // The new password is checked before anything is drawn ([LCK-8]); its username must be this identity's.
        if slot.username != state.username {
            return Err(crate::Error::BadField);
        }
        check_password(slot.password, &state.username)?;
    }
    let seed = draw_account_seed(random)?;
    let reason = match mode {
        InstanceMode::Restore => Reason::Restore,
        InstanceMode::Revoke(_) | InstanceMode::Reset(_) => Reason::Revoke,
        InstanceMode::Fresh(_) => Reason::Fresh,
    };
    let event = pending_instance(state, &recovery.sign_seed, &seed, home, reason, time)?;
    let instance = base64url_encode(&event_hash(&event));
    let carried = |u: Option<&Unlocked>| -> Result<(Map, Option<Map>)> {
        let u = u.ok_or(Error::BadLocks)?;
        Ok((u.contents.data.clone(), u.contents.known.clone()))
    };
    let (data, known, keep, add, public_data) = match mode {
        InstanceMode::Restore => {
            let (d, k) = carried(old)?;
            (
                d,
                k,
                carried_locks(old.ok_or(Error::BadLocks)?, &[]),
                None,
                old_public.cloned(),
            )
        }
        InstanceMode::Revoke(drop) => {
            let (d, k) = carried(old)?;
            (
                d,
                k,
                carried_locks(old.ok_or(Error::BadLocks)?, drop),
                None,
                old_public.cloned(),
            )
        }
        InstanceMode::Reset(slot) => {
            let (d, k) = carried(old)?;
            (d, k, Vec::new(), Some(slot), old_public.cloned())
        }
        InstanceMode::Fresh(slot) => (Map::new(), None, Vec::new(), Some(slot), None),
    };
    let vault = instance_vault(
        InstanceVault {
            account: &state.account,
            instance: &instance,
            recovery,
            contents: Contents {
                account_seed: seed.clone(),
                data,
                known,
            },
            keep,
            add,
        },
        random,
    )?;
    let public = sign_public(&state.account, &instance, 1, &public_data.unwrap_or_default(), &seed)?;
    Ok(NewInstance { event, vault, public })
}

/// A recovery-key rotation ([KT-5]): the event, the vault with the new grant, and the new card.
pub struct Rotation {
    /// The `rotate_recovery` event.
    pub event: Map,
    /// The vault with the new grant.
    pub vault: Value,
    /// The new recovery card, with the log up to the rotation ([CRD-2]).
    pub card: Value,
}

/// Rotate the recovery key ([KT-5]) to `new_key` (32 random bytes the caller generated, usable by [CRY-9] → `bad_key`). `log` is the current log,
/// `old_vault` the current vault and `unlocked` that vault unlocked. Draws: [`crate::vault::regrant`].
#[allow(clippy::too_many_arguments)]
pub fn rotate_recovery(
    state: &LogState,
    log: &[Value],
    old: &RecoveryKeys,
    new_key: &[u8; 32],
    old_vault: &Value,
    unlocked: &Unlocked,
    time: i64,
    random: Random<'_>,
) -> Result<Rotation> {
    let new = derive_recovery_keys(new_key, &state.realm, &state.username);
    check_new_recovery_key(&new)?;
    let event = rotate_recovery_event(state, &old.sign_seed, &new.sign_seed, time)?;
    let vault = crate::vault::regrant(unlocked, old_vault, &new, random)?;
    let mut full = log.to_vec();
    full.push(Value::Object(event.clone()));
    let card = crate::file::recovery_card(&state.realm, &state.username, &state.account, new_key, Some(&full));
    Ok(Rotation { event, vault, card })
}
