//! The vault (SPEC §11): structure checks and signatures (always), and the vault cryptography (feature `vault`).
//!
//! Functions that need random bytes take a `random` callback that fills a buffer ([IMP-1]). The order in which a
//! function draws is part of its contract, so that the Rust and JavaScript implementations produce identical bytes from
//! the same random stream; it is documented on each function.

use crate::crypto::{ed25519_verify, frame_map};
use crate::encoding::base64url_decode;
use crate::error::{Error, Result};
use crate::json::{Map, Value, canonical_map};
use crate::keys::{KeyType, schema};
use crate::label;
use crate::log::LogState;

/// The maximum canonical size of a vault ([VLT-1]).
pub const VAULT_LIMIT: usize = 96 * 1024;
/// The maximum canonical size of the vault contents ([VLT-7]).
pub const CONTENTS_LIMIT: usize = 64 * 1024;
/// The maximum canonical size of the private data ([DAT-6]).
pub const DATA_LIMIT: usize = 48 * 1024;
/// The maximum number of password slots ([LCK-1]).
pub const MAX_SLOTS: usize = 15;
/// The largest `rev` and `gen` ([VLT-4]).
pub const MAX_REV: i64 = 1 << 32;

/// Argon2id parameters of a password lock ([LCK-6]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kdf {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes (always 1).
    pub p: u32,
}

impl Kdf {
    /// The default for new locks: `m = 65536, t = 3, p = 1` ([LCK-6]).
    pub const DEFAULT: Kdf = Kdf { m: 65536, t: 3, p: 1 };
    /// The smallest parameters allowed (`m = 47104, t = 2`), used by tests and vectors.
    pub const MIN: Kdf = Kdf { m: 47104, t: 2, p: 1 };

    /// [LCK-6]. → `kdf_params`
    pub fn check(&self) -> Result<()> {
        if self.p == 1 && (47104..=1_048_576).contains(&self.m) && (2..=16).contains(&self.t) {
            Ok(())
        } else {
            Err(Error::KdfParams)
        }
    }
}

/// The public parts of a password lock: what a lock carries from instance to instance ([LCK-7]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordLockPublic {
    /// The slot id string (b64u of 8 bytes).
    pub id: String,
    /// The Argon2id parameters.
    pub kdf: Kdf,
    /// The 16-byte salt.
    pub salt: [u8; 16],
    /// The Ed25519 `auth` key.
    pub auth: [u8; 32],
    /// The X25519 `box` key.
    pub box_key: [u8; 32],
}

/// One lock of the list, after its schema check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lock {
    /// A password lock.
    Password(PasswordLockPublic, Wrap),
    /// The recovery lock.
    Recovery {
        /// Its id (must be `recovery`).
        id: String,
        /// The recovery lock key (X25519).
        box_key: [u8; 32],
        /// The wrapped vault key.
        wrap: Wrap,
    },
}

impl Lock {
    /// The lock id.
    pub fn id(&self) -> &str {
        match self {
            Lock::Password(p, _) => &p.id,
            Lock::Recovery { id, .. } => id,
        }
    }
    /// The `box` key.
    pub fn box_key(&self) -> &[u8; 32] {
        match self {
            Lock::Password(p, _) => &p.box_key,
            Lock::Recovery { box_key, .. } => box_key,
        }
    }
    /// The wrap.
    pub fn wrap(&self) -> &Wrap {
        match self {
            Lock::Password(_, w) => w,
            Lock::Recovery { wrap, .. } => wrap,
        }
    }
}

/// A wrapped vault key ([LCK-9]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrap {
    /// The ephemeral X25519 public key.
    pub epk: [u8; 32],
    /// The nonce.
    pub nonce: [u8; 12],
    /// The 48-byte ciphertext.
    pub ct: [u8; 48],
}

/// A password slot of the grant ([LCK-1], [LCK-2]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// The slot id string (b64u of 8 bytes).
    pub id: String,
    /// The label.
    pub label: String,
}

/// A vault after [`verify_vault`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    /// The revision.
    pub rev: i64,
    /// The grant generation.
    pub gen_: i64,
    /// The password slots.
    pub slots: Vec<Slot>,
    /// The locks, in list order.
    pub locks: Vec<Lock>,
}

impl VaultInfo {
    /// The lock with id `id`.
    pub fn lock(&self, id: &str) -> Option<&Lock> {
        self.locks.iter().find(|l| l.id() == id)
    }

    /// The password lock of slot `id`.
    pub fn password_lock(&self, id: &str) -> Option<&PasswordLockPublic> {
        self.locks.iter().find_map(|l| match l {
            Lock::Password(p, _) if p.id == id => Some(p),
            _ => None,
        })
    }

    /// The lock hints ([FET-2]): per slot, its `id`, `label` and `kdf`.
    pub fn hints(&self) -> Value {
        Value::Array(
            self.slots
                .iter()
                .filter_map(|s| {
                    let p = self.password_lock(&s.id)?;
                    Some(
                        Map::new()
                            .with("id", s.id.as_str())
                            .with("label", s.label.as_str())
                            .with("kdf", kdf_value(&p.kdf, &p.salt))
                            .into(),
                    )
                })
                .collect(),
        )
    }
}

pub(crate) fn kdf_value(kdf: &Kdf, salt: &[u8; 16]) -> Value {
    Map::new()
        .with("alg", "argon2id")
        .with("m", kdf.m)
        .with("t", kdf.t)
        .with("p", kdf.p)
        .with("salt", crate::encoding::base64url_encode(salt))
        .into()
}

fn parse_wrap(m: &Map) -> Result<Wrap> {
    schema::members(m, &["epk", "nonce", "ct"], &[])?;
    Ok(Wrap {
        epk: schema::key(m, "epk", KeyType::X25519)?,
        nonce: schema::bytes::<12>(m, "nonce")?,
        ct: schema::bytes::<48>(m, "ct")?,
    })
}

/// The kdf member of a password lock: `alg` and the bounds are checked later ([LCK-6], `kdf_params`).
fn parse_kdf(m: &Map) -> Result<(String, i64, i64, i64, [u8; 16])> {
    schema::members(m, &["alg", "m", "t", "p", "salt"], &[])?;
    Ok((
        schema::string(m, "alg")?.to_string(),
        schema::int(m, "m")?,
        schema::int(m, "t")?,
        schema::int(m, "p")?,
        schema::bytes::<16>(m, "salt")?,
    ))
}

struct ParsedLock {
    lock: Lock,
    kdf: Option<(String, i64, i64, i64)>,
}

fn parse_lock(v: &Value) -> Result<ParsedLock> {
    let m = schema::obj(v)?;
    match schema::string(m, "kind")? {
        "password" => {
            schema::members(m, &["id", "kind", "kdf", "auth", "box", "wrap"], &[])?;
            let id = schema::string(m, "id")?.to_string();
            schema::bytes::<8>(m, "id")?;
            let (alg, mm, t, p, salt) = parse_kdf(schema::object(m, "kdf")?)?;
            let public = PasswordLockPublic {
                id,
                kdf: Kdf {
                    m: u32::try_from(mm).unwrap_or(0),
                    t: u32::try_from(t).unwrap_or(0),
                    p: u32::try_from(p).unwrap_or(0),
                },
                salt,
                auth: schema::key(m, "auth", KeyType::Ed25519)?,
                box_key: schema::key(m, "box", KeyType::X25519)?,
            };
            let wrap = parse_wrap(schema::object(m, "wrap")?)?;
            Ok(ParsedLock {
                lock: Lock::Password(public, wrap),
                kdf: Some((alg, mm, t, p)),
            })
        }
        "recovery" => {
            schema::members(m, &["id", "kind", "box", "wrap"], &[])?;
            Ok(ParsedLock {
                lock: Lock::Recovery {
                    id: schema::string(m, "id")?.to_string(),
                    box_key: schema::key(m, "box", KeyType::X25519)?,
                    wrap: parse_wrap(schema::object(m, "wrap")?)?,
                },
                kdf: None,
            })
        }
        _ => Err(Error::BadField),
    }
}

/// A slot label: 1 to 64 Unicode scalar values, none below U+0020 and no U+007F ([LCK-2]). → `bad_field`
pub fn check_label(label: &str) -> Result<()> {
    let n = label.chars().count();
    if (1..=64).contains(&n) && label.chars().all(|c| c >= ' ' && c != '\u{7f}') {
        Ok(())
    } else {
        Err(Error::BadField)
    }
}

/// The grant message signed by the recovery key ([LCK-3]).
pub fn grant_message(grant: &Map, account: &str, instance: &str) -> Vec<u8> {
    let mut m = grant.without("sig");
    m.insert("account", account.into());
    m.insert("instance", instance.into());
    frame_map(&label("locks", 1), &m)
}

/// The message the account key signs on a vault ([VLT-2]).
pub fn vault_message(vault: &Map) -> Vec<u8> {
    frame_map(&label("vault", 1), &vault.without("sig"))
}

/// The authenticated data of the contents encryption ([VLT-6]).
pub fn contents_aad(vault: &Map) -> Vec<u8> {
    let m = vault.without("nonce").without("ct").without("sig");
    frame_map(&label("contents", 1), &m)
}

struct Parsed<'a> {
    map: &'a Map,
    grant: &'a Map,
    info: VaultInfo,
    kdfs: Vec<Option<(String, i64, i64, i64)>>,
    recovery: [u8; 32],
    grant_sig: [u8; 64],
    sig: [u8; 64],
}

fn parse_vault(v: &Value) -> Result<Parsed<'_>> {
    if let Value::Object(m) = v
        && canonical_map(m).len() > VAULT_LIMIT
    {
        return Err(Error::TooLarge);
    }
    let m = schema::obj(v)?;
    schema::version(m)?;
    schema::members(
        m,
        &["v", "account", "instance", "rev", "locks", "nonce", "ct", "sig"],
        &[],
    )?;
    schema::account(m, "account")?;
    schema::bytes::<32>(m, "instance")?;
    let rev = schema::int_in(m, "rev", 1, MAX_REV)?;
    let locks = schema::object(m, "locks")?;
    schema::members(locks, &["grant", "list"], &[])?;
    let grant = schema::object(locks, "grant")?;
    schema::members(grant, &["gen", "slots", "recovery", "sig"], &[])?;
    let gen_ = schema::int_in(grant, "gen", 1, MAX_REV)?;
    let mut slots = Vec::new();
    for s in schema::array(grant, "slots")? {
        let s = schema::obj(s)?;
        schema::members(s, &["id", "label"], &[])?;
        schema::bytes::<8>(s, "id")?;
        slots.push(Slot {
            id: schema::string(s, "id")?.to_string(),
            label: schema::string(s, "label")?.to_string(),
        });
    }
    let recovery = schema::key(grant, "recovery", KeyType::X25519)?;
    let grant_sig = schema::sig(grant, "sig")?;
    let mut list = Vec::new();
    let mut kdfs = Vec::new();
    for l in schema::array(locks, "list")? {
        let p = parse_lock(l)?;
        list.push(p.lock);
        kdfs.push(p.kdf);
    }
    schema::bytes::<12>(m, "nonce")?;
    let ct = base64url_decode(schema::string(m, "ct")?).map_err(|_| Error::BadField)?;
    if ct.len() < 16 {
        return Err(Error::BadField);
    }
    let sig = schema::sig(m, "sig")?;
    Ok(Parsed {
        map: m,
        grant,
        info: VaultInfo {
            rev,
            gen_,
            slots,
            locks: list,
        },
        kdfs,
        recovery,
        grant_sig,
        sig,
    })
}

/// [LCK-1], then [LCK-2], then [LCK-6].
fn check_lock_set(p: &Parsed<'_>) -> Result<()> {
    let slots = &p.info.slots;
    let list = &p.info.locks;
    let unique = slots
        .iter()
        .enumerate()
        .all(|(i, s)| !slots[i + 1..].iter().any(|o| o.id == s.id));
    let recovery_locks: Vec<&Lock> = list.iter().filter(|l| matches!(l, Lock::Recovery { .. })).collect();
    let recovery_ok = recovery_locks.len() == 1
        && matches!(recovery_locks[0], Lock::Recovery { id, box_key, .. } if id == "recovery" && *box_key == p.recovery);
    let passwords: Vec<&PasswordLockPublic> = list
        .iter()
        .filter_map(|l| match l {
            Lock::Password(pl, _) => Some(pl),
            _ => None,
        })
        .collect();
    let per_slot = passwords.len() == slots.len()
        && slots
            .iter()
            .all(|s| passwords.iter().filter(|pl| pl.id == s.id).count() == 1);
    if slots.len() > MAX_SLOTS || !unique || !recovery_ok || !per_slot {
        return Err(Error::BadLocks);
    }
    for s in slots {
        check_label(&s.label)?;
    }
    for (alg, m, t, pp) in p.kdfs.iter().flatten() {
        let in_range = |x: &i64| u32::try_from(*x).is_ok();
        if alg != "argon2id" || ![m, t, pp].iter().all(|x| in_range(x)) {
            return Err(Error::KdfParams);
        }
        Kdf {
            m: *m as u32,
            t: *t as u32,
            p: *pp as u32,
        }
        .check()?;
    }
    Ok(())
}

/// Verify a vault against a log state ([VLT-3]), without decrypting it.
pub fn verify_vault(vault: &Value, state: &LogState) -> Result<VaultInfo> {
    let p = parse_vault(vault)?;
    if schema::string(p.map, "account")? != state.account {
        return Err(Error::AccountMismatch);
    }
    if state.retired {
        return Err(Error::AccountRetired);
    }
    let inst = state.instance.as_ref().ok_or(Error::NoInstance)?;
    let instance = schema::string(p.map, "instance")?;
    if schema::bytes::<32>(p.map, "instance")? != inst.hash {
        return Err(Error::WrongInstance);
    }
    check_lock_set(&p)?;
    ed25519_verify(
        &state.recovery,
        &grant_message(p.grant, &state.account, instance),
        &p.grant_sig,
    )?;
    ed25519_verify(&inst.account_key, &vault_message(p.map), &p.sig)?;
    Ok(p.info)
}

/// What a vault replacement changes, relative to the stored vault ([VLT-4], [HST-12]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultChange {
    /// Only the contents, `rev`, `nonce` and `sig` changed.
    Data,
    /// The password lock of one slot changed as well ([LCK-10]); its id and the SHA-256 of its canonical form.
    Password {
        /// The slot id.
        slot: String,
        /// `SHA-256(canonical(new lock))`.
        new_hash: [u8; 32],
    },
    /// The grant generation increased.
    Grant,
}

/// Classify a replacement of `old` by `new` (both verified for the same instance) under [VLT-4]. → `stale_rev`,
/// `stale_locks`
pub fn vault_change(old: &Value, new: &Value) -> Result<VaultChange> {
    let (o, n) = (schema::obj(old)?, schema::obj(new)?);
    let rev = |m: &Map| schema::int(m, "rev");
    if rev(n)? <= rev(o)? {
        return Err(Error::StaleRev);
    }
    let locks = |m: &Map| schema::object(m, "locks").cloned();
    let (ol, nl) = (locks(o)?, locks(n)?);
    let gen_ = |l: &Map| schema::object(l, "grant").and_then(|g| schema::int(g, "gen"));
    let (og, ng) = (gen_(&ol)?, gen_(&nl)?);
    if ng < og {
        return Err(Error::StaleLocks);
    }
    if ng > og {
        return Ok(VaultChange::Grant);
    }
    if ol.get("grant") != nl.get("grant") {
        return Err(Error::StaleLocks);
    }
    let (olist, nlist) = (schema::array(&ol, "list")?, schema::array(&nl, "list")?);
    if olist.len() != nlist.len() {
        return Err(Error::StaleLocks);
    }
    let changed: Vec<usize> = (0..olist.len()).filter(|i| olist[*i] != nlist[*i]).collect();
    match changed.as_slice() {
        [] => Ok(VaultChange::Data),
        [i] => {
            let (a, b) = (schema::obj(&olist[*i])?, schema::obj(&nlist[*i])?);
            let is_pw = |m: &Map| m.get("kind").and_then(Value::as_str) == Some("password");
            if !is_pw(a) || !is_pw(b) || a.get("id") != b.get("id") {
                return Err(Error::StaleLocks);
            }
            Ok(VaultChange::Password {
                slot: schema::string(b, "id")?.to_string(),
                new_hash: crate::crypto::sha256(&canonical_map(b)),
            })
        }
        _ => Err(Error::StaleLocks),
    }
}

#[cfg(feature = "vault")]
pub use crypto::*;

#[cfg(feature = "vault")]
mod crypto {
    use super::*;
    use crate::crypto::{
        aes_gcm_decrypt, aes_gcm_encrypt, argon2id, ed25519_public, ed25519_sign, hkdf, sha256, x25519, x25519_public,
    };
    use crate::encoding::base64url_encode;
    use crate::id::check_account_id;
    use crate::json::canonical;
    use crate::keys::format_key;
    use crate::profile::check_data;
    use crate::recovery::RecoveryKeys;
    use zeroize::Zeroizing;

    /// A source of random bytes: fills the buffer ([IMP-1]).
    pub type Random<'a> = &'a mut dyn FnMut(&mut [u8]);

    fn draw<const N: usize>(random: &mut dyn FnMut(&mut [u8])) -> Zeroizing<[u8; N]> {
        let mut b = Zeroizing::new([0u8; N]);
        random(b.as_mut());
        b
    }

    /// The password rules ([LCK-8]). → `weak_password`
    pub fn check_password(password: &str, username: &str) -> Result<()> {
        let n = nfc(password);
        if n.chars().count() < 12 || n.len() > 1024 || n.eq_ignore_ascii_case(username) {
            return Err(Error::WeakPassword);
        }
        Ok(())
    }

    fn nfc(password: &str) -> Zeroizing<String> {
        use unicode_normalization::UnicodeNormalization;
        Zeroizing::new(password.nfc().collect())
    }

    /// The secrets of a password lock ([LCK-7]).
    pub struct LockSecrets {
        /// The Ed25519 seed of the `auth` key.
        pub auth_seed: Zeroizing<[u8; 32]>,
        /// The X25519 secret of the `box` key.
        pub box_secret: Zeroizing<[u8; 32]>,
    }

    /// Derive a password lock's secrets ([LCK-7]): Argon2id, then HKDF. → `kdf_params`
    pub fn derive_lock_secrets(
        account: &str,
        lock: &str,
        password: &str,
        kdf: &Kdf,
        salt: &[u8; 16],
    ) -> Result<LockSecrets> {
        kdf.check()?;
        let pw = nfc(password);
        let a = argon2id(pw.as_bytes(), salt, kdf.m, kdf.t, kdf.p)?;
        let ctx = Map::new().with("account", account).with("lock", lock);
        Ok(LockSecrets {
            auth_seed: hkdf(a.as_ref(), &[], &frame_map(&label("password/auth", 1), &ctx)),
            box_secret: hkdf(a.as_ref(), &[], &frame_map(&label("password/box", 1), &ctx)),
        })
    }

    fn wrap_key_material(
        s: &[u8; 32],
        epk: &[u8; 32],
        b: &[u8; 32],
        account: &str,
        instance: &str,
        lock: &str,
    ) -> Zeroizing<[u8; 32]> {
        let ctx = Map::new()
            .with("account", account)
            .with("instance", instance)
            .with("lock", lock);
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(epk);
        salt[32..].copy_from_slice(b);
        hkdf(s, &salt, &frame_map(&label("wrap", 1), &ctx))
    }

    /// Wrap the vault key to a lock's `box` ([LCK-9]). Draws: `e` (32), nonce (12). → `bad_key`
    pub fn wrap_vault_key(
        vk: &[u8; 32],
        box_key: &[u8; 32],
        account: &str,
        instance: &str,
        lock: &str,
        random: Random<'_>,
    ) -> Result<Wrap> {
        let e = draw::<32>(random);
        let nonce = *draw::<12>(random);
        let epk = x25519_public(&e);
        let s = x25519(&e, box_key)?;
        let wk = wrap_key_material(&s, &epk, box_key, account, instance, lock);
        let ct: [u8; 48] = aes_gcm_encrypt(&wk, &nonce, vk, &[])
            .try_into()
            .map_err(|_| Error::BadKey)?;
        Ok(Wrap { epk, nonce, ct })
    }

    /// Unwrap the vault key with a lock secret ([LCK-9]). → `unlock_failed`, `bad_key`
    pub fn unwrap_vault_key(
        wrap: &Wrap,
        secret: &[u8; 32],
        box_key: &[u8; 32],
        account: &str,
        instance: &str,
        lock: &str,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if x25519_public(secret) != *box_key {
            return Err(Error::UnlockFailed);
        }
        let s = x25519(secret, &wrap.epk)?;
        let wk = wrap_key_material(&s, &wrap.epk, box_key, account, instance, lock);
        let pt = aes_gcm_decrypt(&wk, &wrap.nonce, &wrap.ct, &[])?;
        let mut vk = Zeroizing::new([0u8; 32]);
        if pt.len() != 32 {
            return Err(Error::UnlockFailed);
        }
        vk.copy_from_slice(&pt);
        Ok(vk)
    }

    fn wrap_value(w: &Wrap) -> Value {
        Map::new()
            .with("epk", format_key(KeyType::X25519, &w.epk))
            .with("nonce", base64url_encode(&w.nonce))
            .with("ct", base64url_encode(&w.ct))
            .into()
    }

    /// The JSON form of a lock.
    pub fn lock_value(lock: &Lock) -> Value {
        match lock {
            Lock::Password(p, w) => Map::new()
                .with("id", p.id.as_str())
                .with("kind", "password")
                .with("kdf", kdf_value(&p.kdf, &p.salt))
                .with("auth", format_key(KeyType::Ed25519, &p.auth))
                .with("box", format_key(KeyType::X25519, &p.box_key))
                .with("wrap", wrap_value(w))
                .into(),
            Lock::Recovery { id, box_key, wrap } => Map::new()
                .with("id", id.as_str())
                .with("kind", "recovery")
                .with("box", format_key(KeyType::X25519, box_key))
                .with("wrap", wrap_value(wrap))
                .into(),
        }
    }

    /// The vault contents ([VLT-7]).
    #[derive(Clone)]
    pub struct Contents {
        /// The Ed25519 seed of the instance account key.
        pub account_seed: Zeroizing<[u8; 32]>,
        /// The private data.
        pub data: Map,
        /// Identities the user has dealt with, if recorded.
        pub known: Option<Map>,
    }

    impl Contents {
        /// The JSON form.
        pub fn to_value(&self) -> Value {
            let mut m = Map::new()
                .with("v", 1i64)
                .with("account_seed", base64url_encode(self.account_seed.as_ref()))
                .with("data", self.data.clone());
            if let Some(k) = &self.known {
                m.insert("known", k.clone().into());
            }
            m.into()
        }

        /// Parse and check contents ([VLT-7]). → `bad_json`, `bad_field`, `too_large`, `bad_data_key`
        pub fn from_bytes(bytes: &[u8]) -> Result<Contents> {
            let v = crate::json::parse_limited(bytes, CONTENTS_LIMIT)?;
            Self::from_value(&v)
        }

        /// Check contents given as a value ([VLT-7]).
        pub fn from_value(v: &Value) -> Result<Contents> {
            if canonical(v).len() > CONTENTS_LIMIT {
                return Err(Error::TooLarge);
            }
            let m = schema::obj(v)?;
            schema::version(m)?;
            schema::members(m, &["v", "account_seed", "data"], &["known"])?;
            let seed = schema::bytes::<32>(m, "account_seed")?;
            let data = schema::object(m, "data")?;
            check_data(data, DATA_LIMIT)?;
            let known = match m.get("known") {
                None => None,
                Some(k) => {
                    let k = schema::obj(k)?;
                    for (id, entry) in k.iter() {
                        check_account_id(id)?;
                        let e = schema::obj(entry)?;
                        schema::members(e, &["handle", "version"], &[])?;
                        schema::string(e, "handle")?;
                        schema::version_ref(schema::get(e, "version")?)?;
                    }
                    Some(k.clone())
                }
            };
            Ok(Contents {
                account_seed: Zeroizing::new(seed),
                data: data.clone(),
                known,
            })
        }
    }

    /// The secret that unlocks a vault ([VLT-8]).
    pub enum Secret<'a> {
        /// A password for the slot `lock`.
        Password {
            /// The slot id.
            lock: &'a str,
            /// The password.
            password: &'a str,
        },
        /// The identity's recovery keys.
        Recovery(&'a RecoveryKeys),
    }

    /// An unlocked vault.
    pub struct Unlocked {
        /// The vault key.
        pub vault_key: Zeroizing<[u8; 32]>,
        /// The decrypted contents.
        pub contents: Contents,
        /// The lock that was used.
        pub lock: String,
        /// The seed of the key that signs as this lock: the `auth` key of a password lock, or the recovery signing key.
        pub lock_seed: Zeroizing<[u8; 32]>,
        /// The vault, verified.
        pub info: VaultInfo,
    }

    impl Unlocked {
        /// The account key's public key.
        pub fn account_key(&self) -> [u8; 32] {
            ed25519_public(&self.contents.account_seed)
        }
    }

    /// Unlock a vault ([VLT-8]).
    pub fn unlock_vault(vault: &Value, state: &LogState, secret: &Secret<'_>) -> Result<Unlocked> {
        let info = verify_vault(vault, state)?;
        let m = schema::obj(vault)?;
        let instance = schema::string(m, "instance")?;
        let (lock_id, lock_secret, lock_seed) = match secret {
            Secret::Password { lock, password } => {
                let p = info.password_lock(lock).ok_or(Error::BadLocks)?;
                let s = derive_lock_secrets(&state.account, lock, password, &p.kdf, &p.salt)?;
                (lock.to_string(), s.box_secret, s.auth_seed)
            }
            Secret::Recovery(keys) => {
                info.lock("recovery").ok_or(Error::BadLocks)?;
                ("recovery".to_string(), keys.box_secret.clone(), keys.sign_seed.clone())
            }
        };
        let lock = info.lock(&lock_id).ok_or(Error::BadLocks)?;
        let vk = unwrap_vault_key(
            lock.wrap(),
            &lock_secret,
            lock.box_key(),
            &state.account,
            instance,
            &lock_id,
        )?;
        let nonce = schema::bytes::<12>(m, "nonce")?;
        let ct = base64url_decode(schema::string(m, "ct")?).map_err(|_| Error::BadField)?;
        let pt = aes_gcm_decrypt(&vk, &nonce, &ct, &contents_aad(m))?;
        let contents = Contents::from_bytes(&pt)?;
        let inst = state.instance.as_ref().ok_or(Error::NoInstance)?;
        if ed25519_public(&contents.account_seed) != inst.account_key {
            return Err(Error::WrongAccountKey);
        }
        Ok(Unlocked {
            vault_key: vk,
            contents,
            lock: lock_id,
            lock_seed,
            info,
        })
    }

    /// Sign a grant with the recovery key ([LCK-3]).
    pub fn sign_grant(
        account: &str,
        instance: &str,
        gen_: i64,
        slots: &[Slot],
        recovery_box: &[u8; 32],
        recovery_seed: &[u8; 32],
    ) -> Map {
        let slots: Vec<Value> = slots
            .iter()
            .map(|s| {
                Map::new()
                    .with("id", s.id.as_str())
                    .with("label", s.label.as_str())
                    .into()
            })
            .collect();
        let g = Map::new()
            .with("gen", gen_)
            .with("slots", Value::Array(slots))
            .with("recovery", format_key(KeyType::X25519, recovery_box));
        let sig = ed25519_sign(recovery_seed, &grant_message(&g, account, instance));
        g.with("sig", base64url_encode(&sig))
    }

    /// Encrypt the contents and sign a vault ([VLT-2], [VLT-6]). Draws: the contents nonce (12).
    #[allow(clippy::too_many_arguments)]
    pub fn seal_vault(
        account: &str,
        instance: &str,
        rev: i64,
        grant: Map,
        list: &[Lock],
        contents: &Contents,
        vault_key: &[u8; 32],
        random: Random<'_>,
    ) -> Result<Value> {
        let cv = contents.to_value();
        let plain = Zeroizing::new(canonical(&cv));
        Contents::from_value(&cv)?;
        let nonce = *draw::<12>(random);
        let locks = Map::new()
            .with("grant", grant)
            .with("list", Value::Array(list.iter().map(lock_value).collect()));
        let mut v = Map::new()
            .with("v", 1i64)
            .with("account", account)
            .with("instance", instance)
            .with("rev", rev)
            .with("locks", locks)
            .with("nonce", base64url_encode(&nonce));
        let ct = aes_gcm_encrypt(vault_key, &nonce, &plain, &contents_aad(&v));
        v.insert("ct", base64url_encode(&ct).into());
        let sig = ed25519_sign(&contents.account_seed, &vault_message(&v));
        v.insert("sig", base64url_encode(&sig).into());
        let v: Value = v.into();
        if canonical(&v).len() > VAULT_LIMIT {
            return Err(Error::TooLarge);
        }
        Ok(v)
    }

    /// A new password for a slot of a new vault: its label and password.
    pub struct NewSlot<'a> {
        /// The label ([LCK-2]).
        pub label: &'a str,
        /// The password ([LCK-8]).
        pub password: &'a str,
        /// The Argon2id parameters.
        pub kdf: Kdf,
    }

    /// Create the public part of a new password lock. Draws: the slot id (8), the salt (16). → `kdf_params`,
    /// `bad_field`
    pub fn new_password_lock(
        account: &str,
        slot: &NewSlot<'_>,
        random: Random<'_>,
    ) -> Result<(Slot, PasswordLockPublic)> {
        check_label(slot.label)?;
        let id = base64url_encode(draw::<8>(random).as_ref());
        let salt = *draw::<16>(random);
        let s = derive_lock_secrets(account, &id, slot.password, &slot.kdf, &salt)?;
        Ok((
            Slot {
                id: id.clone(),
                label: slot.label.to_string(),
            },
            PasswordLockPublic {
                id,
                kdf: slot.kdf,
                salt,
                auth: ed25519_public(&s.auth_seed),
                box_key: x25519_public(&s.box_secret),
            },
        ))
    }

    /// The vault of a new instance ([CLT-1], [KT-3], [KT-4], [KT-8]).
    pub struct InstanceVault<'a> {
        /// The account id.
        pub account: &'a str,
        /// The b64u event hash of the new instance.
        pub instance: &'a str,
        /// The recovery keys (current).
        pub recovery: &'a RecoveryKeys,
        /// The contents, with the new account seed.
        pub contents: Contents,
        /// Password locks carried over, with their slots, in order.
        pub keep: Vec<(Slot, PasswordLockPublic)>,
        /// A new password slot, after the kept ones.
        pub add: Option<NewSlot<'a>>,
    }

    /// Build the vault of a new instance (`rev` 1, `gen` 1). Draws, in order: the vault key (32); for a new slot, its
    /// id (8) and salt (16); the recovery lock's wrap (32 + 12); each password lock's wrap (32 + 12) in slot order;
    /// the contents nonce (12).
    pub fn instance_vault(p: InstanceVault<'_>, random: Random<'_>) -> Result<Value> {
        let vk = draw::<32>(random);
        let mut pairs = p.keep;
        if let Some(add) = &p.add {
            pairs.push(new_password_lock(p.account, add, random)?);
        }
        let slots: Vec<Slot> = pairs.iter().map(|(s, _)| s.clone()).collect();
        let rbox = p.recovery.box_public();
        let grant = sign_grant(p.account, p.instance, 1, &slots, &rbox, &p.recovery.sign_seed);
        build_locks_and_seal(p.account, p.instance, 1, grant, &rbox, &pairs, &p.contents, &vk, random)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_locks_and_seal(
        account: &str,
        instance: &str,
        rev: i64,
        grant: Map,
        rbox: &[u8; 32],
        pairs: &[(Slot, PasswordLockPublic)],
        contents: &Contents,
        vk: &[u8; 32],
        random: Random<'_>,
    ) -> Result<Value> {
        let mut list = vec![Lock::Recovery {
            id: "recovery".to_string(),
            box_key: *rbox,
            wrap: wrap_vault_key(vk, rbox, account, instance, "recovery", random)?,
        }];
        for (_, pl) in pairs {
            let w = wrap_vault_key(vk, &pl.box_key, account, instance, &pl.id, random)?;
            list.push(Lock::Password(pl.clone(), w));
        }
        seal_vault(account, instance, rev, grant, &list, contents, vk, random)
    }

    fn slot_pairs(u: &Unlocked) -> Vec<(Slot, PasswordLockPublic)> {
        u.info
            .slots
            .iter()
            .filter_map(|s| Some((s.clone(), u.info.password_lock(&s.id)?.clone())))
            .collect()
    }

    /// The password locks of an unlocked vault, to carry over to a new instance ([KT-3]); `drop` names slots to leave
    /// out ([KT-4] revoke).
    pub fn carried_locks(u: &Unlocked, drop: &[&str]) -> Vec<(Slot, PasswordLockPublic)> {
        slot_pairs(u)
            .into_iter()
            .filter(|(s, _)| !drop.contains(&s.id.as_str()))
            .collect()
    }

    /// The account, instance and grant of `vault`, which must be the vault `u` was unlocked from (same `rev` and
    /// `gen`). → `stale_rev`
    fn vault_ids_of(u: &Unlocked, vault: &Value) -> Result<(String, String, Map)> {
        let (a, i, g) = vault_ids(vault)?;
        let m = schema::obj(vault)?;
        if schema::int(m, "rev")? != u.info.rev || schema::int(&g, "gen")? != u.info.gen_ {
            return Err(Error::StaleRev);
        }
        Ok((a, i, g))
    }

    fn vault_ids(vault: &Value) -> Result<(String, String, Map)> {
        let m = schema::obj(vault)?;
        let grant = schema::object(schema::object(m, "locks")?, "grant")?.clone();
        Ok((
            schema::string(m, "account")?.to_string(),
            schema::string(m, "instance")?.to_string(),
            grant,
        ))
    }

    /// Replace the contents (a data update, [HST-12] case 1): `rev + 1`, the same locks. Draws: the contents nonce (12).
    pub fn update_contents(u: &Unlocked, vault: &Value, contents: &Contents, random: Random<'_>) -> Result<Value> {
        let (account, instance, grant) = vault_ids_of(u, vault)?;
        if *contents.account_seed != *u.contents.account_seed {
            return Err(Error::WrongAccountKey);
        }
        seal_vault(
            &account,
            &instance,
            u.info.rev + 1,
            grant,
            &u.info.locks,
            contents,
            &u.vault_key,
            random,
        )
    }

    /// A password change ([CHG-1] step 1): a new lock for slot `slot` and the new vault. Draws: the salt (16), the
    /// wrap (32 + 12), the contents nonce (12). Returns the new vault and `SHA-256(canonical(new lock))`.
    pub fn change_password(
        u: &Unlocked,
        vault: &Value,
        slot: &str,
        password: &str,
        kdf: &Kdf,
        random: Random<'_>,
    ) -> Result<(Value, [u8; 32])> {
        let (account, instance, grant) = vault_ids_of(u, vault)?;
        let index = u
            .info
            .locks
            .iter()
            .position(|l| matches!(l, Lock::Password(p, _) if p.id == slot))
            .ok_or(Error::BadLocks)?;
        let salt = *draw::<16>(random);
        let s = derive_lock_secrets(&account, slot, password, kdf, &salt)?;
        let public = PasswordLockPublic {
            id: slot.to_string(),
            kdf: *kdf,
            salt,
            auth: ed25519_public(&s.auth_seed),
            box_key: x25519_public(&s.box_secret),
        };
        let wrap = wrap_vault_key(&u.vault_key, &public.box_key, &account, &instance, slot, random)?;
        let lock = Lock::Password(public, wrap);
        let hash = sha256(&canonical(&lock_value(&lock)));
        let mut list = u.info.locks.clone();
        list[index] = lock;
        let v = seal_vault(
            &account,
            &instance,
            u.info.rev + 1,
            grant,
            &list,
            &u.contents,
            &u.vault_key,
            random,
        )?;
        Ok((v, hash))
    }

    /// Add a password slot ([KT-4]): `gen + 1` signed by the recovery key, `rev + 1`. Draws: the slot id (8), the salt
    /// (16), the wrap (32 + 12), the contents nonce (12).
    pub fn add_slot(
        u: &Unlocked,
        vault: &Value,
        recovery: &RecoveryKeys,
        slot: &NewSlot<'_>,
        random: Random<'_>,
    ) -> Result<Value> {
        let (account, instance, _) = vault_ids_of(u, vault)?;
        if u.info.slots.len() >= MAX_SLOTS {
            return Err(Error::BadLocks);
        }
        let (s, public) = new_password_lock(&account, slot, random)?;
        let wrap = wrap_vault_key(&u.vault_key, &public.box_key, &account, &instance, &s.id, random)?;
        let mut slots = u.info.slots.clone();
        slots.push(s);
        let mut list = u.info.locks.clone();
        list.push(Lock::Password(public, wrap));
        let grant = sign_grant(
            &account,
            &instance,
            u.info.gen_ + 1,
            &slots,
            &recovery.box_public(),
            &recovery.sign_seed,
        );
        seal_vault(
            &account,
            &instance,
            u.info.rev + 1,
            grant,
            &list,
            &u.contents,
            &u.vault_key,
            random,
        )
    }

    /// The vault after a recovery-key rotation ([KT-5]): a grant (`gen + 1`) with the new recovery lock key, signed by
    /// the new key, and a new recovery lock. Draws: the wrap (32 + 12), the contents nonce (12).
    pub fn regrant(u: &Unlocked, vault: &Value, new_recovery: &RecoveryKeys, random: Random<'_>) -> Result<Value> {
        let (account, instance, _) = vault_ids_of(u, vault)?;
        let rbox = new_recovery.box_public();
        let grant = sign_grant(
            &account,
            &instance,
            u.info.gen_ + 1,
            &u.info.slots,
            &rbox,
            &new_recovery.sign_seed,
        );
        let mut list = u.info.locks.clone();
        for l in list.iter_mut() {
            if matches!(l, Lock::Recovery { .. }) {
                *l = Lock::Recovery {
                    id: "recovery".to_string(),
                    box_key: rbox,
                    wrap: wrap_vault_key(&u.vault_key, &rbox, &account, &instance, "recovery", random)?,
                };
            }
        }
        seal_vault(
            &account,
            &instance,
            u.info.rev + 1,
            grant,
            &list,
            &u.contents,
            &u.vault_key,
            random,
        )
    }

    /// The SHA-256 of a vault's canonical form, for comparing stored vaults.
    pub fn vault_digest(vault: &Value) -> [u8; 32] {
        sha256(&canonical(vault))
    }

    /// Parse vault bytes with the size limit ([CJ-8]).
    pub fn parse_vault_bytes(bytes: &[u8]) -> Result<Value> {
        crate::json::parse_limited(bytes, VAULT_LIMIT)
    }
}
