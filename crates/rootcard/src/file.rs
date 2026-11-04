//! The account file and the recovery card (SPEC §15).

use crate::error::{Error, Result};
use crate::id::{account_id, inception};
use crate::json::{Map, Value, canonical, canonical_map};
use crate::keys::schema;
use crate::log::{LogState, VerifyOptions, verify_log};
use crate::profile::{ProfileInfo, verify_public};
use crate::recovery::{RecoveryKeys, derive_recovery_keys, format_recovery_key, parse_recovery_key};
use crate::vault::{VaultInfo, verify_vault};
use zeroize::Zeroizing;

/// The maximum size of an account file ([FIL-1]).
pub const FILE_LIMIT: usize = 5 * 1024 * 1024;
/// The maximum canonical size of `host_data` ([FIL-2]).
pub const HOST_DATA_LIMIT: usize = 16 * 1024;

/// Build an account file ([FIL-2]).
pub fn export_account(
    state: &LogState,
    log: &[Value],
    public: Option<&Value>,
    vault: Option<&Value>,
    host_data: Option<&Map>,
) -> Value {
    let mut m = Map::new()
        .with("format", "rootcard-account")
        .with("v", 1i64)
        .with("realm", state.realm.as_str())
        .with("account", state.account.as_str())
        .with("handle", state.handle.as_str())
        .with("version", state.version.to_value())
        .with("log", Value::Array(log.to_vec()));
    if let Some(p) = public {
        m.insert("public", p.clone());
    }
    if let Some(v) = vault {
        m.insert("vault", v.clone());
    }
    if let Some(h) = host_data {
        m.insert("host_data", h.clone().into());
    }
    m.into()
}

/// An imported account file.
#[derive(Debug, Clone)]
pub struct ImportedAccount {
    /// The log state.
    pub state: LogState,
    /// The log.
    pub log: Vec<Value>,
    /// The public profile, verified.
    pub public: Option<(Value, ProfileInfo)>,
    /// The vault, verified.
    pub vault: Option<(Value, VaultInfo)>,
    /// `host_data`: unsigned, for information only ([FIL-2]).
    pub host_data: Option<Map>,
}

/// The suggested file name `<username>-<tag>.rootcard.json` ([FIL-1]).
pub fn account_file_name(state: &LogState) -> String {
    format!("{}-{}.rootcard.json", state.username, crate::id::tag(&state.account))
}

/// Import an account file ([FIL-3]).
pub fn import_account(file: &Value, options: &VerifyOptions) -> Result<ImportedAccount> {
    if canonical(file).len() > FILE_LIMIT {
        return Err(Error::TooLarge);
    }
    let m = schema::obj(file)?;
    if m.get("format").and_then(Value::as_str) != Some("rootcard-account") {
        return Err(Error::BadField);
    }
    schema::version(m)?;
    schema::members(
        m,
        &["format", "v", "realm", "account", "handle", "version", "log"],
        &["public", "vault", "host_data"],
    )?;
    let realm = schema::string(m, "realm")?;
    let account = schema::account(m, "account")?;
    let handle = schema::string(m, "handle")?;
    let version = crate::log::Version::from_value(schema::get(m, "version")?)?;
    let log = schema::array(m, "log")?.clone();
    let host_data = match m.get("host_data") {
        None => None,
        Some(h) => {
            let h = schema::obj(h)?;
            if canonical_map(h).len() > HOST_DATA_LIMIT {
                return Err(Error::TooLarge);
            }
            Some(h.clone())
        }
    };
    let state = verify_log(&log, options)?;
    if state.account != account || state.realm != realm || state.handle != handle || state.version != version {
        return Err(Error::AccountMismatch);
    }
    let public = match m.get("public") {
        None => None,
        Some(p) => Some((p.clone(), verify_public(p, &state)?)),
    };
    let vault = match m.get("vault") {
        None => None,
        Some(v) => Some((v.clone(), verify_vault(v, &state)?)),
    };
    Ok(ImportedAccount {
        state,
        log,
        public,
        vault,
        host_data,
    })
}

/// Build a recovery card ([CRD-1], [CRD-2]). `log` is required after a rotation.
pub fn recovery_card(realm: &str, username: &str, account: &str, key: &[u8; 32], log: Option<&[Value]>) -> Value {
    let mut m = Map::new()
        .with("format", "rootcard-card")
        .with("v", 1i64)
        .with("realm", realm)
        .with("username", username)
        .with("account", account)
        .with("key", format_recovery_key(key));
    if let Some(l) = log {
        m.insert("log", Value::Array(l.to_vec()));
    }
    m.into()
}

/// A recovery card after [`read_card`].
pub struct Card {
    /// The realm.
    pub realm: String,
    /// The username.
    pub username: String,
    /// The account id.
    pub account: String,
    /// The recovery key.
    pub key: Zeroizing<[u8; 32]>,
    /// The derived keys.
    pub keys: RecoveryKeys,
    /// The log carried by the card, verified (after a rotation), or the derived inception.
    pub log: Vec<Value>,
    /// The state of that log.
    pub state: LogState,
}

/// Read a recovery card ([CRD-3]).
pub fn read_card(card: &Value) -> Result<Card> {
    let m = schema::obj(card)?;
    if m.get("format").and_then(Value::as_str) != Some("rootcard-card") {
        return Err(Error::BadField);
    }
    schema::version(m)?;
    schema::members(m, &["format", "v", "realm", "username", "account", "key"], &["log"])?;
    let realm = schema::string(m, "realm")?.to_string();
    let username = schema::string(m, "username")?.to_string();
    let account = schema::account(m, "account")?;
    let key_text = schema::string(m, "key")?;
    let log_value = match m.get("log") {
        None => None,
        Some(_) => Some(schema::array(m, "log")?.clone()),
    };
    let key = parse_recovery_key(key_text)?;
    let keys = derive_recovery_keys(&key, &realm, &username);
    let options = VerifyOptions::new([realm.clone()]);
    let (log, state) = match log_value {
        None => {
            let inc = inception(&keys, &realm, &username)?;
            if account_id(&inc) != account {
                return Err(Error::AccountMismatch);
            }
            let log = vec![Value::Object(inc)];
            let state = verify_log(&log, &options)?;
            (log, state)
        }
        Some(log) => {
            let state = verify_log(&log, &options)?;
            if state.account != account || state.realm != realm || state.username != username {
                return Err(Error::AccountMismatch);
            }
            if keys.sign_public() != state.recovery {
                return Err(Error::WrongRecoveryKey);
            }
            (log, state)
        }
    };
    Ok(Card {
        realm,
        username,
        account,
        key,
        keys,
        log,
        state,
    })
}

/// The printable text form of a recovery card ([CRD-4]).
pub fn card_text(card: &Value) -> Result<String> {
    let c = read_card(card)?;
    let groups = |s: &str| {
        s.as_bytes()
            .chunks(4)
            .map(|g| String::from_utf8_lossy(g).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let key = Zeroizing::new(format_recovery_key(&c.key));
    let key_groups = Zeroizing::new(key.trim_start_matches("RCR-").replace('-', " "));
    Ok(format!(
        "rootcard recovery card\n\n\
         Handle:     {handle}\n\
         Realm:      {realm}\n\
         Account id: {id}\n\n\
         Recovery key:\n  RCR {key}\n\n\
         Anyone who has this card controls the identity. Keep it offline and private.\n\
         Only enter the recovery key in the rootcard key tool.\n",
        handle = c.state.handle,
        realm = c.realm,
        id = groups(&c.account),
        key = key_groups.as_str(),
    ))
}
