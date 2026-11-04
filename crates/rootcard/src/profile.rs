//! Arbitrary data: the public profile and data keys (SPEC §12).

use crate::crypto::{ed25519_sign, ed25519_verify, frame_map};
use crate::encoding::base64url_encode;
use crate::error::{Error, Result};
use crate::json::{Map, Value, canonical, canonical_map};
use crate::keys::schema;
use crate::label;
use crate::log::LogState;
use crate::vault::MAX_REV;

/// The maximum canonical size of a public profile ([DAT-1]).
pub const PROFILE_LIMIT: usize = 16 * 1024;

/// A data key ([DAT-4]): 1 to 64 characters of `a–z 0–9 . _ -` with the prefix `user.` or `app.<name>.`, and at least
/// one character after the prefix. → `bad_data_key`
pub fn check_data_key(key: &str) -> Result<()> {
    let b = key.as_bytes();
    let charset = b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'));
    if !(1..=64).contains(&b.len()) || !charset {
        return Err(Error::BadDataKey);
    }
    let rest = if let Some(r) = key.strip_prefix("user.") {
        r
    } else if let Some(r) = key.strip_prefix("app.") {
        let (name, r) = r.split_once('.').ok_or(Error::BadDataKey)?;
        check_app_name(name).map_err(|_| Error::BadDataKey)?;
        r
    } else {
        return Err(Error::BadDataKey);
    };
    if rest.is_empty() {
        Err(Error::BadDataKey)
    } else {
        Ok(())
    }
}

/// An application namespace name: 1 to 32 characters of `a–z 0–9 -`, beginning with `a–z 0–9` ([DAT-4]).
/// → `bad_data_key`
pub fn check_app_name(name: &str) -> Result<()> {
    let b = name.as_bytes();
    let ok = (1..=32).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-';
    if ok { Ok(()) } else { Err(Error::BadDataKey) }
}

/// Every key of `data` is a data key ([DAT-4]) and its canonical form is at most `limit` bytes. → `bad_data_key`,
/// `too_large`
pub fn check_data(data: &Map, limit: usize) -> Result<()> {
    for k in data.keys() {
        check_data_key(k)?;
    }
    if canonical_map(data).len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(())
}

/// Set `key` in `data` on behalf of the application `app` ([DAT-7]): only `user.` and `app.<app>.` keys. → `bad_data_key`,
/// `bad_json`
pub fn set_data(data: &mut Map, app: &str, key: &str, value: Value) -> Result<()> {
    check_data_key(key)?;
    check_app_name(app)?;
    if !key.starts_with("user.") && !key.starts_with(&format!("app.{app}.")) {
        return Err(Error::BadDataKey);
    }
    value.validate()?;
    data.insert(key, value);
    Ok(())
}

/// Remove `key` from `data` on behalf of the application `app` ([DAT-7]). → `bad_data_key`
pub fn remove_data(data: &mut Map, app: &str, key: &str) -> Result<()> {
    check_data_key(key)?;
    if !key.starts_with("user.") && !key.starts_with(&format!("app.{app}.")) {
        return Err(Error::BadDataKey);
    }
    data.remove(key);
    Ok(())
}

/// The message the account key signs on a profile ([DAT-2]).
pub fn public_message(profile: &Map) -> Vec<u8> {
    frame_map(&label("public", 1), &profile.without("sig"))
}

/// Sign a public profile with the account key. → `bad_data_key`, `too_large`
pub fn sign_public(account: &str, instance: &str, rev: i64, data: &Map, account_seed: &[u8; 32]) -> Result<Value> {
    check_data(data, PROFILE_LIMIT)?;
    let m = Map::new()
        .with("v", 1i64)
        .with("account", account)
        .with("instance", instance)
        .with("rev", rev)
        .with("data", data.clone());
    let sig = ed25519_sign(account_seed, &public_message(&m));
    let v: Value = m.with("sig", base64url_encode(&sig)).into();
    if canonical(&v).len() > PROFILE_LIMIT {
        return Err(Error::TooLarge);
    }
    Ok(v)
}

/// A public profile after [`verify_public`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInfo {
    /// The revision.
    pub rev: i64,
    /// The data.
    pub data: Map,
}

/// Verify a public profile against a log state ([DAT-2]).
pub fn verify_public(profile: &Value, state: &LogState) -> Result<ProfileInfo> {
    if canonical(profile).len() > PROFILE_LIMIT {
        return Err(Error::TooLarge);
    }
    let m = schema::obj(profile)?;
    schema::version(m)?;
    schema::members(m, &["v", "account", "instance", "rev", "data", "sig"], &[])?;
    let account = schema::account(m, "account")?;
    let instance = schema::bytes::<32>(m, "instance")?;
    let rev = schema::int_in(m, "rev", 1, MAX_REV)?;
    let data = schema::object(m, "data")?;
    let sig = schema::sig(m, "sig")?;
    if account != state.account {
        return Err(Error::AccountMismatch);
    }
    if state.retired {
        return Err(Error::AccountRetired);
    }
    let inst = state.instance.as_ref().ok_or(Error::NoInstance)?;
    if instance != inst.hash {
        return Err(Error::WrongInstance);
    }
    for k in data.keys() {
        check_data_key(k)?;
    }
    ed25519_verify(&inst.account_key, &public_message(m), &sig)?;
    Ok(ProfileInfo {
        rev,
        data: data.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_keys() {
        for ok in ["user.name", "app.xigna.level", "app.a-1.x_y", "user.a.b"] {
            assert_eq!(check_data_key(ok), Ok(()), "{ok}");
        }
        for bad in [
            "user.", "app.x.", "app..x", "app.-x.y", "name", "User.x", "sys.x", "app.x",
        ] {
            assert_eq!(check_data_key(bad), Err(Error::BadDataKey), "{bad}");
        }
        let mut d = Map::new();
        assert_eq!(
            set_data(&mut d, "xigna", "app.other.x", true.into()),
            Err(Error::BadDataKey)
        );
        assert_eq!(set_data(&mut d, "xigna", "app.xigna.x", true.into()), Ok(()));
    }
}
