//! Challenges and the signed messages of vault fetch, login and password change (SPEC §13).

use crate::crypto::{ed25519_sign, ed25519_verify, frame_map};
use crate::encoding::base64url_encode;
use crate::error::{Error, Result};
use crate::json::{Map, Value};
use crate::keys::{KeyType, format_key, schema};
use crate::label;
use crate::log::{Version, check_url};

/// The maximum lifetime of a challenge, in seconds ([CHL-2]).
pub const CHALLENGE_LIFETIME: i64 = 60;

/// The purpose of a challenge ([CHL-1]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// A vault fetch.
    Fetch,
    /// A login.
    Login,
    /// A password change.
    Change,
}

impl Purpose {
    /// `fetch`, `login` or `change`.
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Fetch => "fetch",
            Purpose::Login => "login",
            Purpose::Change => "change",
        }
    }

    /// Parse a purpose. → `bad_field`
    pub fn parse(s: &str) -> Result<Purpose> {
        match s {
            "fetch" => Ok(Purpose::Fetch),
            "login" => Ok(Purpose::Login),
            "change" => Ok(Purpose::Change),
            _ => Err(Error::BadField),
        }
    }
}

/// A challenge ([CHL-1]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// 32 random bytes.
    pub nonce: [u8; 32],
    /// The home key of the current instance.
    pub host: [u8; 32],
    /// The realm.
    pub realm: String,
    /// The version the host holds.
    pub version: Version,
    /// Expiry, Unix seconds.
    pub expires: i64,
}

impl Challenge {
    /// The JSON form.
    pub fn to_value(&self) -> Value {
        Map::new()
            .with("nonce", base64url_encode(&self.nonce))
            .with("host", format_key(KeyType::Ed25519, &self.host))
            .with("realm", self.realm.as_str())
            .with("version", self.version.to_value())
            .with("expires", self.expires)
            .into()
    }

    /// Parse a challenge. → `bad_field`, `bad_key`
    pub fn from_value(v: &Value) -> Result<Challenge> {
        let m = schema::obj(v)?;
        schema::members(m, &["nonce", "host", "realm", "version", "expires"], &[])?;
        Ok(Challenge {
            nonce: schema::bytes::<32>(m, "nonce")?,
            host: schema::key(m, "host", KeyType::Ed25519)?,
            realm: schema::string(m, "realm")?.to_string(),
            version: Version::from_value(schema::get(m, "version")?)?,
            expires: schema::int(m, "expires")?,
        })
    }
}

/// The login message ([LGN-1] step 5).
pub fn login_message(
    account: &str,
    host: &[u8; 32],
    lock: &str,
    nonce: &[u8; 32],
    realm: &str,
    url: &str,
    version: &Version,
) -> Vec<u8> {
    let m = Map::new()
        .with("account", account)
        .with("host", format_key(KeyType::Ed25519, host))
        .with("lock", lock)
        .with("nonce", base64url_encode(nonce))
        .with("realm", realm)
        .with("url", url)
        .with("version", version.to_value());
    frame_map(&label("login", 1), &m)
}

/// The vault fetch message ([FET-1]).
pub fn fetch_message(account: &str, host: &[u8; 32], lock: &str, nonce: &[u8; 32], url: &str) -> Vec<u8> {
    let m = Map::new()
        .with("account", account)
        .with("host", format_key(KeyType::Ed25519, host))
        .with("lock", lock)
        .with("nonce", base64url_encode(nonce))
        .with("url", url);
    frame_map(&label("fetch", 1), &m)
}

/// The password change proof message ([CHG-1] step 2).
pub fn change_message(
    account: &str,
    host: &[u8; 32],
    lock: &str,
    new_lock_hash: &[u8; 32],
    nonce: &[u8; 32],
    url: &str,
) -> Vec<u8> {
    let m = Map::new()
        .with("account", account)
        .with("host", format_key(KeyType::Ed25519, host))
        .with("lock", lock)
        .with("new", base64url_encode(new_lock_hash))
        .with("nonce", base64url_encode(nonce))
        .with("url", url);
    frame_map(&label("change", 1), &m)
}

/// A login request ([LGN-1] step 5): `{ account, nonce, version, url, lock, sig, lock_sig }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    /// The account id.
    pub account: String,
    /// The challenge nonce.
    pub nonce: [u8; 32],
    /// The version the client logs in with.
    pub version: Version,
    /// The host address the client uses ([LGN-4]).
    pub url: String,
    /// The lock id.
    pub lock: String,
    /// The account key's signature.
    pub sig: [u8; 64],
    /// The lock key's signature.
    pub lock_sig: [u8; 64],
}

impl LoginRequest {
    /// Sign a login for `challenge`: with the account key and the key of the unlocked lock ([LGN-1] step 5). The
    /// client checks the challenge first (step 4). → `wrong_host`, `stale_version`
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        account: &str,
        realm: &str,
        home_key: &[u8; 32],
        version: &Version,
        challenge: &Challenge,
        url: &str,
        lock: &str,
        account_seed: &[u8; 32],
        lock_seed: &[u8; 32],
    ) -> Result<LoginRequest> {
        if challenge.host != *home_key || challenge.realm != realm {
            return Err(Error::WrongHost);
        }
        if challenge.version != *version {
            return Err(Error::StaleVersion);
        }
        check_url(url)?;
        let msg = login_message(account, home_key, lock, &challenge.nonce, realm, url, version);
        Ok(LoginRequest {
            account: account.to_string(),
            nonce: challenge.nonce,
            version: *version,
            url: url.to_string(),
            lock: lock.to_string(),
            sig: ed25519_sign(account_seed, &msg),
            lock_sig: ed25519_sign(lock_seed, &msg),
        })
    }

    /// The JSON form.
    pub fn to_value(&self) -> Value {
        Map::new()
            .with("account", self.account.as_str())
            .with("nonce", base64url_encode(&self.nonce))
            .with("version", self.version.to_value())
            .with("url", self.url.as_str())
            .with("lock", self.lock.as_str())
            .with("sig", base64url_encode(&self.sig))
            .with("lock_sig", base64url_encode(&self.lock_sig))
            .into()
    }

    /// Parse a login request. → `bad_field`
    pub fn from_value(v: &Value) -> Result<LoginRequest> {
        let m = schema::obj(v)?;
        schema::members(
            m,
            &["account", "nonce", "version", "url", "lock", "sig", "lock_sig"],
            &[],
        )?;
        let url = schema::string(m, "url")?;
        check_url(url)?;
        let lock = schema::string(m, "lock")?;
        if lock.is_empty() || lock.len() > 16 {
            return Err(Error::BadField);
        }
        Ok(LoginRequest {
            account: schema::account(m, "account")?,
            nonce: schema::bytes::<32>(m, "nonce")?,
            version: Version::from_value(schema::get(m, "version")?)?,
            url: url.to_string(),
            lock: lock.to_string(),
            sig: schema::sig(m, "sig")?,
            lock_sig: schema::sig(m, "lock_sig")?,
        })
    }

    /// Verify both signatures ([LGN-1] step 6, last check). → `bad_signature`
    pub fn verify(&self, realm: &str, home_key: &[u8; 32], account_key: &[u8; 32], lock_key: &[u8; 32]) -> Result<()> {
        let msg = login_message(
            &self.account,
            home_key,
            &self.lock,
            &self.nonce,
            realm,
            &self.url,
            &self.version,
        );
        ed25519_verify(account_key, &msg, &self.sig)?;
        ed25519_verify(lock_key, &msg, &self.lock_sig)
    }
}
