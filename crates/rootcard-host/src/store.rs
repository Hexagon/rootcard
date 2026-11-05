//! Storage traits shared by every server of a host ([HST-19]), and in-memory implementations for tests and development.

use rootcard::json::Value;
use rootcard::log::{LogState, Version};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

/// A storage failure (the backend is unavailable, a row is corrupt). Answered as `500`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// Everything a host stores per identity ([HST-1]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// The events of the newest valid log the host has seen.
    pub events: Vec<Value>,
    /// The log state produced by `verify_log` or `extend_log` on `events` ([LOG-16]).
    pub state: LogState,
    /// The vault, only while this host is the primary host ([VLT-5]).
    pub vault: Option<Value>,
    /// The newest public profile of the current instance ([DAT-3]).
    pub public: Option<Value>,
}

impl Stored {
    /// `rev` of the stored vault.
    pub fn vault_rev(&self) -> Option<i64> {
        self.vault.as_ref().and_then(|v| v.as_object()?.get("rev")?.as_int())
    }

    /// `rev` of the stored profile.
    pub fn public_rev(&self) -> Option<i64> {
        self.public.as_ref().and_then(|v| v.as_object()?.get("rev")?.as_int())
    }

    /// What a compare-and-swap of this record expects ([HST-19]).
    pub fn expected(&self) -> Expected {
        Expected {
            version: self.state.version,
            vault_rev: self.vault_rev(),
            public_rev: self.public_rev(),
        }
    }
}

/// The values a change was checked against: a swap succeeds only if the stored record still has them ([HST-19]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected {
    /// The log version.
    pub version: Version,
    /// The vault's `rev`, if there is a vault.
    pub vault_rev: Option<i64>,
    /// The profile's `rev`, if there is a profile.
    pub public_rev: Option<i64>,
}

/// The key of the handle uniqueness index: `(realm, lower-case username, tag)` ([HST-4]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HandleKey {
    /// The realm.
    pub realm: String,
    /// The username, ASCII lower case.
    pub username: String,
    /// The 4-character tag.
    pub tag: String,
}

impl HandleKey {
    /// The index key of an identity.
    pub fn of(state: &LogState) -> HandleKey {
        HandleKey {
            realm: state.realm.clone(),
            username: state.username.to_ascii_lowercase(),
            tag: rootcard::id::tag(&state.account).to_string(),
        }
    }
}

/// The outcome of [`IdentityStore::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// Stored.
    Done,
    /// An identity with this account id is already stored.
    Exists,
    /// The handle is taken in the realm (only when claiming).
    HandleTaken,
}

/// Identity storage, shared by every server of the host. Every change is atomic ([HST-19]).
pub trait IdentityStore {
    /// The stored identity.
    fn load(&self, account: &str) -> Result<Option<Stored>, StoreError>;
    /// Store a new identity. With `claim`, claim its handle in the same atomic step ([HST-3], [HST-4]); without, the
    /// identity arrived by propagation and may collide ([HST-15]).
    fn insert(&self, new: &Stored, claim: bool) -> Result<Insert, StoreError>;
    /// Replace the stored identity if it still matches `expected`. Returns whether it was replaced.
    fn swap(&self, account: &str, expected: &Expected, new: &Stored) -> Result<bool, StoreError>;
    /// The account ids stored under a handle key, retired and propagated identities included (for lookups, [HDL-7]).
    fn by_handle(&self, key: &HandleKey) -> Result<Vec<String>, StoreError>;
    /// Whether an identity registered at this host (stored with `claim`) holds the handle key. Only such identities
    /// reserve a handle ([HST-4]); identities that arrived by propagation never do, retired or not.
    fn handle_claimed(&self, key: &HandleKey) -> Result<bool, StoreError>;
    /// The accounts changed after `since` (a cursor from an earlier call, 0 for all), at most `limit`, and the new cursor.
    fn changes(&self, since: u64, limit: usize) -> Result<(u64, Vec<String>), StoreError>;
}

/// The information a challenge was issued with ([CHL-1], [CHL-2]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The account.
    pub account: String,
    /// The purpose.
    pub purpose: rootcard::messages::Purpose,
    /// Expiry, Unix seconds.
    pub expires: i64,
}

/// Challenge storage with a 60 s expiry and an atomic take ([CHL-2], [HST-19]). Issuing a challenge needs no
/// authentication, so a store must drop expired challenges itself (on insert, or with a periodic job): otherwise it
/// grows with every request.
pub trait ChallengeStore {
    /// Store an issued challenge.
    fn put(&self, nonce: [u8; 32], issued: Issued) -> Result<(), StoreError>;
    /// Remove and return a challenge, atomically across all servers.
    fn take(&self, nonce: &[u8; 32]) -> Result<Option<Issued>, StoreError>;
}

/// A session ([HST-10]): one account, one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The account.
    pub account: String,
    /// The instance hash at login.
    pub instance: [u8; 32],
    /// The last use, Unix seconds.
    pub last_used: i64,
}

/// Opaque session tokens, stored by their SHA-256 ([HST-10]).
pub trait SessionStore {
    /// Store a session under the hash of its token.
    fn put(&self, token_hash: [u8; 32], session: Session) -> Result<(), StoreError>;
    /// The session of a token hash.
    fn get(&self, token_hash: &[u8; 32]) -> Result<Option<Session>, StoreError>;
    /// Record a use.
    fn touch(&self, token_hash: &[u8; 32], now: i64) -> Result<(), StoreError>;
    /// End a session.
    fn remove(&self, token_hash: &[u8; 32]) -> Result<(), StoreError>;
}

fn poisoned<T>(_: T) -> StoreError {
    StoreError("lock poisoned".into())
}

#[derive(Default)]
struct MemoryInner {
    identities: HashMap<String, Stored>,
    handles: HashMap<HandleKey, Vec<String>>,
    claims: HashMap<HandleKey, String>,
    log: Vec<String>,
}

/// An in-memory [`IdentityStore`].
#[derive(Default)]
pub struct MemoryIdentityStore(Mutex<MemoryInner>);

impl MemoryIdentityStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for MemoryIdentityStore {
    fn load(&self, account: &str) -> Result<Option<Stored>, StoreError> {
        Ok(self.0.lock().map_err(poisoned)?.identities.get(account).cloned())
    }

    fn insert(&self, new: &Stored, claim: bool) -> Result<Insert, StoreError> {
        let mut g = self.0.lock().map_err(poisoned)?;
        let account = new.state.account.clone();
        if g.identities.contains_key(&account) {
            return Ok(Insert::Exists);
        }
        let key = HandleKey::of(&new.state);
        if claim {
            if g.claims.contains_key(&key) {
                return Ok(Insert::HandleTaken);
            }
            g.claims.insert(key.clone(), account.clone());
        }
        g.handles.entry(key).or_default().push(account.clone());
        g.identities.insert(account.clone(), new.clone());
        g.log.push(account);
        Ok(Insert::Done)
    }

    fn swap(&self, account: &str, expected: &Expected, new: &Stored) -> Result<bool, StoreError> {
        let mut g = self.0.lock().map_err(poisoned)?;
        match g.identities.get(account) {
            Some(cur) if cur.expected() == *expected => {}
            _ => return Ok(false),
        }
        g.identities.insert(account.to_string(), new.clone());
        g.log.push(account.to_string());
        Ok(true)
    }

    fn handle_claimed(&self, key: &HandleKey) -> Result<bool, StoreError> {
        Ok(self.0.lock().map_err(poisoned)?.claims.contains_key(key))
    }

    fn by_handle(&self, key: &HandleKey) -> Result<Vec<String>, StoreError> {
        Ok(self
            .0
            .lock()
            .map_err(poisoned)?
            .handles
            .get(key)
            .cloned()
            .unwrap_or_default())
    }

    fn changes(&self, since: u64, limit: usize) -> Result<(u64, Vec<String>), StoreError> {
        let g = self.0.lock().map_err(poisoned)?;
        let start = usize::try_from(since).unwrap_or(usize::MAX).min(g.log.len());
        let end = (start + limit).min(g.log.len());
        let mut out: Vec<String> = Vec::new();
        for a in &g.log[start..end] {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
        Ok((end as u64, out))
    }
}

/// An in-memory [`ChallengeStore`].
#[derive(Default)]
pub struct MemoryChallengeStore(Mutex<HashMap<[u8; 32], Issued>>);

impl MemoryChallengeStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of stored challenges.
    pub fn len(&self) -> usize {
        self.0.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether no challenge is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ChallengeStore for MemoryChallengeStore {
    /// Stores the challenge and drops every challenge that expired more than one lifetime ago (a challenge is issued
    /// at `expires - CHALLENGE_LIFETIME` of the host's clock). A recently expired one is kept, so that using it still
    /// answers `challenge_expired`.
    fn put(&self, nonce: [u8; 32], issued: Issued) -> Result<(), StoreError> {
        let lifetime = rootcard::messages::CHALLENGE_LIFETIME;
        let cutoff = issued.expires.saturating_sub(lifetime.saturating_mul(2));
        let mut g = self.0.lock().map_err(poisoned)?;
        g.retain(|_, i| i.expires >= cutoff);
        g.insert(nonce, issued);
        Ok(())
    }

    fn take(&self, nonce: &[u8; 32]) -> Result<Option<Issued>, StoreError> {
        Ok(self.0.lock().map_err(poisoned)?.remove(nonce))
    }
}

/// An in-memory [`SessionStore`].
#[derive(Default)]
pub struct MemorySessionStore(Mutex<HashMap<[u8; 32], Session>>);

impl MemorySessionStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn put(&self, token_hash: [u8; 32], session: Session) -> Result<(), StoreError> {
        self.0.lock().map_err(poisoned)?.insert(token_hash, session);
        Ok(())
    }

    fn get(&self, token_hash: &[u8; 32]) -> Result<Option<Session>, StoreError> {
        Ok(self.0.lock().map_err(poisoned)?.get(token_hash).cloned())
    }

    fn touch(&self, token_hash: &[u8; 32], now: i64) -> Result<(), StoreError> {
        if let Some(s) = self.0.lock().map_err(poisoned)?.get_mut(token_hash) {
            s.last_used = now;
        }
        Ok(())
    }

    fn remove(&self, token_hash: &[u8; 32]) -> Result<(), StoreError> {
        self.0.lock().map_err(poisoned)?.remove(token_hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rootcard::messages::{CHALLENGE_LIFETIME, Purpose};

    fn issued(expires: i64) -> Issued {
        Issued {
            account: "a".into(),
            purpose: Purpose::Login,
            expires,
        }
    }

    /// Issuing challenges needs no authentication, so the store must not grow without bound.
    #[test]
    fn expired_challenges_are_dropped_on_insert() {
        let store = MemoryChallengeStore::new();
        let t = 1_800_000_000;
        for i in 0..100u8 {
            store.put([i; 32], issued(t + CHALLENGE_LIFETIME)).unwrap();
        }
        assert_eq!(store.len(), 100);
        // One lifetime later the old ones have just expired and are kept (they still answer `challenge_expired`).
        store.put([200; 32], issued(t + 2 * CHALLENGE_LIFETIME)).unwrap();
        assert_eq!(store.len(), 101);
        // Two lifetimes later they are gone.
        store.put([201; 32], issued(t + 3 * CHALLENGE_LIFETIME + 1)).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.take(&[0; 32]).unwrap().is_none());
        assert!(store.take(&[201; 32]).unwrap().is_some());
        // Extreme times do not overflow.
        store.put([202; 32], issued(i64::MIN)).unwrap();
        store.put([203; 32], issued(i64::MAX)).unwrap();
    }
}
