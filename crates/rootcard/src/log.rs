//! The identity log (SPEC §9) and versions (SPEC §10).

use crate::crypto::{ed25519_public, ed25519_sign, ed25519_verify, frame_map, sha256};
use crate::encoding::{base64url_decode, base64url_encode};
use crate::error::{Error, Result};
use crate::id::{account_id, check_realm, check_username, handle};
use crate::json::{MAX_SAFE, Map, Value, canonical_map};
use crate::keys::{KeyType, format_key, parse_key, schema};
use crate::label;

/// The maximum number of events in a log ([LOG-1]).
pub const MAX_EVENTS: usize = 1000;
/// The maximum canonical size of an event ([LOG-2]).
pub const EVENT_LIMIT: usize = 4096;
/// How far in the future an event's time may be ([LOG-12] step 4.6), in seconds.
pub const FUTURE_WINDOW: i64 = 600;

/// The version of a log: its last event ([VER-1]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// The `seq` of the last event.
    pub seq: u32,
    /// The event hash of the last event.
    pub hash: [u8; 32],
}

impl Version {
    /// `{ "seq": s, "hash": "<b64u>" }`
    pub fn to_value(&self) -> Value {
        Map::new()
            .with("seq", self.seq)
            .with("hash", base64url_encode(&self.hash))
            .into()
    }

    /// Parse a version. → `bad_field`
    pub fn from_value(v: &Value) -> Result<Version> {
        schema::version_ref(v)
    }
}

/// The `reason` of an `instance` event ([LOG-4]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The first instance.
    Register,
    /// Drops password locks.
    Revoke,
    /// Carries the vault over.
    Restore,
    /// Starts empty.
    Fresh,
}

impl Reason {
    /// The JSON string.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Register => "register",
            Reason::Revoke => "revoke",
            Reason::Restore => "restore",
            Reason::Fresh => "fresh",
        }
    }

    /// Parse a reason. → `bad_reason`
    pub fn parse(s: &str) -> Result<Reason> {
        Ok(match s {
            "register" => Reason::Register,
            "revoke" => Reason::Revoke,
            "restore" => Reason::Restore,
            "fresh" => Reason::Fresh,
            _ => return Err(Error::BadReason),
        })
    }
}

/// The home of an instance: the primary host's key and address ([LOG-4]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    /// The host key (Ed25519).
    pub key: [u8; 32],
    /// The host's address at the time of the instance.
    pub url: String,
}

impl Home {
    /// `{ "key": "ed25519:…", "url": … }`
    pub fn to_value(&self) -> Value {
        Map::new()
            .with("key", format_key(KeyType::Ed25519, &self.key))
            .with("url", self.url.as_str())
            .into()
    }

    fn from_map(m: &Map) -> Result<Home> {
        schema::members(m, &["key", "url"], &[])?;
        let key = schema::key(m, "key", KeyType::Ed25519)?;
        let url = schema::string(m, "url")?;
        check_url(url)?;
        Ok(Home {
            key,
            url: url.to_string(),
        })
    }
}

/// `home.url`: 1 to 256 printable ASCII characters ([LOG-4]). → `bad_field`
pub fn check_url(url: &str) -> Result<()> {
    if (1..=256).contains(&url.len()) && url.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        Ok(())
    } else {
        Err(Error::BadField)
    }
}

/// The current instance of a log ([LOG-10]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// The event hash of the `instance` event.
    pub hash: [u8; 32],
    /// Its `seq`.
    pub seq: u32,
    /// The account key (Ed25519).
    pub account_key: [u8; 32],
    /// The primary host.
    pub home: Home,
    /// Why the instance was created.
    pub reason: Reason,
}

/// The state of a verified log ([LOG-12] step 5). Plain data that a host can store ([LOG-16]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogState {
    /// The account id.
    pub account: String,
    /// The realm.
    pub realm: String,
    /// The username.
    pub username: String,
    /// The handle.
    pub handle: String,
    /// The current recovery key (Ed25519).
    pub recovery: [u8; 32],
    /// The current instance; absent if none or retired.
    pub instance: Option<Instance>,
    /// Whether the identity is retired.
    pub retired: bool,
    /// The version: the last event.
    pub version: Version,
    /// The time of the last event (0 for a log of only the inception).
    pub time: i64,
    /// Every recovery and account key so far.
    pub keys: Vec<[u8; 32]>,
    /// Every home key so far.
    pub homes: Vec<[u8; 32]>,
}

fn key_list(keys: &[[u8; 32]]) -> Value {
    Value::Array(keys.iter().map(|k| format_key(KeyType::Ed25519, k).into()).collect())
}

fn parse_key_list(v: &Value) -> Result<Vec<[u8; 32]>> {
    v.as_array()
        .ok_or(Error::BadField)?
        .iter()
        .map(|k| parse_key(k.as_str().ok_or(Error::BadField)?, KeyType::Ed25519))
        .collect()
}

impl LogState {
    /// The JSON form of the state ([LOG-16]).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new()
            .with("account", self.account.as_str())
            .with("realm", self.realm.as_str())
            .with("username", self.username.as_str())
            .with("handle", self.handle.as_str())
            .with("recovery", format_key(KeyType::Ed25519, &self.recovery))
            .with("retired", self.retired)
            .with("version", self.version.to_value())
            .with("time", self.time)
            .with("keys", key_list(&self.keys))
            .with("homes", key_list(&self.homes));
        if let Some(i) = &self.instance {
            m.insert(
                "instance",
                Map::new()
                    .with("hash", base64url_encode(&i.hash))
                    .with("seq", i.seq)
                    .with("account_key", format_key(KeyType::Ed25519, &i.account_key))
                    .with("home", i.home.to_value())
                    .with("reason", i.reason.as_str())
                    .into(),
            );
        }
        m.into()
    }

    /// Load a state stored by [`LogState::to_value`]. Only for states this party produced itself ([LOG-16]).
    pub fn from_value(v: &Value) -> Result<LogState> {
        let m = schema::obj(v)?;
        schema::members(
            m,
            &[
                "account", "realm", "username", "handle", "recovery", "retired", "version", "time", "keys", "homes",
            ],
            &["instance"],
        )?;
        let instance = match m.get("instance") {
            None => None,
            Some(i) => {
                let i = schema::obj(i)?;
                schema::members(i, &["hash", "seq", "account_key", "home", "reason"], &[])?;
                Some(Instance {
                    hash: schema::bytes::<32>(i, "hash")?,
                    seq: schema::int_in(i, "seq", 0, MAX_EVENTS as i64)? as u32,
                    account_key: schema::key(i, "account_key", KeyType::Ed25519)?,
                    home: Home::from_map(schema::object(i, "home")?)?,
                    reason: Reason::parse(schema::string(i, "reason")?)?,
                })
            }
        };
        Ok(LogState {
            account: schema::account(m, "account")?,
            realm: schema::string(m, "realm")?.to_string(),
            username: schema::string(m, "username")?.to_string(),
            handle: schema::string(m, "handle")?.to_string(),
            recovery: schema::key(m, "recovery", KeyType::Ed25519)?,
            instance,
            retired: schema::get(m, "retired")?.as_bool().ok_or(Error::BadField)?,
            version: Version::from_value(schema::get(m, "version")?)?,
            time: schema::int_in(m, "time", 0, MAX_SAFE)?,
            keys: parse_key_list(schema::get(m, "keys")?)?,
            homes: parse_key_list(schema::get(m, "homes")?)?,
        })
    }

    /// The current instance ([LOG-10]).
    pub fn current_instance(&self) -> Option<&Instance> {
        self.instance.as_ref()
    }
}

/// Options of [`verify_log`] and [`extend_log`].
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// The accepted realms ([RLM-3]).
    pub realms: Vec<String>,
    /// The current time; enables the future-time check ([LOG-12] step 4.6).
    pub now: Option<i64>,
}

impl VerifyOptions {
    /// Options accepting `realms`, without a time check.
    pub fn new<S: Into<String>>(realms: impl IntoIterator<Item = S>) -> Self {
        VerifyOptions {
            realms: realms.into_iter().map(Into::into).collect(),
            now: None,
        }
    }

    /// The same options with `now`.
    pub fn at(mut self, now: i64) -> Self {
        self.now = Some(now);
        self
    }
}

/// The event hash ([LOG-5]): `SHA-256(frame("rootcard/event/v1", e without sigs))`.
pub fn event_hash(e: &Map) -> [u8; 32] {
    sha256(&event_message(e))
}

/// The message owners sign on an event ([LOG-6]).
pub fn event_message(e: &Map) -> Vec<u8> {
    frame_map(&label("event", 1), &e.without("sigs"))
}

/// The message the primary host signs as its receipt ([LOG-8]).
pub fn receipt_message(e: &Map) -> Vec<u8> {
    frame_map(&label("receipt", 1), &e.without("sigs"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Incept,
    Instance,
    RotateRecovery,
    Retire,
}

/// One event after its schema check ([LOG-12] step 2).
struct Event<'a> {
    map: &'a Map,
    kind: Kind,
    seq: i64,
    account: Option<String>,
    prev: Option<[u8; 32]>,
    time: i64,
    sigs: Vec<([u8; 32], [u8; 64])>,
    // body
    realm: String,
    username: String,
    recovery: Option<[u8; 32]>,
    account_key: Option<[u8; 32]>,
    home: Option<Home>,
    reason: Option<Reason>,
}

fn parse_event(v: &Value, index: usize) -> Result<Event<'_>> {
    if let Value::Object(m) = v
        && canonical_map(m).len() > EVENT_LIMIT
    {
        return Err(Error::TooLarge);
    }
    let m = schema::obj(v)?;
    schema::version(m)?;
    let kind = match schema::string(m, "kind")? {
        "incept" => Kind::Incept,
        "instance" => Kind::Instance,
        "rotate_recovery" => Kind::RotateRecovery,
        "retire" => Kind::Retire,
        _ => return Err(Error::BadKind),
    };
    if (index == 0) != (kind == Kind::Incept) {
        return Err(Error::BadKind);
    }
    if kind == Kind::Incept {
        schema::members(m, &["v", "kind", "seq", "body", "sigs"], &[])?;
    } else {
        schema::members(m, &["v", "account", "seq", "prev", "kind", "time", "body", "sigs"], &[])?;
    }
    let seq = schema::int_in(m, "seq", 0, MAX_SAFE)?;
    let (account, prev, time) = if kind == Kind::Incept {
        (None, None, 0)
    } else {
        (
            Some(schema::account(m, "account")?),
            Some(schema::bytes::<32>(m, "prev")?),
            schema::int_in(m, "time", 0, MAX_SAFE)?,
        )
    };
    let mut sigs = Vec::new();
    for s in schema::array(m, "sigs")? {
        let s = schema::obj(s)?;
        schema::members(s, &["key", "sig"], &[])?;
        sigs.push((schema::key(s, "key", KeyType::Ed25519)?, schema::sig(s, "sig")?));
    }
    let body = schema::object(m, "body")?;
    let mut e = Event {
        map: m,
        kind,
        seq,
        account,
        prev,
        time,
        sigs,
        realm: String::new(),
        username: String::new(),
        recovery: None,
        account_key: None,
        home: None,
        reason: None,
    };
    match kind {
        Kind::Incept => {
            schema::members(body, &["realm", "username", "recovery"], &[])?;
            e.realm = schema::string(body, "realm")?.to_string();
            e.username = schema::string(body, "username")?.to_string();
            e.recovery = Some(schema::key(body, "recovery", KeyType::Ed25519)?);
        }
        Kind::Instance => {
            schema::members(body, &["account_key", "home", "reason"], &[])?;
            e.account_key = Some(schema::key(body, "account_key", KeyType::Ed25519)?);
            e.home = Some(Home::from_map(schema::object(body, "home")?)?);
            e.reason = Some(Reason::parse(schema::string(body, "reason")?)?);
        }
        Kind::RotateRecovery => {
            schema::members(body, &["recovery"], &[])?;
            e.recovery = Some(schema::key(body, "recovery", KeyType::Ed25519)?);
        }
        Kind::Retire => schema::members(body, &[], &[])?,
    }
    Ok(e)
}

fn check_length(n: usize) -> Result<()> {
    if n == 0 {
        Err(Error::BadField)
    } else if n > MAX_EVENTS {
        Err(Error::TooManyEvents)
    } else {
        Ok(())
    }
}

/// How the receipt of an `instance` event is treated.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Receipt {
    Required,
    Pending,
}

/// [LOG-12] step 4 for one event at `index`, applying its effect to `st`.
fn apply(st: &mut LogState, e: &Event<'_>, index: usize, now: Option<i64>, receipt: Receipt) -> Result<()> {
    if st.retired {
        return Err(Error::AccountRetired);
    }
    if e.account.as_deref() != Some(st.account.as_str()) {
        return Err(Error::AccountMismatch);
    }
    if e.seq != index as i64 {
        return Err(Error::BadSeq);
    }
    if e.prev != Some(st.version.hash) {
        return Err(Error::BadPrev);
    }
    if e.time < st.time {
        return Err(Error::TimeBackwards);
    }
    if let Some(now) = now
        && e.time > now.saturating_add(FUTURE_WINDOW)
    {
        return Err(Error::FutureTime);
    }
    // 4.7 the exact signers, in order.
    let expected: Vec<[u8; 32]> = match e.kind {
        Kind::Instance => {
            let mut v = vec![st.recovery, e.account_key.unwrap_or_default()];
            if receipt == Receipt::Required {
                v.push(e.home.as_ref().map(|h| h.key).unwrap_or_default());
            }
            v
        }
        Kind::RotateRecovery => vec![st.recovery, e.recovery.unwrap_or_default()],
        Kind::Retire => vec![st.recovery],
        Kind::Incept => return Err(Error::BadKind),
    };
    if e.sigs.len() != expected.len() || e.sigs.iter().zip(&expected).any(|((k, _), x)| k != x) {
        return Err(Error::WrongSigner);
    }
    // 4.8 no key reuse.
    match e.kind {
        Kind::Instance => {
            let ak = e.account_key.unwrap_or_default();
            let hk = e.home.as_ref().map(|h| h.key).unwrap_or_default();
            if ak == hk || st.keys.contains(&ak) || st.homes.contains(&ak) || st.keys.contains(&hk) {
                return Err(Error::KeyReuse);
            }
        }
        Kind::RotateRecovery => {
            let r = e.recovery.unwrap_or_default();
            if st.keys.contains(&r) || st.homes.contains(&r) {
                return Err(Error::KeyReuse);
            }
        }
        _ => {}
    }
    // 4.9 reason ([LOG-11]).
    if let Some(reason) = e.reason {
        let has = st.instance.is_some();
        let ok = match reason {
            Reason::Register => !has,
            Reason::Revoke | Reason::Restore => has,
            Reason::Fresh => true,
        };
        if !ok {
            return Err(Error::BadReason);
        }
    }
    // 4.10 signatures.
    let msg = event_message(e.map);
    let owners = if e.kind == Kind::Instance { 2 } else { e.sigs.len() };
    for (k, s) in &e.sigs[..owners] {
        ed25519_verify(k, &msg, s)?;
    }
    if e.kind == Kind::Instance && receipt == Receipt::Required {
        let (k, s) = &e.sigs[2];
        ed25519_verify(k, &receipt_message(e.map), s).map_err(|_| Error::BadReceipt)?;
    }
    // 4.11 effect.
    let hash = sha256(&msg);
    match e.kind {
        Kind::Instance => {
            let ak = e.account_key.unwrap_or_default();
            let home = e.home.clone().unwrap_or(Home {
                key: [0; 32],
                url: String::new(),
            });
            st.keys.push(ak);
            if !st.homes.contains(&home.key) {
                st.homes.push(home.key);
            }
            st.instance = Some(Instance {
                hash,
                seq: index as u32,
                account_key: ak,
                home,
                reason: e.reason.unwrap_or(Reason::Fresh),
            });
        }
        Kind::RotateRecovery => {
            let r = e.recovery.unwrap_or_default();
            st.recovery = r;
            st.keys.push(r);
        }
        Kind::Retire => {
            st.retired = true;
            st.instance = None;
        }
        Kind::Incept => {}
    }
    st.time = e.time;
    st.version = Version {
        seq: index as u32,
        hash,
    };
    Ok(())
}

/// Verify a whole log ([LOG-12]) and return its state.
pub fn verify_log(events: &[Value], options: &VerifyOptions) -> Result<LogState> {
    check_length(events.len())?;
    let parsed = events
        .iter()
        .enumerate()
        .map(|(i, v)| parse_event(v, i))
        .collect::<Result<Vec<_>>>()?;
    let inc = &parsed[0];
    if inc.seq != 0 {
        return Err(Error::BadSeq);
    }
    check_realm(&inc.realm)?;
    if !options.realms.contains(&inc.realm) {
        return Err(Error::RealmNotAccepted);
    }
    check_username(&inc.username)?;
    let recovery = inc.recovery.unwrap_or_default();
    if inc.sigs.len() != 1 || inc.sigs[0].0 != recovery {
        return Err(Error::WrongSigner);
    }
    let msg = event_message(inc.map);
    ed25519_verify(&recovery, &msg, &inc.sigs[0].1)?;
    let account = account_id(inc.map);
    let mut st = LogState {
        handle: handle(&inc.username, &account),
        account,
        realm: inc.realm.clone(),
        username: inc.username.clone(),
        recovery,
        instance: None,
        retired: false,
        version: Version {
            seq: 0,
            hash: sha256(&msg),
        },
        time: 0,
        keys: vec![recovery],
        homes: Vec::new(),
    };
    for (i, e) in parsed.iter().enumerate().skip(1) {
        apply(&mut st, e, i, options.now, Receipt::Required)?;
    }
    Ok(st)
}

/// Verify events that extend a verified log state ([LOG-15]). The result equals [`verify_log`] on the whole log.
pub fn extend_log(state: &LogState, events: &[Value], options: &VerifyOptions) -> Result<LogState> {
    let start = state.version.seq as usize + 1;
    if start + events.len() > MAX_EVENTS {
        return Err(Error::TooManyEvents);
    }
    let parsed = events
        .iter()
        .enumerate()
        .map(|(i, v)| parse_event(v, start + i))
        .collect::<Result<Vec<_>>>()?;
    let mut st = state.clone();
    for (i, e) in parsed.iter().enumerate() {
        apply(&mut st, e, start + i, options.now, Receipt::Required)?;
    }
    Ok(st)
}

/// Check a pending instance against the log it extends ([LOG-9]): like [LOG-12] step 4 with `now`, with the two owner
/// signatures and no receipt.
pub fn verify_pending(state: &LogState, event: &Value, now: i64) -> Result<()> {
    let index = state.version.seq as usize + 1;
    if index >= MAX_EVENTS {
        return Err(Error::TooManyEvents);
    }
    let e = parse_event(event, index)?;
    if e.kind != Kind::Instance {
        return Err(Error::BadKind);
    }
    let mut st = state.clone();
    apply(&mut st, &e, index, Some(now), Receipt::Pending)
}

/// The order of two logs of one account ([VER-2]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOrder {
    /// The same log.
    Same,
    /// The second log extends the first.
    Newer,
    /// The first log extends the second.
    Older,
    /// Neither extends the other.
    Fork,
}

impl LogOrder {
    /// `same`, `newer`, `older` or `fork`.
    pub fn as_str(self) -> &'static str {
        match self {
            LogOrder::Same => "same",
            LogOrder::Newer => "newer",
            LogOrder::Older => "older",
            LogOrder::Fork => "fork",
        }
    }
}

fn event_map(v: &Value) -> Result<&Map> {
    v.as_object().ok_or(Error::BadField)
}

/// Compare two valid logs of the same account ([VER-2]): `b` relative to `a`. → `account_mismatch`
pub fn compare_logs(a: &[Value], b: &[Value]) -> Result<LogOrder> {
    let (Some(a0), Some(b0)) = (a.first(), b.first()) else {
        return Err(Error::BadField);
    };
    if account_id(event_map(a0)?) != account_id(event_map(b0)?) {
        return Err(Error::AccountMismatch);
    }
    let h = |v: &Value| event_map(v).map(event_hash);
    let (short, long, order) = match a.len().cmp(&b.len()) {
        core::cmp::Ordering::Equal => {
            return Ok(if h(&a[a.len() - 1])? == h(&b[b.len() - 1])? {
                LogOrder::Same
            } else {
                LogOrder::Fork
            });
        }
        core::cmp::Ordering::Less => (a, b, LogOrder::Newer),
        core::cmp::Ordering::Greater => (b, a, LogOrder::Older),
    };
    Ok(if h(&short[short.len() - 1])? == h(&long[short.len() - 1])? {
        order
    } else {
        LogOrder::Fork
    })
}

/// An unsigned event after `state` (`sigs` empty), to be signed with [`sign_event`].
pub fn unsigned_event(state: &LogState, kind: &str, body: Map, time: i64) -> Map {
    Map::new()
        .with("v", 1i64)
        .with("account", state.account.as_str())
        .with("seq", i64::from(state.version.seq) + 1)
        .with("prev", base64url_encode(&state.version.hash))
        .with("kind", kind)
        .with("time", time)
        .with("body", body)
        .with("sigs", Value::Array(Vec::new()))
}

fn push_sig(e: &mut Map, key: [u8; 32], sig: [u8; 64]) {
    let entry: Value = Map::new()
        .with("key", format_key(KeyType::Ed25519, &key))
        .with("sig", base64url_encode(&sig))
        .into();
    let mut sigs = e.get("sigs").and_then(Value::as_array).cloned().unwrap_or_default();
    sigs.push(entry);
    e.insert("sigs", Value::Array(sigs));
}

/// Append an owner signature ([LOG-6]) with the key of `seed`.
pub fn sign_event(e: &mut Map, seed: &[u8; 32]) {
    let sig = ed25519_sign(seed, &event_message(e));
    push_sig(e, ed25519_public(seed), sig);
}

/// Append the primary host's receipt ([LOG-8]) with the host key of `host_seed`.
pub fn add_receipt(e: &mut Map, host_seed: &[u8; 32]) {
    let sig = ed25519_sign(host_seed, &receipt_message(e));
    push_sig(e, ed25519_public(host_seed), sig);
}

/// [RK-5]: the recovery signing key of `seed` is the log's current recovery key. → `wrong_recovery_key`
pub fn check_recovery_key(state: &LogState, seed: &[u8; 32]) -> Result<()> {
    if ed25519_public(seed) == state.recovery {
        Ok(())
    } else {
        Err(Error::WrongRecoveryKey)
    }
}

/// A pending instance ([LOG-9]) after `state`, signed by the current recovery key and the new account key.
/// → `wrong_recovery_key`, `bad_field`
pub fn pending_instance(
    state: &LogState,
    recovery_seed: &[u8; 32],
    account_seed: &[u8; 32],
    home: &Home,
    reason: Reason,
    time: i64,
) -> Result<Map> {
    check_recovery_key(state, recovery_seed)?;
    check_url(&home.url)?;
    let body = Map::new()
        .with(
            "account_key",
            format_key(KeyType::Ed25519, &ed25519_public(account_seed)),
        )
        .with("home", home.to_value())
        .with("reason", reason.as_str());
    let mut e = unsigned_event(state, "instance", body, time);
    sign_event(&mut e, recovery_seed);
    sign_event(&mut e, account_seed);
    Ok(e)
}

/// A `rotate_recovery` event after `state`, signed by the old and the new recovery key ([KT-5]).
pub fn rotate_recovery_event(state: &LogState, old_seed: &[u8; 32], new_seed: &[u8; 32], time: i64) -> Result<Map> {
    check_recovery_key(state, old_seed)?;
    let body = Map::new().with("recovery", format_key(KeyType::Ed25519, &ed25519_public(new_seed)));
    let mut e = unsigned_event(state, "rotate_recovery", body, time);
    sign_event(&mut e, old_seed);
    sign_event(&mut e, new_seed);
    Ok(e)
}

/// A `retire` event after `state` ([KT-6]).
pub fn retire_event(state: &LogState, recovery_seed: &[u8; 32], time: i64) -> Result<Map> {
    check_recovery_key(state, recovery_seed)?;
    let mut e = unsigned_event(state, "retire", Map::new(), time);
    sign_event(&mut e, recovery_seed);
    Ok(e)
}

/// Decode the `prev` of an event, if it has one.
pub fn event_prev(e: &Map) -> Option<[u8; 32]> {
    let v = base64url_decode(e.get("prev")?.as_str()?).ok()?;
    v.try_into().ok()
}
