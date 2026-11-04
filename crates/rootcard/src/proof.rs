//! Proofs of identity (SPEC §14).

use crate::crypto::{ed25519_sign, ed25519_verify, frame_map, sha256};
use crate::encoding::base64url_encode;
use crate::error::{Error, Result};
use crate::json::{Map, Value};
use crate::keys::schema;
use crate::label;
use crate::log::{LogState, VerifyOptions, verify_log};

/// Who signs a proof ([PRF-1], [PRF-2]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBy {
    /// The account key of the current instance.
    Account,
    /// The current recovery signing key (key tool only).
    Recovery,
}

impl ProofBy {
    /// `account` or `recovery`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProofBy::Account => "account",
            ProofBy::Recovery => "recovery",
        }
    }
}

/// `challenge = SHA-256(frame("rootcard/statement/v1", { "statement": statement }))` ([PRF-5]). → `bad_json`
pub fn statement_challenge(statement: &Value) -> Result<[u8; 32]> {
    statement.validate()?;
    let m = Map::new().with("statement", statement.clone());
    Ok(sha256(&frame_map(&label("statement", 1), &m)))
}

/// A recipient is 1 to 256 UTF-8 bytes ([PRF-3]). → `bad_field`
fn check_recipient(r: &str) -> Result<()> {
    if (1..=256).contains(&r.len()) {
        Ok(())
    } else {
        Err(Error::BadField)
    }
}

/// Make a proof ([PRF-1], [PRF-2]). For `Account`, `seed` is the account key of the current instance; for `Recovery`,
/// the recovery signing key. → `no_instance`, `wrong_account_key`, `wrong_recovery_key`, `bad_field`
pub fn prove(state: &LogState, by: ProofBy, seed: &[u8; 32], challenge: &[u8; 32], recipient: &str) -> Result<Value> {
    check_recipient(recipient)?;
    let public = crate::crypto::ed25519_public(seed);
    let mut m = Map::new()
        .with("v", 1i64)
        .with("by", by.as_str())
        .with("account", state.account.as_str())
        .with("challenge", base64url_encode(challenge))
        .with("recipient", recipient);
    match by {
        ProofBy::Account => {
            let inst = state.instance.as_ref().ok_or(Error::NoInstance)?;
            if inst.account_key != public {
                return Err(Error::WrongAccountKey);
            }
            m.insert("instance", base64url_encode(&inst.hash).into());
        }
        ProofBy::Recovery => crate::log::check_recovery_key(state, seed)?,
    }
    let sig = ed25519_sign(seed, &frame_map(&label("proof", 1), &m));
    Ok(m.with("sig", base64url_encode(&sig)).into())
}

/// Verify a proof against the newest log the verifier knows ([PRF-4]). Returns the log state.
pub fn verify_proof(
    proof: &Value,
    log: &[Value],
    challenge: &[u8; 32],
    recipient: &str,
    options: &VerifyOptions,
) -> Result<LogState> {
    let m = schema::obj(proof)?;
    schema::version(m)?;
    let by = match schema::string(m, "by")? {
        "account" => ProofBy::Account,
        "recovery" => ProofBy::Recovery,
        _ => return Err(Error::BadField),
    };
    if by == ProofBy::Account {
        schema::members(
            m,
            &["v", "by", "account", "instance", "challenge", "recipient", "sig"],
            &[],
        )?;
    } else {
        schema::members(m, &["v", "by", "account", "challenge", "recipient", "sig"], &[])?;
    }
    let account = schema::account(m, "account")?;
    let instance = if by == ProofBy::Account {
        Some(schema::bytes::<32>(m, "instance")?)
    } else {
        None
    };
    let got_challenge = schema::bytes::<32>(m, "challenge")?;
    let got_recipient = schema::string(m, "recipient")?;
    check_recipient(got_recipient)?;
    let sig = schema::sig(m, "sig")?;
    let state = verify_log(log, options)?;
    if account != state.account {
        return Err(Error::AccountMismatch);
    }
    if state.retired {
        return Err(Error::AccountRetired);
    }
    if got_challenge != *challenge {
        return Err(Error::WrongChallenge);
    }
    if got_recipient != recipient {
        return Err(Error::WrongRecipient);
    }
    let key = match by {
        ProofBy::Account => {
            let inst = state.instance.as_ref().ok_or(Error::NoInstance)?;
            if instance != Some(inst.hash) {
                return Err(Error::StaleVersion);
            }
            inst.account_key
        }
        ProofBy::Recovery => state.recovery,
    };
    ed25519_verify(&key, &frame_map(&label("proof", 1), &m.without("sig")), &sig)?;
    Ok(state)
}
