//! Signed peer requests (HOST_PROTOCOL.md §5, label `rootcard/peer/v1`).

use rootcard::Error;
use rootcard::crypto::{ed25519_public, ed25519_sign, ed25519_verify, frame_map, sha256};
use rootcard::encoding::{base64url_decode, base64url_encode};
use rootcard::json::Map;
use rootcard::keys::{KeyType, format_key, parse_key};
use rootcard::label;

/// How far a peer request's time may be from the receiver's clock, in seconds.
pub const PEER_WINDOW: i64 = 60;

/// The headers of a signed peer request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHeaders {
    /// `Rootcard-Peer-Key`
    pub key: String,
    /// `Rootcard-Peer-Time`
    pub time: i64,
    /// `Rootcard-Peer-Sig`
    pub sig: String,
}

fn message(method: &str, path: &str, time: i64, to: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let m = Map::new()
        .with("method", method)
        .with("path", path)
        .with("time", time)
        .with("to", format_key(KeyType::Ed25519, to))
        .with("body", base64url_encode(&sha256(body)));
    frame_map(&label("peer", 1), &m)
}

/// Sign a peer request to the host with key `to`.
pub fn sign_peer_request(
    seed: &[u8; 32],
    method: &str,
    path: &str,
    time: i64,
    to: &[u8; 32],
    body: &[u8],
) -> PeerHeaders {
    PeerHeaders {
        key: format_key(KeyType::Ed25519, &ed25519_public(seed)),
        time,
        sig: base64url_encode(&ed25519_sign(seed, &message(method, path, time, to, body))),
    }
}

/// Verify a peer request received by the host with key `own` from one of `peers`. Returns the sender's key.
/// → `unauthorized`
pub fn verify_peer_request(
    headers: &PeerHeaders,
    peers: &[[u8; 32]],
    own: &[u8; 32],
    method: &str,
    path: &str,
    body: &[u8],
    now: i64,
) -> Result<[u8; 32], Error> {
    let key = parse_key(&headers.key, KeyType::Ed25519).map_err(|_| Error::Unauthorized)?;
    if !peers.contains(&key) || (headers.time - now).abs() > PEER_WINDOW {
        return Err(Error::Unauthorized);
    }
    let sig = base64url_decode(&headers.sig).map_err(|_| Error::Unauthorized)?;
    ed25519_verify(&key, &message(method, path, headers.time, own, body), &sig).map_err(|_| Error::Unauthorized)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_requests() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let (pa, pb) = (ed25519_public(&a), ed25519_public(&b));
        let h = sign_peer_request(&a, "POST", "/v0/peer/push", 100, &pb, b"{}");
        assert_eq!(
            verify_peer_request(&h, &[pa], &pb, "POST", "/v0/peer/push", b"{}", 130),
            Ok(pa)
        );
        assert_eq!(
            verify_peer_request(&h, &[pa], &pb, "POST", "/v0/peer/push", b"{} ", 130),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            verify_peer_request(&h, &[], &pb, "POST", "/v0/peer/push", b"{}", 130),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            verify_peer_request(&h, &[pa], &pb, "POST", "/v0/peer/push", b"{}", 200),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            verify_peer_request(&h, &[pa], &pa, "POST", "/v0/peer/push", b"{}", 130),
            Err(Error::Unauthorized)
        );
    }
}
