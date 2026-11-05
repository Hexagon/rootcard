//! Cryptographic primitives (SPEC §4) and domain separation (SPEC §5), as thin wrappers over audited crates.

use crate::error::{Error, Result};
use crate::json::{Map, canonical_map};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// `frame(label, m) = utf8(label) ‖ 0x00 ‖ m` ([DS-1]).
pub fn frame(label: &str, m: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 1 + m.len());
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out.extend_from_slice(m);
    out
}

/// `frame(label, canonical(x))` for an object.
pub fn frame_map(label: &str, m: &Map) -> Vec<u8> {
    frame(label, &canonical_map(m))
}

/// SHA-256.
pub fn sha256(m: &[u8]) -> [u8; 32] {
    Sha256::digest(m).into()
}

/// HKDF-SHA256 with a 32-byte output ([CRY-5]).
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0u8; 32]);
    let h = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    // 32 bytes is always a valid HKDF-SHA256 output length.
    let _ = h.expand(info, okm.as_mut());
    okm
}

/// The group order L of Ed25519, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The canonical encodings of the eight points of small order ([CRY-3] step 4).
const SMALL_ORDER: [[u8; 32]; 8] = {
    const fn h(s: &[u8; 64]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
            i += 1;
        }
        out
    }
    const fn nib(c: u8) -> u8 {
        if c >= b'a' { c - b'a' + 10 } else { c - b'0' }
    }
    [
        h(b"0100000000000000000000000000000000000000000000000000000000000000"),
        h(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        h(b"0000000000000000000000000000000000000000000000000000000000000000"),
        h(b"0000000000000000000000000000000000000000000000000000000000000080"),
        h(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        h(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        h(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        h(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    ]
};

/// Compare two little-endian 256-bit integers: `a < b`.
fn lt_le(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// [CRY-3] step 3: the low 255 bits are < p, and the encoding is not `x = 0` with the sign bit set.
fn is_canonical_point(e: &[u8; 32]) -> bool {
    let mut y = *e;
    y[31] &= 0x7f;
    // p = 2^255 - 19, little-endian: ed ff .. ff 7f
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    if !lt_le(&y, &p) {
        return false;
    }
    let mut neg_zero_1 = [0u8; 32];
    neg_zero_1[0] = 1;
    neg_zero_1[31] = 0x80;
    let mut neg_zero_2 = [0xffu8; 32];
    neg_zero_2[0] = 0xec;
    *e != neg_zero_1 && *e != neg_zero_2
}

/// [CRY-3] steps 3 and 4 for an encoded point: canonical and not of small order (also [KEY-3]).
pub fn ed25519_point_ok(e: &[u8; 32]) -> bool {
    is_canonical_point(e) && !SMALL_ORDER.contains(e)
}

/// The Ed25519 public key of a 32-byte seed ([CRY-2]).
pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A deterministic Ed25519 signature ([CRY-8]).
pub fn ed25519_sign(seed: &[u8; 32], m: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    ed25519_dalek::SigningKey::from_bytes(seed).sign(m).to_bytes()
}

/// Strict Ed25519 verification ([CRY-3]). → `bad_signature`
pub fn ed25519_verify(public: &[u8], m: &[u8], sig: &[u8]) -> Result<()> {
    let a: &[u8; 32] = public.try_into().map_err(|_| Error::BadSignature)?;
    let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    if !lt_le(&s, &L) || !ed25519_point_ok(a) || !ed25519_point_ok(&r) {
        return Err(Error::BadSignature);
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(a).map_err(|_| Error::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    key.verify_strict(m, &sig).map_err(|_| Error::BadSignature)
}

/// The X25519 public key of a 32-byte secret (clamped, [CRY-2]).
#[cfg(feature = "vault")]
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    x25519_dalek::PublicKey::from(&s).to_bytes()
}

/// X25519 key agreement; an all-zero result fails ([CRY-4]). → `bad_key`
#[cfg(feature = "vault")]
pub fn x25519(secret: &[u8; 32], public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let s = x25519_dalek::StaticSecret::from(*secret);
    let shared = Zeroizing::new(s.diffie_hellman(&x25519_dalek::PublicKey::from(*public)).to_bytes());
    if shared.iter().all(|b| *b == 0) {
        return Err(Error::BadKey);
    }
    Ok(shared)
}

/// AES-256-GCM encryption: ciphertext ‖ 16-byte tag ([CRY-7]). It fails only for inputs beyond AES-GCM's limits
/// (about 64 GiB), far above every size limit of the format, and then fails rather than returning anything. → `too_large`
#[cfg(feature = "vault")]
pub fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher = aes_gcm::Aes256Gcm::new(&(*key).into());
    cipher
        .encrypt(&(*nonce).into(), Payload { msg: plaintext, aad })
        .map_err(|_| Error::TooLarge)
}

/// AES-256-GCM decryption; a failed tag check fails. → `unlock_failed`
#[cfg(feature = "vault")]
pub fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher = aes_gcm::Aes256Gcm::new(&(*key).into());
    cipher
        .decrypt(&(*nonce).into(), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::UnlockFailed)
}

/// Argon2id, version 0x13, no secret, no associated data, 32-byte tag ([CRY-6]). `m` in KiB. → `kdf_params`
#[cfg(feature = "vault")]
pub fn argon2id(password: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(m, t, p, Some(32)).map_err(|_| Error::KdfParams)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::KdfParams)?;
    Ok(out)
}

/// Constant-time equality of two byte strings of equal length ([IMP-4]).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    core::hint::black_box(d) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{hex_decode, hex_encode};

    fn h(s: &str) -> Vec<u8> {
        hex_decode(s).unwrap()
    }

    #[test]
    fn rfc8032_test_1() {
        let seed: [u8; 32] = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .try_into()
            .unwrap();
        let pk = ed25519_public(&seed);
        assert_eq!(
            hex_encode(&pk),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = ed25519_sign(&seed, b"");
        assert_eq!(
            hex_encode(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(ed25519_verify(&pk, b"", &sig).is_ok());
        assert_eq!(ed25519_verify(&pk, b"x", &sig), Err(Error::BadSignature));
        for so in SMALL_ORDER {
            assert!(!ed25519_point_ok(&so));
        }
    }

    #[test]
    fn rfc5869_case_1_prefix() {
        let okm = hkdf(
            &[0x0b; 22],
            &h("000102030405060708090a0b0c"),
            &h("f0f1f2f3f4f5f6f7f8f9"),
        );
        assert_eq!(
            hex_encode(okm.as_ref()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn rfc9106_argon2id() {
        // RFC 9106 §5.3 uses a secret and associated data, which rootcard does not; the crate supports both.
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
            .build()
            .unwrap();
        let a2 = argon2::Argon2::new_with_secret(&[3; 8], argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .unwrap();
        let mut out = [0u8; 32];
        a2.hash_password_into(&[1; 32], &[2; 16], &mut out).unwrap();
        assert_eq!(
            hex_encode(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn rfc7748_x25519() {
        let k: [u8; 32] = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
            .try_into()
            .unwrap();
        let u: [u8; 32] = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
            .try_into()
            .unwrap();
        assert_eq!(
            hex_encode(x25519(&k, &u).unwrap().as_ref()),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
        assert_eq!(x25519(&k, &[0; 32]).map(|_| ()), Err(Error::BadKey));
    }
}
