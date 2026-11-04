//! Byte encodings (SPEC §3): unpadded base64url and Crockford base32.

use crate::error::{Error, Result};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url ([B64-1]).
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn b64_value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    } as u32)
}

/// Strict unpadded base64url decoding ([B64-2]). → `bad_base64`
pub fn base64url_decode(text: &str) -> Result<Vec<u8>> {
    let s = text.as_bytes();
    if s.len() % 4 == 1 {
        return Err(Error::BadBase64);
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= b64_value(c).ok_or(Error::BadBase64)? << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let len = chunk.len() - 1;
        // Unused bits in the last character must be zero.
        let unused = match len {
            1 => n & 0xFFFF,
            2 => n & 0xFF,
            _ => 0,
        };
        if unused != 0 {
            return Err(Error::BadBase64);
        }
        out.extend_from_slice(&bytes[..len]);
    }
    Ok(out)
}

/// Strict base64url decoding of exactly `N` bytes ([B64-3]). → `bad_base64`
pub fn base64url_decode_fixed<const N: usize>(text: &str) -> Result<[u8; N]> {
    let v = base64url_decode(text)?;
    v.try_into().map_err(|_| Error::BadBase64)
}

/// The Crockford base32 alphabet ([B32-1]).
pub const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford base32, big-endian, zero-padded final group ([B32-2]).
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Strict Crockford base32 decoding of exactly `len` bytes ([B32-3]). → `bad_base32`
pub fn base32_decode(text: &str, len: usize) -> Result<Vec<u8>> {
    let s = text.as_bytes();
    if s.len() != (len * 8).div_ceil(5) {
        return Err(Error::BadBase32);
    }
    let mut out = Vec::with_capacity(len);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s {
        let v = B32.iter().position(|&a| a == c).ok_or(Error::BadBase32)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(Error::BadBase32);
    }
    Ok(out)
}

/// The lenient normalization of typed base32 ([B32-4]): upper case, `I`/`L` → `1`, `O` → `0`, no `-` or spaces.
pub fn base32_normalize(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect()
}

/// Lenient Crockford base32 decoding for human input ([B32-4]). → `bad_base32`
pub fn base32_decode_lenient(text: &str, len: usize) -> Result<Vec<u8>> {
    base32_decode(&base32_normalize(text), len)
}

/// Lower-case hexadecimal (used by the vectors and the key tool).
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Decode lower- or upper-case hexadecimal. → `bad_field`
pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let s = text.as_bytes();
    if !s.len().is_multiple_of(2) {
        return Err(Error::BadField);
    }
    s.chunks(2)
        .map(|p| {
            let h = (p[0] as char).to_digit(16).ok_or(Error::BadField)?;
            let l = (p[1] as char).to_digit(16).ok_or(Error::BadField)?;
            Ok((h * 16 + l) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
        ] {
            assert_eq!(base64url_encode(raw.as_bytes()), enc);
            assert_eq!(base64url_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        for bad in ["Zh", "Zm9=", "Z", "Zm+v", "Zm/v", "Zm9vY"] {
            assert_eq!(base64url_decode(bad), Err(Error::BadBase64), "{bad}");
        }
    }

    #[test]
    fn base32() {
        let k = [0xffu8; 32];
        let e = base32_encode(&k);
        assert_eq!(e.len(), 52);
        assert!(e.ends_with('G'));
        assert_eq!(base32_decode(&e, 32).unwrap(), k);
        assert_eq!(base32_decode("ZZ", 1), Err(Error::BadBase32));
        assert_eq!(base32_decode("zw", 1), Err(Error::BadBase32));
        assert_eq!(base32_decode_lenient("zw", 1).unwrap(), [0xff]);
        assert_eq!(base32_decode_lenient("U0", 1), Err(Error::BadBase32));
        assert_eq!(base32_normalize("o-iL "), "011");
    }
}
