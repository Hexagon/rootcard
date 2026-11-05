//! The HTTP binding's version and base URLs (HOST_PROTOCOL.md §1, §1.3; SPEC [HST-22]). The core makes no requests;
//! these let hosts, clients and the key tool agree on where endpoints live.

use crate::log::check_url;
use crate::{Error, Result};

/// The version segment of the HTTP binding: every endpoint is under `<base URL>/v0` until 1.0.0, then under `/v1`.
/// It is never part of a base URL, `home.url` or anything signed.
pub const API_VERSION: &str = "v0";

/// Check a base URL ([HST-22]): `https://` and a host, an optional port and an optional path without a trailing
/// slash, query, fragment or user info; plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`; and its last path
/// segment is not an API version segment (`v` followed by digits). → `bad_field`
pub fn check_base_url(url: &str) -> Result<()> {
    check_url(url)?;
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        let host = authority_host(r);
        if !["localhost", "127.0.0.1", "[::1]"].contains(&host) {
            return Err(Error::BadField);
        }
        r
    } else {
        return Err(Error::BadField);
    };
    if rest.contains(['?', '#', '@', '\\']) {
        return Err(Error::BadField);
    }
    let (authority, path) = rest.split_once('/').map_or((rest, None), |(a, p)| (a, Some(p)));
    if authority_host(authority).is_empty() || !authority.bytes().all(authority_byte) {
        return Err(Error::BadField);
    }
    if let Some(path) = path {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.iter().any(|s| s.is_empty()) {
            return Err(Error::BadField);
        }
        if segments.last().is_some_and(|s| is_version_segment(s)) {
            return Err(Error::BadField);
        }
    }
    Ok(())
}

/// Whether a path segment has the form of an API version (`v0`, `V12`).
pub fn is_version_segment(segment: &str) -> bool {
    let b = segment.as_bytes();
    b.len() >= 2 && (b[0] == b'v' || b[0] == b'V') && b[1..].iter().all(u8::is_ascii_digit)
}

fn authority_host(rest: &str) -> &str {
    let authority = rest.split('/').next().unwrap_or("");
    if authority.starts_with('[') {
        authority.find(']').map_or("", |i| &authority[..=i])
    } else {
        authority.split(':').next().unwrap_or("")
    }
}

fn authority_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls() {
        for ok in [
            "https://id.example.com",
            "https://example.com/rootcard",
            "https://api.example.com:8443/auth/rootcard",
            "https://example.com/v0x",
            "https://example.com/v",
            "http://127.0.0.1:8787",
            "http://localhost:8787/rootcard",
            "http://[::1]:8787",
        ] {
            assert_eq!(check_base_url(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "id.example.com",
            "ftp://example.com",
            "http://example.com",
            "http://localhost.example.com",
            "https://",
            "https://example.com/",
            "https://example.com//rootcard",
            "https://example.com/v0",
            "https://example.com/rootcard/V12",
            "https://example.com/rootcard?x=1",
            "https://example.com#top",
            "https://user@example.com",
            "https://exa mple.com",
        ] {
            assert_eq!(check_base_url(bad), Err(Error::BadField), "{bad}");
        }
    }
}
