//! Small helpers: time, randomness, hashing, encoding.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Cryptographically secure random bytes from the operating system.
/// Panics if the OS random source fails: continuing without it would be unsafe.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system random source failed");
    buf
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Constant-time equality. Slices of different length compare unequal.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

pub fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn rfc3339(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

/// Parses a UUID and returns it in canonical lower-case form.
pub fn canonical_uuid(text: &str) -> Option<String> {
    if text.len() != 36 {
        return None;
    }
    uuid::Uuid::parse_str(text).ok().map(|u| u.hyphenated().to_string())
}

pub fn new_uuid() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}
