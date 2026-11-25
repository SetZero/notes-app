//! Identifiers: random UUIDs (version 4) in their canonical text form.

use alloc::string::String;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Formats 16 random bytes as a version 4 UUID.
pub fn uuid_from_random(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut out = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// The 16 bytes of a UUID in canonical lower-case form; `None` for anything else.
pub fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let raw = text.as_bytes();
    if raw.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut nibbles = 0;
    for (i, ch) in raw.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if *ch != b'-' {
                return None;
            }
            continue;
        }
        let value = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => ch - b'a' + 10,
            _ => return None,
        };
        out[nibbles / 2] = (out[nibbles / 2] << 4) | value;
        nibbles += 1;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = uuid_from_random([0xff; 16]);
        assert_eq!(id, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        let bytes = uuid_bytes(&id).unwrap();
        assert_eq!(uuid_from_random(bytes), id);
        assert!(uuid_bytes("FFFFFFFF-ffff-4fff-bfff-ffffffffffff").is_none());
        assert!(uuid_bytes("ffffffffffff-4fff-bfff-ffffffffffff-ffff").is_none());
        assert!(uuid_bytes("").is_none());
    }
}
