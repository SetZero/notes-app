//! Hybrid logical clock: the version of a block.
//!
//! 24 lower-case hex characters, compared bytewise: 12 digits of milliseconds,
//! 4 digits of counter, 8 digits of device tag. A new version is always
//! greater than every version this device has created or seen, even if its
//! wall clock stands still or jumps back.

use alloc::format;
use alloc::string::String;

pub const VERSION_LEN: usize = 24;
const MAX_MS: i64 = 0xffff_ffff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hlc {
    pub ms: i64,
    pub counter: u16,
}

pub fn is_version(text: &str) -> bool {
    text.len() == VERSION_LEN && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Milliseconds and counter of a version; `None` if it is not well formed.
pub fn parse(version: &str) -> Option<Hlc> {
    if !is_version(version) {
        return None;
    }
    Some(Hlc {
        ms: i64::from_str_radix(&version[..12], 16).ok()?,
        counter: u16::from_str_radix(&version[12..16], 16).ok()?,
    })
}

impl Hlc {
    /// The next version for this device.
    pub fn next(&mut self, now_ms: i64, device_tag: u32) -> String {
        let now_ms = now_ms.clamp(0, MAX_MS);
        if now_ms > self.ms {
            self.ms = now_ms;
            self.counter = 0;
        } else if self.counter == u16::MAX {
            self.ms += 1;
            self.counter = 0;
        } else {
            self.counter += 1;
        }
        format!("{:012x}{:04x}{:08x}", self.ms, self.counter, device_tag)
    }

    /// Takes note of a version from another device, so that later local
    /// versions sort after it.
    pub fn observe(&mut self, version: &str) {
        if let Some(seen) = parse(version) {
            if (seen.ms, seen.counter) > (self.ms, self.counter) {
                *self = seen;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_only_go_up() {
        let mut clock = Hlc { ms: 0, counter: 0 };
        let a = clock.next(1000, 0xabcdef01);
        let b = clock.next(1000, 0xabcdef01);
        let c = clock.next(900, 0xabcdef01); // the wall clock jumped back
        let d = clock.next(2000, 0xabcdef01);
        assert!(a < b && b < c && c < d, "{a} {b} {c} {d}");
        assert!([&a, &b, &c, &d].iter().all(|v| is_version(v)));
        assert_eq!(a, "0000000003e80000abcdef01");
    }

    #[test]
    fn a_seen_version_is_always_exceeded() {
        let mut clock = Hlc { ms: 0, counter: 0 };
        let remote = "00000000ffff0007deadbeef";
        clock.observe(remote);
        let local = clock.next(5, 1);
        assert!(local.as_str() > remote);
        clock.observe("not a version");
        clock.observe("0000000000010000deadbeef"); // older: ignored
        assert!(clock.next(5, 1) > local);
    }

    #[test]
    fn the_counter_rolls_over_into_the_time() {
        let mut clock = Hlc { ms: 10, counter: u16::MAX };
        let v = clock.next(10, 0);
        assert_eq!(parse(&v), Some(Hlc { ms: 11, counter: 0 }));
    }
}
