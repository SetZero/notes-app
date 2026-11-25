//! Fractional indexes: sort keys that always leave room for one more.
//!
//! A block's position in its note is a string. To put a block between two
//! others, `between` returns a string that sorts between theirs, so moving or
//! inserting a block never has to renumber (and re-upload) its neighbours.
//! Keys are compared bytewise and never end in the lowest digit.

use alloc::string::String;

const DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn value(digit: u8) -> usize {
    DIGITS.iter().position(|d| *d == digit).unwrap_or(0)
}

/// A key strictly between `low` and `high`. An empty `low` means "before
/// everything", `None` for `high` means "after everything".
///
/// If the two are not in order (two devices gave different blocks the same
/// position at the same time), the result sorts directly after `low`.
pub fn between(low: &str, high: Option<&str>) -> String {
    let high = high.filter(|h| *h > low);
    let mut out = String::new();
    midpoint(low.as_bytes(), high.map(str::as_bytes), &mut out);
    out
}

fn midpoint(low: &[u8], high: Option<&[u8]>, out: &mut String) {
    if let Some(high) = high {
        // Copy the common prefix, treating a too-short `low` as padded with
        // the lowest digit.
        let mut n = 0;
        while n < high.len() && low.get(n).copied().unwrap_or(DIGITS[0]) == high[n] {
            n += 1;
        }
        if n > 0 {
            out.push_str(core::str::from_utf8(&high[..n]).unwrap_or(""));
            return midpoint(low.get(n..).unwrap_or(&[]), Some(&high[n..]), out);
        }
    }
    let low_digit = low.first().map_or(0, |d| value(*d));
    let high_digit = high.and_then(|h| h.first()).map_or(DIGITS.len(), |d| value(*d));
    if high.is_none() && !low.is_empty() && low_digit + 1 < DIGITS.len() {
        // Appending at the end is the common case. Stepping by one instead of
        // halving the remaining space keeps the keys of a long note short.
        out.push(DIGITS[low_digit + 1] as char);
    } else if high_digit - low_digit > 1 {
        out.push(DIGITS[(low_digit + high_digit) / 2] as char);
    } else if high.is_some_and(|h| h.len() > 1) {
        // The first digit of `high` alone already sorts between the two.
        out.push(DIGITS[high_digit] as char);
    } else {
        // No room at this digit: keep it and look for room one digit further.
        out.push(DIGITS[low_digit] as char);
        midpoint(low.get(1..).unwrap_or(&[]), None, out);
    }
}

#[cfg(test)]
mod tests {
    use super::between;

    #[test]
    fn results_sort_strictly_between() {
        let first = between("", None);
        assert!(!first.is_empty());
        let before = between("", Some(&first));
        let after = between(&first, None);
        assert!(before.as_str() < first.as_str() && first.as_str() < after.as_str());
        let mid = between(&first, Some(&after));
        assert!(first.as_str() < mid.as_str() && mid.as_str() < after.as_str());
    }

    #[test]
    fn there_is_always_room() {
        // Keep inserting at the same three places a few hundred times.
        let mut low = between("", None);
        let mut high = between(&low, None);
        for _ in 0..300 {
            let mid = between(&low, Some(&high));
            assert!(low < mid && mid < high, "{low} < {mid} < {high}");
            assert!(!mid.ends_with('0'));
            high = mid;
        }
        for _ in 0..300 {
            let mid = between(&low, Some(&high));
            assert!(low < mid && mid < high, "{low} < {mid} < {high}");
            low = mid;
        }
        let mut front = between("", None);
        for _ in 0..300 {
            let earlier = between("", Some(&front));
            assert!(earlier < front && !earlier.is_empty() && !earlier.ends_with('0'));
            front = earlier;
        }
        let mut back = between("", None);
        for _ in 0..300 {
            let later = between(&back, None);
            assert!(later > back);
            back = later;
        }
        // Appending stays short: about one more character per 30 blocks.
        assert!(back.len() < 20, "{back}");
    }

    #[test]
    fn equal_or_reversed_neighbours_still_give_a_usable_key() {
        let a = between("", None);
        assert!(between(&a, Some(&a)) > a);
        let b = between(&a, None);
        assert!(between(&b, Some(&a)) > b);
    }
}
