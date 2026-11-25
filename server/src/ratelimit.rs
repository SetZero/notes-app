//! In-memory token-bucket rate limiter, keyed by client IP or device id.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::error::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Account creation, recovery, pairing creation, OIDC nonces. Per IP.
    Enroll,
    /// Pairing polls. Per IP.
    PairingPoll,
    /// Unauthenticated metadata. Per IP.
    Public,
    /// Requests with a missing or wrong token. Per IP.
    AuthFail,
    /// Authenticated requests. Per device.
    Device,
    /// Pairing claims. Per device.
    PairingClaim,
}

impl Class {
    /// (burst capacity, tokens refilled per second)
    fn budget(self) -> (f64, f64) {
        match self {
            Class::Enroll => (10.0, 10.0 / 60.0),
            Class::PairingPoll => (60.0, 1.0),
            Class::Public => (60.0, 2.0),
            Class::AuthFail => (20.0, 20.0 / 60.0),
            Class::Device => (240.0, 20.0),
            Class::PairingClaim => (5.0, 5.0 / 60.0),
        }
    }
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<(Class, String), Bucket>>,
}

/// Above this many tracked keys, full buckets are dropped on the next call.
const PRUNE_THRESHOLD: usize = 50_000;

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one token, or fails with 429 and the time until one is available.
    pub fn check(&self, class: Class, key: &str) -> Result<(), ApiError> {
        let (capacity, refill) = class.budget();
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() > PRUNE_THRESHOLD {
            Self::prune_locked(&mut buckets, now);
        }
        let bucket = buckets
            .entry((class, key.to_owned()))
            .or_insert(Bucket { tokens: capacity, updated: now });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(capacity);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait = ((1.0 - bucket.tokens) / refill).ceil() as u64;
            Err(ApiError::rate_limited(wait))
        }
    }

    /// Drops buckets that have refilled completely. Called periodically.
    pub fn prune(&self) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune_locked(&mut buckets, Instant::now());
    }

    fn prune_locked(buckets: &mut HashMap<(Class, String), Bucket>, now: Instant) {
        buckets.retain(|(class, _), b| {
            let (capacity, refill) = class.budget();
            b.tokens + now.duration_since(b.updated).as_secs_f64() * refill < capacity
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausts_and_reports_retry_after() {
        let limiter = RateLimiter::new();
        for _ in 0..10 {
            assert!(limiter.check(Class::Enroll, "1.2.3.4").is_ok());
        }
        let err = limiter.check(Class::Enroll, "1.2.3.4").unwrap_err();
        assert_eq!(err.code, "rate_limited");
        assert!(err.retry_after.unwrap() >= 1);
        // another key is unaffected
        assert!(limiter.check(Class::Enroll, "5.6.7.8").is_ok());
    }
}
