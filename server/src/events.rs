//! Per-account change notifications. Only the latest cursor matters, so a
//! watch channel is enough: slow subscribers skip intermediate values.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::watch;

use crate::error::ApiError;

const MAX_SUBSCRIBERS_PER_ACCOUNT: usize = 16;

#[derive(Default)]
pub struct EventHub {
    accounts: Mutex<HashMap<String, watch::Sender<i64>>>,
}

impl EventHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&self, account_id: &str) -> Result<watch::Receiver<i64>, ApiError> {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let sender = accounts
            .entry(account_id.to_owned())
            .or_insert_with(|| watch::channel(0).0);
        if sender.receiver_count() >= MAX_SUBSCRIBERS_PER_ACCOUNT {
            return Err(ApiError::rate_limited(30));
        }
        Ok(sender.subscribe())
    }

    pub fn publish(&self, account_id: &str, cursor: i64) {
        let accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sender) = accounts.get(account_id) {
            sender.send_if_modified(|current| {
                if cursor > *current {
                    *current = cursor;
                    true
                } else {
                    false
                }
            });
        }
    }

    /// Drops channels nobody listens to. Called periodically.
    pub fn prune(&self) {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        accounts.retain(|_, sender| sender.receiver_count() > 0);
    }
}
