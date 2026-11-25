//! Background clean-up: expired pairings and nonces, old deletion markers,
//! idle rate-limit buckets and event channels.

use std::time::Duration;

use crate::{util, AppState};

const TICK: Duration = Duration::from_secs(60);
const TOMBSTONE_EVERY_TICKS: u64 = 60;
const TOMBSTONE_AGE_MS: i64 = 30 * 24 * 3600 * 1000;
const DEVICE_IDLE_MS: i64 = 90 * 24 * 3600 * 1000;

pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        let mut tick: u64 = 0;
        loop {
            interval.tick().await;
            tick += 1;
            let now = util::now_ms();
            if let Err(e) = state.store.gc_expired(now).await {
                tracing::warn!(error = %e, "clean-up of expired rows failed");
            }
            state.limiter.prune();
            state.events.prune();
            if tick % TOMBSTONE_EVERY_TICKS == 1 {
                match state.store.gc_tombstones(now - TOMBSTONE_AGE_MS, now - DEVICE_IDLE_MS).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(removed = n, "removed old deletion markers"),
                    Err(e) => tracing::warn!(error = %e, "clean-up of deletion markers failed"),
                }
            }
        }
    })
}
