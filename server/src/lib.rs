//! notes-syncd: sync server for the notes app.
//!
//! The server is an untrusted relay by design. It stores and forwards encrypted
//! blocks and attachments and never sees note content or the account key.

pub mod api;
pub mod blobs;
pub mod config;
pub mod error;
pub mod events;
pub mod gc;
pub mod oidc;
pub mod ratelimit;
pub mod store;
pub mod util;

use std::ops::Deref;
use std::sync::Arc;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct Inner {
    pub config: config::Config,
    pub store: store::Store,
    pub blobs: blobs::BlobStore,
    pub events: events::EventHub,
    pub limiter: ratelimit::RateLimiter,
    pub oidc: oidc::OidcProviders,
    /// SHA-256 of the invite code, so comparisons never depend on its length.
    pub invite_hash: Option<Vec<u8>>,
    /// True when clients reach the server over TLS (directly or via a proxy).
    pub secure_transport: bool,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub async fn new(config: config::Config) -> Result<Self, BoxError> {
        config.validate()?;
        std::fs::create_dir_all(&config.server.data_dir)?;
        let store = store::Store::connect(&config.database_url()).await?;
        let blobs = blobs::BlobStore::open(&config.server.data_dir)?;
        let oidc = oidc::OidcProviders::new(&config.oidc)?;
        let invite_hash = config
            .enrollment
            .invite_code
            .as_ref()
            .map(|code| util::sha256(code.as_bytes()));
        let secure_transport = config.tls.is_some() || config.server.allow_plain_http;
        Ok(Self(Arc::new(Inner {
            config,
            store,
            blobs,
            events: events::EventHub::new(),
            limiter: ratelimit::RateLimiter::new(),
            oidc,
            invite_hash,
            secure_transport,
        })))
    }
}
