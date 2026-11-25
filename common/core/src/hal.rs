//! The hardware abstraction layer: the six ports a platform has to provide.
//!
//! Everything above this file is shared by all platforms. An adapter (web,
//! desktop, Android, Zephyr) implements these traits and nothing else.

use alloc::string::String;
use alloc::vec::Vec;

/// An error from the platform, with a message for logs. Never shown as is.
#[derive(Debug, Clone)]
pub struct HalError(pub String);

pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Vec<u8>>,
}

pub struct HttpResponse {
    pub status: u16,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// HTTPS requests. The adapter must verify certificates and must not follow
/// redirects or attach cookies.
#[allow(async_fn_in_trait)]
pub trait HttpTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HalError>;
}

/// Named byte blobs that survive a restart. Only ciphertext is stored here.
#[allow(async_fn_in_trait)]
pub trait FileStore {
    async fn file_read(&self, name: &str) -> Result<Option<Vec<u8>>, HalError>;
    async fn file_write(&self, name: &str, data: &[u8]) -> Result<(), HalError>;
    async fn file_remove(&self, name: &str) -> Result<(), HalError>;
    /// Names of all blobs whose name starts with `prefix`.
    async fn file_list(&self, prefix: &str) -> Result<Vec<String>, HalError>;
}

/// The best protected storage the platform has. Holds the account key and
/// the device token.
#[allow(async_fn_in_trait)]
pub trait SecureStore {
    async fn secret_get(&self, name: &str) -> Result<Option<Vec<u8>>, HalError>;
    async fn secret_put(&self, name: &str, data: &[u8]) -> Result<(), HalError>;
    async fn secret_remove(&self, name: &str) -> Result<(), HalError>;
}

pub trait TimeSource {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

pub trait NetworkMonitor {
    fn is_online(&self) -> bool;
}

/// Cryptographically secure random bytes.
pub trait Entropy {
    fn fill_random(&self, buffer: &mut [u8]) -> Result<(), HalError>;
}

/// All six ports together: what the core needs from a platform.
pub trait Platform:
    HttpTransport + FileStore + SecureStore + TimeSource + NetworkMonitor + Entropy
{
}

impl<T> Platform for T where
    T: HttpTransport + FileStore + SecureStore + TimeSource + NetworkMonitor + Entropy
{
}
