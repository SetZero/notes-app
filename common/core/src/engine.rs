//! Account, note model and sync: the part of the app that is the same on
//! every platform.
//!
//! What is kept where:
//! * `SecureStore`: the session (account key, device token, ids).
//! * `FileStore`: one blob per block holding the same encrypted envelope the
//!   server gets, plus a "still has to be uploaded" flag. Note text is never
//!   written to storage in the clear. Attachments are kept the same way: the
//!   encrypted blob as the server has it, plus a marker while it still has to
//!   be uploaded.
//! * memory: the decrypted blocks, while the app runs.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use core::cell::{Cell, RefCell};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, AccountKey};
use crate::hal::{HalError, HttpRequest, HttpResponse, Platform};
use crate::hlc::{self, Hlc};
use crate::ids::{uuid_bytes, uuid_from_random};
use crate::order;

/// Longest text of one block. With JSON escaping and the rest of the payload
/// this stays below the server's default limit of 64 KiB of ciphertext.
pub const MAX_BLOCK_TEXT_BYTES: usize = 16 * 1024;
const MAX_ATTRS_BYTES: usize = 2 * 1024;
const PUSH_BATCH_BLOCKS: usize = 100;
const PUSH_BATCH_BYTES: usize = 512 * 1024;
const PULL_LIMIT: usize = 100;
const KINDS: [&str; 6] = [
    "header",
    "paragraph",
    "heading",
    "todo",
    "code",
    "attachment",
];

const SESSION_SECRET: &str = "session";
const META_FILE: &str = "meta";
const BLOCK_PREFIX: &str = "block/";
const BLOB_PREFIX: &str = "blob/";
const UPLOAD_PREFIX: &str = "upload/";

/// Largest attachment. Encrypted it stays below the server's default limit
/// of 25 MiB per blob.
pub const MAX_ATTACHMENT_BYTES: usize = 24 * 1024 * 1024;
const MAX_NAME_CHARS: usize = 255;
const MAX_FOLDER_BYTES: usize = 200;
const FALLBACK_MIME: &str = "application/octet-stream";
/// The attributes of an attachment block that identify its file.
const FILE_ATTRS: [&str; 4] = ["hash", "key", "size", "mime"];

/// `code` is stable and meant for the user interface to switch on; `message`
/// is for logs and as a fallback text.
#[derive(Debug, Clone, Serialize)]
pub struct CoreError {
    pub code: String,
    pub message: String,
    /// Seconds to wait before trying again, if the server said so.
    pub retry_after: Option<u32>,
}

impl CoreError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after: None,
        }
    }
    fn input(message: &str) -> Self {
        Self::new("input", message)
    }
    fn not_signed_in() -> Self {
        Self::new("not_signed_in", "no account on this device")
    }
    fn storage(error: HalError) -> Self {
        Self::new("storage", error.0)
    }
    fn protocol(message: &str) -> Self {
        Self::new("protocol", message)
    }
}

type Result<T> = core::result::Result<T, CoreError>;

#[derive(Serialize)]
pub struct Status {
    pub signed_in: bool,
    pub server_url: String,
    pub account_id: String,
    pub device_id: String,
    pub online: bool,
    /// Blocks changed here that the server does not have yet.
    pub pending: usize,
    pub notes: usize,
}

#[derive(Serialize)]
pub struct RecoveryKit {
    pub server_url: String,
    pub account_id: String,
    /// The account key as 24 words. Whoever has it can read every note.
    pub phrase: String,
}

#[derive(Serialize)]
pub struct NoteSummary {
    pub note_id: String,
    pub title: String,
    /// Path of the folder the note is in, parts separated by "/". Empty for
    /// a note outside of all folders.
    pub folder: String,
    pub preview: String,
    pub updated_ms: i64,
}

#[derive(Serialize, Clone)]
pub struct BlockView {
    pub block_id: String,
    pub kind: String,
    pub text: String,
    pub attrs: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct NoteView {
    pub note_id: String,
    pub title: String,
    pub folder: String,
    pub updated_ms: i64,
    pub blocks: Vec<BlockView>,
}

#[derive(Serialize, Default)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    /// Notes that changed because of what was pulled.
    pub changed_notes: Vec<String>,
    /// Blocks the server refused for good (too large or malformed).
    pub rejected: usize,
    /// The server refused blocks because this device's clock is too far ahead.
    pub clock_skew: bool,
    /// Blocks from the server that failed authentication and were ignored.
    pub undecryptable: usize,
    /// The server no longer had the history this device needed; everything
    /// was fetched again.
    pub full_resync: bool,
}

#[derive(Serialize)]
pub struct EventsRequest {
    pub url: String,
    pub authorization: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub name: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub current: bool,
}

/// The decrypted content of a block.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Payload {
    schema: u8,
    kind: String,
    order: String,
    text: String,
    #[serde(default)]
    attrs: BTreeMap<String, String>,
}

/// A block as the server sees it. Same field names as the REST API.
#[derive(Serialize, Deserialize, Clone)]
struct Envelope {
    block_id: String,
    note_id: String,
    version: String,
    deleted: bool,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct StoredBlock {
    envelope: Envelope,
    dirty: bool,
}

struct Block {
    envelope: Envelope,
    dirty: bool,
    /// `None` for a deletion marker.
    payload: Option<Payload>,
}

#[derive(Serialize, Deserialize)]
struct StoredSession {
    server_url: String,
    account_id: String,
    device_id: String,
    token: String,
    account_key: String,
}

impl Drop for StoredSession {
    fn drop(&mut self) {
        self.token.zeroize();
        self.account_key.zeroize();
    }
}

struct Session {
    server_url: String,
    account_id: String,
    device_id: String,
    token: String,
    key: AccountKey,
    device_tag: u32,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Meta {
    cursor: i64,
}

struct State {
    session: Option<Session>,
    blocks: BTreeMap<String, Block>,
    cursor: i64,
    clock: Hlc,
}

pub struct Core<P: Platform> {
    platform: P,
    state: RefCell<State>,
    syncing: Cell<bool>,
}

/// Clears the "sync is running" flag even if the sync future is dropped.
struct SyncGuard<'a>(&'a Cell<bool>);

impl Drop for SyncGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[derive(Deserialize)]
struct Problem {
    #[serde(default)]
    code: String,
    #[serde(default)]
    detail: String,
}

#[derive(Deserialize)]
struct Credentials {
    account_id: String,
    device_id: String,
    token: String,
}

#[derive(Deserialize)]
struct MetaResponse {
    api_versions: Vec<String>,
}

#[derive(Deserialize)]
struct PushResult {
    block_id: String,
    status: String,
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
struct PushResponse {
    results: Vec<PushResult>,
}

#[derive(Deserialize)]
struct PullResponse {
    changes: Vec<Envelope>,
    next_cursor: i64,
    has_more: bool,
}

#[derive(Deserialize)]
struct DevicesResponse {
    devices: Vec<DeviceInfo>,
}

/// Checks the authentication tag and decodes the payload. `Err` means the
/// block is not what one of our devices wrote and must be ignored.
fn decode(key: &AccountKey, envelope: &Envelope) -> core::result::Result<Option<Payload>, ()> {
    let block_id = uuid_bytes(&envelope.block_id).ok_or(())?;
    let note_id = uuid_bytes(&envelope.note_id).ok_or(())?;
    if !hlc::is_version(&envelope.version) {
        return Err(());
    }
    let nonce = B64.decode(&envelope.nonce).map_err(|_| ())?;
    let ciphertext = B64.decode(&envelope.ciphertext).map_err(|_| ())?;
    let aad = crypto::aad(&block_id, &note_id, &envelope.version, envelope.deleted);
    let mut note_key = crypto::note_key(key, &note_id);
    let plaintext = crypto::open(&note_key, &nonce, &ciphertext, &aad);
    note_key.zeroize();
    let plaintext = plaintext.ok_or(())?;
    if envelope.deleted {
        return if plaintext.is_empty() {
            Ok(None)
        } else {
            Err(())
        };
    }
    let payload: Payload = serde_json::from_slice(&plaintext).map_err(|_| ())?;
    Ok(Some(payload))
}

/// The blob an attachment block points to, if the block is well-formed.
fn blob_hash(payload: Option<&Payload>) -> Option<&str> {
    let payload = payload.filter(|p| p.kind == "attachment")?;
    let hash = payload.attrs.get("hash")?;
    let hex = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    hex.then_some(hash.as_str())
}

fn blob_file(hash: &str) -> String {
    format!("{BLOB_PREFIX}{hash}")
}

fn upload_file(hash: &str) -> String {
    format!("{UPLOAD_PREFIX}{hash}")
}

/// "  Work //Plans/ " becomes "Work/Plans".
fn normalize_folder(folder: &str) -> Result<String> {
    let parts: Vec<&str> = folder
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let folder = parts.join("/");
    if folder.len() > MAX_FOLDER_BYTES || folder.chars().any(char::is_control) {
        return Err(CoreError::input(
            "the folder name is too long or has control characters",
        ));
    }
    Ok(folder)
}

fn folder_of(header: Option<&Block>) -> String {
    header
        .and_then(|h| h.payload.as_ref())
        .and_then(|p| p.attrs.get("folder"))
        .cloned()
        .unwrap_or_default()
}

fn block_file(block_id: &str) -> String {
    format!("{BLOCK_PREFIX}{block_id}")
}

fn stored_bytes(block: &Block) -> Result<Vec<u8>> {
    serde_json::to_vec(&StoredBlock {
        envelope: block.envelope.clone(),
        dirty: block.dirty,
    })
    .map_err(|e| CoreError::new("storage", e.to_string()))
}

fn version_ms(version: &str) -> i64 {
    hlc::parse(version).map_or(0, |v| v.ms)
}

/// `https://…` always; plain `http://` only for this machine, for development.
fn normalize_server_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        });
    let secure = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty());
    if !(secure || local) || url.contains(['?', '#', ' ']) {
        return Err(CoreError::input(
            "the server address must start with https://",
        ));
    }
    Ok(url.to_string())
}

fn check_device_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(CoreError::input(
            "the device name must have 1 to 64 characters",
        ));
    }
    Ok(name)
}

impl<P: Platform> Core<P> {
    /// Loads the session and all blocks from storage.
    pub async fn open(platform: P) -> Result<Self> {
        let mut state = State {
            session: None,
            blocks: BTreeMap::new(),
            cursor: 0,
            clock: Hlc { ms: 0, counter: 0 },
        };
        if let Some(mut raw) = platform
            .secret_get(SESSION_SECRET)
            .await
            .map_err(CoreError::storage)?
        {
            let stored: core::result::Result<StoredSession, _> = serde_json::from_slice(&raw);
            raw.zeroize();
            // A session that cannot be read is treated as "not signed in".
            state.session = stored.ok().and_then(|s| Self::session_from_stored(&s));
        }
        if let Some(session) = &state.session {
            if let Some(raw) = platform
                .file_read(META_FILE)
                .await
                .map_err(CoreError::storage)?
            {
                state.cursor = serde_json::from_slice::<Meta>(&raw)
                    .map(|m| m.cursor)
                    .unwrap_or(0);
            }
            for name in platform
                .file_list(BLOCK_PREFIX)
                .await
                .map_err(CoreError::storage)?
            {
                let Some(raw) = platform
                    .file_read(&name)
                    .await
                    .map_err(CoreError::storage)?
                else {
                    continue;
                };
                let Ok(stored) = serde_json::from_slice::<StoredBlock>(&raw) else {
                    continue;
                };
                // Storage is not trusted either: a block that fails
                // authentication is left out.
                let Ok(payload) = decode(&session.key, &stored.envelope) else {
                    continue;
                };
                state.clock.observe(&stored.envelope.version);
                state.blocks.insert(
                    stored.envelope.block_id.clone(),
                    Block {
                        envelope: stored.envelope,
                        dirty: stored.dirty,
                        payload,
                    },
                );
            }
        }
        Ok(Self {
            platform,
            state: RefCell::new(state),
            syncing: Cell::new(false),
        })
    }

    fn session_from_stored(stored: &StoredSession) -> Option<Session> {
        let mut raw = B64.decode(&stored.account_key).ok()?;
        let key: Option<[u8; crypto::KEY_LEN]> = raw.as_slice().try_into().ok();
        raw.zeroize();
        uuid_bytes(&stored.account_id)?;
        let device = uuid_bytes(&stored.device_id)?;
        Some(Session {
            server_url: stored.server_url.clone(),
            account_id: stored.account_id.clone(),
            device_id: stored.device_id.clone(),
            token: stored.token.clone(),
            key: AccountKey(key?),
            device_tag: u32::from_be_bytes([device[0], device[1], device[2], device[3]]),
        })
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn status(&self) -> Status {
        let state = self.state.borrow();
        let session = state.session.as_ref();
        let notes: BTreeSet<&str> = state
            .blocks
            .values()
            .filter(|b| b.payload.is_some())
            .map(|b| b.envelope.note_id.as_str())
            .collect();
        Status {
            signed_in: session.is_some(),
            server_url: session.map(|s| s.server_url.clone()).unwrap_or_default(),
            account_id: session.map(|s| s.account_id.clone()).unwrap_or_default(),
            device_id: session.map(|s| s.device_id.clone()).unwrap_or_default(),
            online: self.platform.is_online(),
            pending: state.blocks.values().filter(|b| b.dirty).count(),
            notes: notes.len(),
        }
    }

    // ------------------------------------------------------------ transport

    /// One request. Any answer from the server is `Ok`, whatever its status.
    async fn send(
        &self,
        server_url: &str,
        method: &'static str,
        path: &str,
        token: Option<&str>,
        body: Option<(&'static str, Vec<u8>)>,
    ) -> Result<HttpResponse> {
        if !self.platform.is_online() {
            return Err(CoreError::new("offline", "no network connection"));
        }
        let mut headers = Vec::new();
        headers.push(("accept", "application/json".to_string()));
        if let Some(token) = token {
            headers.push(("authorization", format!("Bearer {token}")));
        }
        let body = body.map(|(content_type, bytes)| {
            headers.push(("content-type", content_type.to_string()));
            bytes
        });
        let request = HttpRequest {
            method,
            url: format!("{server_url}{path}"),
            headers,
            body,
        };
        self.platform
            .send(request)
            .await
            .map_err(|e| CoreError::new("network", e.0))
    }

    /// The error a response with a status outside 2xx stands for.
    fn failure(response: &HttpResponse) -> CoreError {
        let problem: Problem = serde_json::from_slice(&response.body).unwrap_or(Problem {
            code: String::new(),
            detail: String::new(),
        });
        let code = if problem.code.is_empty() {
            format!("http_{}", response.status)
        } else {
            problem.code
        };
        CoreError {
            code,
            message: if problem.detail.is_empty() {
                format!("the server answered {}", response.status)
            } else {
                problem.detail
            },
            retry_after: response
                .header("retry-after")
                .and_then(|v| v.trim().parse().ok()),
        }
    }

    /// A JSON request that must succeed.
    async fn call<B: Serialize>(
        &self,
        server_url: &str,
        method: &'static str,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> Result<HttpResponse> {
        let body = match body {
            Some(body) => Some((
                "application/json",
                serde_json::to_vec(body).map_err(|e| CoreError::new("protocol", e.to_string()))?,
            )),
            None => None,
        };
        let response = self.send(server_url, method, path, token, body).await?;
        if (200..300).contains(&response.status) {
            Ok(response)
        } else {
            Err(Self::failure(&response))
        }
    }

    fn session_endpoint(&self) -> Result<(String, String)> {
        let state = self.state.borrow();
        let session = state
            .session
            .as_ref()
            .ok_or_else(CoreError::not_signed_in)?;
        Ok((session.server_url.clone(), session.token.clone()))
    }

    // -------------------------------------------------------------- account

    async fn check_server(&self, server_url: &str) -> Result<()> {
        let response = self
            .call::<()>(server_url, "GET", "/v1/meta", None, None)
            .await?;
        let meta: MetaResponse = serde_json::from_slice(&response.body)
            .map_err(|_| CoreError::protocol("this is not a notes server"))?;
        if !meta.api_versions.iter().any(|v| v == "v1") {
            return Err(CoreError::new(
                "unsupported_server",
                "the server does not speak API version 1",
            ));
        }
        Ok(())
    }

    async fn start_session(
        &self,
        server_url: String,
        credentials: Credentials,
        key: AccountKey,
    ) -> Result<()> {
        let stored = StoredSession {
            server_url,
            account_id: credentials.account_id,
            device_id: credentials.device_id,
            token: credentials.token,
            account_key: B64.encode(key.0),
        };
        let session = Self::session_from_stored(&stored)
            .ok_or_else(|| CoreError::protocol("unusable ids from the server"))?;
        let mut raw =
            serde_json::to_vec(&stored).map_err(|e| CoreError::new("storage", e.to_string()))?;
        let written = self.platform.secret_put(SESSION_SECRET, &raw).await;
        raw.zeroize();
        written.map_err(CoreError::storage)?;
        // Whatever an earlier account left behind does not belong to this one.
        self.wipe_files().await?;
        let mut state = self.state.borrow_mut();
        state.blocks.clear();
        state.cursor = 0;
        state.session = Some(session);
        Ok(())
    }

    /// Creates a new account with this device as its first device. The
    /// returned recovery kit is the only backup of the account key.
    pub async fn create_account(
        &self,
        server_url: &str,
        invite_code: &str,
        device_name: &str,
    ) -> Result<RecoveryKit> {
        if self.state.borrow().session.is_some() {
            return Err(CoreError::input("this device already has an account"));
        }
        let server_url = normalize_server_url(server_url)?;
        let device_name = check_device_name(device_name)?;
        self.check_server(&server_url).await?;

        let mut raw = [0u8; crypto::KEY_LEN];
        self.platform
            .fill_random(&mut raw)
            .map_err(|e| CoreError::new("entropy", e.0))?;
        let key = AccountKey(raw);
        raw.zeroize();

        #[derive(Serialize)]
        struct Request<'a> {
            invite_code: &'a str,
            device_name: &'a str,
            recovery_verifier: String,
        }
        let request = Request {
            invite_code: invite_code.trim(),
            device_name,
            recovery_verifier: B64.encode(crypto::recovery_verifier(&key)),
        };
        let response = self
            .call(&server_url, "POST", "/v1/accounts", None, Some(&request))
            .await?;
        let credentials: Credentials = serde_json::from_slice(&response.body)
            .map_err(|_| CoreError::protocol("unexpected answer from the server"))?;
        let kit = RecoveryKit {
            server_url: server_url.clone(),
            account_id: credentials.account_id.clone(),
            phrase: crypto::recovery_phrase(&key),
        };
        self.start_session(server_url, credentials, key).await?;
        Ok(kit)
    }

    /// Adds this device to an existing account with the recovery phrase.
    pub async fn recover(
        &self,
        server_url: &str,
        account_id: &str,
        phrase: &str,
        device_name: &str,
    ) -> Result<()> {
        if self.state.borrow().session.is_some() {
            return Err(CoreError::input("this device already has an account"));
        }
        let server_url = normalize_server_url(server_url)?;
        let device_name = check_device_name(device_name)?;
        let account_id = account_id.trim().to_lowercase();
        if uuid_bytes(&account_id).is_none() {
            return Err(CoreError::new(
                "bad_account_id",
                "this is not an account id",
            ));
        }
        let key = crypto::account_key_from_phrase(phrase)
            .ok_or_else(|| CoreError::new("bad_phrase", "the recovery phrase is not valid"))?;
        self.check_server(&server_url).await?;

        #[derive(Serialize)]
        struct Request<'a> {
            device_name: &'a str,
            recovery_verifier: String,
        }
        let request = Request {
            device_name,
            recovery_verifier: B64.encode(crypto::recovery_verifier(&key)),
        };
        let path = format!("/v1/accounts/{account_id}/recover");
        let response = self
            .call(&server_url, "POST", &path, None, Some(&request))
            .await?;
        let credentials: Credentials = serde_json::from_slice(&response.body)
            .map_err(|_| CoreError::protocol("unexpected answer from the server"))?;
        self.start_session(server_url, credentials, key).await
    }

    /// The recovery kit again, for a user who wants to write it down later.
    pub fn recovery_kit(&self) -> Result<RecoveryKit> {
        let state = self.state.borrow();
        let session = state
            .session
            .as_ref()
            .ok_or_else(CoreError::not_signed_in)?;
        Ok(RecoveryKit {
            server_url: session.server_url.clone(),
            account_id: session.account_id.clone(),
            phrase: crypto::recovery_phrase(&session.key),
        })
    }

    async fn wipe_files(&self) -> Result<()> {
        for name in self
            .platform
            .file_list("")
            .await
            .map_err(CoreError::storage)?
        {
            self.platform
                .file_remove(&name)
                .await
                .map_err(CoreError::storage)?;
        }
        Ok(())
    }

    /// Removes the account from this device. With `revoke` the server is told
    /// to stop accepting this device's token; if that fails (offline), the
    /// local data is removed anyway.
    pub async fn sign_out(&self, revoke: bool) -> Result<()> {
        if revoke {
            if let Ok((server_url, token)) = self.session_endpoint() {
                let device_id = self
                    .state
                    .borrow()
                    .session
                    .as_ref()
                    .map(|s| s.device_id.clone())
                    .unwrap_or_default();
                let path = format!("/v1/devices/{device_id}");
                let _ = self
                    .call::<()>(&server_url, "DELETE", &path, Some(&token), None)
                    .await;
            }
        }
        self.platform
            .secret_remove(SESSION_SECRET)
            .await
            .map_err(CoreError::storage)?;
        {
            let mut state = self.state.borrow_mut();
            state.session = None;
            state.blocks.clear();
            state.cursor = 0;
        }
        self.wipe_files().await
    }

    /// Where and how to listen for "something changed" notifications. The
    /// stream itself is opened by the platform; a notification only means
    /// "call sync now" and carries no data.
    pub fn events_request(&self) -> Result<EventsRequest> {
        let (server_url, token) = self.session_endpoint()?;
        Ok(EventsRequest {
            url: format!("{server_url}/v1/events"),
            authorization: format!("Bearer {token}"),
        })
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let (server_url, token) = self.session_endpoint()?;
        let response = self
            .call::<()>(&server_url, "GET", "/v1/devices", Some(&token), None)
            .await?;
        serde_json::from_slice::<DevicesResponse>(&response.body)
            .map(|r| r.devices)
            .map_err(|_| CoreError::protocol("unexpected answer from the server"))
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        if uuid_bytes(device_id).is_none() {
            return Err(CoreError::input("this is not a device id"));
        }
        let (server_url, token) = self.session_endpoint()?;
        let path = format!("/v1/devices/{device_id}");
        self.call::<()>(&server_url, "DELETE", &path, Some(&token), None)
            .await
            .map(|_| ())
    }

    // ---------------------------------------------------------------- notes

    fn random_uuid(&self) -> Result<String> {
        let mut raw = [0u8; 16];
        self.platform
            .fill_random(&mut raw)
            .map_err(|e| CoreError::new("entropy", e.0))?;
        Ok(uuid_from_random(raw))
    }

    /// Encrypts a new version of a block, keeps it in memory and returns
    /// what has to be written to storage.
    fn stage(
        &self,
        block_id: &str,
        note_id: &str,
        payload: Option<Payload>,
    ) -> Result<(String, Vec<u8>)> {
        let block_bytes = uuid_bytes(block_id).ok_or_else(|| CoreError::input("not a block id"))?;
        let note_bytes = uuid_bytes(note_id).ok_or_else(|| CoreError::input("not a note id"))?;
        let mut nonce = [0u8; crypto::NONCE_LEN];
        self.platform
            .fill_random(&mut nonce)
            .map_err(|e| CoreError::new("entropy", e.0))?;
        let now = self.platform.now_ms();

        let mut state = self.state.borrow_mut();
        let state = &mut *state;
        let session = state
            .session
            .as_ref()
            .ok_or_else(CoreError::not_signed_in)?;
        let version = state.clock.next(now, session.device_tag);
        let plaintext = match &payload {
            Some(payload) => {
                serde_json::to_vec(payload).map_err(|e| CoreError::new("storage", e.to_string()))?
            }
            None => Vec::new(),
        };
        let aad = crypto::aad(&block_bytes, &note_bytes, &version, payload.is_none());
        let mut note_key = crypto::note_key(&session.key, &note_bytes);
        let ciphertext = crypto::seal(&note_key, &nonce, &plaintext, &aad);
        note_key.zeroize();
        let block = Block {
            envelope: Envelope {
                block_id: block_id.to_string(),
                note_id: note_id.to_string(),
                version,
                deleted: payload.is_none(),
                nonce: B64.encode(nonce),
                ciphertext: B64.encode(ciphertext),
            },
            dirty: true,
            payload,
        };
        let bytes = stored_bytes(&block)?;
        state.blocks.insert(block_id.to_string(), block);
        Ok((block_file(block_id), bytes))
    }

    async fn write_block(
        &self,
        block_id: &str,
        note_id: &str,
        payload: Option<Payload>,
    ) -> Result<()> {
        let (name, bytes) = self.stage(block_id, note_id, payload)?;
        self.platform
            .file_write(&name, &bytes)
            .await
            .map_err(CoreError::storage)
    }

    fn check_content(kind: &str, text: &str, attrs: &BTreeMap<String, String>) -> Result<()> {
        if !KINDS.contains(&kind) {
            return Err(CoreError::input("unknown kind of block"));
        }
        if text.len() > MAX_BLOCK_TEXT_BYTES {
            return Err(CoreError::new(
                "too_long",
                "this block is too long; split it into several",
            ));
        }
        if attrs.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > MAX_ATTRS_BYTES {
            return Err(CoreError::input("too many attributes"));
        }
        Ok(())
    }

    /// The live blocks of a note: its header (the newest, if two devices
    /// created one each) and the content in display order.
    fn note_blocks<'a>(state: &'a State, note_id: &str) -> (Option<&'a Block>, Vec<&'a Block>) {
        let mut header: Option<&Block> = None;
        let mut content = Vec::new();
        for block in state
            .blocks
            .values()
            .filter(|b| b.envelope.note_id == note_id)
        {
            let Some(payload) = &block.payload else {
                continue;
            };
            if payload.kind == "header" {
                if header.is_none_or(|h| h.envelope.version < block.envelope.version) {
                    header = Some(block);
                }
            } else {
                content.push(block);
            }
        }
        content.sort_by(|a, b| {
            let (pa, pb) = (a.payload.as_ref(), b.payload.as_ref());
            (pa.map(|p| p.order.as_str()), &a.envelope.block_id)
                .cmp(&(pb.map(|p| p.order.as_str()), &b.envelope.block_id))
        });
        (header, content)
    }

    fn view(block: &Block) -> Option<BlockView> {
        let payload = block.payload.as_ref()?;
        Some(BlockView {
            block_id: block.envelope.block_id.clone(),
            kind: payload.kind.clone(),
            text: payload.text.clone(),
            attrs: payload.attrs.clone(),
        })
    }

    /// All notes, most recently changed first.
    pub fn list_notes(&self) -> Vec<NoteSummary> {
        let state = self.state.borrow();
        let mut updated: BTreeMap<&str, i64> = BTreeMap::new();
        let mut live: BTreeSet<&str> = BTreeSet::new();
        for block in state.blocks.values() {
            let note_id = block.envelope.note_id.as_str();
            let ms = version_ms(&block.envelope.version);
            let entry = updated.entry(note_id).or_insert(0);
            *entry = (*entry).max(ms);
            if block.payload.is_some() {
                live.insert(note_id);
            }
        }
        let mut notes: Vec<NoteSummary> = live
            .into_iter()
            .map(|note_id| {
                let (header, content) = Self::note_blocks(&state, note_id);
                let title = header
                    .and_then(|h| h.payload.as_ref())
                    .map(|p| p.text.clone())
                    .unwrap_or_default();
                let preview = content
                    .iter()
                    .filter_map(|b| b.payload.as_ref())
                    .map(|p| p.text.trim())
                    .find(|text| !text.is_empty())
                    .map(|text| text.chars().take(140).collect())
                    .unwrap_or_default();
                NoteSummary {
                    note_id: note_id.to_string(),
                    title,
                    folder: folder_of(header),
                    preview,
                    updated_ms: updated.get(note_id).copied().unwrap_or(0),
                }
            })
            .collect();
        notes.sort_by(|a, b| {
            b.updated_ms
                .cmp(&a.updated_ms)
                .then_with(|| a.note_id.cmp(&b.note_id))
        });
        notes
    }

    pub fn get_note(&self, note_id: &str) -> Option<NoteView> {
        let state = self.state.borrow();
        let (header, content) = Self::note_blocks(&state, note_id);
        if header.is_none() && content.is_empty() {
            return None;
        }
        let updated_ms = state
            .blocks
            .values()
            .filter(|b| b.envelope.note_id == note_id)
            .map(|b| version_ms(&b.envelope.version))
            .max()
            .unwrap_or(0);
        Some(NoteView {
            note_id: note_id.to_string(),
            title: header
                .and_then(|h| h.payload.as_ref())
                .map(|p| p.text.clone())
                .unwrap_or_default(),
            folder: folder_of(header),
            updated_ms,
            blocks: content.into_iter().filter_map(Self::view).collect(),
        })
    }

    /// A new note with an empty title and one empty paragraph, in `folder`
    /// ("" for none).
    pub async fn create_note(&self, folder: &str) -> Result<NoteView> {
        let folder = normalize_folder(folder)?;
        let note_id = self.random_uuid()?;
        let mut attrs = BTreeMap::new();
        if !folder.is_empty() {
            attrs.insert("folder".to_string(), folder);
        }
        let header = Payload {
            schema: 1,
            kind: "header".into(),
            order: String::new(),
            text: String::new(),
            attrs,
        };
        self.write_block(&self.random_uuid()?, &note_id, Some(header))
            .await?;
        let first = Payload {
            schema: 1,
            kind: "paragraph".into(),
            order: order::between("", None),
            text: String::new(),
            attrs: BTreeMap::new(),
        };
        self.write_block(&self.random_uuid()?, &note_id, Some(first))
            .await?;
        self.get_note(&note_id)
            .ok_or_else(|| CoreError::new("storage", "the new note is missing"))
    }

    pub async fn set_title(&self, note_id: &str, title: &str) -> Result<()> {
        Self::check_content("header", title, &BTreeMap::new())?;
        self.edit_header(note_id, |payload| payload.text = title.to_string())
            .await
    }

    /// Moves a note into a folder, given as a path like "Work/Plans". An
    /// empty path takes it out of all folders. Folders exist as long as a
    /// note is in them.
    pub async fn set_folder(&self, note_id: &str, folder: &str) -> Result<()> {
        let folder = normalize_folder(folder)?;
        self.edit_header(note_id, |payload| {
            if folder.is_empty() {
                payload.attrs.remove("folder");
            } else {
                payload.attrs.insert("folder".to_string(), folder);
            }
        })
        .await
    }

    /// Changes the header block of a note, creating it if another device
    /// deleted it meanwhile. Nothing is written if nothing changed.
    async fn edit_header(&self, note_id: &str, change: impl FnOnce(&mut Payload)) -> Result<()> {
        let existing = {
            let state = self.state.borrow();
            let (header, content) = Self::note_blocks(&state, note_id);
            if header.is_none() && content.is_empty() {
                return Err(CoreError::new(
                    "not_found",
                    "this note does not exist any more",
                ));
            }
            header.map(|h| (h.envelope.block_id.clone(), h.payload.clone()))
        };
        let (block_id, before, is_new) = match existing {
            Some((block_id, Some(payload))) => (block_id, payload, false),
            _ => (
                self.random_uuid()?,
                Payload {
                    schema: 1,
                    kind: "header".into(),
                    order: String::new(),
                    text: String::new(),
                    attrs: BTreeMap::new(),
                },
                true,
            ),
        };
        let mut payload = before.clone();
        change(&mut payload);
        if payload == before && !is_new {
            return Ok(());
        }
        self.write_block(&block_id, note_id, Some(payload)).await
    }

    /// Adds a block after `after`, or at the top of the note without it.
    pub async fn insert_block(
        &self,
        note_id: &str,
        after: Option<&str>,
        kind: &str,
        text: &str,
    ) -> Result<BlockView> {
        if kind == "header" {
            return Err(CoreError::input("a note has one header"));
        }
        if kind == "attachment" {
            return Err(CoreError::input("attachments are added with their file"));
        }
        self.insert(note_id, after, kind, text, BTreeMap::new())
            .await
    }

    async fn insert(
        &self,
        note_id: &str,
        after: Option<&str>,
        kind: &str,
        text: &str,
        attrs: BTreeMap<String, String>,
    ) -> Result<BlockView> {
        Self::check_content(kind, text, &attrs)?;
        let position = {
            let state = self.state.borrow();
            let (header, content) = Self::note_blocks(&state, note_id);
            if header.is_none() && content.is_empty() {
                return Err(CoreError::new(
                    "not_found",
                    "this note does not exist any more",
                ));
            }
            let orders: Vec<&str> = content
                .iter()
                .filter_map(|b| b.payload.as_ref())
                .map(|p| p.order.as_str())
                .collect();
            let index = match after {
                Some(after) => content
                    .iter()
                    .position(|b| b.envelope.block_id == after)
                    .map(|i| i + 1),
                None => Some(0),
            };
            // The block to insert after is gone (deleted on another device):
            // append instead of failing.
            let index = index.unwrap_or(orders.len());
            let low = if index == 0 { "" } else { orders[index - 1] };
            order::between(low, orders.get(index).copied())
        };
        let block_id = self.random_uuid()?;
        let payload = Payload {
            schema: 1,
            kind: kind.to_string(),
            order: position,
            text: text.to_string(),
            attrs,
        };
        self.write_block(&block_id, note_id, Some(payload.clone()))
            .await?;
        Ok(BlockView {
            block_id,
            kind: payload.kind,
            text: payload.text,
            attrs: payload.attrs,
        })
    }

    /// Changes kind, text and attributes of a block. Nothing is written if
    /// nothing changed.
    pub async fn update_block(
        &self,
        block_id: &str,
        kind: &str,
        text: &str,
        attrs: BTreeMap<String, String>,
    ) -> Result<()> {
        Self::check_content(kind, text, &attrs)?;
        let (note_id, mut payload) = {
            let state = self.state.borrow();
            let block = state.blocks.get(block_id);
            match block.and_then(|b| b.payload.clone().map(|p| (b.envelope.note_id.clone(), p))) {
                Some(found) => found,
                None => {
                    return Err(CoreError::new(
                        "not_found",
                        "this block does not exist any more",
                    ))
                }
            }
        };
        if (payload.kind == "header") != (kind == "header") {
            return Err(CoreError::input("a header stays a header"));
        }
        // An attachment keeps its file. Its name (the text) and how it is
        // shown (width, alignment, caption) can change.
        if payload.kind == "attachment" || kind == "attachment" {
            let file = |attrs: &BTreeMap<String, String>| FILE_ATTRS.map(|name| attrs.get(name).cloned());
            if payload.kind != kind || file(&payload.attrs) != file(&attrs) {
                return Err(CoreError::input("an attachment stays an attachment"));
            }
        }
        if payload.kind == kind && payload.text == text && payload.attrs == attrs {
            return Ok(());
        }
        payload.kind = kind.to_string();
        payload.text = text.to_string();
        payload.attrs = attrs;
        self.write_block(block_id, &note_id, Some(payload)).await
    }

    /// Moves a block within its note: behind the block `after`, or to the
    /// top without it.
    pub async fn move_block(&self, block_id: &str, after: Option<&str>) -> Result<()> {
        let (note_id, mut payload) = {
            let state = self.state.borrow();
            let Some(block) = state.blocks.get(block_id) else {
                return Err(CoreError::new("not_found", "this block does not exist any more"));
            };
            let Some(payload) = block.payload.clone().filter(|p| p.kind != "header") else {
                return Err(CoreError::new("not_found", "this block does not exist any more"));
            };
            let note_id = block.envelope.note_id.clone();
            let (_, content) = Self::note_blocks(&state, &note_id);
            // The neighbours at the new place, not counting the block itself.
            let others: Vec<&Block> = content.into_iter().filter(|b| b.envelope.block_id != block_id).collect();
            let index = match after {
                Some(after) if after == block_id => return Ok(()),
                Some(after) => others.iter().position(|b| b.envelope.block_id == after).map_or(others.len(), |i| i + 1),
                None => 0,
            };
            let order_at = |i: usize| others.get(i).and_then(|b| b.payload.as_ref()).map(|p| p.order.as_str());
            let low = if index == 0 { "" } else { order_at(index - 1).unwrap_or("") };
            let order = order::between(low, order_at(index));
            (note_id, Payload { order, ..payload })
        };
        payload.schema = 1;
        self.write_block(block_id, &note_id, Some(payload)).await
    }

    pub async fn delete_block(&self, block_id: &str) -> Result<()> {
        let (note_id, hash) = {
            let state = self.state.borrow();
            match state.blocks.get(block_id) {
                Some(block) if block.payload.is_some() => (
                    block.envelope.note_id.clone(),
                    blob_hash(block.payload.as_ref()).map(str::to_string),
                ),
                _ => return Ok(()),
            }
        };
        self.write_block(block_id, &note_id, None).await?;
        self.forget_blobs(hash).await
    }

    pub async fn delete_note(&self, note_id: &str) -> Result<()> {
        let blocks: Vec<(String, Option<String>)> = {
            let state = self.state.borrow();
            state
                .blocks
                .values()
                .filter(|b| b.envelope.note_id == note_id && b.payload.is_some())
                .map(|b| {
                    (
                        b.envelope.block_id.clone(),
                        blob_hash(b.payload.as_ref()).map(str::to_string),
                    )
                })
                .collect()
        };
        for (block_id, hash) in blocks {
            self.write_block(&block_id, note_id, None).await?;
            self.forget_blobs(hash).await?;
        }
        Ok(())
    }

    // ---------------------------------------------------------- attachments

    /// Removes the local copies of blobs whose attachment block is gone.
    async fn forget_blobs(&self, hashes: impl IntoIterator<Item = String>) -> Result<()> {
        for hash in hashes {
            self.platform
                .file_remove(&upload_file(&hash))
                .await
                .map_err(CoreError::storage)?;
            self.platform
                .file_remove(&blob_file(&hash))
                .await
                .map_err(CoreError::storage)?;
        }
        Ok(())
    }

    /// Adds a file to a note, after the block `after` or at the top without
    /// it. The file is encrypted here with a key of its own; the next sync
    /// uploads it. `mime` decides how the app shows it (image, audio, video
    /// or a plain download).
    pub async fn add_attachment(
        &self,
        note_id: &str,
        after: Option<&str>,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<BlockView> {
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(CoreError::new(
                "too_large",
                "this file is too large to attach",
            ));
        }
        let name: String = name
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_NAME_CHARS)
            .collect();
        let mime = mime.trim().to_ascii_lowercase();
        let plain_mime = mime.len() <= 100
            && mime.split('/').count() == 2
            && mime
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/.+-_".contains(&b));
        let mime = if plain_mime {
            mime
        } else {
            FALLBACK_MIME.to_string()
        };

        let mut key = [0u8; crypto::KEY_LEN];
        let mut prefix = [0u8; crypto::BLOB_PREFIX_LEN];
        self.platform
            .fill_random(&mut key)
            .map_err(|e| CoreError::new("entropy", e.0))?;
        self.platform
            .fill_random(&mut prefix)
            .map_err(|e| CoreError::new("entropy", e.0))?;
        let blob = crypto::seal_blob(&key, &prefix, data);
        let hash = crypto::sha256_hex(&blob);
        let mut attrs = BTreeMap::new();
        attrs.insert("hash".to_string(), hash.clone());
        attrs.insert("key".to_string(), B64.encode(key));
        attrs.insert("size".to_string(), data.len().to_string());
        attrs.insert("mime".to_string(), mime);
        key.zeroize();

        // The blob first: a block must never point to a file that is nowhere.
        self.platform
            .file_write(&blob_file(&hash), &blob)
            .await
            .map_err(CoreError::storage)?;
        self.platform
            .file_write(&upload_file(&hash), &[])
            .await
            .map_err(CoreError::storage)?;
        match self
            .insert(note_id, after, "attachment", &name, attrs)
            .await
        {
            Ok(block) => Ok(block),
            Err(error) => {
                self.forget_blobs([hash]).await?;
                Err(error)
            }
        }
    }

    /// The decrypted file of an attachment block. Fetched from the server the
    /// first time and kept (encrypted) on this device afterwards.
    pub async fn attachment(&self, block_id: &str) -> Result<Vec<u8>> {
        let (hash, mut key) = {
            let state = self.state.borrow();
            let payload = state.blocks.get(block_id).and_then(|b| b.payload.as_ref());
            let hash = blob_hash(payload)
                .ok_or_else(|| CoreError::new("not_found", "this is not an attachment"))?;
            let raw = payload
                .and_then(|p| p.attrs.get("key"))
                .and_then(|k| B64.decode(k).ok());
            let key: [u8; crypto::KEY_LEN] = raw
                .and_then(|k| k.as_slice().try_into().ok())
                .ok_or_else(|| CoreError::new("corrupt", "the attachment has no usable key"))?;
            (hash.to_string(), key)
        };
        let stored = self
            .platform
            .file_read(&blob_file(&hash))
            .await
            .map_err(CoreError::storage)?;
        let blob = match stored {
            Some(blob) => blob,
            None => {
                let (server_url, token) = self.session_endpoint()?;
                let path = format!("/v1/blobs/{hash}");
                let response = self
                    .send(&server_url, "GET", &path, Some(&token), None)
                    .await?;
                if response.status == 404 {
                    return Err(CoreError::new(
                        "not_uploaded",
                        "the device that added this file has not uploaded it yet",
                    ));
                }
                if response.status != 200 {
                    return Err(Self::failure(&response));
                }
                // The server is not trusted: only the bytes the block names.
                if crypto::sha256_hex(&response.body) != hash {
                    return Err(CoreError::new(
                        "corrupt",
                        "the server sent a different file",
                    ));
                }
                self.platform
                    .file_write(&blob_file(&hash), &response.body)
                    .await
                    .map_err(CoreError::storage)?;
                response.body
            }
        };
        let plain = crypto::open_blob(&key, &blob);
        key.zeroize();
        match plain {
            Some(plain) => Ok(plain),
            None => {
                // A damaged local copy; the next attempt fetches it again.
                self.platform
                    .file_remove(&blob_file(&hash))
                    .await
                    .map_err(CoreError::storage)?;
                Err(CoreError::new(
                    "corrupt",
                    "the attachment failed its integrity check",
                ))
            }
        }
    }

    /// Uploads attachments added on this device. Runs before blocks are
    /// pushed, so other devices never see a block whose file is missing.
    async fn upload_blobs(
        &self,
        server_url: &str,
        token: &str,
        report: &mut SyncReport,
    ) -> Result<()> {
        for marker in self
            .platform
            .file_list(UPLOAD_PREFIX)
            .await
            .map_err(CoreError::storage)?
        {
            let Some(hash) = marker.strip_prefix(UPLOAD_PREFIX) else {
                continue;
            };
            let path = format!("/v1/blobs/{hash}");
            let exists = self
                .send(server_url, "HEAD", &path, Some(token), None)
                .await?;
            let done = match exists.status {
                200 => true,
                404 => match self
                    .platform
                    .file_read(&blob_file(hash))
                    .await
                    .map_err(CoreError::storage)?
                {
                    // Deleted again before it was ever uploaded.
                    None => true,
                    Some(blob) => {
                        let body = Some(("application/octet-stream", blob));
                        let response = self
                            .send(server_url, "PUT", &path, Some(token), body)
                            .await?;
                        match response.status {
                            200 | 201 => true,
                            // Too large for this server or the account's
                            // space is used up: trying again will not help.
                            413 => {
                                report.rejected += 1;
                                true
                            }
                            _ => return Err(Self::failure(&response)),
                        }
                    }
                },
                _ => return Err(Self::failure(&exists)),
            };
            if done {
                self.platform
                    .file_remove(&marker)
                    .await
                    .map_err(CoreError::storage)?;
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------- sync

    async fn save_meta(&self) -> Result<()> {
        let meta = Meta {
            cursor: self.state.borrow().cursor,
        };
        let bytes =
            serde_json::to_vec(&meta).map_err(|e| CoreError::new("storage", e.to_string()))?;
        self.platform
            .file_write(META_FILE, &bytes)
            .await
            .map_err(CoreError::storage)
    }

    /// Uploads local changes, then downloads what other devices changed.
    /// Safe to call at any time; a second call while one runs returns `busy`.
    pub async fn sync(&self) -> Result<SyncReport> {
        if self.syncing.replace(true) {
            return Err(CoreError::new("busy", "a sync is already running"));
        }
        let _guard = SyncGuard(&self.syncing);
        let (server_url, token) = self.session_endpoint()?;
        let mut report = SyncReport::default();
        self.upload_blobs(&server_url, &token, &mut report).await?;
        self.push(&server_url, &token, &mut report).await?;
        self.pull(&server_url, &token, &mut report).await?;
        Ok(report)
    }

    async fn push(&self, server_url: &str, token: &str, report: &mut SyncReport) -> Result<()> {
        #[derive(Serialize)]
        struct Request<'a> {
            changes: &'a [Envelope],
        }
        // Every version is offered once per sync, so a block the server keeps
        // refusing cannot make this loop run forever.
        let mut offered: BTreeSet<(String, String)> = BTreeSet::new();
        loop {
            let batch: Vec<Envelope> = {
                let state = self.state.borrow();
                let mut bytes = 0;
                state
                    .blocks
                    .values()
                    .filter(|b| {
                        b.dirty
                            && !offered.contains(&(
                                b.envelope.block_id.clone(),
                                b.envelope.version.clone(),
                            ))
                    })
                    .take(PUSH_BATCH_BLOCKS)
                    .take_while(|b| {
                        bytes += b.envelope.ciphertext.len() + 256;
                        bytes <= PUSH_BATCH_BYTES || bytes == b.envelope.ciphertext.len() + 256
                    })
                    .map(|b| b.envelope.clone())
                    .collect()
            };
            if batch.is_empty() {
                return Ok(());
            }
            for envelope in &batch {
                offered.insert((envelope.block_id.clone(), envelope.version.clone()));
            }
            let response = self
                .call(
                    server_url,
                    "POST",
                    "/v1/changes",
                    Some(token),
                    Some(&Request { changes: &batch }),
                )
                .await?;
            let answer: PushResponse = serde_json::from_slice(&response.body)
                .map_err(|_| CoreError::protocol("unexpected answer to a push"))?;

            let mut writes = Vec::new();
            {
                let mut state = self.state.borrow_mut();
                for (sent, result) in batch.iter().zip(&answer.results) {
                    if result.block_id != sent.block_id {
                        return Err(CoreError::protocol("push results do not match the request"));
                    }
                    let settled = match result.status.as_str() {
                        // "stale": the server already has something newer,
                        // which the pull below brings in.
                        "accepted" | "duplicate" | "stale" => true,
                        "rejected" if result.reason == "clock_skew" => {
                            report.clock_skew = true;
                            false
                        }
                        "rejected" => {
                            report.rejected += 1;
                            true
                        }
                        _ => false,
                    };
                    if !settled {
                        continue;
                    }
                    if result.status == "accepted" {
                        report.pushed += 1;
                    }
                    // Only if the block was not edited again in the meantime.
                    if let Some(block) = state.blocks.get_mut(&sent.block_id) {
                        if block.dirty && block.envelope.version == sent.version {
                            block.dirty = false;
                            writes.push((block_file(&sent.block_id), stored_bytes(block)?));
                        }
                    }
                }
            }
            for (name, bytes) in writes {
                self.platform
                    .file_write(&name, &bytes)
                    .await
                    .map_err(CoreError::storage)?;
            }
        }
    }

    async fn pull(&self, server_url: &str, token: &str, report: &mut SyncReport) -> Result<()> {
        // During a full resync: every block the server still has.
        let mut seen: Option<BTreeSet<String>> = None;
        let mut changed: BTreeSet<String> = BTreeSet::new();
        loop {
            let cursor = self.state.borrow().cursor;
            let path = format!("/v1/changes?since={cursor}&limit={PULL_LIMIT}");
            let response = match self
                .call::<()>(server_url, "GET", &path, Some(token), None)
                .await
            {
                Ok(response) => response,
                Err(error) if error.code == "cursor_expired" && seen.is_none() => {
                    // This device was away for so long that the server has
                    // dropped deletion markers it would have needed.
                    report.full_resync = true;
                    seen = Some(BTreeSet::new());
                    self.state.borrow_mut().cursor = 0;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let page: PullResponse = serde_json::from_slice(&response.body)
                .map_err(|_| CoreError::protocol("unexpected answer to a pull"))?;
            if page.next_cursor < cursor || (page.has_more && page.next_cursor == cursor) {
                return Err(CoreError::protocol("the server's cursor does not advance"));
            }

            let mut writes = Vec::new();
            let mut dropped_blobs = Vec::new();
            {
                let mut state = self.state.borrow_mut();
                let state = &mut *state;
                let Some(session) = state.session.as_ref() else {
                    return Err(CoreError::not_signed_in());
                };
                for envelope in page.changes {
                    if let Some(seen) = seen.as_mut() {
                        seen.insert(envelope.block_id.clone());
                    }
                    let Ok(payload) = decode(&session.key, &envelope) else {
                        report.undecryptable += 1;
                        continue;
                    };
                    // Only authenticated versions move the clock.
                    state.clock.observe(&envelope.version);
                    let newer = match state.blocks.get_mut(&envelope.block_id) {
                        None => true,
                        Some(local) if local.envelope.version < envelope.version => true,
                        Some(local) => {
                            if local.envelope.version == envelope.version && local.dirty {
                                local.dirty = false;
                                writes.push((block_file(&envelope.block_id), stored_bytes(local)?));
                            }
                            false
                        }
                    };
                    if newer {
                        let block = Block {
                            envelope,
                            dirty: false,
                            payload,
                        };
                        writes.push((block_file(&block.envelope.block_id), stored_bytes(&block)?));
                        changed.insert(block.envelope.note_id.clone());
                        report.pulled += 1;
                        let new_hash = blob_hash(block.payload.as_ref()).map(str::to_string);
                        if let Some(old) =
                            state.blocks.insert(block.envelope.block_id.clone(), block)
                        {
                            if let Some(old_hash) = blob_hash(old.payload.as_ref()) {
                                if new_hash.as_deref() != Some(old_hash) {
                                    dropped_blobs.push(old_hash.to_string());
                                }
                            }
                        }
                    }
                }
                state.cursor = page.next_cursor;
            }
            for (name, bytes) in writes {
                self.platform
                    .file_write(&name, &bytes)
                    .await
                    .map_err(CoreError::storage)?;
            }
            self.forget_blobs(dropped_blobs).await?;
            self.save_meta().await?;
            if !page.has_more {
                break;
            }
        }

        if let Some(seen) = seen {
            // Whatever the server no longer has was deleted while this
            // device was away. Local changes not yet uploaded are kept.
            let gone: Vec<(String, String)> = {
                let state = self.state.borrow();
                state
                    .blocks
                    .values()
                    .filter(|b| !b.dirty && !seen.contains(&b.envelope.block_id))
                    .map(|b| (b.envelope.block_id.clone(), b.envelope.note_id.clone()))
                    .collect()
            };
            for (block_id, note_id) in gone {
                let removed = self.state.borrow_mut().blocks.remove(&block_id);
                let hash = removed
                    .as_ref()
                    .and_then(|b| blob_hash(b.payload.as_ref()))
                    .map(str::to_string);
                self.platform
                    .file_remove(&block_file(&block_id))
                    .await
                    .map_err(CoreError::storage)?;
                self.forget_blobs(hash).await?;
                changed.insert(note_id);
            }
        }
        report.changed_notes = changed.into_iter().collect();
        Ok(())
    }
}
