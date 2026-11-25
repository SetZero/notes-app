//! Shared test harness: an in-process server with a temporary SQLite database.
#![allow(dead_code)]

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;

use notes_syncd::config::Config;
use notes_syncd::{api, AppState};

pub const INVITE: &str = "test-invite-code-0123456789";

pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    next_ip: AtomicU32,
    _dir: tempfile::TempDir,
}

pub struct Account {
    pub account_id: String,
    pub device_id: String,
    pub token: String,
}

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn version(ms: i64, counter: u16) -> String {
    format!("{ms:012x}{counter:04x}{:08x}", 0xabcd_ef01u32)
}

pub fn now_ms() -> i64 {
    notes_syncd::util::now_ms()
}

pub fn block(block_id: &str, version: &str, payload: &[u8]) -> Value {
    json!({
        "block_id": block_id,
        "note_id": "11111111-1111-4111-8111-111111111111",
        "version": version,
        "deleted": false,
        "nonce": b64(&[7u8; 12]),
        "ciphertext": b64(payload),
    })
}

pub async fn app() -> TestApp {
    app_with(|_| {}).await
}

pub async fn app_with(configure: impl FnOnce(&mut Config)) -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.server.data_dir = dir.path().to_path_buf();
    config.enrollment.invite_code = Some(INVITE.into());
    // With NOTES_TEST_POSTGRES_URL (a server URL without a database name, for
    // example postgres://postgres:secret@127.0.0.1:5432) every test gets its
    // own freshly created database on that server instead of SQLite.
    if let Ok(server_url) = std::env::var("NOTES_TEST_POSTGRES_URL") {
        use sqlx::Connection;
        sqlx::any::install_default_drivers();
        let name = format!("t_{}", uuid::Uuid::new_v4().simple());
        let mut admin = sqlx::AnyConnection::connect(&format!("{server_url}/postgres")).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut admin).await.unwrap();
        admin.close().await.unwrap();
        config.server.database_url = Some(format!("{server_url}/{name}"));
    }
    configure(&mut config);
    let state = AppState::new(config).await.unwrap();
    TestApp { router: api::router(state.clone()), state, next_ip: AtomicU32::new(1), _dir: dir }
}

impl TestApp {
    /// Each request comes from a fresh address unless a test pins one,
    /// so per-IP rate limits do not interfere with unrelated tests.
    fn fresh_ip(&self) -> IpAddr {
        let n = self.next_ip.fetch_add(1, Ordering::Relaxed);
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n))
    }

    pub async fn send(
        &self,
        ip: Option<IpAddr>,
        method: Method,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Body,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(body).unwrap();
        let ip = ip.unwrap_or_else(|| self.fresh_ip());
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 40000)));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        (parts.status, parts.headers, bytes)
    }

    pub async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
        self.call_from(None, method, path, token, body).await
    }

    pub async fn call_from(
        &self,
        ip: Option<IpAddr>,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (headers, body): (&[(&str, &str)], Body) = match body {
            Some(json) => (&[("content-type", "application/json")], Body::from(json.to_string())),
            None => (&[], Body::empty()),
        };
        let (status, _, bytes) = self.send(ip, method, path, token, headers, body).await;
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    pub async fn create_account(&self, device_name: &str) -> Account {
        let (status, body) = self
            .call(
                Method::POST,
                "/v1/accounts",
                None,
                Some(json!({
                    "invite_code": INVITE,
                    "device_name": device_name,
                    "recovery_verifier": b64(&[9u8; 32]),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        Account {
            account_id: body["account_id"].as_str().unwrap().into(),
            device_id: body["device_id"].as_str().unwrap().into(),
            token: body["token"].as_str().unwrap().into(),
        }
    }

    pub async fn push(&self, token: &str, changes: Vec<Value>) -> (StatusCode, Value) {
        self.call(Method::POST, "/v1/changes", Some(token), Some(json!({ "changes": changes }))).await
    }

    pub async fn pull(&self, token: &str, query: &str) -> (StatusCode, Value) {
        self.call(Method::GET, &format!("/v1/changes?{query}"), Some(token), None).await
    }
}
