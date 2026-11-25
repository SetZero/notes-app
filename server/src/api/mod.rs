//! HTTP API: router, middleware and the extractors every handler shares.

mod accounts;
mod pairing;
mod sync;

use axum::extract::{
    ConnectInfo, DefaultBodyLimit, FromRequest, FromRequestParts, OriginalUri, Request, State,
};
use axum::http::request::Parts;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::error::{ApiError, REQUEST_ID};
use crate::ratelimit::Class;
use crate::store::DeviceCtx;
use crate::{util, AppState};

pub const TOKEN_BYTES: usize = 32;

/// JSON body with our error format instead of axum's plain-text rejections.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

/// Query string with our error format.
#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);

fn client_ip(parts: &Parts, state: &AppState) -> Result<IpAddr, ApiError> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
        .ok_or_else(|| ApiError::internal("peer address missing"))?;
    // Only a configured reverse proxy may tell us who the client is. The proxy
    // appends the address it saw, so the last entry is the one it vouches for.
    if state.config.server.trusted_proxies.iter().any(|net| net.contains(peer)) {
        let forwarded = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok());
        if let Some(ip) = forwarded {
            return Ok(ip);
        }
    }
    Ok(peer)
}

/// The client's IP address, used as the rate-limit key for unauthenticated calls.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        client_ip(parts, state).map(ClientIp)
    }
}

/// Extracts a 32-byte bearer token. Anything else counts as no token.
pub fn bearer_token(parts: &Parts) -> Option<Vec<u8>> {
    let value = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = util::b64_decode(value.strip_prefix("Bearer ")?)?;
    (token.len() == TOKEN_BYTES).then_some(token)
}

/// An authenticated, non-revoked device. Handlers that take this cannot be
/// reached without a valid device token.
pub struct Device(pub DeviceCtx);

impl FromRequestParts<AppState> for Device {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let ip = client_ip(parts, state)?;
        let device = match bearer_token(parts) {
            // Only the hash is stored, so a database leak does not leak tokens.
            Some(token) => state.store.find_device_by_token_hash(&util::sha256(&token)).await?,
            None => None,
        };
        match device {
            Some(ctx) => {
                state.limiter.check(Class::Device, &ctx.device_id)?;
                Ok(Device(ctx))
            }
            None => {
                state.limiter.check(Class::AuthFail, &ip.to_string())?;
                Err(ApiError::unauthorized())
            }
        }
    }
}

/// A new random token: the value for the client and the hash for the database.
pub fn new_token() -> (String, Vec<u8>) {
    let token = util::random_bytes::<TOKEN_BYTES>();
    (util::b64(&token), util::sha256(&token))
}

pub fn validate_device_name(name: &str) -> Result<(), ApiError> {
    let chars = name.chars().count();
    if chars == 0 || chars > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::validation("device_name must have 1 to 64 printable characters"));
    }
    Ok(())
}

/// Decodes a base64 field and checks its length.
pub fn decode_field(name: &str, value: &str, min: usize, max: usize) -> Result<Vec<u8>, ApiError> {
    // Reject oversized input before decoding it.
    if value.len() > max.div_ceil(3) * 4 {
        return Err(ApiError::validation(format!("{name} is too long")));
    }
    let bytes = util::b64_decode(value).ok_or_else(|| ApiError::validation(format!("{name} is not valid base64")))?;
    if bytes.len() < min || bytes.len() > max {
        return Err(ApiError::validation(format!("{name} has the wrong length")));
    }
    Ok(bytes)
}

pub fn parse_uuid(name: &str, value: &str) -> Result<String, ApiError> {
    util::canonical_uuid(value).ok_or_else(|| ApiError::validation(format!("{name} is not a UUID")))
}

async fn request_id(request: Request, next: Next) -> Response {
    let id = util::new_uuid();
    let mut response = REQUEST_ID.scope(id.clone(), next.run(request)).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(HeaderName::from_static("x-request-id"), value);
    }
    response
}

async fn healthz() -> &'static str {
    "ok"
}

async fn meta(State(state): State<AppState>, ClientIp(ip): ClientIp) -> Result<Json<serde_json::Value>, ApiError> {
    state.limiter.check(Class::Public, &ip.to_string())?;
    let limits = &state.config.limits;
    let providers: Vec<_> = state
        .oidc
        .configs()
        .map(|p| {
            serde_json::json!({
                "id": p.id, "issuer": p.issuer, "client_id": p.client_id, "scopes": p.scopes,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "api_versions": ["v1"],
        "server_time": util::rfc3339(util::now_ms()),
        "limits": {
            "max_batch_blocks": limits.max_batch_blocks,
            "max_block_ciphertext_bytes": limits.max_block_ciphertext_bytes,
            "max_request_bytes": limits.max_request_bytes,
            "max_blob_bytes": limits.max_blob_bytes,
            "max_clock_skew_seconds": limits.max_clock_skew_seconds,
        },
        "auth": {
            "enrollment": state.config.enrollment.mode.as_str(),
            "oidc": providers,
        },
    })))
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// What the web app may do in the browser. It holds the account key, so the
/// policy allows nothing but its own files: no inline or remote scripts, no
/// remote styles, images or connections, no framing, no DOM injection sinks.
/// `wasm-unsafe-eval` permits compiling the app's own WebAssembly module and
/// nothing else.
const WEB_APP_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval';     style-src 'self'; img-src 'self'; connect-src 'self'; manifest-src 'self';     base-uri 'none'; form-action 'none'; frame-ancestors 'none';     require-trusted-types-for 'script'; trusted-types 'none'";

/// The API returns data, never documents: it may load and run nothing.
const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// The built web app from `dir`, mounted by the caller at `/app`.
fn web_app(dir: &std::path::Path) -> Router {
    // The page uses relative URLs, which resolve correctly only below "/app/".
    async fn add_slash(OriginalUri(uri): OriginalUri, request: Request, next: Next) -> Response {
        if uri.path() == "/app" {
            return Redirect::permanent("/app/").into_response();
        }
        next.run(request).await
    }
    let overriding = |name: HeaderName, value: &'static str| {
        SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
    };
    Router::new()
        .fallback_service(tower_http::services::ServeDir::new(dir))
        .layer(axum::middleware::from_fn(add_slash))
        // Always ask the server whether a file changed, so that a fixed
        // version of the app is in use right after it is deployed.
        .layer(overriding(header::CACHE_CONTROL, "no-cache"))
        .layer(overriding(header::CONTENT_SECURITY_POLICY, WEB_APP_CSP))
        .layer(overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ))
        .layer(overriding(
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ))
        .layer(overriding(
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ))
}

pub fn router(state: AppState) -> Router {
    let json_api = Router::new()
        .route("/v1/meta", get(meta))
        .route("/v1/auth/oidc/nonce", post(accounts::oidc_nonce))
        .route("/v1/accounts", post(accounts::create_account))
        .route("/v1/accounts/{account_id}/recover", post(accounts::recover_account))
        .route("/v1/devices", get(accounts::list_devices))
        .route("/v1/devices/{device_id}", delete(accounts::revoke_device))
        .route("/v1/pairings", post(pairing::create))
        .route("/v1/pairings/claim", post(pairing::claim))
        .route("/v1/pairings/{pairing_id}", get(pairing::poll))
        .route("/v1/pairings/{pairing_id}/approve", post(pairing::approve))
        .route("/v1/changes", get(sync::pull).post(sync::push))
        .layer(DefaultBodyLimit::max(state.config.limits.max_request_bytes))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)));

    // Attachments are streamed with their own size limit and a longer timeout.
    let blob_api = Router::new()
        .route(
            "/v1/blobs/{hash}",
            get(sync::get_blob).head(sync::head_blob).put(sync::put_blob),
        )
        .layer(DefaultBodyLimit::disable())
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(600)));

    // The event stream stays open, so it has no request timeout.
    let events_api = Router::new().route("/v1/events", get(sync::events));

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .merge(json_api)
        .merge(blob_api)
        .merge(events_api);

    app = match &state.config.server.static_dir {
        Some(dir) => app
            .route("/", get(|| async { Redirect::temporary("/app/") }))
            .nest_service("/app", web_app(dir))
            .fallback(not_found),
        None => app.fallback(not_found),
    };

    let mut app = app
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(API_CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ));
    if state.secure_transport {
        app = app.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        ));
    }
    app.layer(axum::middleware::from_fn(request_id)).with_state(state)
}
