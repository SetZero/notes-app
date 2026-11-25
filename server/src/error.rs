//! API errors, rendered as RFC 9457 problem details with a stable `code`.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

tokio::task_local! {
    /// Set by the request-id middleware for the duration of one request.
    pub static REQUEST_ID: String;
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: Option<String>,
    pub retry_after: Option<u64>,
    pub extra: Option<(&'static str, String)>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code, detail: None, retry_after: None, extra: None }
    }
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    pub fn extra(mut self, key: &'static str, value: String) -> Self {
        self.extra = Some((key, value));
        self
    }

    pub fn malformed(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "malformed_request").detail(detail)
    }
    pub fn validation(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "validation_failed").detail(detail)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden")
    }
    pub fn invalid_invite() -> Self {
        Self::new(StatusCode::FORBIDDEN, "invalid_invite")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found")
    }
    pub fn account_exists(account_id: String) -> Self {
        Self::new(StatusCode::CONFLICT, "account_exists").extra("account_id", account_id)
    }
    pub fn pairing_conflict() -> Self {
        Self::new(StatusCode::CONFLICT, "pairing_state_conflict")
    }
    pub fn pairing_expired() -> Self {
        Self::new(StatusCode::GONE, "pairing_expired")
    }
    pub fn cursor_expired() -> Self {
        Self::new(StatusCode::GONE, "cursor_expired")
    }
    pub fn payload_too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
    }
    pub fn blob_too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "blob_too_large")
    }
    pub fn hash_mismatch() -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "hash_mismatch")
    }
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        let mut e = Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        e.retry_after = Some(retry_after_secs.max(1));
        e
    }
    /// Logs the cause and returns a response that reveals nothing about it.
    pub fn internal(cause: impl std::fmt::Display) -> Self {
        tracing::error!(error = %cause, "internal error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal")
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::internal(e)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(e)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(r: JsonRejection) -> Self {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::payload_too_large()
        } else {
            Self::malformed(r.body_text())
        }
    }
}

impl From<QueryRejection> for ApiError {
    fn from(r: QueryRejection) -> Self {
        Self::malformed(r.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = REQUEST_ID.try_with(|id| id.clone()).unwrap_or_default();
        let mut body = serde_json::json!({
            "type": "about:blank",
            "title": self.status.canonical_reason().unwrap_or("Error"),
            "status": self.status.as_u16(),
            "code": self.code,
            "request_id": request_id,
        });
        if let Some(detail) = self.detail {
            body["detail"] = detail.into();
        }
        if let Some((key, value)) = self.extra {
            body[key] = value.into();
        }
        let mut response = (self.status, body.to_string()).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
        if let Some(secs) = self.retry_after {
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}
