//! The change feed of encrypted blocks, attachments, and change notifications.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Response;
use axum::Json;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_stream::wrappers::WatchStream;
use tokio_util::io::ReaderStream;

use super::{decode_field, parse_uuid, ApiJson, ApiQuery, Device};
use crate::blobs::PutOutcome;
use crate::error::ApiError;
use crate::store::{BlockIn, Upsert};
use crate::{util, AppState};

const MAX_PULL_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_PULL_BYTES: usize = 1024 * 1024;
const GCM_TAG_BYTES: usize = 16;
/// Event streams end after this long; the client reconnects and is authenticated again.
const MAX_EVENT_STREAM: Duration = Duration::from_secs(3600);

#[derive(Deserialize)]
pub struct PullQuery {
    since: i64,
    limit: Option<usize>,
    max_bytes: Option<usize>,
}

#[derive(Deserialize)]
pub struct BlockUpload {
    block_id: String,
    note_id: String,
    version: String,
    deleted: bool,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
pub struct PushRequest {
    changes: Vec<BlockUpload>,
}

pub async fn pull(
    State(state): State<AppState>,
    Device(ctx): Device,
    ApiQuery(query): ApiQuery<PullQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if query.since < 0 {
        return Err(ApiError::validation("since must not be negative"));
    }
    let max_batch = state.config.limits.max_batch_blocks;
    let limit = query.limit.unwrap_or(max_batch);
    if limit == 0 {
        return Err(ApiError::validation("limit must be at least 1"));
    }
    let max_bytes = query.max_bytes.unwrap_or(DEFAULT_PULL_BYTES).clamp(1, MAX_PULL_BYTES);
    let slice = state
        .store
        .changes_since(&ctx, query.since, limit.min(max_batch), max_bytes, util::now_ms())
        .await?
        .ok_or_else(ApiError::cursor_expired)?;
    let changes: Vec<_> = slice
        .blocks
        .iter()
        .map(|b| {
            serde_json::json!({
                "block_id": b.block.block_id,
                "note_id": b.block.note_id,
                "version": b.block.version,
                "deleted": b.block.deleted,
                "nonce": util::b64(&b.block.nonce),
                "ciphertext": util::b64(&b.block.ciphertext),
                "seq": b.seq,
                "origin_device_id": b.origin_device_id,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "changes": changes,
        "next_cursor": slice.next_cursor,
        "has_more": slice.has_more,
    })))
}

/// Milliseconds since the epoch from the first 12 hex digits of a version.
fn version_time_ms(version: &str) -> Option<i64> {
    if !util::is_lower_hex(version, 24) {
        return None;
    }
    i64::from_str_radix(&version[..12], 16).ok()
}

pub async fn push(
    State(state): State<AppState>,
    Device(ctx): Device,
    ApiJson(body): ApiJson<PushRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limits = &state.config.limits;
    if body.changes.is_empty() || body.changes.len() > limits.max_batch_blocks {
        return Err(ApiError::validation(format!(
            "changes must hold 1 to {} blocks",
            limits.max_batch_blocks
        )));
    }
    let now = util::now_ms();
    let latest_allowed = now + limits.max_clock_skew_seconds * 1000;

    // Malformed ids or encodings fail the whole request. Blocks that are well
    // formed but not acceptable are rejected one by one.
    let mut rejected: Vec<Option<&'static str>> = Vec::with_capacity(body.changes.len());
    let mut accepted = Vec::new();
    for upload in &body.changes {
        let block_id = parse_uuid("block_id", &upload.block_id)?;
        let note_id = parse_uuid("note_id", &upload.note_id)?;
        let nonce = decode_field("nonce", &upload.nonce, 12, 12)?;
        // The request body is already capped, so decoding up to that size is safe.
        let ciphertext = decode_field("ciphertext", &upload.ciphertext, GCM_TAG_BYTES, limits.max_request_bytes)?;
        let reason = match version_time_ms(&upload.version) {
            None => Some("invalid_version"),
            Some(t) if t > latest_allowed => Some("clock_skew"),
            Some(_) if ciphertext.len() > limits.max_block_ciphertext_bytes => Some("ciphertext_too_large"),
            Some(_) => None,
        };
        rejected.push(reason);
        if reason.is_none() {
            accepted.push(BlockIn {
                block_id,
                note_id,
                version: upload.version.clone(),
                deleted: upload.deleted,
                nonce,
                ciphertext,
            });
        }
    }

    let (outcomes, cursor) = state.store.upsert_blocks(&ctx, &accepted, now).await?;
    let mut outcomes = outcomes.into_iter();
    let mut any_accepted = false;
    let results: Vec<_> = body
        .changes
        .iter()
        .zip(&rejected)
        .map(|(upload, reason)| {
            if let Some(reason) = reason {
                return serde_json::json!({ "block_id": upload.block_id, "status": "rejected", "reason": reason });
            }
            match outcomes.next() {
                Some(Upsert::Accepted(seq)) => {
                    any_accepted = true;
                    serde_json::json!({ "block_id": upload.block_id, "status": "accepted", "seq": seq })
                }
                Some(Upsert::Duplicate(seq)) => {
                    serde_json::json!({ "block_id": upload.block_id, "status": "duplicate", "seq": seq })
                }
                Some(Upsert::Stale) | None => {
                    serde_json::json!({ "block_id": upload.block_id, "status": "stale" })
                }
            }
        })
        .collect();
    if any_accepted {
        state.events.publish(&ctx.account_id, cursor);
    }
    Ok(Json(serde_json::json!({ "results": results, "cursor": cursor })))
}

fn validate_hash(hash: &str) -> Result<(), ApiError> {
    if util::is_lower_hex(hash, 64) {
        Ok(())
    } else {
        Err(ApiError::validation("hash must be 64 lower-case hex characters"))
    }
}

pub async fn head_blob(
    State(state): State<AppState>,
    Device(ctx): Device,
    Path(hash): Path<String>,
) -> Result<Response, ApiError> {
    validate_hash(&hash)?;
    let size = state
        .store
        .blob_size(&ctx.account_id, &hash)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let mut response = Response::new(Body::empty());
    response.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    Ok(response)
}

/// Parses `bytes=N-`. Other range forms are ignored and the whole blob is sent.
fn range_start(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(header::RANGE)?.to_str().ok()?;
    value.strip_prefix("bytes=")?.strip_suffix('-')?.parse().ok()
}

pub async fn get_blob(
    State(state): State<AppState>,
    Device(ctx): Device,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_hash(&hash)?;
    // The database row is the authority on which account owns which blob.
    let size = state
        .store
        .blob_size(&ctx.account_id, &hash)
        .await?
        .ok_or_else(ApiError::not_found)? as u64;
    let mut file = state.blobs.open_read(&ctx.account_id, &hash).await?;
    let start = range_start(&headers).filter(|s| *s > 0 && *s < size);
    let mut response = match start {
        Some(start) => {
            file.seek(std::io::SeekFrom::Start(start)).await?;
            let mut r = Response::new(Body::from_stream(ReaderStream::new(file.take(size - start))));
            *r.status_mut() = StatusCode::PARTIAL_CONTENT;
            let range = format!("bytes {start}-{}/{size}", size - 1);
            r.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&range).map_err(ApiError::internal)?,
            );
            r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(size - start));
            r
        }
        None => {
            let mut r = Response::new(Body::from_stream(ReaderStream::new(file.take(size))));
            r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(size));
            r
        }
    };
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    Ok(response)
}

pub async fn put_blob(
    State(state): State<AppState>,
    Device(ctx): Device,
    Path(hash): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiError> {
    validate_hash(&hash)?;
    if state.store.blob_size(&ctx.account_id, &hash).await?.is_some() {
        return Ok(StatusCode::OK);
    }
    let limits = &state.config.limits;
    let declared: Option<u64> = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if declared.is_some_and(|len| len > limits.max_blob_bytes) {
        return Err(ApiError::blob_too_large());
    }
    // Per-account quota, so one account cannot fill the disk.
    let used = state.store.blob_usage(&ctx.account_id).await? as u64;
    let remaining = limits.max_account_blob_bytes.saturating_sub(used);
    if remaining == 0 || declared.is_some_and(|len| len > remaining) {
        return Err(ApiError::blob_too_large().detail("account storage quota reached"));
    }
    let max = limits.max_blob_bytes.min(remaining);
    match state.blobs.put(&ctx.account_id, &hash, body.into_data_stream(), max).await? {
        PutOutcome::Stored(size) => {
            state.store.insert_blob(&ctx.account_id, &hash, size as i64, util::now_ms()).await?;
            Ok(StatusCode::CREATED)
        }
        PutOutcome::TooLarge => Err(ApiError::blob_too_large()),
        PutOutcome::HashMismatch => Err(ApiError::hash_mismatch()),
        PutOutcome::Aborted => Err(ApiError::malformed("upload was interrupted")),
    }
}

pub async fn events(
    State(state): State<AppState>,
    Device(ctx): Device,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let receiver = state.events.subscribe(&ctx.account_id)?;
    let stream = WatchStream::from_changes(receiver)
        .map(|cursor| Ok(Event::default().event("changed").data(format!("{{\"cursor\":{cursor}}}"))))
        .take_until(tokio::time::sleep(MAX_EVENT_STREAM));
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(25))))
}
