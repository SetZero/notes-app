//! Device pairing. The server relays the SPAKE2 messages and the wrapped account
//! key between the two devices. It never sees the pairing secret or the key.

use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use super::{bearer_token, decode_field, new_token, parse_uuid, validate_device_name, ApiJson, ClientIp, Device};
use crate::error::ApiError;
use crate::ratelimit::Class;
use crate::store::{NewDevice, NewPairing, PairingError};
use crate::{util, AppState};

const PAIRING_TTL_MS: i64 = 5 * 60 * 1000;
const CHANNEL_DIGITS: usize = 6;
const MAX_PAKE_MSG_BYTES: usize = 128;
const MAX_WRAPPED_KEY_BYTES: usize = 256;

#[derive(Deserialize)]
pub struct CreateRequest {
    device_name: String,
    pake_msg: String,
}

#[derive(Deserialize)]
pub struct ClaimRequest {
    channel: String,
}

#[derive(Deserialize)]
pub struct WrappedKey {
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pake_msg: String,
    wrapped_account_key: WrappedKey,
}

impl From<PairingError> for ApiError {
    fn from(e: PairingError) -> Self {
        match e {
            PairingError::NotFound => ApiError::not_found(),
            PairingError::Conflict => ApiError::pairing_conflict(),
            PairingError::Expired => ApiError::pairing_expired(),
        }
    }
}

/// A uniformly random decimal channel number (rejection sampling, no modulo bias).
fn random_channel() -> String {
    loop {
        let n = u32::from_le_bytes(util::random_bytes::<4>());
        if n < 4_000_000_000 {
            return format!("{:0width$}", n % 1_000_000, width = CHANNEL_DIGITS);
        }
    }
}

pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(body): ApiJson<CreateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    state.limiter.check(Class::Enroll, &ip.to_string())?;
    validate_device_name(&body.device_name)?;
    let pake_msg = decode_field("pake_msg", &body.pake_msg, 1, MAX_PAKE_MSG_BYTES)?;
    let pairing_id = util::new_uuid();
    let (poll_token, poll_token_hash) = new_token();
    let now = util::now_ms();
    for _ in 0..8 {
        let channel = random_channel();
        let pairing = NewPairing {
            id: &pairing_id,
            channel: &channel,
            poll_token_hash: &poll_token_hash,
            device_name: &body.device_name,
            pake_msg: &pake_msg,
            expires_at: now + PAIRING_TTL_MS,
        };
        if state.store.create_pairing(pairing, now).await? {
            return Ok((
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "pairing_id": pairing_id,
                    "channel": channel,
                    "poll_token": poll_token,
                    "expires_in": PAIRING_TTL_MS / 1000,
                })),
            ));
        }
    }
    Err(ApiError::internal("no free pairing channel"))
}

pub async fn claim(
    State(state): State<AppState>,
    Device(ctx): Device,
    ApiJson(body): ApiJson<ClaimRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Strict limit: stops a device from walking through channel numbers.
    state.limiter.check(Class::PairingClaim, &ctx.device_id)?;
    if body.channel.len() != CHANNEL_DIGITS || !body.channel.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::validation("channel must be 6 digits"));
    }
    let claimed = state
        .store
        .claim_pairing(&body.channel, &ctx.account_id, util::now_ms())
        .await??;
    Ok(Json(serde_json::json!({
        "pairing_id": claimed.id,
        "device_name": claimed.device_name,
        "pake_msg": util::b64(&claimed.pake_msg),
    })))
}

pub async fn approve(
    State(state): State<AppState>,
    Device(ctx): Device,
    Path(pairing_id): Path<String>,
    ApiJson(body): ApiJson<ApproveRequest>,
) -> Result<StatusCode, ApiError> {
    let pairing_id = parse_uuid("pairing_id", &pairing_id)?;
    let pake_msg = decode_field("pake_msg", &body.pake_msg, 1, MAX_PAKE_MSG_BYTES)?;
    let nonce = decode_field("wrapped_account_key.nonce", &body.wrapped_account_key.nonce, 12, 12)?;
    let ciphertext = decode_field(
        "wrapped_account_key.ciphertext",
        &body.wrapped_account_key.ciphertext,
        16,
        MAX_WRAPPED_KEY_BYTES,
    )?;
    state
        .store
        .approve_pairing(&pairing_id, &ctx.account_id, &pake_msg, &nonce, &ciphertext, util::now_ms())
        .await??;
    tracing::info!(account_id = %ctx.account_id, by = %ctx.device_id, "pairing approved");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn poll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(pairing_id): Path<String>,
    parts: Parts,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.limiter.check(Class::PairingPoll, &ip.to_string())?;
    let now = util::now_ms();
    // A missing pairing and a wrong poll token look the same to the caller.
    let unauthorized = || {
        let _ = state.limiter.check(Class::AuthFail, &ip.to_string());
        ApiError::unauthorized()
    };
    let token = bearer_token(&parts).ok_or_else(unauthorized)?;
    let pairing_id = util::canonical_uuid(&pairing_id).ok_or_else(unauthorized)?;
    let pairing = state.store.get_pairing(&pairing_id).await?;
    let stored_hash = pairing.as_ref().map(|p| p.poll_token_hash.clone()).unwrap_or_else(|| vec![0; 32]);
    let token_ok = util::ct_eq(&util::sha256(&token), &stored_hash);
    let pairing = pairing.filter(|_| token_ok).ok_or_else(unauthorized)?;
    if pairing.expires_at <= now {
        return Err(ApiError::pairing_expired());
    }
    if pairing.state != "approved" {
        return Ok(Json(serde_json::json!({ "state": pairing.state })));
    }
    // Approved: create the device and hand everything out exactly once. The token
    // is generated only now, so it never rests in the database in clear text.
    let device_id = util::new_uuid();
    let (device_token, device_token_hash) = new_token();
    let device = NewDevice { id: &device_id, name: &pairing.device_name, token_hash: &device_token_hash };
    let approval = state
        .store
        .deliver_pairing(&pairing_id, device, now)
        .await?
        .ok_or_else(unauthorized)?;
    tracing::info!(account_id = %approval.account_id, %device_id, "device added by pairing");
    Ok(Json(serde_json::json!({
        "state": "approved",
        "account_id": approval.account_id,
        "device_id": device_id,
        "token": device_token,
        "pake_msg": util::b64(&approval.pake_msg),
        "wrapped_account_key": {
            "nonce": util::b64(&approval.wrapped_nonce),
            "ciphertext": util::b64(&approval.wrapped_ciphertext),
        },
    })))
}
