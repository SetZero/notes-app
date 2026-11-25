//! Account creation, recovery, OIDC nonces and device management.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use super::{decode_field, new_token, parse_uuid, validate_device_name, ApiJson, ClientIp, Device};
use crate::error::ApiError;
use crate::oidc::OidcError;
use crate::ratelimit::Class;
use crate::store::{CreateAccount, NewDevice};
use crate::{util, AppState};

const OIDC_NONCE_TTL_MS: i64 = 10 * 60 * 1000;

#[derive(Deserialize)]
pub struct OidcAssertion {
    provider: String,
    id_token: String,
}

#[derive(Deserialize)]
pub struct NonceRequest {
    provider: String,
}

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    #[serde(default)]
    invite_code: Option<String>,
    #[serde(default)]
    oidc: Option<OidcAssertion>,
    device_name: String,
    recovery_verifier: String,
}

#[derive(Deserialize)]
pub struct RecoverRequest {
    #[serde(default)]
    oidc: Option<OidcAssertion>,
    device_name: String,
    recovery_verifier: String,
}

fn credentials(account_id: &str, device_id: &str, token: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "account_id": account_id, "device_id": device_id, "token": token }))
}

/// Verifies an ID token and consumes its nonce. Returns the subject.
/// Every failure looks the same to the client; the reason goes to the log.
async fn verify_oidc(state: &AppState, assertion: &OidcAssertion) -> Result<String, ApiError> {
    let identity = match state.oidc.verify(&assertion.provider, &assertion.id_token).await {
        Ok(identity) => identity,
        Err(OidcError::UnknownProvider) => return Err(ApiError::validation("unknown oidc provider")),
        Err(OidcError::Rejected(reason)) => {
            tracing::info!(provider = %assertion.provider, %reason, "id token rejected");
            return Err(ApiError::forbidden());
        }
        Err(OidcError::Provider(reason)) => {
            tracing::warn!(provider = %assertion.provider, %reason, "oidc provider unavailable");
            return Err(ApiError::internal("oidc provider unavailable"));
        }
    };
    // The nonce must have been issued by this server and is single use, so a
    // captured ID token cannot be replayed.
    let nonce_hash = util::sha256(identity.nonce.as_bytes());
    if !state
        .store
        .consume_oidc_nonce(&nonce_hash, &assertion.provider, util::now_ms())
        .await?
    {
        tracing::info!(provider = %assertion.provider, "id token nonce unknown, expired or already used");
        return Err(ApiError::forbidden());
    }
    Ok(identity.subject)
}

pub async fn oidc_nonce(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(body): ApiJson<NonceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.limiter.check(Class::Enroll, &ip.to_string())?;
    if !state.oidc.contains(&body.provider) {
        return Err(ApiError::validation("unknown oidc provider"));
    }
    let nonce = util::b64(&util::random_bytes::<32>());
    let now = util::now_ms();
    state
        .store
        .insert_oidc_nonce(&util::sha256(nonce.as_bytes()), &body.provider, now + OIDC_NONCE_TTL_MS)
        .await?;
    Ok(Json(serde_json::json!({ "nonce": nonce, "expires_in": OIDC_NONCE_TTL_MS / 1000 })))
}

pub async fn create_account(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(body): ApiJson<CreateAccountRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    state.limiter.check(Class::Enroll, &ip.to_string())?;
    validate_device_name(&body.device_name)?;
    let verifier = decode_field("recovery_verifier", &body.recovery_verifier, 32, 32)?;
    let mode = state.config.enrollment.mode;

    let subject = match (&body.oidc, &body.invite_code) {
        (Some(assertion), _) if mode.allows_oidc() => Some(verify_oidc(&state, assertion).await?),
        (None, Some(code)) if mode.allows_invite() => {
            // Compare hashes in constant time: neither content nor length leaks.
            let given = util::sha256(code.as_bytes());
            match &state.invite_hash {
                Some(expected) if util::ct_eq(&given, expected) => None,
                _ => return Err(ApiError::invalid_invite()),
            }
        }
        _ if mode.allows_invite() && !mode.allows_oidc() => return Err(ApiError::invalid_invite()),
        _ => return Err(ApiError::forbidden()),
    };

    let account_id = util::new_uuid();
    let device_id = util::new_uuid();
    let (token, token_hash) = new_token();
    let identity = match (&body.oidc, &subject) {
        (Some(assertion), Some(subject)) => Some((assertion.provider.as_str(), subject.as_str())),
        _ => None,
    };
    let device = NewDevice { id: &device_id, name: &body.device_name, token_hash: &token_hash };
    match state
        .store
        .create_account(&account_id, &util::sha256(&verifier), identity, device, util::now_ms())
        .await?
    {
        CreateAccount::Created => {
            tracing::info!(%account_id, oidc = identity.is_some(), "account created");
            Ok((StatusCode::CREATED, credentials(&account_id, &device_id, token)))
        }
        // The caller proved who they are, so telling them their account id is fine.
        CreateAccount::IdentityTaken(existing) => Err(ApiError::account_exists(existing)),
    }
}

pub async fn recover_account(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(account_id): Path<String>,
    ApiJson(body): ApiJson<RecoverRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    state.limiter.check(Class::Enroll, &ip.to_string())?;
    validate_device_name(&body.device_name)?;
    let verifier_hash = util::sha256(&decode_field("recovery_verifier", &body.recovery_verifier, 32, 32)?);
    // Unknown account and wrong verifier are indistinguishable for the caller.
    let Some(account_id) = util::canonical_uuid(&account_id) else {
        return Err(ApiError::forbidden());
    };
    let auth = state.store.account_auth(&account_id).await?;
    let stored_hash = auth.as_ref().map(|a| a.recovery_verifier_hash.clone()).unwrap_or_else(|| vec![0; 32]);
    let verifier_ok = util::ct_eq(&verifier_hash, &stored_hash);
    let Some(auth) = auth.filter(|_| verifier_ok) else {
        return Err(ApiError::forbidden());
    };
    // An account bound to an OIDC identity needs both: the recovery phrase and a login.
    if let Some((provider, subject)) = &auth.identity {
        let Some(assertion) = body.oidc.as_ref().filter(|a| &a.provider == provider) else {
            return Err(ApiError::forbidden());
        };
        if &verify_oidc(&state, assertion).await? != subject {
            return Err(ApiError::forbidden());
        }
    }
    let device_id = util::new_uuid();
    let (token, token_hash) = new_token();
    let device = NewDevice { id: &device_id, name: &body.device_name, token_hash: &token_hash };
    state.store.insert_device(&account_id, device, util::now_ms()).await?;
    tracing::info!(%account_id, %device_id, "device added by recovery");
    Ok((StatusCode::CREATED, credentials(&account_id, &device_id, token)))
}

pub async fn list_devices(
    State(state): State<AppState>,
    Device(ctx): Device,
) -> Result<Json<serde_json::Value>, ApiError> {
    let devices: Vec<_> = state
        .store
        .list_devices(&ctx.account_id)
        .await?
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "device_id": d.id,
                "name": d.name,
                "created_at": util::rfc3339(d.created_at),
                "last_seen_at": util::rfc3339(d.last_seen_at),
                "current": d.id == ctx.device_id,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "devices": devices })))
}

pub async fn revoke_device(
    State(state): State<AppState>,
    Device(ctx): Device,
    Path(device_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let device_id = parse_uuid("device_id", &device_id)?;
    // Scoped by the caller's account: a device of another account is "not found".
    if !state.store.revoke_device(&ctx.account_id, &device_id, util::now_ms()).await? {
        return Err(ApiError::not_found());
    }
    tracing::info!(account_id = %ctx.account_id, %device_id, by = %ctx.device_id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}
