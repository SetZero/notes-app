//! OpenID Connect ID token verification (for example against Keycloak).
//!
//! The server is a relying party that only verifies ID tokens. The client runs
//! the login flow itself (authorization code with PKCE, or the device flow),
//! using a nonce issued by this server, and sends the resulting ID token.
//!
//! Checks, all mandatory:
//! - signature against the provider's published keys (asymmetric algorithms only)
//! - `iss` equals the configured issuer exactly
//! - `aud` contains the configured client id; with several audiences `azp` must match
//! - `exp`, `nbf`, and `iat` not older than `MAX_TOKEN_AGE_SECS`
//! - `nonce` present (the caller checks it was issued here and consumes it)
//! - optional required claim, e.g. a group

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::config::OidcConfig;
use crate::BoxError;

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_AGE_SECS: i64 = 600;
const CLOCK_LEEWAY_SECS: u64 = 60;
const KEYS_TTL: Duration = Duration::from_secs(600);
const KEYS_MIN_REFETCH: Duration = Duration::from_secs(60);

/// Asymmetric signature algorithms only. "none" and HMAC are never accepted:
/// with HMAC the public client id or a public key could be abused as the secret.
pub fn parse_algorithm(name: &str) -> Option<Algorithm> {
    Some(match name {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "EdDSA" => Algorithm::EdDSA,
        _ => return None,
    })
}

#[derive(Debug)]
pub struct VerifiedIdentity {
    pub subject: String,
    pub nonce: String,
}

#[derive(Debug)]
pub enum OidcError {
    UnknownProvider,
    /// The token is not acceptable. The reason is for the server log only.
    Rejected(String),
    /// The provider could not be reached or returned unusable metadata.
    Provider(String),
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    aud: serde_json::Value,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(flatten)]
    other: HashMap<String, serde_json::Value>,
}

struct CachedKeys {
    keys: JwkSet,
    fetched: Instant,
}

struct Provider {
    config: OidcConfig,
    algorithms: Vec<Algorithm>,
    keys: Mutex<Option<CachedKeys>>,
}

pub struct OidcProviders {
    providers: HashMap<String, Provider>,
    http: reqwest::Client,
}

impl OidcProviders {
    pub fn new(configs: &[OidcConfig]) -> Result<Self, BoxError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let mut providers = HashMap::new();
        for config in configs {
            let algorithms = config
                .algorithms
                .iter()
                .map(|a| parse_algorithm(a).ok_or_else(|| format!("algorithm {a} is not allowed")))
                .collect::<Result<Vec<_>, _>>()?;
            providers.insert(
                config.id.clone(),
                Provider { config: config.clone(), algorithms, keys: Mutex::new(None) },
            );
        }
        Ok(Self { providers, http })
    }

    pub fn configs(&self) -> impl Iterator<Item = &OidcConfig> {
        self.providers.values().map(|p| &p.config)
    }

    pub fn contains(&self, provider_id: &str) -> bool {
        self.providers.contains_key(provider_id)
    }

    pub async fn verify(&self, provider_id: &str, id_token: &str) -> Result<VerifiedIdentity, OidcError> {
        let provider = self.providers.get(provider_id).ok_or(OidcError::UnknownProvider)?;
        if id_token.len() > MAX_TOKEN_BYTES {
            return Err(OidcError::Rejected("token too large".into()));
        }
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| OidcError::Rejected(format!("bad header: {e}")))?;
        if !provider.algorithms.contains(&header.alg) {
            return Err(OidcError::Rejected(format!("algorithm {:?} not allowed", header.alg)));
        }
        let key = self.find_key(provider, header.kid.as_deref()).await?;

        let mut validation = Validation::new(header.alg);
        validation.leeway = CLOCK_LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[&provider.config.issuer]);
        validation.set_audience(&[&provider.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = jsonwebtoken::decode::<Claims>(id_token, &key, &validation)
            .map_err(|e| OidcError::Rejected(format!("validation failed: {e}")))?
            .claims;

        if claims.sub.is_empty() || claims.sub.len() > 255 {
            return Err(OidcError::Rejected("missing or oversized sub".into()));
        }
        // With several audiences the token must name us as the authorised party.
        let audiences = claims.aud.as_array().map(|a| a.len()).unwrap_or(1);
        match &claims.azp {
            Some(azp) if azp != &provider.config.client_id => {
                return Err(OidcError::Rejected("azp does not match client id".into()));
            }
            None if audiences > 1 => {
                return Err(OidcError::Rejected("several audiences but no azp".into()));
            }
            _ => {}
        }
        let now = crate::util::now_ms() / 1000;
        match claims.iat {
            Some(iat)
                if now - iat <= MAX_TOKEN_AGE_SECS + CLOCK_LEEWAY_SECS as i64
                    && iat - now <= CLOCK_LEEWAY_SECS as i64 => {}
            _ => return Err(OidcError::Rejected("iat missing, too old or in the future".into())),
        }
        if let Some(required) = &provider.config.required_claim {
            let present = match claims.other.get(&required.name) {
                Some(serde_json::Value::String(s)) => s == &required.value,
                Some(serde_json::Value::Array(items)) => {
                    items.iter().any(|v| v.as_str() == Some(required.value.as_str()))
                }
                _ => false,
            };
            if !present {
                return Err(OidcError::Rejected(format!("required claim {} not satisfied", required.name)));
            }
        }
        let nonce = claims
            .nonce
            .filter(|n| !n.is_empty())
            .ok_or_else(|| OidcError::Rejected("nonce missing".into()))?;
        Ok(VerifiedIdentity { subject: claims.sub, nonce })
    }

    async fn find_key(&self, provider: &Provider, kid: Option<&str>) -> Result<DecodingKey, OidcError> {
        let mut cache = provider.keys.lock().await;
        let stale = cache.as_ref().is_none_or(|c| c.fetched.elapsed() > KEYS_TTL);
        if stale {
            *cache = Some(self.fetch_keys(provider).await?);
        }
        if let Some(key) = select_key(&cache.as_ref().expect("cache filled").keys, kid) {
            return key;
        }
        // Unknown key id: the provider may have rotated keys. Refetch, but not too often.
        if cache.as_ref().is_some_and(|c| c.fetched.elapsed() > KEYS_MIN_REFETCH) {
            *cache = Some(self.fetch_keys(provider).await?);
            if let Some(key) = select_key(&cache.as_ref().expect("cache filled").keys, kid) {
                return key;
            }
        }
        Err(OidcError::Rejected("no matching signing key".into()))
    }

    async fn fetch_keys(&self, provider: &Provider) -> Result<CachedKeys, OidcError> {
        let config = &provider.config;
        let url = format!("{}/.well-known/openid-configuration", config.issuer.trim_end_matches('/'));
        let discovery: Discovery = self.get_json(&url, config.allow_insecure_http).await?;
        if discovery.issuer != config.issuer {
            return Err(OidcError::Provider("discovery document names a different issuer".into()));
        }
        let keys: JwkSet = self.get_json(&discovery.jwks_uri, config.allow_insecure_http).await?;
        Ok(CachedKeys { keys, fetched: Instant::now() })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str, allow_http: bool) -> Result<T, OidcError> {
        if !(url.starts_with("https://") || (allow_http && url.starts_with("http://"))) {
            return Err(OidcError::Provider(format!("refusing non-https URL {url}")));
        }
        let fail = |e: reqwest::Error| OidcError::Provider(format!("{url}: {e}"));
        let mut response = self.http.get(url).send().await.map_err(fail)?;
        if !response.status().is_success() {
            return Err(OidcError::Provider(format!("{url}: status {}", response.status())));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(fail)? {
            if body.len() + chunk.len() > MAX_METADATA_BYTES {
                return Err(OidcError::Provider(format!("{url}: response too large")));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| OidcError::Provider(format!("{url}: {e}")))
    }
}

/// Picks the key named by `kid`. Without a `kid` the set must hold exactly one key.
fn select_key(keys: &JwkSet, kid: Option<&str>) -> Option<Result<DecodingKey, OidcError>> {
    let jwk = match kid {
        Some(kid) => keys.find(kid)?,
        None if keys.keys.len() == 1 => &keys.keys[0],
        None => return None,
    };
    Some(DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Rejected(format!("unusable key: {e}"))))
}
