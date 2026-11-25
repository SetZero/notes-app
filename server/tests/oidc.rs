//! OIDC enrollment against a mock identity provider on loopback.

mod common;

use axum::http::{Method, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use notes_syncd::config::{EnrollmentMode, OidcConfig, RequiredClaim};

const CLIENT_ID: &str = "notes-app";

struct MockIdp {
    issuer: String,
    key: EncodingKey,
    /// A key the provider does not publish.
    rogue_key: EncodingKey,
}

fn generate_key() -> (EncodingKey, String) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    (EncodingKey::from_ed_der(pkcs8.as_ref()), public)
}

impl MockIdp {
    async fn start() -> Self {
        let (key, public) = generate_key();
        let (rogue_key, _) = generate_key();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let discovery = json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/jwks") });
        let jwks = json!({ "keys": [{
            "kty": "OKP", "crv": "Ed25519", "x": public, "kid": "key-1", "use": "sig", "alg": "EdDSA",
        }]});
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(move || async move { Json(discovery) }))
            .route("/jwks", get(move || async move { Json(jwks) }));
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { issuer, key, rogue_key }
    }

    fn config(&self) -> OidcConfig {
        OidcConfig {
            id: "mock".into(),
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.into(),
            scopes: vec!["openid".into()],
            algorithms: vec!["EdDSA".into()],
            required_claim: None,
            allow_insecure_http: true,
        }
    }

    fn claims(&self, subject: &str, nonce: &str) -> Value {
        let now = now_ms() / 1000;
        json!({
            "iss": self.issuer, "aud": CLIENT_ID, "sub": subject,
            "iat": now, "exp": now + 300, "nonce": nonce,
        })
    }

    fn sign_with(&self, key: &EncodingKey, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("key-1".into());
        jsonwebtoken::encode(&header, claims, key).unwrap()
    }

    fn sign(&self, claims: &Value) -> String {
        self.sign_with(&self.key, claims)
    }
}

async fn oidc_app(idp: &MockIdp, mode: EnrollmentMode) -> TestApp {
    let provider = idp.config();
    app_with(move |c| {
        c.enrollment.mode = mode;
        c.oidc = vec![provider];
    })
    .await
}

async fn nonce(app: &TestApp) -> String {
    let (status, body) = app
        .call(Method::POST, "/v1/auth/oidc/nonce", None, Some(json!({ "provider": "mock" })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["nonce"].as_str().unwrap().to_owned()
}

async fn enroll(app: &TestApp, id_token: &str) -> (StatusCode, Value) {
    app.call(
        Method::POST,
        "/v1/accounts",
        None,
        Some(json!({
            "oidc": { "provider": "mock", "id_token": id_token },
            "device_name": "laptop",
            "recovery_verifier": b64(&[9u8; 32]),
        })),
    )
    .await
}

#[tokio::test]
async fn oidc_login_creates_an_account_once_per_identity() {
    let idp = MockIdp::start().await;
    let app = oidc_app(&idp, EnrollmentMode::Oidc).await;

    let (_, meta) = app.call(Method::GET, "/v1/meta", None, None).await;
    assert_eq!(meta["auth"]["enrollment"], "oidc");
    assert_eq!(meta["auth"]["oidc"][0]["client_id"], CLIENT_ID);

    let token = idp.sign(&idp.claims("alice", &nonce(&app).await));
    let (status, created) = enroll(&app, &token).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, _) = app.pull(created["token"].as_str().unwrap(), "since=0").await;
    assert_eq!(status, StatusCode::OK);

    // Replaying the same ID token fails: its nonce is used up.
    let (status, body) = enroll(&app, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A fresh login of the same identity is told which account it already has.
    let token = idp.sign(&idp.claims("alice", &nonce(&app).await));
    let (status, body) = enroll(&app, &token).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "account_exists");
    assert_eq!(body["account_id"], created["account_id"]);

    // Another identity gets its own account.
    let token = idp.sign(&idp.claims("bob", &nonce(&app).await));
    let (status, other) = enroll(&app, &token).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ne!(other["account_id"], created["account_id"]);

    // In oidc mode the invite code alone is not enough.
    let (status, _) = app
        .call(
            Method::POST,
            "/v1/accounts",
            None,
            Some(json!({ "invite_code": INVITE, "device_name": "x", "recovery_verifier": b64(&[9u8; 32]) })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn forged_or_unsuitable_id_tokens_are_rejected() {
    let idp = MockIdp::start().await;
    let app = oidc_app(&idp, EnrollmentMode::Oidc).await;
    let now = now_ms() / 1000;

    // (description, token) pairs; each uses a fresh, valid nonce unless stated.
    let mut cases: Vec<(&str, String)> = Vec::new();

    let mut c = idp.claims("mallory", &nonce(&app).await);
    cases.push(("signed with a key the provider does not publish", idp.sign_with(&idp.rogue_key, &c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c["aud"] = json!("some-other-client");
    cases.push(("issued for another client", idp.sign(&c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c["aud"] = json!([CLIENT_ID, "other"]);
    cases.push(("several audiences without azp", idp.sign(&c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c["azp"] = json!("other");
    cases.push(("authorised party is someone else", idp.sign(&c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c["iss"] = json!("https://evil.example");
    cases.push(("wrong issuer", idp.sign(&c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c["exp"] = json!(now - 600);
    c["iat"] = json!(now - 900);
    cases.push(("expired", idp.sign(&c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c["iat"] = json!(now - 3600);
    c["exp"] = json!(now + 3600);
    cases.push(("issued too long ago", idp.sign(&c)));

    c = idp.claims("mallory", "a-nonce-this-server-never-issued");
    cases.push(("nonce not issued by this server", idp.sign(&c)));

    c = idp.claims("mallory", &nonce(&app).await);
    c.as_object_mut().unwrap().remove("nonce");
    cases.push(("no nonce", idp.sign(&c)));

    // HMAC with the public client id as the secret: the classic algorithm confusion.
    c = idp.claims("mallory", &nonce(&app).await);
    let hs = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &c,
        &EncodingKey::from_secret(CLIENT_ID.as_bytes()),
    )
    .unwrap();
    cases.push(("HS256 instead of an asymmetric signature", hs));

    // Unsigned token with alg "none".
    c = idp.claims("mallory", &nonce(&app).await);
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(c.to_string())
    );
    cases.push(("alg none", unsigned));

    cases.push(("not a token at all", "garbage".into()));
    cases.push(("oversized token", "a".repeat(20_000)));

    for (what, token) in cases {
        let (status, body) = enroll(&app, &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
        assert_eq!(body["code"], "forbidden", "{what}");
        assert!(body.get("detail").is_none(), "{what}: the reason must not leak to the client");
    }

    let (status, body) = app
        .call(
            Method::POST,
            "/v1/accounts",
            None,
            Some(json!({
                "oidc": { "provider": "unknown", "id_token": "x" },
                "device_name": "laptop",
                "recovery_verifier": b64(&[9u8; 32]),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn required_claim_gates_enrollment() {
    let idp = MockIdp::start().await;
    let mut provider = idp.config();
    provider.required_claim = Some(RequiredClaim { name: "groups".into(), value: "notes-users".into() });
    let app = app_with(move |c| {
        c.enrollment.mode = EnrollmentMode::Oidc;
        c.oidc = vec![provider];
    })
    .await;

    let mut claims = idp.claims("carol", &nonce(&app).await);
    let (status, _) = enroll(&app, &idp.sign(&claims)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "claim missing");

    claims = idp.claims("carol", &nonce(&app).await);
    claims["groups"] = json!(["staff"]);
    let (status, _) = enroll(&app, &idp.sign(&claims)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "not in the group");

    claims = idp.claims("carol", &nonce(&app).await);
    claims["groups"] = json!(["staff", "notes-users"]);
    let (status, body) = enroll(&app, &idp.sign(&claims)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn recovery_of_an_oidc_account_needs_phrase_and_login() {
    let idp = MockIdp::start().await;
    let app = oidc_app(&idp, EnrollmentMode::Either).await;

    let token = idp.sign(&idp.claims("dave", &nonce(&app).await));
    let (status, created) = enroll(&app, &token).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let path = format!("/v1/accounts/{}/recover", created["account_id"].as_str().unwrap());
    let recover = |oidc: Option<String>, verifier: [u8; 32]| {
        let mut body = json!({ "device_name": "phone", "recovery_verifier": b64(&verifier) });
        if let Some(id_token) = oidc {
            body["oidc"] = json!({ "provider": "mock", "id_token": id_token });
        }
        body
    };

    // Recovery phrase alone is not enough for an account bound to an identity.
    let (status, _) = app.call(Method::POST, &path, None, Some(recover(None, [9u8; 32]))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A login as someone else does not help either.
    let other = idp.sign(&idp.claims("eve", &nonce(&app).await));
    let (status, _) = app.call(Method::POST, &path, None, Some(recover(Some(other), [9u8; 32]))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The right login with the wrong phrase fails.
    let login = idp.sign(&idp.claims("dave", &nonce(&app).await));
    let (status, _) = app.call(Method::POST, &path, None, Some(recover(Some(login), [1u8; 32]))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Both together work.
    let login = idp.sign(&idp.claims("dave", &nonce(&app).await));
    let (status, body) = app.call(Method::POST, &path, None, Some(recover(Some(login), [9u8; 32]))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // In "either" mode the invite code still works for accounts without an identity.
    let account = app.create_account("invited").await;
    let (status, _) = app.pull(&account.token, "since=0").await;
    assert_eq!(status, StatusCode::OK);
}
