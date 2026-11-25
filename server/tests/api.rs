mod common;

use axum::body::Body;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

const B1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const B2: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2";
const B3: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3";

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn health_meta_and_security_headers() {
    let app = app().await;
    let (status, headers, body) = app.send(None, Method::GET, "/healthz", None, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers.contains_key("x-request-id"));

    let (status, meta) = app.call(Method::GET, "/v1/meta", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(meta["api_versions"][0], "v1");
    assert_eq!(meta["limits"]["max_batch_blocks"], 100);
    assert_eq!(meta["auth"]["enrollment"], "invite");
}

#[tokio::test]
async fn account_creation_requires_the_invite_code() {
    let app = app().await;
    let request = |invite: &str| {
        json!({ "invite_code": invite, "device_name": "laptop", "recovery_verifier": b64(&[1u8; 32]) })
    };
    let (status, body) = app.call(Method::POST, "/v1/accounts", None, Some(request("wrong-invite-code-000000"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "invalid_invite");
    assert!(body["request_id"].as_str().unwrap().len() > 10);

    // No invite code at all.
    let (status, _) = app
        .call(
            Method::POST,
            "/v1/accounts",
            None,
            Some(json!({ "device_name": "laptop", "recovery_verifier": b64(&[1u8; 32]) })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = app.call(Method::POST, "/v1/accounts", None, Some(request(INVITE))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["token"].as_str().unwrap().len(), 44);
}

#[tokio::test]
async fn input_validation_rejects_bad_fields() {
    let app = app().await;
    for (name, verifier) in [("", b64(&[1u8; 32])), ("ok", b64(&[1u8; 31])), ("bad\u{7}name", b64(&[1u8; 32]))] {
        let (status, body) = app
            .call(
                Method::POST,
                "/v1/accounts",
                None,
                Some(json!({ "invite_code": INVITE, "device_name": name, "recovery_verifier": verifier })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "validation_failed");
    }
    // Malformed JSON gets a problem document, not a plain-text error.
    let (status, headers, _) = app
        .send(None, Method::POST, "/v1/accounts", None, &[("content-type", "application/json")], Body::from("{"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(headers["content-type"], "application/problem+json");
}

#[tokio::test]
async fn protected_endpoints_need_a_valid_token() {
    let app = app().await;
    let account = app.create_account("laptop").await;
    for token in [None, Some("not-base64!"), Some(b64(&[0u8; 32]).as_str()), Some(b64(&[0u8; 16]).as_str())] {
        for path in ["/v1/changes?since=0", "/v1/devices", "/v1/events"] {
            let (status, body) = app.call(Method::GET, path, token, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} {token:?}");
            assert_eq!(body["code"], "unauthorized");
        }
    }
    let (status, _) = app.pull(&account.token, "since=0").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn push_and_pull_follow_last_writer_wins() {
    let app = app().await;
    let account = app.create_account("laptop").await;
    let t = now_ms();

    let (status, body) = app
        .push(&account.token, vec![block(B1, &version(t, 0), &[1u8; 32]), block(B2, &version(t, 0), &[2u8; 32])])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["results"][0]["status"], "accepted");
    assert_eq!(body["results"][0]["seq"], 1);
    assert_eq!(body["results"][1]["seq"], 2);
    assert_eq!(body["cursor"], 2);

    // Same version again: duplicate. Older version: stale. Newer version: accepted with a new seq.
    let (_, body) = app
        .push(
            &account.token,
            vec![
                block(B1, &version(t, 0), &[1u8; 32]),
                block(B2, &version(t - 1000, 0), &[3u8; 32]),
                block(B1, &version(t, 1), &[4u8; 32]),
            ],
        )
        .await;
    assert_eq!(body["results"][0]["status"], "duplicate");
    assert_eq!(body["results"][0]["seq"], 1);
    assert_eq!(body["results"][1]["status"], "stale");
    assert_eq!(body["results"][2]["status"], "accepted");
    assert_eq!(body["results"][2]["seq"], 3);

    // Only the newest version of each block is kept, ordered by seq.
    let (status, page) = app.pull(&account.token, "since=0").await;
    assert_eq!(status, StatusCode::OK);
    let changes = page["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["block_id"], B2);
    assert_eq!(changes[0]["ciphertext"], b64(&[2u8; 32]));
    assert_eq!(changes[1]["block_id"], B1);
    assert_eq!(changes[1]["ciphertext"], b64(&[4u8; 32]));
    assert_eq!(changes[1]["origin_device_id"], account.device_id);
    assert_eq!(page["next_cursor"], 3);
    assert_eq!(page["has_more"], false);

    // Paging.
    let (_, page) = app.pull(&account.token, "since=0&limit=1").await;
    assert_eq!(page["changes"].as_array().unwrap().len(), 1);
    assert_eq!(page["has_more"], true);
    assert_eq!(page["next_cursor"], 2);
    let (_, page) = app.pull(&account.token, "since=2&limit=1").await;
    assert_eq!(page["changes"][0]["block_id"], B1);
    assert_eq!(page["has_more"], false);
    let (_, page) = app.pull(&account.token, "since=3").await;
    assert_eq!(page["changes"].as_array().unwrap().len(), 0);
    assert_eq!(page["next_cursor"], 3);

    // The byte cap also pages, but always returns at least one block.
    let (_, page) = app.pull(&account.token, "since=0&max_bytes=1").await;
    assert_eq!(page["changes"].as_array().unwrap().len(), 1);
    assert_eq!(page["has_more"], true);
}

#[tokio::test]
async fn push_rejects_bad_blocks_individually() {
    let app = app_with(|c| c.limits.max_block_ciphertext_bytes = 64).await;
    let account = app.create_account("laptop").await;
    let t = now_ms();
    let far_future = version(t + 3_600_000, 0);
    let (status, body) = app
        .push(
            &account.token,
            vec![
                block(B1, &far_future, &[1u8; 32]),
                block(B2, "not-a-version", &[1u8; 32]),
                block(B3, &version(t, 0), &[1u8; 65]),
                block(B3, &version(t, 0), &[1u8; 64]),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["results"][0]["reason"], "clock_skew");
    assert_eq!(body["results"][1]["reason"], "invalid_version");
    assert_eq!(body["results"][2]["reason"], "ciphertext_too_large");
    assert_eq!(body["results"][3]["status"], "accepted");

    // Structurally invalid input fails the whole request.
    let (status, _) = app.push(&account.token, vec![block("not-a-uuid", &version(t, 0), &[1u8; 32])]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = app.push(&account.token, vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A ciphertext shorter than an authentication tag cannot be valid.
    let (status, _) = app.push(&account.token, vec![block(B1, &version(t, 0), &[1u8; 8])]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let too_many = (0..101).map(|_| block(B1, &version(t, 0), &[1u8; 32])).collect();
    let (status, _) = app.push(&account.token, too_many).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn accounts_are_isolated_from_each_other() {
    let app = app().await;
    let alice = app.create_account("alice").await;
    let bob = app.create_account("bob").await;
    let t = now_ms();
    app.push(&alice.token, vec![block(B1, &version(t, 0), &[1u8; 32])]).await;

    let (_, page) = app.pull(&bob.token, "since=0").await;
    assert_eq!(page["changes"].as_array().unwrap().len(), 0);

    // Bob can use the same block id without touching Alice's block.
    let (_, body) = app.push(&bob.token, vec![block(B1, &version(t - 5000, 0), &[2u8; 32])]).await;
    assert_eq!(body["results"][0]["status"], "accepted");
    assert_eq!(body["results"][0]["seq"], 1);
    let (_, page) = app.pull(&alice.token, "since=0").await;
    assert_eq!(page["changes"][0]["ciphertext"], b64(&[1u8; 32]));

    // Bob cannot see or revoke Alice's device.
    let (_, devices) = app.call(Method::GET, "/v1/devices", Some(&bob.token), None).await;
    assert_eq!(devices["devices"].as_array().unwrap().len(), 1);
    let path = format!("/v1/devices/{}", alice.device_id);
    let (status, _) = app.call(Method::DELETE, &path, Some(&bob.token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app.pull(&alice.token, "since=0").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pairing_adds_a_device_exactly_once() {
    let app = app().await;
    let owner = app.create_account("laptop").await;
    let other = app.create_account("stranger").await;

    let (status, created) = app
        .call(
            Method::POST,
            "/v1/pairings",
            None,
            Some(json!({ "device_name": "esp32", "pake_msg": b64(&[5u8; 33]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let pairing_id = created["pairing_id"].as_str().unwrap();
    let channel = created["channel"].as_str().unwrap();
    let poll_token = created["poll_token"].as_str().unwrap();
    assert_eq!(channel.len(), 6);
    let poll_path = format!("/v1/pairings/{pairing_id}");
    let approve_path = format!("/v1/pairings/{pairing_id}/approve");
    let approval = json!({
        "pake_msg": b64(&[6u8; 33]),
        "wrapped_account_key": { "nonce": b64(&[1u8; 12]), "ciphertext": b64(&[2u8; 64]) },
    });

    // Polling needs the poll token; a device token or a wrong token is not enough.
    let (status, _) = app.call(Method::GET, &poll_path, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = app.call(Method::GET, &poll_path, Some(&owner.token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = app.call(Method::GET, &poll_path, Some(poll_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "state": "pending" }));

    // Approving before claiming is a conflict-free "not found" for everyone.
    let (status, _) = app.call(Method::POST, &approve_path, Some(&owner.token), Some(approval.clone())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Claiming needs a device token and works once.
    let claim = json!({ "channel": channel });
    let (status, _) = app.call(Method::POST, "/v1/pairings/claim", None, Some(claim.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, claimed) = app.call(Method::POST, "/v1/pairings/claim", Some(&owner.token), Some(claim.clone())).await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    assert_eq!(claimed["device_name"], "esp32");
    assert_eq!(claimed["pake_msg"], b64(&[5u8; 33]));
    let (status, body) = app.call(Method::POST, "/v1/pairings/claim", Some(&other.token), Some(claim)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "pairing_state_conflict");

    // Only the claiming account can approve.
    let (status, _) = app.call(Method::POST, &approve_path, Some(&other.token), Some(approval.clone())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app.call(Method::POST, &approve_path, Some(&owner.token), Some(approval.clone())).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = app.call(Method::POST, &approve_path, Some(&owner.token), Some(approval)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The new device gets its token and the wrapped key once.
    let (status, delivered) = app.call(Method::GET, &poll_path, Some(poll_token), None).await;
    assert_eq!(status, StatusCode::OK, "{delivered}");
    assert_eq!(delivered["state"], "approved");
    assert_eq!(delivered["account_id"], owner.account_id);
    assert_eq!(delivered["pake_msg"], b64(&[6u8; 33]));
    assert_eq!(delivered["wrapped_account_key"]["ciphertext"], b64(&[2u8; 64]));
    let new_token = delivered["token"].as_str().unwrap();
    let (status, _) = app.call(Method::GET, &poll_path, Some(poll_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The new token belongs to the owner's account.
    let (_, devices) = app.call(Method::GET, "/v1/devices", Some(new_token), None).await;
    let devices = devices["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices.iter().filter(|d| d["current"] == true).count(), 1);
}

#[tokio::test]
async fn revoked_devices_lose_access_immediately() {
    let app = app().await;
    let account = app.create_account("laptop").await;
    // Add a second device through recovery.
    let recover_path = format!("/v1/accounts/{}/recover", account.account_id);
    let (status, _) = app
        .call(
            Method::POST,
            &recover_path,
            None,
            Some(json!({ "device_name": "phone", "recovery_verifier": b64(&[8u8; 32]) })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong verifier must fail");
    let unknown = "/v1/accounts/00000000-0000-4000-8000-000000000000/recover";
    let (status, _) = app
        .call(
            Method::POST,
            unknown,
            None,
            Some(json!({ "device_name": "phone", "recovery_verifier": b64(&[9u8; 32]) })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unknown account looks like a wrong verifier");
    let (status, phone) = app
        .call(
            Method::POST,
            &recover_path,
            None,
            Some(json!({ "device_name": "phone", "recovery_verifier": b64(&[9u8; 32]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{phone}");
    let phone_token = phone["token"].as_str().unwrap();
    let phone_id = phone["device_id"].as_str().unwrap();

    let path = format!("/v1/devices/{phone_id}");
    let (status, _) = app.call(Method::DELETE, &path, Some(&account.token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = app.call(Method::DELETE, &path, Some(&account.token), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoking twice is harmless");

    let (status, _) = app.pull(phone_token, "since=0").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, devices) = app.call(Method::GET, "/v1/devices", Some(&account.token), None).await;
    assert_eq!(devices["devices"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn blobs_are_verified_limited_and_private() {
    let app = app_with(|c| c.limits.max_blob_bytes = 1024).await;
    let alice = app.create_account("alice").await;
    let bob = app.create_account("bob").await;
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let hash = hex(&Sha256::digest(&data));
    let path = format!("/v1/blobs/{hash}");
    let octets = [("content-type", "application/octet-stream")];

    let (status, _, _) = app.send(None, Method::HEAD, &path, Some(&alice.token), &[], Body::empty()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Wrong content for the hash.
    let (status, _, body) = app
        .send(None, Method::PUT, &path, Some(&alice.token), &octets, Body::from(vec![1u8; 10]))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{}", String::from_utf8_lossy(&body));

    // Too large.
    let big = vec![0u8; 2000];
    let big_path = format!("/v1/blobs/{}", hex(&Sha256::digest(&big)));
    let (status, _, _) = app.send(None, Method::PUT, &big_path, Some(&alice.token), &octets, Body::from(big)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Path tricks never reach the file system.
    for bad in ["/v1/blobs/..%2F..%2Fnotes.db", "/v1/blobs/ABCDEF", &format!("/v1/blobs/{}", "g".repeat(64))] {
        let (status, _, _) = app.send(None, Method::GET, bad, Some(&alice.token), &[], Body::empty()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }

    let (status, _, _) = app
        .send(None, Method::PUT, &path, Some(&alice.token), &octets, Body::from(data.clone()))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = app
        .send(None, Method::PUT, &path, Some(&alice.token), &octets, Body::from(data.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "second upload is a no-op");

    let (status, headers, _) = app.send(None, Method::HEAD, &path, Some(&alice.token), &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-length"], "1000");

    let (status, _, body) = app.send(None, Method::GET, &path, Some(&alice.token), &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, data);

    let (status, headers, body) = app
        .send(None, Method::GET, &path, Some(&alice.token), &[("range", "bytes=900-")], Body::empty())
        .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers["content-range"], "bytes 900-999/1000");
    assert_eq!(body, &data[900..]);

    // Another account cannot read it, even knowing the hash.
    let (status, _, _) = app.send(None, Method::GET, &path, Some(&bob.token), &[], Body::empty()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = app.send(None, Method::GET, &path, None, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn blob_quota_is_enforced_per_account() {
    let app = app_with(|c| {
        c.limits.max_blob_bytes = 1024;
        c.limits.max_account_blob_bytes = 1500;
    })
    .await;
    let account = app.create_account("laptop").await;
    let octets = [("content-type", "application/octet-stream")];
    let first = vec![1u8; 1000];
    let second = vec![2u8; 1000];
    let p1 = format!("/v1/blobs/{}", hex(&Sha256::digest(&first)));
    let p2 = format!("/v1/blobs/{}", hex(&Sha256::digest(&second)));
    let (status, _, _) = app.send(None, Method::PUT, &p1, Some(&account.token), &octets, Body::from(first)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = app.send(None, Method::PUT, &p2, Some(&account.token), &octets, Body::from(second)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn oversized_json_bodies_are_refused() {
    let app = app_with(|c| c.limits.max_request_bytes = 2048).await;
    let account = app.create_account("laptop").await;
    let (status, body) = app
        .push(&account.token, vec![block(B1, &version(now_ms(), 0), &[1u8; 4096])])
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
}

#[tokio::test]
async fn enrollment_and_bad_tokens_are_rate_limited_per_ip() {
    let app = app().await;
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    let request = json!({ "invite_code": "wrong-invite-code-000000", "device_name": "x", "recovery_verifier": b64(&[1u8; 32]) });
    let mut limited = None;
    for attempt in 0..12 {
        let (status, _, _) = app
            .send(
                Some(ip),
                Method::POST,
                "/v1/accounts",
                None,
                &[("content-type", "application/json")],
                Body::from(request.to_string()),
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(attempt);
            break;
        }
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    assert_eq!(limited, Some(10), "the 11th guess from one address is refused");

    // Guessing device tokens is throttled too.
    let ip: IpAddr = "203.0.113.8".parse().unwrap();
    let guess = b64(&[3u8; 32]);
    let mut statuses = Vec::new();
    for _ in 0..22 {
        let (status, headers, _) = app
            .send(Some(ip), Method::GET, "/v1/devices", Some(&guess), &[], Body::empty())
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert!(headers.contains_key("retry-after"));
        }
        statuses.push(status);
    }
    assert_eq!(statuses[19], StatusCode::UNAUTHORIZED);
    assert_eq!(statuses[20], StatusCode::TOO_MANY_REQUESTS);

    // Another address is not affected.
    let (status, _) = app.call(Method::GET, "/v1/devices", Some(&guess), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forwarded_for_is_only_trusted_from_configured_proxies() {
    let proxy: IpAddr = "10.9.9.9".parse().unwrap();
    let app = app_with(|c| c.server.trusted_proxies = vec![proxy.into()]).await;
    let request = json!({ "invite_code": "wrong-invite-code-000000", "device_name": "x", "recovery_verifier": b64(&[1u8; 32]) });
    let send = |from: IpAddr, forwarded: &'static str| {
        let app = &app;
        let body = request.to_string();
        async move {
            app.send(
                Some(from),
                Method::POST,
                "/v1/accounts",
                None,
                &[("content-type", "application/json"), ("x-forwarded-for", forwarded)],
                Body::from(body),
            )
            .await
            .0
        }
    };
    // Through the proxy, each client address has its own budget.
    for _ in 0..10 {
        assert_eq!(send(proxy, "198.51.100.1").await, StatusCode::FORBIDDEN);
    }
    assert_eq!(send(proxy, "198.51.100.1").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(send(proxy, "198.51.100.2").await, StatusCode::FORBIDDEN);

    // A direct client cannot dodge its limit by inventing the header.
    let direct: IpAddr = "192.0.2.50".parse().unwrap();
    for _ in 0..10 {
        assert_eq!(send(direct, "198.51.100.99").await, StatusCode::FORBIDDEN);
    }
    assert_eq!(send(direct, "198.51.100.77").await, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unknown_routes_return_a_problem_document() {
    let app = app().await;
    let (status, body) = app.call(Method::GET, "/v1/nope", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[tokio::test]
async fn insecure_configurations_are_refused_at_startup() {
    use notes_syncd::config::{Config, EnrollmentMode};
    let mut config = Config::default();
    assert!(config.validate().is_err(), "invite mode without a code");
    config.enrollment.invite_code = Some("short".into());
    assert!(config.validate().is_err(), "short invite code");
    config.enrollment.invite_code = Some(INVITE.into());
    assert!(config.validate().is_ok());

    config.server.listen = "0.0.0.0:8443".parse().unwrap();
    assert!(config.validate().is_err(), "plain HTTP on a public address");
    config.server.allow_plain_http = true;
    assert!(config.validate().is_ok());

    config.enrollment.mode = EnrollmentMode::Oidc;
    assert!(config.validate().is_err(), "oidc mode without a provider");
    let provider: notes_syncd::config::OidcConfig = serde_json::from_value(json!({
        "id": "kc", "issuer": "http://idp.example/realms/x", "client_id": "notes",
    }))
    .unwrap();
    config.oidc = vec![provider.clone()];
    assert!(config.validate().is_err(), "http issuer");
    config.oidc[0].issuer = "https://idp.example/realms/x".into();
    assert!(config.validate().is_ok());
    for alg in ["HS256", "none"] {
        config.oidc[0].algorithms = vec![alg.into()];
        assert!(config.validate().is_err(), "{alg} must not be accepted");
    }
}

#[tokio::test]
async fn cleanup_removes_expired_rows_and_old_deletion_markers() {
    let app = app().await;
    let a = app.create_account("laptop").await;
    let now = now_ms();

    // A block, then its deletion marker, then a block that stays.
    let (_, r) = app.push(&a.token, vec![block(B1, &version(now - 2000, 0), &[1u8; 32])]).await;
    assert_eq!(r["results"][0]["status"], "accepted", "{r}");
    let mut marker = block(B1, &version(now - 1000, 0), &[0u8; 16]);
    marker["deleted"] = json!(true);
    let (_, r) = app.push(&a.token, vec![marker, block(B2, &version(now - 1000, 1), &[2u8; 32])]).await;
    assert_eq!(r["results"][0]["status"], "accepted", "{r}");
    let cursor = r["cursor"].as_i64().unwrap();

    // Nothing is removed while the device has not pulled past the marker.
    let far = now + 3_600_000;
    assert_eq!(app.state.store.gc_tombstones(far, 0).await.unwrap(), 0);
    let (status, pulled) = app.pull(&a.token, "since=0").await;
    assert_eq!(status, StatusCode::OK, "{pulled}");
    assert_eq!(pulled["changes"].as_array().unwrap().len(), 2);
    // The cursor a device reports is the one it pulled from.
    let (status, _) = app.pull(&a.token, &format!("since={cursor}")).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(app.state.store.gc_tombstones(far, 0).await.unwrap(), 1);
    // A device that would have needed the removed marker has to resync,
    // and a full sync from 0 simply no longer contains it.
    let (status, problem) = app.pull(&a.token, "since=1").await;
    assert_eq!(status, StatusCode::GONE, "{problem}");
    assert_eq!(problem["code"], "cursor_expired");
    let (status, pulled) = app.pull(&a.token, "since=0").await;
    assert_eq!(status, StatusCode::OK, "{pulled}");
    assert_eq!(pulled["changes"].as_array().unwrap().len(), 1);
    let (status, pulled) = app.pull(&a.token, &format!("since={cursor}")).await;
    assert_eq!(status, StatusCode::OK, "{pulled}");

    // Expired pairings disappear.
    let (status, created) = app
        .call(
            Method::POST,
            "/v1/pairings",
            None,
            Some(json!({ "device_name": "esp32", "pake_msg": b64(&[5u8; 33]) })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let path = format!("/v1/pairings/{}", created["pairing_id"].as_str().unwrap());
    let poll_token = created["poll_token"].as_str().unwrap();
    app.state.store.gc_expired(now).await.unwrap();
    let (status, _) = app.call(Method::GET, &path, Some(poll_token), None).await;
    assert_eq!(status, StatusCode::OK);
    app.state.store.gc_expired(far).await.unwrap();
    let (status, _) = app.call(Method::GET, &path, Some(poll_token), None).await;
    assert_ne!(status, StatusCode::OK);
}
