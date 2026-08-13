// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Integration tests for the CIBA elicitation handler against a mock OP
// (mockito). Exercises the real request shapes and the lifecycle mapping
// for dispatch → check → validate without a live Keycloak.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
use std::collections::HashSet;

use base64::Engine as _;
use serde_json::json;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::elicitation::{
    ElicitationOp, ElicitationOutcomeKind, ElicitationPayload, ElicitationStatusKind,
};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::HookHandler as _;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_elicitation_ciba::CibaApprover;

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

fn approver(server_url: &str) -> CibaApprover {
    let cfg = PluginConfig {
        name: "manager-approver".to_owned(),
        kind: "elicitation/ciba".to_owned(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["elicit".to_owned()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(json!({
            "backchannel_endpoint": format!("{server_url}/ciba/auth"),
            "token_endpoint": format!("{server_url}/token"),
            "client_id": "praxis-policy-gateway",
            "client_secret_source": { "kind": "literal", "secret": "shh" },
            // mockito serves http:// — allow it for the test only.
            "insecure_http": true,
        })),
    };
    CibaApprover::new(cfg).expect("construct approver")
}

async fn run(approver: &CibaApprover, payload: ElicitationPayload) -> ElicitationPayload {
    let ext = Extensions::default();
    let mut ctx = PluginContext::new();
    let result = approver.handle(&payload, &ext, &mut ctx).await;
    assert!(
        result.continue_processing,
        "handler denied: {:?}",
        result.violation
    );
    result
        .modified_payload
        .expect("handler returned an ElicitationPayload")
}

/// Build a fake `id_token` whose payload carries `preferred_username`.
fn fake_id_token(username: &str) -> String {
    let payload = json!({ "preferred_username": username, "sub": "u-1" });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    format!("aaa.{b64}.sig")
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatch_posts_backchannel_and_returns_auth_req_id() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/ciba/auth")
        // Assert the CIBA request shape: login_hint + binding_message.
        // The purpose "Approve raise" is sanitized to a Keycloak-valid,
        // space-free correlation code before it goes on the wire.
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("login_hint".into(), "alice@corp.com".into()),
            mockito::Matcher::UrlEncoded("binding_message".into(), "Approve-raise".into()),
            mockito::Matcher::UrlEncoded("scope".into(), "openid".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "auth_req_id": "REQ-123", "expires_in": 300, "interval": 5 }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let out = run(&app, payload).await;

    m.assert_async().await;
    assert_eq!(out.id.as_deref(), Some("REQ-123"));
    assert_eq!(out.status, Some(ElicitationStatusKind::Pending));
    assert_eq!(out.approver.as_deref(), Some("alice@corp.com"));
    assert!(out.expires_at.is_some());
}

#[tokio::test]
async fn check_authorization_pending_maps_to_pending() {
    let mut server = mockito::Server::new_async().await;
    let m = server
        .mock("POST", "/token")
        .match_body(mockito::Matcher::UrlEncoded(
            "auth_req_id".into(),
            "REQ-123".into(),
        ))
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(json!({ "error": "authorization_pending" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    m.assert_async().await;
    assert_eq!(out.status, Some(ElicitationStatusKind::Pending));
    assert!(out.outcome.is_none());
}

#[tokio::test]
async fn check_success_maps_to_resolved_approved() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({ "access_token": "at", "id_token": fake_id_token("alice@corp.com") })
                .to_string(),
        )
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Resolved));
    assert_eq!(out.outcome, Some(ElicitationOutcomeKind::Approved));
}

#[tokio::test]
async fn check_access_denied_maps_to_resolved_denied() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(json!({ "error": "access_denied" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Resolved));
    assert_eq!(out.outcome, Some(ElicitationOutcomeKind::Denied));
}

#[tokio::test]
async fn check_expired_token_maps_to_expired() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(json!({ "error": "expired_token" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let out = run(&app, payload).await;

    assert_eq!(out.status, Some(ElicitationStatusKind::Expired));
}

#[tokio::test]
async fn full_flow_dispatch_check_validate_approves() {
    // One approver instance across all three ops, so the in-memory
    // correlation store carries the expected approver + cached token.
    let mut server = mockito::Server::new_async().await;
    let _auth = server
        .mock("POST", "/ciba/auth")
        .with_status(200)
        .with_body(json!({ "auth_req_id": "REQ-9", "expires_in": 300 }).to_string())
        .create_async()
        .await;
    let _tok = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(json!({ "id_token": fake_id_token("alice@corp.com") }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());

    // 1. dispatch — login_hint = the resolved approver.
    let d = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
            .with_purpose("Approve raise"),
    )
    .await;
    let id = d.id.clone().expect("dispatch id");

    // 2. check — approved.
    let c = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id(&id),
    )
    .await;
    assert_eq!(c.outcome, Some(ElicitationOutcomeKind::Approved));

    // 3. validate — token's preferred_username matches the login_hint.
    let v = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "").with_elicitation_id(&id),
    )
    .await;
    assert_eq!(v.valid, Some(true));
    assert_eq!(v.approver.as_deref(), Some("alice@corp.com"));
}

#[tokio::test]
async fn validate_rejects_approver_mismatch() {
    let mut server = mockito::Server::new_async().await;
    let _auth = server
        .mock("POST", "/ciba/auth")
        .with_status(200)
        .with_body(json!({ "auth_req_id": "REQ-x", "expires_in": 300 }).to_string())
        .create_async()
        .await;
    // The token comes back naming a DIFFERENT user than the login_hint.
    let _tok = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(json!({ "id_token": fake_id_token("mallory@corp.com") }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let d = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com"),
    )
    .await;
    let id = d.id.unwrap();
    let _ = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id(&id),
    )
    .await;
    let v = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Validate, "approval", "").with_elicitation_id(&id),
    )
    .await;

    assert_eq!(v.valid, Some(false));
    assert!(v.reason.unwrap().contains("approver mismatch"));
}

// ---------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------

/// Run a payload and require a denial, returning the violation.
async fn deny_for(
    app: &CibaApprover,
    payload: ElicitationPayload,
) -> praxis_policy_core::error::PluginViolation {
    let ext = Extensions::default();
    let mut ctx = PluginContext::new();
    let result = app.handle(&payload, &ext, &mut ctx).await;
    assert!(
        !result.continue_processing,
        "this case must deny rather than report a lifecycle state"
    );
    result.violation.expect("a deny carries a violation")
}

/// A URL whose port has been released, so connecting is refused rather than
/// hanging until the timeout.
fn closed_endpoint() -> String {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
        listener.local_addr().expect("the bound address").port()
    };
    format!("http://127.0.0.1:{port}")
}

/// An unreachable OP on dispatch must deny, not report pending. Reporting
/// pending would leave the caller polling an approval request that was never
/// created, so the request would sit until it expired with nobody notified.
#[tokio::test]
async fn a_dispatch_that_cannot_reach_the_op_denies_rather_than_reporting_pending() {
    let app = approver(&closed_endpoint());
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let violation = deny_for(&app, payload).await;
    assert_eq!(violation.code, "elicitation.op_unreachable");
    assert!(
        violation.reason.contains("backchannel"),
        "the reason must name the leg that failed, since dispatch and check \
         talk to different endpoints: {}",
        violation.reason
    );
}

/// The same for the token poll: an unreachable OP is a transport failure, not
/// an approval outcome. Treating it as either approved or denied would invent a
/// human decision that nobody made.
#[tokio::test]
async fn a_check_that_cannot_reach_the_op_denies_rather_than_inventing_an_outcome() {
    let app = approver(&closed_endpoint());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let violation = deny_for(&app, payload).await;
    assert_eq!(violation.code, "elicitation.op_unreachable");
    assert!(
        violation.reason.contains("token poll"),
        "the reason must name the token poll: {}",
        violation.reason
    );
}

/// A backchannel rejection is reported with its status, because the request was
/// never registered and the caller has to stop rather than poll.
#[tokio::test]
async fn a_rejected_backchannel_request_denies_with_its_status() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/ciba/auth")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(json!({ "error": "invalid_request" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    let violation = deny_for(&app, payload).await;
    assert_eq!(violation.code, "elicitation.op_rejected");
    assert!(
        violation.reason.contains("400"),
        "the status must appear so an operator can tell a bad request from an \
         outage: {}",
        violation.reason
    );
}

/// A 200 from the backchannel carrying no `auth_req_id` cannot be treated as a
/// dispatched request: there would be no id for the agent to poll with.
#[tokio::test]
async fn a_backchannel_success_with_no_auth_req_id_denies() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/ciba/auth")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "expires_in": 300 }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
        .with_purpose("Approve raise");
    assert_eq!(
        deny_for(&app, payload).await.code,
        "elicitation.bad_response"
    );
}

/// A successful poll whose body is not JSON denies rather than being read as an
/// approval. This is the dangerous direction: a 200 means the OP issued tokens,
/// so a parse failure here must not be allowed to resolve as approved with no
/// approver recorded.
#[tokio::test]
async fn a_successful_poll_with_an_unparseable_body_denies() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("not json at all")
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    assert_eq!(
        deny_for(&app, payload).await.code,
        "elicitation.bad_response"
    );
}

/// An OAuth error the lifecycle mapping does not recognize is a genuine
/// failure, not a state. `authorization_pending`, `expired_token` and
/// `access_denied` each map to a lifecycle outcome; anything else, such as the
/// `invalid_grant` a spent request id produces, has to deny. Mapping an unknown
/// error to pending would make the caller poll forever.
#[tokio::test]
async fn an_unrecognized_poll_error_denies_instead_of_becoming_a_lifecycle_state() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("POST", "/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(json!({ "error": "invalid_grant" }).to_string())
        .create_async()
        .await;

    let app = approver(&server.url());
    let payload = ElicitationPayload::new(ElicitationOp::Check, "approval", "")
        .with_elicitation_id("REQ-123");
    let violation = deny_for(&app, payload).await;
    assert_eq!(violation.code, "elicitation.op_rejected");
    assert!(
        violation.reason.contains("invalid_grant"),
        "the unrecognized error must be quoted so it can be diagnosed: {}",
        violation.reason
    );
}

/// A second check after approval must replay the cached result rather than poll
/// again.
///
/// A CIBA `auth_req_id` is spent by the exchange that consumes it, so a re-poll
/// comes back `invalid_grant`, which the case above shows is a denial. The
/// confirm-then-apply retry does exactly this second check, so without the
/// replay an approval the user actually granted would turn into a denial on the
/// call that depends on it.
///
/// The replay depends on the dispatch having registered the correlation in this
/// same process: caching the resolved approver is a no-op for an id the store
/// does not already know, so the sequence has to start at dispatch. The token
/// mock expects exactly one hit, so a re-poll fails the assertion rather than
/// quietly succeeding against a still-live mock.
#[tokio::test]
async fn a_second_check_after_approval_replays_instead_of_repolling() {
    let mut server = mockito::Server::new_async().await;
    let _dispatch = server
        .mock("POST", "/ciba/auth")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "auth_req_id": "REQ-123", "expires_in": 300 }).to_string())
        .create_async()
        .await;
    let poll = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({ "access_token": "at", "id_token": fake_id_token("alice@corp.com") })
                .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = approver(&server.url());
    let dispatched = run(
        &app,
        ElicitationPayload::new(ElicitationOp::Dispatch, "approval", "alice@corp.com")
            .with_purpose("Approve raise"),
    )
    .await;
    assert_eq!(dispatched.id.as_deref(), Some("REQ-123"));

    let check = || {
        ElicitationPayload::new(ElicitationOp::Check, "approval", "").with_elicitation_id("REQ-123")
    };

    let first = run(&app, check()).await;
    assert_eq!(first.outcome, Some(ElicitationOutcomeKind::Approved));

    let second = run(&app, check()).await;
    assert_eq!(
        second.outcome,
        Some(ElicitationOutcomeKind::Approved),
        "the cached approval must be replayed"
    );
    assert_eq!(second.status, Some(ElicitationStatusKind::Resolved));

    // Exactly one poll reached the OP across both checks.
    poll.assert_async().await;
}

// ---------------------------------------------------------------------
// Configuration the approver has to refuse
// ---------------------------------------------------------------------

fn config_err(config: serde_json::Value) -> String {
    let cfg = PluginConfig {
        name: "manager-approver".to_owned(),
        kind: "elicitation/ciba".to_owned(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["elicit".to_owned()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(config),
    };
    match CibaApprover::new(cfg) {
        Ok(_) => panic!("this config must not load"),
        Err(e) => e.to_string(),
    }
}

/// Both endpoints and the client id are required, and plaintext is refused
/// unless the operator opted in.
///
/// The plaintext check is the one that matters most: this plugin sends the
/// client secret as Basic auth on every call, so an `http://` endpoint puts it
/// on the wire in the clear.
#[tokio::test]
async fn each_incomplete_ciba_config_is_refused_at_load() {
    let base = json!({
        "backchannel_endpoint": "https://op.example/ciba/auth",
        "token_endpoint": "https://op.example/token",
        "client_id": "praxis-policy-gateway",
        "client_secret_source": { "kind": "literal", "secret": "shh" },
    });

    // The control: the baseline loads, so each failure below is attributable to
    // the single field it changes.
    let cfg = PluginConfig {
        name: "manager-approver".to_owned(),
        kind: "elicitation/ciba".to_owned(),
        description: None,
        author: None,
        version: None,
        hooks: vec!["elicit".to_owned()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        capabilities: HashSet::new(),
        tags: Vec::new(),
        conditions: Vec::new(),
        config: Some(base.clone()),
    };
    assert!(
        CibaApprover::new(cfg).is_ok(),
        "the baseline config must load"
    );

    let with = |field: &str, value: serde_json::Value| {
        let mut c = base.clone();
        c.as_object_mut().unwrap().insert(field.to_owned(), value);
        c
    };

    for (field, value, expected) in [
        ("backchannel_endpoint", json!(""), "must be non-empty"),
        ("token_endpoint", json!("  "), "must be non-empty"),
        ("client_id", json!(""), "client_id must be non-empty"),
        (
            "backchannel_endpoint",
            json!("http://op.example/ciba/auth"),
            "https://",
        ),
        (
            "token_endpoint",
            json!("http://op.example/token"),
            "https://",
        ),
    ] {
        let err = config_err(with(field, value.clone()));
        assert!(
            err.contains(expected),
            "{field} = {value}: the message must contain {expected:?}, got: {err}"
        );
    }
}
