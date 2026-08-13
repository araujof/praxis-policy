// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// End-to-end tests for `OAuthDelegator` against a `mockito`-backed
// fake IdP. Exercises the full handler path:
// `mgr.invoke_named::<TokenDelegateHook>(...)` → delegator builds
// RFC 8693 form body → POSTs to mock IdP → mock returns response
// → delegator translates into a `RawDelegatedToken` → host
// extracts via `from_pipeline_result`.
//
// Scenarios:
//   * happy path — minted token populated with audience + scopes + expiry
//   * IdP returns 400 with `invalid_grant` — surfaces `delegation.idp_rejected`
//   * IdP unreachable — surfaces `delegation.idp_unreachable`
//   * Request body shape — mockito's matcher verifies we send the
//     correct RFC 8693 fields
//   * actor_token — present on the wire when the payload carries one
//     (Mode B), fully absent when it doesn't
//   * workload subject (Mode A) — the SVID authenticates the agent as
//     a client_assertion (leg 1), then the exchange runs on that base
//     token (leg 2); attributed `AsCallerWorkload`, not `AsThisWorkload`

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
use std::sync::Arc;

use praxis_policy_core::delegation::{
    AttenuationConfig, AuthEnforcedBy, DelegationPayload, DelegationSubject, HOOK_TOKEN_DELEGATE,
    TargetType, TokenDelegateHook,
};
use praxis_policy_core::extensions::raw_credentials::{DelegationMode, TokenRole};
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::manager::PluginManager;
use praxis_policy_core::plugin::{OnError, PluginConfig, PluginMode};

use praxis_policy_plugin_delegator_oauth::OAuthDelegator;

use mockito::{Matcher, Server};
use serde_json::json;

// =====================================================================
// Fixtures
// =====================================================================

fn plugin_config(token_endpoint: &str) -> PluginConfig {
    PluginConfig {
        name: "oauth-delegator".into(),
        kind: "test".into(),
        hooks: vec![HOOK_TOKEN_DELEGATE.into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(json!({
            "token_endpoint": token_endpoint,
            "client_id": "gateway-client",
            "client_secret_source": {
                "kind": "literal",
                "secret": "test-secret",
            },
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "timeout_seconds": 2,
            "default_outbound_header": "Authorization",
            // wiremock binds to http://127.0.0.1 — opt in to plaintext
            // for the test. Production deployments must omit this.
            "insecure_http": true,
        })),
        ..Default::default()
    }
}

fn build_payload(target: &str, audience: &str, scopes: &[&str]) -> DelegationPayload {
    DelegationPayload::new("caller-bearer-token-bytes", target)
        .with_target_type(TargetType::Tool)
        .with_target_audience(audience)
        .with_required_permissions(
            scopes
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        )
        .with_auth_enforced_by(AuthEnforcedBy::Target)
        .with_route_attenuation(AttenuationConfig {
            capabilities: vec!["audit".into()],
            resource_template: None,
            actions: Vec::new(),
            ttl_seconds: Some(120),
        })
}

async fn build_manager(token_endpoint: &str) -> Arc<PluginManager> {
    let cfg = plugin_config(token_endpoint);
    let delegator = OAuthDelegator::new(cfg.clone()).expect("delegator constructs");
    let mgr = Arc::new(PluginManager::default());
    mgr.register_handler_for_names::<TokenDelegateHook, _>(
        Arc::new(delegator),
        cfg,
        &[HOOK_TOKEN_DELEGATE],
    )
    .unwrap();
    mgr.initialize().await.unwrap();
    mgr
}

async fn invoke(
    mgr: &Arc<PluginManager>,
    payload: DelegationPayload,
) -> praxis_policy_core::executor::PipelineResult {
    let (result, _bg) = mgr
        .invoke_named::<TokenDelegateHook>(
            HOOK_TOKEN_DELEGATE,
            payload,
            Extensions::default(),
            None,
        )
        .await;
    result
}

// =====================================================================
// Scenarios
// =====================================================================

/// Happy path: mock `IdP` responds with a fresh `access_token`; the
/// delegator translates it into a `RawDelegatedToken` populated
/// with the requested audience, the effective scopes, and an
/// expiry derived from `expires_in`.
#[tokio::test]
async fn happy_path_mints_delegated_token() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_header("content-type", "application/x-www-form-urlencoded")
        // Expect the form fields RFC 8693 requires.
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded(
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            ),
            Matcher::UrlEncoded(
                "subject_token".into(),
                "caller-bearer-token-bytes".into(),
            ),
            Matcher::UrlEncoded(
                "audience".into(),
                "https://hr.example.com".into(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "minted-downstream-jwt",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                "scope": "read:compensation audit",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "happy path should mint a token: violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    let token = final_payload
        .delegated_token
        .as_ref()
        .expect("delegated_token populated");

    assert_eq!(&*token.token, "minted-downstream-jwt");
    assert_eq!(token.audience, "https://hr.example.com");
    assert_eq!(token.outbound_header, "Authorization");
    // Effective scopes come from the IdP's `scope` field.
    assert!(token.scopes.contains(&"read:compensation".to_owned()));
    assert!(token.scopes.contains(&"audit".to_owned()));

    // Mode is OnBehalfOfUser by default for RFC 8693 exchange.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // TTL respects the route hint (120s) — IdP's expires_in was 300,
    // but the route asked to cap at 120, so effective is 120.
    let ttl_left = (token.expires_at - chrono::Utc::now()).num_seconds();
    assert!(
        ttl_left <= 120 && ttl_left > 100,
        "ttl should reflect min(idp_ttl, route_hint); got {ttl_left}s",
    );

    mock.assert_async().await;
}

/// `IdP` returns a 400 with the standard `error` / `error_description`
/// shape — delegator surfaces `delegation.idp_rejected` carrying the
/// `IdP`'s machine-readable code.
#[tokio::test]
async fn idp_rejection_surfaces_error_code() {
    let mut server = Server::new_async().await;
    server
        .mock("POST", "/oauth/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "invalid_grant",
                "error_description": "subject_token is not active",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read"]);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("invalid_grant"),
        "reason should include IdP's error code; got: {}",
        violation.reason,
    );
    assert!(
        violation.reason.contains("not active"),
        "reason should include the error_description; got: {}",
        violation.reason,
    );
}

/// `IdP` unreachable (mockito server stopped) — delegator surfaces
/// `delegation.idp_unreachable` rather than panicking.
#[tokio::test]
async fn idp_unreachable_surfaces_violation() {
    // Use a localhost URL that should be unreachable (no listener
    // on that port). The `127.0.0.1:1` port-1 trick: port 1 isn't
    // bound by typical systems and connection refusal is fast.
    let mgr = build_manager("http://127.0.0.1:1/oauth/token").await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read"]);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    // Either `idp_unreachable` (connection refused) or `idp_timeout`
    // (if the OS decides to slow-fail) — both are valid outcomes
    // for "IdP isn't there." The test accepts either.
    assert!(
        violation.code == "delegation.idp_unreachable"
            || violation.code == "delegation.idp_timeout",
        "expected idp_unreachable or idp_timeout; got {}",
        violation.code,
    );
}

/// Empty bearer token — fails fast at the handler entry before
/// touching the network. Verifies the input-validation path.
#[tokio::test]
async fn empty_bearer_token_rejects_without_network() {
    let mgr = build_manager("http://this-must-not-be-called/oauth/token").await;
    let payload =
        DelegationPayload::new("", "tool").with_target_audience("https://downstream.example.com");

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("empty bearer_token"));
}

/// Missing target audience — fails fast (RFC 8693 requires
/// `audience` for downstream scoping).
#[tokio::test]
async fn missing_audience_rejects_without_network() {
    let mgr = build_manager("http://this-must-not-be-called/oauth/token").await;
    let payload = DelegationPayload::new("some-token", "tool"); // no audience

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing);
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.bad_request");
    assert!(violation.reason.contains("target_audience"));
}

/// `IdP` grants narrower scopes than requested — delegator emits the
/// documented `delegation.scope_too_broad` code rather than silently
/// proceeding. Without this check, a route that requested
/// `read+write` and got back only `read` would mint a token the
/// downstream call can't actually use, leaving the policy author
/// with no observable signal about *why* the call failed downstream.
#[tokio::test]
async fn idp_narrower_scope_surfaces_scope_too_broad() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "narrower-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                // Asked for both, got only `read`.
                "scope": "read",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read", "write"]);

    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "narrower IdP grant must NOT silently succeed",
    );
    let violation = result.violation.expect("rejection should surface");
    assert_eq!(violation.code, "delegation.scope_too_broad");
    assert!(
        violation.reason.contains("write"),
        "reason should name the missing scope: {}",
        violation.reason,
    );

    mock.assert_async().await;
}

/// Sanity check: when the `IdP` grants exactly the requested set, the
/// scope check passes. Pins the "no false positive" half of the
/// `scope_too_broad` behaviour.
#[tokio::test]
async fn idp_exact_scope_match_succeeds() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": "ok-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "expires_in": 300,
                "scope": "read write",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload("tool", "https://downstream.example.com", &["read", "write"]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "exact scope match should mint a token; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}

// =====================================================================
// RFC 8693 actor_token / subject-role attribution
// =====================================================================

/// Standard 200 response body, factored out so the actor tests can
/// focus on what they're actually asserting (the request side).
fn ok_token_response() -> String {
    json!({
        "access_token": "minted-downstream-jwt",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 300,
        "scope": "read:compensation",
    })
    .to_string()
}

/// Mode B — user subject + workload actor. The delegator must put the
/// SVID on the wire as RFC 8693 §2.1 `actor_token`, tagged with the
/// configured `actor_token_type`, alongside the user's `subject_token`.
/// This is the on-behalf-of-a-user shape, and the
/// minted token still speaks for the user.
#[tokio::test]
async fn actor_token_reaches_the_idp_when_the_payload_carries_one() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::AllOf(vec![
            // The user is still the subject...
            Matcher::UrlEncoded("subject_token".into(), "caller-bearer-token-bytes".into()),
            // ...and the workload SVID rides along as the actor.
            Matcher::UrlEncoded("actor_token".into(), "workload.svid.bytes".into()),
            Matcher::UrlEncoded(
                "actor_token_type".into(),
                "urn:ietf:params:oauth:token-type:jwt".into(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_actor(TokenRole::CallerWorkload, "workload.svid.bytes");

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "actor-token exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    // Subject is the user, so the token still speaks for the user
    // even though a workload actor was recorded.
    assert!(matches!(
        final_payload.delegation_mode,
        Some(DelegationMode::OnBehalfOfUser),
    ));

    // If the actor fields hadn't been sent, the matcher above would
    // have failed to match and this assertion would fire.
    mock.assert_async().await;
}

/// The negative half: a payload with no actor must produce a plain
/// single-token exchange. Asserted by rejecting any request whose body
/// mentions `actor_token` at all — a stray empty `actor_token=` field
/// would confuse strict `IdPs`, so "absent" has to mean absent.
#[tokio::test]
async fn absent_actor_leaves_no_actor_fields_on_the_wire() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_request(|req| {
            let body = req.body().expect("request has a body");
            !String::from_utf8_lossy(body).contains("actor_token")
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    // No `.with_actor_token(...)` — the ordinary single-token case.
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    );

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "single-token exchange should still succeed; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}

/// `subject: this_workload` — this instance holds the access to the
/// downstream (the "hold the tool credentials here" deployment)
/// and calls it as itself. There is no inbound credential to
/// exchange, so this must switch to an RFC 6749 §4.4
/// `client_credentials` grant rather than a token exchange: no
/// `subject_token`, and this instance's identity proven by the Basic
/// auth header it already sends.
#[tokio::test]
async fn this_workload_subject_uses_client_credentials_not_token_exchange() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".into(), "client_credentials".into()),
            Matcher::UrlEncoded("audience".into(), "https://hr.example.com".into()),
        ]))
        // A token exchange sends subject_token; this must not.
        .match_request(|req| {
            let body = req.body().expect("request has a body");
            !String::from_utf8_lossy(body).contains("subject_token")
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    // Note the empty bearer token: for a this_workload subject that is the
    // expected state, not the "caller forgot the credential" error.
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::ThisWorkload)
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".into()]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "this_workload-subject exchange should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert!(
        matches!(
            final_payload.delegation_mode,
            Some(DelegationMode::AsThisWorkload),
        ),
        "this_workload subject must be attributed to this instance, got {:?}",
        final_payload.delegation_mode,
    );
    mock.assert_async().await;
}

/// An empty bearer token is still an error for every subject that
/// *does* have an inbound credential. Pins the boundary: the
/// `this_workload`'s exemption must not silently swallow a genuinely missing
/// workload or user token.
#[tokio::test]
async fn empty_bearer_still_rejected_for_non_this_workload_subjects() {
    let mgr = build_manager("https://unused.example.com/oauth/token").await;
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::CallerWorkload)
        .with_target_audience("https://hr.example.com");

    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "a missing credential must still be an error for a workload subject",
    );
    assert_eq!(
        result.violation.expect("violation surfaced").code,
        "delegation.bad_request",
    );
}

/// `actor_token` is a token-exchange parameter with no meaning under
/// `client_credentials`, so a this_workload-subject call must not send it
/// even when the payload carries one — an `IdP` receiving both would be
/// getting a malformed request.
#[tokio::test]
async fn this_workload_subject_never_sends_actor_token() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("POST", "/oauth/token")
        .match_request(|req| {
            let body = req.body().expect("request has a body");
            !String::from_utf8_lossy(body).contains("actor_token")
        })
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = DelegationPayload::new("", "get_compensation")
        .with_subject(DelegationSubject::ThisWorkload)
        .with_actor(TokenRole::CallerWorkload, "workload.svid.bytes")
        .with_target_audience("https://hr.example.com")
        .with_required_permissions(vec!["read:compensation".into()]);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "should still mint; violation = {:?}",
        result.violation,
    );
    mock.assert_async().await;
}

/// Mode A — the calling agent acts as itself. Its SVID is a *client
/// credential*, not a `subject_token`, so the delegator runs two legs:
///
///   leg 1  present the SVID as an RFC 7523 `client_assertion`
///          (`client_credentials`) → the agent's base `IdP` token;
///   leg 2  the ordinary exchange, run on that BASE token, scopes it
///          to the target audience.
///
/// This is what keeps this instance (holder of the leg-2 client secret),
/// not the agent, as the grantor of downstream authority. The minted
/// credential still speaks for the agent, so `delegation_mode` must be
/// `AsCallerWorkload` (the delegated-token cache keys off it) — and
/// specifically not `AsThisWorkload`, which is this instance's own identity.
///
/// Both legs are asserted: proving the SVID went out as a
/// `client_assertion` in leg 1 and that leg 2 exchanged the base token
/// — never the raw SVID as a `subject_token`.
#[tokio::test]
async fn workload_subject_authenticates_by_svid_then_exchanges() {
    let mut server = Server::new_async().await;

    // Leg 1: SVID as client_assertion (jwt-spiffe) under
    // client_credentials → the agent's base token. Must NOT be a
    // subject_token here.
    let leg1 = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("grant_type".into(), "client_credentials".into()),
            Matcher::UrlEncoded(
                "client_assertion_type".into(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe".into(),
            ),
            Matcher::UrlEncoded(
                "client_assertion".into(),
                "caller-bearer-token-bytes".into(),
            ),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "access_token": "agent-base-token", "expires_in": 300 }).to_string())
        .create_async()
        .await;

    // Leg 2: the exchange runs on the BASE token from leg 1, not the
    // SVID. Pinning subject_token here is what fails if leg 1 is
    // skipped or the raw SVID leaks through as the subject.
    let leg2 = server
        .mock("POST", "/oauth/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded(
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            ),
            Matcher::UrlEncoded("subject_token".into(), "agent-base-token".into()),
            Matcher::UrlEncoded("audience".into(), "https://hr.example.com".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(ok_token_response())
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload);

    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "two-leg workload delegation should mint a token; violation = {:?}",
        result.violation,
    );

    let final_payload = DelegationPayload::from_pipeline_result(&result)
        .expect("delegation payload should be present");
    assert!(
        matches!(
            final_payload.delegation_mode,
            Some(DelegationMode::AsCallerWorkload),
        ),
        "workload subject must be attributed to the calling agent, got {:?}",
        final_payload.delegation_mode,
    );

    // Both legs actually fired — the SVID authenticated the agent (leg
    // 1) and the exchange ran on the base token (leg 2).
    leg1.assert_async().await;
    leg2.assert_async().await;
}

/// A leg-1 rejection must not echo submitted credential material. Even
/// when the `IdP` hostilely parrots the SVID back in `error_description`, the
/// caller-visible violation carries only the OAuth error code — never the
/// `client_assertion` bytes.
#[tokio::test]
async fn leg1_rejection_does_not_leak_the_client_assertion() {
    let mut server = Server::new_async().await;

    let _leg1 = server
        .mock("POST", "/oauth/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "invalid_client",
                "error_description": "assertion 'caller-bearer-token-bytes' is not valid",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let payload = build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload);

    let result = invoke(&mgr, payload).await;
    assert!(!result.continue_processing, "leg-1 rejection should deny");
    let violation = result.violation.expect("violation surfaced");
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        !violation.reason.contains("caller-bearer-token-bytes"),
        "violation must NOT echo the submitted SVID; got: {}",
        violation.reason,
    );
    assert!(
        violation.reason.contains("invalid_client"),
        "violation should carry the OAuth error code; got: {}",
        violation.reason,
    );
}

// =====================================================================
// Leg-1 failures other than a clean rejection
// =====================================================================

/// A payload for the two-leg workload shape, so the tests below all enter
/// through leg 1.
fn workload_payload() -> DelegationPayload {
    build_payload(
        "get_compensation",
        "https://hr.example.com",
        &["read:compensation"],
    )
    .with_subject(DelegationSubject::CallerWorkload)
}

async fn violation_for(
    payload: DelegationPayload,
    endpoint: &str,
) -> praxis_policy_core::error::PluginViolation {
    let mgr = build_manager(endpoint).await;
    let result = invoke(&mgr, payload).await;
    assert!(
        !result.continue_processing,
        "this case must deny rather than mint a token"
    );
    result.violation.expect("a deny carries a violation")
}

/// Leg 1 against an endpoint with nothing listening. The agent cannot be
/// authenticated, so the whole delegation has to fail closed: minting on a
/// failed leg 1 would hand out a downstream token for an agent whose identity
/// was never established.
#[tokio::test]
async fn a_leg1_transport_failure_denies_the_whole_delegation() {
    // Bind a loopback port, learn its number, then release it. Connecting to a
    // closed loopback port is refused immediately, which keeps this a transport
    // failure rather than the timeout a firewalled address would produce.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
        listener.local_addr().expect("the bound address").port()
    };
    let violation = violation_for(
        workload_payload(),
        &format!("http://127.0.0.1:{port}/oauth/token"),
    )
    .await;
    assert_eq!(violation.code, "delegation.idp_unreachable");
    assert!(
        violation.reason.contains("workload client_assertion"),
        "the reason must say which leg failed, since both legs post to the \
         same endpoint: {}",
        violation.reason
    );
}

/// A leg-1 rejection whose body is not the OAuth error JSON at all. The status
/// is all there is to report, and reporting it is the point: an operator seeing
/// a bare `idp_rejected` with no detail cannot tell a 400 from a 503.
#[tokio::test]
async fn a_leg1_rejection_with_an_unparseable_body_still_reports_the_status() {
    let mut server = Server::new_async().await;
    let _leg1 = server
        .mock("POST", "/oauth/token")
        .with_status(503)
        .with_body("<html>gateway timeout</html>")
        .create_async()
        .await;

    let violation =
        violation_for(workload_payload(), &format!("{}/oauth/token", server.url())).await;
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("503"),
        "the status is the only detail available and must appear: {}",
        violation.reason
    );
    assert!(
        !violation.reason.contains("gateway timeout"),
        "an unparseable body is not echoed, for the same reason \
         error_description is not: {}",
        violation.reason
    );
}

/// Leg 1 answering 200 with something that is not a token response. Treating a
/// missing `access_token` as success would carry an empty credential into leg 2
/// and produce a confusing leg-2 rejection instead of naming the real fault.
#[tokio::test]
async fn a_leg1_success_that_is_not_a_token_response_denies() {
    let mut server = Server::new_async().await;
    let _leg1 = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "not_a_token": true }).to_string())
        .create_async()
        .await;

    let violation =
        violation_for(workload_payload(), &format!("{}/oauth/token", server.url())).await;
    assert_eq!(violation.code, "delegation.bad_response");
    assert!(
        violation.reason.contains("workload client_assertion"),
        "the reason must attribute the bad response to leg 1: {}",
        violation.reason
    );
}

// =====================================================================
// Leg-2 error shapes
// =====================================================================

/// A leg-2 rejection carrying `error_description` surfaces both the code and
/// the description.
///
/// Note the asymmetry with leg 1, which deliberately drops the description
/// because an `IdP` may echo the submitted credential back in it. Leg 2 submits
/// the caller's bearer token as `subject_token`, so the same echo is possible
/// here. This test records what the code does today rather than endorsing it.
#[tokio::test]
async fn a_leg2_rejection_surfaces_the_error_description() {
    let mut server = Server::new_async().await;
    let _leg2 = server
        .mock("POST", "/oauth/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "invalid_scope",
                "error_description": "read:compensation is not granted to this client",
            })
            .to_string(),
        )
        .create_async()
        .await;

    let violation = violation_for(
        build_payload(
            "get_compensation",
            "https://hr.example.com",
            &["read:compensation"],
        ),
        &format!("{}/oauth/token", server.url()),
    )
    .await;
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("invalid_scope"),
        "the machine-readable code must appear: {}",
        violation.reason
    );
    assert!(
        violation.reason.contains("not granted to this client"),
        "and today the description is appended to it: {}",
        violation.reason
    );
}

/// A leg-2 rejection whose body is not OAuth error JSON falls back to the
/// status. Without the fallback the violation would carry an empty reason.
#[tokio::test]
async fn a_leg2_rejection_with_an_unparseable_body_falls_back_to_the_status() {
    let mut server = Server::new_async().await;
    let _leg2 = server
        .mock("POST", "/oauth/token")
        .with_status(500)
        .with_body("upstream exploded")
        .create_async()
        .await;

    let violation = violation_for(
        build_payload("get_compensation", "https://hr.example.com", &[]),
        &format!("{}/oauth/token", server.url()),
    )
    .await;
    assert_eq!(violation.code, "delegation.idp_rejected");
    assert!(
        violation.reason.contains("500"),
        "the status must appear when nothing else is parseable: {}",
        violation.reason
    );
}

/// Leg 2 answering 200 with a body that carries no `access_token`. There is no
/// token to forward, so this has to deny rather than mint an empty credential.
#[tokio::test]
async fn a_leg2_success_with_no_access_token_denies() {
    let mut server = Server::new_async().await;
    let _leg2 = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "token_type": "Bearer" }).to_string())
        .create_async()
        .await;

    let violation = violation_for(
        build_payload("get_compensation", "https://hr.example.com", &[]),
        &format!("{}/oauth/token", server.url()),
    )
    .await;
    assert_eq!(violation.code, "delegation.bad_response");
}

// =====================================================================
// Lifetime and metadata of the minted token
// =====================================================================

/// Run the happy path with a chosen token response and attenuation, and return
/// the minted payload.
async fn mint_with(body: String, attenuation: Option<AttenuationConfig>) -> DelegationPayload {
    let mut server = Server::new_async().await;
    let _m = server
        .mock("POST", "/oauth/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let mut payload = DelegationPayload::new("caller-bearer-token-bytes", "get_compensation")
        .with_target_type(TargetType::Tool)
        .with_target_audience("https://hr.example.com")
        .with_auth_enforced_by(AuthEnforcedBy::Target);
    if let Some(att) = attenuation {
        payload = payload.with_route_attenuation(att);
    }

    let mgr = build_manager(&format!("{}/oauth/token", server.url())).await;
    let result = invoke(&mgr, payload).await;
    assert!(
        result.continue_processing,
        "this case must mint a token; violation = {:?}",
        result.violation
    );
    DelegationPayload::from_pipeline_result(&result).expect("a minted payload")
}

fn attenuation_with_ttl(ttl: Option<u64>) -> AttenuationConfig {
    AttenuationConfig {
        capabilities: Vec::new(),
        resource_template: None,
        actions: Vec::new(),
        ttl_seconds: ttl,
    }
}

/// Route attenuation shortens the token's life but never extends it, and an
/// attenuation hint too large to be a duration must leave the `IdP`'s lifetime
/// alone rather than wrap into a negative one.
///
/// A negative lifetime is the failure worth guarding: the minted token would
/// already be expired, so every downstream call fails in a way that looks like
/// an `IdP` problem. The cast saturates for that reason, and nothing else here
/// would notice if it stopped.
#[tokio::test]
async fn attenuation_only_ever_shortens_the_minted_token_lifetime() {
    let body = json!({ "access_token": "t", "expires_in": 3600 }).to_string();

    let shortened = mint_with(body.clone(), Some(attenuation_with_ttl(Some(60)))).await;
    let ttl = shortened
        .delegated_token
        .expect("a token")
        .expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    assert!(
        (0..=60).contains(&ttl),
        "a 60s attenuation hint must shorten a 3600s grant, got {ttl}s"
    );

    // A hint larger than any real duration means "no further shortening".
    let absurd = mint_with(body.clone(), Some(attenuation_with_ttl(Some(u64::MAX)))).await;
    let ttl = absurd
        .delegated_token
        .expect("a token")
        .expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    assert!(
        ttl > 0,
        "an unrepresentable attenuation hint must not produce an \
         already-expired token, got {ttl}s"
    );
    assert!(
        ttl > 3000,
        "and must leave the IdP's own lifetime in place, got {ttl}s"
    );
}

/// An `IdP` that sends no `expires_in` gets a short default rather than an
/// unbounded lifetime, so a misconfigured `IdP` cannot cause long-lived tokens.
#[tokio::test]
async fn a_token_response_with_no_expiry_gets_a_short_default() {
    let minted = mint_with(json!({ "access_token": "t" }).to_string(), None).await;
    let ttl = minted
        .delegated_token
        .expect("a token")
        .expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    assert!(
        (0..=300).contains(&ttl),
        "an absent expires_in must default to at most 5 minutes, got {ttl}s"
    );
}

/// `issued_token_type` is recorded either way: echoed when the `IdP` sends one,
/// defaulted when it does not. Downstream reads this from metadata, so an
/// absent key and a defaulted key are different outcomes for it.
#[tokio::test]
async fn the_issued_token_type_is_recorded_whether_or_not_the_idp_sends_one() {
    let echoed = mint_with(
        json!({
            "access_token": "t",
            "expires_in": 300,
            "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
        .to_string(),
        None,
    )
    .await;
    assert_eq!(
        echoed.metadata.get("issued_token_type"),
        Some(&json!("urn:ietf:params:oauth:token-type:jwt")),
        "an explicit issued_token_type must be carried through"
    );

    let defaulted = mint_with(
        json!({ "access_token": "t", "expires_in": 300 }).to_string(),
        None,
    )
    .await;
    assert_eq!(
        defaulted.metadata.get("issued_token_type"),
        Some(&json!("urn:ietf:params:oauth:token-type:access_token")),
        "and an absent one must be defaulted rather than left unset"
    );
}
