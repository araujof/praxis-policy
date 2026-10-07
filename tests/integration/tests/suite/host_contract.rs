// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The shared harness does what the suites rely on it to do.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Barrier};

use praxis_policy::{SessionStore, SessionStoreFactory};
use praxis_policy_core::cmf::{CmfHook, ContentPart};
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::http::{HttpRequest, HttpTransport, form_urlencode};
use praxis_policy_core::http_testing::FakeTransport;
use praxis_policy_core::identity::{
    HOOK_IDENTITY_RESOLVE, IdentityHook, IdentityPayload, TokenSource,
};
use praxis_policy_plugin_audit_logger::{AuditLoggerFactory, KIND as AUDIT_KIND};
use praxis_policy_test_utils::capture::{self, Events};
use praxis_policy_test_utils::fixtures::{self, CLIENT_SECRET, Fixture};
use praxis_policy_test_utils::host::{Call, RefHost, Stage};
use praxis_policy_test_utils::idp::{
    self, ACCESS_TOKEN_TYPE, CIBA_BACKCHANNEL_URL, CIBA_TOKEN_URL, Ciba, CibaPoll, Exchange,
    Persona, TOKEN_EXCHANGE_URL,
};
use praxis_policy_test_utils::secrets::Planted;
use praxis_policy_test_utils::upstream::Upstream;
use praxis_policy_test_utils::{host, mcp};
use serde_json::{Value, json};

fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// POST `form` to `url` on `transport` and parse the JSON answer.
async fn post_form(transport: &FakeTransport, url: &str, form: &[(&str, &str)]) -> (u16, Value) {
    let resp = transport
        .execute(HttpRequest::post(url, form_urlencode(form)))
        .await
        .expect("a responder answers");
    let body = serde_json::from_slice(&resp.body).expect("JSON body");
    (resp.status, body)
}

const JWT_CONFIG: &str = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.test/realms/policy-demo"
          audiences: ["praxis-gateway"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.test/realms/policy-demo/protocol/openid-connect/certs"
      claim_mapper: standard
  - name: jwt-client
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      role: client
      header: Authorization
      trusted_issuers:
        - issuer: "https://idp.test/realms/policy-demo"
          audiences: ["praxis-gateway"]
          algorithms: ["RS256"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.test/realms/policy-demo/protocol/openid-connect/certs"
      claim_mapper: standard
"#;

#[tokio::test]
async fn persona_tokens_verify_against_the_published_jwks() {
    let transport =
        Arc::new(FakeTransport::new().json(idp::JWKS_URL, 200, &idp::jwks().to_string()));
    let engine = host::engine(Vec::new());
    let shared: Arc<dyn HttpTransport> = transport.clone();
    engine.set_http_transport(shared);
    engine.load_config_yaml(JWT_CONFIG).expect("load");
    engine
        .initialize()
        .await
        .expect("initialize fetches the JWKS");

    let client = format!("Bearer {}", Persona::HrCopilot.token());
    let minted = idp::claims_of(&Persona::Bob.token()).expect("a JWT");
    assert_eq!(
        (&minted["iss"], &minted["aud"]),
        (&json!(idp::ISSUER), &json!(idp::GATEWAY_AUDIENCE))
    );
    // `sign` is the path a test crafting its own claims takes.
    let user = idp::sign(&Persona::Bob.claims());
    let payload =
        IdentityPayload::new(String::new(), TokenSource::Bearer).with_headers(headers(&[
            ("x-user-token", &user),
            ("authorization", &client),
        ]));
    let (result, _bg) = engine
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    assert!(result.continue_processing, "denied: {:?}", result.violation);

    let identity = IdentityPayload::from_pipeline_result(&result).expect("resolved identity");
    let subject = identity.subject.expect("a user subject");
    assert_eq!(subject.id.as_deref(), Some(Persona::Bob.sub()));
    assert_eq!(
        subject.claims.get("preferred_username"),
        Some(&json!(Persona::Bob.username()))
    );
    assert!(subject.roles.contains("hr"), "roles: {:?}", subject.roles);
    assert!(
        subject.permissions.contains("view_ssn"),
        "perms: {:?}",
        subject.permissions
    );
    assert!(subject.teams.contains("hr"), "teams: {:?}", subject.teams);
    assert_eq!(
        subject.claims.get("manager"),
        Some(&json!("alice")),
        "CIBA reads the manager claim as the login_hint"
    );
    assert_eq!(identity.client.expect("a client").client_id, "hr-copilot");
}

#[tokio::test]
async fn token_exchange_mints_from_the_request_form() {
    let subject_token = Persona::Bob.token();
    let form = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", subject_token.as_str()),
        ("audience", "workday-api"),
        ("scope", "read_compensation"),
    ];

    let cases = [
        (
            Exchange::Honest,
            "workday-api",
            Persona::Bob.sub(),
            "read_compensation",
            ACCESS_TOKEN_TYPE,
        ),
        (
            Exchange::BroaderScope,
            "workday-api",
            Persona::Bob.sub(),
            "read_compensation admin",
            ACCESS_TOKEN_TYPE,
        ),
        (
            Exchange::DifferentSubject,
            "workday-api",
            Persona::Eve.sub(),
            "read_compensation",
            ACCESS_TOKEN_TYPE,
        ),
        (
            Exchange::UnexpectedTokenType,
            "workday-api",
            Persona::Bob.sub(),
            "read_compensation",
            "urn:ietf:params:oauth:token-type:id_token",
        ),
        (
            Exchange::WrongAudience,
            "not-workday-api",
            Persona::Bob.sub(),
            "read_compensation",
            ACCESS_TOKEN_TYPE,
        ),
    ];
    for (mode, aud, sub, scope, issued) in cases {
        let transport = mode.install(FakeTransport::new());
        let (status, body) = post_form(&transport, TOKEN_EXCHANGE_URL, &form).await;
        assert_eq!(status, 200, "{mode:?}: {body}");
        assert_eq!(body["issued_token_type"], issued, "{mode:?}");
        assert_eq!(body["scope"], scope, "{mode:?}");
        let claims = idp::claims_of(body["access_token"].as_str().expect("a token"))
            .expect("the minted token is a JWT");
        assert_eq!(claims["aud"], aud, "{mode:?}");
        assert_eq!(claims["sub"], sub, "{mode:?}");
        assert_eq!(claims["preferred_username"], "bob", "{mode:?}");
    }

    let transport = Exchange::Honest.install(FakeTransport::new());
    let (status, body) = post_form(
        &transport,
        TOKEN_EXCHANGE_URL,
        &[("audience", "workday-api")],
    )
    .await;
    assert_eq!((status, &body["error"]), (400, &json!("invalid_request")));
}

#[tokio::test]
async fn ciba_answers_pending_then_approved_then_each_terminal_state() {
    let ciba = Ciba::new();
    let transport = ciba.install(FakeTransport::new());

    let (status, ack) =
        post_form(&transport, CIBA_BACKCHANNEL_URL, &[("login_hint", "alice")]).await;
    assert_eq!(status, 200, "{ack}");
    let id = ack["auth_req_id"]
        .as_str()
        .expect("an auth_req_id")
        .to_owned();
    assert_eq!(ciba.auth_req_ids(), vec![id.clone()]);

    let poll = [
        ("grant_type", "urn:openid:params:grant-type:ciba"),
        ("auth_req_id", id.as_str()),
    ];
    let (status, body) = post_form(&transport, CIBA_TOKEN_URL, &poll).await;
    assert_eq!(
        (status, &body["error"]),
        (400, &json!("authorization_pending"))
    );

    ciba.set(CibaPoll::Approved {
        approver: "alice".to_owned(),
    });
    let (status, body) = post_form(&transport, CIBA_TOKEN_URL, &poll).await;
    assert_eq!(status, 200, "{body}");
    let claims = idp::claims_of(body["id_token"].as_str().expect("an id_token")).expect("a JWT");
    assert_eq!(claims["preferred_username"], "alice");

    for (state, code) in [
        (CibaPoll::Denied, "access_denied"),
        (CibaPoll::Expired, "expired_token"),
    ] {
        ciba.set(state);
        let (status, body) = post_form(&transport, CIBA_TOKEN_URL, &poll).await;
        assert_eq!((status, &body["error"]), (400, &json!(code)));
    }
}

/// An engine running the audit-logger reference plugin on tool calls,
/// emitting through `tracing` with `source` as a per-test marker.
async fn audit_engine(source: &str) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    engine.register_factory(AUDIT_KIND, Box::new(AuditLoggerFactory));
    engine
        .load_config_yaml(&format!(
            "
engine_settings:
  dispatch: hooks
plugins:
  - name: audit-log
    kind: audit/logger
    hooks: [cmf.tool_pre_invoke]
    on_error: ignore
    capabilities: [read_subject, read_meta]
    config:
      destination: tracing
      source: {source}
"
        ))
        .expect("load");
    engine.initialize().await.expect("initialize");
    engine
}

async fn audited_call(engine: &PolicyEngine, arguments: Value) {
    let ext = mcp::tool_extensions(
        Extensions::default(),
        "send_email",
        &headers(&[("X-Session-Id", "s-1")]),
        Some("s-1"),
    );
    let (result, _bg) = engine
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            mcp::tool_call("call-1", "send_email", &arguments),
            ext,
            None,
        )
        .await;
    assert!(result.continue_processing, "auditing never blocks");
}

/// The audit records `events` holds, asserting they all carry `source`.
fn sources_of(events: &Events) -> Vec<String> {
    events
        .audit_records()
        .iter()
        .map(|r| r["source"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[tokio::test]
async fn audit_from_a_spawned_plugin_task_is_captured_on_a_current_thread_runtime() {
    let (events, _guard) = capture::capturing();
    let engine = audit_engine("current-thread").await;
    audited_call(&engine, json!({ "to": "partner@example.com" })).await;

    let records = events.audit_records();
    assert_eq!(records.len(), 1, "logs: {:#?}", events.logs());
    assert_eq!(records[0]["source"], "current-thread");
    assert_eq!(records[0]["entity"]["name"], "send_email");
    assert_eq!(records[0]["tool_call"]["args"]["to"], "partner@example.com");
}

#[test]
fn audit_from_a_spawned_plugin_task_is_captured_on_a_multi_thread_runtime() {
    let runtime = capture::multi_thread(2);
    runtime.block_on(async {
        let engine = audit_engine("multi-thread").await;
        audited_call(&engine, json!({ "to": "partner@example.com" })).await;
    });
    assert_eq!(sources_of(runtime.events()), vec!["multi-thread"]);
}

/// Four captures at once, two per runtime flavor, each overlapping the
/// others' invokes. Every one sees exactly its own record.
#[test]
fn parallel_captures_each_see_only_their_own_records() {
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let marker = format!("parallel-{i}");
                let body = async {
                    let engine = audit_engine(&marker).await;
                    barrier.wait();
                    audited_call(&engine, json!({ "to": marker })).await;
                };
                let events = if i % 2 == 0 {
                    let (events, _guard) = capture::capturing();
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("runtime")
                        .block_on(body);
                    events
                } else {
                    let runtime = capture::multi_thread(2);
                    runtime.block_on(body);
                    runtime.events().clone()
                };
                (marker, sources_of(&events))
            })
        })
        .collect();
    for thread in threads {
        let (marker, sources) = thread.join().expect("capture thread");
        assert_eq!(sources, vec![marker]);
    }
}

#[tokio::test]
async fn the_leak_assertion_fails_when_a_planted_secret_reaches_an_audit_record() {
    let token = Persona::Bob.token();
    let mut planted = Planted::new();
    planted.plant("bob user token", token.clone());
    planted.plant("ssn", "123-45-6789");

    let (events, _guard) = capture::capturing();
    let engine = audit_engine("leak").await;
    audited_call(&engine, json!({ "to": "partner@example.com" })).await;
    planted.assert_absent_events(&events);

    audited_call(&engine, json!({ "body": format!("token {token}") })).await;
    let panic =
        std::panic::catch_unwind(AssertUnwindSafe(|| planted.assert_absent_events(&events)))
            .expect_err("the planted token is in an audit record");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        message.contains("bob user token"),
        "names the label: {message}"
    );
    assert!(!message.contains(&token), "never prints the secret");

    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
        planted.assert_absent_json("a response", &json!({ "record": { "ssn": "123-45-6789" } }));
    }))
    .expect_err("nested JSON strings are searched");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("ssn"), "{message}");
}

#[test]
fn the_upstream_records_calls_and_decodes_bearer_claims() {
    let upstream = Upstream::new().with_result("send_email", json!({ "content": [] }));
    let bearer = format!("Bearer {}", Persona::Bob.token());
    let response = upstream.call(
        &mcp::tool_call_body(
            7,
            "get_compensation",
            &json!({ "employee_id": "EMP-001234", "include_ssn": true }),
        ),
        &headers(&[("Authorization", &bearer)]),
    );
    assert_eq!(response["id"], 7);
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("a text part");
    let record: Value = serde_json::from_str(text).expect("the text part is the record");
    assert_eq!(record["ssn"], "123-45-6789");
    assert_eq!(record["salary"], 125_000);

    let overridden = upstream.call(
        &mcp::tool_call_body(8, "send_email", &json!({})),
        &headers(&[]),
    );
    assert_eq!(overridden["result"], json!({ "content": [] }));
    let unknown = upstream.call(&mcp::tool_call_body(9, "rm_rf", &json!({})), &headers(&[]));
    assert_eq!(unknown["error"]["code"], -32601);

    let seen = upstream.requests();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].tool, "get_compensation");
    assert_eq!(seen[0].arguments["include_ssn"], true);
    let claims = seen[0]
        .jwt_claims("authorization")
        .expect("a decoded bearer");
    assert_eq!(claims["sub"], Persona::Bob.sub());
    assert!(seen[1].jwt_claims("authorization").is_none());
}

#[test]
fn mcp_builders_match_the_filter_shapes() {
    let ext = mcp::tool_extensions(
        Extensions::default(),
        "get_compensation",
        &headers(&[("X-Session-Id", "s-9")]),
        Some("s-9"),
    );
    let meta = ext.meta.as_deref().expect("meta");
    assert_eq!(meta.entity_type.as_deref(), Some("tool"));
    assert_eq!(meta.entity_name.as_deref(), Some("get_compensation"));
    let http = ext.http.as_deref().expect("http");
    assert_eq!(
        http.request_headers.get("x-session-id").map(String::as_str),
        Some("s-9")
    );
    let session = ext.agent.as_deref().and_then(|a| a.session_id.as_deref());
    assert_eq!(session, Some("s-9"));

    let call = mcp::tool_call("c-1", "get_compensation", &json!({ "employee_id": "E" }));
    let ContentPart::ToolCall { content } = &call.message.content[0] else {
        panic!("a tool call part");
    };
    assert_eq!(content.arguments.get("employee_id"), Some(&json!("E")));

    let result = mcp::tool_result("c-1", "get_compensation", json!({ "ssn": "x" }), false);
    let ContentPart::ToolResult { content } = &result.message.content[0] else {
        panic!("a tool result part");
    };
    assert_eq!(content.content["ssn"], "x");
}

// -----------------------------------------------------------------------------
// The reference host
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// The reference host
// -----------------------------------------------------------------------------

/// The Jane Smith record, which `server.py` answers with an SSN when asked.
fn jane_with_ssn() -> Value {
    json!({ "employee_id": "EMP-001234", "include_ssn": true })
}

#[tokio::test]
async fn every_fixture_loads_and_initializes() {
    for fixture in Fixture::ALL {
        let host = RefHost::hermetic(fixture).await;
        assert!(
            host.transport().call_count_for(idp::JWKS_URL) >= 1,
            "{}: initialize fetches the JWKS",
            fixture.name()
        );
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{}: nothing delegates before a call",
            fixture.name()
        );
    }
}

#[tokio::test]
async fn a_call_without_tokens_is_denied_at_the_identity_gate() {
    for fixture in Fixture::ALL {
        let host = RefHost::hermetic(fixture).await;
        let out = host.call(Call::anonymous("get_compensation")).await;
        let pdp = fixture.name();
        assert_eq!(out.denied_at, Some(Stage::Identity), "{pdp}");
        assert_eq!(out.violation_code(), Some("auth.malformed_header"), "{pdp}");
        assert!(
            out.events.audit_records().is_empty(),
            "{pdp}: no CMF hook ran, so the audit plugin did not"
        );
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{pdp}"
        );
        assert!(out.upstream.is_none(), "{pdp}");
        assert!(host.upstream().requests().is_empty(), "{pdp}");
    }
}

#[tokio::test]
async fn an_allowed_call_reaches_the_upstream_with_a_delegated_token() {
    for fixture in Fixture::ALL {
        let pdp = fixture.name();
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "get_compensation")
            .args(jane_with_ssn())
            .session("s-1");
        let mut planted = call.planted();
        planted.plant("client secret", CLIENT_SECRET);
        let out = host.call(call).await;
        assert!(out.allowed(), "{pdp}: {:?}", out.violation);

        let seen = out.upstream.as_ref().expect("the upstream was called");
        let bearer = seen
            .jwt_claims("authorization")
            .expect("a delegated bearer");
        assert_eq!(bearer["aud"], "workday-api", "{pdp}");
        assert_eq!(bearer["sub"], Persona::Bob.sub(), "{pdp}");
        assert_eq!(bearer["scope"], "read_compensation", "{pdp}");
        assert!(
            !seen.headers.contains_key("x-user-token"),
            "{pdp}: assertions strip the user's own token: {:?}",
            seen.headers.keys()
        );
        assert_eq!(
            seen.headers.get("x-auth-user-id").map(String::as_str),
            Some(Persona::Bob.sub()),
            "{pdp}"
        );
        assert_eq!(seen.arguments["include_ssn"], true, "{pdp}");
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            1,
            "{pdp}: the delegator caches nothing by default"
        );

        let record = out.record().expect("the tool's record");
        assert_eq!(record["ssn"], "123-45-6789", "{pdp}: Bob holds view_ssn");
        let audit = out.events.audit_records();
        assert_eq!(audit.len(), 1, "{pdp}");
        assert_eq!(
            audit[0]["delegated_tokens"][0]["audience"], "workday-api",
            "{pdp}"
        );

        let minted = seen.headers["authorization"].trim_start_matches("Bearer ");
        planted.plant("minted workday token", minted);
        out.assert_no_leaks(&planted);
    }
}

#[tokio::test]
async fn the_pdp_step_denies_with_the_fixture_violation() {
    for fixture in Fixture::ALL {
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Alice, "search_repos")
            .args(json!({ "repo_name": "partner-sdk", "visibility": "external" }));
        let planted = call.planted();
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request), "{}", fixture.name());
        assert_eq!(out.violation_code(), Some(fixture.deny_violation()));
        assert_eq!(host.transport().call_count_for(TOKEN_EXCHANGE_URL), 0);
        assert!(host.upstream().requests().is_empty());
        out.assert_no_leaks(&planted);
    }
}

/// No route names the tool and `dispatch: policy` has no catch-all, so the
/// call passes on identity alone. Nothing delegates, so the agent's own
/// bearer reaches the upstream, while assertions still strip the user token
/// and assert the subject.
#[tokio::test]
async fn an_unknown_tool_passes_on_identity_with_the_global_assertions() {
    for fixture in Fixture::ALL {
        let pdp = fixture.name();
        let host = RefHost::hermetic(fixture).await;
        let call = Call::new(Persona::Bob, "delete_records").args(json!({ "all": true }));
        let planted = call.planted();
        let out = host.call(call).await;
        assert!(out.allowed(), "{pdp}: {:?}", out.violation);
        let seen = out.upstream.as_ref().expect("the upstream was called");
        assert_eq!(seen.tool, "delete_records", "{pdp}");
        let bearer = seen.jwt_claims("authorization").expect("a bearer");
        assert_eq!(
            bearer["azp"], "hr-copilot",
            "{pdp}: the inbound agent token"
        );
        assert!(!seen.headers.contains_key("x-user-token"), "{pdp}");
        assert_eq!(
            seen.headers.get("x-auth-username").map(String::as_str),
            Some("bob"),
            "{pdp}"
        );
        assert_eq!(
            host.transport().call_count_for(TOKEN_EXCHANGE_URL),
            0,
            "{pdp}"
        );
        assert!(
            out.events.audit_records().is_empty(),
            "{pdp}: no route runs audit-log"
        );
        assert_eq!(
            out.response.as_ref().map(|r| r["error"]["code"].clone()),
            Some(json!(-32601)),
            "{pdp}: the upstream's own answer"
        );
        out.assert_no_leaks(&planted);
    }
}

#[tokio::test]
async fn a_pending_elicitation_carries_its_protocol_code_and_details() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let adjust = || {
        Call::new(Persona::Bob, "adjust_compensation")
            .args(json!({ "employee_id": "EMP-001234", "amount": 25_000 }))
    };
    let call = adjust();
    let mut planted = call.planted();
    planted.plant("client secret", CLIENT_SECRET);
    let out = host.call(call).await;
    assert_eq!(out.denied_at, Some(Stage::Request));
    assert_eq!(out.violation_code(), Some("elicitation.pending"));
    assert_eq!(out.proto_error_code(), Some(-32_120));
    assert_eq!(out.detail("approver"), Some(&json!("alice")));
    assert_eq!(out.detail("channel"), Some(&json!("ciba")));
    let id = out
        .detail("elicitation_id")
        .and_then(Value::as_str)
        .expect("an elicitation id")
        .to_owned();
    assert_eq!(
        host.ciba().auth_req_ids(),
        vec![id.clone()],
        "the CIBA auth_req_id is the elicitation id the caller echoes"
    );
    out.assert_no_leaks(&planted);

    let peek = host.call(adjust().elicitation_id(&id).peek()).await;
    assert_eq!(peek.violation_code(), Some("elicitation.pending"));
    assert!(host.upstream().requests().is_empty());
}

#[tokio::test]
async fn a_secret_assertion_reaches_only_the_upstream_in_clear() {
    const KEY: &str = "sk-hr-mcp-0f9e8d7c";
    let host = RefHost::builder()
        .transport(fixtures::vault(FakeTransport::new(), KEY))
        .start(fixtures::SECRET_HEADER)
        .await
        .expect("the secret fixture starts");
    let call = Call::new(Persona::Bob, "get_directory").args(json!({ "department": "hr" }));
    let mut planted = call.planted();
    planted.plant("vault-sourced api key", KEY);
    planted.plant("vault client token", "hvs.ppe-tests");
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);

    let seen = out.upstream.as_ref().expect("the upstream was called");
    assert_eq!(seen.headers.get("x-api-key").map(String::as_str), Some(KEY));
    assert!(!seen.headers.contains_key("x-user-token"));

    let marker = format!("<redacted secret.{}>", fixtures::SECRET_NAME);
    let views = host.header_views();
    let hooks: Vec<&str> = views.iter().map(|(hook, _)| hook.as_str()).collect();
    assert_eq!(hooks, ["cmf.tool_pre_invoke", "cmf.tool_post_invoke"]);
    assert!(
        !views[0].1.contains_key("x-api-key"),
        "a pre-invoke plugin runs before the contract renders: {:?}",
        views[0].1
    );
    assert_eq!(
        views[1].1.get("x-api-key"),
        Some(&marker),
        "a later hook sees the marker, not the value"
    );
    // A plugin holding read_headers sees the caller's own tokens, by design.
    let mut key_only = Planted::new();
    key_only.plant("vault-sourced api key", KEY);
    for (hook, headers) in &views {
        key_only.assert_absent_json(hook, &json!(headers));
    }
    assert_eq!(out.events.audit_records().len(), 1);
    out.assert_no_leaks(&planted);
}

/// A session store that cannot be reached, standing in for an outage.
struct Unreachable;

impl SessionStoreFactory for Unreachable {
    fn kind(&self) -> &str {
        "test/unreachable"
    }

    fn build(
        &self,
        _config: &serde_yaml::Value,
    ) -> Result<Arc<dyn SessionStore>, Box<dyn std::error::Error + Send + Sync>> {
        Err("session store unreachable".into())
    }
}

#[tokio::test]
async fn a_builder_session_store_is_selectable_by_kind() {
    let yaml = Fixture::Cedar.hermetic().replacen(
        "\nroutes:",
        "\n  session_store:\n    kind: test/unreachable\n\nroutes:",
        1,
    );
    let err = RefHost::builder()
        .session_store(Arc::new(Unreachable))
        .start(&yaml)
        .await
        .expect_err("the store fails to build");
    assert!(err.to_string().contains("unreachable"), "{err}");
}
