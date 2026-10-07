// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The shared harness does what the suites rely on it to do.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Barrier};

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
use praxis_policy_test_utils::idp::{
    self, ACCESS_TOKEN_TYPE, CIBA_BACKCHANNEL_URL, CIBA_TOKEN_URL, Ciba, CibaPoll, Exchange,
    Persona, TOKEN_EXCHANGE_URL,
};
use praxis_policy_test_utils::secrets::Planted;
use praxis_policy_test_utils::upstream::Upstream;
use praxis_policy_test_utils::{builtin_engine, mcp};
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
    let engine = builtin_engine();
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
