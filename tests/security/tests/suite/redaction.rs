// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! What leaves in a response, and what a session carries to its next call.
//!
//! The demo redacts `result.ssn` unless the caller holds `perm.view_ssn`.
//! Eve does not. Each case reshapes the upstream record so the SSN sits
//! somewhere that field path may not reach.

use praxis_policy_test_utils::fixtures::Fixture;
use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::Persona;
use praxis_policy_test_utils::secrets::Planted;
use serde_json::{Value, json};

use crate::support::{JANE_SSN, forwarded_bearer, planted_for};

fn jane() -> Value {
    json!({ "employee_id": "EMP-001234", "name": "Jane Smith", "ssn": JANE_SSN })
}

/// A `result` whose single text part is `record`, as `server.py` answers.
fn as_text(record: &Value) -> Value {
    json!({ "content": [{ "type": "text", "text": record.to_string() }] })
}

/// Eve reads Jane's record with the upstream answering `result`. Returns
/// the outcome after the leak check on everything but the SSN, and the SSN
/// alone for the case to check.
async fn eve_reads(result: Value) -> (Outcome, Planted) {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    host.upstream().set_result("get_compensation", result);
    let call = Call::new(Persona::Eve, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234", "include_ssn": true }));
    let mut planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    planted.plant("minted workday token", forwarded_bearer(&out));
    out.assert_no_leaks(&planted);
    let mut ssn = Planted::new();
    ssn.plant("ssn", JANE_SSN);
    (out, ssn)
}

/// The gap form of the SSN leak check: the same search, with the gap's
/// message.
fn assert_no_ssn(out: &Outcome, gap: &str) {
    let response = serde_json::to_string(&out.response).unwrap_or_default();
    assert!(
        !response.contains(JANE_SSN),
        "{gap}: Eve's response carries the SSN"
    );
}

#[tokio::test]
async fn a_top_level_ssn_is_redacted() {
    let (out, ssn) = eve_reads(as_text(&jane())).await;
    assert_eq!(out.record().expect("a record")["ssn"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

#[tokio::test]
async fn an_ssn_inside_an_array_is_redacted() {
    let (out, ssn) = eve_reads(as_text(&json!([jane(), jane()]))).await;
    let record = out.record().expect("a record");
    assert_eq!(record[0]["ssn"], "[REDACTED]");
    assert_eq!(record[1]["ssn"], "[REDACTED]");
    out.assert_no_leaks(&ssn);
}

/// Field paths match keys exactly.
#[tokio::test]
#[should_panic(expected = "known gap #181 redact-key-case")]
async fn known_gap_a_case_variant_ssn_key_is_redacted() {
    let mut record = jane();
    let value = record
        .as_object_mut()
        .and_then(|r| r.remove("ssn"))
        .expect("an ssn");
    record["SSN"] = value;
    let (out, _) = eve_reads(as_text(&record)).await;
    assert_no_ssn(&out, "known gap #181 redact-key-case");
}

/// `ssn` addresses the top level (and array elements), not a nested record.
#[tokio::test]
#[should_panic(expected = "known gap #181 redact-nested")]
async fn known_gap_a_nested_ssn_is_redacted() {
    let (out, _) = eve_reads(as_text(&json!({ "employee": jane() }))).await;
    assert_no_ssn(&out, "known gap #181 redact-nested");
}

/// Two text parts are joined into one string, as praxis does
/// (`build_response_content_for_method` in `json_rpc.rs`), so the record
/// is never parsed and no field path applies.
#[tokio::test]
#[should_panic(expected = "known gap #181 redact-stringified")]
async fn known_gap_a_stringified_record_is_redacted() {
    let result = json!({ "content": [
        { "type": "text", "text": "Record:" },
        { "type": "text", "text": jane().to_string() },
    ] });
    let (out, _) = eve_reads(result).await;
    assert_no_ssn(&out, "known gap #181 redact-stringified");
}

/// Accepted behavior. Taint is keyed by subject and `X-Session-Id`, and
/// `session` scope lasts for that session only
/// (`docs/content/apl/tainting.md`, "Setting Session Taint" and
/// "Persistence and isolation"). The session id is the caller's, so a
/// fresh one starts clean. Same-session write-down still denies.
#[tokio::test]
async fn a_fresh_session_id_starts_without_the_taint() {
    let host = RefHost::hermetic(Fixture::Cedar).await;
    let read = Call::new(Persona::Bob, "get_compensation")
        .args(json!({ "employee_id": "EMP-001234" }))
        .session("s-read");
    let mut planted = planted_for(&read);
    let out = host.call(read).await;
    assert!(out.allowed(), "{:?}", out.violation);
    planted.plant("minted workday token", forwarded_bearer(&out));
    out.assert_no_leaks(&planted);

    let email = |session: &str| {
        Call::new(Persona::Bob, "send_email")
            .args(json!({ "to": "partner@example.com", "subject": "hi", "body": "clean" }))
            .session(session)
    };
    let call = email("s-read");
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert_eq!(out.denied_at, Some(Stage::Request));
    assert_eq!(out.violation_code(), Some("session_tainted_secret"));
    out.assert_no_leaks(&planted);

    let call = email("s-fresh");
    let planted = planted_for(&call);
    let out = host.call(call).await;
    assert!(out.allowed(), "{:?}", out.violation);
    out.assert_no_leaks(&planted);
}
