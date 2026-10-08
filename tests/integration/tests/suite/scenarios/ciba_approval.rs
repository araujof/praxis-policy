// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! 11: an adjustment over the $10k threshold suspends on a CIBA approval
//! from Bob's manager, then applies once she approves.
//!
//! The CIBA `auth_req_id` is the elicitation id the caller echoes, so it is
//! returned in the deny details by design and is not planted.

use praxis_policy_test_utils::host::{Call, Outcome, RefHost, Stage};
use praxis_policy_test_utils::idp::{CibaPoll, Persona};
use serde_json::{Value, json};

use super::{adjust, audit_for, each_pdp, planted, upstream_calls};

/// Rule source of the `require_approval` step a denied or failed approval
/// is attributed to.
const APPROVAL_STEP: &str = "routes.tool:adjust_compensation.pre_invocation[1]";

fn over_threshold() -> Call {
    Call::new(Persona::Bob, "adjust_compensation").args(adjust(25_000))
}

/// S1: the first call suspends. Returns the elicitation id.
async fn suspend(host: &RefHost) -> String {
    let call = over_threshold();
    let planted = planted(&call);
    let out = host.call(call).await;
    assert_pending(&out, "S1");
    assert_eq!(out.detail("approver"), Some(&json!("alice")), "S1");
    assert_eq!(upstream_calls(host), 0, "S1 reaches no upstream");
    out.assert_no_leaks(&planted);
    let id = out
        .detail("elicitation_id")
        .and_then(Value::as_str)
        .expect("an elicitation id")
        .to_owned();
    assert_eq!(host.ciba().auth_req_ids(), vec![id.clone()], "S1");
    id
}

fn assert_pending(out: &Outcome, step: &str) {
    assert_eq!(out.denied_at, Some(Stage::Request), "{step}");
    assert_eq!(out.violation_code(), Some("elicitation.pending"), "{step}");
    assert_eq!(out.proto_error_code(), Some(-32_120), "{step}");
}

#[tokio::test]
async fn a_large_adjustment_applies_after_manager_approval() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let id = suspend(&host).await;

        let call = over_threshold().elicitation_id(&id).peek();
        let planted_peek = planted(&call);
        let peek = host.call(call).await;
        assert_pending(&peek, "S3 before approval");
        assert_eq!(peek.detail("elicitation_id"), Some(&json!(id)));
        peek.assert_no_leaks(&planted_peek);

        host.ciba().set(CibaPoll::Approved {
            approver: "alice".to_owned(),
        });
        let call = over_threshold().elicitation_id(&id).peek();
        let planted_peek = planted(&call);
        let peek = host.call(call).await;
        assert_eq!(peek.denied_at, Some(Stage::Request), "S3");
        assert_eq!(peek.violation_code(), Some("elicitation.approved"), "S3");
        assert_eq!(peek.proto_error_code(), Some(-32_121), "S3");
        assert_eq!(peek.detail("elicitation_id"), Some(&json!(id)), "S3");
        assert_eq!(peek.detail("approver"), Some(&json!("alice")), "S3");
        assert_eq!(upstream_calls(&host), 0, "a peek does not apply");
        peek.assert_no_leaks(&planted_peek);

        let call = over_threshold().elicitation_id(&id);
        let planted_apply = planted(&call);
        let out = host.call(call).await;
        assert!(out.allowed(), "S4: {:?}", out.violation);
        assert_eq!(upstream_calls(&host), 1, "S4");
        assert_eq!(out.record().expect("a record")["status"], "applied");
        assert_eq!(audit_for(&out, "adjust_compensation").len(), 1, "S4");
        out.assert_no_leaks(&planted_apply);
    })
    .await;
}

#[tokio::test]
async fn a_denied_approval_denies_the_adjustment() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let id = suspend(&host).await;
        host.ciba().set(CibaPoll::Denied);
        let call = over_threshold().elicitation_id(&id);
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert_eq!(out.violation_code(), Some(APPROVAL_STEP));
        let reason = out.violation.as_ref().map(|v| v.reason.as_str());
        assert_eq!(reason, Some("elicitation denied by approver"));
        assert_eq!(out.proto_error_code(), None, "a deny, not a retry signal");
        assert_eq!(upstream_calls(&host), 0);
        out.assert_no_leaks(&planted);
    })
    .await;
}

#[tokio::test]
async fn an_expired_approval_denies_the_adjustment() {
    each_pdp(|fixture| async move {
        let host = RefHost::hermetic(fixture).await;
        let id = suspend(&host).await;
        host.ciba().set(CibaPoll::Expired);
        let call = over_threshold().elicitation_id(&id);
        let planted = planted(&call);
        let out = host.call(call).await;
        assert_eq!(out.denied_at, Some(Stage::Request));
        assert_eq!(out.violation_code(), Some(APPROVAL_STEP));
        assert_eq!(out.proto_error_code(), None, "a deny, not a retry signal");
        assert_eq!(upstream_calls(&host), 0, "not applied");
        out.assert_no_leaks(&planted);
    })
    .await;
}
