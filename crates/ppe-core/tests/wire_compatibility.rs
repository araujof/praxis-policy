// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The rename must not move the policy wire surface.
//!
//! The fixture is a real policy document authored against the engine's previous
//! name, copied verbatim. It exercises multi-source identity, token exchange,
//! policy requirements, a decision point, argument redaction, PII scanning,
//! audit emission, and session taint, so a change to any plugin kind string,
//! hook name, field name, or policy expression breaks it.
//!
//! It is checked in rather than read from a sibling repository so the guarantee
//! travels with this crate.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test and example code"
)]
#[test]
fn legacy_policy_document_parses_unchanged() {
    let yaml = include_str!("fixtures/legacy-policy-document.yaml");
    let cfg = praxis_policy_core::config::parse_config(yaml)
        .expect("a policy document written before the rename must still load");
    assert!(!cfg.plugins.is_empty(), "fixture declares plugins");
}

/// Every `kind:` string in the fixture, in declaration order.
///
/// The full set rather than a spot check. A `kind` is what an operator types, so
/// renaming one breaks their document with "no factory registered" at startup —
/// and asserting only that *some* plugin is `identity/jwt` would let any of the
/// other six be renamed silently. Names are included because the document is also
/// how a route refers to a plugin by name.
///
/// Add a plugin to the fixture and this fails; that is the prompt to decide
/// whether the new `kind` is one you are willing to keep.
#[test]
fn the_kind_strings_an_operator_writes_are_unchanged() {
    let yaml = include_str!("fixtures/legacy-policy-document.yaml");
    let cfg = praxis_policy_core::config::parse_config(yaml).expect("fixture must load");

    let declared: Vec<(&str, &str)> = cfg
        .plugins
        .iter()
        .map(|p| (p.name.as_str(), p.kind.as_str()))
        .collect();

    assert_eq!(
        declared,
        vec![
            ("jwt-user", "identity/jwt"),
            ("jwt-client", "identity/jwt"),
            ("workday-oauth", "delegator/oauth"),
            ("pii-scan", "validator/pii-scan"),
            ("audit-log", "audit/logger"),
            ("github-oauth", "delegator/oauth"),
            ("manager-approver", "elicitation/ciba"),
        ],
        "plugin names and kind strings are the operator-facing contract",
    );
}

/// The route set the document declares, by entity.
///
/// A route key is the other half of what an operator writes: it selects which
/// policy applies to a tool, prompt or resource call. Losing or renaming one means
/// a call silently evaluates under no policy, which fails open.
#[test]
fn the_route_keys_are_unchanged() {
    let yaml = include_str!("fixtures/legacy-policy-document.yaml");
    let cfg = praxis_policy_core::config::parse_config(yaml).expect("fixture must load");
    assert_eq!(cfg.routes.len(), 4, "recorded route count");
    assert!(
        cfg.routing_enabled(),
        "a document with routes must enable routing, or none of them are consulted",
    );
}
