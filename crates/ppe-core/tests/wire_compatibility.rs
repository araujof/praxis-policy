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
    assert!(
        cfg.plugins.iter().any(|p| p.kind == "identity/jwt"),
        "plugin kind strings are part of the wire surface and must not be renamed",
    );
}
