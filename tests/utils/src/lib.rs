// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared harness for the integration, resilience and security suites.
//!
//! Every item is gated on the `suite` feature, so the default workspace pass
//! builds an empty crate and unifies no builtin features. A crate-level
//! `#![cfg]` would strip these docs too and trip `missing_docs`.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    reason = "test harness; a broken fixture should fail the test loudly"
)]

#[cfg(feature = "suite")]
pub mod capture;
#[cfg(feature = "suite")]
pub mod idp;
#[cfg(feature = "suite")]
pub mod mcp;
#[cfg(feature = "suite")]
pub mod secrets;
#[cfg(feature = "suite")]
pub mod upstream;

#[cfg(feature = "suite")]
use std::sync::Arc;

#[cfg(feature = "suite")]
use praxis_policy::{PolicyEngine, install_builtins};

/// A policy engine with every builtin and the APL config visitor installed.
#[cfg(feature = "suite")]
#[must_use]
pub fn builtin_engine() -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::default());
    install_builtins(&engine);
    engine
}
