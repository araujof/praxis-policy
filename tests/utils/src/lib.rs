// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Shared harness for the integration, resilience and security suites.
//!
//! Every item is gated on the `suite` feature, so the default workspace pass
//! builds an empty crate and unifies no builtin features. A crate-level
//! `#![cfg]` would strip these docs too and trip `missing_docs`.

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
