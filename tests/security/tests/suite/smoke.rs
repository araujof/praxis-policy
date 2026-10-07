// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The suite links against the shared harness.

use praxis_policy_test_utils::builtin_engine;

#[test]
fn harness_builds_an_engine() {
    let engine = builtin_engine();
    assert!(
        !engine.is_initialized(),
        "a fresh engine is not initialized"
    );
}
