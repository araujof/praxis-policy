// Location: ./crates/ppe-core/src/elicitation/mod.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Elicitation hook family — human-in-the-loop dispatch (approval,
// confirmation, step-up, attestation, …).
//
// Mirrors the delegation/ module layout: the hook marker (via the
// generic hooks layer) plus the hook-specific payload + enums. No
// executor wiring needed — dispatch is free via
// `mgr.invoke_entries::<ElicitationHook>`. The praxis-policy-apl-runtime bridge fills the
// payload and maps the result back to praxis-policy-apl-core's `ElicitationInvoker`
// return types.

/// The elicitation hook.
pub mod hook;
/// The payload carrying the prompt, its state, and the response.
pub mod payload;

pub use hook::{ElicitationHook, HOOK_ELICIT};
pub use payload::{
    ElicitationOp, ElicitationOutcomeKind, ElicitationPayload, ElicitationStatusKind,
};
