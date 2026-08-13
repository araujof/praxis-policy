// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// praxis-policy-apl-runtime — bridge between APL evaluator (`praxis-policy-apl-core`) and PPE runtime
// (`praxis-policy-core`).
//
// `praxis-policy-apl-core::PluginInvoker` is string-typed by design (so `praxis-policy-apl-core`
// stays free of PPE deps). The actual typed boundary lives in this
// crate: one `PluginInvoker` implementation per `HookTypeDef`. The
// payload type is locked at the impl level — e.g. [`CmfPluginInvoker`]
// can only dispatch to CMF hooks because every internal call goes
// through `invoke_named::<CmfHook>`, and the compiler enforces that
// the payload is `MessagePayload`.
//
// # v0 simplification — single-view-per-Message
//
// CMF distinguishes two messaging patterns:
//   - LLM wire format — bundled multi-part Messages (thinking + text +
//     tool_call(s)) — many MessageViews per Message.
//   - Framework/protocol format (MCP, A2A, LangGraph) — single
//     ContentPart per Message — one view per Message.
//
// v0 only handles request-side flows (outbound LLM call from the user,
// outbound MCP tools/call from the agent). Both are single-part, so the
// route → MessageView matching collapses to "one route fires per
// Message." When response-side handling lands, this assumption breaks
// and praxis-policy-apl-core's route-matching layer needs to switch from
// routes-as-map to routes-as-list with a `match:` block filtering on
// MessageView attributes. See the APL implementation memory's
// "list-with-matchers" deferred item.

//! Connects the APL evaluator to the plugin runtime.
//!
//! The evaluator's invoker traits are string-typed so the language crate stays
//! free of runtime dependencies. The typed boundary lives here: one invoker per
//! hook type, with the payload locked at the impl so the compiler rejects a
//! mismatched dispatch.

/// Loads external attribute trees for the evaluator.
pub mod attribute_source;
/// Applies a route's backend candidate constraint.
pub mod candidate_constraint;
/// Dispatches plugin steps to CMF hooks.
pub mod cmf_invoker;
/// Dispatches delegation steps to the delegation hook.
pub mod delegation_invoker;
/// The per-request plan of which handlers run in which phase.
pub mod dispatch_plan;
/// Dispatches elicitation steps to the elicitation hook.
pub mod elicitation_invoker;
/// Folds a plugin's payload edits back into the request.
mod message_projection;
/// Rejects plugins whose mode is unsafe inside a `parallel:` block.
pub mod parallel_safety;
/// Routes a decision point call to the resolver for its dialect.
pub mod pdp_router;
/// Wires the runtime into a plugin manager.
pub mod register;
/// Runs a compiled route for one hook invocation.
pub mod route_handler;
/// Resolves the session identity a taint label attaches to.
pub mod session_resolver;
/// The session store trait and its in-memory default.
pub mod session_store;
/// Compiles route blocks at config load time.
pub mod visitor;

pub use attribute_source::{FileAttributeSource, merge_attribute_docs};
pub use candidate_constraint::{ConstraintConflict, fold_candidate_constraints};
pub use cmf_invoker::CmfPluginInvoker;
pub use delegation_invoker::DelegationPluginInvoker;
pub use dispatch_plan::{DispatchCache, RouteDispatchPlan, RoutePluginEntry};
pub use elicitation_invoker::ElicitationPluginInvoker;
pub use pdp_router::PdpRouter;
pub use register::{AplOptions, register_apl};
pub use route_handler::{
    AplRouteHandler, ELICITATION_APPROVED_CODE, ELICITATION_ID_HEADER, ELICITATION_PEEK_HEADER,
    ELICITATION_PENDING_CODE, Phase,
};
pub use session_store::{MemorySessionStore, SessionStore, SessionStoreError, SessionStoreFactory};
pub use visitor::AplConfigVisitor;
