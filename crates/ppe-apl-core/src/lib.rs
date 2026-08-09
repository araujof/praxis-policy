// Location: ./crates/ppe-apl-core/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// APL core — Authorization Policy Language compiler + evaluator.
//
// This crate is the language nucleus. It does not depend on PPE directly;
// the bridge from praxis-policy-core extensions into the AttributeBag lives in
// `praxis-policy-apl-cmf`, and the `PolicyEvaluator` implementation lives in `praxis-policy-apl-runtime`.

#![doc = "APL — Authorization Policy Language."]

pub mod attribute_source;
pub mod attributes;
pub mod constraint;
pub mod evaluator;
pub mod parser;
pub mod pipeline;
pub mod plugin_decl;
pub mod route;
pub mod rules;
pub mod step;

pub use attribute_source::{AttributeError, AttributeSource, AttributeTree};
pub use attributes::{AttributeBag, AttributeExtractor, AttributeValue};
pub use evaluator::{
    Decision, FieldOutcome, PipelineEvaluation, evaluate_effects, evaluate_pipeline, evaluate_rules,
};
pub use parser::{
    CompiledConfig, ConfigYaml, ParseError, RouteYaml, compile_config, compile_policy_block_value,
    parse_pipeline, parse_predicate, parse_rule,
};
pub use pipeline::{FieldRule, Pipeline, ScanKind, Stage, TaintEvent, TaintScope, TypeCheck};
pub use plugin_decl::{
    CapsView, EffectivePlugin, PluginDeclaration, PluginOverride, PluginRegistry,
};
pub use route::{
    RouteDecision, RoutePayload, evaluate_post, evaluate_pre, evaluate_route, get_dotted,
};
pub use rules::{
    CompareOp, CompiledRoute, Condition, DenyResponse, Effect, Expression, Literal, Phase,
    PhaseSet, Rule,
};
pub use step::{
    AutoApprovingElicitor, DelegateStep, DelegationError, DelegationInvoker, DelegationOutcome,
    DispatchPhase, ElicitKind, ElicitStep, ElicitationDispatch, ElicitationError,
    ElicitationInvoker, ElicitationOutcome, ElicitationStatus, ElicitationValidation,
    NoopDelegationInvoker, NoopElicitationInvoker, PdpCall, PdpDecision, PdpDialect, PdpError,
    PdpFactory, PdpResolver, PendingElicitation, PluginError, PluginInvocation, PluginInvoker,
    PluginOutcome, delegation_bag_keys, elicitation_bag_keys,
};
