// Location: ./crates/ppe-apl-core/src/pipeline.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Pipe-chain IR for APL `args:` and `result:` phases.
//
// A field-level pipeline is a sequence of `Stage`s separated by `|` in the
// DSL. Validators (str/int/range/...) check the field's value and can fail
// the request; transforms (mask/redact/omit/hash) modify the value; effects
// (taint) record side information.
//
// Stages whose evaluator behavior is deferred (taint dispatch,
// plugin invocation, regex/named validators, scan placeholders) are still
// represented in the IR so the parser can produce them — the evaluator
// recognizes them and returns a clear "deferred" signal rather than crashing.

use serde::{Deserialize, Serialize};

use crate::rules::Expression;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The type a `str`, `int`, or similar stage asserts a field holds.
pub enum TypeCheck {
    /// A string.
    Str,
    /// An integer.
    Int,
    /// A boolean.
    Bool,
    /// A floating-point number.
    Float,
    /// A syntactically valid email address.
    Email,
    /// A syntactically valid URL.
    Url,
    /// A syntactically valid UUID.
    Uuid,
}

/// Scope at which a taint applies. Marked `#[non_exhaustive]` so new
/// variants (e.g. `Request`, `Pipeline`, conversation-level) can be
/// added without breaking downstream exhaustive matches. v0 emits only
/// `Session` and `Message`; plugin-extracted taints (from
/// `extensions.security.labels` diffs in `CmfPluginInvoker`) default to
/// `Session` because praxis-policy-core's label monotonicity is session-semantic.
/// Config-side `Step::Taint`/`Stage::Taint` declares scopes explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TaintScope {
    /// Persists for the session, so later requests see it.
    Session,
    /// Applies to this message only.
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Which scan a `scan` stage runs.
pub enum ScanKind {
    /// Find PII and replace it.
    PiiRedact,
    /// Find PII and report it without changing the value.
    PiiDetect,
    /// Look for prompt injection.
    InjectionScan,
}

/// One stage in a pipe chain.
///
/// Stages execute left-to-right against a single field value. Validators
/// halt the pipeline on failure; transforms produce a new value; effects
/// (taint) annotate without changing the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Assert the field holds the given type.
    Type(TypeCheck),
    /// `regex("pattern")` — parser captures the pattern; evaluator stubbed
    /// until we add the `regex` crate dependency.
    Regex {
        /// The pattern the value must match.
        pattern: String,
    },
    /// `validate(name)` — named validator dispatch; evaluator stubbed.
    Validate {
        /// The registered validator to run.
        name: String,
    },
    /// `len(..N)`, `len(N..M)`, `len(N..)` — string length bounds.
    Length {
        /// Inclusive lower bound, if any.
        min: Option<usize>,
        /// Inclusive upper bound, if any.
        max: Option<usize>,
    },
    /// Bare range literal `N..M`, `..M`, `N..`, with optional `k`/`K`/`m`/`M`
    /// numeric suffixes. Integer-only.
    Range {
        /// Inclusive lower bound, if any.
        min: Option<i64>,
        /// Inclusive upper bound, if any.
        max: Option<i64>,
    },
    /// `enum(a, b, c)` — value must equal one of the listed strings.
    Enum {
        /// The permitted values.
        values: Vec<String>,
    },

    /// `mask(N)` — replace all but last N chars with `*`.
    Mask {
        /// How many trailing characters survive unmasked.
        keep_last: usize,
    },
    /// `redact` (unconditional) or `redact(!condition)` (conditional).
    /// Replaces value with `[REDACTED]` when condition is true (or always,
    /// if no condition).
    Redact {
        /// Redact only when this holds. `None` redacts unconditionally.
        condition: Option<Expression>,
    },
    /// `omit` — drop the field from output entirely. No conditional form
    /// — use a policy rule for conditional omit.
    Omit,
    /// `hash` — replace value with a hash digest.
    Hash,

    /// Attach a label without changing the value.
    Taint {
        /// The label to attach.
        label: String,
        /// How far the label propagates.
        scopes: Vec<TaintScope>,
    },
    /// Hand the value to a named plugin.
    Plugin {
        /// The plugin to invoke.
        name: String,
    },
    /// Scan the value for PII or injection.
    Scan {
        /// Which scan to run.
        kind: ScanKind,
    },
}

/// Sequence of stages applied to one field's value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pipeline {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The stages, applied left to right.
    pub stages: Vec<Stage>,
}

impl Pipeline {
    /// An empty pipeline, which leaves the value untouched.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a stage.
    pub fn push(&mut self, stage: Stage) {
        self.stages.push(stage);
    }
    /// Whether the pipeline has no stages.
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }
}

/// Attaches a pipeline to a specific field name in the args or result phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    /// Dotted path to the field this applies to.
    pub field: String,
    /// The stages to apply.
    pub pipeline: Pipeline,
    /// Source location (e.g., `"get_compensation.result.ssn"`) for audit.
    pub source: String,
}

/// A taint label produced as a side effect of running a pipeline.
///
/// The evaluator accumulates these in `PipelineEvaluation.taints`; the host
/// (praxis-policy-apl-runtime) drains them and writes to the actual `SessionStore`. Same shape
/// as `Stage::Taint`'s fields, but lives at the evaluator boundary because
/// it also carries taints emitted by plugin invocations and scan stages
/// — not just literal `taint(...)` stages.
#[derive(Debug, Clone, PartialEq)]
pub struct TaintEvent {
    /// The label attached.
    pub label: String,
    /// How far it propagates.
    pub scopes: Vec<TaintScope>,
}
