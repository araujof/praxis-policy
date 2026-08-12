// Location: ./crates/ppe/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

//! **PPE is a policy enforcement runtime for AI agents.**
//!
//! It is a deterministic reference monitor between an agent and every
//! capability it invokes: tools, prompts, resources, inference providers, and
//! A2A methods. Each operation runs through a policy-defined pipeline that can
//! resolve identity, make an authorization decision (delegated to an engine
//! like Cedar or CEL), exchange and reduce credentials before a downstream
//! call, redact inputs and outputs, track information flow across calls, and
//! audit. You write that policy declaratively in APL, the configuration that
//! defines each operation's pipeline; PPE evaluates and enforces it at the
//! boundary, against state the model cannot observe or forge.
//!
//! - Source and issues: <https://github.com/praxis-proxy/policy>
//!
//! # This crate
//!
//! `praxis-policy` is the **host facade**: one dependency that re-exports the PPE
//! runtime (`praxis-policy-core`, `praxis-policy-apl-core`, `praxis-policy-apl-cmf`, `praxis-policy-apl-runtime`), so a host depends
//! on this crate instead of pinning each of them separately.
//!
//! By default it is the **engine only**: no builtin plugins are compiled in.
//! The bundled extension set lives in `praxis-policy-builtins` and is
//! pulled in only when a builtins feature is enabled.
//!
//! # Usage
//!
//! Engine only (register your own factories):
//!
//! ```no_run
//! use std::sync::Arc;
//! use praxis_policy::PluginManager;
//!
//! let mgr = Arc::new(PluginManager::default());
//! // ... register host factories, then `praxis_policy_apl_runtime::register_apl(&mgr, opts)`.
//! ```
//!
//! With the bundled builtins (enable the `builtins` feature):
//!
//! ```ignore
//! use std::sync::Arc;
//! use praxis_policy::PluginManager;
//!
//! let mgr = Arc::new(PluginManager::default());
//! // Register every enabled builtin factory and install the APL config
//! // visitor (in-process defaults) in one call:
//! praxis_policy::install_builtins(&mgr);
//! // ... then load a config that references the enabled `kind`s.
//! ```
//!
//! # Features
//!
//! No plugins are on by default (`praxis-policy` alone is the engine).
//! `builtins` enables every bundled extension, including the Valkey session
//! store; or pick a granular subset (`jwt`, `oauth`, `pii`, `audit`,
//! `elicitation-ciba`, `cedar`, `cel`, `opa`, `valkey`). Any of them brings in
//! the registration helpers, and each one re-exports its own concrete factory
//! type here from `praxis-policy-builtins`.

// Whole-crate re-exports for advanced use (types not surfaced below).
pub use {
    praxis_policy_apl_cmf, praxis_policy_apl_core, praxis_policy_apl_runtime, praxis_policy_core,
};

pub use praxis_policy_apl_core::step::PdpFactory;
pub use praxis_policy_apl_runtime::{
    AplOptions, DispatchCache, MemorySessionStore, SessionStore, SessionStoreFactory, register_apl,
};
pub use praxis_policy_core::manager::PluginManager;

/// Curated re-exports for plugin authors, so a plugin crate can depend on this
/// facade alone. See [`praxis_policy_core::prelude`].
pub use praxis_policy_core::prelude;

// The whole aggregator, for advanced use.
#[cfg(feature = "praxis-policy-builtins")]
pub use praxis_policy_builtins;

// Registration helpers — delegated to praxis-policy-builtins, keeping the facade's
// historical names (`register_builtin_plugins`, `builtin_pdp_factories`).
#[cfg(feature = "praxis-policy-builtins")]
pub use praxis_policy_builtins::{
    builtin_pdps as builtin_pdp_factories, builtin_session_store_factories, install_builtins,
    register_builtins as register_builtin_plugins,
};

// Concrete factory types + KIND consts, each behind its facade feature
// (which forwards to the matching praxis-policy-builtins feature).
#[cfg(feature = "cedar")]
pub use praxis_policy_builtins::CedarDirectPdpFactory;
#[cfg(feature = "cel")]
pub use praxis_policy_builtins::CelPdpFactory;
#[cfg(feature = "opa")]
pub use praxis_policy_builtins::OpaPdpFactory;
#[cfg(feature = "audit")]
pub use praxis_policy_builtins::{AUDIT_KIND, AuditLoggerFactory};
#[cfg(feature = "elicitation-ciba")]
pub use praxis_policy_builtins::{CIBA_KIND, CibaApproverFactory};
#[cfg(feature = "jwt")]
pub use praxis_policy_builtins::{JWT_KIND, JwtIdentityFactory};
#[cfg(feature = "oauth")]
pub use praxis_policy_builtins::{OAUTH_KIND, OAuthDelegatorFactory};
#[cfg(feature = "pii")]
pub use praxis_policy_builtins::{PII_KIND, PiiScannerFactory};
#[cfg(feature = "valkey")]
pub use praxis_policy_builtins::{VALKEY_KIND, ValkeyConfig, ValkeySessionStoreFactory};

#[cfg(all(test, feature = "praxis-policy-builtins"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn install_builtins_runs_without_panic() {
        let mgr = Arc::new(PluginManager::default());
        install_builtins(&mgr);
    }
}
