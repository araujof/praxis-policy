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
//! The bundled plugins, PDPs and session stores are registered from here, each
//! behind a feature, and only what you enable is compiled.
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
//! type here.

// Whole-crate re-exports for advanced use (types not surfaced below).
pub use {
    praxis_policy_apl_cmf, praxis_policy_apl_core, praxis_policy_apl_runtime, praxis_policy_core,
};

pub use praxis_policy_apl_core::step::PdpFactory;
pub use praxis_policy_apl_runtime::{
    AplOptions, DispatchCache, MemorySessionStore, SessionStore, SessionStoreFactory, register_apl,
};
pub use praxis_policy_core::manager::PluginManager;

/// The two types a host needs to accept a plugin it did not compile in:
/// [`PluginManager::register_factory`] takes a `Box<dyn PluginFactory>`, and
/// [`PluginInstance`] is what that factory returns.
///
/// Surfaced here so a host embedding the engine can name them without reaching
/// through to `praxis_policy_core`. Plugin *authors* get the same two names from
/// [`prelude`].
pub use praxis_policy_core::factory::{PluginFactory, PluginInstance};

/// Curated re-exports for plugin authors, so a plugin crate can depend on this
/// facade alone. See [`praxis_policy_core::prelude`].
pub use praxis_policy_core::prelude;

// Concrete factory types + KIND consts, each behind its feature.
#[cfg(feature = "cedar")]
pub use praxis_policy_pdp_cedar_direct::CedarDirectPdpFactory;
#[cfg(feature = "cel")]
pub use praxis_policy_pdp_cel::CelPdpFactory;
#[cfg(feature = "opa")]
pub use praxis_policy_pdp_opa::OpaPdpFactory;
#[cfg(feature = "audit")]
pub use praxis_policy_plugin_audit_logger::{AuditLoggerFactory, KIND as AUDIT_KIND};
#[cfg(feature = "oauth")]
pub use praxis_policy_plugin_delegator_oauth::{KIND as OAUTH_KIND, OAuthDelegatorFactory};
#[cfg(feature = "elicitation-ciba")]
pub use praxis_policy_plugin_elicitation_ciba::{CibaApproverFactory, KIND as CIBA_KIND};
#[cfg(feature = "jwt")]
pub use praxis_policy_plugin_identity_jwt::{JwtIdentityFactory, KIND as JWT_KIND};
#[cfg(feature = "pii")]
pub use praxis_policy_plugin_pii_scanner::{KIND as PII_KIND, PiiScannerFactory};
#[cfg(feature = "valkey")]
pub use praxis_policy_session_valkey::{
    KIND as VALKEY_KIND, ValkeyConfig, ValkeySessionStoreFactory,
};

// =============================================================================
// Builtin registration
// =============================================================================
//
// Which builtins exist and how they are registered lives here rather than in a
// separate aggregator crate. It was split for a while, and the split cost a real
// bug: both layers defined an umbrella over the same set, and the forwarding
// between them left these factory re-exports unreachable, so enabling
// `builtins` compiled every builtin in and exported none of their types. One
// layer cannot disagree with itself.

/// Generate [`register_builtin_plugins`] from a feature to factory table. Each
/// entry expands to a `#[cfg(feature = ...)]`-gated, **explicit**
/// `register_factory(KIND, Box::new(Factory))` call keyed off the builtin
/// crate's own `KIND` const.
///
/// Explicit calls (rather than `inventory` / `linkme` link-section registration)
/// are deliberate: in the CPEX FFI staticlib the linker garbage-collects
/// sections nothing references, which would silently drop auto-registered
/// plugins. Naming each factory here keeps its object code alive.
#[cfg(feature = "_builtin")]
macro_rules! register_builtins {
    ( $( feature $feat:literal => $krate:ident :: $factory:ident ),* $(,)? ) => {
        /// Register every enabled by-kind plugin factory on `mgr`: identity
        /// (`jwt`), delegators (`oauth`), validators (`pii`), and observers
        /// (`audit`). Call before loading a config so the manager can
        /// instantiate plugins whose YAML `kind:` matches.
        ///
        /// PDP and session-store factories are wired through [`AplOptions`]
        /// instead; see [`builtin_pdp_factories`] and
        /// [`builtin_session_store_factories`], or use [`install_builtins`].
        #[allow(unused_variables)]
        pub fn register_builtin_plugins(mgr: &std::sync::Arc<PluginManager>) {
            $(
                #[cfg(feature = $feat)]
                mgr.register_factory($krate::KIND, Box::new($krate::$factory));
            )*
        }
    };
}

#[cfg(feature = "_builtin")]
register_builtins! {
    feature "jwt"              => praxis_policy_plugin_identity_jwt::JwtIdentityFactory,
    feature "oauth"            => praxis_policy_plugin_delegator_oauth::OAuthDelegatorFactory,
    feature "elicitation-ciba" => praxis_policy_plugin_elicitation_ciba::CibaApproverFactory,
    feature "pii"              => praxis_policy_plugin_pii_scanner::PiiScannerFactory,
    feature "audit"            => praxis_policy_plugin_audit_logger::AuditLoggerFactory,
}

/// The enabled PDP factories, ready to drop into
/// [`AplOptions::pdp_factories`]. A route's `cedar:`, `cel:` or `opa:` step
/// selects which one runs.
// `vec![]` can't replace the conditional pushes: each element is
// `#[cfg]`-gated on its feature, so the set is built incrementally.
#[cfg(feature = "_builtin")]
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_pdp_factories() -> Vec<std::sync::Arc<dyn PdpFactory>> {
    let mut factories: Vec<std::sync::Arc<dyn PdpFactory>> = Vec::new();
    #[cfg(feature = "cedar")]
    factories.push(std::sync::Arc::new(CedarDirectPdpFactory::new()));
    #[cfg(feature = "cel")]
    factories.push(std::sync::Arc::new(CelPdpFactory::new()));
    #[cfg(feature = "opa")]
    factories.push(std::sync::Arc::new(OpaPdpFactory::new()));
    factories
}

/// The enabled session-store factories, ready to drop into
/// [`AplOptions::session_store_factories`]. A `global.apl.session_store:
/// { kind: ... }` config block selects one; absent that, the in-process
/// [`MemorySessionStore`] default stays active.
#[cfg(feature = "_builtin")]
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn builtin_session_store_factories() -> Vec<std::sync::Arc<dyn SessionStoreFactory>> {
    let mut factories: Vec<std::sync::Arc<dyn SessionStoreFactory>> = Vec::new();
    #[cfg(feature = "valkey")]
    factories.push(std::sync::Arc::new(ValkeySessionStoreFactory::new()));
    factories
}

/// Register every enabled plugin factory and install the APL config visitor on
/// `mgr` with in-process defaults (a [`MemorySessionStore`] and the default
/// baseline capabilities). The enabled PDP and session-store factories are wired
/// in, so a later config load can reference any of them by `kind`.
///
/// This is the one-call path; reach for [`register_builtin_plugins`] and
/// [`AplOptions`] directly when you need to customize capabilities or the
/// default store.
#[cfg(feature = "_builtin")]
pub fn install_builtins(mgr: &std::sync::Arc<PluginManager>) {
    register_builtin_plugins(mgr);

    let mut opts = AplOptions::in_process();
    opts.pdp_factories = builtin_pdp_factories();
    opts.session_store_factories = builtin_session_store_factories();

    let _visitor = register_apl(mgr, opts);
}

#[cfg(all(test, feature = "_builtin"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn install_builtins_runs_without_panic() {
        let mgr = Arc::new(PluginManager::default());
        install_builtins(&mgr);
    }

    #[test]
    fn pdp_factories_track_enabled_features() {
        let expected = usize::from(cfg!(feature = "cedar"))
            + usize::from(cfg!(feature = "cel"))
            + usize::from(cfg!(feature = "opa"));
        assert_eq!(
            builtin_pdp_factories().len(),
            expected,
            "one PDP factory per enabled feature",
        );
    }

    #[test]
    fn session_store_factories_track_enabled_features() {
        let expected = usize::from(cfg!(feature = "valkey"));
        assert_eq!(
            builtin_session_store_factories().len(),
            expected,
            "one session-store factory per enabled feature",
        );
    }
}
