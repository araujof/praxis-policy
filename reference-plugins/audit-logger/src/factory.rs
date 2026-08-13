// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

use std::sync::Arc;

use praxis_policy_core::{
    cmf::CmfHook,
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::logger::AuditLogger;

/// `kind:` string operators write in PPE YAML to declare an audit
/// logger instance.
pub const KIND: &str = "audit/logger";

/// Constructs an [`AuditLogger`] from config.
///
/// [`AuditLogger`]: crate::logger::AuditLogger
pub struct AuditLoggerFactory;

impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let logger = Arc::new(AuditLogger::new(config.clone())?);

        if config.hooks.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-audit-logger): `hooks:` must list at \
                     least one CMF hook to audit (e.g. cmf.tool_pre_invoke)",
                    config.name
                ),
            }));
        }

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&logger)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: logger,
            handlers,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use praxis_policy_core::plugin::{OnError, PluginMode};

    /// A config the factory accepts, with `hooks` left to the caller so each
    /// test can vary the one thing it is about.
    fn cfg(hooks: Vec<String>) -> PluginConfig {
        PluginConfig {
            name: "audit".into(),
            kind: KIND.into(),
            hooks,
            mode: PluginMode::Sequential,
            priority: 50,
            on_error: OnError::Fail,
            config: Some(serde_json::json!({ "destination": "stderr" })),
            ..Default::default()
        }
    }

    #[test]
    fn one_hook_yields_one_handler_registered_under_that_hook_name() {
        let inst = AuditLoggerFactory
            .create(&cfg(vec!["cmf.tool_pre_invoke".into()]))
            .expect("a config with one hook must build");
        assert_eq!(inst.handlers.len(), 1, "one hook, one handler");
        assert_eq!(
            inst.handlers[0].0, "cmf.tool_pre_invoke",
            "the handler must be registered under the hook name from config"
        );
    }

    /// The handler list is built by mapping over `hooks`, so a single-hook test
    /// cannot distinguish "one per hook" from "exactly one, always".
    #[test]
    fn every_configured_hook_gets_its_own_handler() {
        let hooks = vec![
            "cmf.tool_pre_invoke".to_owned(),
            "cmf.tool_post_invoke".to_owned(),
            "cmf.prompt_pre_fetch".to_owned(),
        ];
        let inst = AuditLoggerFactory
            .create(&cfg(hooks.clone()))
            .expect("a config with three hooks must build");
        let names: Vec<&str> = inst.handlers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, hooks, "one handler per hook, in config order");
    }

    /// An audit logger wired to no hooks would load without error and then never
    /// run, which is worse than refusing: the operator believes they have an
    /// audit trail.
    #[test]
    fn empty_hooks_is_rejected_and_the_message_names_the_key() {
        // `.err()` rather than `expect_err`: PluginInstance is not Debug.
        let err = AuditLoggerFactory
            .create(&cfg(vec![]))
            .err()
            .expect("no hooks must not build");
        assert!(
            matches!(*err, PluginError::Config { .. }),
            "expected a config error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("hooks:"),
            "the message must name the key the operator has to fix: {msg}"
        );
    }
}
