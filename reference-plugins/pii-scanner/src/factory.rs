// Location: ./reference-plugins/pii-scanner/src/factory.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use std::sync::Arc;

use praxis_policy_core::{
    cmf::CmfHook,
    error::PluginError,
    factory::{PluginFactory, PluginInstance},
    hooks::TypedHandlerAdapter,
    plugin::PluginConfig,
};

use crate::scanner::PiiScanner;

/// `kind:` string operators write in PPE YAML to declare a PII
/// scanner instance.
pub const KIND: &str = "validator/pii-scan";

/// Factory for `kind: validator/pii-scan`. Instantiates a
/// `PiiScanner` from the `config:` block and registers a handler
/// for every CMF hook name listed in `cfg.hooks`. Operators
/// typically wire it on `cmf.tool_pre_invoke` /
/// `cmf.prompt_pre_invoke` / `cmf.resource_pre_fetch` so it runs
/// before any of those entity types reach the backend.
pub struct PiiScannerFactory;

impl PluginFactory for PiiScannerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let scanner = Arc::new(PiiScanner::new(config.clone())?);

        // Register the same handler instance against every CMF hook
        // name the operator declared in YAML — same plugin, multiple
        // entry points. Empty hooks list is a config error.
        if config.hooks.is_empty() {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (praxis-policy-plugin-pii-scanner): `hooks:` must list at \
                     least one CMF hook to scan on (e.g. cmf.tool_pre_invoke)",
                    config.name
                ),
            }));
        }

        let handlers: Vec<_> = config
            .hooks
            .iter()
            .map(|h| -> (&'static str, _) {
                // Leak the string to get a 'static lifetime — the
                // handler registry stores it that way for cheap
                // comparison. PluginConfigs are read once at startup
                // and live for the process lifetime, so the leak
                // bound is the number of plugin × hook pairs in
                // config (small, bounded).
                let leaked: &'static str = Box::leak(h.clone().into_boxed_str());
                let adapter: Arc<dyn praxis_policy_core::registry::AnyHookHandler> =
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&scanner)));
                (leaked, adapter)
            })
            .collect();

        Ok(PluginInstance {
            plugin: scanner,
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
    /// test can vary the one thing it is about. The empty `config:` block takes
    /// the scanner's own defaults.
    fn cfg(hooks: Vec<String>) -> PluginConfig {
        PluginConfig {
            name: "pii-scan".into(),
            kind: KIND.into(),
            hooks,
            mode: PluginMode::Sequential,
            priority: 10,
            on_error: OnError::Fail,
            config: Some(serde_json::json!({})),
            ..Default::default()
        }
    }

    #[test]
    fn one_hook_yields_one_handler_registered_under_that_hook_name() {
        let inst = PiiScannerFactory
            .create(&cfg(vec!["cmf.tool_pre_invoke".into()]))
            .expect("a config with one hook must build");
        assert_eq!(inst.handlers.len(), 1, "one hook, one handler");
        assert_eq!(
            inst.handlers[0].0, "cmf.tool_pre_invoke",
            "the handler must be registered under the hook name from config"
        );
    }

    /// The scanner is meant to be wired on several entity types at once, so the
    /// one-handler-per-hook fan-out is the behavior operators depend on.
    #[test]
    fn every_configured_hook_gets_its_own_handler() {
        let hooks = vec![
            "cmf.tool_pre_invoke".to_owned(),
            "cmf.prompt_pre_fetch".to_owned(),
            "cmf.resource_pre_fetch".to_owned(),
        ];
        let inst = PiiScannerFactory
            .create(&cfg(hooks.clone()))
            .expect("a config with three hooks must build");
        let names: Vec<&str> = inst.handlers.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, hooks, "one handler per hook, in config order");
    }

    /// A scanner wired to no hooks would load without error and never inspect
    /// anything, so the operator would believe traffic was being scanned.
    #[test]
    fn empty_hooks_is_rejected_and_the_message_names_the_key() {
        // `.err()` rather than `expect_err`: PluginInstance is not Debug.
        let err = PiiScannerFactory
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
