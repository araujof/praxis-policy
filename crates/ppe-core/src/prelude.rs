// Location: ./crates/ppe-core/src/prelude.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

//! Curated surface for plugin authors.
//!
//! Everything needed to write a plugin and hand it to a host: the `Plugin`
//! trait, the hook traits, the payload and result types, the CMF domain objects,
//! and the factory types a plugin exposes so a host can construct it. Import it
//! as a block rather than tracking which module each name lives in.
//!
//! A whole plugin, from this module alone. Compiled rather than `ignore`d,
//! because "everything needed to write a plugin" is a claim that regresses
//! silently: the factory group below was missing for exactly as long as nothing
//! checked it.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use praxis_policy_core::prelude::*;
//!
//! /// Denies any message whose text mentions a banned word.
//! struct WordBlocker {
//!     cfg: PluginConfig,
//! }
//!
//! impl Plugin for WordBlocker {
//!     fn config(&self) -> &PluginConfig {
//!         &self.cfg
//!     }
//! }
//!
//! impl HookHandler<CmfHook> for WordBlocker {
//!     async fn handle(
//!         &self,
//!         payload: &MessagePayload,
//!         _ext: &Extensions,
//!         _ctx: &mut PluginContext,
//!     ) -> PluginResult<MessagePayload> {
//!         if payload.message.get_text_content().contains("banned") {
//!             return PluginResult::deny(PluginViolation::new(
//!                 "example.banned_word",
//!                 "the payload mentions a banned word",
//!             ));
//!         }
//!         PluginResult::allow()
//!     }
//! }
//!
//! /// What the host registers, via `PluginManager::register_factory`.
//! struct WordBlockerFactory;
//!
//! impl PluginFactory for WordBlockerFactory {
//!     fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
//!         let plugin = Arc::new(WordBlocker { cfg: config.clone() });
//!         let adapter: Arc<dyn AnyHookHandler> =
//!             Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
//!         Ok(PluginInstance {
//!             plugin,
//!             handlers: vec![("cmf.tool_pre_invoke", adapter)],
//!         })
//!     }
//! }
//! ```
//!
//! This was a separate `praxis-policy-sdk` crate, on the reasoning that plugin
//! authors could depend on it "instead of the full runtime" for a smaller
//! dependency tree. That did not hold: every name here is re-exported from this
//! crate, so depending on the wrapper pulled the same graph. What it really
//! offered was the curated namespace, which a module provides without a second
//! crate to version and publish.
//!
//! The factory group below was missing until the bundled PII scanner and audit
//! logger moved out of the published builtins and became worked examples of
//! out-of-tree plugins. The omission traced to reading this module as "nothing
//! that only a host needs": `PluginFactory` is what a *host* calls, so it looked
//! host-only. But the plugin is what implements it, so a plugin crate that could
//! not name it could not expose itself at all, and every bundled plugin reached
//! past this module into `crate::factory` to write its own `factory.rs`.

// Plugin lifecycle
pub use crate::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// Hook system
pub use crate::hooks::{Extensions, HookHandler, HookTypeDef, PluginPayload, PluginResult};

// Construction. A plugin implements `PluginFactory` and returns a
// `PluginInstance`; `TypedHandlerAdapter` is how a typed `HookHandler` is
// type-erased into the `AnyHookHandler` list that instance carries, and naming
// that trait is unavoidable because the handler vec's element type is explicit.
pub use crate::factory::{PluginFactory, PluginInstance};
pub use crate::hooks::TypedHandlerAdapter;
pub use crate::registry::AnyHookHandler;

// Context
pub use crate::context::PluginContext;

// Errors
pub use crate::error::{PluginError, PluginViolation};

// The define_hook! macro. Exported at the crate root by `#[macro_export]`, so it
// is named through `crate::` rather than the module it is written in.
pub use crate::define_hook;

// CMF types
pub use crate::cmf::{
    // Content parts and domain objects
    AudioSource,
    // Enums
    Channel,
    // Message and payload
    CmfHook,
    ContentPart,
    ContentType,
    DocumentSource,
    ImageSource,
    Message,
    MessagePayload,
    PromptRequest,
    PromptResult,
    Resource,
    ResourceReference,
    ResourceType,
    Role,
    ToolCall,
    ToolResult,
    VideoSource,
};
