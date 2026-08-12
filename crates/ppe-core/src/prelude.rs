// Location: ./crates/ppe-core/src/prelude.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

//! Curated surface for plugin authors.
//!
//! Everything a plugin needs, and nothing that only a host needs: the `Plugin`
//! trait, the hook traits, the payload and result types, and the CMF domain
//! objects. Import it as a block rather than tracking which module each name
//! lives in.
//!
//! ```rust,ignore
//! use praxis_policy_core::prelude::*;
//! ```
//!
//! This was a separate `praxis-policy-sdk` crate, on the reasoning that plugin
//! authors could depend on it "instead of the full runtime" for a smaller
//! dependency tree. That did not hold: every name here is re-exported from this
//! crate, so depending on the wrapper pulled the same graph. What it really
//! offered was the curated namespace, which a module provides without a second
//! crate to version and publish.

// Plugin lifecycle
pub use crate::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// Hook system
pub use crate::hooks::{Extensions, HookHandler, HookTypeDef, PluginPayload, PluginResult};

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
