// Location: ./crates/ppe-sdk/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// PPE SDK — lean crate for plugin authors.
//
// Re-exports the Plugin trait and supporting types from praxis-policy-core.
// Plugin authors depend on this crate instead of the full runtime,
// keeping their dependency tree minimal. This is also the crate
// that WASM plugins compile against.

// Plugin lifecycle

//! Re-exports for plugin authors.
//!
//! Depend on this instead of the full runtime to keep a plugin's dependency
//! tree small. Carries the `Plugin` trait, the hook traits, and the supporting
//! types, and nothing that only the host needs.

pub use praxis_policy_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// Hook system
pub use praxis_policy_core::hooks::{
    Extensions, HookHandler, HookTypeDef, PluginPayload, PluginResult,
};

// Context
pub use praxis_policy_core::context::PluginContext;

// Errors
pub use praxis_policy_core::error::{PluginError, PluginViolation};

// Re-export the define_hook! macro
pub use praxis_policy_core::define_hook;

// CMF types
pub use praxis_policy_core::cmf::{
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
