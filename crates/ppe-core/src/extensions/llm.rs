// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// LLMExtension — model identity and capabilities.

use serde::{Deserialize, Serialize};

/// Model identity and capabilities.
///
/// Immutable — set by the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LLMExtension {
    /// Model identifier (e.g., "gpt-4o", "claude-sonnet-4-20250514").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,

    /// Provider name (e.g., "openai", "anthropic").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Model capabilities (e.g., "`tool_use`", "vision", "streaming").
    #[serde(default)]
    pub capabilities: Vec<String>,
}
