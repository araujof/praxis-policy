// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// ProvenanceExtension — origin and message threading.

use serde::{Deserialize, Serialize};

/// Origin and message threading.
///
/// Immutable — set by the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceExtension {
    /// Source system or service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Unique message identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,

    /// Parent message ID (for threading).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}
