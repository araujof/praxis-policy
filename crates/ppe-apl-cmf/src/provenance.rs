// Location: ./crates/ppe-apl-cmf/src/provenance.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// ProvenanceExtension → AttributeBag.
//
// Namespace:
//   provenance.source       : String
//   provenance.message_id   : String
//   provenance.parent_id    : String

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::ProvenanceExtension;

pub fn extract_provenance(p: &ProvenanceExtension, bag: &mut AttributeBag) {
    if let Some(v) = &p.source {
        bag.set("provenance.source", v.clone());
    }
    if let Some(v) = &p.message_id {
        bag.set("provenance.message_id", v.clone());
    }
    if let Some(v) = &p.parent_id {
        bag.set("provenance.parent_id", v.clone());
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn extracts_threading_fields() {
        let p = ProvenanceExtension {
            source: Some("upstream-mcp".into()),
            message_id: Some("msg-1".into()),
            parent_id: Some("msg-0".into()),
        };
        let mut bag = AttributeBag::new();
        extract_provenance(&p, &mut bag);
        assert_eq!(bag.get_string("provenance.source"), Some("upstream-mcp"));
        assert_eq!(bag.get_string("provenance.parent_id"), Some("msg-0"));
    }
}
