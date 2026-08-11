// Location: ./crates/ppe-apl-cmf/src/completion.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CompletionExtension → AttributeBag.
//
// Namespace:
//   completion.stop_reason     : String  (snake_case: "end" | "return" | "call" | "max_tokens" | "stop_sequence")
//   completion.model           : String
//   completion.raw_format      : String
//   completion.created_at      : String
//   completion.latency_ms      : Int
//   completion.tokens.input    : Int
//   completion.tokens.output   : Int
//   completion.tokens.total    : Int

use praxis_policy_apl_core::AttributeBag;
use praxis_policy_core::extensions::{CompletionExtension, StopReason};

/// Write completion metadata into the bag.
pub fn extract_completion(c: &CompletionExtension, bag: &mut AttributeBag) {
    if let Some(sr) = c.stop_reason {
        bag.set("completion.stop_reason", stop_reason_str(sr));
    }
    if let Some(tu) = &c.tokens {
        bag.set("completion.tokens.input", i64::from(tu.input_tokens));
        bag.set("completion.tokens.output", i64::from(tu.output_tokens));
        bag.set("completion.tokens.total", i64::from(tu.total_tokens));
    }
    if let Some(v) = &c.model {
        bag.set("completion.model", v.clone());
    }
    if let Some(v) = &c.raw_format {
        bag.set("completion.raw_format", v.clone());
    }
    if let Some(v) = &c.created_at {
        bag.set("completion.created_at", v.clone());
    }
    if let Some(ms) = c.latency_ms {
        // Saturating. This is a telemetry attribute a policy can read, so a
        // wrapped negative latency would be both wrong and confusing in a rule.
        bag.set(
            "completion.latency_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        );
    }
}

fn stop_reason_str(sr: StopReason) -> &'static str {
    match sr {
        StopReason::End => "end",
        StopReason::Return => "return",
        StopReason::Call => "call",
        StopReason::MaxTokens => "max_tokens",
        StopReason::StopSequence => "stop_sequence",
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
    use praxis_policy_core::extensions::completion::TokenUsage;

    #[test]
    fn stop_reason_serializes_as_snake_case_string() {
        let c = CompletionExtension {
            stop_reason: Some(StopReason::MaxTokens),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        assert_eq!(bag.get_string("completion.stop_reason"), Some("max_tokens"));
    }

    #[test]
    fn tokens_flatten_to_nested_ints() {
        let c = CompletionExtension {
            tokens: Some(TokenUsage {
                input_tokens: 100,
                output_tokens: 50,
                total_tokens: 150,
            }),
            latency_ms: Some(420),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_completion(&c, &mut bag);
        assert_eq!(bag.get_int("completion.tokens.input"), Some(100));
        assert_eq!(bag.get_int("completion.tokens.output"), Some(50));
        assert_eq!(bag.get_int("completion.tokens.total"), Some(150));
        assert_eq!(bag.get_int("completion.latency_ms"), Some(420));
    }
}
