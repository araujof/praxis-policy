// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Planted secrets and the check that none of them leaks.
//!
//! A test plants every value that must never reach a diagnostic (inbound
//! tokens, client secrets, minted tokens, `auth_req_id`s, the SSN) and then
//! asserts over everything the caller can observe. A failure names the
//! secret by label, never by value.

use serde_json::Value;

use crate::capture::Events;

/// The secrets one test planted.
#[derive(Clone, Debug, Default)]
pub struct Planted(Vec<(String, String)>);

impl Planted {
    /// No secrets yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Plant `value` under `label`. An empty value is ignored, since it
    /// would match everything.
    pub fn plant(&mut self, label: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.0.push((label.to_owned(), value));
        }
    }

    /// Plant everything `other` planted.
    pub fn extend(&mut self, other: &Self) {
        self.0.extend(other.0.iter().cloned());
    }

    /// The labels of the secrets found in `text`.
    fn found_in(&self, text: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(_, value)| text.contains(value.as_str()))
            .map(|(label, _)| label.as_str())
            .collect()
    }

    /// Assert no planted secret appears in `text`, described as `place`.
    ///
    /// # Panics
    ///
    /// Naming `place` and the labels of every secret found.
    pub fn assert_absent(&self, place: &str, text: &str) {
        let found = self.found_in(text);
        assert!(
            found.is_empty(),
            "planted secrets leaked into {place}: {found:?}"
        );
    }

    /// Assert no planted secret appears in any key or string of `value`.
    ///
    /// # Panics
    ///
    /// As [`Planted::assert_absent`].
    pub fn assert_absent_json(&self, place: &str, value: &Value) {
        let mut strings = Vec::new();
        collect_strings(value, &mut strings);
        self.assert_absent(place, &strings.join("\n"));
    }

    /// Assert no planted secret appears in captured logs or audit records.
    ///
    /// # Panics
    ///
    /// As [`Planted::assert_absent`].
    pub fn assert_absent_events(&self, events: &Events) {
        self.assert_absent("captured logs", &events.logs().join("\n"));
        for record in events.audit_records() {
            self.assert_absent_json("an audit record", &record);
        }
    }
}

fn collect_strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k);
                collect_strings(v, out);
            }
        },
        Value::Null | Value::Bool(_) | Value::Number(_) => {},
    }
}
