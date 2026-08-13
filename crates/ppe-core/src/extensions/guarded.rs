// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Guarded<T> — capability-gated write access.
//
// A value that requires a WriteToken for mutable access. Read access
// is always available (if the plugin can see the extension at all).
// Write access requires the framework to issue a WriteToken based on
// the plugin's declared capabilities.
//
// Mirrors the reference implementation spec.

use serde::{Deserialize, Serialize};

/// A value that requires a `WriteToken` for mutable access.
///
/// Read access via `.read()` is always available. Write access via
/// `.write(token)` requires a `WriteToken` proving the caller has
/// the capability.
///
/// The framework issues write tokens only to plugins that declared
/// the corresponding write capability (e.g., `write_headers`).
/// Plugin code without a token cannot call `.write()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Guarded<T> {
    inner: T,
}

impl<T> Guarded<T> {
    /// Wrap a value in a guard.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Read access — always available if the plugin can see this extension.
    pub fn read(&self) -> &T {
        &self.inner
    }

    /// Write access — requires a `WriteToken` proving the caller has capability.
    ///
    /// The framework issues `WriteTokens` only to plugins that declared
    /// the write capability in their config. Without the token, this
    /// method is uncallable — the plugin can read but not write.
    pub fn write(&mut self, _token: &WriteToken) -> &mut T {
        &mut self.inner
    }

    /// Consume the guard, returning the inner value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Default> Default for Guarded<T> {
    fn default() -> Self {
        Self {
            inner: T::default(),
        }
    }
}

/// Opaque token for write access — only the framework can create one.
///
/// `pub(crate)` constructor means plugin crates cannot mint tokens.
/// The executor creates tokens based on the plugin's declared
/// capabilities from `PluginConfig`.
pub struct WriteToken {
    _private: (),
}

impl WriteToken {
    /// Only callable by the framework (pub(crate)).
    /// Plugin crates cannot construct this.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

// Not Clone and not Copy: each plugin gets its own from the executor.
//
// `Send` and `Sync` are not implemented by hand. The only field is `()`, which
// is both, so the auto traits already apply structurally. Two `unsafe impl`s
// used to stand here with a comment claiming a zero-sized private field
// suppresses auto traits, which is not how auto traits work. They were the
// crate's only unsafe code and they bought nothing.
//
// A compile-time assertion in place of the impls, so a future field that is not
// `Send`/`Sync` fails here with a clear message rather than silently at a
// distant use site.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WriteToken>();
};

impl std::fmt::Debug for WriteToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteToken")
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::get_unwrap,
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
    fn test_guarded_read_without_token() {
        let guarded = Guarded::new(42);
        assert_eq!(*guarded.read(), 42);
    }

    #[test]
    fn test_guarded_write_with_token() {
        let mut guarded = Guarded::new(42);
        let token = WriteToken::new();
        *guarded.write(&token) = 100;
        assert_eq!(*guarded.read(), 100);
    }

    #[test]
    fn test_guarded_serde_transparent() {
        let guarded = Guarded::new("hello".to_owned());
        let json = serde_json::to_string(&guarded).unwrap();
        assert_eq!(json, "\"hello\"");
        let deserialized: Guarded<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(*deserialized.read(), "hello");
    }

    #[test]
    fn test_guarded_with_struct() {
        use std::collections::HashMap;

        #[derive(Clone, Debug, Default, Serialize, Deserialize)]
        struct Headers {
            map: HashMap<String, String>,
        }

        let mut guarded = Guarded::new(Headers::default());
        let token = WriteToken::new();

        // Read — no token needed
        assert!(guarded.read().map.is_empty());

        guarded
            .write(&token)
            .map
            .insert("X-Auth".into(), "Bearer tok".into());
        assert_eq!(guarded.read().map.get("X-Auth").unwrap(), "Bearer tok");
    }
}
