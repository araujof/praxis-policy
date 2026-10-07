// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Capturing logs and audit records, including those emitted inside the
//! tasks the engine spawns for each plugin invoke.
//!
//! The pattern of `crates/ppe-core/src/trace_capture.rs`: one subscriber for
//! the whole binary, always interested, so callsite interest cached
//! process-wide can never race a test into seeing nothing. Events go to a
//! thread-local sink.
//!
//! The executor runs every plugin invoke in `tokio::spawn` and does not
//! propagate spans or task-locals into it, so neither can key the sink. A
//! thread can: on a current-thread runtime the spawned task runs on the
//! test's own thread ([`capturing`]), and [`multi_thread`] builds a runtime
//! whose every worker carries the test's sink. Each test owns its runtime's
//! threads, so parallel tests stay isolated.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde_json::Value;

/// Target the audit-logger reference plugin emits its records at.
const AUDIT_TARGET: &str = "apl.audit";

#[derive(Clone, Debug)]
struct Event {
    target: String,
    rendered: String,
    record: Option<String>,
}

/// The events one test captured.
#[derive(Clone, Debug, Default)]
pub struct Events(Arc<Mutex<Vec<Event>>>);

impl Events {
    fn snapshot(&self) -> Vec<Event> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every event rendered as `[LEVEL target] field=value ...`, in order.
    #[must_use]
    pub fn logs(&self) -> Vec<String> {
        self.snapshot().into_iter().map(|e| e.rendered).collect()
    }

    /// The audit records emitted at target `apl.audit`, parsed as JSON.
    ///
    /// # Panics
    ///
    /// When a record is not JSON, since that is a broken audit trail.
    #[must_use]
    pub fn audit_records(&self) -> Vec<Value> {
        self.snapshot()
            .into_iter()
            .filter(|e| e.target == AUDIT_TARGET)
            .filter_map(|e| e.record)
            .map(|raw| {
                serde_json::from_str(&raw)
                    .unwrap_or_else(|err| panic!("audit record is not JSON ({err}): {raw}"))
            })
            .collect()
    }
}

thread_local! {
    static SINK: RefCell<Option<Events>> = const { RefCell::new(None) };
}

fn set_sink(events: Option<Events>) -> Option<Events> {
    SINK.with_borrow_mut(|sink| std::mem::replace(sink, events))
}

struct Render {
    rendered: String,
    record: Option<String>,
}

impl tracing::field::Visit for Render {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let value = format!("{value:?}");
        self.rendered
            .push_str(&format!(" {}={value}", field.name()));
        if field.name() == "record" {
            self.record = Some(value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.rendered
            .push_str(&format!(" {}={value}", field.name()));
        if field.name() == "record" {
            self.record = Some(value.to_owned());
        }
    }
}

struct Subscriber;

impl tracing::Subscriber for Subscriber {
    fn register_callsite(&self, _: &tracing::Metadata<'_>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        SINK.with_borrow(|sink| {
            let Some(events) = sink.as_ref() else {
                return;
            };
            let meta = event.metadata();
            let mut render = Render {
                rendered: format!("[{} {}]", meta.level(), meta.target()),
                record: None,
            };
            event.record(&mut render);
            events
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Event {
                    target: meta.target().to_owned(),
                    rendered: render.rendered,
                    record: render.record,
                });
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn install() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing::subscriber::set_global_default(Subscriber)
            .expect("no other subscriber is installed in this test binary");
    });
}

/// Restores the thread's previous sink on drop, even if the test panics.
#[derive(Debug)]
pub struct CaptureGuard(Option<Events>);

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        set_sink(self.0.take());
    }
}

/// Capture what this thread emits until the guard drops.
///
/// Use on a current-thread runtime (`#[tokio::test]`), where the engine's
/// spawned plugin tasks run on this thread too.
#[must_use]
pub fn capturing() -> (Events, CaptureGuard) {
    install();
    let events = Events::default();
    let previous = set_sink(Some(events.clone()));
    (events, CaptureGuard(previous))
}

/// A multi-thread runtime whose every thread captures into one sink.
#[derive(Debug)]
pub struct CapturingRuntime {
    runtime: tokio::runtime::Runtime,
    events: Events,
}

impl CapturingRuntime {
    /// What the runtime's threads, and the thread blocking on it, emitted.
    #[must_use]
    pub fn events(&self) -> &Events {
        &self.events
    }

    /// Run `future` to completion, capturing on the calling thread as well.
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        let previous = set_sink(Some(self.events.clone()));
        let _restore = CaptureGuard(previous);
        self.runtime.block_on(future)
    }
}

/// Build a multi-thread runtime with `workers` threads, all capturing.
///
/// # Panics
///
/// When the runtime cannot be built.
#[must_use]
pub fn multi_thread(workers: usize) -> CapturingRuntime {
    install();
    let events = Events::default();
    let sink = events.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .on_thread_start(move || {
            set_sink(Some(sink.clone()));
        })
        .on_thread_stop(|| {
            set_sink(None);
        })
        .build()
        .expect("build a multi-thread runtime");
    CapturingRuntime { runtime, events }
}
