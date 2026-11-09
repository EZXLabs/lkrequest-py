//! `set_log_level(..., format="logging")`: the events that pass the level
//! filter, handed to Python's `logging`.
//!
//! The events are queued and passed on by a thread of their own, a batch per
//! hold of the GIL, so that a request never waits for the GIL in order to log.
//! A queue that is full drops the newest events rather than grow, and once the
//! interpreter starts shutting down nothing is passed on.

use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use pyo3::prelude::*;
use pyo3::types::PyCFunction;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Events waiting for the forwarding thread.
const QUEUE_SIZE: usize = 4096;

/// Events passed on per hold of the GIL, at most.
const BATCH_SIZE: usize = 256;

/// Set by an `atexit` hook: past that point Python must not be called.
static EXITING: AtomicBool = AtomicBool::new(false);

/// Hands events to the forwarding thread.
pub(crate) struct PythonLogging {
    queue: SyncSender<Record>,
}

/// One event, as the forwarding thread passes it on.
struct Record {
    level: Level,
    target: String,
    message: String,
}

impl PythonLogging {
    /// Start the forwarding thread, and stop it from calling Python once the
    /// interpreter begins to exit.
    pub(crate) fn start(py: Python<'_>) -> PyResult<Self> {
        let stop = PyCFunction::new_closure(py, None, None, |_args, _kwargs| {
            EXITING.store(true, Ordering::Relaxed);
        })?;
        py.import("atexit")?.call_method1("register", (stop,))?;
        let (queue, events) = sync_channel(QUEUE_SIZE);
        std::thread::Builder::new()
            .name("lkrequest-log".into())
            .spawn(move || forward(events))?;
        Ok(Self { queue })
    }
}

impl<S: Subscriber> Layer<S> for PythonLogging {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let metadata = event.metadata();
        let mut message = MessageVisitor::default();
        event.record(&mut message);
        let record = Record {
            level: *metadata.level(),
            target: metadata.target().to_owned(),
            message: message.into_text(),
        };
        // Logging must never hold a request up: a full queue drops the event.
        let _ = self.queue.try_send(record);
    }
}

/// Pass queued events on to `logging` until the process exits.
fn forward(events: Receiver<Record>) {
    while let Ok(first) = events.recv() {
        if EXITING.load(Ordering::Relaxed) {
            return;
        }
        let batch: Vec<Record> = std::iter::once(first)
            .chain(events.try_iter().take(BATCH_SIZE - 1))
            .collect();
        Python::try_attach(|py| {
            // The hook may have run while this thread waited for the GIL.
            if EXITING.load(Ordering::Relaxed) {
                return;
            }
            let Ok(get_logger) = py.import("logging").and_then(|m| m.getattr("getLogger")) else {
                return;
            };
            for record in &batch {
                // A logging setup that raises is not ours to report.
                let _ = emit(&get_logger, record);
            }
        });
    }
}

/// Log `record` on `lkrequest.<target>`, `::` turned into `.`.
fn emit(get_logger: &Bound<'_, PyAny>, record: &Record) -> PyResult<()> {
    let name = format!("lkrequest.{}", record.target.replace("::", "."));
    let logger = get_logger.call1((name,))?;
    let level = python_level(record.level);
    if logger.call_method1("isEnabledFor", (level,))?.is_truthy()? {
        logger.call_method1("log", (level, record.message.as_str()))?;
    }
    Ok(())
}

/// `logging`'s number for a level; TRACE, which it lacks, goes below DEBUG.
fn python_level(level: Level) -> u8 {
    match level {
        Level::TRACE => 5,
        Level::DEBUG => 10,
        Level::INFO => 20,
        Level::WARN => 30,
        Level::ERROR => 40,
    }
}

/// An event's message, followed by its other fields as `name=value`.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, format_args!("{value}"));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format_args!("{value:?}"));
    }
}

impl MessageVisitor {
    fn push(&mut self, field: &Field, value: fmt::Arguments<'_>) {
        let _ = match field.name() {
            "message" => self.message.write_fmt(value),
            name => write!(self.fields, " {name}={value}"),
        };
    }

    fn into_text(mut self) -> String {
        self.message.push_str(&self.fields);
        self.message.trim_start().to_owned()
    }
}
