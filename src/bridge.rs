//! The tokio → asyncio bridge, wrapped so a Rust task that finishes *after* the
//! Python event loop has closed cannot take the process down.
//!
//! `pyo3_async_runtimes` delivers a completed future's result by calling
//! `event_loop.call_soon_threadsafe(...)`. On a closed loop that raises
//! `RuntimeError: Event loop is closed`, and the bridge does not propagate it —
//! it calls `print_and_set_sys_last_vars`, dumping a traceback to stderr from
//! whichever tokio worker thread the task landed on. With many tasks finishing
//! late, every worker writes to stderr at once; during interpreter shutdown they
//! contend for the `BufferedWriter` lock and CPython aborts the process with
//! `Fatal Python error: _enter_buffered_busy`.
//!
//! The bridge only ever calls two methods on the object it is handed as the
//! event loop — `create_future()` and `call_soon_threadsafe()` — and takes it
//! from a caller-supplied `TaskLocals`. So instead of forking the bridge, we
//! hand it [`GuardedEventLoop`]: a proxy that forwards both to the real loop but
//! drops the callback once that loop is closed.
//!
//! # In-flight tracking and the drain guarantee
//!
//! On top of crash-proofing, every tracked bridge crossing is counted so
//! `drain_pending()` can hold shutdown until the work has settled. *When* the
//! count releases is what makes `drain_pending() == True` a delivery
//! guarantee rather than a race:
//!
//! * The count is taken in [`future_into_py`] before anything fallible runs,
//!   held by a guard the wrapper future captures. A submission that fails
//!   synchronously (no running event loop, say) drops the never-polled
//!   wrapper, which drops the captured guard: the count rolls back.
//! * A wrapper dropped without completing — Python cancelled the future, or
//!   the inner future panicked — releases its guard right there: no result is
//!   left to deliver.
//! * A wrapper that completes hands its guard to the proxy, and the proxy
//!   releases it only at the end of `call_soon_threadsafe` — once the result
//!   callback sits in the real loop's FIFO queue, or is knowingly dropped
//!   because that loop is closed. The count therefore reaches zero only after
//!   every completed result is enqueued; the `drain_pending()` wake-up is
//!   enqueued after that (its own delivery crosses the same bridge), so by
//!   the time Python observes `True`, every tracked future is already done.
//!
//! One sliver needs a backstop: a future cancelled between wrapper completion
//! and `set_result` makes the bridge skip delivery entirely (it checks
//! `future.cancelled()` first), so the handed-over guard is freed only when
//! the proxy object itself is — via pyo3's *deferred* decref, which runs on
//! the next GIL acquisition. [`drain`] taps the GIL periodically while
//! waiting so that acquisition is guaranteed to come.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use pyo3_async_runtimes::TaskLocals;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use tokio::sync::Notify;

/// Process-wide count of bridged futures that have been handed to Python but
/// whose results are not yet delivered, so [`pending_count`] and [`drain`]
/// can see them.
///
/// Deliberately global rather than per-Session: the failure this guards against
/// is process-level (the loop closing while *anything* is still in flight), and
/// requests are only one source — WebSocket handshakes, pool acquisition, and
/// streaming body reads all cross the same bridge.
static IN_FLIGHT: LazyLock<Arc<InFlight>> = LazyLock::new(|| {
    Arc::new(InFlight {
        count: AtomicUsize::new(0),
        idle: Notify::new(),
    })
});

struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

/// Holds one unit of the in-flight count, released on drop.
struct InFlightGuard(Arc<InFlight>);

impl InFlightGuard {
    /// Counting starts at construction, before anything fallible, so the
    /// increment/decrement pairing is structural: whoever ends up owning the
    /// guard releases it on drop — including an async block that captured it
    /// and was then dropped before its first poll.
    fn register() -> Self {
        let tracker = IN_FLIGHT.clone();
        tracker.count.fetch_add(1, Ordering::AcqRel);
        InFlightGuard(tracker)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// Where a completed wrapper parks its guard for the proxy to release after
/// the result callback is enqueued (see module docs for the full timeline).
type Handoff = Arc<Mutex<Option<InFlightGuard>>>;

/// A mutex poisoned by a panicking holder still contains data that is valid
/// for our purposes (an `Option` slot); recover it rather than unwrapping.
fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Proxy standing in for the running event loop in the bridge's `TaskLocals`.
///
/// Forwards the two methods the bridge uses, and swallows a late
/// `call_soon_threadsafe` instead of letting it raise (see module docs).
#[pyclass]
pub struct GuardedEventLoop {
    inner: PyObject,
    /// Filled by a tracked wrapper future when it completes; empty for
    /// untracked bridges. Released at the end of `call_soon_threadsafe`.
    handoff: Handoff,
}

#[pymethods]
impl GuardedEventLoop {
    /// Forwarded verbatim: the bridge calls this to allocate the Python future
    /// it hands back to the caller, and that must be a real asyncio future
    /// belonging to the real loop.
    fn create_future(&self, py: Python<'_>) -> PyResult<PyObject> {
        Ok(self.inner.bind(py).call_method0("create_future")?.unbind())
    }

    /// Forwarded unless the loop is already closed, in which case the result is
    /// dropped: nobody is left to await it, and raising here would only be
    /// printed to stderr by the bridge.
    #[pyo3(signature = (*args, **kwargs))]
    fn call_soon_threadsafe(
        &self,
        py: Python<'_>,
        args: &Bound<'_, PyTuple>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        // Taken up front, dropped when this call returns — on every path. By
        // then the result is either in the loop's queue or will never be
        // delivered, which is exactly when the in-flight count may release:
        // a drain observing zero must know the queue already has everything.
        let _guard = lock_ignore_poison(&self.handoff).take();
        let loop_obj = self.inner.bind(py);
        if loop_obj.call_method0("is_closed")?.extract::<bool>()? {
            return Ok(());
        }
        match loop_obj.call_method("call_soon_threadsafe", args, kwargs) {
            Ok(_) => Ok(()),
            // The loop can close between the check above and this call. Treat
            // that identically rather than letting the race become a crash;
            // anything else is a real error and still propagates.
            Err(e) if is_loop_closed_error(py, &e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Everything else falls through to the real loop untouched.
    ///
    /// The bridge reaches for other attributes on paths we do not currently
    /// take (`into_future` wants `create_task`, for one), and a future version
    /// may reach for more. Forwarding by default keeps the proxy a proxy: only
    /// `call_soon_threadsafe` above behaves differently.
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<PyObject> {
        Ok(self.inner.bind(py).getattr(name)?.unbind())
    }
}

/// True for the `RuntimeError("Event loop is closed")` asyncio raises once the
/// loop is shut down. Matched on the message because asyncio has no dedicated
/// exception type for it.
fn is_loop_closed_error(py: Python<'_>, err: &PyErr) -> bool {
    err.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py)
        && err.value(py).to_string().contains("Event loop is closed")
}

/// Drop-in replacement for `pyo3_async_runtimes::tokio::future_into_py` that
/// installs the [`GuardedEventLoop`] proxy and counts the future as in flight
/// until its result is delivered (or provably never will be).
///
/// Contextvars are preserved: only the event loop of the current `TaskLocals`
/// is swapped, the captured context is carried over untouched.
pub fn future_into_py<F, T>(py: Python<'_>, fut: F) -> PyResult<Bound<'_, PyAny>>
where
    F: std::future::Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py>,
{
    let guard = InFlightGuard::register();
    let handoff: Handoff = Arc::new(Mutex::new(None));
    let transfer = handoff.clone();
    bridged_into_py(py, handoff, async move {
        let result = fut.await;
        // Completed: delivery (set_result → call_soon_threadsafe) happens
        // after this future returns, so the guard moves to the proxy, which
        // releases it once the result is enqueued. A wrapper dropped before
        // reaching this line — cancellation, a panic in `fut`, or a
        // submission that failed before the first poll — still owns the
        // guard and releases it on drop: nothing is left to deliver.
        *lock_ignore_poison(&transfer) = Some(guard);
        result
    })
}

/// As [`future_into_py`], but the future is not counted as in flight.
///
/// Used by `drain_pending`, which must not wait on itself.
pub fn future_into_py_untracked<F, T>(py: Python<'_>, fut: F) -> PyResult<Bound<'_, PyAny>>
where
    F: std::future::Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py>,
{
    bridged_into_py(py, Arc::new(Mutex::new(None)), fut)
}

/// Shared plumbing: swap the event loop in the current `TaskLocals` for a
/// [`GuardedEventLoop`] carrying `handoff`, then enter the bridge.
fn bridged_into_py<F, T>(py: Python<'_>, handoff: Handoff, fut: F) -> PyResult<Bound<'_, PyAny>>
where
    F: std::future::Future<Output = PyResult<T>> + Send + 'static,
    T: for<'py> IntoPyObject<'py>,
{
    let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
    let guarded = Py::new(
        py,
        GuardedEventLoop {
            inner: locals.event_loop(py).unbind(),
            handoff,
        },
    )?;
    let locals =
        TaskLocals::new(guarded.into_bound(py).into_any()).with_context(locals.context(py));
    pyo3_async_runtimes::tokio::future_into_py_with_locals(py, locals, fut)
}

/// Number of bridged futures still in flight process-wide.
pub fn pending_count() -> usize {
    IN_FLIGHT.count.load(Ordering::Acquire)
}

/// Wait until nothing is in flight, or until `timeout` elapses.
///
/// Returns whether the wait finished with the count at zero.
pub async fn drain(timeout: Option<std::time::Duration>) -> bool {
    let wait = async {
        loop {
            // Register before re-reading: a task finishing in between would
            // otherwise notify while nobody is listening and leave us parked.
            let notified = IN_FLIGHT.idle.notified();
            if IN_FLIGHT.count.load(Ordering::Acquire) == 0 {
                return;
            }
            // Wake periodically to take the GIL even if nothing notifies: a
            // guard stranded in a proxy (future cancelled in the sliver
            // between wrapper completion and set_result — the bridge skips
            // delivery for cancelled futures) is freed by pyo3's deferred
            // decref, which only runs on the next GIL acquisition. Tapping
            // the GIL here guarantees that acquisition happens.
            if tokio::time::timeout(std::time::Duration::from_millis(100), notified)
                .await
                .is_err()
            {
                Python::with_gil(|_| ());
            }
        }
    };
    match timeout {
        Some(t) => tokio::time::timeout(t, wait).await.is_ok(),
        None => {
            wait.await;
            true
        }
    }
}
