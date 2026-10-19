//! What a `Session` handle owns besides the Rust session itself: its event
//! hooks, the middleware callbacks registered on it, and whether it was closed.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::gc::PyVisit;
use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3::PyTraverseError;
use tokio::sync::watch;

use crate::middleware::MiddlewareSlots;

// ---------------------------------------------------------------------------
// Event hooks
// ---------------------------------------------------------------------------

/// The `on_request` / `on_response` callbacks of a session.
///
/// They are kept in Python lists, not in a Rust `Vec`, so that Python's cycle
/// collector can see them. A hook is often a bound method of the object that
/// holds the session (`session.on_response(self.log)`), which closes a cycle
/// `owner -> session -> hook -> owner`. The collector can only break a cycle
/// whose every edge it can see, and a `Vec<Py<PyAny>>` behind an `Arc` is
/// invisible to it: the session stayed alive for good, connections included.
/// A `Py<PyList>` is an ordinary reference to an ordinary container, so the
/// owning pyclass reports it from `__traverse__` and the list reports its items.
pub(crate) struct EventHooks {
    request_hooks: Py<PyList>,
    response_hooks: Py<PyList>,
}

impl Default for EventHooks {
    fn default() -> Self {
        Python::with_gil(|py| EventHooks {
            request_hooks: PyList::empty(py).unbind(),
            response_hooks: PyList::empty(py).unbind(),
        })
    }
}

impl Clone for EventHooks {
    /// The clone shares the same lists, so a hook registered on one handle is
    /// seen by the request futures that hold the other.
    fn clone(&self) -> Self {
        Python::with_gil(|py| EventHooks {
            request_hooks: self.request_hooks.clone_ref(py),
            response_hooks: self.response_hooks.clone_ref(py),
        })
    }
}

/// The callbacks as they are right now. Hooks run with no list borrowed, so a
/// hook may register or drop hooks, or close the session, without invalidating
/// the iteration.
fn snapshot<'py>(hooks: &Py<PyList>, py: Python<'py>) -> Vec<Bound<'py, PyAny>> {
    hooks.bind(py).iter().collect()
}

/// Empty a hook list in place. In place, because the list is shared with every
/// other handle onto the session.
fn empty(hooks: &Py<PyList>, py: Python<'_>) {
    let list = hooks.bind(py);
    // Deleting the whole range cannot fail for a list we own.
    let _ = list.del_slice(0, list.len());
}

impl EventHooks {
    pub(crate) fn push_request(&self, py: Python<'_>, callback: Py<PyAny>) -> PyResult<()> {
        self.request_hooks.bind(py).append(callback)
    }

    pub(crate) fn push_response(&self, py: Python<'_>, callback: Py<PyAny>) -> PyResult<()> {
        self.response_hooks.bind(py).append(callback)
    }

    pub(crate) fn fire_request(
        &self,
        method: &str,
        url: &str,
        headers: &Option<Vec<(String, String)>>,
    ) {
        Python::with_gil(|py| {
            let hooks = snapshot(&self.request_hooks, py);
            if hooks.is_empty() {
                return;
            }
            let headers_val: HashMap<String, String> =
                headers.clone().unwrap_or_default().into_iter().collect();
            for hook in hooks {
                if let Err(e) = hook.call1((method, url, &headers_val)) {
                    tracing::warn!(error = %e, "event_hook.on_request failed");
                }
            }
        });
    }

    pub(crate) fn fire_response(&self, status_code: u16, url: &str, elapsed: f64) {
        Python::with_gil(|py| {
            for hook in snapshot(&self.response_hooks, py) {
                if let Err(e) = hook.call1((status_code, url, elapsed)) {
                    tracing::warn!(error = %e, "event_hook.on_response failed");
                }
            }
        });
    }

    fn clear(&self, py: Python<'_>) {
        empty(&self.request_hooks, py);
        empty(&self.response_hooks, py);
    }

    fn traverse(&self, visit: &PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.request_hooks)?;
        visit.call(&self.response_hooks)
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// The Python-side state of one session handle. Cloning shares it: the clones
/// held by in-flight requests see the same hooks and the same closed flag.
#[derive(Clone)]
pub(crate) struct SessionState {
    pub(crate) hooks: EventHooks,
    /// Flips to `true` once, when the session is closed. A channel rather than
    /// a flag so that requests already in flight hear about it.
    closed: Arc<watch::Sender<bool>>,
    /// Callbacks of the middleware given to `Client.session(middleware=...)`.
    /// They sit in the Rust session, out of the collector's sight, so closing
    /// the session is what releases them.
    middleware: Vec<Arc<MiddlewareSlots>>,
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState {
            hooks: EventHooks::default(),
            closed: Arc::new(watch::channel(false).0),
            middleware: Vec::new(),
        }
    }
}

impl SessionState {
    pub(crate) fn with_middleware(mut self, middleware: Vec<Arc<MiddlewareSlots>>) -> Self {
        self.middleware = middleware;
        self
    }

    pub(crate) fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// What a request future holds so that it can be abandoned when the session
    /// is closed under it.
    pub(crate) fn closing(&self) -> Closing {
        Closing(Arc::clone(&self.closed))
    }

    /// Fails once the session is closed. Called by everything that would start
    /// network activity or register a callback.
    pub(crate) fn ensure_open(&self) -> PyResult<()> {
        if self.is_closed() {
            return Err(PyRuntimeError::new_err("Session is closed"));
        }
        Ok(())
    }

    /// Mark the session closed, abandon the requests in flight, and let go of
    /// what it holds in Python: the hooks and the session-level middleware
    /// callbacks. Pooled connections are the caller's to drop, since they live
    /// in the Rust session.
    pub(crate) fn close(&self, py: Python<'_>) {
        self.closed.send_replace(true);
        self.hooks.clear(py);
        for slots in &self.middleware {
            slots.release();
        }
    }

    /// For `__traverse__`: report the references this handle owns.
    pub(crate) fn traverse(&self, visit: &PyVisit<'_>) -> Result<(), PyTraverseError> {
        self.hooks.traverse(visit)
    }

    /// For `__clear__`: called by the collector on a handle it found to be
    /// garbage, to break the cycle it sits in.
    pub(crate) fn clear_for_gc(&self) {
        Python::with_gil(|py| self.hooks.clear(py));
    }
}

// ---------------------------------------------------------------------------
// In-flight requests
// ---------------------------------------------------------------------------

/// Held by a request future so that closing the session can stop it.
///
/// Emptying the connection pool is not enough on its own. A request in flight
/// has its H1 connection checked out of the pool, and one on an H2 connection
/// that was just aborted did not fail either: it went on waiting. So the
/// request itself is abandoned.
///
/// It owns the sender: the channel therefore stays open for as long as the
/// request runs, even if every handle onto the session has been dropped (as in
/// `await client.session().get(url)`), and only an actual `close()` fires it.
pub(crate) struct Closing(Arc<watch::Sender<bool>>);

impl Closing {
    /// Run `work`, unless the session is closed first.
    pub(crate) async fn guard<T>(self, work: impl Future<Output = PyResult<T>>) -> PyResult<T> {
        let mut closed = self.0.subscribe();
        tokio::select! {
            result = work => result,
            _ = closed.wait_for(|closed| *closed) => {
                Err(PyRuntimeError::new_err("Session was closed while the request was in flight"))
            }
        }
    }
}
