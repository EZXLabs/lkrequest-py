//! Where the proxies of a `ProxyPool` or `SessionPool` come from: a fixed list,
//! or a Python function called for every proxy, as for a gateway that picks
//! the exit by a session id in the username.

use std::cell::Cell;
use std::future::{poll_fn, Future};
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use lkrequest::proxy::{ProxyConfig, ProxyProvider};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;

use crate::proxy::{resolve_proxy, resolve_proxy_list};
use crate::types::is_async_function;

/// How long upstream's `proxy_buffer` thread is held back after the function
/// failed. Left alone, it calls again at once, over and over.
const BUFFER_RETRY_DELAY: Duration = Duration::from_secs(1);

tokio::task_local! {
    /// What the proxy function raised while an `acquire()` was calling it, for
    /// that `acquire()` to raise in turn.
    static FAILURE: Cell<Option<PyErr>>;
}

/// A pool's `proxies` argument.
pub(crate) enum ProxySource {
    List(Vec<ProxyConfig>),
    /// A function, and how many of its proxies to make ahead of time.
    Function(PyProxyFunction, Option<usize>),
}

impl ProxySource {
    /// Read `proxies` and `proxy_buffer` as both pools take them.
    pub(crate) fn resolve(
        proxies: &Bound<'_, PyAny>,
        proxy_buffer: Option<usize>,
    ) -> PyResult<Self> {
        if !proxies.is_callable() {
            // Upstream would buffer a list as well, which only reorders it, and
            // spins a thread for good on an empty one.
            if proxy_buffer.is_some() {
                return Err(PyValueError::new_err(
                    "proxy_buffer only applies when proxies is a function",
                ));
            }
            return Ok(Self::List(resolve_proxy_list(proxies)?));
        }
        if is_async_function(proxies)? {
            return Err(PyTypeError::new_err(
                "proxies must be a plain function, not an async one",
            ));
        }
        let function = PyProxyFunction {
            function: proxies.clone().unbind(),
        };
        Ok(Self::Function(function, proxy_buffer.filter(|n| *n > 0)))
    }
}

/// Upstream's `ProxyProvider` backed by a Python function returning a proxy
/// URL or a `ProxyConfig`.
pub(crate) struct PyProxyFunction {
    function: Py<PyAny>,
}

impl PyProxyFunction {
    fn call(&self, py: Python<'_>) -> PyResult<ProxyConfig> {
        resolve_proxy(&self.function.bind(py).call0()?)
    }
}

impl ProxyProvider for PyProxyFunction {
    /// `None` when the function fails; upstream's pools then ask again shortly,
    /// and never hand out a lease without a proxy, which would connect direct.
    fn next_proxy(&self) -> Option<ProxyConfig> {
        // `None` as well once the interpreter is gone.
        let err = match Python::try_attach(|py| self.call(py))? {
            Ok(proxy) => return Some(proxy),
            Err(err) => err,
        };
        if FAILURE.try_with(|_| ()).is_ok() {
            FAILURE.with(|failure| failure.set(Some(err)));
        } else {
            // Nothing is waiting on this call: it comes from upstream's
            // `proxy_buffer` thread.
            tracing::warn!(error = %err, "proxy_pool.proxy_function_failed");
            std::thread::sleep(BUFFER_RETRY_DELAY);
        }
        None
    }

    /// Every call makes a new proxy, so there is no list to count.
    fn len(&self) -> usize {
        1
    }

    /// Each proxy is new, so the pool keeps no failures or health for it.
    fn is_dynamic(&self) -> bool {
        true
    }
}

/// Run a pool's `acquire()` so that it raises what the proxy function raised
/// while it was calling it, instead of calling it again and again.
pub(crate) async fn acquiring<T>(acquire: impl Future<Output = T>) -> PyResult<T> {
    FAILURE
        .scope(Cell::new(None), async move {
            let mut acquire = pin!(acquire);
            poll_fn(|cx| match acquire.as_mut().poll(cx) {
                Poll::Ready(guard) => Poll::Ready(Ok(guard)),
                Poll::Pending => match FAILURE.with(Cell::take) {
                    Some(err) => Poll::Ready(Err(err)),
                    None => Poll::Pending,
                },
            })
            .await
        })
        .await
}
