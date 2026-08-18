//! Session-pool pyclasses: `SessionPool` / `BlockingSessionPool` that allocate
//! per-proxy sessions, plus the `SessionGuard` handles that lease and return
//! them.

use pyo3::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::client::{blocking_runtime, PyBlockingClient, PyClient};
use crate::proxy::resolve_proxy_list;
use crate::session::{EventHooks, PyBlockingSession, PySession};
use crate::types::validated_duration;

// ---------------------------------------------------------------------------
// Async SessionPool
// ---------------------------------------------------------------------------

#[pyclass(name = "SessionPool")]
#[derive(Clone)]
pub struct PySessionPool {
    pub(crate) inner: lkrequest::SessionPool,
}

#[pymethods]
impl PySessionPool {
    #[new]
    #[pyo3(signature = (client, proxies, *, max_sessions=None, idle_timeout=None, rotation=None))]
    fn new(
        client: &PyClient,
        proxies: &Bound<'_, PyAny>,
        max_sessions: Option<usize>,
        idle_timeout: Option<f64>,
        rotation: Option<&str>,
    ) -> PyResult<Self> {
        let configs = resolve_proxy_list(proxies)?;
        let mut builder = lkrequest::SessionPool::builder()
            .client(&client.inner)
            .proxies(configs);
        if let Some(n) = max_sessions {
            builder = builder.max_sessions(n);
        }
        if let Some(t) = idle_timeout {
            builder = builder.idle_timeout(validated_duration(t)?);
        }
        if let Some(strategy) = rotation {
            let rs = match strategy {
                "round_robin" => lkrequest::proxy::RotationStrategy::RoundRobin,
                "random" => lkrequest::proxy::RotationStrategy::Random,
                other => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Unknown rotation strategy: '{}'. Use 'round_robin' or 'random'",
                        other
                    )));
                }
            };
            builder = builder.rotation(rs);
        }
        let _guard = blocking_runtime().enter();
        Ok(PySessionPool {
            inner: builder.build(),
        })
    }

    fn acquire<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let pool = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            tracing::debug!("session_pool.acquire");
            let guard = pool.acquire().await;
            Ok(PySessionGuard {
                guard: Arc::new(Mutex::new(Some(guard))),
            })
        })
    }

    fn acquire_fresh<'py>(
        &self,
        py: Python<'py>,
        bad_guard: &PySessionGuard,
    ) -> PyResult<Bound<'py, PyAny>> {
        let pool = self.inner.clone();
        let old_guard = bad_guard.guard.clone();
        crate::bridge::future_into_py(py, async move {
            tracing::debug!("session_pool.acquire_fresh (marking old session bad)");
            {
                let mut lock = old_guard.lock().await;
                if let Some(ref g) = *lock {
                    pool.mark_bad(g);
                }
                *lock = None;
            }
            let guard = pool.acquire().await;
            Ok(PySessionGuard {
                guard: Arc::new(Mutex::new(Some(guard))),
            })
        })
    }

    fn mark_bad<'py>(
        &self,
        py: Python<'py>,
        session_guard: &PySessionGuard,
    ) -> PyResult<Bound<'py, PyAny>> {
        let pool = self.inner.clone();
        let guard_arc = session_guard.guard.clone();
        crate::bridge::future_into_py(py, async move {
            let lock = guard_arc.lock().await;
            if let Some(ref g) = *lock {
                pool.mark_bad(g);
            }
            Ok(())
        })
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let pool = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let stats = pool.stats().await;
            Ok(crate::types::PySessionPoolStats::from(stats))
        })
    }

    fn __repr__(&self) -> String {
        "<SessionPool>".to_string()
    }
}

// ---------------------------------------------------------------------------
// Async SessionGuard — supports `async with`
// ---------------------------------------------------------------------------

#[pyclass(name = "SessionGuard")]
pub struct PySessionGuard {
    guard: Arc<Mutex<Option<lkrequest::SessionGuard>>>,
}

#[pymethods]
impl PySessionGuard {
    #[getter]
    fn session<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let guard_arc = self.guard.clone();
        crate::bridge::future_into_py(py, async move {
            let lock = guard_arc.lock().await;
            let g = lock.as_ref().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("SessionGuard already released")
            })?;
            Ok(PySession {
                inner: (**g).clone(),
                hooks: EventHooks::default(),
                base_url: None,
            })
        })
    }

    fn __aenter__<'py>(slf: PyRef<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let guard_arc = slf.guard.clone();
        crate::bridge::future_into_py(py, async move {
            let lock = guard_arc.lock().await;
            let g = lock.as_ref().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("SessionGuard already released")
            })?;
            Ok(PySession {
                inner: (**g).clone(),
                hooks: EventHooks::default(),
                base_url: None,
            })
        })
    }

    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Bound<'py, PyAny>,
        _exc_val: Bound<'py, PyAny>,
        _exc_tb: Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let guard_arc = self.guard.clone();
        crate::bridge::future_into_py(py, async move {
            let mut lock = guard_arc.lock().await;
            *lock = None;
            Ok(false)
        })
    }

    fn __repr__(&self) -> String {
        "<SessionGuard>".to_string()
    }
}

// ---------------------------------------------------------------------------
// Blocking SessionPool
// ---------------------------------------------------------------------------

#[pyclass(name = "BlockingSessionPool")]
#[derive(Clone)]
pub struct PyBlockingSessionPool {
    pub(crate) inner: lkrequest::SessionPool,
}

#[pymethods]
impl PyBlockingSessionPool {
    #[new]
    #[pyo3(signature = (client, proxies, *, max_sessions=None, idle_timeout=None, rotation=None))]
    fn new(
        client: &PyBlockingClient,
        proxies: &Bound<'_, PyAny>,
        max_sessions: Option<usize>,
        idle_timeout: Option<f64>,
        rotation: Option<&str>,
    ) -> PyResult<Self> {
        let configs = resolve_proxy_list(proxies)?;
        let mut builder = lkrequest::SessionPool::builder()
            .client(&client.inner)
            .proxies(configs);
        if let Some(n) = max_sessions {
            builder = builder.max_sessions(n);
        }
        if let Some(t) = idle_timeout {
            builder = builder.idle_timeout(validated_duration(t)?);
        }
        if let Some(strategy) = rotation {
            let rs = match strategy {
                "round_robin" => lkrequest::proxy::RotationStrategy::RoundRobin,
                "random" => lkrequest::proxy::RotationStrategy::Random,
                other => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "Unknown rotation strategy: '{}'. Use 'round_robin' or 'random'",
                        other
                    )));
                }
            };
            builder = builder.rotation(rs);
        }
        let _guard = blocking_runtime().enter();
        Ok(PyBlockingSessionPool {
            inner: builder.build(),
        })
    }

    fn acquire(&self, py: Python<'_>) -> PyResult<PyBlockingSessionGuard> {
        let pool = self.inner.clone();
        py.allow_threads(|| {
            let guard = blocking_runtime().block_on(pool.acquire());
            Ok(PyBlockingSessionGuard { guard: Some(guard) })
        })
    }

    fn acquire_fresh(
        &self,
        py: Python<'_>,
        bad_guard: &mut PyBlockingSessionGuard,
    ) -> PyResult<PyBlockingSessionGuard> {
        let pool = self.inner.clone();
        if let Some(ref g) = bad_guard.guard {
            pool.mark_bad(g);
        }
        bad_guard.guard = None;
        py.allow_threads(|| {
            let guard = blocking_runtime().block_on(pool.acquire());
            Ok(PyBlockingSessionGuard { guard: Some(guard) })
        })
    }

    fn mark_bad(&self, session_guard: &PyBlockingSessionGuard) {
        if let Some(ref g) = session_guard.guard {
            self.inner.mark_bad(g);
        }
    }

    fn stats(&self, py: Python<'_>) -> PyResult<crate::types::PySessionPoolStats> {
        let pool = self.inner.clone();
        py.allow_threads(|| {
            blocking_runtime().block_on(async move {
                let stats = pool.stats().await;
                Ok(crate::types::PySessionPoolStats::from(stats))
            })
        })
    }

    fn __repr__(&self) -> String {
        "<BlockingSessionPool>".to_string()
    }
}

// ---------------------------------------------------------------------------
// Blocking SessionGuard — supports `with`
// ---------------------------------------------------------------------------

#[pyclass(name = "BlockingSessionGuard")]
pub struct PyBlockingSessionGuard {
    guard: Option<lkrequest::SessionGuard>,
}

#[pymethods]
impl PyBlockingSessionGuard {
    #[getter]
    fn session(&self) -> PyResult<PyBlockingSession> {
        let g = self.guard.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("SessionGuard already released")
        })?;
        Ok(PyBlockingSession {
            inner: (**g).clone(),
            hooks: EventHooks::default(),
            base_url: None,
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyResult<PyBlockingSession> {
        let g = slf.guard.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("SessionGuard already released")
        })?;
        Ok(PyBlockingSession {
            inner: (**g).clone(),
            hooks: EventHooks::default(),
            base_url: None,
        })
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &mut self,
        _exc_type: Option<Bound<'_, PyAny>>,
        _exc_val: Option<Bound<'_, PyAny>>,
        _exc_tb: Option<Bound<'_, PyAny>>,
    ) -> bool {
        self.guard = None;
        false
    }

    fn __repr__(&self) -> String {
        "<BlockingSessionGuard>".to_string()
    }
}
