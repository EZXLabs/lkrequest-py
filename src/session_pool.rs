//! Session-pool pyclasses: `SessionPool` / `BlockingSessionPool` that allocate
//! per-proxy sessions, plus the `SessionGuard` handles that lease and return
//! them.

use pyo3::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::client::{blocking_runtime, PyBlockingClient, PyClient};
use crate::proxy::{rotation_strategy, PyBadProxyConfig, PyHealthCheckConfig};
use crate::proxy_source::{acquiring, ProxySource};
use crate::session::{PyBlockingSession, PySession};
use crate::session_state::SessionState;
use crate::types::validated_duration;

/// The upstream pool both `SessionPool` classes wrap.
fn build_session_pool(
    client: &lkrequest::Client,
    proxies: &Bound<'_, PyAny>,
    max_sessions: Option<usize>,
    idle_timeout: Option<f64>,
    rotation: Option<&str>,
    bad_proxy_config: Option<PyBadProxyConfig>,
    health_check: Option<PyHealthCheckConfig>,
    proxy_buffer: Option<usize>,
) -> PyResult<lkrequest::SessionPool> {
    let builder = lkrequest::SessionPool::builder().client(client);
    let mut builder = match ProxySource::resolve(proxies, proxy_buffer)? {
        ProxySource::List(configs) => builder.proxies(configs),
        ProxySource::Function(function, buffer) => {
            let builder = builder.proxy_provider(function);
            match buffer {
                Some(capacity) => builder.proxy_buffer(capacity),
                None => builder,
            }
        }
    };
    if let Some(n) = max_sessions {
        builder = builder.max_sessions(n);
    }
    if let Some(t) = idle_timeout {
        builder = builder.idle_timeout(validated_duration(t)?);
    }
    if let Some(strategy) = rotation {
        builder = builder.rotation(rotation_strategy(strategy)?);
    }
    if let Some(bpc) = bad_proxy_config {
        builder = builder.bad_proxy_config(bpc.inner);
    }
    if let Some(hc) = health_check {
        builder = builder.health_check(hc.inner);
    }
    let _guard = blocking_runtime().enter();
    Ok(builder.build())
}

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
    #[pyo3(signature = (client, proxies, *, max_sessions=None, idle_timeout=None, rotation=None, bad_proxy_config=None, health_check=None, proxy_buffer=None))]
    fn new(
        client: &PyClient,
        proxies: &Bound<'_, PyAny>,
        max_sessions: Option<usize>,
        idle_timeout: Option<f64>,
        rotation: Option<&str>,
        bad_proxy_config: Option<PyBadProxyConfig>,
        health_check: Option<PyHealthCheckConfig>,
        proxy_buffer: Option<usize>,
    ) -> PyResult<Self> {
        Ok(PySessionPool {
            inner: build_session_pool(
                &client.inner,
                proxies,
                max_sessions,
                idle_timeout,
                rotation,
                bad_proxy_config,
                health_check,
                proxy_buffer,
            )?,
        })
    }

    fn acquire<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let pool = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            tracing::debug!("session_pool.acquire");
            let guard = acquiring(pool.acquire()).await?;
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
            let guard = acquiring(pool.acquire()).await?;
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
                state: SessionState::default(),
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
                state: SessionState::default(),
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
    #[pyo3(signature = (client, proxies, *, max_sessions=None, idle_timeout=None, rotation=None, bad_proxy_config=None, health_check=None, proxy_buffer=None))]
    fn new(
        client: &PyBlockingClient,
        proxies: &Bound<'_, PyAny>,
        max_sessions: Option<usize>,
        idle_timeout: Option<f64>,
        rotation: Option<&str>,
        bad_proxy_config: Option<PyBadProxyConfig>,
        health_check: Option<PyHealthCheckConfig>,
        proxy_buffer: Option<usize>,
    ) -> PyResult<Self> {
        Ok(PyBlockingSessionPool {
            inner: build_session_pool(
                &client.inner,
                proxies,
                max_sessions,
                idle_timeout,
                rotation,
                bad_proxy_config,
                health_check,
                proxy_buffer,
            )?,
        })
    }

    fn acquire(&self, py: Python<'_>) -> PyResult<PyBlockingSessionGuard> {
        let pool = self.inner.clone();
        py.detach(|| {
            let guard = blocking_runtime().block_on(acquiring(pool.acquire()))?;
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
        py.detach(|| {
            let guard = blocking_runtime().block_on(acquiring(pool.acquire()))?;
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
        py.detach(|| {
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
            state: SessionState::default(),
            base_url: None,
        })
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyResult<PyBlockingSession> {
        let g = slf.guard.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("SessionGuard already released")
        })?;
        Ok(PyBlockingSession {
            inner: (**g).clone(),
            state: SessionState::default(),
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
