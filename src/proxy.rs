//! Proxy pyclasses: immutable `ProxyConfig` values (including multi-hop chains),
//! plus `ProxyPool`, `BadProxyConfig`, and `HealthCheckConfig`.

use pyo3::prelude::*;

use crate::client::blocking_runtime;
use crate::error::to_py_err;
use crate::types::validated_duration;

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

#[pyclass(name = "ProxyConfig", frozen)]
#[derive(Clone)]
pub struct PyProxyConfig {
    pub(crate) inner: lkrequest::proxy::ProxyConfig,
}

#[pymethods]
impl PyProxyConfig {
    #[new]
    fn new(url: &str) -> PyResult<Self> {
        Self::parse(url)
    }

    /// Parse a single HTTP CONNECT or SOCKS5 proxy URL.
    #[staticmethod]
    fn parse(url: &str) -> PyResult<Self> {
        Ok(Self {
            inner: lkrequest::proxy::ProxyConfig::parse(url).map_err(to_py_err)?,
        })
    }

    /// Build an ordered multi-hop chain (client -> first -> ... -> target).
    #[staticmethod]
    fn parse_chain(urls: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            inner: lkrequest::proxy::ProxyConfig::parse_chain(resolve_proxy_urls(urls)?)
                .map_err(to_py_err)?,
        })
    }

    /// Return a new config with the supplied proxies prepended as upstream hops.
    fn through(&self, hops: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            inner: self.inner.clone().through(resolve_proxy_list(hops)?),
        })
    }

    fn hop_count(&self) -> usize {
        self.inner.hop_count()
    }

    fn identity(&self) -> String {
        self.inner.identity()
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!(
            "<ProxyConfig path='{}' hops={}>",
            self.inner,
            self.inner.hop_count()
        )
    }
}

pub(crate) fn apply_session_proxy(
    builder: lkrequest::session::SessionBuilder,
    proxy: &Bound<'_, PyAny>,
) -> PyResult<lkrequest::session::SessionBuilder> {
    if let Ok(url) = proxy.extract::<String>() {
        Ok(builder.proxy(&url))
    } else if let Ok(config) = proxy.extract::<PyProxyConfig>() {
        Ok(builder.proxy_config(config.inner))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "proxy must be str or ProxyConfig",
        ))
    }
}

pub(crate) fn resolve_proxy(obj: &Bound<'_, PyAny>) -> PyResult<lkrequest::proxy::ProxyConfig> {
    if let Ok(url) = obj.extract::<String>() {
        lkrequest::proxy::ProxyConfig::parse(&url).map_err(to_py_err)
    } else if let Ok(config) = obj.extract::<PyProxyConfig>() {
        Ok(config.inner)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "proxy must be str or ProxyConfig",
        ))
    }
}

fn resolve_proxy_urls(urls: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    if urls.extract::<String>().is_ok() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "proxy URLs must be an iterable of str, not a single str",
        ));
    }

    let iter = urls.try_iter().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("proxy URLs must be an iterable of str")
    })?;
    iter.map(|item| {
        item?
            .extract::<String>()
            .map_err(|_| pyo3::exceptions::PyTypeError::new_err("every proxy URL must be str"))
    })
    .collect()
}

pub(crate) fn resolve_proxy_list(
    proxies: &Bound<'_, PyAny>,
) -> PyResult<Vec<lkrequest::proxy::ProxyConfig>> {
    if proxies.extract::<String>().is_ok() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "proxies must be an iterable of str or ProxyConfig, not a single str",
        ));
    }

    let iter = proxies.try_iter().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("proxies must be an iterable of str or ProxyConfig")
    })?;
    iter.map(|item| resolve_proxy(&item?)).collect()
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

#[pyclass(name = "BadProxyConfig")]
#[derive(Clone)]
pub struct PyBadProxyConfig {
    pub(crate) inner: lkrequest::BadProxyConfig,
}

#[pymethods]
impl PyBadProxyConfig {
    #[new]
    #[pyo3(signature = (*, failure_threshold=3, window=60.0, cooldown_duration=300.0, max_cooldowns=5))]
    fn new(
        failure_threshold: u32,
        window: f64,
        cooldown_duration: f64,
        max_cooldowns: u32,
    ) -> PyResult<Self> {
        Ok(PyBadProxyConfig {
            inner: lkrequest::BadProxyConfig {
                failure_threshold,
                window: validated_duration(window)?,
                cooldown_duration: validated_duration(cooldown_duration)?,
                max_cooldowns,
            },
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "BadProxyConfig(failure_threshold={}, cooldown={:?})",
            self.inner.failure_threshold, self.inner.cooldown_duration
        )
    }
}

#[pyclass(name = "HealthCheckConfig")]
#[derive(Clone)]
pub struct PyHealthCheckConfig {
    pub(crate) inner: lkrequest::HealthCheckConfig,
}

#[pymethods]
impl PyHealthCheckConfig {
    #[new]
    #[pyo3(signature = (*, interval=60.0, timeout=5.0, target_host="www.google.com", target_port=443))]
    fn new(interval: f64, timeout: f64, target_host: &str, target_port: u16) -> PyResult<Self> {
        Ok(PyHealthCheckConfig {
            inner: lkrequest::HealthCheckConfig {
                interval: validated_duration(interval)?,
                timeout: validated_duration(timeout)?,
                target_host: target_host.to_string(),
                target_port,
            },
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "HealthCheckConfig(interval={:?}, target={}:{})",
            self.inner.interval, self.inner.target_host, self.inner.target_port
        )
    }
}

// ---------------------------------------------------------------------------
// ProxyPool
// ---------------------------------------------------------------------------

#[pyclass(name = "ProxyPool")]
pub struct PyProxyPool {
    pub(crate) inner: lkrequest::ProxyPool,
}

#[pymethods]
impl PyProxyPool {
    #[new]
    #[pyo3(signature = (proxies, *, max_proxies=None, rotation=None, bad_proxy_config=None, health_check=None))]
    fn new(
        proxies: &Bound<'_, PyAny>,
        max_proxies: Option<usize>,
        rotation: Option<&str>,
        bad_proxy_config: Option<PyBadProxyConfig>,
        health_check: Option<PyHealthCheckConfig>,
    ) -> PyResult<Self> {
        let configs = resolve_proxy_list(proxies)?;
        let mut builder = lkrequest::ProxyPool::builder().proxies(configs);
        if let Some(n) = max_proxies {
            builder = builder.max_proxies(n);
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
        if let Some(bpc) = bad_proxy_config {
            builder = builder.bad_proxy_config(bpc.inner);
        }
        if let Some(hc) = health_check {
            builder = builder.health_check(hc.inner);
        }
        let _guard = blocking_runtime().enter();
        Ok(PyProxyPool {
            inner: builder.build(),
        })
    }

    fn acquire<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let pool = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = pool.acquire().await;
            let proxy_url = guard.proxy().map(|p| p.identity()).unwrap_or_default();
            tracing::debug!(proxy = %proxy_url, "proxy_pool.acquire");
            Ok(proxy_url)
        })
    }

    fn mark_bad(&self, identity: &str) {
        tracing::info!(proxy = %identity, "proxy_pool.mark_bad");
        self.inner.mark_bad_proxy(identity);
    }

    fn __repr__(&self) -> String {
        "<ProxyPool>".to_string()
    }
}
