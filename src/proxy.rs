//! Proxy pyclasses: immutable `ProxyConfig` values (including multi-hop chains),
//! plus `ProxyPool` / `BlockingProxyPool` and the `ProxyLease` they hand out,
//! `BadProxyConfig`, and `HealthCheckConfig`.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lkrequest::proxy::ProxyAuthenticator;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

use crate::client::blocking_runtime;
use crate::error::to_py_err;
use crate::proxy_source::{acquiring, ProxySource};
use crate::types::{is_async_function, validated_duration};

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

#[pyclass(name = "ProxyConfig", frozen, from_py_object)]
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

    /// Parse a single HTTP CONNECT, SOCKS5 or (with the `masque` feature)
    /// MASQUE proxy URL.
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

    /// Return a new config that authenticates this hop with a username and
    /// password, replacing any credential already set.
    fn with_user_pass(&self, username: &str, password: &str) -> PyResult<Self> {
        Ok(Self {
            inner: self
                .inner
                .clone()
                .with_user_pass(username, password)
                .map_err(to_py_err)?,
        })
    }

    /// Return a new config that authenticates this hop with a static HTTP
    /// auth-scheme and already-encoded credentials (`Bearer`, `Preshared`,
    /// ...), replacing any credential already set.
    fn with_http_auth(&self, scheme: &str, credentials: &str) -> PyResult<Self> {
        Ok(Self {
            inner: self
                .inner
                .clone()
                .with_http_auth(scheme, credentials)
                .map_err(to_py_err)?,
        })
    }

    /// Return a new config whose credential `authorize()` gives for each
    /// connection through this hop, replacing any credential already set.
    /// `identity` tells it apart from other credentials on the same address.
    fn with_custom_auth(&self, identity: String, authorize: &Bound<'_, PyAny>) -> PyResult<Self> {
        if !authorize.is_callable() {
            return Err(PyTypeError::new_err("authorize must be callable"));
        }
        if is_async_function(authorize)? {
            return Err(PyTypeError::new_err(
                "authorize must be a plain function, not an async one",
            ));
        }
        let authenticator = Arc::new(PyAuthenticator {
            identity,
            authorize: authorize.clone().unbind(),
        });
        Ok(Self {
            inner: self
                .inner
                .clone()
                .with_custom_auth(authenticator)
                .map_err(to_py_err)?,
        })
    }

    /// Return a new config that sends the credential in the given header:
    /// `"proxy-authorization"` (the default) or `"authorization"`.
    fn with_auth_header(&self, header: &str) -> PyResult<Self> {
        let header = match header.to_ascii_lowercase().as_str() {
            "proxy-authorization" => lkrequest::proxy::ProxyAuthHeader::ProxyAuthorization,
            "authorization" => lkrequest::proxy::ProxyAuthHeader::Authorization,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown proxy auth header: '{header}'. Use 'proxy-authorization' or 'authorization'"
                )));
            }
        };
        Ok(Self {
            inner: self.inner.clone().with_auth_header(header),
        })
    }

    fn hop_count(&self) -> usize {
        self.inner.hop_count()
    }

    /// Host of the proxy the client talks to last: the only one, or a chain's
    /// final hop, which connects to the target.
    #[getter]
    fn host(&self) -> &str {
        self.inner.host_port().0
    }

    /// Port of the proxy the client talks to last.
    #[getter]
    fn port(&self) -> u16 {
        self.inner.host_port().1
    }

    /// Whether a failed tunnel must never fall back to a direct connection,
    /// whatever `proxy_fallback_direct` says: true when a MASQUE hop is
    /// involved, as falling back would reveal the address it hides.
    #[getter]
    fn forbids_direct_fallback(&self) -> bool {
        self.inner.forbids_direct_fallback()
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

/// What `check_proxy()` runs: a tunnel through `proxy` to the target, names
/// resolved as `client` resolves them, and the seconds it took to set up.
pub(crate) fn proxy_check(
    client: &lkrequest::Client,
    proxy: &Bound<'_, PyAny>,
    target_host: &str,
    target_port: u16,
    timeout: f64,
) -> PyResult<impl std::future::Future<Output = PyResult<f64>> + Send + 'static> {
    let proxy = resolve_proxy(proxy)?;
    let timeout = validated_duration(timeout)?;
    let client = client.clone();
    let target_host = target_host.to_owned();
    Ok(async move {
        let latency = proxy
            .health_check(&target_host, target_port, timeout, client.resolver())
            .await
            .map_err(to_py_err)?;
        Ok(latency.as_secs_f64())
    })
}

/// Upstream's `ProxyAuthenticator` backed by a Python function giving the
/// header value. The identity is fixed, as `ProxyConfig.identity()` asks for
/// it on whatever thread it runs.
struct PyAuthenticator {
    identity: String,
    authorize: Py<PyAny>,
}

impl ProxyAuthenticator for PyAuthenticator {
    fn identity_fragment(&self) -> String {
        self.identity.clone()
    }

    /// Called as a connection is set up, on the thread setting it up. A
    /// failure sends no credential, which a proxy that wants one refuses.
    fn authorization_value(&self) -> Option<String> {
        // `None` as well once the interpreter is gone.
        let value = Python::try_attach(|py| self.authorize.bind(py).call0()?.extract())?;
        value.unwrap_or_else(|err: PyErr| {
            tracing::warn!(identity = %self.identity, error = %err, "proxy.authorize_failed");
            None
        })
    }
}

pub(crate) fn apply_session_proxy(
    builder: lkrequest::session::SessionBuilder,
    proxy: &Bound<'_, PyAny>,
) -> PyResult<lkrequest::session::SessionBuilder> {
    // Upstream's `SessionBuilder::proxy(&str)` only logs a URL it cannot parse
    // and builds the session without a proxy, so a typo would send every
    // request direct from this machine. Parse it here so it raises instead.
    Ok(builder.proxy_config(resolve_proxy(proxy)?))
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

/// A pool's `rotation` argument.
pub(crate) fn rotation_strategy(name: &str) -> PyResult<lkrequest::proxy::RotationStrategy> {
    match name {
        "round_robin" => Ok(lkrequest::proxy::RotationStrategy::RoundRobin),
        "random" => Ok(lkrequest::proxy::RotationStrategy::Random),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown rotation strategy: '{}'. Use 'round_robin' or 'random'",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

#[pyclass(name = "BadProxyConfig", from_py_object)]
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

#[pyclass(name = "HealthCheckConfig", from_py_object)]
#[derive(Clone)]
pub struct PyHealthCheckConfig {
    pub(crate) inner: lkrequest::HealthCheckConfig,
}

#[pymethods]
impl PyHealthCheckConfig {
    #[new]
    #[pyo3(signature = (*, interval=60.0, timeout=5.0, target_host="www.google.com", target_port=443, tunnel_probe=false, masque=None))]
    fn new(
        interval: f64,
        timeout: f64,
        target_host: &str,
        target_port: u16,
        tunnel_probe: bool,
        masque: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        // `HealthCheckConfig` is `#[non_exhaustive]`, so start from the default
        // and assign the fields rather than writing a literal.
        let mut inner = lkrequest::HealthCheckConfig::default();
        inner.interval = validated_duration(interval)?;
        inner.timeout = validated_duration(timeout)?;
        inner.target_host = target_host.to_string();
        inner.target_port = target_port;
        // A plain TCP connect proves nothing about a MASQUE proxy, so upstream
        // skips those unless the CONNECT-UDP probe is switched on.
        let masque = crate::masque::resolve(masque.as_ref())?;
        crate::masque::apply_to_health_check(&mut inner, tunnel_probe, masque)?;
        Ok(PyHealthCheckConfig { inner })
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

/// The upstream pool both `ProxyPool` classes wrap.
fn build_proxy_pool(
    proxies: &Bound<'_, PyAny>,
    max_proxies: Option<usize>,
    rotation: Option<&str>,
    bad_proxy_config: Option<PyBadProxyConfig>,
    health_check: Option<PyHealthCheckConfig>,
    proxy_buffer: Option<usize>,
) -> PyResult<lkrequest::ProxyPool> {
    let mut builder = match ProxySource::resolve(proxies, proxy_buffer)? {
        ProxySource::List(configs) => lkrequest::ProxyPool::builder().proxies(configs),
        ProxySource::Function(function, buffer) => {
            let builder = lkrequest::ProxyPool::builder().proxy_provider(function);
            match buffer {
                Some(capacity) => builder.proxy_buffer(capacity),
                None => builder,
            }
        }
    };
    if let Some(n) = max_proxies {
        builder = builder.max_proxies(n);
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

#[pyclass(name = "ProxyPool")]
pub struct PyProxyPool {
    pub(crate) inner: lkrequest::ProxyPool,
}

#[pymethods]
impl PyProxyPool {
    #[new]
    #[pyo3(signature = (proxies, *, max_proxies=None, rotation=None, bad_proxy_config=None, health_check=None, proxy_buffer=None))]
    fn new(
        proxies: &Bound<'_, PyAny>,
        max_proxies: Option<usize>,
        rotation: Option<&str>,
        bad_proxy_config: Option<PyBadProxyConfig>,
        health_check: Option<PyHealthCheckConfig>,
        proxy_buffer: Option<usize>,
    ) -> PyResult<Self> {
        Ok(PyProxyPool {
            inner: build_proxy_pool(
                proxies,
                max_proxies,
                rotation,
                bad_proxy_config,
                health_check,
                proxy_buffer,
            )?,
        })
    }

    /// Waits while every proxy of a non-empty pool is cooling down, rather than
    /// answering "no proxy" (a direct connection); only an empty pool hands out
    /// a lease whose `proxy` is `None`.
    fn acquire<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        crate::bridge::future_into_py(py, lease(self.inner.clone()))
    }

    /// Record a failure of `lease`'s proxy, release the lease and acquire a new
    /// one. Releasing first means a pool whose `max_proxies` are all taken does
    /// not wait on the share the old lease held.
    fn acquire_fresh<'py>(
        &self,
        py: Python<'py>,
        lease: &PyProxyLease,
    ) -> PyResult<Bound<'py, PyAny>> {
        lease.mark_bad();
        lease.release();
        self.acquire(py)
    }

    fn mark_bad(&self, identity: &str) {
        tracing::info!(proxy = %identity, "proxy_pool.mark_bad");
        self.inner.mark_bad_proxy(identity);
    }

    /// How many leases can be out at once (`max_proxies`).
    #[getter]
    fn max_concurrent(&self) -> usize {
        self.inner.max_concurrent()
    }

    fn __repr__(&self) -> String {
        "<ProxyPool>".to_string()
    }
}

#[pyclass(name = "BlockingProxyPool")]
pub struct PyBlockingProxyPool {
    inner: lkrequest::ProxyPool,
}

#[pymethods]
impl PyBlockingProxyPool {
    #[new]
    #[pyo3(signature = (proxies, *, max_proxies=None, rotation=None, bad_proxy_config=None, health_check=None, proxy_buffer=None))]
    fn new(
        proxies: &Bound<'_, PyAny>,
        max_proxies: Option<usize>,
        rotation: Option<&str>,
        bad_proxy_config: Option<PyBadProxyConfig>,
        health_check: Option<PyHealthCheckConfig>,
        proxy_buffer: Option<usize>,
    ) -> PyResult<Self> {
        Ok(PyBlockingProxyPool {
            inner: build_proxy_pool(
                proxies,
                max_proxies,
                rotation,
                bad_proxy_config,
                health_check,
                proxy_buffer,
            )?,
        })
    }

    /// As `ProxyPool.acquire()`, blocking until a proxy is leased.
    fn acquire(&self, py: Python<'_>) -> PyResult<PyProxyLease> {
        let pool = self.inner.clone();
        py.detach(|| blocking_runtime().block_on(lease(pool)))
    }

    /// As `ProxyPool.acquire_fresh()`.
    fn acquire_fresh(&self, py: Python<'_>, lease: &PyProxyLease) -> PyResult<PyProxyLease> {
        lease.mark_bad();
        lease.release();
        self.acquire(py)
    }

    fn mark_bad(&self, identity: &str) {
        tracing::info!(proxy = %identity, "proxy_pool.mark_bad");
        self.inner.mark_bad_proxy(identity);
    }

    #[getter]
    fn max_concurrent(&self) -> usize {
        self.inner.max_concurrent()
    }

    fn __repr__(&self) -> String {
        "<BlockingProxyPool>".to_string()
    }
}

/// Wait for a proxy from `pool` and wrap it in a `ProxyLease`.
async fn lease(pool: lkrequest::ProxyPool) -> PyResult<PyProxyLease> {
    let guard = acquiring(pool.acquire()).await?;
    let proxy = guard.proxy().cloned();
    tracing::debug!(
        proxy = %proxy.as_ref().map(|p| p.to_string()).unwrap_or_default(),
        "proxy_pool.acquire"
    );
    Ok(PyProxyLease {
        proxy,
        pool,
        guard: Mutex::new(Some(guard)),
    })
}

// ---------------------------------------------------------------------------
// ProxyLease
// ---------------------------------------------------------------------------

/// A proxy handed out by a `ProxyPool`, together with one of the pool's
/// `max_proxies` shares, which goes back on `release()`, at the end of a `with`
/// or `async with` block, or when the lease is collected.
#[pyclass(name = "ProxyLease", frozen)]
pub struct PyProxyLease {
    /// `None` only from an empty pool, which means a direct connection.
    proxy: Option<lkrequest::proxy::ProxyConfig>,
    pool: lkrequest::ProxyPool,
    /// The upstream guard holds the share; `None` once released.
    guard: Mutex<Option<lkrequest::ProxyGuard>>,
}

#[pymethods]
impl PyProxyLease {
    /// The proxy to pass to `session(proxy=...)`, credentials included.
    #[getter]
    fn proxy(&self) -> Option<PyProxyConfig> {
        self.proxy.clone().map(|inner| PyProxyConfig { inner })
    }

    #[getter]
    fn released(&self) -> bool {
        lock(&self.guard).is_none()
    }

    /// Record a failure of this proxy, as `ProxyPool.mark_bad()` does. Still
    /// works after the lease is released.
    fn mark_bad(&self) {
        if let Some(proxy) = &self.proxy {
            self.pool.mark_bad_proxy(&proxy.identity());
        }
    }

    /// Give the share back to the pool. Releasing twice is harmless.
    fn release(&self) {
        lock(&self.guard).take();
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<Bound<'_, PyAny>>,
        _exc_val: Option<Bound<'_, PyAny>>,
        _exc_tb: Option<Bound<'_, PyAny>>,
    ) -> bool {
        self.release();
        false
    }

    fn __aenter__<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let lease = slf.unbind();
        crate::bridge::future_into_py(py, async move { Ok(lease) })
    }

    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Bound<'py, PyAny>,
        _exc_val: Bound<'py, PyAny>,
        _exc_tb: Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.release();
        crate::bridge::future_into_py(py, async move { Ok(false) })
    }

    fn __repr__(&self) -> String {
        let proxy = match &self.proxy {
            Some(proxy) => format!("'{proxy}'"),
            None => "None".to_string(),
        };
        let state = if self.released() { " released" } else { "" };
        format!("<ProxyLease proxy={proxy}{state}>")
    }
}

/// Poisoning needs a panic while the lock is held, and nothing here does more
/// than take an `Option` or test it; the data is as valid afterwards as before.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
