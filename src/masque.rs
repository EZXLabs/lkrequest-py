//! MASQUE (RFC 9298 CONNECT-UDP) proxy bindings.
//!
//! [`PyMasqueConfig`] only exists with the `masque` feature. The helpers below
//! exist in every build, so `Client(masque=...)` and
//! `HealthCheckConfig(masque=..., tunnel_probe=...)` keep one signature across
//! feature sets: without the feature they refuse a value with an actionable
//! message rather than silently ignoring it.

use pyo3::prelude::*;

/// The outer-hop configuration the helpers pass around.
#[cfg(feature = "masque")]
pub(crate) type OuterConfig = lkrequest::proxy::MasqueOuterConfig;

/// Uninhabited without the feature, so [`resolve`] can never produce one and
/// the code consuming it reduces to an empty `match`.
#[cfg(not(feature = "masque"))]
pub(crate) type OuterConfig = std::convert::Infallible;

/// Configuration of the hop to a MASQUE proxy — the outer HTTP/3 connection
/// that tunnels go through. Only available when built with the `masque` feature.
///
/// Experimental, upstream and here: this class, the `masque=` / `tunnel_probe=`
/// parameters and the behaviour of `masque://` routes may change in any
/// release without a deprecation period.
///
/// Trust here is deliberately separate from the client's own `verify` /
/// `ca_cert*` options, which govern the tunneled connection to the origin.
/// Neither inherits from the other, so relaxing one hop for debugging never
/// silently relaxes the other.
#[cfg(feature = "masque")]
#[pyclass(name = "MasqueConfig", frozen)]
#[derive(Clone)]
pub struct PyMasqueConfig {
    pub(crate) inner: lkrequest::proxy::MasqueOuterConfig,
}

#[cfg(feature = "masque")]
#[pymethods]
impl PyMasqueConfig {
    #[new]
    #[pyo3(signature = (
        *,
        server_name=None,
        ca_cert=None,
        ca_cert_pem=None,
        use_native_certs=true,
        verify=true,
        tunnel_idle_timeout=Some(lkrequest::proxy::masque::DEFAULT_TUNNEL_IDLE_TIMEOUT.as_secs_f64()),
        max_idle_tunnels=lkrequest::proxy::masque::DEFAULT_MAX_IDLE_TUNNELS,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        server_name: Option<String>,
        ca_cert: Option<String>,
        ca_cert_pem: Option<Vec<u8>>,
        use_native_certs: bool,
        verify: bool,
        tunnel_idle_timeout: Option<f64>,
        max_idle_tunnels: usize,
    ) -> PyResult<Self> {
        let mut inner = lkrequest::proxy::MasqueOuterConfig::default();
        inner.server_name = server_name;
        inner.use_native_certs = use_native_certs;
        inner.verify = verify;
        inner.tunnel_idle_timeout = tunnel_idle_timeout
            .map(crate::types::validated_duration)
            .transpose()?;
        inner.max_idle_tunnels = max_idle_tunnels;
        if let Some(path) = ca_cert {
            let pem = std::fs::read(&path).map_err(|e| {
                pyo3::exceptions::PyIOError::new_err(format!(
                    "Failed to read MASQUE CA cert '{}': {}",
                    path, e
                ))
            })?;
            add_ca_certs_pem(&mut inner, &pem)?;
        }
        if let Some(pem) = ca_cert_pem {
            add_ca_certs_pem(&mut inner, &pem)?;
        }
        Ok(PyMasqueConfig { inner })
    }

    #[getter]
    fn server_name(&self) -> Option<String> {
        self.inner.server_name.clone()
    }

    #[getter]
    fn use_native_certs(&self) -> bool {
        self.inner.use_native_certs
    }

    #[getter]
    fn verify(&self) -> bool {
        self.inner.verify
    }

    /// Number of extra trust anchors loaded from `ca_cert` / `ca_cert_pem`.
    #[getter]
    fn ca_cert_count(&self) -> usize {
        self.inner.extra_roots.len()
    }

    #[getter]
    fn tunnel_idle_timeout(&self) -> Option<f64> {
        self.inner.tunnel_idle_timeout.map(|d| d.as_secs_f64())
    }

    #[getter]
    fn max_idle_tunnels(&self) -> usize {
        self.inner.max_idle_tunnels
    }

    fn __repr__(&self) -> String {
        // Python spellings, so the repr reads like the constructor call.
        let py_bool = |b: bool| if b { "True" } else { "False" };
        let server_name = match &self.inner.server_name {
            Some(name) => format!("'{name}'"),
            None => "None".to_string(),
        };
        format!(
            "MasqueConfig(server_name={}, verify={}, ca_cert_count={}, use_native_certs={})",
            server_name,
            py_bool(self.inner.verify),
            self.inner.extra_roots.len(),
            py_bool(self.inner.use_native_certs)
        )
    }
}

/// Load a PEM bundle. Upstream rejects a malformed bundle, or one holding no
/// certificate, as `InvalidConfig` (-> `ValueError`) instead of leaving the
/// trust store silently unchanged.
#[cfg(feature = "masque")]
fn add_ca_certs_pem(inner: &mut OuterConfig, pem: &[u8]) -> PyResult<()> {
    inner
        .add_ca_certs_pem(pem)
        .map(|_| ())
        .map_err(crate::error::to_py_err)
}

/// Extract the `masque=` argument shared by `Client` and `HealthCheckConfig`.
#[cfg(feature = "masque")]
pub(crate) fn resolve(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<OuterConfig>> {
    obj.map(|obj| {
        obj.extract::<PyMasqueConfig>()
            .map(|config| config.inner)
            .map_err(|_| pyo3::exceptions::PyTypeError::new_err("masque must be a MasqueConfig"))
    })
    .transpose()
}

#[cfg(not(feature = "masque"))]
pub(crate) fn resolve(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<OuterConfig>> {
    match obj {
        None => Ok(None),
        Some(_) => Err(feature_required("masque")),
    }
}

/// Install the outer-hop configuration on a client builder.
#[cfg(feature = "masque")]
pub(crate) fn apply_to_client(
    builder: lkrequest::client::ClientBuilder,
    config: OuterConfig,
) -> lkrequest::client::ClientBuilder {
    builder.masque(config)
}

#[cfg(not(feature = "masque"))]
pub(crate) fn apply_to_client(
    _builder: lkrequest::client::ClientBuilder,
    config: OuterConfig,
) -> lkrequest::client::ClientBuilder {
    match config {}
}

/// Configure the CONNECT-UDP health-check probe.
///
/// Upstream skips the probe with only a log line when it is enabled without an
/// outer configuration, rather than guess trust anchors and blacklist a healthy
/// proxy fronted by a private CA. Here both arrive in the same call, so the
/// combination is refused up front instead of turning into a silent no-op; an
/// explicit `MasqueConfig()` still selects the operating system's trust store.
#[cfg(feature = "masque")]
pub(crate) fn apply_to_health_check(
    health: &mut lkrequest::HealthCheckConfig,
    tunnel_probe: bool,
    config: Option<OuterConfig>,
) -> PyResult<()> {
    if tunnel_probe && config.is_none() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "tunnel_probe=True needs masque=MasqueConfig(...): the probe must know which \
             trust anchors the proxy's certificate chains to",
        ));
    }
    health.tunnel_probe = tunnel_probe;
    health.masque_outer_config = config;
    Ok(())
}

#[cfg(not(feature = "masque"))]
pub(crate) fn apply_to_health_check(
    _health: &mut lkrequest::HealthCheckConfig,
    tunnel_probe: bool,
    config: Option<OuterConfig>,
) -> PyResult<()> {
    if let Some(config) = config {
        match config {}
    }
    if tunnel_probe {
        return Err(feature_required("tunnel_probe"));
    }
    Ok(())
}

#[cfg(not(feature = "masque"))]
fn feature_required(option: &str) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!(
        "{option} requires building lkrequest-py with the 'masque' feature: maturin develop --features masque"
    ))
}
