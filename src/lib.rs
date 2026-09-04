//! `lkrequest` Python extension module, built with PyO3 and maturin.
//!
//! This crate wraps the sibling Rust `lkrequest` HTTP client (together with the
//! `lktls`, `lkh2`, and `lkprofile` crates) and exposes it to Python as the
//! native `_lkrequest` extension. It offers an async API (`Client` / `Session`)
//! and a blocking API (`blocking.Client`), plus TLS/HTTP2/TCP fingerprint
//! configuration, connection and proxy pools, websockets, streaming responses,
//! multipart bodies, retries, middleware, and metrics.

// Request methods mirror Python's kwargs-style API, so they intentionally take
// many parameters (headers, params, json, data, body, multipart, cookies, auth,
// timeout, proxy, encoding, …). Collapsing them to <=7 would hurt the binding.
#![allow(clippy::too_many_arguments)]

mod bridge;
mod client;
mod client_pool;
mod error;
mod fingerprint;
mod hsts;
mod metrics;
mod middleware;
mod multipart;
mod network_partition;
mod priority;
mod protocol;
mod proxy;
mod quic;
mod randomize;
mod response;
mod retry;
mod session;
mod session_pool;
mod types;
mod websocket;

use pyo3::prelude::*;

#[pymodule]
fn _lkrequest(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Async API
    m.add_class::<client::PyClient>()?;
    m.add_class::<session::PySession>()?;
    m.add_class::<response::PyResponse>()?;
    m.add_class::<response::PyStreamingResponse>()?;
    m.add_class::<response::PyHeaderMap>()?;
    m.add_class::<response::PyRedirectRecord>()?;

    // Blocking API
    m.add_class::<client::PyBlockingClient>()?;
    m.add_class::<session::PyBlockingSession>()?;
    m.add_class::<response::PyBlockingStreamingResponse>()?;

    // Configuration
    m.add_class::<types::PyTimeoutConfig>()?;
    m.add_class::<types::PyResourceLimits>()?;
    m.add_class::<types::PyHttpVersion>()?;
    m.add_class::<types::PyAcceptEncoding>()?;
    m.add_class::<types::PyPoolStats>()?;
    m.add_class::<types::PySessionPoolStats>()?;
    m.add_class::<types::PySessionResumptionConfig>()?;
    m.add_class::<types::PyH2DataFramePolicy>()?;

    // Browser-style network session policies (ticket resumption / cache
    // partitioning / browsing context)
    m.add_class::<network_partition::PyTlsSessionResumptionPolicy>()?;
    m.add_class::<network_partition::PyTlsSessionCachePartitionPolicy>()?;
    m.add_class::<network_partition::PyNetworkPartitionContext>()?;

    // Multipart
    m.add_class::<multipart::PyMultipart>()?;
    m.add_class::<multipart::PyPart>()?;

    // Proxy
    m.add_class::<proxy::PyProxyConfig>()?;
    m.add_class::<proxy::PyProxyPool>()?;
    m.add_class::<proxy::PyBadProxyConfig>()?;
    m.add_class::<proxy::PyHealthCheckConfig>()?;

    // Session Pool
    m.add_class::<session_pool::PySessionPool>()?;
    m.add_class::<session_pool::PySessionGuard>()?;
    m.add_class::<session_pool::PyBlockingSessionPool>()?;
    m.add_class::<session_pool::PyBlockingSessionGuard>()?;

    // Retry
    m.add_class::<retry::PyExponentialBackoff>()?;
    m.add_class::<retry::PyFixedInterval>()?;

    // Request priority (RFC 9218)
    m.add_class::<priority::PyRequestPriority>()?;

    // Protocol policy
    m.add_class::<protocol::PyProtocolPolicy>()?;
    m.add_class::<protocol::PyHttpIntent>()?;
    m.add_class::<protocol::PyPreferredHttpVersion>()?;
    m.add_class::<protocol::PyIdempotency>()?;
    m.add_class::<protocol::PyBrokenQuicPolicy>()?;

    // HSTS / scheme-upgrade policy
    m.add_class::<hsts::PyHsts>()?;

    // QUIC / HTTP3 (only available with the quic-h3 feature)
    #[cfg(feature = "quic-h3")]
    m.add_class::<quic::PyQuicProfile>()?;

    // Fingerprint randomization policy. `Randomize` (Tiers 0/1) is always
    // present; the `Layers` mask and `NegotiabilityFloor` are only meaningful for
    // the synthetic tiers and are registered only with the `synthetic-fp` feature.
    m.add_class::<randomize::PyRandomize>()?;
    #[cfg(feature = "synthetic-fp")]
    m.add_class::<randomize::PyLayers>()?;
    #[cfg(feature = "synthetic-fp")]
    m.add_class::<randomize::PyNegotiabilityFloor>()?;

    // Middleware
    m.add_class::<middleware::PyMiddleware>()?;

    // WebSocket
    m.add_class::<websocket::PyWsMessage>()?;
    m.add_class::<websocket::PyWsConnection>()?;
    m.add_class::<websocket::PyBlockingWsConnection>()?;

    // Metrics
    m.add_class::<metrics::PyMetricsCollector>()?;

    // Fingerprint configuration
    m.add_class::<fingerprint::PyExtType>()?;
    m.add_class::<fingerprint::PyExtensionSpec>()?;
    m.add_class::<fingerprint::PyGreaseConfig>()?;
    m.add_class::<fingerprint::PyPaddingStrategy>()?;
    m.add_class::<fingerprint::PyRandomizationConfig>()?;
    m.add_class::<fingerprint::PyTlsProfile>()?;
    m.add_class::<fingerprint::PyH2Setting>()?;
    m.add_class::<fingerprint::PyHeadersPriority>()?;
    m.add_class::<fingerprint::PyPriorityFrame>()?;
    m.add_class::<fingerprint::PyPriorityConfig>()?;
    m.add_class::<fingerprint::PyH2Profile>()?;
    m.add_class::<fingerprint::PyTcpFingerprint>()?;

    // Client Pool
    m.add_class::<client_pool::PyClientPool>()?;

    // Exceptions
    error::register_exceptions(m)?;

    // Module-level functions
    m.add_function(pyo3::wrap_pyfunction!(set_log_level, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(metrics::enable_metrics, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(validate_fingerprint_consistency, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(metrics_snapshot, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(pending_requests, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(drain_pending, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(blocking_drain_pending, m)?)?;

    Ok(())
}

/// Number of async operations that have been handed to Python but have not
/// finished yet, counted process-wide.
#[pyfunction]
fn pending_requests() -> usize {
    bridge::pending_count()
}

/// Wait until no async operation is still in flight.
///
/// Call this before the event loop closes if requests may still be running:
/// a result arriving after the loop is gone has nowhere to go and is dropped.
///
/// ``timeout`` is in seconds; ``None`` waits indefinitely. Returns True if
/// everything finished, False if the timeout elapsed first.
#[pyfunction]
#[pyo3(signature = (timeout=None))]
fn drain_pending(py: Python<'_>, timeout: Option<f64>) -> PyResult<Bound<'_, PyAny>> {
    let timeout = timeout.map(types::validated_duration).transpose()?;
    // Untracked: a tracked drain would be counted as in flight and wait on itself.
    bridge::future_into_py_untracked(py, async move { Ok(bridge::drain(timeout).await) })
}

/// Blocking counterpart of :func:`drain_pending`.
#[pyfunction]
#[pyo3(signature = (timeout=None))]
fn blocking_drain_pending(py: Python<'_>, timeout: Option<f64>) -> PyResult<bool> {
    let timeout = timeout.map(types::validated_duration).transpose()?;
    Ok(py.allow_threads(|| {
        pyo3_async_runtimes::tokio::get_runtime().block_on(bridge::drain(timeout))
    }))
}

/// Validate that TLS, H2, and TCP fingerprint configurations are consistent.
///
/// Checks browser family matching and protocol compatibility.
/// Returns a dict with "valid" (bool) and "warnings" (list of strings).
#[pyfunction]
#[pyo3(signature = (*, tls_profile=None, h2_profile=None, tcp_fingerprint=None))]
fn validate_fingerprint_consistency(
    py: Python<'_>,
    tls_profile: Option<&str>,
    h2_profile: Option<&str>,
    tcp_fingerprint: Option<&str>,
) -> PyResult<PyObject> {
    use pyo3::types::{PyDict, PyList};

    let mut warnings: Vec<String> = Vec::new();

    fn browser_family(name: &str) -> Option<&str> {
        if name.contains("chrome") {
            Some("chrome")
        } else if name.contains("firefox") {
            Some("firefox")
        } else if name.contains("safari") {
            Some("safari")
        } else {
            None
        }
    }

    let tls_family = tls_profile.and_then(browser_family);
    let h2_family = h2_profile.and_then(browser_family);
    let tcp_family = tcp_fingerprint.and_then(browser_family);

    if let (Some(tf), Some(hf)) = (tls_family, h2_family) {
        if tf != hf {
            warnings.push(format!(
                "TLS profile family '{}' does not match H2 profile family '{}'",
                tf, hf
            ));
        }
    }
    if let (Some(tf), Some(tcf)) = (tls_family, tcp_family) {
        if tf != tcf {
            warnings.push(format!(
                "TLS profile family '{}' does not match TCP fingerprint family '{}'",
                tf, tcf
            ));
        }
    }

    if let Some(tls_name) = tls_profile {
        if let Ok(profile) = crate::types::resolve_tls_profile(tls_name) {
            let has_h2_alpn = profile.alpn_protocols.iter().any(|p| p == "h2");
            if has_h2_alpn && h2_profile.is_none() {
                warnings
                    .push("TLS profile advertises h2 in ALPN but no H2 profile is set".to_string());
            }
        }
    }

    let dict = PyDict::new(py);
    dict.set_item("valid", warnings.is_empty())?;
    let py_warnings = PyList::new(py, warnings.iter().map(|s| s.as_str()))?;
    dict.set_item("warnings", py_warnings)?;
    Ok(dict.into())
}

/// Initialize tracing subscriber with the given log level.
///
/// Valid levels: "trace", "debug", "info", "warn", "error", "off"
/// Also supports filter directives like "lkrequest=debug,lktls=trace".
///
/// ``format`` controls log output style:
///   - "compact" (default): single-line, human-readable
///   - "full": multi-line with all metadata
///   - "json": structured JSON, one object per line (machine-parseable)
///
/// Returns True if the log level was set, False if a subscriber was already initialized.
/// The log level can only be set once per process — subsequent calls return False.
#[pyfunction]
#[pyo3(signature = (level, *, format="compact"))]
fn set_log_level(level: &str, format: &str) -> PyResult<bool> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(level).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid log level '{}': {}", level, e))
    })?;

    let result = match format {
        "compact" => tracing_subscriber::fmt()
            .compact()
            .with_env_filter(filter)
            .with_target(true)
            .try_init(),
        "full" => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .try_init(),
        "json" => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .try_init(),
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown log format '{}'. Use: compact, full, json",
                other
            )));
        }
    };

    Ok(result.is_ok())
}

/// Snapshot of process-global operational counters: wire bytes in/out, request
/// counts, and connection counts. Returns a dict. Pull-only and near-free.
///
/// Reports all-zero counters unless the extension was built with the `telemetry`
/// feature (`maturin build --features telemetry`), which adds the transport
/// byte-counting instrumentation.
#[pyfunction]
fn metrics_snapshot(py: Python<'_>) -> PyResult<Bound<'_, pyo3::types::PyDict>> {
    let d = pyo3::types::PyDict::new(py);
    #[cfg(feature = "telemetry")]
    {
        let s = lkrequest::telemetry::metrics_snapshot();
        d.set_item("bytes_in", s.bytes_in)?;
        d.set_item("bytes_out", s.bytes_out)?;
        d.set_item("requests_total", s.requests_total)?;
        d.set_item("requests_failed", s.requests_failed)?;
        d.set_item("active_connections", s.active_connections)?;
        d.set_item("total_connections", s.total_connections)?;
    }
    #[cfg(not(feature = "telemetry"))]
    {
        for key in [
            "bytes_in",
            "bytes_out",
            "requests_total",
            "requests_failed",
            "active_connections",
            "total_connections",
        ] {
            d.set_item(key, 0u64)?;
        }
    }
    Ok(d)
}

// OpenTelemetry export was removed — observability is now exposed as data/hooks
// for the host to consume: per-request diagnostics + the metrics snapshot, plus
// `set_log_level()`. See README. A host that wants OTel can run its own tracing
// subscriber over the engine's spans.
