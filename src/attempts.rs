//! Request attempt limits and the accounting of one request's attempts.
//!
//! `AttemptLimits` caps, for one logical request, the HTTP submissions beyond
//! the first and its redirects, and the TCP/QUIC connection starts, at client,
//! session and request scope. What a request did is read back as a summary
//! dict, the way `diagnostics` is, so that it survives pickling with the
//! exception it may be attached to.

use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Upstream's `AttemptLimits`: an unset limit adds no cap of its own, and a
/// session or request inherits the one above it.
#[pyclass(name = "AttemptLimits", frozen, eq, from_py_object)]
#[derive(Clone, Copy, PartialEq)]
pub struct PyAttemptLimits {
    pub(crate) inner: lkrequest::AttemptLimits,
}

#[pymethods]
impl PyAttemptLimits {
    /// `extra_http_attempts` caps the HTTP submissions beyond a request's
    /// first and its redirects (retries, recoveries); `connect_attempts` caps
    /// the TCP and QUIC connections it starts. `None` sets no cap here.
    #[new]
    #[pyo3(signature = (*, extra_http_attempts=None, connect_attempts=None))]
    fn new(extra_http_attempts: Option<u64>, connect_attempts: Option<u64>) -> Self {
        let mut inner = lkrequest::AttemptLimits::default();
        if let Some(limit) = extra_http_attempts {
            inner = inner.with_extra_http_attempts(limit);
        }
        if let Some(limit) = connect_attempts {
            inner = inner.with_connect_attempts(limit);
        }
        Self { inner }
    }

    /// The cap on extra HTTP submissions set here, or `None`.
    #[getter]
    fn extra_http_attempts(&self) -> Option<u64> {
        self.inner.extra_http_attempts()
    }

    /// The cap on connection starts set here, or `None`.
    #[getter]
    fn connect_attempts(&self) -> Option<u64> {
        self.inner.connect_attempts()
    }

    /// `AttemptLimits(extra_http_attempts=..., connect_attempts=...)`.
    fn __repr__(&self) -> String {
        let show = |limit: Option<u64>| limit.map_or_else(|| "None".to_owned(), |n| n.to_string());
        format!(
            "AttemptLimits(extra_http_attempts={}, connect_attempts={})",
            show(self.inner.extra_http_attempts()),
            show(self.inner.connect_attempts())
        )
    }
}

/// The limits in effect, each with the scope (`"client"`, `"session"` or
/// `"request"`) that set it, under the names upstream's C API uses.
pub(crate) fn effective_limits_dict<'py>(
    py: Python<'py>,
    limits: &lkrequest::EffectiveAttemptLimits,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("extra_http_attempts", limits.extra_http_attempts())?;
    dict.set_item(
        "extra_http_scope",
        limits.extra_http_scope().map(|scope| scope.as_str()),
    )?;
    dict.set_item("connect_attempts", limits.connect_attempts())?;
    dict.set_item(
        "connect_scope",
        limits.connect_scope().map(|scope| scope.as_str()),
    )?;
    Ok(dict)
}

/// What one request did, under the names of upstream's C API summary.
pub(crate) fn summary_dict<'py>(
    py: Python<'py>,
    summary: &lkrequest::AttemptSummary,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("started", summary.started())?;
    let limits = summary
        .effective_limits()
        .map(|limits| effective_limits_dict(py, &limits))
        .transpose()?;
    dict.set_item("effective_limits", limits)?;
    dict.set_item("http_submissions", summary.http_submissions())?;
    dict.set_item("extra_http_submissions", summary.extra_http_submissions())?;
    dict.set_item("redirects", summary.redirects())?;
    dict.set_item("recoveries", summary.recoveries())?;
    dict.set_item("connect_initiations", summary.connect_initiations())?;
    dict.set_item(
        "probe_suppressed_by_connect_limit",
        summary.probe_suppressed_by_connect_limit(),
    )?;
    dict.set_item("outcome", summary.outcome().as_str())?;
    dict.set_item("final", summary.outcome().is_final())?;
    dict.set_item(
        "denial_reason",
        summary.denial_reason().map(|reason| reason.as_str()),
    )?;
    Ok(dict)
}
