//! `RequestPriority` pyclass: RFC 9218 per-request priority (urgency plus
//! incremental flag) used to derive the HTTP `priority` header and H2 weight.

use pyo3::prelude::*;

/// RFC 9218 request priority — urgency (0–7) plus an incremental flag.
///
/// This is the single source from which both the HTTP `priority` header and
/// the HTTP/2 HEADERS-frame weight are derived, mirroring how a real browser
/// assigns priority based on the resource type (navigation, fetch, image, …).
///
/// Pass it to a request via the ``priority`` keyword argument:
///
/// ```python
/// session.get(url, priority=RequestPriority.image())
/// session.post(url, json=payload, priority=RequestPriority(1, incremental=True))
/// ```
#[pyclass(name = "RequestPriority")]
#[derive(Clone, Copy)]
pub struct PyRequestPriority {
    pub(crate) inner: lkh2::RequestPriority,
}

#[pymethods]
impl PyRequestPriority {
    /// Construct a custom priority. ``urgency`` is clamped to the 0–7 range.
    #[new]
    #[pyo3(signature = (urgency, incremental=false))]
    fn new(urgency: u8, incremental: bool) -> Self {
        PyRequestPriority {
            inner: lkh2::RequestPriority::custom(urgency, incremental),
        }
    }

    /// Navigation / document request (u=0).
    #[staticmethod]
    fn navigation() -> Self {
        PyRequestPriority {
            inner: lkh2::RequestPriority::navigation(),
        }
    }

    /// XHR / fetch / script request (u=1, incremental).
    #[staticmethod]
    fn fetch() -> Self {
        PyRequestPriority {
            inner: lkh2::RequestPriority::fetch(),
        }
    }

    /// Image resource (u=2).
    #[staticmethod]
    fn image() -> Self {
        PyRequestPriority {
            inner: lkh2::RequestPriority::image(),
        }
    }

    /// Background / low-priority resource (u=3).
    #[staticmethod]
    fn background() -> Self {
        PyRequestPriority {
            inner: lkh2::RequestPriority::background(),
        }
    }

    /// Urgency level 0–7 (lower is higher priority).
    #[getter]
    fn urgency(&self) -> u8 {
        self.inner.urgency
    }

    /// Whether the response can be processed incrementally.
    #[getter]
    fn incremental(&self) -> bool {
        self.inner.incremental
    }

    /// Format as the RFC 9218 ``priority`` header value, e.g. ``"u=1, i"``.
    #[allow(clippy::wrong_self_convention)]
    fn to_header_value(&self) -> String {
        self.inner.to_header_value()
    }

    fn __repr__(&self) -> String {
        format!(
            "RequestPriority(urgency={}, incremental={})",
            self.inner.urgency, self.inner.incremental
        )
    }
}
