//! QUIC / HTTP3 fingerprint bindings.
//!
//! The [`PyQuicProfile`] type is only compiled when the `quic-h3` feature is
//! enabled (it wraps `lkrequest::QuicProfile`, which is a real type only under
//! that feature). Build with `maturin develop --features quic-h3`.

#[cfg(feature = "quic-h3")]
use pyo3::prelude::*;

/// A full QUIC + HTTP/3 fingerprint profile (transport parameters, H3 settings,
/// packetization). Only available when built with the `quic-h3` feature.
///
/// Custom transport parameters are not exposed; use the captured browser
/// presets or load from JSON.
#[cfg(feature = "quic-h3")]
#[pyclass(name = "QuicProfile")]
#[derive(Clone)]
pub struct PyQuicProfile {
    pub(crate) inner: lkrequest::QuicProfile,
}

#[cfg(feature = "quic-h3")]
#[pymethods]
impl PyQuicProfile {
    /// Generic Chrome QUIC / HTTP/3 profile.
    #[staticmethod]
    fn chrome() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_quic(),
        }
    }

    /// Chrome 146 QUIC / HTTP/3 profile (captured transport parameters).
    #[staticmethod]
    fn chrome_146() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_146_quic(),
        }
    }

    /// Chrome 150 QUIC / HTTP/3 profile captured from an Outlook navigation.
    #[staticmethod]
    fn chrome_150() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_150_quic(),
        }
    }

    /// Load a profile from a JSON string.
    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner = serde_json::from_str(json_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Failed to parse QuicProfile JSON: {e}"
            ))
        })?;
        Ok(PyQuicProfile { inner })
    }

    /// Serialize the profile to a JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize QuicProfile: {e}"))
        })
    }

    /// Validate the profile; raises ``ValueError`` if it is inconsistent.
    fn validate(&self) -> PyResult<()> {
        self.inner
            .validate()
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    #[getter]
    fn connection_id_length(&self) -> usize {
        self.inner.connection_id_length
    }

    fn __repr__(&self) -> String {
        format!(
            "QuicProfile(connection_id_length={})",
            self.inner.connection_id_length
        )
    }
}
