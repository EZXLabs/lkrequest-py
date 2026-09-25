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

    /// Chrome 151 QUIC / HTTP/3 profile captured from public H3 origins. Unlike
    /// Chrome 150 it omits the three ML-DSA signature algorithms; transport
    /// parameters and H3 SETTINGS stay aligned with Chrome 150.
    #[staticmethod]
    fn chrome_151() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_151_quic(),
        }
    }

    /// Chrome 152 QUIC / HTTP/3 profile: Chrome 151's shape minus the obsolete
    /// `google_initial_rtt` transport parameter.
    #[staticmethod]
    fn chrome_152() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_152_quic(),
        }
    }

    /// Chrome 153 QUIC / HTTP/3 profile. Like the other captured Chromium
    /// profiles it follows Chromium's GREASE generation rules, so the reserved
    /// H3 SETTINGS, the reserved transport parameters and the Initial packet
    /// layout are re-randomized per connection rather than fixed.
    #[staticmethod]
    fn chrome_153() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_153_quic(),
        }
    }

    /// Chrome 154 QUIC / HTTP/3 profile: identical to Chrome 153. The public
    /// capture verified QUIC through the Initial flight; the H3 SETTINGS and
    /// request priority carry over from Chrome 153's completed navigation,
    /// since that capture path never received a QUIC response.
    #[staticmethod]
    fn chrome_154() -> Self {
        PyQuicProfile {
            inner: lkrequest::lkh3::chrome_154_quic(),
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
