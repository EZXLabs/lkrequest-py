//! Protocol-behaviour pyclasses: `HttpIntent`, `ProtocolPolicy`,
//! `PreferredHttpVersion`, `Idempotency`, and `BrokenQuicPolicy` controlling
//! HTTP version negotiation, QUIC/HTTP3 acquisition, and fallback.

use pyo3::prelude::*;

/// High-level desired HTTP protocol behaviour, independent of the wire-format
/// fingerprint profiles (TLS / H2 / H3).
#[pyclass(name = "HttpIntent", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
pub enum PyHttpIntent {
    /// Disable QUIC / HTTP/3 and stay on TCP-based HTTP.
    H2Only = 0,
    /// Require QUIC / HTTP/3 and do not silently downgrade.
    H3Only = 1,
    /// Acquire QUIC / HTTP/3 when it is advertised or otherwise viable.
    AcquireH3WhenViable = 2,
    /// Reuse the currently healthy protocol; avoid extra H3 acquisition work.
    ReuseExistingProtocol = 3,
}

impl From<PyHttpIntent> for lkrequest::HttpIntent {
    fn from(v: PyHttpIntent) -> Self {
        match v {
            PyHttpIntent::H2Only => lkrequest::HttpIntent::H2Only,
            PyHttpIntent::H3Only => lkrequest::HttpIntent::H3Only,
            PyHttpIntent::AcquireH3WhenViable => lkrequest::HttpIntent::AcquireH3WhenViable,
            PyHttpIntent::ReuseExistingProtocol => lkrequest::HttpIntent::ReuseExistingProtocol,
        }
    }
}

impl From<lkrequest::HttpIntent> for PyHttpIntent {
    fn from(v: lkrequest::HttpIntent) -> Self {
        #[allow(deprecated)]
        match v {
            lkrequest::HttpIntent::H2Only => PyHttpIntent::H2Only,
            lkrequest::HttpIntent::H3Only => PyHttpIntent::H3Only,
            lkrequest::HttpIntent::AcquireH3WhenViable | lkrequest::HttpIntent::PreferH3 => {
                PyHttpIntent::AcquireH3WhenViable
            }
            lkrequest::HttpIntent::ReuseExistingProtocol | lkrequest::HttpIntent::Auto => {
                PyHttpIntent::ReuseExistingProtocol
            }
        }
    }
}

/// Runtime protocol behaviour policy: which HTTP versions to use, how to
/// acquire connections (TCP/QUIC race), how to upgrade to H3, and how to
/// fall back.
///
/// Construct one of the presets and optionally narrow the intent:
///
/// ```python
/// policy = ProtocolPolicy.chrome_standard().with_intent(HttpIntent.H2Only)
/// client.session(protocol_policy=policy)
/// ```
#[pyclass(name = "ProtocolPolicy")]
#[derive(Clone)]
pub struct PyProtocolPolicy {
    pub(crate) inner: lkrequest::ProtocolPolicy,
}

#[pymethods]
impl PyProtocolPolicy {
    /// Chrome's standard policy: acquire H3 when viable (TCP/QUIC race),
    /// probe-and-migrate, fall back on network errors.
    #[staticmethod]
    fn chrome_standard() -> Self {
        Self {
            inner: lkrequest::ProtocolPolicy::chrome_standard(),
        }
    }

    /// Conservative Chrome policy: reuse the existing protocol, probe only.
    #[staticmethod]
    fn chrome_conservative() -> Self {
        Self {
            inner: lkrequest::ProtocolPolicy::chrome_conservative(),
        }
    }

    /// High-throughput crawler policy: reuse the existing protocol, no H3
    /// upgrade, allow fallback. This is the library default.
    #[staticmethod]
    fn crawler_throughput() -> Self {
        Self {
            inner: lkrequest::ProtocolPolicy::crawler_throughput(),
        }
    }

    /// Strict HTTP/3: require H3 and never fall back to TCP.
    #[staticmethod]
    fn h3_strict() -> Self {
        Self {
            inner: lkrequest::ProtocolPolicy::h3_strict(),
        }
    }

    /// Return a copy with the high-level HTTP intent overridden (other axes
    /// are normalised to stay coherent).
    fn with_intent(&self, intent: PyHttpIntent) -> Self {
        Self {
            inner: self.inner.clone().with_intent(intent.into()),
        }
    }

    /// The current high-level HTTP intent.
    #[getter]
    fn intent(&self) -> PyHttpIntent {
        self.inner.intent.into()
    }

    fn __repr__(&self) -> String {
        format!(
            "ProtocolPolicy(intent={:?}, upgrade={:?}, fallback={:?})",
            self.inner.intent, self.inner.upgrade, self.inner.fallback
        )
    }
}

/// Per-request preferred HTTP version. Overrides the session's protocol
/// preference for a single request without changing the rest of the policy.
#[pyclass(name = "PreferredHttpVersion", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
pub enum PyPreferredHttpVersion {
    /// Use whatever the server negotiates via ALPN and policy defaults.
    Auto = 0,
    /// Force HTTP/1.1 only (do not use HTTP/2 even if negotiated).
    Http1Only = 1,
    /// Force HTTP/2 only (fail if the server does not support H2).
    Http2Only = 2,
    /// Force HTTP/3 only (requires a client built with QUIC/H3 support).
    Http3Only = 3,
    /// Prefer HTTP/3, fall back to TCP-based HTTP if QUIC fails.
    Http3WithFallback = 4,
}

impl From<PyPreferredHttpVersion> for lkrequest::PreferredHttpVersion {
    fn from(v: PyPreferredHttpVersion) -> Self {
        match v {
            PyPreferredHttpVersion::Auto => lkrequest::PreferredHttpVersion::Auto,
            PyPreferredHttpVersion::Http1Only => lkrequest::PreferredHttpVersion::Http1Only,
            PyPreferredHttpVersion::Http2Only => lkrequest::PreferredHttpVersion::Http2Only,
            PyPreferredHttpVersion::Http3Only => lkrequest::PreferredHttpVersion::Http3Only,
            PyPreferredHttpVersion::Http3WithFallback => {
                lkrequest::PreferredHttpVersion::Http3WithFallback
            }
        }
    }
}

/// Per-request replay-safety declaration, controlling QUIC 0-RTT / TLS early
/// data eligibility.
#[pyclass(name = "Idempotency", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
pub enum PyIdempotency {
    /// Decide automatically based on the HTTP method (RFC 9110 safe methods).
    Default = 0,
    /// Assert the request is safe to replay — allows 0-RTT for any method.
    Idempotent = 1,
    /// Declare the request unsafe to replay — disables 0-RTT.
    NotIdempotent = 2,
}

impl From<PyIdempotency> for lkrequest::Idempotency {
    fn from(v: PyIdempotency) -> Self {
        match v {
            PyIdempotency::Default => lkrequest::Idempotency::Default,
            PyIdempotency::Idempotent => lkrequest::Idempotency::Idempotent,
            PyIdempotency::NotIdempotent => lkrequest::Idempotency::NotIdempotent,
        }
    }
}

/// How a session quarantines an origin whose QUIC/H3 path has been failing, so
/// it temporarily falls back to TCP instead of retrying H3 every time.
#[pyclass(name = "BrokenQuicPolicy", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
pub enum PyBrokenQuicPolicy {
    /// Library default — 5 min initial cooldown, escalating up to 1 h after
    /// repeated failures. Best for stable networks (matches Chrome).
    Strict = 0,
    /// 1 s initial cooldown capped at 10 s, no escalation. Recommended behind
    /// transparent proxies / sticky UDP relays where failures are transient.
    Resilient = 1,
    /// Never quarantine an origin — every request retries H3 from scratch.
    Disabled = 2,
}

impl From<PyBrokenQuicPolicy> for lkrequest::BrokenQuicPolicy {
    fn from(v: PyBrokenQuicPolicy) -> Self {
        match v {
            PyBrokenQuicPolicy::Strict => lkrequest::BrokenQuicPolicy::Strict,
            PyBrokenQuicPolicy::Resilient => lkrequest::BrokenQuicPolicy::Resilient,
            PyBrokenQuicPolicy::Disabled => lkrequest::BrokenQuicPolicy::Disabled,
        }
    }
}
