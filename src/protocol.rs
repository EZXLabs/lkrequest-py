//! Protocol-behaviour pyclasses: `HttpIntent`, `ProtocolPolicy` and its axes
//! (`AcquisitionPolicy`, `RacePolicy`, `UpgradePolicy`, `FallbackPolicy`),
//! `PreferredHttpVersion`, `Idempotency`, `BrokenQuicPolicy`, `BrokenQuicConfig` and
//! `H3RetryMode` controlling HTTP version negotiation, QUIC/HTTP3 acquisition,
//! and fallback.

use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::error::to_py_err;
use crate::types::validated_duration;

/// High-level desired HTTP protocol behaviour, independent of the wire-format
/// fingerprint profiles (TLS / H2 / H3).
#[pyclass(name = "HttpIntent", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
#[pyclass(name = "ProtocolPolicy", from_py_object)]
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

    /// Return a copy acquiring connections as `acquisition` says: an
    /// `AcquisitionPolicy`, or a `RacePolicy` to race TCP against QUIC.
    fn with_acquisition(&self, acquisition: &Bound<'_, PyAny>) -> PyResult<Self> {
        let acquisition = if let Ok(race) = acquisition.extract::<PyRacePolicy>() {
            lkrequest::AcquisitionPolicy::Race(race.inner)
        } else if let Ok(policy) = acquisition.extract::<PyAcquisitionPolicy>() {
            policy.into()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "acquisition must be an AcquisitionPolicy or a RacePolicy",
            ));
        };
        Ok(Self {
            inner: self.inner.clone().with_acquisition(acquisition),
        })
    }

    /// Return a copy with the upgrade policy replaced.
    fn with_upgrade(&self, upgrade: PyUpgradePolicy) -> Self {
        Self {
            inner: self.inner.clone().with_upgrade(upgrade.into()),
        }
    }

    /// Return a copy with the fallback policy replaced.
    fn with_fallback(&self, fallback: PyFallbackPolicy) -> Self {
        Self {
            inner: self.inner.clone().with_fallback(fallback.into()),
        }
    }

    /// Raise `ValueError` if the axes contradict one another. A session or a
    /// client given the policy checks it the same way.
    fn validate(&self) -> PyResult<()> {
        self.inner.validate().map_err(to_py_err)
    }

    /// The current high-level HTTP intent.
    #[getter]
    fn intent(&self) -> PyHttpIntent {
        self.inner.intent.into()
    }

    /// An `AcquisitionPolicy`, or the `RacePolicy` of a TCP/QUIC race.
    #[getter]
    fn acquisition(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        Ok(match &self.inner.acquisition {
            lkrequest::AcquisitionPolicy::Race(race) => {
                Py::new(py, PyRacePolicy { inner: *race })?.into_any()
            }
            lkrequest::AcquisitionPolicy::ReuseExistingFirst => {
                Py::new(py, PyAcquisitionPolicy::ReuseExistingFirst)?.into_any()
            }
            lkrequest::AcquisitionPolicy::EstablishBestAvailable => {
                Py::new(py, PyAcquisitionPolicy::EstablishBestAvailable)?.into_any()
            }
        })
    }

    #[getter]
    fn upgrade(&self) -> PyUpgradePolicy {
        self.inner.upgrade.into()
    }

    #[getter]
    fn fallback(&self) -> PyFallbackPolicy {
        self.inner.fallback.into()
    }

    fn __repr__(&self) -> String {
        let acquisition = match &self.inner.acquisition {
            lkrequest::AcquisitionPolicy::Race(race) => PyRacePolicy { inner: *race }.__repr__(),
            other => format!("AcquisitionPolicy.{other:?}"),
        };
        format!(
            "ProtocolPolicy(intent={:?}, acquisition={acquisition}, upgrade={:?}, fallback={:?})",
            self.inner.intent, self.inner.upgrade, self.inner.fallback
        )
    }
}

impl PyProtocolPolicy {
    /// The policy, checked, for a session or a client: upstream would only
    /// refuse it when the first request is sent.
    pub(crate) fn validated(self) -> PyResult<lkrequest::ProtocolPolicy> {
        self.inner.validate().map_err(to_py_err)?;
        Ok(self.inner)
    }
}

/// How a request acquires a transport when no pooled connection is selected;
/// a `RacePolicy` stands for the third way, a TCP/QUIC race.
#[pyclass(name = "AcquisitionPolicy", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PyAcquisitionPolicy {
    /// Reuse a healthy connection first; otherwise stay conservative and open
    /// no new HTTP/3 path just to upgrade.
    ReuseExistingFirst = 0,
    /// Establish the best protocol currently known for a new connection.
    EstablishBestAvailable = 1,
}

impl From<PyAcquisitionPolicy> for lkrequest::AcquisitionPolicy {
    fn from(v: PyAcquisitionPolicy) -> Self {
        match v {
            PyAcquisitionPolicy::ReuseExistingFirst => Self::ReuseExistingFirst,
            PyAcquisitionPolicy::EstablishBestAvailable => Self::EstablishBestAvailable,
        }
    }
}

/// The timing of a TCP-versus-QUIC race. Each value left out keeps that of
/// `RacePolicy.chrome_like()`.
#[pyclass(name = "RacePolicy", eq, frozen, from_py_object)]
#[derive(Clone, PartialEq)]
pub struct PyRacePolicy {
    inner: lkrequest::RacePolicy,
}

#[pymethods]
impl PyRacePolicy {
    #[new]
    #[pyo3(signature = (*, enable_tcp=None, enable_quic=None, tcp_delay=None, quic_delay=None, only_when_h3_advertised=None))]
    fn new(
        enable_tcp: Option<bool>,
        enable_quic: Option<bool>,
        tcp_delay: Option<f64>,
        quic_delay: Option<f64>,
        only_when_h3_advertised: Option<bool>,
    ) -> PyResult<Self> {
        let mut inner = lkrequest::RacePolicy::chrome_like();
        if let Some(enabled) = enable_tcp {
            inner.enable_tcp = enabled;
        }
        if let Some(enabled) = enable_quic {
            inner.enable_quic = enabled;
        }
        if let Some(delay) = tcp_delay {
            inner.tcp_delay = validated_duration(delay)?;
        }
        if let Some(delay) = quic_delay {
            inner.quic_delay = validated_duration(delay)?;
        }
        if let Some(only) = only_when_h3_advertised {
            inner.only_when_h3_advertised = only;
        }
        Ok(Self { inner })
    }

    /// Chrome's: QUIC at once, TCP 0.3 s later, and only for an origin that
    /// has advertised HTTP/3.
    #[staticmethod]
    fn chrome_like() -> Self {
        Self {
            inner: lkrequest::RacePolicy::chrome_like(),
        }
    }

    #[getter]
    fn enable_tcp(&self) -> bool {
        self.inner.enable_tcp
    }

    #[getter]
    fn enable_quic(&self) -> bool {
        self.inner.enable_quic
    }

    /// Seconds before the TCP attempt starts.
    #[getter]
    fn tcp_delay(&self) -> f64 {
        self.inner.tcp_delay.as_secs_f64()
    }

    /// Seconds before the QUIC attempt starts.
    #[getter]
    fn quic_delay(&self) -> f64 {
        self.inner.quic_delay.as_secs_f64()
    }

    #[getter]
    fn only_when_h3_advertised(&self) -> bool {
        self.inner.only_when_h3_advertised
    }

    fn __repr__(&self) -> String {
        let race = &self.inner;
        format!(
            "RacePolicy(enable_tcp={}, enable_quic={}, tcp_delay={:?}, quic_delay={:?}, only_when_h3_advertised={})",
            py_bool(race.enable_tcp),
            py_bool(race.enable_quic),
            race.tcp_delay.as_secs_f64(),
            race.quic_delay.as_secs_f64(),
            py_bool(race.only_when_h3_advertised),
        )
    }
}

fn py_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

/// How a session upgrades from TCP-based HTTP to HTTP/3 once it learns that an
/// origin may support it.
#[pyclass(name = "UpgradePolicy", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PyUpgradePolicy {
    /// Never upgrade: stay on the TCP-based protocol.
    Off = 0,
    /// Probe for HTTP/3 in the background, but keep requests on TCP.
    ProbeOnly = 1,
    /// Probe, and move new requests over once HTTP/3 has proved healthy.
    ProbeAndMigrate = 2,
    /// Put new requests on HTTP/3 as soon as the origin is known to support it.
    ForceForNewRequests = 3,
}

impl From<PyUpgradePolicy> for lkrequest::UpgradePolicy {
    fn from(v: PyUpgradePolicy) -> Self {
        match v {
            PyUpgradePolicy::Off => Self::Off,
            PyUpgradePolicy::ProbeOnly => Self::ProbeOnly,
            PyUpgradePolicy::ProbeAndMigrate => Self::ProbeAndMigrate,
            PyUpgradePolicy::ForceForNewRequests => Self::ForceForNewRequests,
        }
    }
}

impl From<lkrequest::UpgradePolicy> for PyUpgradePolicy {
    fn from(v: lkrequest::UpgradePolicy) -> Self {
        use lkrequest::UpgradePolicy as U;
        // Upstream's deprecated names are aliases of the current ones.
        #[allow(deprecated)]
        match v {
            U::Off | U::Disabled => Self::Off,
            U::ProbeOnly | U::BackgroundProbe => Self::ProbeOnly,
            U::ProbeAndMigrate | U::BackgroundProbeAndMigrate => Self::ProbeAndMigrate,
            U::ForceForNewRequests | U::ForceUpgradeForNewRequests => Self::ForceForNewRequests,
        }
    }
}

/// Whether a failure over QUIC/HTTP3 may fall back to TCP-based HTTP.
#[pyclass(name = "FallbackPolicy", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PyFallbackPolicy {
    /// Fall back on any QUIC/HTTP3 failure.
    AllowFallback = 0,
    /// Fall back on network failures only, not on protocol errors.
    AllowFallbackOnNetworkErrors = 1,
    /// Never fall back: the failure is raised.
    NoFallback = 2,
}

impl From<PyFallbackPolicy> for lkrequest::FallbackPolicy {
    fn from(v: PyFallbackPolicy) -> Self {
        match v {
            PyFallbackPolicy::AllowFallback => Self::AllowFallback,
            PyFallbackPolicy::AllowFallbackOnNetworkErrors => Self::AllowFallbackOnNetworkErrors,
            PyFallbackPolicy::NoFallback => Self::NoFallback,
        }
    }
}

impl From<lkrequest::FallbackPolicy> for PyFallbackPolicy {
    fn from(v: lkrequest::FallbackPolicy) -> Self {
        match v {
            lkrequest::FallbackPolicy::AllowFallback => Self::AllowFallback,
            lkrequest::FallbackPolicy::AllowFallbackOnNetworkErrors => {
                Self::AllowFallbackOnNetworkErrors
            }
            lkrequest::FallbackPolicy::NoFallback => Self::NoFallback,
        }
    }
}

/// Per-request preferred HTTP version. Overrides the session's protocol
/// preference for a single request without changing the rest of the policy.
#[pyclass(
    name = "PreferredHttpVersion",
    eq,
    eq_int,
    hash,
    frozen,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
#[pyclass(name = "Idempotency", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
#[pyclass(name = "BrokenQuicPolicy", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

/// Cooldowns for origins whose QUIC/H3 attempts failed, for when none of the
/// `BrokenQuicPolicy` presets fits. Each value left out keeps `Strict`'s.
#[pyclass(name = "BrokenQuicConfig", eq, frozen, from_py_object)]
#[derive(Clone)]
pub struct PyBrokenQuicConfig {
    inner: lkrequest::BrokenQuicConfig,
}

impl PartialEq for PyBrokenQuicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.settings() == other.settings()
    }
}

impl PyBrokenQuicConfig {
    /// The settings a caller can give, which are all that tell two apart.
    fn settings(&self) -> (Duration, Duration, u32, Duration, usize, usize) {
        let config = &self.inner;
        (
            config.initial_cooldown,
            config.max_cooldown,
            config.failure_escalation_threshold,
            config.route_cooldown,
            config.max_entries,
            config.max_route_entries,
        )
    }
}

#[pymethods]
impl PyBrokenQuicConfig {
    /// Upstream would take an `initial_cooldown` above `max_cooldown` as
    /// `max_cooldown`, and a count of zero as one; both are refused instead.
    #[new]
    #[pyo3(signature = (*, initial_cooldown=None, max_cooldown=None, failure_escalation_threshold=None, route_cooldown=None, max_entries=None, max_route_entries=None))]
    fn new(
        initial_cooldown: Option<f64>,
        max_cooldown: Option<f64>,
        failure_escalation_threshold: Option<u32>,
        route_cooldown: Option<f64>,
        max_entries: Option<usize>,
        max_route_entries: Option<usize>,
    ) -> PyResult<Self> {
        let mut inner = lkrequest::BrokenQuicConfig::default();
        if let Some(secs) = initial_cooldown {
            inner.initial_cooldown = validated_duration(secs)?;
        }
        if let Some(secs) = max_cooldown {
            inner.max_cooldown = validated_duration(secs)?;
        }
        if inner.initial_cooldown > inner.max_cooldown {
            return Err(PyValueError::new_err(format!(
                "initial_cooldown ({:?} s) must not exceed max_cooldown ({:?} s)",
                inner.initial_cooldown.as_secs_f64(),
                inner.max_cooldown.as_secs_f64()
            )));
        }
        if let Some(count) = failure_escalation_threshold {
            inner.failure_escalation_threshold =
                at_least_one("failure_escalation_threshold", count)?;
        }
        if let Some(secs) = route_cooldown {
            inner.route_cooldown = validated_duration(secs)?;
        }
        if let Some(count) = max_entries {
            inner.max_entries = at_least_one("max_entries", count)?;
        }
        if let Some(count) = max_route_entries {
            inner.max_route_entries = at_least_one("max_route_entries", count)?;
        }
        Ok(Self { inner })
    }

    /// Seconds an origin stays on TCP after its first failure.
    #[getter]
    fn initial_cooldown(&self) -> f64 {
        self.inner.initial_cooldown.as_secs_f64()
    }

    /// Seconds an origin stays on TCP at most, after repeated failures.
    #[getter]
    fn max_cooldown(&self) -> f64 {
        self.inner.max_cooldown.as_secs_f64()
    }

    /// Failures in a row at which the cooldown reaches `max_cooldown`.
    #[getter]
    fn failure_escalation_threshold(&self) -> u32 {
        self.inner.failure_escalation_threshold
    }

    /// Seconds a proxy route that cannot carry QUIC stays on TCP.
    #[getter]
    fn route_cooldown(&self) -> f64 {
        self.inner.route_cooldown.as_secs_f64()
    }

    /// Origins remembered at most.
    #[getter]
    fn max_entries(&self) -> usize {
        self.inner.max_entries
    }

    /// Proxy routes remembered at most.
    #[getter]
    fn max_route_entries(&self) -> usize {
        self.inner.max_route_entries
    }

    fn __repr__(&self) -> String {
        let config = &self.inner;
        format!(
            "BrokenQuicConfig(initial_cooldown={:?}, max_cooldown={:?}, failure_escalation_threshold={}, route_cooldown={:?}, max_entries={}, max_route_entries={})",
            config.initial_cooldown.as_secs_f64(),
            config.max_cooldown.as_secs_f64(),
            config.failure_escalation_threshold,
            config.route_cooldown.as_secs_f64(),
            config.max_entries,
            config.max_route_entries,
        )
    }
}

/// `value`, unless it is zero.
fn at_least_one<T: Default + PartialEq>(name: &str, value: T) -> PyResult<T> {
    if value == T::default() {
        return Err(PyValueError::new_err(format!("{name} must be at least 1")));
    }
    Ok(value)
}

/// What `broken_quic_policy=` takes: a `BrokenQuicPolicy` preset, or a
/// `BrokenQuicConfig` with the cooldowns themselves.
pub(crate) struct BrokenQuic(pub(crate) lkrequest::BrokenQuicPolicy);

impl<'py> FromPyObject<'_, 'py> for BrokenQuic {
    type Error = PyErr;

    fn extract(obj: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(config) = obj.extract::<PyBrokenQuicConfig>() {
            return Ok(Self(lkrequest::BrokenQuicPolicy::Custom(config.inner)));
        }
        match obj.extract::<PyBrokenQuicPolicy>() {
            Ok(preset) => Ok(Self(preset.into())),
            Err(_) => Err(pyo3::exceptions::PyTypeError::new_err(
                "expected a BrokenQuicPolicy or a BrokenQuicConfig",
            )),
        }
    }
}

/// Whether a session replays a request after selected HTTP/3 protocol errors.
///
/// Independent of the session's retry policy and of QUIC 0-RTT. Only the
/// default exists without the `quic-h3` feature.
#[pyclass(name = "H3RetryMode", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PyH3RetryMode {
    /// Library default: no replay beyond the usual safety checks.
    Safe = 0,
    /// Retry selected HTTP/3 protocol errors up to twice per redirect hop,
    /// before response headers arrive, as Chrome 155 does.
    ///
    /// This replays a finite buffered request, including a POST the server may
    /// already have processed. Streaming uploads are not retried, and a request
    /// sent with `Idempotency.NotIdempotent` opts out. It adds no status-code
    /// retries and does not touch 0-RTT eligibility. A request that is not
    /// HTTP/3-only also needs a protocol policy that allows falling back to TCP.
    Chrome155ProtocolErrors = 1,
}

#[cfg(feature = "quic-h3")]
impl From<PyH3RetryMode> for lkrequest::H3RetryMode {
    fn from(v: PyH3RetryMode) -> Self {
        match v {
            PyH3RetryMode::Safe => lkrequest::H3RetryMode::Safe,
            PyH3RetryMode::Chrome155ProtocolErrors => {
                lkrequest::H3RetryMode::Chrome155ProtocolErrors
            }
        }
    }
}
