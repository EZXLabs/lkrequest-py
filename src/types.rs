//! Shared value-type pyclasses and helpers: `HttpVersion`, `TimeoutConfig`,
//! `ResourceLimits`, `SessionResumptionConfig`, `AcceptEncoding`, pool-stats
//! types, plus duration validation and preset/JSON conversion utilities.

use pyo3::prelude::*;
use std::time::Duration;

/// Validate and convert a Python float to Duration, rejecting NaN/Infinity/negative values
/// that would panic in `Duration::from_secs_f64`.
pub fn validated_duration(secs: f64) -> PyResult<Duration> {
    if !secs.is_finite() || secs < 0.0 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Duration must be a finite non-negative number, got {}",
            secs
        )));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// Accept either a Python `dict[str, str]` or a sequence of `(str, str)` pairs
/// (e.g. `list[tuple[str, str]]`) and produce an ordered `Vec<(String, String)>`.
///
/// Unlike extracting straight into a `HashMap`, this preserves caller order
/// (CPython dicts are insertion-ordered) and allows duplicate keys — both of
/// which matter for header-order fingerprinting and for repeated query/form
/// fields like `?tag=a&tag=b`.
pub struct StrPairs(pub Vec<(String, String)>);

impl<'py> FromPyObject<'py> for StrPairs {
    fn extract_bound(obj: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(dict) = obj.downcast::<pyo3::types::PyDict>() {
            let mut pairs = Vec::with_capacity(dict.len());
            for (k, v) in dict.iter() {
                pairs.push((k.extract::<String>()?, v.extract::<String>()?));
            }
            return Ok(StrPairs(pairs));
        }
        match obj.extract::<Vec<(String, String)>>() {
            Ok(pairs) => Ok(StrPairs(pairs)),
            Err(_) => Err(pyo3::exceptions::PyTypeError::new_err(
                "expected a dict[str, str] or a sequence of (str, str) pairs",
            )),
        }
    }
}

// `hash` is not optional here: `eq` alone makes CPython set `__hash__ = None`,
// and an unhashable enum cannot be a dict key or a set member — which is the
// obvious way to map a version onto something. `frozen` is what `hash` requires
// and costs nothing for a fieldless enum.
#[pyclass(name = "HttpVersion", eq, eq_int, hash, frozen)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PyHttpVersion {
    HTTP10 = 0,
    HTTP11 = 1,
    H2 = 2,
    Unknown = 3,
    H3 = 4,
}

impl From<lkrequest::HttpVersion> for PyHttpVersion {
    fn from(v: lkrequest::HttpVersion) -> Self {
        match v {
            lkrequest::HttpVersion::Http10 => PyHttpVersion::HTTP10,
            lkrequest::HttpVersion::Http11 => PyHttpVersion::HTTP11,
            lkrequest::HttpVersion::H2 => PyHttpVersion::H2,
            lkrequest::HttpVersion::H3 => PyHttpVersion::H3,
            _ => PyHttpVersion::Unknown,
        }
    }
}

#[pyclass(name = "TimeoutConfig")]
#[derive(Clone)]
pub struct PyTimeoutConfig {
    pub(crate) inner: lkrequest::TimeoutConfig,
}

#[pymethods]
impl PyTimeoutConfig {
    #[new]
    #[pyo3(signature = (*, dns=None, tcp_connect=None, tls_handshake=None, ttfb=None, total=None))]
    fn new(
        dns: Option<f64>,
        tcp_connect: Option<f64>,
        tls_handshake: Option<f64>,
        ttfb: Option<f64>,
        total: Option<f64>,
    ) -> PyResult<Self> {
        let mut config = lkrequest::TimeoutConfig::none();
        if let Some(t) = dns {
            config = config.with_dns_timeout(validated_duration(t)?);
        }
        if let Some(t) = tcp_connect {
            config = config.with_tcp_connect_timeout(validated_duration(t)?);
        }
        if let Some(t) = tls_handshake {
            config = config.with_tls_handshake_timeout(validated_duration(t)?);
        }
        if let Some(t) = ttfb {
            config = config.with_ttfb_timeout(validated_duration(t)?);
        }
        if let Some(t) = total {
            config = config.with_total_timeout(validated_duration(t)?);
        }
        Ok(PyTimeoutConfig { inner: config })
    }

    fn __repr__(&self) -> String {
        format!(
            "TimeoutConfig(dns={:?}, tcp_connect={:?}, tls_handshake={:?}, ttfb={:?}, total={:?})",
            self.inner.dns_timeout,
            self.inner.tcp_connect_timeout,
            self.inner.tls_handshake_timeout,
            self.inner.ttfb_timeout,
            self.inner.total_timeout,
        )
    }
}

#[pyclass(name = "ResourceLimits")]
#[derive(Clone)]
pub struct PyResourceLimits {
    pub(crate) inner: lkrequest::ResourceLimits,
}

#[pymethods]
impl PyResourceLimits {
    #[new]
    #[pyo3(signature = (*, max_response_body_size=None, max_connections_per_session=None, min_transfer_rate=None, transfer_rate_window=None))]
    fn new(
        max_response_body_size: Option<usize>,
        max_connections_per_session: Option<usize>,
        min_transfer_rate: Option<usize>,
        transfer_rate_window: Option<f64>,
    ) -> PyResult<Self> {
        let mut limits = lkrequest::ResourceLimits::default();
        if let Some(s) = max_response_body_size {
            limits = limits.with_max_response_body_size(s);
        }
        if let Some(n) = max_connections_per_session {
            limits = limits.with_max_connections_per_session(n);
        }
        if transfer_rate_window.is_some() && min_transfer_rate.is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "transfer_rate_window has no effect without min_transfer_rate; set both or neither",
            ));
        }
        if let Some(rate) = min_transfer_rate {
            let window = validated_duration(transfer_rate_window.unwrap_or(10.0))?;
            limits = limits.with_min_transfer_rate(rate, window);
        }
        Ok(PyResourceLimits { inner: limits })
    }

    fn __repr__(&self) -> String {
        format!(
            "ResourceLimits(max_body={}, max_conn={}, min_rate={:?})",
            self.inner.max_response_body_size,
            self.inner.max_connections_per_session,
            self.inner.min_transfer_rate,
        )
    }
}

// ---------------------------------------------------------------------------
// SessionResumptionConfig — TLS 1.3 PSK / TLS 1.2 ticket resumption control
// ---------------------------------------------------------------------------

#[pyclass(name = "SessionResumptionConfig")]
#[derive(Clone)]
pub struct PySessionResumptionConfig {
    pub(crate) inner: lktls::profile::types::SessionResumptionConfig,
}

#[pymethods]
impl PySessionResumptionConfig {
    #[new]
    #[pyo3(signature = (*, tls13_psk=true, tls12_session_ticket=true, store_tickets=true, max_tickets_per_host=None))]
    fn new(
        tls13_psk: bool,
        tls12_session_ticket: bool,
        store_tickets: bool,
        max_tickets_per_host: Option<usize>,
    ) -> Self {
        PySessionResumptionConfig {
            inner: lktls::profile::types::SessionResumptionConfig {
                tls13_psk,
                tls12_session_ticket,
                store_tickets,
                max_tickets_per_host,
            },
        }
    }

    /// All resumption modes disabled — every connection does a full handshake.
    #[staticmethod]
    fn disabled() -> Self {
        PySessionResumptionConfig {
            inner: lktls::profile::types::SessionResumptionConfig::disabled(),
        }
    }

    /// Chrome-like resumption (all modes enabled — the default).
    #[staticmethod]
    fn chrome() -> Self {
        PySessionResumptionConfig {
            inner: lktls::profile::types::SessionResumptionConfig::chrome(),
        }
    }

    /// Firefox-like resumption (all modes enabled).
    #[staticmethod]
    fn firefox() -> Self {
        PySessionResumptionConfig {
            inner: lktls::profile::types::SessionResumptionConfig::firefox(),
        }
    }

    #[getter]
    fn tls13_psk(&self) -> bool {
        self.inner.tls13_psk
    }

    #[getter]
    fn tls12_session_ticket(&self) -> bool {
        self.inner.tls12_session_ticket
    }

    #[getter]
    fn store_tickets(&self) -> bool {
        self.inner.store_tickets
    }

    #[getter]
    fn max_tickets_per_host(&self) -> Option<usize> {
        self.inner.max_tickets_per_host
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionResumptionConfig(tls13_psk={}, tls12_session_ticket={}, store_tickets={}, max_tickets_per_host={:?})",
            self.inner.tls13_psk,
            self.inner.tls12_session_ticket,
            self.inner.store_tickets,
            self.inner.max_tickets_per_host,
        )
    }
}

pub fn resolve_tls_profile(name: &str) -> PyResult<lktls::profile::TlsProfile> {
    match name {
        "chrome_131" => Ok(lktls::profile::presets::chrome_131()),
        "chrome_144" => Ok(lktls::profile::presets::chrome_144()),
        "chrome_145" => Ok(lktls::profile::presets::chrome_145()),
        "chrome_146" => Ok(lktls::profile::presets::chrome_146()),
        "chrome_147" => Ok(lktls::profile::presets::chrome_147()),
        "chrome_148" => Ok(lktls::profile::presets::chrome_148()),
        "chrome_149" => Ok(lktls::profile::presets::chrome_149()),
        "chrome_150" => Ok(lktls::profile::presets::chrome_150()),
        "chrome_151" => Ok(lktls::profile::presets::chrome_151()),
        "chrome_152" => Ok(lktls::profile::presets::chrome_152()),
        "chrome_153" => Ok(lktls::profile::presets::chrome_153()),
        "chrome_154" => Ok(lktls::profile::presets::chrome_154()),
        "firefox_133" => Ok(lktls::profile::presets::firefox_133()),
        "firefox_147" => Ok(lktls::profile::presets::firefox_147()),
        "firefox_156" => Ok(lktls::profile::presets::firefox_156()),
        "safari_18" => Ok(lktls::profile::presets::safari_18()),
        "safari_26" => Ok(lktls::profile::presets::safari_26()),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown TLS profile: '{}'. Available: chrome_131, chrome_144, chrome_145, chrome_146, chrome_147, chrome_148, chrome_149, chrome_150, chrome_151, chrome_152, chrome_153, chrome_154, firefox_133, firefox_147, firefox_156, safari_18, safari_26",
            name
        ))),
    }
}

pub fn resolve_h2_profile(name: &str) -> PyResult<lkh2::profile::H2Profile> {
    match name {
        "chrome_131" => Ok(lkh2::profile::chrome_131_h2()),
        "chrome_144" => Ok(lkh2::profile::chrome_144_h2()),
        "chrome_145" => Ok(lkh2::profile::chrome_145_h2()),
        "chrome_146" => Ok(lkh2::profile::chrome_146_h2()),
        "chrome_147" => Ok(lkh2::profile::chrome_147_h2()),
        "chrome_148" => Ok(lkh2::profile::chrome_148_h2()),
        "chrome_149" => Ok(lkh2::profile::chrome_149_h2()),
        "chrome_150" => Ok(lkh2::profile::chrome_150_h2()),
        "chrome_151" => Ok(lkh2::profile::chrome_151_h2()),
        "chrome_152" => Ok(lkh2::profile::chrome_152_h2()),
        "chrome_153" => Ok(lkh2::profile::chrome_153_h2()),
        "chrome_154" => Ok(lkh2::profile::chrome_154_h2()),
        "firefox_133" => Ok(lkh2::profile::firefox_133_h2()),
        "firefox_147" => Ok(lkh2::profile::firefox_147_h2()),
        "firefox_156" => Ok(lkh2::profile::firefox_156_h2()),
        "safari_18" => Ok(lkh2::profile::safari_18_h2()),
        "safari_26" => Ok(lkh2::profile::safari_26_h2()),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown H2 profile: '{}'. Available: chrome_131, chrome_144, chrome_145, chrome_146, chrome_147, chrome_148, chrome_149, chrome_150, chrome_151, chrome_152, chrome_153, chrome_154, firefox_133, firefox_147, firefox_156, safari_18, safari_26",
            name
        ))),
    }
}

pub fn resolve_tcp_fingerprint(name: &str) -> PyResult<lkrequest::TcpFingerprint> {
    match name {
        "chrome" => Ok(lkrequest::TcpFingerprint::chrome()),
        "chrome_win" => Ok(lkrequest::TcpFingerprint::chrome_win()),
        "chrome_linux" => Ok(lkrequest::TcpFingerprint::chrome_linux()),
        "chrome_macos" => Ok(lkrequest::TcpFingerprint::chrome_macos()),
        "firefox" => Ok(lkrequest::TcpFingerprint::firefox()),
        "firefox_win" => Ok(lkrequest::TcpFingerprint::firefox_win()),
        "firefox_linux" => Ok(lkrequest::TcpFingerprint::firefox_linux()),
        "firefox_macos" => Ok(lkrequest::TcpFingerprint::firefox_macos()),
        "safari" => Ok(lkrequest::TcpFingerprint::safari()),
        _ => {
            // Try parsing as JA4T string
            lkrequest::TcpFingerprint::from_ja4t(name).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown TCP fingerprint preset '{}' and failed to parse as JA4T: {}",
                    name, e
                ))
            })
        }
    }
}

// ---------------------------------------------------------------------------
// AcceptEncoding — bitflag-style encoding selection
// ---------------------------------------------------------------------------

#[pyclass(name = "AcceptEncoding")]
#[derive(Clone, Copy)]
pub struct PyAcceptEncoding {
    pub(crate) inner: lkrequest::AcceptEncoding,
}

#[pymethods]
impl PyAcceptEncoding {
    #[classattr]
    const GZIP: PyAcceptEncoding = PyAcceptEncoding {
        inner: lkrequest::AcceptEncoding::GZIP,
    };
    #[classattr]
    const BR: PyAcceptEncoding = PyAcceptEncoding {
        inner: lkrequest::AcceptEncoding::BR,
    };
    #[classattr]
    const DEFLATE: PyAcceptEncoding = PyAcceptEncoding {
        inner: lkrequest::AcceptEncoding::DEFLATE,
    };
    #[classattr]
    const ZSTD: PyAcceptEncoding = PyAcceptEncoding {
        inner: lkrequest::AcceptEncoding::ZSTD,
    };
    #[classattr]
    const ALL: PyAcceptEncoding = PyAcceptEncoding {
        inner: lkrequest::AcceptEncoding::ALL,
    };

    fn __or__(&self, other: &PyAcceptEncoding) -> PyAcceptEncoding {
        PyAcceptEncoding {
            inner: self.inner | other.inner,
        }
    }

    fn __repr__(&self) -> String {
        format!("AcceptEncoding({})", self.inner.to_header_value())
    }
}

// ---------------------------------------------------------------------------
// PoolStats — connection pool statistics
// ---------------------------------------------------------------------------

#[pyclass(name = "PoolStats")]
#[derive(Clone)]
pub struct PyPoolStats {
    #[pyo3(get)]
    pub h2_connections: usize,
    #[pyo3(get)]
    pub h1_connections: usize,
    #[pyo3(get)]
    pub total: usize,
    #[pyo3(get)]
    pub max_total: usize,
    #[pyo3(get)]
    pub at_capacity: bool,
}

impl From<lkrequest::PoolStats> for PyPoolStats {
    fn from(s: lkrequest::PoolStats) -> Self {
        PyPoolStats {
            h2_connections: s.h2_connections,
            h1_connections: s.h1_connections,
            total: s.total,
            max_total: s.max_total,
            at_capacity: s.at_capacity,
        }
    }
}

#[pymethods]
impl PyPoolStats {
    fn __repr__(&self) -> String {
        format!(
            "PoolStats(h2={}, h1={}, total={}, max={}, at_capacity={})",
            self.h2_connections, self.h1_connections, self.total, self.max_total, self.at_capacity
        )
    }
}

// ---------------------------------------------------------------------------
// SessionPoolStats
// ---------------------------------------------------------------------------

#[pyclass(name = "SessionPoolStats")]
#[derive(Clone)]
pub struct PySessionPoolStats {
    #[pyo3(get)]
    pub idle_sessions: usize,
    #[pyo3(get)]
    pub max_sessions: usize,
}

impl From<lkrequest::SessionPoolStats> for PySessionPoolStats {
    fn from(s: lkrequest::SessionPoolStats) -> Self {
        PySessionPoolStats {
            idle_sessions: s.idle_sessions,
            max_sessions: s.max_sessions,
        }
    }
}

#[pymethods]
impl PySessionPoolStats {
    fn __repr__(&self) -> String {
        format!(
            "SessionPoolStats(idle={}, max={})",
            self.idle_sessions, self.max_sessions
        )
    }
}

// ---------------------------------------------------------------------------
// H2DataFramePolicy
// ---------------------------------------------------------------------------

/// Capping policy for outbound HTTP/2 DATA frame payloads. Pass to
/// `Client(h2_data_frame_policy=...)`.
///
/// The default keeps whatever the browser preset does natively; set this
/// explicitly only when deliberately reshaping DATA framing, since the frame
/// sizes are themselves an observable fingerprint trait.
#[pyclass(name = "H2DataFramePolicy", eq)]
#[derive(Clone, Copy, PartialEq)]
pub struct PyH2DataFramePolicy {
    pub(crate) inner: lkrequest::H2DataFramePolicy,
}

#[pymethods]
impl PyH2DataFramePolicy {
    /// Keep the browser preset's native framing behaviour (the default).
    #[classattr]
    #[allow(non_snake_case)]
    fn BROWSER_DEFAULT() -> PyH2DataFramePolicy {
        PyH2DataFramePolicy {
            inner: lkrequest::H2DataFramePolicy::BrowserDefault,
        }
    }

    /// Honour only the peer's SETTINGS_MAX_FRAME_SIZE, with no extra cap.
    #[classattr]
    #[allow(non_snake_case)]
    fn PEER_MAX_FRAME_SIZE() -> PyH2DataFramePolicy {
        PyH2DataFramePolicy {
            inner: lkrequest::H2DataFramePolicy::PeerMaxFrameSize,
        }
    }

    /// Cap every DATA payload to a fixed byte count. `max_payload` must be
    /// positive — upstream turns 0 into an `assert!` panic, so reject it here
    /// with a clean ValueError.
    #[staticmethod]
    fn fixed_payload(max_payload: usize) -> PyResult<PyH2DataFramePolicy> {
        if max_payload == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_payload must be greater than zero",
            ));
        }
        Ok(PyH2DataFramePolicy {
            inner: lkrequest::H2DataFramePolicy::FixedPayload(max_payload),
        })
    }

    /// Reserve the 9-byte HTTP/2 frame header inside a target socket write
    /// size. `max_write_size` must exceed 9 — upstream turns anything smaller
    /// into an `assert!` panic, so reject it here with a clean ValueError.
    #[staticmethod]
    fn socket_write_aligned(max_write_size: usize) -> PyResult<PyH2DataFramePolicy> {
        if max_write_size <= 9 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_write_size must exceed the 9-byte HTTP/2 frame header",
            ));
        }
        Ok(PyH2DataFramePolicy {
            inner: lkrequest::H2DataFramePolicy::SocketWriteAligned { max_write_size },
        })
    }

    fn __repr__(&self) -> String {
        match self.inner {
            lkrequest::H2DataFramePolicy::BrowserDefault => {
                "H2DataFramePolicy.BROWSER_DEFAULT".to_string()
            }
            lkrequest::H2DataFramePolicy::PeerMaxFrameSize => {
                "H2DataFramePolicy.PEER_MAX_FRAME_SIZE".to_string()
            }
            lkrequest::H2DataFramePolicy::FixedPayload(n) => {
                format!("H2DataFramePolicy.fixed_payload({n})")
            }
            lkrequest::H2DataFramePolicy::SocketWriteAligned { max_write_size } => {
                format!("H2DataFramePolicy.socket_write_aligned({max_write_size})")
            }
        }
    }
}

pub fn serialize_json(py: Python<'_>, obj: Option<Bound<'_, PyAny>>) -> PyResult<Option<String>> {
    match obj {
        Some(o) => {
            let json_mod = py.import("json")?;
            let s: String = json_mod.call_method1("dumps", (&o,))?.extract()?;
            Ok(Some(s))
        }
        None => Ok(None),
    }
}
