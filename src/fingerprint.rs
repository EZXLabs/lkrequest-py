//! Wire-format fingerprint pyclasses: `TlsProfile`, `H2Profile`, and
//! `TcpFingerprint` (plus their building blocks such as `ExtensionSpec`,
//! `GreaseConfig`, `PaddingStrategy`, and H2 settings/priority types) used to
//! mimic real browser TLS/HTTP2/TCP behaviour.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use lktls::profile::types::{
    self as tls_types, DelegatedCredentialConfig, ExtensionSource, GreaseConfig, PaddingStrategy,
    RandomizationConfig,
};
use lktls::profile::{ExtensionSpec, TlsProfile, TlsVersion};

// ============================================================
// Helper conversion functions
// ============================================================

fn str_to_tls_version(s: &str) -> PyResult<TlsVersion> {
    match s {
        "tls10" => Ok(TlsVersion::Tls10),
        "tls11" => Ok(TlsVersion::Tls11),
        "tls12" => Ok(TlsVersion::Tls12),
        "tls13" => Ok(TlsVersion::Tls13),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown TLS version: '{}'. Use: tls10, tls11, tls12, tls13",
            s
        ))),
    }
}

fn str_to_h2_setting_id(s: &str) -> PyResult<lkh2::profile::H2SettingId> {
    use lkh2::profile::H2SettingId;
    match s {
        "header_table_size" => Ok(H2SettingId::HeaderTableSize),
        "enable_push" => Ok(H2SettingId::EnablePush),
        "max_concurrent_streams" => Ok(H2SettingId::MaxConcurrentStreams),
        "initial_window_size" => Ok(H2SettingId::InitialWindowSize),
        "max_frame_size" => Ok(H2SettingId::MaxFrameSize),
        "max_header_list_size" => Ok(H2SettingId::MaxHeaderListSize),
        "enable_connect_protocol" => Ok(H2SettingId::EnableConnectProtocol),
        "no_rfc7540_priorities" => Ok(H2SettingId::NoRfc7540Priorities),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown H2 setting: '{}'. Use: header_table_size, enable_push, \
             max_concurrent_streams, initial_window_size, max_frame_size, \
             max_header_list_size, enable_connect_protocol, no_rfc7540_priorities",
            s
        ))),
    }
}

fn str_to_pseudo_header_id(s: &str) -> PyResult<lkh2::profile::PseudoHeaderId> {
    use lkh2::profile::PseudoHeaderId;
    match s {
        "method" => Ok(PseudoHeaderId::Method),
        "authority" => Ok(PseudoHeaderId::Authority),
        "scheme" => Ok(PseudoHeaderId::Scheme),
        "path" => Ok(PseudoHeaderId::Path),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown pseudo header: '{}'. Use: method, authority, scheme, path",
            s
        ))),
    }
}

// ============================================================
// ExtType — TLS extension type constants
// ============================================================

#[pyclass(name = "ExtType", frozen)]
pub struct PyExtType;

#[pymethods]
impl PyExtType {
    #[classattr]
    const SNI: u16 = tls_types::ext_type::SNI;
    #[classattr]
    const EC_POINT_FORMATS: u16 = tls_types::ext_type::EC_POINT_FORMATS;
    #[classattr]
    const SUPPORTED_GROUPS: u16 = tls_types::ext_type::SUPPORTED_GROUPS;
    #[classattr]
    const SESSION_TICKET: u16 = tls_types::ext_type::SESSION_TICKET;
    #[classattr]
    const ENCRYPT_THEN_MAC: u16 = tls_types::ext_type::ENCRYPT_THEN_MAC;
    #[classattr]
    const EXTENDED_MASTER_SECRET: u16 = tls_types::ext_type::EXTENDED_MASTER_SECRET;
    #[classattr]
    const SIGNATURE_ALGORITHMS: u16 = tls_types::ext_type::SIGNATURE_ALGORITHMS;
    #[classattr]
    const SUPPORTED_VERSIONS: u16 = tls_types::ext_type::SUPPORTED_VERSIONS;
    #[classattr]
    const PSK_KEY_EXCHANGE_MODES: u16 = tls_types::ext_type::PSK_KEY_EXCHANGE_MODES;
    #[classattr]
    const KEY_SHARE: u16 = tls_types::ext_type::KEY_SHARE;
    #[classattr]
    const ALPN: u16 = tls_types::ext_type::ALPN;
    #[classattr]
    const STATUS_REQUEST: u16 = tls_types::ext_type::STATUS_REQUEST;
    #[classattr]
    const SIGNED_CERTIFICATE_TIMESTAMP: u16 = tls_types::ext_type::SIGNED_CERTIFICATE_TIMESTAMP;
    #[classattr]
    const COMPRESS_CERTIFICATE: u16 = tls_types::ext_type::COMPRESS_CERTIFICATE;
    #[classattr]
    const APPLICATION_SETTINGS: u16 = tls_types::ext_type::APPLICATION_SETTINGS;
    #[classattr]
    const APPLICATION_SETTINGS_NEW: u16 = tls_types::ext_type::APPLICATION_SETTINGS_NEW;
    #[classattr]
    const RENEGOTIATION_INFO: u16 = tls_types::ext_type::RENEGOTIATION_INFO;
    #[classattr]
    const DELEGATED_CREDENTIALS: u16 = tls_types::ext_type::DELEGATED_CREDENTIALS;
    #[classattr]
    const RECORD_SIZE_LIMIT: u16 = tls_types::ext_type::RECORD_SIZE_LIMIT;
    #[classattr]
    const PADDING: u16 = tls_types::ext_type::PADDING;
    #[classattr]
    const COOKIE: u16 = tls_types::ext_type::COOKIE;
    #[classattr]
    const PRE_SHARED_KEY: u16 = tls_types::ext_type::PRE_SHARED_KEY;
    #[classattr]
    const ENCRYPTED_CLIENT_HELLO: u16 = tls_types::ext_type::ENCRYPTED_CLIENT_HELLO;
    /// Chromium/BoringSSL's experimental trust anchor IDs extension (used from
    /// Chrome 152 onwards).
    #[classattr]
    const TRUST_ANCHOR_IDS: u16 = tls_types::ext_type::TRUST_ANCHOR_IDS;
}

// ============================================================
// ExtensionSpec
// ============================================================

#[pyclass(name = "ExtensionSpec")]
#[derive(Clone)]
pub struct PyExtensionSpec {
    pub(crate) inner: ExtensionSpec,
}

#[pymethods]
impl PyExtensionSpec {
    #[new]
    #[pyo3(signature = (extension_type, *, source="auto", raw_data=None, trust_anchor_ids=None, shuffle=false))]
    fn new(
        extension_type: u16,
        source: &str,
        raw_data: Option<&str>,
        trust_anchor_ids: Option<Vec<String>>,
        shuffle: bool,
    ) -> PyResult<Self> {
        let ext_source = match source {
            "auto" => ExtensionSource::Auto,
            "grease" => ExtensionSource::Grease,
            "raw_bytes" => {
                let data = raw_data.ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "raw_data (hex string) is required when source='raw_bytes'",
                    )
                })?;
                ExtensionSource::RawBytes {
                    data: data.to_string(),
                }
            }
            "trust_anchor_ids" => {
                let ids = trust_anchor_ids.ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "trust_anchor_ids (list of hex strings) is required when source='trust_anchor_ids'",
                    )
                })?;
                ExtensionSource::TrustAnchorIds { ids, shuffle }
            }
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown source: '{}'. Use: auto, grease, raw_bytes, trust_anchor_ids",
                    source
                )))
            }
        };
        Ok(PyExtensionSpec {
            inner: ExtensionSpec {
                extension_type,
                source: ext_source,
            },
        })
    }

    #[getter]
    fn extension_type(&self) -> u16 {
        self.inner.extension_type
    }

    #[getter]
    fn source(&self) -> String {
        match &self.inner.source {
            ExtensionSource::Auto => "auto".to_string(),
            ExtensionSource::Grease => "grease".to_string(),
            ExtensionSource::RawBytes { .. } => "raw_bytes".to_string(),
            ExtensionSource::TrustAnchorIds { .. } => "trust_anchor_ids".to_string(),
        }
    }

    /// The hex identifier list for a trust_anchor_ids source; None otherwise.
    #[getter]
    fn trust_anchor_ids(&self) -> Option<Vec<String>> {
        match &self.inner.source {
            ExtensionSource::TrustAnchorIds { ids, .. } => Some(ids.clone()),
            _ => None,
        }
    }

    /// Whether a trust_anchor_ids source reshuffles on every ClientHello;
    /// None for other sources.
    #[getter]
    fn shuffle(&self) -> Option<bool> {
        match &self.inner.source {
            ExtensionSource::TrustAnchorIds { shuffle, .. } => Some(*shuffle),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ExtensionSpec(0x{:04x}, source='{}')",
            self.inner.extension_type,
            self.source()
        )
    }
}

// ============================================================
// GreaseConfig
// ============================================================

#[pyclass(name = "GreaseConfig")]
#[derive(Clone)]
pub struct PyGreaseConfig {
    pub(crate) inner: GreaseConfig,
}

#[pymethods]
impl PyGreaseConfig {
    #[new]
    #[pyo3(signature = (*, cipher_suite=false, extensions=false, supported_groups=false, supported_versions=false, signature_algorithms=false, key_share=false))]
    fn new(
        cipher_suite: bool,
        extensions: bool,
        supported_groups: bool,
        supported_versions: bool,
        signature_algorithms: bool,
        key_share: bool,
    ) -> Self {
        PyGreaseConfig {
            inner: GreaseConfig {
                cipher_suite,
                extensions,
                supported_groups,
                supported_versions,
                signature_algorithms,
                key_share,
            },
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "GreaseConfig(cipher_suite={}, extensions={}, supported_groups={}, \
             supported_versions={}, signature_algorithms={}, key_share={})",
            self.inner.cipher_suite,
            self.inner.extensions,
            self.inner.supported_groups,
            self.inner.supported_versions,
            self.inner.signature_algorithms,
            self.inner.key_share,
        )
    }
}

// ============================================================
// PaddingStrategy
// ============================================================

#[pyclass(name = "PaddingStrategy")]
#[derive(Clone)]
pub struct PyPaddingStrategy {
    pub(crate) inner: PaddingStrategy,
}

#[pymethods]
impl PyPaddingStrategy {
    #[staticmethod]
    fn block_align(min_length: u16, block_size: u16) -> Self {
        PyPaddingStrategy {
            inner: PaddingStrategy::BlockAlign {
                min_length,
                block_size,
            },
        }
    }

    #[staticmethod]
    fn fixed_target(target_length: u16) -> Self {
        PyPaddingStrategy {
            inner: PaddingStrategy::FixedTarget { target_length },
        }
    }

    #[staticmethod]
    fn no_padding() -> Self {
        PyPaddingStrategy {
            inner: PaddingStrategy::None,
        }
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            PaddingStrategy::BlockAlign {
                min_length,
                block_size,
            } => format!(
                "PaddingStrategy.block_align({}, {})",
                min_length, block_size
            ),
            PaddingStrategy::FixedTarget { target_length } => {
                format!("PaddingStrategy.fixed_target({})", target_length)
            }
            PaddingStrategy::None => "PaddingStrategy.no_padding()".to_string(),
        }
    }
}

// ============================================================
// RandomizationConfig
// ============================================================

#[pyclass(name = "RandomizationConfig")]
#[derive(Clone)]
pub struct PyRandomizationConfig {
    pub(crate) inner: RandomizationConfig,
}

#[pymethods]
impl PyRandomizationConfig {
    #[new]
    #[pyo3(signature = (*, shuffle_extensions=false))]
    fn new(shuffle_extensions: bool) -> Self {
        PyRandomizationConfig {
            inner: RandomizationConfig { shuffle_extensions },
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "RandomizationConfig(shuffle_extensions={})",
            self.inner.shuffle_extensions,
        )
    }
}

// ============================================================
// TlsProfile
// ============================================================

#[pyclass(name = "TlsProfile")]
#[derive(Clone)]
pub struct PyTlsProfile {
    pub(crate) inner: TlsProfile,
}

#[pymethods]
impl PyTlsProfile {
    #[new]
    #[pyo3(signature = (
        name,
        *,
        cipher_suites=None,
        extensions=None,
        supported_groups=None,
        signature_algorithms=None,
        key_share_curves=None,
        alpn_protocols=None,
        tls_min_version=None,
        tls_max_version=None,
        ec_point_formats=None,
        compression_methods=None,
        grease=None,
        padding=None,
        alps_protocols=None,
        compress_cert_algorithms=None,
        record_size_limit=None,
        delegated_credentials_sig_algs=None,
        session_id_length=32,
        randomization=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: String,
        cipher_suites: Option<Vec<u16>>,
        extensions: Option<Vec<PyExtensionSpec>>,
        supported_groups: Option<Vec<u16>>,
        signature_algorithms: Option<Vec<u16>>,
        key_share_curves: Option<Vec<u16>>,
        alpn_protocols: Option<Vec<String>>,
        tls_min_version: Option<&str>,
        tls_max_version: Option<&str>,
        ec_point_formats: Option<Vec<u8>>,
        compression_methods: Option<Vec<u8>>,
        grease: Option<PyGreaseConfig>,
        padding: Option<PyPaddingStrategy>,
        alps_protocols: Option<Vec<String>>,
        compress_cert_algorithms: Option<Vec<u16>>,
        record_size_limit: Option<u16>,
        delegated_credentials_sig_algs: Option<Vec<u16>>,
        session_id_length: u8,
        randomization: Option<PyRandomizationConfig>,
    ) -> PyResult<Self> {
        let min_ver = match tls_min_version {
            Some(s) => str_to_tls_version(s)?,
            None => TlsVersion::Tls12,
        };
        let max_ver = match tls_max_version {
            Some(s) => str_to_tls_version(s)?,
            None => TlsVersion::Tls13,
        };

        let profile = TlsProfile {
            name,
            tls_min_version: min_ver,
            tls_max_version: max_ver,
            cipher_suites: cipher_suites.unwrap_or_default(),
            extensions: extensions
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.inner)
                .collect(),
            supported_groups: supported_groups.unwrap_or_default(),
            signature_algorithms: signature_algorithms.unwrap_or_default(),
            ec_point_formats: ec_point_formats.unwrap_or_else(|| vec![0]),
            compression_methods: compression_methods.unwrap_or_else(|| vec![0]),
            grease: grease.map(|g| g.inner).unwrap_or_default(),
            padding: padding.map(|p| p.inner).unwrap_or_default(),
            alps_protocols,
            compress_cert_algorithms,
            key_share_curves: key_share_curves.unwrap_or_default(),
            record_size_limit,
            delegated_credentials: delegated_credentials_sig_algs.map(|sa| {
                DelegatedCredentialConfig {
                    signature_algorithms: sa,
                }
            }),
            session_id_length,
            alpn_protocols: alpn_protocols
                .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]),
            randomization: randomization.map(|r| r.inner),
            session_resumption: Default::default(),
            tls_client_hello_style: Default::default(),
            ech: None,
            ech_outer_extensions: None,
        };
        Ok(PyTlsProfile { inner: profile })
    }

    // ---- Preset constructors ----

    #[staticmethod]
    fn chrome_131() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_131(),
        }
    }
    #[staticmethod]
    fn chrome_144() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_144(),
        }
    }
    #[staticmethod]
    fn chrome_145() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_145(),
        }
    }
    #[staticmethod]
    fn chrome_146() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_146(),
        }
    }
    #[staticmethod]
    fn chrome_147() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_147(),
        }
    }
    #[staticmethod]
    fn chrome_148() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_148(),
        }
    }
    #[staticmethod]
    fn chrome_149() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_149(),
        }
    }
    #[staticmethod]
    fn chrome_150() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_150(),
        }
    }
    #[staticmethod]
    fn chrome_151() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_151(),
        }
    }
    /// Chrome 152: the first Chromium profile that GREASEs `signature_algorithms`
    /// and carries shuffled trust-anchor identifiers (extension `0xca34`).
    #[staticmethod]
    fn chrome_152() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_152(),
        }
    }
    /// Chrome 146 QUIC-TLS profile: the ClientHello Chrome sends *inside* QUIC,
    /// which differs from the TCP profile of the same version. Pass it to
    /// `Client(quic_fingerprint=...)`; HTTP/3 otherwise reuses the main TLS profile.
    #[staticmethod]
    fn chrome_146_quic() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_146_quic(),
        }
    }
    /// Chrome 150 QUIC-TLS profile (see `chrome_146_quic`).
    #[staticmethod]
    fn chrome_150_quic() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_150_quic(),
        }
    }
    /// Chrome 151 QUIC-TLS profile: Chrome 150's QUIC ClientHello minus the three
    /// ML-DSA signature algorithms, matching real Chrome 151 HTTP/3 captures.
    #[staticmethod]
    fn chrome_151_quic() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_151_quic(),
        }
    }
    /// Chrome 152 QUIC-TLS profile (see `chrome_146_quic`).
    #[staticmethod]
    fn chrome_152_quic() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::chrome_152_quic(),
        }
    }
    #[staticmethod]
    fn firefox_133() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::firefox_133(),
        }
    }
    #[staticmethod]
    fn firefox_147() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::firefox_147(),
        }
    }
    #[staticmethod]
    fn safari_18() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::safari_18(),
        }
    }
    #[staticmethod]
    fn safari_26() -> Self {
        PyTlsProfile {
            inner: lktls::profile::presets::safari_26(),
        }
    }

    // ---- JSON loading/saving ----

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let profile = lktls::profile::loader::from_json_str(json_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Failed to parse TLS profile JSON: {}",
                e
            ))
        })?;
        Ok(PyTlsProfile { inner: profile })
    }

    // ---- lkprofile integration ----

    #[staticmethod]
    #[pyo3(signature = (data, *, name="captured"))]
    fn from_client_hello(data: &[u8], name: &str) -> PyResult<Self> {
        let ch = lkprofile::parse_client_hello(data).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to parse ClientHello: {}", e))
        })?;
        let profile = lkprofile::build_tls_profile(name, &ch);
        Ok(PyTlsProfile { inner: profile })
    }

    #[staticmethod]
    fn from_json_file(path: &str) -> PyResult<Self> {
        let profile = lktls::profile::loader::from_json_file(path).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Failed to load TLS profile from '{}': {}",
                path, e
            ))
        })?;
        Ok(PyTlsProfile { inner: profile })
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("JSON serialization failed: {}", e))
        })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let json_str = self.to_json()?;
        let json_mod = py.import("json")?;
        let obj = json_mod.call_method1("loads", (&json_str,))?;
        obj.downcast_into::<PyDict>().map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Unexpected conversion error: {}", e))
        })
    }

    // ---- Properties ----

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn cipher_suites(&self) -> Vec<u16> {
        self.inner.cipher_suites.clone()
    }

    #[getter]
    fn supported_groups(&self) -> Vec<u16> {
        self.inner.supported_groups.clone()
    }

    #[getter]
    fn signature_algorithms(&self) -> Vec<u16> {
        self.inner.signature_algorithms.clone()
    }

    #[getter]
    fn alpn_protocols(&self) -> Vec<String> {
        self.inner.alpn_protocols.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "TlsProfile('{}', ciphers={}, extensions={}, groups={})",
            self.inner.name,
            self.inner.cipher_suites.len(),
            self.inner.extensions.len(),
            self.inner.supported_groups.len(),
        )
    }
}

// ============================================================
// H2Setting
// ============================================================

#[pyclass(name = "H2Setting")]
#[derive(Clone)]
pub struct PyH2Setting {
    pub(crate) inner: lkh2::profile::H2Setting,
}

#[pymethods]
impl PyH2Setting {
    #[new]
    fn new(id: &Bound<'_, PyAny>, value: u32) -> PyResult<Self> {
        let setting_id = if let Ok(s) = id.extract::<String>() {
            str_to_h2_setting_id(&s)?
        } else if let Ok(n) = id.extract::<u16>() {
            lkh2::profile::H2SettingId::Unknown(n)
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "id must be str (e.g. 'header_table_size') or int",
            ));
        };
        Ok(PyH2Setting {
            inner: lkh2::profile::H2Setting {
                id: setting_id,
                value,
            },
        })
    }

    #[getter]
    fn value(&self) -> u32 {
        self.inner.value
    }

    fn __repr__(&self) -> String {
        format!("H2Setting({:?}, {})", self.inner.id, self.inner.value)
    }
}

// ============================================================
// HeadersPriority
// ============================================================

#[pyclass(name = "HeadersPriority")]
#[derive(Clone)]
pub struct PyHeadersPriority {
    pub(crate) inner: lkh2::profile::HeadersPriority,
}

#[pymethods]
impl PyHeadersPriority {
    #[new]
    fn new(stream_dependency: u32, weight: u8, exclusive: bool) -> Self {
        PyHeadersPriority {
            inner: lkh2::profile::HeadersPriority {
                stream_dependency,
                weight,
                exclusive,
            },
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "HeadersPriority(dep={}, weight={}, exclusive={})",
            self.inner.stream_dependency, self.inner.weight, self.inner.exclusive,
        )
    }
}

// ============================================================
// PriorityFrame
// ============================================================

#[pyclass(name = "PriorityFrame")]
#[derive(Clone)]
pub struct PyPriorityFrame {
    pub(crate) inner: lkh2::profile::ProfilePriorityFrame,
}

#[pymethods]
impl PyPriorityFrame {
    #[new]
    fn new(stream_id: u32, dependency: u32, weight: u8, exclusive: bool) -> Self {
        PyPriorityFrame {
            inner: lkh2::profile::ProfilePriorityFrame {
                stream_id,
                dependency,
                weight,
                exclusive,
            },
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "PriorityFrame(stream={}, dep={}, weight={}, exclusive={})",
            self.inner.stream_id, self.inner.dependency, self.inner.weight, self.inner.exclusive,
        )
    }
}

// ============================================================
// PriorityConfig
// ============================================================

/// Per-browser H2 priority strategy: how a request's urgency maps to the
/// HEADERS-frame wire weight / exclusive bit / stream dependencies, and whether
/// the RFC 9218 `priority` header is auto-injected.
///
/// The named browser presets already embed the right config; construct one of
/// these only when hand-building an `H2Profile` and pass it via the
/// `priority_config` argument:
///
/// ```python
/// H2Profile(settings, window_update, order, priority_config=PriorityConfig.chrome())
/// ```
#[pyclass(name = "PriorityConfig")]
#[derive(Clone)]
pub struct PyPriorityConfig {
    pub(crate) inner: lkh2::profile::PriorityConfig,
}

fn str_to_stream_dep_policy(s: &str) -> PyResult<lkh2::profile::StreamDepPolicy> {
    match s {
        "flat" => Ok(lkh2::profile::StreamDepPolicy::Flat),
        "chain" => Ok(lkh2::profile::StreamDepPolicy::Chain),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown stream_dep_policy: '{}'. Use 'flat' or 'chain'",
            other
        ))),
    }
}

fn stream_dep_policy_to_str(p: lkh2::profile::StreamDepPolicy) -> &'static str {
    match p {
        lkh2::profile::StreamDepPolicy::Flat => "flat",
        lkh2::profile::StreamDepPolicy::Chain => "chain",
    }
}

#[pymethods]
impl PyPriorityConfig {
    /// Construct a custom priority configuration.
    ///
    /// `urgency_weights`, when given, must be exactly 8 bytes (urgency 0–7 ->
    /// H2 wire weight 0–255). `stream_dep_policy` is `"flat"` or `"chain"`.
    #[new]
    #[pyo3(signature = (
        *,
        urgency_weights=None,
        exclusive=false,
        stream_dep_policy="flat",
        auto_priority_header=false,
        default_urgency=3,
        default_incremental=false,
    ))]
    fn new(
        urgency_weights: Option<Vec<u8>>,
        exclusive: bool,
        stream_dep_policy: &str,
        auto_priority_header: bool,
        default_urgency: u8,
        default_incremental: bool,
    ) -> PyResult<Self> {
        let weights = match urgency_weights {
            Some(w) => {
                let arr: [u8; 8] = w.try_into().map_err(|v: Vec<u8>| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "urgency_weights must have exactly 8 elements, got {}",
                        v.len()
                    ))
                })?;
                Some(arr)
            }
            None => None,
        };
        if default_urgency > 7 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "default_urgency must be in the range 0–7",
            ));
        }
        Ok(PyPriorityConfig {
            inner: lkh2::profile::PriorityConfig {
                urgency_weights: weights,
                exclusive,
                stream_dep_policy: str_to_stream_dep_policy(stream_dep_policy)?,
                auto_priority_header,
                default_urgency,
                default_incremental,
            },
        })
    }

    /// Neutral default: no urgency weights, no auto priority header.
    #[staticmethod]
    fn default_config() -> Self {
        PyPriorityConfig {
            inner: lkh2::profile::PriorityConfig::default(),
        }
    }

    /// Chrome priority strategy (urgency weights, exclusive, chained deps,
    /// auto RFC 9218 header).
    #[staticmethod]
    fn chrome() -> Self {
        PyPriorityConfig {
            inner: lkh2::profile::PriorityConfig::chrome(),
        }
    }

    /// Firefox priority strategy (fixed weight, auto RFC 9218 header).
    #[staticmethod]
    fn firefox() -> Self {
        PyPriorityConfig {
            inner: lkh2::profile::PriorityConfig::firefox(),
        }
    }

    /// Safari 18 priority strategy (RFC 7540 priorities, no HTTP header).
    #[staticmethod]
    fn safari18() -> Self {
        PyPriorityConfig {
            inner: lkh2::profile::PriorityConfig::safari18(),
        }
    }

    /// Safari 26 priority strategy (RFC 9218 only, no H2 frame priority).
    #[staticmethod]
    fn safari26() -> Self {
        PyPriorityConfig {
            inner: lkh2::profile::PriorityConfig::safari26(),
        }
    }

    #[getter]
    fn urgency_weights(&self) -> Option<Vec<u16>> {
        // Map to u16 so PyO3 yields a list[int]; a Vec<u8> would become `bytes`.
        self.inner
            .urgency_weights
            .map(|w| w.iter().map(|&b| b as u16).collect())
    }

    #[getter]
    fn exclusive(&self) -> bool {
        self.inner.exclusive
    }

    #[getter]
    fn stream_dep_policy(&self) -> &'static str {
        stream_dep_policy_to_str(self.inner.stream_dep_policy)
    }

    #[getter]
    fn auto_priority_header(&self) -> bool {
        self.inner.auto_priority_header
    }

    #[getter]
    fn default_urgency(&self) -> u8 {
        self.inner.default_urgency
    }

    #[getter]
    fn default_incremental(&self) -> bool {
        self.inner.default_incremental
    }

    fn __repr__(&self) -> String {
        format!(
            "PriorityConfig(urgency_weights={:?}, exclusive={}, stream_dep_policy={:?}, auto_priority_header={}, default_urgency={}, default_incremental={})",
            self.inner.urgency_weights,
            self.inner.exclusive,
            stream_dep_policy_to_str(self.inner.stream_dep_policy),
            self.inner.auto_priority_header,
            self.inner.default_urgency,
            self.inner.default_incremental,
        )
    }
}

// ============================================================
// H2Profile
// ============================================================

#[pyclass(name = "H2Profile")]
#[derive(Clone)]
pub struct PyH2Profile {
    pub(crate) inner: lkh2::profile::H2Profile,
}

#[pymethods]
impl PyH2Profile {
    #[new]
    #[pyo3(signature = (
        settings,
        window_update,
        pseudo_header_order,
        *,
        headers_priority=None,
        priority_frames=None,
        priority_config=None,
    ))]
    fn new(
        settings: Vec<PyH2Setting>,
        window_update: u32,
        pseudo_header_order: Vec<String>,
        headers_priority: Option<PyHeadersPriority>,
        priority_frames: Option<Vec<PyPriorityFrame>>,
        priority_config: Option<PyPriorityConfig>,
    ) -> PyResult<Self> {
        let pho: Vec<lkh2::profile::PseudoHeaderId> = pseudo_header_order
            .iter()
            .map(|s| str_to_pseudo_header_id(s))
            .collect::<PyResult<Vec<_>>>()?;

        Ok(PyH2Profile {
            inner: lkh2::profile::H2Profile {
                settings: settings.into_iter().map(|s| s.inner).collect(),
                window_update,
                pseudo_header_order: pho,
                headers_priority: headers_priority.map(|h| h.inner),
                priority_frames: priority_frames
                    .unwrap_or_default()
                    .into_iter()
                    .map(|p| p.inner)
                    .collect(),
                priority_config: priority_config.map(|c| c.inner).unwrap_or_default(),
                behavior: None,
            },
        })
    }

    /// The H2 priority strategy embedded in this profile.
    #[getter]
    fn priority_config(&self) -> PyPriorityConfig {
        PyPriorityConfig {
            inner: self.inner.priority_config.clone(),
        }
    }

    // ---- Preset constructors ----

    #[staticmethod]
    fn chrome_131() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_131_h2(),
        }
    }
    #[staticmethod]
    fn chrome_144() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_144_h2(),
        }
    }
    #[staticmethod]
    fn chrome_145() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_145_h2(),
        }
    }
    #[staticmethod]
    fn chrome_146() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_146_h2(),
        }
    }
    #[staticmethod]
    fn chrome_147() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_147_h2(),
        }
    }
    #[staticmethod]
    fn chrome_148() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_148_h2(),
        }
    }
    #[staticmethod]
    fn chrome_149() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_149_h2(),
        }
    }
    #[staticmethod]
    fn chrome_150() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_150_h2(),
        }
    }
    #[staticmethod]
    fn chrome_151() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_151_h2(),
        }
    }
    /// Chrome 152 H2 profile: retains Chrome 151's stable SETTINGS / window shape.
    #[staticmethod]
    fn chrome_152() -> Self {
        PyH2Profile {
            inner: lkh2::profile::chrome_152_h2(),
        }
    }
    #[staticmethod]
    fn firefox_133() -> Self {
        PyH2Profile {
            inner: lkh2::profile::firefox_133_h2(),
        }
    }
    #[staticmethod]
    fn firefox_147() -> Self {
        PyH2Profile {
            inner: lkh2::profile::firefox_147_h2(),
        }
    }
    #[staticmethod]
    fn safari_18() -> Self {
        PyH2Profile {
            inner: lkh2::profile::safari_18_h2(),
        }
    }
    #[staticmethod]
    fn safari_26() -> Self {
        PyH2Profile {
            inner: lkh2::profile::safari_26_h2(),
        }
    }

    // ---- JSON loading/saving ----

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let profile: lkh2::profile::H2Profile = serde_json::from_str(json_str).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Failed to parse H2 profile JSON: {}",
                e
            ))
        })?;
        Ok(PyH2Profile { inner: profile })
    }

    // ---- lkprofile integration ----

    #[staticmethod]
    fn from_h2_frames(data: &[u8]) -> PyResult<Self> {
        let h2fp = lkprofile::h2_fingerprint_from_frames(data).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to parse H2 frames: {}", e))
        })?;
        let json_val = serde_json::to_value(&h2fp.profile).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "H2 profile conversion failed: {}",
                e
            ))
        })?;
        let profile: lkh2::profile::H2Profile = serde_json::from_value(json_val).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "H2 profile deserialization failed: {}",
                e
            ))
        })?;
        Ok(PyH2Profile { inner: profile })
    }

    #[staticmethod]
    fn from_json_file(path: &str) -> PyResult<Self> {
        let data = std::fs::read_to_string(path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to read H2 profile from '{}': {}",
                path, e
            ))
        })?;
        Self::from_json(&data)
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("JSON serialization failed: {}", e))
        })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let json_str = self.to_json()?;
        let json_mod = py.import("json")?;
        let obj = json_mod.call_method1("loads", (&json_str,))?;
        obj.downcast_into::<PyDict>().map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("Unexpected conversion error: {}", e))
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "H2Profile(settings={}, window_update={})",
            self.inner.settings.len(),
            self.inner.window_update,
        )
    }
}

// ============================================================
// TcpFingerprint
// ============================================================

#[pyclass(name = "TcpFingerprint")]
#[derive(Clone)]
pub struct PyTcpFingerprint {
    pub(crate) inner: lkrequest::TcpFingerprint,
}

#[pymethods]
impl PyTcpFingerprint {
    #[new]
    #[pyo3(signature = (
        *,
        window_size=None,
        mss=None,
        window_scale=None,
        ttl=None,
        tcp_nodelay=None,
        recv_buf_size=None,
        send_buf_size=None,
    ))]
    fn new(
        window_size: Option<u32>,
        mss: Option<u32>,
        window_scale: Option<u8>,
        ttl: Option<u32>,
        tcp_nodelay: Option<bool>,
        recv_buf_size: Option<u32>,
        send_buf_size: Option<u32>,
    ) -> Self {
        let mut fp = lkrequest::TcpFingerprint::none();
        if let Some(v) = window_size {
            fp = fp.with_window_size(v);
        }
        if let Some(v) = mss {
            fp = fp.with_mss(v);
        }
        if let Some(v) = window_scale {
            fp = fp.with_window_scale(v);
        }
        if let Some(v) = ttl {
            fp = fp.with_ttl(v);
        }
        if let Some(v) = tcp_nodelay {
            fp = fp.with_tcp_nodelay(v);
        }
        if let Some(v) = recv_buf_size {
            fp = fp.with_recv_buf_size(v);
        }
        if let Some(v) = send_buf_size {
            fp = fp.with_send_buf_size(v);
        }
        PyTcpFingerprint { inner: fp }
    }

    // ---- JA4T ----

    #[staticmethod]
    fn from_ja4t(ja4t: &str) -> PyResult<Self> {
        let fp = lkrequest::TcpFingerprint::from_ja4t(ja4t).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid JA4T string: {}", e))
        })?;
        Ok(PyTcpFingerprint { inner: fp })
    }

    fn to_ja4t(&self) -> Option<String> {
        self.inner.to_ja4t()
    }

    // ---- Preset constructors ----

    #[staticmethod]
    fn chrome() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::chrome(),
        }
    }
    #[staticmethod]
    fn chrome_win() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::chrome_win(),
        }
    }
    #[staticmethod]
    fn chrome_linux() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::chrome_linux(),
        }
    }
    #[staticmethod]
    fn chrome_macos() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::chrome_macos(),
        }
    }
    #[staticmethod]
    fn firefox() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::firefox(),
        }
    }
    #[staticmethod]
    fn firefox_win() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::firefox_win(),
        }
    }
    #[staticmethod]
    fn firefox_linux() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::firefox_linux(),
        }
    }
    #[staticmethod]
    fn firefox_macos() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::firefox_macos(),
        }
    }
    #[staticmethod]
    fn safari() -> Self {
        PyTcpFingerprint {
            inner: lkrequest::TcpFingerprint::safari(),
        }
    }

    fn __repr__(&self) -> String {
        match self.inner.to_ja4t() {
            Some(ja4t) => format!("TcpFingerprint(ja4t='{}')", ja4t),
            None => "TcpFingerprint()".to_string(),
        }
    }
}
