//! Async `Client` and blocking `BlockingClient` pyclasses: the configurable
//! HTTP client entry points that build a `lkrequest::Client` from fingerprint,
//! protocol, retry, proxy, and timeout settings and issue requests.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

use crate::fingerprint::{PyH2Profile, PyTcpFingerprint, PyTlsProfile};
use crate::hsts::PyHsts;
use crate::middleware::{PyMiddleware, PyMiddlewareWrapper};
use crate::protocol::{PyBrokenQuicPolicy, PyHttpIntent, PyProtocolPolicy};
use crate::proxy::apply_session_proxy;
use crate::randomize::PyRandomize;
use crate::retry::{PyCallableRetryPolicy, PyExponentialBackoff, PyFixedInterval};
use crate::session::{EventHooks, PyBlockingSession, PySession};
use crate::types::{
    resolve_h2_profile, resolve_tcp_fingerprint, resolve_tls_profile, validated_duration,
    PyAcceptEncoding, PySessionResumptionConfig,
};

fn resolve_tls_from_any(obj: &Bound<'_, PyAny>) -> PyResult<lktls::profile::TlsProfile> {
    if let Ok(s) = obj.extract::<String>() {
        resolve_tls_profile(&s)
    } else if let Ok(p) = obj.extract::<PyTlsProfile>() {
        Ok(p.inner)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "tls_profile must be str (preset name) or TlsProfile object",
        ))
    }
}

fn resolve_h2_from_any(obj: &Bound<'_, PyAny>) -> PyResult<lkh2::profile::H2Profile> {
    if let Ok(s) = obj.extract::<String>() {
        resolve_h2_profile(&s)
    } else if let Ok(p) = obj.extract::<PyH2Profile>() {
        Ok(p.inner)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "h2_profile must be str (preset name) or H2Profile object",
        ))
    }
}

/// Resolve a QUIC profile from a preset name (`"chrome"` / `"chrome_146"` /
/// `"chrome_150"` / `"chrome_151"` / `"chrome_152"` / `"chrome_153"` /
/// `"chrome_154"`) or a
/// `QuicProfile` object. Requires the `quic-h3` feature; without it any value is
/// rejected with a clear error.
#[cfg(feature = "quic-h3")]
fn resolve_quic_from_any(obj: &Bound<'_, PyAny>) -> PyResult<lkrequest::QuicProfile> {
    if let Ok(s) = obj.extract::<String>() {
        match s.as_str() {
            "chrome" => Ok(lkrequest::lkh3::chrome_quic()),
            "chrome_146" => Ok(lkrequest::lkh3::chrome_146_quic()),
            "chrome_150" => Ok(lkrequest::lkh3::chrome_150_quic()),
            "chrome_151" => Ok(lkrequest::lkh3::chrome_151_quic()),
            "chrome_152" => Ok(lkrequest::lkh3::chrome_152_quic()),
            "chrome_153" => Ok(lkrequest::lkh3::chrome_153_quic()),
            "chrome_154" => Ok(lkrequest::lkh3::chrome_154_quic()),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown QUIC profile: '{}'. Available: chrome, chrome_146, chrome_150, chrome_151, chrome_152, chrome_153, chrome_154",
                s
            ))),
        }
    } else if let Ok(p) = obj.extract::<crate::quic::PyQuicProfile>() {
        Ok(p.inner)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "quic_profile must be str (preset name) or QuicProfile object",
        ))
    }
}

#[cfg(not(feature = "quic-h3"))]
fn resolve_quic_from_any(_obj: &Bound<'_, PyAny>) -> PyResult<lkrequest::QuicProfile> {
    Err(pyo3::exceptions::PyRuntimeError::new_err(
        "quic_profile requires building lkrequest-py with the 'quic-h3' feature: maturin develop --features quic-h3",
    ))
}

fn resolve_tcp_from_any(obj: &Bound<'_, PyAny>) -> PyResult<lkrequest::TcpFingerprint> {
    if let Ok(s) = obj.extract::<String>() {
        resolve_tcp_fingerprint(&s)
    } else if let Ok(p) = obj.extract::<PyTcpFingerprint>() {
        Ok(p.inner)
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "tcp_fingerprint must be str (preset name or JA4T) or TcpFingerprint object",
        ))
    }
}

fn apply_retry_policy(
    builder: lkrequest::session::SessionBuilder,
    retry_obj: &Bound<'_, PyAny>,
) -> PyResult<lkrequest::session::SessionBuilder> {
    if let Ok(eb) = retry_obj.extract::<PyExponentialBackoff>() {
        Ok(builder.retry_policy(eb.inner))
    } else if let Ok(fi) = retry_obj.extract::<PyFixedInterval>() {
        Ok(builder.retry_policy(fi.inner))
    } else if retry_obj.is_callable() {
        let callable = retry_obj.clone().unbind();
        Ok(builder.retry_policy(PyCallableRetryPolicy::new(callable)))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "retry must be ExponentialBackoff, FixedInterval, or a callable(attempt, error, status) -> float | None",
        ))
    }
}

fn apply_middlewares_to_session(
    mut builder: lkrequest::session::SessionBuilder,
    middlewares: &[PyMiddleware],
) -> lkrequest::session::SessionBuilder {
    for mw in middlewares {
        builder = builder.middleware(PyMiddlewareWrapper::from_py(mw));
    }
    builder
}

/// Resolve a DNS resolver preset name. The three `*_https` (DNS-over-HTTPS)
/// presets sit behind upstream's `doh` feature; the published wheel always
/// enables it (see `pyproject.toml`), so user-visible behaviour is unchanged.
/// A reduced-feature build rejects those three names with an actionable error
/// rather than a vague "Unknown DNS config".
fn resolve_dns_config(name: &str) -> PyResult<lkrequest::dns::DnsConfig> {
    match name {
        "system" => Ok(lkrequest::dns::DnsConfig::System),
        "google" => Ok(lkrequest::dns::DnsConfig::Google),
        "cloudflare" => Ok(lkrequest::dns::DnsConfig::Cloudflare),
        "quad9" => Ok(lkrequest::dns::DnsConfig::Quad9),
        #[cfg(feature = "doh")]
        "google_https" => Ok(lkrequest::dns::DnsConfig::GoogleHttps),
        #[cfg(feature = "doh")]
        "cloudflare_https" => Ok(lkrequest::dns::DnsConfig::CloudflareHttps),
        #[cfg(feature = "doh")]
        "quad9_https" => Ok(lkrequest::dns::DnsConfig::Quad9Https),
        #[cfg(not(feature = "doh"))]
        "google_https" | "cloudflare_https" | "quad9_https" => {
            Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "DNS config '{}' requires building lkrequest-py with the 'doh' feature: maturin develop --features doh",
                name
            )))
        }
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unknown DNS config: '{}'. Available: system, google, google_https, cloudflare, cloudflare_https, quad9, quad9_https",
            name
        ))),
    }
}

/// All resolved options for constructing a [`lkrequest::Client`], grouped so
/// the (long) set of settings is threaded by name rather than by ~30 positional
/// arguments. Adding a new option is a single named field set at each call
/// site, which the compiler checks for completeness — there is no risk of
/// mis-aligning two same-typed positional arguments.
#[derive(Default)]
struct ClientConfig {
    tls_profile: Option<lktls::profile::TlsProfile>,
    h2_profile: Option<lkh2::profile::H2Profile>,
    tcp_fingerprint: Option<lkrequest::TcpFingerprint>,
    default_headers: Option<HashMap<String, String>>,
    header_order: Option<Vec<String>>,
    h3_header_order: Option<Vec<String>>,
    cookie_order: Option<Vec<String>>,
    dns_timeout: Option<f64>,
    tcp_connect_timeout: Option<f64>,
    tls_handshake_timeout: Option<f64>,
    ttfb_timeout: Option<f64>,
    total_timeout: Option<f64>,
    max_response_body_size: Option<usize>,
    max_connections_per_session: Option<usize>,
    max_pending_h2_requests: Option<usize>,
    h2_dispatch_batch_size: Option<usize>,
    quic_connect_timeout: Option<f64>,
    max_header_count: Option<usize>,
    max_header_size: Option<usize>,
    max_headers_total_size: Option<usize>,
    min_transfer_rate: Option<usize>,
    min_transfer_rate_window: Option<f64>,
    h2_fallback_h1: Option<bool>,
    proxy_fallback_direct: Option<bool>,
    retry_on_connection_close: Option<bool>,
    middleware: Option<Vec<PyMiddleware>>,
    ca_cert: Option<String>,
    ca_cert_pem: Option<Vec<u8>>,
    ca_cert_der: Option<Vec<u8>>,
    verify: Option<bool>,
    use_native_certs: bool,
    ech_config: Option<Vec<u8>>,
    dns: Option<String>,
    ip_family: Option<String>,
    connect_to: Option<HashMap<String, String>>,
    system_dns_cache_ttl: Option<f64>,
    system_dns_cache_max_entries: Option<usize>,
    keylog: Option<String>,
    protocol_policy: Option<lkrequest::ProtocolPolicy>,
    session_resumption: Option<lktls::profile::types::SessionResumptionConfig>,
    disable_http3: bool,
    quic_fingerprint: Option<lktls::profile::TlsProfile>,
    quic_profile: Option<lkrequest::QuicProfile>,
    randomize: Option<lkrequest::Randomize>,
    h2_data_frame_policy: Option<lkrequest::H2DataFramePolicy>,
    require_close_notify: Option<bool>,
    tls_session_resumption_policy: Option<lkrequest::TlsSessionResumptionPolicy>,
    tls_session_cache_partition_policy: Option<lkrequest::TlsSessionCachePartitionPolicy>,
    masque: Option<crate::masque::OuterConfig>,
}

fn build_client(cfg: ClientConfig) -> PyResult<lkrequest::Client> {
    let ClientConfig {
        tls_profile,
        h2_profile,
        tcp_fingerprint,
        default_headers,
        header_order,
        h3_header_order,
        cookie_order,
        dns_timeout,
        tcp_connect_timeout,
        tls_handshake_timeout,
        ttfb_timeout,
        total_timeout,
        max_response_body_size,
        max_connections_per_session,
        max_pending_h2_requests,
        h2_dispatch_batch_size,
        quic_connect_timeout,
        max_header_count,
        max_header_size,
        max_headers_total_size,
        min_transfer_rate,
        min_transfer_rate_window,
        h2_fallback_h1,
        proxy_fallback_direct,
        retry_on_connection_close,
        middleware,
        ca_cert,
        ca_cert_pem,
        ca_cert_der,
        verify,
        use_native_certs,
        ech_config,
        dns,
        ip_family,
        connect_to,
        system_dns_cache_ttl,
        system_dns_cache_max_entries,
        keylog,
        protocol_policy,
        session_resumption,
        disable_http3,
        quic_fingerprint,
        quic_profile,
        randomize,
        h2_data_frame_policy,
        require_close_notify,
        tls_session_resumption_policy,
        tls_session_cache_partition_policy,
        masque,
    } = cfg;

    let mut builder = lkrequest::Client::builder();

    if let Some(p) = tls_profile {
        builder = builder.fingerprint(p);
    }
    if let Some(p) = h2_profile {
        builder = builder.h2_profile(p);
    }
    if let Some(fp) = tcp_fingerprint {
        builder = builder.tcp_fingerprint(fp);
    }
    if let Some(headers) = default_headers {
        for (k, v) in headers {
            builder = builder.default_header(&k, &v);
        }
    }
    if let Some(order) = header_order {
        let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        builder = builder.header_order(refs);
    }
    if let Some(order) = h3_header_order {
        let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        builder = builder.h3_header_order(refs);
    }
    if let Some(order) = cookie_order {
        let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        builder = builder.cookie_order(refs);
    }
    // Timeouts and resource limits are gathered into a single TimeoutConfig /
    // ResourceLimits each (seeded from the defaults the builder would use) and
    // applied via the whole-struct setters. This is how we reach fields with no
    // dedicated ClientBuilder method — quic_connect_timeout, the header
    // count/size caps, and min_transfer_rate — without clobbering the others.
    if dns_timeout.is_some()
        || tcp_connect_timeout.is_some()
        || tls_handshake_timeout.is_some()
        || ttfb_timeout.is_some()
        || total_timeout.is_some()
        || quic_connect_timeout.is_some()
    {
        let mut tc = lkrequest::TimeoutConfig::default();
        if let Some(t) = dns_timeout {
            tc.dns_timeout = Some(validated_duration(t)?);
        }
        if let Some(t) = tcp_connect_timeout {
            tc.tcp_connect_timeout = Some(validated_duration(t)?);
        }
        if let Some(t) = tls_handshake_timeout {
            tc.tls_handshake_timeout = Some(validated_duration(t)?);
        }
        if let Some(t) = ttfb_timeout {
            tc.ttfb_timeout = Some(validated_duration(t)?);
        }
        if let Some(t) = total_timeout {
            tc.total_timeout = Some(validated_duration(t)?);
        }
        if let Some(t) = quic_connect_timeout {
            tc.quic_connect_timeout = Some(validated_duration(t)?);
        }
        builder = builder.timeout_config(tc);
    }
    if max_response_body_size.is_some()
        || max_connections_per_session.is_some()
        || max_header_count.is_some()
        || max_header_size.is_some()
        || max_headers_total_size.is_some()
        || min_transfer_rate.is_some()
    {
        let mut rl = lkrequest::ResourceLimits::default();
        if let Some(s) = max_response_body_size {
            rl.max_response_body_size = s;
        }
        if let Some(n) = max_connections_per_session {
            rl.max_connections_per_session = n;
        }
        if let Some(n) = max_header_count {
            rl.max_header_count = n;
        }
        if let Some(n) = max_header_size {
            rl.max_header_size = n;
        }
        if let Some(n) = max_headers_total_size {
            rl.max_headers_total_size = n;
        }
        if let Some(rate) = min_transfer_rate {
            rl.min_transfer_rate = Some(rate);
            if let Some(w) = min_transfer_rate_window {
                rl.transfer_rate_window = validated_duration(w)?;
            }
        }
        builder = builder.resource_limits(rl);
    }
    // Upstream asserts this is non-zero, which would surface as a panic rather
    // than a Python exception. Leaving it unset keeps the default (unbounded).
    if let Some(n) = max_pending_h2_requests {
        if n == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_pending_h2_requests must be greater than 0 (omit it for unbounded)",
            ));
        }
        builder = builder.max_pending_h2_requests(n);
    }
    // Upstream asserts this is non-zero too. The default of 1 sends each ready
    // request in its own write turn, which is the fingerprint-safe shape; a
    // larger batch coalesces them and is observable on the wire.
    if let Some(n) = h2_dispatch_batch_size {
        if n == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "h2_dispatch_batch_size must be greater than 0 (omit it for the default of 1)",
            ));
        }
        builder = builder.h2_dispatch_batch_size(n);
    }
    if let Some(v) = h2_fallback_h1 {
        builder = builder.h2_fallback_h1(v);
    }
    if let Some(v) = proxy_fallback_direct {
        builder = builder.proxy_fallback_direct(v);
    }
    if let Some(v) = retry_on_connection_close {
        builder = builder.retry_on_connection_close(v);
    }
    if let Some(mws) = middleware {
        for mw in mws {
            builder = builder.middleware(PyMiddlewareWrapper::from_py(&mw));
        }
    }
    if let Some(path) = ca_cert {
        let pem_data = std::fs::read(&path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to read CA cert '{}': {}",
                path, e
            ))
        })?;
        builder = builder.add_ca_certs_pem(&pem_data);
    }
    if let Some(pem) = ca_cert_pem {
        builder = builder.add_ca_certs_pem(&pem);
    }
    if let Some(der) = ca_cert_der {
        builder = builder.add_ca_cert_der(&der);
    }
    if let Some(v) = verify {
        builder = builder.verify(v);
    }
    if use_native_certs {
        builder = builder.use_native_certs();
    }
    if let Some(ech) = ech_config {
        builder = builder.ech_config(ech);
    }
    // The cache implies the system resolver. Combined with `dns=` one of the
    // two would silently win (upstream: last resolver-setting call wins), so
    // reject the ambiguity instead.
    if system_dns_cache_ttl.is_some() && dns.is_some() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "system_dns_cache_ttl cannot be combined with dns: the cache already selects the system resolver",
        ));
    }
    if system_dns_cache_max_entries.is_some() && system_dns_cache_ttl.is_none() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "system_dns_cache_max_entries requires system_dns_cache_ttl",
        ));
    }
    if let Some(ttl) = system_dns_cache_ttl {
        let mut cache = lkrequest::SystemDnsCacheConfig::positive(validated_duration(ttl)?);
        if let Some(n) = system_dns_cache_max_entries {
            cache = cache.with_max_entries(n);
        }
        builder = builder.system_dns_cache(cache);
    } else if let Some(ref dns_name) = dns {
        builder = builder.dns(resolve_dns_config(dns_name)?);
    }
    // Upstream applies the family policy to whichever resolver ends up
    // configured, so it composes with both options above regardless of order.
    let ip_family = ip_family
        .as_deref()
        .map(crate::dns::parse_ip_family)
        .transpose()?
        .unwrap_or_default();
    builder = builder.ip_family(ip_family);
    if let Some(entries) = connect_to {
        for entry in crate::dns::parse_connect_to(entries, ip_family)? {
            builder = builder.connect_to(&entry.host, entry.port, entry.address);
        }
    }
    if let Some(ref path) = keylog {
        let callback = lkrequest::keylog_to_file(path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to open keylog file '{}': {}",
                path, e
            ))
        })?;
        builder = builder.keylog(callback);
    }
    if let Some(policy) = protocol_policy {
        builder = builder.protocol_policy(policy);
    }
    if let Some(cfg) = session_resumption {
        builder = builder.session_resumption(cfg);
    }
    if let Some(p) = quic_fingerprint {
        builder = builder.quic_fingerprint(p);
    }
    if let Some(p) = quic_profile {
        builder = builder.quic_profile(p);
    }
    if disable_http3 {
        builder = builder.disable_http3();
    }
    if let Some(policy) = randomize {
        builder = builder.randomize(policy);
    }
    if let Some(policy) = h2_data_frame_policy {
        builder = builder.h2_data_frame_policy(policy);
    }
    if let Some(require) = require_close_notify {
        builder = builder.require_close_notify(require);
    }
    if let Some(policy) = tls_session_resumption_policy {
        builder = builder.tls_session_resumption_policy(policy);
    }
    if let Some(policy) = tls_session_cache_partition_policy {
        builder = builder.tls_session_cache_partition_policy(policy);
    }
    if let Some(config) = masque {
        builder = crate::masque::apply_to_client(builder, config);
    }

    Ok(builder.build())
}

/// Build a `Client` from a high-level upstream preset bundle plus a TCP
/// fingerprint.
///
/// Delegating to `lkrequest::preset::*` keeps the Python presets in lock-step
/// with the Rust core: TLS/H2 profiles, header order, protocol policy, and
/// (where modelled) the QUIC/H3 profile all come from a single source of
/// truth, so new upstream browser builds flow through automatically. The TCP
/// fingerprint is layered on top because `ClientPreset` does not cover it.
fn build_preset_client(
    preset: lkrequest::preset::ClientPreset,
    tcp: lkrequest::TcpFingerprint,
) -> lkrequest::Client {
    lkrequest::Client::builder()
        .preset(preset)
        .tcp_fingerprint(tcp)
        .build()
}

// ---------------------------------------------------------------------------
// Async Client
// ---------------------------------------------------------------------------

#[pyclass(name = "Client")]
#[derive(Clone)]
pub struct PyClient {
    pub(crate) inner: lkrequest::Client,
}

#[pymethods]
impl PyClient {
    #[new]
    #[pyo3(signature = (
        *,
        tls_profile=None,
        h2_profile=None,
        tcp_fingerprint=None,
        default_headers=None,
        header_order=None,
        h3_header_order=None,
        cookie_order=None,
        dns_timeout=None,
        tcp_connect_timeout=None,
        tls_handshake_timeout=None,
        ttfb_timeout=None,
        total_timeout=None,
        max_response_body_size=None,
        max_connections_per_session=None,
        max_pending_h2_requests=None,
        h2_dispatch_batch_size=None,
        quic_connect_timeout=None,
        max_header_count=None,
        max_header_size=None,
        max_headers_total_size=None,
        min_transfer_rate=None,
        min_transfer_rate_window=None,
        h2_fallback_h1=None,
        proxy_fallback_direct=None,
        retry_on_connection_close=None,
        middleware=None,
        ca_cert=None,
        ca_cert_pem=None,
        ca_cert_der=None,
        verify=None,
        use_native_certs=false,
        ech_config=None,
        dns=None,
        ip_family=None,
        connect_to=None,
        system_dns_cache_ttl=None,
        system_dns_cache_max_entries=None,
        keylog=None,
        protocol_policy=None,
        session_resumption=None,
        disable_http3=false,
        quic_fingerprint=None,
        quic_profile=None,
        randomize=None,
        h2_data_frame_policy=None,
        require_close_notify=None,
        tls_session_resumption_policy=None,
        tls_session_cache_partition_policy=None,
        masque=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new<'py>(
        tls_profile: Option<Bound<'py, PyAny>>,
        h2_profile: Option<Bound<'py, PyAny>>,
        tcp_fingerprint: Option<Bound<'py, PyAny>>,
        default_headers: Option<HashMap<String, String>>,
        header_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        dns_timeout: Option<f64>,
        tcp_connect_timeout: Option<f64>,
        tls_handshake_timeout: Option<f64>,
        ttfb_timeout: Option<f64>,
        total_timeout: Option<f64>,
        max_response_body_size: Option<usize>,
        max_connections_per_session: Option<usize>,
        max_pending_h2_requests: Option<usize>,
        h2_dispatch_batch_size: Option<usize>,
        quic_connect_timeout: Option<f64>,
        max_header_count: Option<usize>,
        max_header_size: Option<usize>,
        max_headers_total_size: Option<usize>,
        min_transfer_rate: Option<usize>,
        min_transfer_rate_window: Option<f64>,
        h2_fallback_h1: Option<bool>,
        proxy_fallback_direct: Option<bool>,
        retry_on_connection_close: Option<bool>,
        middleware: Option<Vec<PyMiddleware>>,
        ca_cert: Option<String>,
        ca_cert_pem: Option<Vec<u8>>,
        ca_cert_der: Option<Vec<u8>>,
        verify: Option<bool>,
        use_native_certs: bool,
        ech_config: Option<Vec<u8>>,
        dns: Option<String>,
        ip_family: Option<String>,
        connect_to: Option<HashMap<String, String>>,
        system_dns_cache_ttl: Option<f64>,
        system_dns_cache_max_entries: Option<usize>,
        keylog: Option<String>,
        protocol_policy: Option<PyProtocolPolicy>,
        session_resumption: Option<PySessionResumptionConfig>,
        disable_http3: bool,
        quic_fingerprint: Option<Bound<'py, PyAny>>,
        quic_profile: Option<Bound<'py, PyAny>>,
        randomize: Option<PyRandomize>,
        h2_data_frame_policy: Option<crate::types::PyH2DataFramePolicy>,
        require_close_notify: Option<bool>,
        tls_session_resumption_policy: Option<
            crate::network_partition::PyTlsSessionResumptionPolicy,
        >,
        tls_session_cache_partition_policy: Option<
            crate::network_partition::PyTlsSessionCachePartitionPolicy,
        >,
        masque: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let masque = crate::masque::resolve(masque.as_ref())?;
        let tls = tls_profile.as_ref().map(resolve_tls_from_any).transpose()?;
        let h2 = h2_profile.as_ref().map(resolve_h2_from_any).transpose()?;
        let tcp = tcp_fingerprint
            .as_ref()
            .map(resolve_tcp_from_any)
            .transpose()?;
        let quic_fp = quic_fingerprint
            .as_ref()
            .map(resolve_tls_from_any)
            .transpose()?;
        let quic = quic_profile
            .as_ref()
            .map(resolve_quic_from_any)
            .transpose()?;
        let client = build_client(ClientConfig {
            tls_profile: tls,
            h2_profile: h2,
            tcp_fingerprint: tcp,
            default_headers,
            header_order,
            h3_header_order,
            cookie_order,
            dns_timeout,
            tcp_connect_timeout,
            tls_handshake_timeout,
            ttfb_timeout,
            total_timeout,
            max_response_body_size,
            max_connections_per_session,
            max_pending_h2_requests,
            h2_dispatch_batch_size,
            quic_connect_timeout,
            max_header_count,
            max_header_size,
            max_headers_total_size,
            min_transfer_rate,
            min_transfer_rate_window,
            h2_fallback_h1,
            proxy_fallback_direct,
            retry_on_connection_close,
            middleware,
            ca_cert,
            ca_cert_pem,
            ca_cert_der,
            verify,
            use_native_certs,
            ech_config,
            dns,
            ip_family,
            connect_to,
            system_dns_cache_ttl,
            system_dns_cache_max_entries,
            keylog,
            protocol_policy: protocol_policy.map(|p| p.inner),
            session_resumption: session_resumption.map(|c| c.inner),
            disable_http3,
            quic_fingerprint: quic_fp,
            quic_profile: quic,
            randomize: randomize.map(|r| r.inner),
            h2_data_frame_policy: h2_data_frame_policy.map(|p| p.inner),
            require_close_notify,
            tls_session_resumption_policy: tls_session_resumption_policy.map(|p| p.inner),
            tls_session_cache_partition_policy: tls_session_cache_partition_policy.map(|p| p.inner),
            masque,
        })?;
        tracing::info!(tls = %client.tls_profile().name, "Client created");
        Ok(PyClient { inner: client })
    }

    #[staticmethod]
    fn chrome_131() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_131(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_144() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_144(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_145() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_145(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_146() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_146(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_147() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_147(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_148() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_148(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_149() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_149(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_150() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_150(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_151() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_151(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_152() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_152(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_153() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_153(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_154() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_154(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn firefox_133() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::firefox_133(),
                lkrequest::TcpFingerprint::firefox(),
            ),
        }
    }

    #[staticmethod]
    fn firefox_147() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::firefox_147(),
                lkrequest::TcpFingerprint::firefox(),
            ),
        }
    }

    #[staticmethod]
    fn firefox_156() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::firefox_156(),
                lkrequest::TcpFingerprint::firefox(),
            ),
        }
    }

    #[staticmethod]
    fn safari_18() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::safari_18(),
                lkrequest::TcpFingerprint::safari(),
            ),
        }
    }

    #[staticmethod]
    fn safari_26() -> Self {
        PyClient {
            inner: build_preset_client(
                lkrequest::preset::safari_26(),
                lkrequest::TcpFingerprint::safari(),
            ),
        }
    }

    #[pyo3(signature = (*, proxy=None, max_redirects=None, allow_redirects=true, http1_only=false, http2_only=false, http3_only=false, http3_with_fallback=false, retry=None, middleware=None, accept_encoding=None, ech_config=None, max_connections=None, idle_timeout=None, on_request=None, on_response=None, protocol_policy=None, http_intent=None, broken_quic_policy=None, header_order=None, h3_header_order=None, cookie_order=None, https_only=false, hsts=None, base_url=None, network_partition_context=None))]
    fn session<'py>(
        &self,
        _py: Python<'py>,
        proxy: Option<Bound<'py, PyAny>>,
        max_redirects: Option<u32>,
        allow_redirects: bool,
        http1_only: bool,
        http2_only: bool,
        http3_only: bool,
        http3_with_fallback: bool,
        retry: Option<Bound<'py, PyAny>>,
        middleware: Option<Vec<PyMiddleware>>,
        accept_encoding: Option<PyAcceptEncoding>,
        ech_config: Option<Vec<u8>>,
        max_connections: Option<usize>,
        idle_timeout: Option<f64>,
        on_request: Option<Py<PyAny>>,
        on_response: Option<Py<PyAny>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
        broken_quic_policy: Option<PyBrokenQuicPolicy>,
        header_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        https_only: bool,
        hsts: Option<PyHsts>,
        base_url: Option<String>,
        network_partition_context: Option<crate::network_partition::PyNetworkPartitionContext>,
    ) -> PyResult<PySession> {
        let mut builder = self.inner.session();
        if let Some(p) = proxy {
            builder = apply_session_proxy(builder, &p)?;
        }
        if !allow_redirects {
            // allow_redirects=False maps to RedirectPolicy::None — return the
            // 3xx response as-is. This takes precedence over max_redirects;
            // note that max_redirects=0 would instead raise TooManyRedirects.
            builder = builder.redirect_policy(lkrequest::RedirectPolicy::None);
        } else if let Some(n) = max_redirects {
            builder = builder.max_redirects(n);
        }
        if http1_only {
            builder = builder.http1_only();
        }
        if http2_only {
            builder = builder.http2_only();
        }
        if http3_only {
            builder = builder.http3_only();
        }
        if http3_with_fallback {
            builder = builder.http3_with_fallback();
        }
        if let Some(ref retry_obj) = retry {
            builder = apply_retry_policy(builder, retry_obj)?;
        }
        if let Some(ref mws) = middleware {
            builder = apply_middlewares_to_session(builder, mws);
        }
        if let Some(ae) = accept_encoding {
            builder = builder.default_accept_encoding(ae.inner);
        }
        if let Some(ech) = ech_config {
            builder = builder.ech_config(ech);
        }
        if let Some(n) = max_connections {
            builder = builder.max_connections(n);
        }
        if let Some(t) = idle_timeout {
            builder = builder.idle_timeout(validated_duration(t)?);
        }
        if let Some(policy) = protocol_policy {
            builder = builder.protocol_policy(policy.inner);
        }
        if let Some(intent) = http_intent {
            builder = builder.http_intent(intent.into());
        }
        if let Some(policy) = broken_quic_policy {
            builder = builder.broken_quic_policy(policy.into());
        }
        if let Some(order) = header_order {
            let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
            builder = builder.header_order(refs);
        }
        if let Some(order) = cookie_order {
            let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
            builder = builder.cookie_order(refs);
        }
        if let Some(order) = h3_header_order {
            let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
            builder = builder.h3_header_order(refs);
        }
        if https_only {
            builder = builder.https_only(true);
        }
        if let Some(policy) = hsts {
            builder = policy.apply(builder);
        }
        if let Some(ctx) = network_partition_context {
            builder = builder.network_partition_context(ctx.inner);
        }
        let hooks = EventHooks::default();
        if let Some(cb) = on_request {
            hooks
                .request_hooks
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
                .push(cb);
        }
        if let Some(cb) = on_response {
            hooks
                .response_hooks
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
                .push(cb);
        }
        Ok(PySession {
            inner: builder.build(),
            hooks,
            base_url,
        })
    }

    fn fingerprint_info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("tls_profile", self.inner.tls_profile().name.as_str())?;
        dict.set_item("h2_settings_count", self.inner.h2_profile().settings.len())?;
        dict.set_item("h2_window_update", self.inner.h2_profile().window_update)?;
        let tcp_ja4t = self.inner.tcp_fingerprint().and_then(|f| f.to_ja4t());
        dict.set_item("tcp_ja4t", tcp_ja4t)?;
        Ok(dict)
    }

    /// Whether the peer must send a TLS `close_notify` before closing. When
    /// True, a bare socket EOF is treated as an error rather than a clean end
    /// of body. Defaults to False.
    #[getter]
    fn require_close_notify(&self) -> bool {
        self.inner.require_close_notify()
    }

    /// How many ready HTTP/2 requests are coalesced into one driver write turn.
    ///
    /// Readable because it changes the bytes on the wire: the default of 1
    /// gives each request its own write, while a larger batch packs several
    /// into one, which is observable.
    #[getter]
    fn h2_dispatch_batch_size(&self) -> usize {
        self.inner.h2_dispatch_batch_size()
    }

    /// The TLS session ticket resumption policy in effect for this client.
    #[getter]
    fn tls_session_resumption_policy(
        &self,
    ) -> crate::network_partition::PyTlsSessionResumptionPolicy {
        crate::network_partition::PyTlsSessionResumptionPolicy {
            inner: self.inner.tls_session_resumption_policy(),
        }
    }

    /// Return a copy of this client with TLS-extension randomization enabled.
    ///
    /// Only the fingerprint layers are carried over (TLS profile + its QUIC
    /// fingerprint, H2 profile, TCP fingerprint). Other client-level
    /// configuration — timeouts, default headers, header/cookie order,
    /// certificate/`verify` settings, protocol policy, DNS, proxy and resource
    /// limits — is NOT preserved and reverts to builder defaults. To keep that
    /// config, pass a randomized `TlsProfile` (with its `randomization` set)
    /// to the `Client(...)` constructor instead of calling this afterwards.
    #[pyo3(signature = (*, shuffle_extensions=true))]
    fn randomize_fingerprint(&self, shuffle_extensions: bool) -> Self {
        let mut profile = self.inner.tls_profile().clone();
        profile.randomization =
            Some(lktls::profile::types::RandomizationConfig { shuffle_extensions });
        let mut builder = lkrequest::Client::builder()
            .fingerprint(profile)
            .h2_profile(self.inner.h2_profile().clone());
        if let Some(tcp) = self.inner.tcp_fingerprint() {
            builder = builder.tcp_fingerprint(tcp.clone());
        }
        if let Some(quic_tls) = self.inner.quic_tls_profile() {
            builder = builder.quic_fingerprint(quic_tls.clone());
        }
        PyClient {
            inner: builder.build(),
        }
    }

    fn __repr__(&self) -> String {
        format!("<Client tls='{}'>", self.inner.tls_profile().name)
    }
}

// ---------------------------------------------------------------------------
// Blocking Client
// ---------------------------------------------------------------------------

// expect: a failed runtime build at process init is unrecoverable, and a
// LazyLock initializer cannot return a Result to propagate the error.
#[allow(clippy::expect_used)]
static BLOCKING_RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> =
    std::sync::LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime for blocking API")
    });

pub(crate) fn blocking_runtime() -> &'static tokio::runtime::Runtime {
    &BLOCKING_RUNTIME
}

#[pyclass(name = "BlockingClient")]
#[derive(Clone)]
pub struct PyBlockingClient {
    pub(crate) inner: lkrequest::Client,
}

#[pymethods]
impl PyBlockingClient {
    #[new]
    #[pyo3(signature = (
        *,
        tls_profile=None,
        h2_profile=None,
        tcp_fingerprint=None,
        default_headers=None,
        header_order=None,
        h3_header_order=None,
        cookie_order=None,
        dns_timeout=None,
        tcp_connect_timeout=None,
        tls_handshake_timeout=None,
        ttfb_timeout=None,
        total_timeout=None,
        max_response_body_size=None,
        max_connections_per_session=None,
        max_pending_h2_requests=None,
        h2_dispatch_batch_size=None,
        quic_connect_timeout=None,
        max_header_count=None,
        max_header_size=None,
        max_headers_total_size=None,
        min_transfer_rate=None,
        min_transfer_rate_window=None,
        h2_fallback_h1=None,
        proxy_fallback_direct=None,
        retry_on_connection_close=None,
        middleware=None,
        ca_cert=None,
        ca_cert_pem=None,
        ca_cert_der=None,
        verify=None,
        use_native_certs=false,
        ech_config=None,
        dns=None,
        ip_family=None,
        connect_to=None,
        system_dns_cache_ttl=None,
        system_dns_cache_max_entries=None,
        keylog=None,
        protocol_policy=None,
        session_resumption=None,
        disable_http3=false,
        quic_fingerprint=None,
        quic_profile=None,
        randomize=None,
        h2_data_frame_policy=None,
        require_close_notify=None,
        tls_session_resumption_policy=None,
        tls_session_cache_partition_policy=None,
        masque=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new<'py>(
        tls_profile: Option<Bound<'py, PyAny>>,
        h2_profile: Option<Bound<'py, PyAny>>,
        tcp_fingerprint: Option<Bound<'py, PyAny>>,
        default_headers: Option<HashMap<String, String>>,
        header_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        dns_timeout: Option<f64>,
        tcp_connect_timeout: Option<f64>,
        tls_handshake_timeout: Option<f64>,
        ttfb_timeout: Option<f64>,
        total_timeout: Option<f64>,
        max_response_body_size: Option<usize>,
        max_connections_per_session: Option<usize>,
        max_pending_h2_requests: Option<usize>,
        h2_dispatch_batch_size: Option<usize>,
        quic_connect_timeout: Option<f64>,
        max_header_count: Option<usize>,
        max_header_size: Option<usize>,
        max_headers_total_size: Option<usize>,
        min_transfer_rate: Option<usize>,
        min_transfer_rate_window: Option<f64>,
        h2_fallback_h1: Option<bool>,
        proxy_fallback_direct: Option<bool>,
        retry_on_connection_close: Option<bool>,
        middleware: Option<Vec<PyMiddleware>>,
        ca_cert: Option<String>,
        ca_cert_pem: Option<Vec<u8>>,
        ca_cert_der: Option<Vec<u8>>,
        verify: Option<bool>,
        use_native_certs: bool,
        ech_config: Option<Vec<u8>>,
        dns: Option<String>,
        ip_family: Option<String>,
        connect_to: Option<HashMap<String, String>>,
        system_dns_cache_ttl: Option<f64>,
        system_dns_cache_max_entries: Option<usize>,
        keylog: Option<String>,
        protocol_policy: Option<PyProtocolPolicy>,
        session_resumption: Option<PySessionResumptionConfig>,
        disable_http3: bool,
        quic_fingerprint: Option<Bound<'py, PyAny>>,
        quic_profile: Option<Bound<'py, PyAny>>,
        randomize: Option<PyRandomize>,
        h2_data_frame_policy: Option<crate::types::PyH2DataFramePolicy>,
        require_close_notify: Option<bool>,
        tls_session_resumption_policy: Option<
            crate::network_partition::PyTlsSessionResumptionPolicy,
        >,
        tls_session_cache_partition_policy: Option<
            crate::network_partition::PyTlsSessionCachePartitionPolicy,
        >,
        masque: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Self> {
        let masque = crate::masque::resolve(masque.as_ref())?;
        let tls = tls_profile.as_ref().map(resolve_tls_from_any).transpose()?;
        let h2 = h2_profile.as_ref().map(resolve_h2_from_any).transpose()?;
        let tcp = tcp_fingerprint
            .as_ref()
            .map(resolve_tcp_from_any)
            .transpose()?;
        let quic_fp = quic_fingerprint
            .as_ref()
            .map(resolve_tls_from_any)
            .transpose()?;
        let quic = quic_profile
            .as_ref()
            .map(resolve_quic_from_any)
            .transpose()?;
        let client = build_client(ClientConfig {
            tls_profile: tls,
            h2_profile: h2,
            tcp_fingerprint: tcp,
            default_headers,
            header_order,
            h3_header_order,
            cookie_order,
            dns_timeout,
            tcp_connect_timeout,
            tls_handshake_timeout,
            ttfb_timeout,
            total_timeout,
            max_response_body_size,
            max_connections_per_session,
            max_pending_h2_requests,
            h2_dispatch_batch_size,
            quic_connect_timeout,
            max_header_count,
            max_header_size,
            max_headers_total_size,
            min_transfer_rate,
            min_transfer_rate_window,
            h2_fallback_h1,
            proxy_fallback_direct,
            retry_on_connection_close,
            middleware,
            ca_cert,
            ca_cert_pem,
            ca_cert_der,
            verify,
            use_native_certs,
            ech_config,
            dns,
            ip_family,
            connect_to,
            system_dns_cache_ttl,
            system_dns_cache_max_entries,
            keylog,
            protocol_policy: protocol_policy.map(|p| p.inner),
            session_resumption: session_resumption.map(|c| c.inner),
            disable_http3,
            quic_fingerprint: quic_fp,
            quic_profile: quic,
            randomize: randomize.map(|r| r.inner),
            h2_data_frame_policy: h2_data_frame_policy.map(|p| p.inner),
            require_close_notify,
            tls_session_resumption_policy: tls_session_resumption_policy.map(|p| p.inner),
            tls_session_cache_partition_policy: tls_session_cache_partition_policy.map(|p| p.inner),
            masque,
        })?;
        Ok(PyBlockingClient { inner: client })
    }

    #[staticmethod]
    fn chrome_131() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_131(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_144() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_144(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_145() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_145(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_146() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_146(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_147() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_147(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_148() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_148(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_149() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_149(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_150() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_150(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_151() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_151(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_152() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_152(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_153() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_153(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn chrome_154() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::chrome_154(),
                lkrequest::TcpFingerprint::chrome(),
            ),
        }
    }

    #[staticmethod]
    fn firefox_133() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::firefox_133(),
                lkrequest::TcpFingerprint::firefox(),
            ),
        }
    }

    #[staticmethod]
    fn firefox_147() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::firefox_147(),
                lkrequest::TcpFingerprint::firefox(),
            ),
        }
    }

    #[staticmethod]
    fn firefox_156() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::firefox_156(),
                lkrequest::TcpFingerprint::firefox(),
            ),
        }
    }

    #[staticmethod]
    fn safari_18() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::safari_18(),
                lkrequest::TcpFingerprint::safari(),
            ),
        }
    }

    #[staticmethod]
    fn safari_26() -> Self {
        PyBlockingClient {
            inner: build_preset_client(
                lkrequest::preset::safari_26(),
                lkrequest::TcpFingerprint::safari(),
            ),
        }
    }

    #[pyo3(signature = (*, proxy=None, max_redirects=None, allow_redirects=true, http1_only=false, http2_only=false, http3_only=false, http3_with_fallback=false, retry=None, middleware=None, accept_encoding=None, ech_config=None, max_connections=None, idle_timeout=None, on_request=None, on_response=None, protocol_policy=None, http_intent=None, broken_quic_policy=None, header_order=None, h3_header_order=None, cookie_order=None, https_only=false, hsts=None, base_url=None, network_partition_context=None))]
    fn session<'py>(
        &self,
        _py: Python<'py>,
        proxy: Option<Bound<'py, PyAny>>,
        max_redirects: Option<u32>,
        allow_redirects: bool,
        http1_only: bool,
        http2_only: bool,
        http3_only: bool,
        http3_with_fallback: bool,
        retry: Option<Bound<'py, PyAny>>,
        middleware: Option<Vec<PyMiddleware>>,
        accept_encoding: Option<PyAcceptEncoding>,
        ech_config: Option<Vec<u8>>,
        max_connections: Option<usize>,
        idle_timeout: Option<f64>,
        on_request: Option<Py<PyAny>>,
        on_response: Option<Py<PyAny>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
        broken_quic_policy: Option<PyBrokenQuicPolicy>,
        header_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        https_only: bool,
        hsts: Option<PyHsts>,
        base_url: Option<String>,
        network_partition_context: Option<crate::network_partition::PyNetworkPartitionContext>,
    ) -> PyResult<PyBlockingSession> {
        let mut builder = self.inner.session();
        if let Some(p) = proxy {
            builder = apply_session_proxy(builder, &p)?;
        }
        if !allow_redirects {
            // allow_redirects=False maps to RedirectPolicy::None — return the
            // 3xx response as-is. This takes precedence over max_redirects;
            // note that max_redirects=0 would instead raise TooManyRedirects.
            builder = builder.redirect_policy(lkrequest::RedirectPolicy::None);
        } else if let Some(n) = max_redirects {
            builder = builder.max_redirects(n);
        }
        if http1_only {
            builder = builder.http1_only();
        }
        if http2_only {
            builder = builder.http2_only();
        }
        if http3_only {
            builder = builder.http3_only();
        }
        if http3_with_fallback {
            builder = builder.http3_with_fallback();
        }
        if let Some(ref retry_obj) = retry {
            builder = apply_retry_policy(builder, retry_obj)?;
        }
        if let Some(ref mws) = middleware {
            builder = apply_middlewares_to_session(builder, mws);
        }
        if let Some(ae) = accept_encoding {
            builder = builder.default_accept_encoding(ae.inner);
        }
        if let Some(ech) = ech_config {
            builder = builder.ech_config(ech);
        }
        if let Some(n) = max_connections {
            builder = builder.max_connections(n);
        }
        if let Some(t) = idle_timeout {
            builder = builder.idle_timeout(validated_duration(t)?);
        }
        if let Some(policy) = protocol_policy {
            builder = builder.protocol_policy(policy.inner);
        }
        if let Some(intent) = http_intent {
            builder = builder.http_intent(intent.into());
        }
        if let Some(policy) = broken_quic_policy {
            builder = builder.broken_quic_policy(policy.into());
        }
        if let Some(order) = header_order {
            let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
            builder = builder.header_order(refs);
        }
        if let Some(order) = cookie_order {
            let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
            builder = builder.cookie_order(refs);
        }
        if let Some(order) = h3_header_order {
            let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
            builder = builder.h3_header_order(refs);
        }
        if https_only {
            builder = builder.https_only(true);
        }
        if let Some(policy) = hsts {
            builder = policy.apply(builder);
        }
        if let Some(ctx) = network_partition_context {
            builder = builder.network_partition_context(ctx.inner);
        }
        let hooks = EventHooks::default();
        if let Some(cb) = on_request {
            hooks
                .request_hooks
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
                .push(cb);
        }
        if let Some(cb) = on_response {
            hooks
                .response_hooks
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
                .push(cb);
        }
        Ok(PyBlockingSession {
            inner: builder.build(),
            hooks,
            base_url,
        })
    }

    fn fingerprint_info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("tls_profile", self.inner.tls_profile().name.as_str())?;
        dict.set_item("h2_settings_count", self.inner.h2_profile().settings.len())?;
        dict.set_item("h2_window_update", self.inner.h2_profile().window_update)?;
        let tcp_ja4t = self.inner.tcp_fingerprint().and_then(|f| f.to_ja4t());
        dict.set_item("tcp_ja4t", tcp_ja4t)?;
        Ok(dict)
    }

    /// Whether the peer must send a TLS `close_notify` before closing. When
    /// True, a bare socket EOF is treated as an error rather than a clean end
    /// of body. Defaults to False.
    #[getter]
    fn require_close_notify(&self) -> bool {
        self.inner.require_close_notify()
    }

    /// How many ready HTTP/2 requests are coalesced into one driver write turn.
    ///
    /// Readable because it changes the bytes on the wire: the default of 1
    /// gives each request its own write, while a larger batch packs several
    /// into one, which is observable.
    #[getter]
    fn h2_dispatch_batch_size(&self) -> usize {
        self.inner.h2_dispatch_batch_size()
    }

    /// The TLS session ticket resumption policy in effect for this client.
    #[getter]
    fn tls_session_resumption_policy(
        &self,
    ) -> crate::network_partition::PyTlsSessionResumptionPolicy {
        crate::network_partition::PyTlsSessionResumptionPolicy {
            inner: self.inner.tls_session_resumption_policy(),
        }
    }

    /// Return a copy of this client with TLS-extension randomization enabled.
    ///
    /// Only the fingerprint layers are carried over (TLS profile + its QUIC
    /// fingerprint, H2 profile, TCP fingerprint). Other client-level
    /// configuration — timeouts, default headers, header/cookie order,
    /// certificate/`verify` settings, protocol policy, DNS, proxy and resource
    /// limits — is NOT preserved and reverts to builder defaults. To keep that
    /// config, pass a randomized `TlsProfile` (with its `randomization` set)
    /// to the `Client(...)` constructor instead of calling this afterwards.
    #[pyo3(signature = (*, shuffle_extensions=true))]
    fn randomize_fingerprint(&self, shuffle_extensions: bool) -> Self {
        let mut profile = self.inner.tls_profile().clone();
        profile.randomization =
            Some(lktls::profile::types::RandomizationConfig { shuffle_extensions });
        let mut builder = lkrequest::Client::builder()
            .fingerprint(profile)
            .h2_profile(self.inner.h2_profile().clone());
        if let Some(tcp) = self.inner.tcp_fingerprint() {
            builder = builder.tcp_fingerprint(tcp.clone());
        }
        if let Some(quic_tls) = self.inner.quic_tls_profile() {
            builder = builder.quic_fingerprint(quic_tls.clone());
        }
        PyBlockingClient {
            inner: builder.build(),
        }
    }

    fn __repr__(&self) -> String {
        format!("<BlockingClient tls='{}'>", self.inner.tls_profile().name)
    }
}
