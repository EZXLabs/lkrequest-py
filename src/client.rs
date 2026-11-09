//! Async `Client` and blocking `BlockingClient` pyclasses: the configurable
//! HTTP client entry points that build a `lkrequest::Client` from fingerprint,
//! protocol, retry, proxy, and timeout settings and issue requests.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::fingerprint::{PyH2Profile, PyTcpFingerprint, PyTlsProfile};
use crate::hsts::PyHsts;
use crate::middleware::{MiddlewareSlots, PyMiddleware, PyMiddlewareWrapper};
use crate::protocol::{BrokenQuic, PyH3RetryMode, PyHttpIntent, PyProtocolPolicy};
use crate::proxy::{apply_session_proxy, proxy_check};
use crate::randomize::PyRandomize;
use crate::retry::{PyCallableRetryPolicy, PyExponentialBackoff, PyFixedInterval};
use crate::session::{PyBlockingSession, PySession};
use crate::session_state::SessionState;
use crate::types::{
    resolve_h2_profile, resolve_tcp_fingerprint, resolve_tls_profile, validated_duration,
    PyAcceptEncoding, PySessionResumptionConfig, StrPairs,
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
/// `"chrome_154"` / `"chrome_155"` / `"chrome_156"` / `"chrome_157"`) or a
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
            "chrome_155" => Ok(lkrequest::lkh3::chrome_155_quic()),
            "chrome_156" => Ok(lkrequest::lkh3::chrome_156_quic()),
            "chrome_157" => Ok(lkrequest::lkh3::chrome_157_quic()),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown QUIC profile: '{}'. Available: chrome, chrome_146, chrome_150, chrome_151, chrome_152, chrome_153, chrome_154, chrome_155, chrome_156, chrome_157",
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

/// Set the session's HTTP/3 retry mode. Anything but the default needs the
/// `quic-h3` feature; `Safe` is what a build without it does anyway.
#[cfg(feature = "quic-h3")]
fn apply_h3_retry_mode(
    builder: lkrequest::session::SessionBuilder,
    mode: PyH3RetryMode,
) -> PyResult<lkrequest::session::SessionBuilder> {
    Ok(builder.h3_retry_mode(mode.into()))
}

#[cfg(not(feature = "quic-h3"))]
fn apply_h3_retry_mode(
    builder: lkrequest::session::SessionBuilder,
    mode: PyH3RetryMode,
) -> PyResult<lkrequest::session::SessionBuilder> {
    match mode {
        PyH3RetryMode::Safe => Ok(builder),
        PyH3RetryMode::Chrome155ProtocolErrors => {
            Err(pyo3::exceptions::PyRuntimeError::new_err(
                "h3_retry_mode=H3RetryMode.Chrome155ProtocolErrors requires building lkrequest-py with the 'quic-h3' feature: maturin develop --features quic-h3",
            ))
        }
    }
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
        Ok(builder.retry_policy(PyCallableRetryPolicy::new(retry_obj)))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "retry must be ExponentialBackoff, FixedInterval, or a callable(attempt, error, status) -> float | None",
        ))
    }
}

/// Add Python middleware to a session builder. The returned handles let the
/// session release the callbacks when it is closed.
fn apply_middlewares_to_session(
    mut builder: lkrequest::session::SessionBuilder,
    middlewares: &[PyMiddleware],
) -> (
    lkrequest::session::SessionBuilder,
    Vec<std::sync::Arc<MiddlewareSlots>>,
) {
    let mut slots = Vec::with_capacity(middlewares.len());
    for mw in middlewares {
        let wrapper = PyMiddlewareWrapper::from_py(mw);
        slots.push(wrapper.slots());
        builder = builder.middleware(wrapper);
    }
    (builder, slots)
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
        _ => crate::dns::parse_dns_server(name)
            .map(lkrequest::dns::DnsConfig::Custom)
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown DNS config: '{}'. Available: system, google, google_https, cloudflare, cloudflare_https, quad9, quad9_https, or a DNS server as \"ip\" or \"ip:port\" (IPv6 as \"[2606:4700::1111]:53\")",
                    name
                ))
            }),
    }
}

/// What `dns=` was given.
#[derive(Clone)]
enum Dns {
    Config(lkrequest::dns::DnsConfig),
    Resolver(Arc<crate::resolver::PyDnsResolver>),
}

/// Read `dns=`: a resolver's name or a DNS server's address, or Python code
/// that looks names up.
fn resolve_dns(dns: &Bound<'_, PyAny>) -> PyResult<Dns> {
    if let Ok(name) = dns.extract::<String>() {
        return resolve_dns_config(&name).map(Dns::Config);
    }
    let resolver = crate::resolver::PyDnsResolver::from_python(dns)?;
    Ok(Dns::Resolver(Arc::new(resolver)))
}

/// What `keylog=` was given.
#[derive(Clone)]
enum Keylog {
    /// A file the lines are appended to, opened when the client is built.
    File(std::path::PathBuf),
    /// A Python function called with each line.
    Function(lkrequest::KeyLogCallback),
}

/// Read `keylog=`: a file path, or a function called with each line on the
/// thread doing the handshake.
fn resolve_keylog(keylog: &Bound<'_, PyAny>) -> PyResult<Keylog> {
    if !keylog.is_callable() {
        return keylog.extract().map(Keylog::File).map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(
                "keylog must be a file path or a function taking each line",
            )
        });
    }
    if crate::types::is_async_function(keylog)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "keylog must be a plain function, not an async one",
        ));
    }
    let function = keylog.clone().unbind();
    Ok(Keylog::Function(Arc::new(move |line: &str| {
        let outcome = Python::try_attach(|py| function.bind(py).call1((line,)).map(drop));
        if let Some(Err(err)) = outcome {
            tracing::warn!(error = %err, "tls.keylog_failed");
        }
    })))
}

/// All resolved options for constructing a [`lkrequest::Client`], grouped so
/// the (long) set of settings is threaded by name rather than by ~30 positional
/// arguments. Adding a new option is a single named field set at each call
/// site, which the compiler checks for completeness — there is no risk of
/// mis-aligning two same-typed positional arguments.
#[derive(Clone, Default)]
struct ClientConfig {
    tls_profile: Option<lktls::profile::TlsProfile>,
    h2_profile: Option<lkh2::profile::H2Profile>,
    tcp_fingerprint: Option<lkrequest::TcpFingerprint>,
    default_headers: Option<StrPairs>,
    header_order: Option<Vec<String>>,
    h3_header_order: Option<Vec<String>>,
    cookie_order: Option<Vec<String>>,
    http1_title_case_headers: Option<bool>,
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
    trust_anchor_policy: Option<lkrequest::TrustAnchorPolicy>,
    trust_anchor_bindings: Option<Vec<lkrequest::TrustAnchorBinding>>,
    ech_config: Option<Vec<u8>>,
    dns: Option<Dns>,
    ip_family: Option<String>,
    connect_to: Option<HashMap<String, String>>,
    system_dns_cache_ttl: Option<f64>,
    system_dns_cache_max_entries: Option<usize>,
    keylog: Option<Keylog>,
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
        http1_title_case_headers,
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
        trust_anchor_policy,
        trust_anchor_bindings,
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
        // In the caller's order: it is the order the defaults go on the wire
        // in, wherever the header order does not place them itself.
        for (k, v) in headers.0 {
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
    if let Some(enabled) = http1_title_case_headers {
        builder = builder.http1_title_case_headers(enabled);
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
    if let Some(policy) = trust_anchor_policy {
        builder = builder.trust_anchor_policy(policy);
    }
    for binding in trust_anchor_bindings.into_iter().flatten() {
        builder = builder.trust_anchor_binding(binding);
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
    } else if let Some(dns) = dns {
        builder = match dns {
            Dns::Config(config) => builder.dns(config),
            Dns::Resolver(resolver) => builder.dns_resolver(resolver),
        };
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
    match keylog {
        Some(Keylog::File(path)) => {
            let callback = lkrequest::keylog_to_file(&path).map_err(|e| {
                pyo3::exceptions::PyIOError::new_err(format!(
                    "Failed to open keylog file '{}': {}",
                    path.display(),
                    e
                ))
            })?;
            builder = builder.keylog(callback);
        }
        Some(Keylog::Function(callback)) => builder = builder.keylog(callback),
        None => {}
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

    // `build()` panics on settings upstream rejects, such as trust-anchor
    // recovery without verification; `try_build()` reports them instead.
    builder.try_build().map_err(crate::error::to_py_err)
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
    tls_profile: Option<lktls::profile::TlsProfile>,
) -> lkrequest::Client {
    let mut builder = lkrequest::Client::builder()
        .preset(preset)
        .tcp_fingerprint(tcp);
    // A later `fingerprint()` replaces the preset's TLS profile and leaves the
    // rest of the preset alone; `randomize_fingerprint()` relies on that.
    if let Some(profile) = tls_profile {
        builder = builder.fingerprint(profile);
    }
    builder.build()
}

/// How a client was built, kept so `randomize_fingerprint()` can build the
/// same client again with only its TLS profile replaced: upstream's `Client`
/// has no way back to a builder.
// Built once per client and kept behind an `Arc`, so the size of the larger
// variant costs nothing that boxing it would save.
#[allow(clippy::large_enum_variant)]
enum ClientRecipe {
    /// From the constructor's options.
    Options(ClientConfig),
    /// From a browser preset method.
    Preset {
        preset: lkrequest::preset::ClientPreset,
        tcp: lkrequest::TcpFingerprint,
        /// The preset's own TLS profile until `randomize_fingerprint()`
        /// replaces it.
        tls_profile: Option<lktls::profile::TlsProfile>,
    },
}

impl ClientRecipe {
    fn preset(preset: lkrequest::preset::ClientPreset, tcp: lkrequest::TcpFingerprint) -> Self {
        Self::Preset {
            preset,
            tcp,
            tls_profile: None,
        }
    }

    fn build(&self) -> PyResult<lkrequest::Client> {
        match self {
            Self::Options(config) => build_client(config.clone()),
            Self::Preset {
                preset,
                tcp,
                tls_profile,
            } => Ok(build_preset_client(
                preset.clone(),
                tcp.clone(),
                tls_profile.clone(),
            )),
        }
    }

    /// The same recipe with `profile` as the TLS profile.
    fn with_tls_profile(&self, profile: lktls::profile::TlsProfile) -> Self {
        match self {
            Self::Options(config) => {
                let mut config = config.clone();
                config.tls_profile = Some(profile);
                Self::Options(config)
            }
            Self::Preset { preset, tcp, .. } => Self::Preset {
                preset: preset.clone(),
                tcp: tcp.clone(),
                tls_profile: Some(profile),
            },
        }
    }
}

/// The TLS profile `client` uses, set to shuffle its extensions per connection
/// (`shuffle_extensions=True`) or explicitly not to.
fn randomized_tls_profile(
    client: &lkrequest::Client,
    shuffle_extensions: bool,
) -> lktls::profile::TlsProfile {
    let mut profile = client.tls_profile().clone();
    profile.randomization = Some(lktls::profile::types::RandomizationConfig { shuffle_extensions });
    profile
}

// ---------------------------------------------------------------------------
// Async Client
// ---------------------------------------------------------------------------

#[pyclass(name = "Client", from_py_object)]
#[derive(Clone)]
pub struct PyClient {
    pub(crate) inner: lkrequest::Client,
    /// How `inner` was built, for `randomize_fingerprint()`.
    recipe: Arc<ClientRecipe>,
}

impl PyClient {
    fn from_recipe(recipe: ClientRecipe) -> PyResult<Self> {
        Ok(Self {
            inner: recipe.build()?,
            recipe: Arc::new(recipe),
        })
    }

    fn from_preset(
        preset: lkrequest::preset::ClientPreset,
        tcp: lkrequest::TcpFingerprint,
    ) -> Self {
        Self {
            inner: build_preset_client(preset.clone(), tcp.clone(), None),
            recipe: Arc::new(ClientRecipe::preset(preset, tcp)),
        }
    }
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
        http1_title_case_headers=None,
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
        trust_anchor_advertisement=None,
        trust_anchor_recovery=None,
        trust_anchor_bindings=None,
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
        default_headers: Option<StrPairs>,
        header_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        http1_title_case_headers: Option<bool>,
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
        trust_anchor_advertisement: Option<String>,
        trust_anchor_recovery: Option<String>,
        trust_anchor_bindings: Option<BTreeMap<String, String>>,
        ech_config: Option<Vec<u8>>,
        dns: Option<Bound<'_, PyAny>>,
        ip_family: Option<String>,
        connect_to: Option<HashMap<String, String>>,
        system_dns_cache_ttl: Option<f64>,
        system_dns_cache_max_entries: Option<usize>,
        keylog: Option<Bound<'_, PyAny>>,
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
        let config = ClientConfig {
            tls_profile: tls,
            h2_profile: h2,
            tcp_fingerprint: tcp,
            default_headers,
            header_order,
            h3_header_order,
            cookie_order,
            http1_title_case_headers,
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
            trust_anchor_policy: crate::trust_anchor::parse_policy(
                trust_anchor_advertisement.as_deref(),
                trust_anchor_recovery.as_deref(),
            )?,
            trust_anchor_bindings: trust_anchor_bindings
                .map(crate::trust_anchor::parse_bindings)
                .transpose()?,
            ech_config,
            dns: dns.as_ref().map(resolve_dns).transpose()?,
            ip_family,
            connect_to,
            system_dns_cache_ttl,
            system_dns_cache_max_entries,
            keylog: keylog.as_ref().map(resolve_keylog).transpose()?,
            protocol_policy: protocol_policy
                .map(PyProtocolPolicy::validated)
                .transpose()?,
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
        };
        let client = Self::from_recipe(ClientRecipe::Options(config))?;
        tracing::info!(tls = %client.inner.tls_profile().name, "Client created");
        Ok(client)
    }

    #[staticmethod]
    fn chrome_131() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_131(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_144() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_144(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_145() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_145(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_146() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_146(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_147() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_147(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_148() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_148(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_149() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_149(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_150() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_150(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_151() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_151(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_152() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_152(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_153() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_153(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_154() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_154(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_155() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_155(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_156() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_156(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_157() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_157(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn firefox_133() -> Self {
        Self::from_preset(
            lkrequest::preset::firefox_133(),
            lkrequest::TcpFingerprint::firefox(),
        )
    }

    #[staticmethod]
    fn firefox_147() -> Self {
        Self::from_preset(
            lkrequest::preset::firefox_147(),
            lkrequest::TcpFingerprint::firefox(),
        )
    }

    #[staticmethod]
    fn firefox_156() -> Self {
        Self::from_preset(
            lkrequest::preset::firefox_156(),
            lkrequest::TcpFingerprint::firefox(),
        )
    }

    #[staticmethod]
    fn safari_18() -> Self {
        Self::from_preset(
            lkrequest::preset::safari_18(),
            lkrequest::TcpFingerprint::safari(),
        )
    }

    #[staticmethod]
    fn safari_26() -> Self {
        Self::from_preset(
            lkrequest::preset::safari_26(),
            lkrequest::TcpFingerprint::safari(),
        )
    }

    #[pyo3(signature = (*, proxy=None, max_redirects=None, allow_redirects=true, http1_only=false, http2_only=false, http3_only=false, http3_with_fallback=false, retry=None, middleware=None, accept_encoding=None, ech_config=None, max_connections=None, idle_timeout=None, on_request=None, on_response=None, protocol_policy=None, http_intent=None, broken_quic_policy=None, h3_retry_mode=None, header_order=None, h3_header_order=None, cookie_order=None, https_only=false, hsts=None, base_url=None, network_partition_context=None))]
    fn session<'py>(
        &self,
        py: Python<'py>,
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
        broken_quic_policy: Option<BrokenQuic>,
        h3_retry_mode: Option<PyH3RetryMode>,
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
        let mut middleware_slots = Vec::new();
        if let Some(ref mws) = middleware {
            (builder, middleware_slots) = apply_middlewares_to_session(builder, mws);
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
            builder = builder.protocol_policy(policy.validated()?);
        }
        if let Some(intent) = http_intent {
            builder = builder.http_intent(intent.into());
        }
        if let Some(policy) = broken_quic_policy {
            builder = builder.broken_quic_policy(policy.0);
        }
        if let Some(mode) = h3_retry_mode {
            builder = apply_h3_retry_mode(builder, mode)?;
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
        let state = SessionState::default().with_middleware(middleware_slots);
        if let Some(cb) = on_request {
            state.hooks.push_request(py, cb)?;
        }
        if let Some(cb) = on_response {
            state.hooks.push_response(py, cb)?;
        }
        Ok(PySession {
            inner: builder.build(),
            state,
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

    /// Whether HTTP/1.1 requests send header names in Title-Case
    /// (`Content-Type`) rather than lowercase (`content-type`). Readable because
    /// the casing is on the wire. Host keeps its capital H in either mode.
    /// HTTP/2 and HTTP/3 always send lowercase names.
    /// Defaults to True.
    #[getter]
    fn http1_title_case_headers(&self) -> bool {
        self.inner.http1_title_case_headers()
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
    /// The copy is built again from the same constructor options, or the same
    /// preset, with only the TLS profile replaced: its `randomization` is set,
    /// and the rest of the profile and every other option carry over. A CA file
    /// the options name is read again, and a keylog file opened again for
    /// appending.
    #[pyo3(signature = (*, shuffle_extensions=true))]
    fn randomize_fingerprint(&self, shuffle_extensions: bool) -> PyResult<Self> {
        let profile = randomized_tls_profile(&self.inner, shuffle_extensions);
        Self::from_recipe(self.recipe.with_tls_profile(profile))
    }

    /// Tunnel to `target_host:target_port` through `proxy`, resolving names as
    /// this client does, and return the seconds the tunnel took to set up.
    #[pyo3(signature = (proxy, target_host="www.google.com", target_port=443, timeout=5.0))]
    fn check_proxy<'py>(
        &self,
        py: Python<'py>,
        proxy: &Bound<'py, PyAny>,
        target_host: &str,
        target_port: u16,
        timeout: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let check = proxy_check(&self.inner, proxy, target_host, target_port, timeout)?;
        crate::bridge::future_into_py(py, check)
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
    /// How `inner` was built, for `randomize_fingerprint()`.
    recipe: Arc<ClientRecipe>,
}

impl PyBlockingClient {
    fn from_recipe(recipe: ClientRecipe) -> PyResult<Self> {
        Ok(Self {
            inner: recipe.build()?,
            recipe: Arc::new(recipe),
        })
    }

    fn from_preset(
        preset: lkrequest::preset::ClientPreset,
        tcp: lkrequest::TcpFingerprint,
    ) -> Self {
        Self {
            inner: build_preset_client(preset.clone(), tcp.clone(), None),
            recipe: Arc::new(ClientRecipe::preset(preset, tcp)),
        }
    }
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
        http1_title_case_headers=None,
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
        trust_anchor_advertisement=None,
        trust_anchor_recovery=None,
        trust_anchor_bindings=None,
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
        default_headers: Option<StrPairs>,
        header_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        http1_title_case_headers: Option<bool>,
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
        trust_anchor_advertisement: Option<String>,
        trust_anchor_recovery: Option<String>,
        trust_anchor_bindings: Option<BTreeMap<String, String>>,
        ech_config: Option<Vec<u8>>,
        dns: Option<Bound<'_, PyAny>>,
        ip_family: Option<String>,
        connect_to: Option<HashMap<String, String>>,
        system_dns_cache_ttl: Option<f64>,
        system_dns_cache_max_entries: Option<usize>,
        keylog: Option<Bound<'_, PyAny>>,
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
        let config = ClientConfig {
            tls_profile: tls,
            h2_profile: h2,
            tcp_fingerprint: tcp,
            default_headers,
            header_order,
            h3_header_order,
            cookie_order,
            http1_title_case_headers,
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
            trust_anchor_policy: crate::trust_anchor::parse_policy(
                trust_anchor_advertisement.as_deref(),
                trust_anchor_recovery.as_deref(),
            )?,
            trust_anchor_bindings: trust_anchor_bindings
                .map(crate::trust_anchor::parse_bindings)
                .transpose()?,
            ech_config,
            dns: dns.as_ref().map(resolve_dns).transpose()?,
            ip_family,
            connect_to,
            system_dns_cache_ttl,
            system_dns_cache_max_entries,
            keylog: keylog.as_ref().map(resolve_keylog).transpose()?,
            protocol_policy: protocol_policy
                .map(PyProtocolPolicy::validated)
                .transpose()?,
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
        };
        Self::from_recipe(ClientRecipe::Options(config))
    }

    #[staticmethod]
    fn chrome_131() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_131(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_144() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_144(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_145() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_145(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_146() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_146(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_147() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_147(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_148() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_148(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_149() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_149(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_150() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_150(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_151() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_151(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_152() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_152(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_153() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_153(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_154() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_154(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_155() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_155(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_156() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_156(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn chrome_157() -> Self {
        Self::from_preset(
            lkrequest::preset::chrome_157(),
            lkrequest::TcpFingerprint::chrome(),
        )
    }

    #[staticmethod]
    fn firefox_133() -> Self {
        Self::from_preset(
            lkrequest::preset::firefox_133(),
            lkrequest::TcpFingerprint::firefox(),
        )
    }

    #[staticmethod]
    fn firefox_147() -> Self {
        Self::from_preset(
            lkrequest::preset::firefox_147(),
            lkrequest::TcpFingerprint::firefox(),
        )
    }

    #[staticmethod]
    fn firefox_156() -> Self {
        Self::from_preset(
            lkrequest::preset::firefox_156(),
            lkrequest::TcpFingerprint::firefox(),
        )
    }

    #[staticmethod]
    fn safari_18() -> Self {
        Self::from_preset(
            lkrequest::preset::safari_18(),
            lkrequest::TcpFingerprint::safari(),
        )
    }

    #[staticmethod]
    fn safari_26() -> Self {
        Self::from_preset(
            lkrequest::preset::safari_26(),
            lkrequest::TcpFingerprint::safari(),
        )
    }

    #[pyo3(signature = (*, proxy=None, max_redirects=None, allow_redirects=true, http1_only=false, http2_only=false, http3_only=false, http3_with_fallback=false, retry=None, middleware=None, accept_encoding=None, ech_config=None, max_connections=None, idle_timeout=None, on_request=None, on_response=None, protocol_policy=None, http_intent=None, broken_quic_policy=None, h3_retry_mode=None, header_order=None, h3_header_order=None, cookie_order=None, https_only=false, hsts=None, base_url=None, network_partition_context=None))]
    fn session<'py>(
        &self,
        py: Python<'py>,
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
        broken_quic_policy: Option<BrokenQuic>,
        h3_retry_mode: Option<PyH3RetryMode>,
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
        let mut middleware_slots = Vec::new();
        if let Some(ref mws) = middleware {
            (builder, middleware_slots) = apply_middlewares_to_session(builder, mws);
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
            builder = builder.protocol_policy(policy.validated()?);
        }
        if let Some(intent) = http_intent {
            builder = builder.http_intent(intent.into());
        }
        if let Some(policy) = broken_quic_policy {
            builder = builder.broken_quic_policy(policy.0);
        }
        if let Some(mode) = h3_retry_mode {
            builder = apply_h3_retry_mode(builder, mode)?;
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
        let state = SessionState::default().with_middleware(middleware_slots);
        if let Some(cb) = on_request {
            state.hooks.push_request(py, cb)?;
        }
        if let Some(cb) = on_response {
            state.hooks.push_response(py, cb)?;
        }
        Ok(PyBlockingSession {
            inner: builder.build(),
            state,
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

    /// Whether HTTP/1.1 requests send header names in Title-Case
    /// (`Content-Type`) rather than lowercase (`content-type`). Readable because
    /// the casing is on the wire. Host keeps its capital H in either mode.
    /// HTTP/2 and HTTP/3 always send lowercase names.
    /// Defaults to True.
    #[getter]
    fn http1_title_case_headers(&self) -> bool {
        self.inner.http1_title_case_headers()
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
    /// The copy is built again from the same constructor options, or the same
    /// preset, with only the TLS profile replaced: its `randomization` is set,
    /// and the rest of the profile and every other option carry over. A CA file
    /// the options name is read again, and a keylog file opened again for
    /// appending.
    #[pyo3(signature = (*, shuffle_extensions=true))]
    fn randomize_fingerprint(&self, shuffle_extensions: bool) -> PyResult<Self> {
        let profile = randomized_tls_profile(&self.inner, shuffle_extensions);
        Self::from_recipe(self.recipe.with_tls_profile(profile))
    }

    /// As `Client.check_proxy()`, blocking until the check is done.
    #[pyo3(signature = (proxy, target_host="www.google.com", target_port=443, timeout=5.0))]
    fn check_proxy(
        &self,
        py: Python<'_>,
        proxy: &Bound<'_, PyAny>,
        target_host: &str,
        target_port: u16,
        timeout: f64,
    ) -> PyResult<f64> {
        let check = proxy_check(&self.inner, proxy, target_host, target_port, timeout)?;
        py.detach(|| blocking_runtime().block_on(check))
    }

    fn __repr__(&self) -> String {
        format!("<BlockingClient tls='{}'>", self.inner.tls_profile().name)
    }
}

// ---------------------------------------------------------------------------
// Requests straight from a client
// ---------------------------------------------------------------------------

/// `get()` … `options()` on a client class, each sending the request from a
/// session of its own, as upstream's `Client::get()` and the like build one
/// per call. Forwarding to the session's method keeps the arguments, and how
/// they are checked, the same as there.
macro_rules! one_off_requests {
    ($client:ty: $($method:ident),*) => {
        #[pymethods]
        impl $client {
            $(
                #[doc = concat!(
                    "`session().", stringify!($method), "(url, **kwargs)`: the request ",
                    "from a session of its own, so no connection or cookie is kept ",
                    "from one call to the next."
                )]
                #[pyo3(signature = (url, **kwargs))]
                fn $method<'py>(
                    slf: &Bound<'py, Self>,
                    url: &Bound<'py, PyAny>,
                    kwargs: Option<&Bound<'py, PyDict>>,
                ) -> PyResult<Bound<'py, PyAny>> {
                    slf.call_method0("session")?
                        .call_method(stringify!($method), (url,), kwargs)
                }
            )*
        }
    };
}

one_off_requests!(PyClient: get, post, put, delete, head, patch, options);
one_off_requests!(PyBlockingClient: get, post, put, delete, head, patch, options);

// ---------------------------------------------------------------------------
// What a client was built with
// ---------------------------------------------------------------------------

/// `timeouts`, in seconds under the names of the arguments that set them.
fn timeouts_dict<'py>(
    py: Python<'py>,
    timeouts: &lkrequest::TimeoutConfig,
) -> PyResult<Bound<'py, PyDict>> {
    let secs = |timeout: Option<std::time::Duration>| timeout.map(|t| t.as_secs_f64());
    let dict = PyDict::new(py);
    dict.set_item("dns_timeout", secs(timeouts.dns_timeout))?;
    dict.set_item("tcp_connect_timeout", secs(timeouts.tcp_connect_timeout))?;
    dict.set_item(
        "tls_handshake_timeout",
        secs(timeouts.tls_handshake_timeout),
    )?;
    dict.set_item("ttfb_timeout", secs(timeouts.ttfb_timeout))?;
    dict.set_item("total_timeout", secs(timeouts.total_timeout))?;
    dict.set_item("quic_connect_timeout", secs(timeouts.quic_connect_timeout))?;
    Ok(dict)
}

/// `limits`, under the names of the arguments that set them; no cap on
/// connections reads as `None`, as that argument takes it.
fn resource_limits_dict<'py>(
    py: Python<'py>,
    limits: &lkrequest::ResourceLimits,
) -> PyResult<Bound<'py, PyDict>> {
    let connections = Some(limits.max_connections_per_session).filter(|&cap| cap != usize::MAX);
    let dict = PyDict::new(py);
    dict.set_item("max_response_body_size", limits.max_response_body_size)?;
    dict.set_item("max_connections_per_session", connections)?;
    dict.set_item("max_header_count", limits.max_header_count)?;
    dict.set_item("max_header_size", limits.max_header_size)?;
    dict.set_item("max_headers_total_size", limits.max_headers_total_size)?;
    dict.set_item("min_transfer_rate", limits.min_transfer_rate)?;
    dict.set_item(
        "min_transfer_rate_window",
        limits.transfer_rate_window.as_secs_f64(),
    )?;
    Ok(dict)
}

/// Read-only settings on a client class, as the client has them once built,
/// a preset applied: mostly under the name of the argument that sets them.
macro_rules! client_settings {
    ($client:ty) => {
        #[pymethods]
        impl $client {
            /// The TLS profile its ClientHello is built from.
            #[getter]
            fn tls_profile(&self) -> crate::fingerprint::PyTlsProfile {
                crate::fingerprint::PyTlsProfile {
                    inner: self.inner.tls_profile().clone(),
                }
            }

            /// The HTTP/2 profile.
            #[getter]
            fn h2_profile(&self) -> crate::fingerprint::PyH2Profile {
                crate::fingerprint::PyH2Profile {
                    inner: self.inner.h2_profile().clone(),
                }
            }

            /// The TCP fingerprint, or `None` to leave sockets as the OS sets
            /// them up.
            #[getter]
            fn tcp_fingerprint(&self) -> Option<crate::fingerprint::PyTcpFingerprint> {
                self.inner.tcp_fingerprint().map(|fingerprint| {
                    crate::fingerprint::PyTcpFingerprint {
                        inner: fingerprint.clone(),
                    }
                })
            }

            /// The default headers as `(name, value)` pairs, in the order they
            /// go out wherever `header_order` does not place them.
            #[getter]
            fn default_headers(&self) -> Vec<(String, String)> {
                self.inner
                    .default_headers()
                    .iter()
                    .map(|(name, value)| {
                        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
                        (name.as_str().to_owned(), value)
                    })
                    .collect()
            }

            #[getter]
            fn header_order(&self) -> Option<Vec<String>> {
                self.inner
                    .header_order()
                    .map(|names| names.iter().map(|name| name.as_str().to_owned()).collect())
            }

            #[getter]
            fn h3_header_order(&self) -> Option<Vec<String>> {
                self.inner
                    .h3_header_order()
                    .map(|names| names.iter().map(|name| name.as_str().to_owned()).collect())
            }

            #[getter]
            fn cookie_order(&self) -> Option<Vec<String>> {
                self.inner
                    .cookie_order()
                    .map(|names| names.iter().map(|name| name.to_string()).collect())
            }

            /// The timeouts in seconds, `None` where there is none.
            #[getter]
            fn timeouts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
                timeouts_dict(py, self.inner.timeouts())
            }

            /// The response and connection limits.
            #[getter]
            fn resource_limits<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
                resource_limits_dict(py, self.inner.resource_limits())
            }

            /// The protocol policy its sessions start from.
            #[getter]
            fn protocol_policy(&self) -> PyProtocolPolicy {
                PyProtocolPolicy {
                    inner: self.inner.protocol_policy().clone(),
                }
            }

            #[getter]
            fn verify(&self) -> bool {
                self.inner.verify()
            }

            #[getter]
            fn ip_family(&self) -> &'static str {
                crate::dns::family_label(self.inner.ip_family())
            }

            #[getter]
            fn h2_fallback_h1(&self) -> bool {
                self.inner.fallback().h2_to_h1
            }

            #[getter]
            fn proxy_fallback_direct(&self) -> bool {
                self.inner.fallback().proxy_to_direct
            }

            #[getter]
            fn max_pending_h2_requests(&self) -> Option<usize> {
                self.inner.max_pending_h2_requests()
            }

            #[getter]
            fn ech_config(&self) -> Option<Vec<u8>> {
                self.inner.ech_config().map(<[u8]>::to_vec)
            }
        }
    };
}

client_settings!(PyClient);
client_settings!(PyBlockingClient);
