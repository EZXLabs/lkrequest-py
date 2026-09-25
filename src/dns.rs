//! Address selection: `Client(ip_family=...)` and `Client(connect_to=...)`.
//!
//! Both are upstream's — `ClientBuilder::ip_family` restricts the endpoints this
//! process picks (the target, a proxy's ingress, a SOCKS5 UDP relay, QUIC) to
//! one family, and `ClientBuilder::connect_to` dials a fixed address for a
//! `host:port` while TLS, `Host` and cookies keep the original name. This
//! module only turns the Python spellings into upstream's types, rejecting as
//! `ValueError` what upstream would panic on (a bad host, a zero port) or would
//! report only once a request is sent (an override outside `ip_family`).
//!
//! **Scope of `ip_family`:** only addresses this process selects. An HTTP
//! `CONNECT` proxy, `socks5h` or MASQUE resolves a hostname target itself, so
//! the family it dials is the proxy's choice; `connect_to` is how a caller
//! hands such a proxy an address instead of a name.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use lkrequest::IpFamily;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Parse the `ip_family=` argument.
pub(crate) fn parse_ip_family(name: &str) -> PyResult<IpFamily> {
    match name {
        "any" => Ok(IpFamily::Any),
        "ipv4" => Ok(IpFamily::Ipv4),
        "ipv6" => Ok(IpFamily::Ipv6),
        _ => Err(PyValueError::new_err(format!(
            "Unknown ip_family: '{name}'. Available: any, ipv4, ipv6"
        ))),
    }
}

/// The `ip_family=` spelling, for error messages.
fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Any => "any",
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
    }
}

/// Whether `ip` is an address `family` permits. Mirrors upstream's rule,
/// including that `ipv6` excludes IPv4-mapped addresses (`::ffff:a.b.c.d`),
/// which would otherwise carry IPv4 traffic under an IPv6 policy.
fn family_allows(family: IpFamily, ip: IpAddr) -> bool {
    match family {
        IpFamily::Any => true,
        IpFamily::Ipv4 => ip.is_ipv4(),
        IpFamily::Ipv6 => matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none()),
    }
}

/// One `connect_to=` entry: requests to `host:port` dial `address` instead.
pub(crate) struct DialOverride {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) address: SocketAddr,
}

/// Parse `connect_to={"host:port": "ip:port", ...}`.
///
/// The key names the origin as it appears in request URLs, an IPv6 host in
/// brackets (`"[::1]:8443"`); the value is the address to dial, IPv6 likewise
/// bracketed (`"[2001:db8::1]:443"`).
pub(crate) fn parse_connect_to(
    entries: HashMap<String, String>,
    family: IpFamily,
) -> PyResult<Vec<DialOverride>> {
    let mut overrides: Vec<DialOverride> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let (host, port) = parse_origin(&key)?;
        // Upstream keys the table by the normalized host, so two spellings of
        // one origin ("Example.com" / "example.com") would silently collapse
        // into whichever it happened to insert last.
        if overrides.iter().any(|o| o.host == host && o.port == port) {
            return Err(PyValueError::new_err(format!(
                "connect_to lists {host}:{port} more than once"
            )));
        }
        let address = parse_address(&key, &value)?;
        if !family_allows(family, address.ip()) {
            return Err(PyValueError::new_err(format!(
                "connect_to maps {key} to {address}, which ip_family=\"{}\" excludes",
                family_label(family)
            )));
        }
        overrides.push(DialOverride {
            host,
            port,
            address,
        });
    }
    Ok(overrides)
}

/// Split and validate a `"host:port"` key into upstream's normalized host.
fn parse_origin(key: &str) -> PyResult<(String, u16)> {
    let invalid = |why: &str| {
        PyValueError::new_err(format!(
            "connect_to key '{key}' {why}; expected \"host:port\" (an IPv6 host in brackets, e.g. \"[::1]:443\")"
        ))
    };
    let (host, port) = if key.starts_with('[') {
        let end = key.find("]:").ok_or_else(|| invalid("has no port"))?;
        (&key[..=end], &key[end + 2..])
    } else {
        let (host, port) = key.rsplit_once(':').ok_or_else(|| invalid("has no port"))?;
        if host.contains(':') {
            return Err(invalid("has an unbracketed IPv6 host"));
        }
        (host, port)
    };
    let port = parse_port(port).ok_or_else(|| invalid("has an invalid port"))?;
    let host = url::Host::parse(host)
        .map_err(|_| invalid("has an invalid host"))?
        .to_string();
    Ok((host, port))
}

/// Parse a `connect_to` value as a socket address with a non-zero port.
fn parse_address(key: &str, value: &str) -> PyResult<SocketAddr> {
    match value.parse::<SocketAddr>() {
        Ok(address) if address.port() != 0 => Ok(address),
        _ => Err(PyValueError::new_err(format!(
            "connect_to value '{value}' for {key} must be \"ip:port\" with a non-zero port (IPv6 as \"[2001:db8::1]:443\")"
        ))),
    }
}

/// A port in 1..=65535; upstream rejects 0 with a panic.
fn parse_port(text: &str) -> Option<u16> {
    text.parse::<u16>().ok().filter(|&port| port != 0)
}
