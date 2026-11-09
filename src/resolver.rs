//! `Client(dns=...)` given Python code to look names up with — a function
//! `resolve(host, port)`, or an object with that method and, optionally,
//! `lookup_https(host)` — behind upstream's `DnsResolver` trait.
//!
//! The code is synchronous and upstream resolves in async code, so each call
//! runs on tokio's blocking pool, where waiting for the GIL, and for the code,
//! holds up none of the workers. Upstream bounds every lookup with the client's
//! `dns_timeout` and applies `ip_family` to what comes back.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use lkrequest::dns::{DnsResolver, HttpsRecord};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::error::RaisedInPython;
use crate::types::is_async_function;

pub(crate) struct PyDnsResolver {
    resolve: Arc<Py<PyAny>>,
    lookup_https: Option<Arc<Py<PyAny>>>,
}

impl PyDnsResolver {
    /// `dns=` given as a function, or as an object with a `resolve` method.
    pub(crate) fn from_python(dns: &Bound<'_, PyAny>) -> PyResult<Self> {
        let (resolve, lookup_https) = match dns.getattr_opt("resolve")? {
            Some(resolve) => (resolve, dns.getattr_opt("lookup_https")?),
            None if dns.is_callable() => (dns.clone(), None),
            None => {
                return Err(PyTypeError::new_err(
                    "dns must be str, a function resolve(host, port), or an object with a resolve(host, port) method",
                ));
            }
        };
        for function in std::iter::once(&resolve).chain(&lookup_https) {
            if !function.is_callable() {
                return Err(PyTypeError::new_err(
                    "dns resolve and lookup_https must be callable",
                ));
            }
            // Upstream asks synchronously, so a coroutine would come back unawaited.
            if is_async_function(function)? {
                return Err(PyTypeError::new_err(
                    "dns resolve() and lookup_https() must be plain functions, not async ones",
                ));
            }
        }
        Ok(Self {
            resolve: Arc::new(resolve.unbind()),
            lookup_https: lookup_https.map(|function| Arc::new(function.unbind())),
        })
    }
}

#[async_trait]
impl DnsResolver for PyDnsResolver {
    /// What the code returns: each address an IP, which takes the requested
    /// port, or `"ip:port"`. Upstream fails the request when there is none.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let function = Arc::clone(&self.resolve);
        let name = host.to_owned();
        let answers: Vec<String> = call(format!("dns resolve() for {host}:{port}"), move |py| {
            function.bind(py).call1((name, port))?.extract()
        })
        .await?;
        answers
            .iter()
            .map(|answer| parse_address(answer, port))
            .collect()
    }

    /// The dict `lookup_https()` returns, or no record without one.
    async fn lookup_https(&self, host: &str) -> io::Result<Option<HttpsRecord>> {
        let Some(function) = self.lookup_https.as_ref().map(Arc::clone) else {
            return Ok(None);
        };
        let name = host.to_owned();
        let record = call(format!("dns lookup_https() for {host}"), move |py| {
            let record = function.bind(py).call1((name,))?;
            if record.is_none() {
                return Ok(None);
            }
            https_record(&record).map(Some)
        })
        .await;
        // Upstream takes a failed lookup for a missing record without a word.
        if let Err(err) = &record {
            tracing::warn!(host, error = %err, "dns.lookup_https_failed");
        }
        record
    }
}

/// Run `function` with the GIL on the blocking pool. What it raises comes back
/// inside the I/O error, for the request error to name as its `__cause__`.
async fn call<T: Send + 'static>(
    what: String,
    function: impl FnOnce(Python<'_>) -> PyResult<T> + Send + 'static,
) -> io::Result<T> {
    let outcome = tokio::task::spawn_blocking(move || {
        Python::try_attach(|py| {
            function(py).map_err(|err| {
                io::Error::other(RaisedInPython::new(format!("{what} raised {err}"), err))
            })
        })
    })
    .await
    .map_err(io::Error::other)?;
    outcome.unwrap_or_else(|| Err(io::Error::other("the Python interpreter has shut down")))
}

/// An address `resolve()` returned: an IP, which takes the requested port, or
/// `"ip:port"`, an IPv6 address with a port in brackets.
fn parse_address(answer: &str, port: u16) -> io::Result<SocketAddr> {
    answer
        .parse::<SocketAddr>()
        .ok()
        .or_else(|| {
            answer
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port))
        })
        .filter(|address| address.port() != 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "dns resolve() returned {answer:?}, which is not an IP address with an optional non-zero port (IPv6 with a port as \"[::1]:443\")"
                ),
            )
        })
}

/// An HTTPS record from the dict `lookup_https()` returned, refusing what
/// upstream's own parser would discard.
fn https_record(record: &Bound<'_, PyAny>) -> PyResult<HttpsRecord> {
    let fields = record
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("dns lookup_https() must return a dict or None"))?;
    let mut parsed = HttpsRecord::default();
    for (key, value) in fields.iter() {
        match key.extract::<String>()?.as_str() {
            "alpn" => parsed.alpn = value.extract()?,
            "no_default_alpn" => parsed.no_default_alpn = value.extract()?,
            "target" => parsed.target = value.extract()?,
            "port" => parsed.port = value.extract()?,
            "ech_config_list" => parsed.ech_config_list = value.extract()?,
            "ipv4_hints" => parsed.ipv4_hints = hints(&value, "IPv4")?,
            "ipv6_hints" => parsed.ipv6_hints = hints(&value, "IPv6")?,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown HTTPS record field '{other}'"
                )));
            }
        }
    }
    if parsed.port == Some(0) {
        return Err(PyValueError::new_err("an HTTPS record's port cannot be 0"));
    }
    if parsed.no_default_alpn && parsed.alpn.is_empty() {
        return Err(PyValueError::new_err(
            "an HTTPS record with no_default_alpn needs an alpn list",
        ));
    }
    Ok(parsed)
}

/// Address hints of one family, given as strings.
fn hints<T: FromStr>(value: &Bound<'_, PyAny>, family: &str) -> PyResult<Vec<T>> {
    value
        .extract::<Vec<String>>()?
        .iter()
        .map(|hint| {
            hint.parse()
                .map_err(|_| PyValueError::new_err(format!("'{hint}' is not an {family} address")))
        })
        .collect()
}
