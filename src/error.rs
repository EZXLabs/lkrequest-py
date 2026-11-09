//! Python exception hierarchy (`RequestError` and subclasses) and the mapping
//! from `lkrequest::error::Error` variants to the corresponding `PyErr`, with
//! what upstream knows about the failure set on the exception as attributes.

use std::fmt;
use std::marker::PhantomData;
use std::sync::{Mutex, PoisonError};

use lkrequest::diagnostics::RequestDiagnostics;
use lkrequest::error::{ConnectionPhase, ProxyErrorKind};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyString, PyTuple, PyType};
use pyo3::{PyErrArguments, PyTypeInfo};

// The first argument becomes `__module__`, and it has to name a module that can
// actually be imported under the name the class reports, because that is how
// `pickle` finds a class again: import `__module__`, then `getattr` it by
// `__qualname__`, then check the result is the same object. `_lkrequest` is not
// importable on its own — the extension lives inside the `lkrequest` package —
// so every exception here used to fail to pickle, which silently replaced a real
// error crossing a process boundary with `PicklingError`.
//
// So these name the package, not the extension module, and each Rust ident has
// to match the attribute `lkrequest/__init__.py` re-exports it as. That is why
// `ConnectionError` and `TimeoutError` keep an `Lk` prefix the other two do not:
// the package renames those two to stay clear of the Python builtins, and the
// name here has to follow. `TestExceptionPickling` in `tests/test_advanced.py`
// pins the whole mapping.
create_exception!(lkrequest, RequestError, PyException);
create_exception!(lkrequest, TlsError, RequestError);
create_exception!(lkrequest, ProxyError, RequestError);
create_exception!(lkrequest, HttpStatusError, RequestError);
create_exception!(lkrequest, LkConnectionError, RequestError);
create_exception!(lkrequest, LkTimeoutError, RequestError);
create_exception!(lkrequest, TooManyRedirectsError, RequestError);
create_exception!(lkrequest, ResourceLimitError, RequestError);

/// `JsonDecodeError`, assembled at import time rather than by
/// `create_exception!`, which takes a single base — this one needs two, and one
/// of them only exists at runtime.
static JSON_DECODE_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// Build `JsonDecodeError` deriving from both `json.JSONDecodeError` and
/// [`RequestError`].
///
/// Two bases so that neither `except` breaks. Catching it as a `RequestError`
/// is the point of the class; catching it as a `json.JSONDecodeError` is what
/// callers had to write while `json()` leaked the stdlib exception, and fixing
/// that leak should not invalidate their code. `requests` resolves the same
/// dilemma the same way.
///
/// `json.JSONDecodeError` comes first so that `__init__` resolves to it, which
/// is what populates `msg` / `doc` / `pos` / `lineno` / `colno`. With
/// `RequestError` first, `Exception.__init__` would win and those attributes
/// would silently go missing.
fn build_json_decode_error(py: Python<'_>) -> PyResult<Py<PyType>> {
    let stdlib = py
        .import("json")?
        .getattr("JSONDecodeError")?
        .cast_into::<PyType>()?;
    let bases = PyTuple::new(py, [stdlib, py.get_type::<RequestError>()])?;
    let namespace = PyDict::new(py);
    // The package, for the same reason the `create_exception!` calls above name
    // it: `pickle` has to be able to import this and find the class again.
    namespace.set_item("__module__", "lkrequest")?;
    namespace.set_item(
        "__doc__",
        "Raised when a response body cannot be parsed as JSON. \
         Subclasses both RequestError and json.JSONDecodeError.",
    )?;
    let class =
        py.import("builtins")?
            .getattr("type")?
            .call1(("JsonDecodeError", bases, namespace))?;
    Ok(class.cast_into::<PyType>()?.unbind())
}

/// Re-raise a failure from the `json` module inside the library's hierarchy.
///
/// Only a decode failure is converted. Anything else — a `RecursionError` from
/// a pathologically nested document, say — is passed through untouched rather
/// than disguised as a request error.
pub fn to_json_py_err(py: Python<'_>, err: PyErr) -> PyErr {
    match as_json_decode_error(py, &err) {
        Ok(Some(converted)) => converted,
        // Either not a decode failure, or the conversion itself failed. The
        // original error is more useful than a bookkeeping error about it.
        Ok(None) | Err(_) => err,
    }
}

fn as_json_decode_error(py: Python<'_>, err: &PyErr) -> PyResult<Option<PyErr>> {
    let stdlib = py.import("json")?.getattr("JSONDecodeError")?;
    if !err.is_instance(py, &stdlib) {
        return Ok(None);
    }
    let Some(class) = JSON_DECODE_ERROR.get(py) else {
        return Ok(None);
    };
    // Rebuilt from the original's fields rather than from a rendered message:
    // inheriting `json.JSONDecodeError.__init__` means ours also requires
    // (msg, doc, pos), and passing them through is what keeps the position
    // information the stdlib exception carried.
    let value = err.value(py);
    let args = (
        value.getattr("msg")?,
        value.getattr("doc")?,
        value.getattr("pos")?,
    );
    Ok(Some(PyErr::from_value(class.bind(py).call1(args)?)))
}

pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Class-level defaults, so that every `RequestError` has the attributes,
    // one raised by Python code or built by hand included.
    let request_error = m.py().get_type::<RequestError>();
    for name in [
        "phase",
        "status_code",
        "proxy_error_kind",
        "tls_alert",
        "diagnostics",
    ] {
        request_error.setattr(name, m.py().None())?;
    }
    request_error.setattr("retryable", false)?;
    request_error.setattr("safe_to_replay", false)?;

    m.add("RequestError", request_error)?;
    m.add("TlsError", m.py().get_type::<TlsError>())?;
    m.add("ProxyError", m.py().get_type::<ProxyError>())?;
    m.add("HttpStatusError", m.py().get_type::<HttpStatusError>())?;
    m.add("ConnectionError", m.py().get_type::<LkConnectionError>())?;
    m.add("TimeoutError", m.py().get_type::<LkTimeoutError>())?;
    m.add(
        "TooManyRedirectsError",
        m.py().get_type::<TooManyRedirectsError>(),
    )?;
    m.add(
        "ResourceLimitError",
        m.py().get_type::<ResourceLimitError>(),
    )?;

    let json_decode_error = build_json_decode_error(m.py())?;
    m.add("JsonDecodeError", json_decode_error.clone_ref(m.py()))?;
    // Stashed so `Response.json()` can raise it without rebuilding the class.
    // A second module init (re-import, subinterpreter) keeps the first class
    // rather than failing the import; the two are structurally identical.
    let _ = JSON_DECODE_ERROR.set(m.py(), json_decode_error);
    Ok(())
}

pub fn to_py_err(err: lkrequest::error::Error) -> PyErr {
    let cause = raised_in_python(&err).and_then(RaisedInPython::take);
    raise(&err, None, cause)
}

/// The exception `err` is raised as, for a retry callback to look at. The
/// Python exception behind it stays where it is, for the one finally raised.
pub(crate) fn exception_for(py: Python<'_>, err: &lkrequest::error::Error) -> PyErr {
    let cause = raised_in_python(err).and_then(|raised| raised.clone_ref(py));
    raise(err, None, cause)
}

/// `to_py_err`, with the timings and transport of the failed request attached
/// as `diagnostics`.
pub(crate) fn to_py_err_with_diagnostics(
    err: lkrequest::error::Error,
    diagnostics: RequestDiagnostics,
) -> PyErr {
    let cause = raised_in_python(&err).and_then(RaisedInPython::take);
    raise(&err, Some(diagnostics), cause)
}

/// `HttpStatusError` for a response that `error_for_status()` refuses.
pub(crate) fn status_error(
    message: String,
    status_code: u16,
    diagnostics: &RequestDiagnostics,
) -> PyErr {
    let details = ErrorDetails {
        status_code: Some(status_code),
        // As upstream counts a status error: a 5xx is worth another try.
        retryable: status_code >= 500,
        diagnostics: Some(diagnostics.clone()),
        ..ErrorDetails::default()
    };
    raised::<HttpStatusError>(message, details, None)
}

fn raise(
    err: &lkrequest::error::Error,
    diagnostics: Option<RequestDiagnostics>,
    cause: Option<PyErr>,
) -> PyErr {
    use lkrequest::error::Error as E;
    let details = ErrorDetails::of(err, diagnostics);
    // A failed trust-anchor recovery keeps upstream's wording, which says a
    // second connection was tried; it is classified by its cause below.
    let message = match err {
        E::TrustAnchorRecovery { .. } => describe(err),
        _ => describe(err.unwrapped()),
    };
    // With an H3 retry mode on, upstream wraps the original error in a request
    // context, and a trust-anchor recovery wraps its cause. Classify the
    // original: a wrapper itself would always fall through to the catch-all
    // arm below.
    let err = err.unwrapped();
    match err {
        E::Timeout { .. } => raised::<LkTimeoutError>(message, details, cause),
        E::Connection(_) | E::Io(_) => raised::<LkConnectionError>(message, details, cause),
        E::Tls(_) => raised::<TlsError>(message, details, cause),
        E::Proxy(_) => raised::<ProxyError>(message, details, cause),
        E::Status { .. } => raised::<HttpStatusError>(message, details, cause),
        E::TooManyRedirects(_) => raised::<TooManyRedirectsError>(message, details, cause),
        E::InvalidConfig(_) => PyValueError::new_err(message),
        E::ResourceLimitExceeded(_) => raised::<ResourceLimitError>(message, details, cause),
        _ => raised::<RequestError>(message, details, cause),
    }
}

/// A Python exception raised by code the Rust library called back into, a
/// `dns=` resolver, carried inside the error the library wraps it in so that
/// the `RequestError` this becomes can name it as its `__cause__`.
pub(crate) struct RaisedInPython {
    /// What the error says to Rust, written while the exception was at hand.
    message: String,
    error: Mutex<Option<PyErr>>,
}

impl RaisedInPython {
    pub(crate) fn new(message: String, error: PyErr) -> Self {
        Self {
            message,
            error: Mutex::new(Some(error)),
        }
    }

    fn take(&self) -> Option<PyErr> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    fn clone_ref(&self, py: Python<'_>) -> Option<PyErr> {
        self.error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|error| error.clone_ref(py))
    }
}

impl fmt::Display for RaisedInPython {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl fmt::Debug for RaisedInPython {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RaisedInPython {}

/// The `RaisedInPython` inside `err`, which upstream keeps as the source of the
/// connection error it reports for a failed lookup.
fn raised_in_python(err: &lkrequest::error::Error) -> Option<&RaisedInPython> {
    use lkrequest::error::Error as E;
    type Source<'a> = &'a (dyn std::error::Error + 'static);
    let mut source: Option<Source<'_>> = match err.unwrapped() {
        E::Io(io) => Some(io),
        E::Connection(connection) => connection.source.as_deref().map(|s| s as Source<'_>),
        E::Proxy(proxy) => proxy.source.as_deref().map(|s| s as Source<'_>),
        _ => None,
    };
    while let Some(error) = source {
        if let Some(raised) = error.downcast_ref::<RaisedInPython>() {
            return Some(raised);
        }
        // `io::Error::source()` skips the error it wraps, so look at that too.
        let wrapped = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<RaisedInPython>());
        if wrapped.is_some() {
            return wrapped;
        }
        source = error.source();
    }
    None
}

/// What upstream knows about a failure beyond its message, for the attributes
/// of the exception.
#[derive(Default)]
struct ErrorDetails {
    phase: Option<&'static str>,
    retryable: bool,
    safe_to_replay: bool,
    status_code: Option<u16>,
    proxy_error_kind: Option<&'static str>,
    tls_alert: Option<&'static str>,
    diagnostics: Option<RequestDiagnostics>,
}

impl ErrorDetails {
    fn of(err: &lkrequest::error::Error, diagnostics: Option<RequestDiagnostics>) -> Self {
        Self {
            phase: err.phase().map(phase_name),
            retryable: err.is_retryable(),
            safe_to_replay: err.is_safe_to_replay(),
            status_code: err.status().map(|status| status.as_u16()),
            proxy_error_kind: err
                .as_proxy_error()
                .map(|proxy| proxy_error_kind(proxy.kind)),
            tls_alert: err.as_tls_alert().map(|alert| alert.description.name()),
            diagnostics,
        }
    }
}

/// A `T` raised with `details` as its attributes, and `cause` as its `__cause__`.
fn raised<T: PyTypeInfo + 'static>(
    message: String,
    details: ErrorDetails,
    cause: Option<PyErr>,
) -> PyErr {
    PyErr::new::<T, _>(Raised::<T> {
        message,
        details,
        cause,
        class: PhantomData,
    })
}

/// The arguments of a lazily raised `T`, which are the finished instance: the
/// exception is only made once Python looks at it, so a request failing on a
/// worker thread does not wait there for the GIL, and Python takes an instance
/// of the class it is raising as it is.
struct Raised<T> {
    message: String,
    details: ErrorDetails,
    cause: Option<PyErr>,
    class: PhantomData<fn() -> T>,
}

impl<T: PyTypeInfo> Raised<T> {
    fn instance<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let instance = T::type_object(py).call1((self.message.as_str(),))?;
        let details = &self.details;
        instance.setattr("phase", details.phase)?;
        instance.setattr("retryable", details.retryable)?;
        instance.setattr("safe_to_replay", details.safe_to_replay)?;
        instance.setattr("status_code", details.status_code)?;
        instance.setattr("proxy_error_kind", details.proxy_error_kind)?;
        instance.setattr("tls_alert", details.tls_alert)?;
        if let Some(diagnostics) = &details.diagnostics {
            instance.setattr(
                "diagnostics",
                crate::response::diagnostics_dict(py, diagnostics)?,
            )?;
        }
        if let Some(cause) = &self.cause {
            instance.setattr("__cause__", cause.clone_ref(py).into_value(py))?;
        }
        Ok(instance)
    }
}

impl<T: PyTypeInfo> PyErrArguments for Raised<T> {
    fn arguments(self, py: Python<'_>) -> Py<PyAny> {
        // Setting attributes on a fresh exception does not fail; should it, the
        // class is called with the message alone and keeps its defaults.
        self.instance(py).map_or_else(
            |_| PyString::new(py, &self.message).into_any().unbind(),
            Bound::unbind,
        )
    }
}

fn phase_name(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::DnsResolution => "dns_resolution",
        ConnectionPhase::TcpConnect => "tcp_connect",
        ConnectionPhase::ProxyTunnel => "proxy_tunnel",
        ConnectionPhase::TlsHandshake => "tls_handshake",
        ConnectionPhase::H2Negotiation => "h2_negotiation",
        ConnectionPhase::H2cUpgrade => "h2c_upgrade",
        ConnectionPhase::QuicHandshake => "quic_handshake",
        ConnectionPhase::H3Negotiation => "h3_negotiation",
        ConnectionPhase::QuicFallback => "quic_fallback",
        ConnectionPhase::HttpRequest => "http_request",
    }
}

fn proxy_error_kind(kind: ProxyErrorKind) -> &'static str {
    match kind {
        ProxyErrorKind::TcpConnectFailed => "tcp_connect_failed",
        ProxyErrorKind::AuthenticationRequired => "authentication_required",
        ProxyErrorKind::AuthenticationFailed => "authentication_failed",
        ProxyErrorKind::TunnelRefused { .. } => "tunnel_refused",
        ProxyErrorKind::Socks5Error { .. } => "socks5_error",
        ProxyErrorKind::ProtocolError => "protocol_error",
        ProxyErrorKind::IoError => "io_error",
    }
}

/// The error's message, with an address-family rejection pointed at the
/// argument behind it: upstream words it as an "IPv4 policy" / "IPv6 policy",
/// which a Python caller has no way to connect to the `ip_family=` they passed.
fn describe(err: &lkrequest::error::Error) -> String {
    let message = err.to_string();
    if err.is_address_family_mismatch() {
        format!("{message} (excluded by the client's ip_family setting)")
    } else {
        message
    }
}
