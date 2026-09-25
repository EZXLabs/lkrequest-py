//! Python exception hierarchy (`RequestError` and subclasses) and the mapping
//! from `lkrequest::error::Error` variants to the corresponding `PyErr`.

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::GILOnceCell;
use pyo3::types::{PyDict, PyTuple, PyType};

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
// name here has to follow. `tests/test_exceptions.py` pins the whole mapping.
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
static JSON_DECODE_ERROR: GILOnceCell<Py<PyType>> = GILOnceCell::new();

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
        .downcast_into::<PyType>()?;
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
    Ok(class.downcast_into::<PyType>()?.unbind())
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
    m.add("RequestError", m.py().get_type::<RequestError>())?;
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
    use lkrequest::error::Error as E;
    let message = describe(&err);
    match &err {
        E::Timeout { .. } => LkTimeoutError::new_err(message),
        E::Connection(_) | E::Io(_) => LkConnectionError::new_err(message),
        E::Tls(_) => TlsError::new_err(message),
        E::Proxy(_) => ProxyError::new_err(message),
        E::Status { .. } => HttpStatusError::new_err(message),
        E::TooManyRedirects(_) => TooManyRedirectsError::new_err(message),
        E::InvalidConfig(_) => PyValueError::new_err(message),
        E::ResourceLimitExceeded(_) => ResourceLimitError::new_err(message),
        _ => RequestError::new_err(message),
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
