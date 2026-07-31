//! Python exception hierarchy (`RequestError` and subclasses) and the mapping
//! from `lkrequest::error::Error` variants to the corresponding `PyErr`.

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;

create_exception!(_lkrequest, RequestError, PyException);
create_exception!(_lkrequest, TlsError, RequestError);
create_exception!(_lkrequest, LkProxyError, RequestError);
create_exception!(_lkrequest, HttpStatusError, RequestError);
create_exception!(_lkrequest, LkConnectionError, RequestError);
create_exception!(_lkrequest, LkTimeoutError, RequestError);
create_exception!(_lkrequest, TooManyRedirectsError, RequestError);
create_exception!(_lkrequest, ResourceLimitError, RequestError);

pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("RequestError", m.py().get_type::<RequestError>())?;
    m.add("TlsError", m.py().get_type::<TlsError>())?;
    m.add("ProxyError", m.py().get_type::<LkProxyError>())?;
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
    Ok(())
}

pub fn to_py_err(err: lkrequest::error::Error) -> PyErr {
    use lkrequest::error::Error as E;
    match &err {
        E::Timeout { .. } => LkTimeoutError::new_err(err.to_string()),
        E::Connection(_) | E::Io(_) => LkConnectionError::new_err(err.to_string()),
        E::Tls(_) => TlsError::new_err(err.to_string()),
        E::Proxy(_) => LkProxyError::new_err(err.to_string()),
        E::Status { .. } => HttpStatusError::new_err(err.to_string()),
        E::TooManyRedirects(_) => TooManyRedirectsError::new_err(err.to_string()),
        E::InvalidConfig(_) => PyValueError::new_err(err.to_string()),
        E::ResourceLimitExceeded(_) => ResourceLimitError::new_err(err.to_string()),
        _ => RequestError::new_err(err.to_string()),
    }
}
