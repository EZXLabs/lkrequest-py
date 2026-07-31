//! `Middleware` pyclass and the wrapper that bridges Python `on_request` /
//! `on_response` callbacks into the `lkrequest::Middleware` trait.

use pyo3::prelude::*;
use pyo3::types::PyDict;

// ---------------------------------------------------------------------------
// PyMiddleware — Python-facing pyclass
// ---------------------------------------------------------------------------

#[pyclass(name = "Middleware")]
pub struct PyMiddleware {
    pub(crate) name: String,
    pub(crate) on_request_fn: Option<PyObject>,
    pub(crate) on_response_fn: Option<PyObject>,
}

impl Clone for PyMiddleware {
    fn clone(&self) -> Self {
        Python::with_gil(|py| PyMiddleware {
            name: self.name.clone(),
            on_request_fn: self.on_request_fn.as_ref().map(|o| o.clone_ref(py)),
            on_response_fn: self.on_response_fn.as_ref().map(|o| o.clone_ref(py)),
        })
    }
}

#[pymethods]
impl PyMiddleware {
    #[new]
    #[pyo3(signature = (name, *, on_request=None, on_response=None))]
    fn new(name: String, on_request: Option<PyObject>, on_response: Option<PyObject>) -> Self {
        PyMiddleware {
            name,
            on_request_fn: on_request,
            on_response_fn: on_response,
        }
    }

    fn __repr__(&self) -> String {
        format!("<Middleware '{}'>", self.name)
    }
}

// ---------------------------------------------------------------------------
// PyMiddlewareWrapper — bridges PyMiddleware → lkrequest::Middleware trait
// ---------------------------------------------------------------------------

pub(crate) struct PyMiddlewareWrapper {
    name: String,
    on_request_fn: Option<PyObject>,
    on_response_fn: Option<PyObject>,
}

impl PyMiddlewareWrapper {
    pub fn from_py(mw: &PyMiddleware) -> Self {
        Python::with_gil(|py| PyMiddlewareWrapper {
            name: mw.name.clone(),
            on_request_fn: mw.on_request_fn.as_ref().map(|o| o.clone_ref(py)),
            on_response_fn: mw.on_response_fn.as_ref().map(|o| o.clone_ref(py)),
        })
    }
}

impl lkrequest::Middleware for PyMiddlewareWrapper {
    fn on_request(
        &self,
        mut req: lkrequest::middleware::MiddlewareRequest,
    ) -> Result<lkrequest::middleware::MiddlewareRequest, lkrequest::error::Error> {
        let Some(ref func) = self.on_request_fn else {
            return Ok(req);
        };
        tracing::debug!(middleware = %self.name, method = %req.method, url = %req.url, "middleware.on_request");
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("method", req.method.as_str());
            let _ = dict.set_item("url", &req.url);

            let headers_dict = PyDict::new(py);
            for (k, v) in req.headers.iter() {
                let _ = headers_dict.set_item(k.as_str(), v.to_str().unwrap_or(""));
            }
            let _ = dict.set_item("headers", headers_dict);

            let result = func.call1(py, (dict,)).map_err(|e| {
                lkrequest::error::Error::Http(format!("Middleware on_request error: {e}"))
            })?;

            if let Ok(returned) = result.downcast_bound::<PyDict>(py) {
                if let Ok(Some(url)) = returned.get_item("url") {
                    match url.extract::<String>() {
                        Ok(u) => req.url = u,
                        Err(_) => {
                            tracing::warn!(middleware = %self.name, "on_request returned non-string url, ignored")
                        }
                    }
                }
                if let Ok(Some(headers_obj)) = returned.get_item("headers") {
                    if let Ok(h) = headers_obj.downcast::<PyDict>() {
                        let mut new_headers = http::HeaderMap::new();
                        for (k, v) in h.iter() {
                            if let (Ok(name), Ok(val)) =
                                (k.extract::<String>(), v.extract::<String>())
                            {
                                match (
                                    http::header::HeaderName::from_bytes(name.as_bytes()),
                                    http::header::HeaderValue::from_str(&val),
                                ) {
                                    (Ok(hn), Ok(hv)) => {
                                        new_headers.append(hn, hv);
                                    }
                                    _ => {
                                        tracing::warn!(middleware = %self.name, header = %name, "on_request returned invalid header, skipped")
                                    }
                                }
                            }
                        }
                        req.headers = new_headers;
                    } else {
                        tracing::warn!(middleware = %self.name, "on_request returned non-dict headers, ignored");
                    }
                }
            } else if !result.is_none(py) {
                tracing::warn!(middleware = %self.name, "on_request should return a dict or None");
            }
            Ok(req)
        })
    }

    fn on_response(
        &self,
        mut resp: lkrequest::middleware::MiddlewareResponse,
    ) -> Result<lkrequest::middleware::MiddlewareResponse, lkrequest::error::Error> {
        let Some(ref func) = self.on_response_fn else {
            return Ok(resp);
        };
        tracing::debug!(middleware = %self.name, status = %resp.status.as_u16(), "middleware.on_response");
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            let _ = dict.set_item("status", resp.status.as_u16());

            let headers_dict = PyDict::new(py);
            for (k, v) in resp.headers.iter() {
                let _ = headers_dict.set_item(k.as_str(), v.to_str().unwrap_or(""));
            }
            let _ = dict.set_item("headers", headers_dict);

            let result = func.call1(py, (dict,)).map_err(|e| {
                lkrequest::error::Error::Http(format!("Middleware on_response error: {e}"))
            })?;

            if let Ok(returned) = result.downcast_bound::<PyDict>(py) {
                if let Ok(Some(headers_obj)) = returned.get_item("headers") {
                    if let Ok(h) = headers_obj.downcast::<PyDict>() {
                        let mut new_headers = http::HeaderMap::new();
                        for (k, v) in h.iter() {
                            if let (Ok(name), Ok(val)) =
                                (k.extract::<String>(), v.extract::<String>())
                            {
                                match (
                                    http::header::HeaderName::from_bytes(name.as_bytes()),
                                    http::header::HeaderValue::from_str(&val),
                                ) {
                                    (Ok(hn), Ok(hv)) => {
                                        new_headers.append(hn, hv);
                                    }
                                    _ => {
                                        tracing::warn!(middleware = %self.name, header = %name, "on_response returned invalid header, skipped")
                                    }
                                }
                            }
                        }
                        resp.headers = new_headers;
                    } else {
                        tracing::warn!(middleware = %self.name, "on_response returned non-dict headers, ignored");
                    }
                }
            } else if !result.is_none(py) {
                tracing::warn!(middleware = %self.name, "on_response should return a dict or None");
            }
            Ok(resp)
        })
    }

    fn name(&self) -> &str {
        &self.name
    }
}
