//! Response-side pyclasses: `Response`, `StreamingResponse` (async and
//! blocking), `HeaderMap`, and `RedirectRecord`, exposing status, headers,
//! body/text/json access, and the redirect chain.

use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

use crate::types::PyHttpVersion;

// ---------------------------------------------------------------------------
// HeaderMap — case-insensitive header collection
// ---------------------------------------------------------------------------

#[pyclass(name = "HeaderMap")]
#[derive(Clone)]
pub struct PyHeaderMap {
    entries: Vec<(String, String)>,
}

#[pymethods]
impl PyHeaderMap {
    fn __getitem__(&self, name: &str) -> PyResult<String> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(name.to_string()))
    }

    #[pyo3(signature = (name, default=None))]
    fn get(&self, name: &str, default: Option<&str>) -> Option<String> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.clone())
            .or_else(|| default.map(|d| d.to_string()))
    }

    fn get_all(&self, name: &str) -> Vec<String> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn __contains__(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .any(|(k, _)| k.to_ascii_lowercase() == lower)
    }

    fn __len__(&self) -> usize {
        self.entries.len()
    }

    fn __iter__(&self) -> PyHeaderMapKeysIter {
        PyHeaderMapKeysIter {
            keys: self.entries.iter().map(|(k, _)| k.clone()).collect(),
            index: 0,
        }
    }

    fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|(k, _)| k.clone()).collect()
    }

    fn values(&self) -> Vec<String> {
        self.entries.iter().map(|(_, v)| v.clone()).collect()
    }

    fn items(&self) -> Vec<(String, String)> {
        self.entries.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (k, v) in &self.entries {
            dict.set_item(k, v)?;
        }
        Ok(dict)
    }

    fn __repr__(&self) -> String {
        let items: Vec<String> = self
            .entries
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        format!("HeaderMap({{{}}})", items.join(", "))
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[pyclass]
struct PyHeaderMapKeysIter {
    keys: Vec<String>,
    index: usize,
}

#[pymethods]
impl PyHeaderMapKeysIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<String> {
        if self.index < self.keys.len() {
            let key = self.keys[self.index].clone();
            self.index += 1;
            Some(key)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// RedirectRecord — a single hop in the redirect chain
// ---------------------------------------------------------------------------

#[pyclass(name = "RedirectRecord")]
#[derive(Clone)]
pub struct PyRedirectRecord {
    #[pyo3(get)]
    url: String,
    #[pyo3(get)]
    status_code: u16,
    headers: Vec<(String, String)>,
    #[pyo3(get)]
    redirect_to: String,
}

#[pymethods]
impl PyRedirectRecord {
    #[getter]
    fn headers(&self) -> PyHeaderMap {
        PyHeaderMap {
            entries: self.headers.clone(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<RedirectRecord {} {} -> {}>",
            self.status_code, self.url, self.redirect_to
        )
    }
}

impl PyRedirectRecord {
    fn from_rust(r: &lkrequest::RedirectRecord) -> Self {
        let headers: Vec<(String, String)> = r
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        PyRedirectRecord {
            url: r.url().to_string(),
            status_code: r.status().as_u16(),
            headers,
            redirect_to: r.redirect_to().to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// Resolve a WHATWG encoding label (`gbk`, `shift_jis`, `utf-8`, …) to a
/// decoder. Label matching is case-insensitive and whitespace-tolerant, so the
/// raw `charset=` value from the header can be passed straight in.
fn encoding_for_label(label: &str) -> Option<&'static encoding_rs::Encoding> {
    encoding_rs::Encoding::for_label(label.as_bytes())
}

/// Decode a body, replacing malformed sequences with U+FFFD.
///
/// Lossy rather than fatal, matching `requests` and `httpx`: a body is remote
/// input, and one bad byte in the middle of a page should not cost the caller
/// the entire response. `content` is there when the exact bytes matter.
///
/// A BOM is stripped, and it wins over a charset the header declared — the
/// WHATWG Encoding Standard's rule, and therefore what browsers do. Both halves
/// are deliberate, and both go further than `requests` and `httpx`, which strip
/// nothing and always let the header win:
///
/// - stripping keeps an invisible U+FEFF out of the string, where it silently
///   defeats `json.loads`, `startswith` and equality. `requests.json()` fails
///   outright on a BOM-prefixed UTF-8 body for exactly this reason;
/// - overriding is almost always right, because a UTF-8 BOM read under the
///   declared charset is garbage no real document starts with, so its presence
///   says the body is UTF-8 and the header is wrong.
///
/// `decode_with_bom_removal` would strip only a BOM that agrees with the header,
/// and `decode_without_bom_handling` would match the other two clients; the
/// browser rule is the choice here.
fn decode_body(encoding: &'static encoding_rs::Encoding, body: &[u8]) -> String {
    let (text, _, _) = encoding.decode(body);
    text.into_owned()
}

/// The decoder for a charset the response declared, or UTF-8 without one.
///
/// A label the server made up is remote data, not a caller mistake, so it
/// falls back to UTF-8 rather than denying access to the body.
fn declared_decoder(declared: Option<&str>) -> &'static encoding_rs::Encoding {
    declared
        .and_then(encoding_for_label)
        .unwrap_or(encoding_rs::UTF_8)
}

/// Decode with a codec the *caller* named through `encoding=`.
///
/// That is a Python programmer naming a codec, so it goes to Python's codec
/// registry rather than the WHATWG table (see `Response.text`). An unknown
/// codec raises `LookupError`, which is what `bytes.decode` itself raises for
/// the same mistake.
fn decode_with_codec<'py>(
    py: Python<'py>,
    body: &[u8],
    codec: &str,
) -> PyResult<Bound<'py, PyString>> {
    PyBytes::new(py, body)
        .call_method1("decode", (codec, "replace"))?
        .downcast_into()
        .map_err(Into::into)
}

/// `text()` for a body read in one piece: `encoding=` when the caller gave
/// one, otherwise the declared charset. Shared by both streaming responses so
/// they decode exactly like `Response.text()`.
fn decode_text<'py>(
    py: Python<'py>,
    body: &[u8],
    declared: Option<&str>,
    encoding: Option<&str>,
) -> PyResult<Bound<'py, PyString>> {
    match encoding {
        Some(codec) => decode_with_codec(py, body, codec),
        None => Ok(PyString::new(
            py,
            &decode_body(declared_decoder(declared), body),
        )),
    }
}

fn parse_encoding(headers: &[(String, String)]) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("content-type") {
            for part in v.split(';') {
                let part = part.trim();
                if let Some(charset) = part.strip_prefix("charset=") {
                    return Some(charset.trim_matches('"').trim().to_string());
                }
            }
        }
    }
    None
}

#[pyclass(name = "Response")]
pub struct PyResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    url: String,
    version: PyHttpVersion,
    cookies: Vec<(String, String)>,
    content_length: Option<u64>,
    body: Bytes,
    encoding: Option<String>,
    elapsed: f64,
    history: Vec<PyRedirectRecord>,
    diagnostics: lkrequest::diagnostics::RequestDiagnostics,
    cached_text: OnceLock<String>,
    cached_json: OnceLock<Py<PyAny>>,
    // Only read by the buffer-protocol surface (see the cfg-gated impl block
    // below); abi3 builds omit that block, so the field is intentionally dead
    // there.
    #[cfg_attr(Py_LIMITED_API, allow(dead_code))]
    body_shape: [isize; 1],
}

impl PyResponse {
    pub fn from_response(
        resp: lkrequest::Response,
        elapsed: f64,
        diagnostics: lkrequest::diagnostics::RequestDiagnostics,
    ) -> PyResult<Self> {
        let status_code = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let url = resp.url().to_string();
        let version = PyHttpVersion::from(resp.version());
        let cookies: Vec<(String, String)> = resp
            .cookies()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let content_length = resp.content_length();
        let encoding = parse_encoding(&headers);
        let history: Vec<PyRedirectRecord> = resp
            .redirect_history()
            .iter()
            .map(PyRedirectRecord::from_rust)
            .collect();
        let body = resp.into_bytes();
        let body_shape = [body.len() as isize];

        Ok(PyResponse {
            status_code,
            headers,
            url,
            version,
            cookies,
            content_length,
            body,
            encoding,
            elapsed,
            history,
            diagnostics,
            cached_text: OnceLock::new(),
            cached_json: OnceLock::new(),
            body_shape,
        })
    }
}

#[pymethods]
impl PyResponse {
    #[getter]
    fn status_code(&self) -> u16 {
        self.status_code
    }

    #[getter]
    fn url(&self) -> &str {
        &self.url
    }

    #[getter]
    fn version(&self) -> PyHttpVersion {
        self.version
    }

    #[getter]
    fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    #[getter]
    fn headers(&self) -> PyHeaderMap {
        PyHeaderMap {
            entries: self.headers.clone(),
        }
    }

    #[getter]
    fn headers_list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let items: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        PyList::new(py, items)
    }

    #[getter]
    fn cookies<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (k, v) in &self.cookies {
            dict.set_item(k, v)?;
        }
        Ok(dict)
    }

    #[getter]
    fn encoding<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyString>> {
        self.encoding.as_ref().map(|e| PyString::new(py, e))
    }

    #[getter]
    fn elapsed(&self) -> f64 {
        self.elapsed
    }

    #[getter]
    fn history(&self) -> Vec<PyRedirectRecord> {
        self.history.clone()
    }

    /// Per-request timing/transport diagnostics: dns_ms, tcp_ms, tls_ms,
    /// ttfb_ms, total_ms (int milliseconds or None), plus remote_addr, protocol,
    /// cipher_suite (str or None). Fields are None when the phase was not
    /// measured (e.g. a reused connection skips DNS/TCP/TLS).
    #[getter]
    fn diagnostics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        let diag = &self.diagnostics;
        d.set_item("dns_ms", diag.dns_ms)?;
        d.set_item("tcp_ms", diag.tcp_ms)?;
        d.set_item("tls_ms", diag.tls_ms)?;
        d.set_item("ttfb_ms", diag.ttfb_ms)?;
        d.set_item("total_ms", diag.total_ms)?;
        d.set_item("remote_addr", diag.remote_addr.clone())?;
        d.set_item("protocol", diag.protocol.clone())?;
        d.set_item("cipher_suite", diag.cipher_suite.clone())?;
        Ok(d)
    }

    /// Decode the body as text.
    ///
    /// The charset comes from `Content-Type` (the same value `encoding`
    /// reports) and falls back to UTF-8 when the response declares none.
    /// `encoding=` overrides both, for servers that omit the charset or state
    /// the wrong one.
    ///
    /// The two paths deliberately consult different authorities. A charset out
    /// of a header is a *web* label, so it is resolved against the WHATWG
    /// Encoding Standard — the set browsers implement, which is the behaviour
    /// this library exists to reproduce. An `encoding=` argument is a *Python
    /// caller* naming a codec, so it goes to Python's codec registry: a
    /// Python programmer reaches for `latin-1`, `utf-8-sig` or `cp936`, none of
    /// which the web standard lists, and being refused those would make the
    /// argument useless for the job it is here to do.
    ///
    /// The result is cached, except when `encoding=` is given — that decode is
    /// one-off and neither reads nor fills the cache.
    #[pyo3(signature = (encoding=None))]
    fn text<'py>(&self, py: Python<'py>, encoding: Option<&str>) -> PyResult<Bound<'py, PyString>> {
        if let Some(codec) = encoding {
            return decode_with_codec(py, &self.body, codec);
        }

        if let Some(cached) = self.cached_text.get() {
            return Ok(PyString::new(py, cached));
        }
        let text = decode_body(declared_decoder(self.encoding.as_deref()), &self.body);
        let decoded = PyString::new(py, &text);
        let _ = self.cached_text.set(text);
        Ok(decoded)
    }

    /// Parse the body as JSON (cached after the first call).
    ///
    /// Raises `JsonDecodeError` when the body is not JSON. That class is both a
    /// `RequestError` and a `json.JSONDecodeError`, so either `except` catches
    /// it.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(cached) = self.cached_json.get() {
            return Ok(cached.bind(py).clone());
        }
        let text = self.text(py, None)?;
        let json_mod = py.import("json")?;
        let result = json_mod
            .call_method1("loads", (text,))
            .map_err(|e| crate::error::to_json_py_err(py, e))?;
        let _ = self.cached_json.set(result.clone().unbind());
        Ok(result)
    }

    #[getter]
    fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body)
    }

    fn error_for_status(&self) -> PyResult<()> {
        if self.status_code >= 400 {
            Err(crate::error::HttpStatusError::new_err(format!(
                "{} for url: {}",
                self.status_code, self.url
            )))
        } else {
            Ok(())
        }
    }

    #[getter]
    fn ok(&self) -> bool {
        self.status_code < 400
    }

    #[getter]
    fn was_redirected(&self) -> bool {
        !self.history.is_empty()
    }

    fn __repr__(&self) -> String {
        format!("<Response [{}]>", self.status_code)
    }

    fn __bool__(&self) -> bool {
        self.status_code < 400
    }

    fn __len__(&self) -> usize {
        self.body.len()
    }
}

/// Zero-copy buffer-protocol surface — gated out of `abi3` builds because the
/// limited Python ABI does not expose the raw `Py_buffer`/`PyBUF_*` FFI. abi3
/// wheels still expose the body via `.content` / `bytes(resp)`, only without
/// the zero-copy `memoryview(resp)` fast path. Lives in its own `#[pymethods]`
/// block (enabled by the `multiple-pymethods` pyo3 feature) so the entire
/// block — including macro-generated trampolines — disappears in `abi3`.
#[cfg(not(Py_LIMITED_API))]
#[pymethods]
impl PyResponse {
    /// # Safety
    ///
    /// This relies on PyO3's buffer protocol trampoline to set `view->obj`
    /// to `self` with an incremented refcount, ensuring `self.body` and
    /// `self.body_shape` remain valid for the lifetime of the buffer view.
    unsafe fn __getbuffer__(
        &self,
        view: *mut pyo3::ffi::Py_buffer,
        flags: std::os::raw::c_int,
    ) -> PyResult<()> {
        if view.is_null() {
            return Err(pyo3::exceptions::PyBufferError::new_err("null Py_buffer"));
        }
        if (flags & pyo3::ffi::PyBUF_WRITABLE) != 0 {
            return Err(pyo3::exceptions::PyBufferError::new_err(
                "Response buffer is read-only",
            ));
        }

        (*view).buf = self.body.as_ptr() as *mut std::os::raw::c_void;
        (*view).len = self.body.len() as isize;
        (*view).readonly = 1;
        (*view).itemsize = 1;
        (*view).ndim = 1;
        (*view).format = if (flags & pyo3::ffi::PyBUF_FORMAT) != 0 {
            b"B\0".as_ptr() as *mut std::os::raw::c_char
        } else {
            std::ptr::null_mut()
        };
        (*view).shape = self.body_shape.as_ptr() as *mut isize;
        (*view).strides = std::ptr::null_mut();
        (*view).suboffsets = std::ptr::null_mut();
        (*view).internal = std::ptr::null_mut();

        Ok(())
    }

    unsafe fn __releasebuffer__(&self, _view: *mut pyo3::ffi::Py_buffer) {}
}

// ---------------------------------------------------------------------------
// StreamingResponse — uses Arc<Mutex> so chunk() can be called repeatedly
// ---------------------------------------------------------------------------

#[pyclass(name = "StreamingResponse")]
pub struct PyStreamingResponse {
    pub(crate) status_code: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) inner: Arc<Mutex<Option<lkrequest::StreamingResponse>>>,
}

impl PyStreamingResponse {
    pub fn new(resp: lkrequest::StreamingResponse) -> Self {
        let status_code = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        PyStreamingResponse {
            status_code,
            headers,
            inner: Arc::new(Mutex::new(Some(resp))),
        }
    }
}

#[pymethods]
impl PyStreamingResponse {
    #[getter]
    fn status_code(&self) -> u16 {
        self.status_code
    }

    #[getter]
    fn headers(&self) -> PyHeaderMap {
        PyHeaderMap {
            entries: self.headers.clone(),
        }
    }

    fn chunk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let stream = guard.as_mut().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
            })?;
            match stream.chunk().await {
                Ok(Some(chunk)) => Ok(Some(chunk.to_vec())),
                Ok(None) => {
                    *guard = None;
                    Ok(None::<Vec<u8>>)
                }
                Err(e) => Err(crate::error::to_py_err(e)),
            }
        })
    }

    fn chunk_decoded<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let stream = guard.as_mut().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
            })?;
            match stream.chunk_decoded().await {
                Ok(Some(chunk)) => Ok(Some(chunk.to_vec())),
                Ok(None) => {
                    *guard = None;
                    Ok(None::<Vec<u8>>)
                }
                Err(e) => Err(crate::error::to_py_err(e)),
            }
        })
    }

    fn bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let stream = guard.take().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
            })?;
            match stream.bytes().await {
                Ok(data) => Python::with_gil(|py| Ok(PyBytes::new(py, &data).unbind())),
                Err(e) => Err(crate::error::to_py_err(e)),
            }
        })
    }

    /// Read the rest of the body and decode it exactly like `Response.text()`:
    /// the charset `Content-Type` declares (UTF-8 without one), or the codec
    /// named by `encoding=`, with malformed bytes replaced by U+FFFD.
    #[pyo3(signature = (encoding=None))]
    fn text<'py>(&self, py: Python<'py>, encoding: Option<String>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let declared = parse_encoding(&self.headers);
        crate::bridge::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let stream = guard.take().ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
            })?;
            let body = stream.bytes().await.map_err(crate::error::to_py_err)?;
            Python::with_gil(|py| {
                decode_text(py, &body, declared.as_deref(), encoding.as_deref()).map(Bound::unbind)
            })
        })
    }

    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let stream = match guard.as_mut() {
                Some(s) => s,
                None => return Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            };
            match stream.chunk().await {
                Ok(Some(chunk)) => Ok(chunk.to_vec()),
                Ok(None) => {
                    *guard = None;
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
                Err(e) => Err(crate::error::to_py_err(e)),
            }
        })
    }

    fn __repr__(&self) -> String {
        format!("<StreamingResponse [{}]>", self.status_code)
    }
}

// ---------------------------------------------------------------------------
// BlockingStreamingResponse — synchronous counterpart for the blocking API
// ---------------------------------------------------------------------------

/// Synchronous streaming response returned by `BlockingSession.send_streaming`.
///
/// Mirrors `StreamingResponse` but drives the underlying async stream on the
/// shared blocking runtime so the body can be consumed from synchronous code
/// (`stream.bytes()`, `for chunk in stream:`), without an event loop.
#[pyclass(name = "BlockingStreamingResponse")]
pub struct PyBlockingStreamingResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    inner: Arc<Mutex<Option<lkrequest::StreamingResponse>>>,
}

impl PyBlockingStreamingResponse {
    pub fn new(resp: lkrequest::StreamingResponse) -> Self {
        let status_code = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        PyBlockingStreamingResponse {
            status_code,
            headers,
            inner: Arc::new(Mutex::new(Some(resp))),
        }
    }
}

#[pymethods]
impl PyBlockingStreamingResponse {
    #[getter]
    fn status_code(&self) -> u16 {
        self.status_code
    }

    #[getter]
    fn headers(&self) -> PyHeaderMap {
        PyHeaderMap {
            entries: self.headers.clone(),
        }
    }

    fn chunk<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let inner = self.inner.clone();
        let chunk = py.allow_threads(|| {
            crate::client::blocking_runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let stream = guard.as_mut().ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
                })?;
                match stream.chunk().await {
                    Ok(Some(c)) => Ok(Some(c.to_vec())),
                    Ok(None) => {
                        *guard = None;
                        Ok(None)
                    }
                    Err(e) => Err(crate::error::to_py_err(e)),
                }
            })
        })?;
        Ok(chunk.map(|c| PyBytes::new(py, &c)))
    }

    fn chunk_decoded<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let inner = self.inner.clone();
        let chunk = py.allow_threads(|| {
            crate::client::blocking_runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let stream = guard.as_mut().ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
                })?;
                match stream.chunk_decoded().await {
                    Ok(Some(c)) => Ok(Some(c.to_vec())),
                    Ok(None) => {
                        *guard = None;
                        Ok(None)
                    }
                    Err(e) => Err(crate::error::to_py_err(e)),
                }
            })
        })?;
        Ok(chunk.map(|c| PyBytes::new(py, &c)))
    }

    fn bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner.clone();
        let data = py.allow_threads(|| {
            crate::client::blocking_runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let stream = guard.take().ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
                })?;
                stream.bytes().await.map_err(crate::error::to_py_err)
            })
        })?;
        Ok(PyBytes::new(py, &data))
    }

    /// Read the rest of the body and decode it exactly like `Response.text()`:
    /// the charset `Content-Type` declares (UTF-8 without one), or the codec
    /// named by `encoding=`, with malformed bytes replaced by U+FFFD.
    #[pyo3(signature = (encoding=None))]
    fn text<'py>(&self, py: Python<'py>, encoding: Option<&str>) -> PyResult<Bound<'py, PyString>> {
        let inner = self.inner.clone();
        let body = py.allow_threads(|| {
            crate::client::blocking_runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let stream = guard.take().ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err("Stream already consumed")
                })?;
                stream.bytes().await.map_err(crate::error::to_py_err)
            })
        })?;
        decode_text(
            py,
            &body,
            parse_encoding(&self.headers).as_deref(),
            encoding,
        )
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner.clone();
        let chunk = py.allow_threads(|| {
            crate::client::blocking_runtime().block_on(async move {
                let mut guard = inner.lock().await;
                let stream = match guard.as_mut() {
                    Some(s) => s,
                    None => return Err(pyo3::exceptions::PyStopIteration::new_err(())),
                };
                match stream.chunk().await {
                    Ok(Some(c)) => Ok(c.to_vec()),
                    Ok(None) => {
                        *guard = None;
                        Err(pyo3::exceptions::PyStopIteration::new_err(()))
                    }
                    Err(e) => Err(crate::error::to_py_err(e)),
                }
            })
        })?;
        Ok(PyBytes::new(py, &chunk))
    }

    fn __repr__(&self) -> String {
        format!("<BlockingStreamingResponse [{}]>", self.status_code)
    }
}
