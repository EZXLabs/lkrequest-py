//! Async `Session` and blocking `BlockingSession` pyclasses: stateful clients
//! that persist cookies and base configuration across requests and fire
//! request/response event hooks.

use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

use crate::client::blocking_runtime;
use crate::error::to_py_err;
use crate::multipart::PyMultipart;
use crate::priority::PyRequestPriority;
use crate::protocol::{PyHttpIntent, PyIdempotency, PyPreferredHttpVersion, PyProtocolPolicy};
use crate::response::PyResponse;
use crate::types::{serialize_json, validated_duration, PyAcceptEncoding, StrPairs};
use crate::websocket::{PyBlockingWsConnection, PyWsConnection};

// ---------------------------------------------------------------------------
// Event Hooks
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub(crate) struct EventHooks {
    pub request_hooks: Arc<std::sync::Mutex<Vec<Py<PyAny>>>>,
    pub response_hooks: Arc<std::sync::Mutex<Vec<Py<PyAny>>>>,
}

impl EventHooks {
    fn fire_request(&self, method: &str, url: &str, headers: &Option<Vec<(String, String)>>) {
        Python::with_gil(|py| {
            let hooks: Vec<Py<PyAny>> = {
                let guard = match self.request_hooks.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                if guard.is_empty() {
                    return;
                }
                guard.iter().map(|h| h.clone_ref(py)).collect()
            };
            let headers_val: HashMap<String, String> =
                headers.clone().unwrap_or_default().into_iter().collect();
            for hook in &hooks {
                if let Err(e) = hook.call1(py, (method, url, &headers_val)) {
                    tracing::warn!(error = %e, "event_hook.on_request failed");
                }
            }
        });
    }

    fn fire_response(&self, status_code: u16, url: &str, elapsed: f64) {
        Python::with_gil(|py| {
            let hooks: Vec<Py<PyAny>> = {
                let guard = match self.response_hooks.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                if guard.is_empty() {
                    return;
                }
                guard.iter().map(|h| h.clone_ref(py)).collect()
            };
            for hook in &hooks {
                if let Err(e) = hook.call1(py, (status_code, url, elapsed)) {
                    tracing::warn!(error = %e, "event_hook.on_response failed");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Shared request-building logic
// ---------------------------------------------------------------------------

struct PreparedRequest {
    method: String,
    url: String,
    headers: Option<Vec<(String, String)>>,
    params: Option<Vec<(String, String)>>,
    json_body: Option<String>,
    form_data: Option<Vec<(String, String)>>,
    raw_body: Option<Vec<u8>>,
    cookies: Option<HashMap<String, String>>,
    cookie_overrides: Option<HashMap<String, String>>,
    timeout: Option<f64>,
    bearer_auth: Option<String>,
    basic_auth: Option<(String, Option<String>)>,
    multipart: Option<lkrequest::multipart::Multipart>,
    proxy: Option<String>,
    no_auto_decompress: bool,
    accept_encoding: Option<lkrequest::AcceptEncoding>,
    opts: RequestOpts,
}

/// Advanced, optional per-request settings threaded as a single bundle so new
/// options can be added without re-threading every HTTP method signature.
#[derive(Default)]
struct RequestOpts {
    priority: Option<lkh2::RequestPriority>,
    preferred_http_version: Option<lkrequest::PreferredHttpVersion>,
    idempotency: Option<lkrequest::Idempotency>,
    header_order: Option<Vec<String>>,
    cookie_order: Option<Vec<String>>,
    h3_header_order: Option<Vec<String>>,
    protocol_policy: Option<lkrequest::ProtocolPolicy>,
    http_intent: Option<lkrequest::HttpIntent>,
}

/// Apply a [`PreparedRequest`]'s options to a fresh `RequestBuilder` (method
/// dispatch, headers, params, cookies, auth, body, timeout, proxy, …) and
/// return it ready to send. Shared by the buffered (`execute_request`) and
/// streaming (`send_streaming`) paths so the two cannot drift in which options
/// they honor.
fn apply_request_options(
    session: &lkrequest::Session,
    req: PreparedRequest,
) -> PyResult<lkrequest::session::RequestBuilder> {
    let mut rb = match req.method.as_str() {
        "GET" => session.get(&req.url),
        "POST" => session.post(&req.url),
        "PUT" => session.put(&req.url),
        "DELETE" => session.delete(&req.url),
        "HEAD" => session.head(&req.url),
        "PATCH" => session.patch(&req.url),
        "OPTIONS" => session.options(&req.url),
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unsupported HTTP method: {}",
                other
            )))
        }
    };

    if let Some(h) = req.headers {
        for (k, v) in h {
            rb = rb.header(&k, &v);
        }
    }
    if let Some(p) = req.params {
        let refs: Vec<(&str, &str)> = p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        rb = rb.query(&refs);
    }
    if let Some(c) = req.cookies {
        for (k, v) in c {
            rb = rb.cookie(&k, &v);
        }
    }
    if let Some(co) = req.cookie_overrides {
        for (k, v) in co {
            rb = rb.cookie_override(&k, &v);
        }
    }
    if let Some(token) = req.bearer_auth {
        rb = rb.bearer_auth(&token);
    }
    if let Some((user, pass)) = req.basic_auth {
        rb = rb.basic_auth(&user, pass.as_deref());
    }
    if let Some(t) = req.timeout {
        rb = rb.timeout(validated_duration(t)?);
    }
    if let Some(proxy_url) = req.proxy {
        rb = rb.proxy(&proxy_url);
    }
    if req.no_auto_decompress {
        rb = rb.no_auto_decompress();
    }
    if let Some(ae) = req.accept_encoding {
        rb = rb.accept_encoding(ae);
    }
    if let Some(priority) = req.opts.priority {
        rb = rb.priority(priority);
    }
    if let Some(version) = req.opts.preferred_http_version {
        rb = rb.preferred_http_version(version);
    }
    if let Some(idempotency) = req.opts.idempotency {
        rb = rb.idempotency(idempotency);
    }
    if let Some(order) = req.opts.header_order {
        let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        rb = rb.header_order(refs);
    }
    if let Some(order) = req.opts.cookie_order {
        let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        rb = rb.cookie_order(refs);
    }
    if let Some(order) = req.opts.h3_header_order {
        let refs: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        rb = rb.h3_header_order(refs);
    }
    if let Some(policy) = req.opts.protocol_policy {
        rb = rb.protocol_policy(policy);
    }
    if let Some(intent) = req.opts.http_intent {
        rb = rb.http_intent(intent);
    }

    if let Some(json_str) = req.json_body {
        rb = rb.header("content-type", "application/json");
        rb = rb.body(json_str.into_bytes());
    } else if let Some(form) = req.form_data {
        rb = rb.form(&form);
    } else if let Some(mp) = req.multipart {
        rb = rb.multipart(mp);
    } else if let Some(body) = req.raw_body {
        rb = rb.body(body);
    }

    Ok(rb)
}

async fn execute_request(
    session: lkrequest::Session,
    req: PreparedRequest,
    hooks: EventHooks,
) -> PyResult<PyResponse> {
    hooks.fire_request(&req.method, &req.url, &req.headers);

    tracing::debug!(
        method = %req.method,
        url = %req.url,
        has_body = req.json_body.is_some() || req.form_data.is_some() || req.raw_body.is_some() || req.multipart.is_some(),
        proxy = ?req.proxy,
        "sending request"
    );

    let method_for_log = req.method.clone();
    let url_for_log = req.url.clone();
    let rb = apply_request_options(&session, req)?;

    let start = tokio::time::Instant::now();
    let (send_result, diagnostics) =
        lkrequest::diagnostics::capture_request_diagnostics(rb.send()).await;
    let resp = match send_result {
        Ok(r) => r,
        Err(e) => {
            let elapsed = start.elapsed().as_secs_f64();
            tracing::error!(
                method = %method_for_log,
                url = %url_for_log,
                elapsed_ms = format_args!("{:.1}", elapsed * 1000.0),
                error = %e,
                "request failed"
            );
            return Err(to_py_err(e));
        }
    };
    let elapsed = start.elapsed().as_secs_f64();
    let url = resp.url().to_string();
    let status_code = resp.status().as_u16();
    let body_size = resp.bytes().len() as u64;
    let is_error = status_code >= 400;

    tracing::debug!(
        method = %method_for_log,
        url = %url,
        status = status_code,
        elapsed_ms = format_args!("{:.1}", elapsed * 1000.0),
        body_bytes = body_size,
        "response received"
    );

    let py_resp = PyResponse::from_response(resp, elapsed, diagnostics)?;

    crate::metrics::record_global_metrics(&url, elapsed, body_size, is_error);
    hooks.fire_response(status_code, &url, elapsed);

    Ok(py_resp)
}

fn validate_body_params(
    json: &Option<String>,
    data: &Option<Vec<(String, String)>>,
    body: &Option<Vec<u8>>,
    multipart: &Option<lkrequest::multipart::Multipart>,
) -> PyResult<()> {
    let count = json.is_some() as u8
        + data.is_some() as u8
        + body.is_some() as u8
        + multipart.is_some() as u8;
    if count > 1 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Cannot specify more than one of: json, data, body, multipart",
        ));
    }
    Ok(())
}

/// Resolve a (possibly relative) request URL against the session's optional
/// `base_url`, using RFC 3986 join semantics (the same as `url::Url::join`).
///
/// A URL that parses on its own (e.g. `https://other/x`) is treated as absolute
/// and used as-is, so a request can always override the base. A relative URL is
/// joined onto the base. Note the standard RFC rules this implies: a `base_url`
/// **without** a trailing slash drops its last path segment, and a relative URL
/// beginning with `/` replaces the base's path entirely — so prefer a host-only
/// base (`https://api.example.com`) or one ending in `/`, and relative paths
/// like `users`. If joining fails the original string is returned so the
/// downstream request surfaces a clear error.
fn resolve_base_url(base: &Option<String>, url: &str) -> String {
    match base {
        Some(b) if url::Url::parse(url).is_err() => {
            match url::Url::parse(b).and_then(|bu| bu.join(url)) {
                Ok(joined) => joined.to_string(),
                Err(_) => url.to_string(),
            }
        }
        _ => url.to_string(),
    }
}

fn extract_multipart(
    py: Python<'_>,
    multipart: Option<Py<PyMultipart>>,
) -> Option<lkrequest::multipart::Multipart> {
    match multipart {
        Some(mp_ref) => {
            let mut guard = mp_ref.borrow_mut(py);
            Some(std::mem::replace(
                &mut guard.inner,
                lkrequest::multipart::Multipart::new(),
            ))
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Async Session
// ---------------------------------------------------------------------------

#[pyclass(name = "Session")]
#[derive(Clone)]
pub struct PySession {
    pub(crate) inner: lkrequest::Session,
    pub(crate) hooks: EventHooks,
    pub(crate) base_url: Option<String>,
}

impl PySession {
    fn make_request<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json_body: Option<String>,
        form_data: Option<StrPairs>,
        raw_body: Option<Vec<u8>>,
        cookies: Option<HashMap<String, String>>,
        cookie_overrides: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        multipart: Option<lkrequest::multipart::Multipart>,
        proxy: Option<String>,
        no_auto_decompress: bool,
        accept_encoding: Option<lkrequest::AcceptEncoding>,
        opts: RequestOpts,
    ) -> PyResult<Bound<'py, PyAny>> {
        let headers = headers.map(|p| p.0);
        let params = params.map(|p| p.0);
        let form_data = form_data.map(|p| p.0);
        let url = resolve_base_url(&self.base_url, &url);
        validate_body_params(&json_body, &form_data, &raw_body, &multipart)?;
        let session = self.inner.clone();
        let hooks = self.hooks.clone();
        let prepared = PreparedRequest {
            method: method.to_string(),
            url,
            headers,
            params,
            json_body,
            form_data,
            raw_body,
            cookies,
            cookie_overrides,
            timeout,
            bearer_auth,
            basic_auth,
            multipart,
            proxy,
            no_auto_decompress,
            accept_encoding,
            opts,
        };
        crate::bridge::future_into_py(py, async move {
            execute_request(session, prepared, hooks).await
        })
    }
}

#[pymethods]
impl PySession {
    // --- HTTP Methods -------------------------------------------------------

    #[pyo3(signature = (url, *, headers=None, params=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.make_request(
            py,
            "GET",
            url,
            headers,
            params,
            None,
            None,
            None,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn post<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'py, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_request(
            py,
            "POST",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (method, url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn request<'py>(
        &self,
        py: Python<'py>,
        method: String,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'py, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_request(
            py,
            &method.to_uppercase(),
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn put<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'py, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_request(
            py,
            "PUT",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn delete<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'py, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_str = serialize_json(py, json)?;
        self.make_request(
            py,
            "DELETE",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn head<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.make_request(
            py,
            "HEAD",
            url,
            headers,
            params,
            None,
            None,
            None,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            false,
            None,
            RequestOpts {
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
                ..Default::default()
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn patch<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'py, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_request(
            py,
            "PATCH",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn options<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.make_request(
            py,
            "OPTIONS",
            url,
            headers,
            params,
            None,
            None,
            None,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            false,
            None,
            RequestOpts {
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
                ..Default::default()
            },
        )
    }

    // --- Pool Stats ----------------------------------------------------------

    fn pool_stats(&self) -> crate::types::PyPoolStats {
        crate::types::PyPoolStats::from(self.inner.pool_stats())
    }

    fn pool_clear(&self) {
        self.inner.pool_clear();
    }

    // --- WebSocket -----------------------------------------------------------

    #[pyo3(signature = (url, *, headers=None, protocols=None))]
    fn ws_connect<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<StrPairs>,
        protocols: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let mut builder = session.websocket(&url);
            if let Some(h) = headers {
                for (k, v) in h.0 {
                    builder = builder.header(&k, &v);
                }
            }
            if let Some(protos) = protocols {
                for p in protos {
                    builder = builder.protocol(&p);
                }
            }
            let conn = builder.connect().await.map_err(to_py_err)?;
            Ok(PyWsConnection::new(conn))
        })
    }

    // --- Cookie Management --------------------------------------------------

    fn set_cookie(&self, url: &str, name: &str, value: &str) {
        self.inner.set_cookie(url, name, value);
    }

    #[pyo3(signature = (url, name, value, *, path=None, domain=None, secure=false, http_only=false))]
    fn set_cookie_with_attrs(
        &self,
        url: &str,
        name: &str,
        value: &str,
        path: Option<&str>,
        domain: Option<&str>,
        secure: bool,
        http_only: bool,
    ) {
        self.inner
            .set_cookie_with_attrs(url, name, value, path, domain, secure, http_only);
    }

    fn set_cookie_raw(&self, url: &str, set_cookie_header: &str) {
        self.inner.set_cookie_raw(url, set_cookie_header);
    }

    fn get_cookie(&self, url: &str, name: &str) -> Option<String> {
        self.inner.get_cookie(url, name)
    }

    fn get_cookies(&self, url: &str) -> Vec<(String, String)> {
        self.inner.get_cookies(url)
    }

    fn remove_cookie(&self, url: &str, name: &str) {
        self.inner.remove_cookie(url, name);
    }

    fn get_cookie_values(&self, url: &str, name: &str) -> Vec<String> {
        self.inner.get_cookie_values(url, name)
    }

    fn cookie_header(&self, url: &str) -> Option<String> {
        self.inner.cookie_header(url)
    }

    fn clear_cookies(&self) {
        self.inner.clear_cookies();
    }

    // --- Connection Preconnect -----------------------------------------------

    fn preconnect<'py>(&self, py: Python<'py>, url: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            session.preconnect(&url).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn preconnect_many<'py>(
        &self,
        py: Python<'py>,
        urls: Vec<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
            let results = session.preconnect_many(&url_refs).await;
            Python::with_gil(|py| {
                let list: Vec<Py<pyo3::types::PyDict>> = results
                    .into_iter()
                    .zip(urls.iter())
                    .map(|(r, url)| {
                        let dict = pyo3::types::PyDict::new(py);
                        dict.set_item("url", url)?;
                        dict.set_item("success", r.is_ok())?;
                        dict.set_item("error", r.err().map(|e| e.to_string()))?;
                        Ok(dict.unbind())
                    })
                    .collect::<PyResult<_>>()?;
                Ok(list)
            })
        })
    }

    // --- Connection Prefetch -------------------------------------------------

    fn prefetch<'py>(&self, py: Python<'py>, urls: Vec<String>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        crate::bridge::future_into_py(py, async move {
            let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
            let results = session.prefetch(&url_refs).await;
            Python::with_gil(|py| {
                let list: Vec<Py<pyo3::types::PyDict>> = results
                    .iter()
                    .map(|r| {
                        let dict = pyo3::types::PyDict::new(py);
                        dict.set_item("url", &r.url)?;
                        dict.set_item("success", r.success)?;
                        dict.set_item("duration_ms", r.duration.as_secs_f64() * 1000.0)?;
                        dict.set_item("error", r.error.as_deref())?;
                        Ok(dict.unbind())
                    })
                    .collect::<PyResult<_>>()?;
                Ok(list)
            })
        })
    }

    // --- Streaming -----------------------------------------------------------

    #[pyo3(signature = (method, url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, accept_encoding=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    #[allow(clippy::too_many_arguments)]
    fn send_streaming<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'py, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        accept_encoding: Option<PyAcceptEncoding>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        let headers = headers.map(|p| p.0);
        let params = params.map(|p| p.0);
        let data = data.map(|p| p.0);
        let url = resolve_base_url(&self.base_url, &url);
        validate_body_params(&json_str, &data, &body, &mp)?;
        let session = self.inner.clone();
        let prepared = PreparedRequest {
            method: method.to_string(),
            url,
            headers,
            params,
            json_body: json_str,
            form_data: data,
            raw_body: body,
            cookies,
            cookie_overrides: cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            multipart: mp,
            proxy,
            no_auto_decompress: false,
            accept_encoding: accept_encoding.map(|a| a.inner),
            opts: RequestOpts {
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
                ..Default::default()
            },
        };
        crate::bridge::future_into_py(py, async move {
            let rb = apply_request_options(&session, prepared)?;
            let resp = rb.send_streaming().await.map_err(to_py_err)?;
            Ok(crate::response::PyStreamingResponse::new(resp))
        })
    }

    // --- Event Hooks ---------------------------------------------------------

    fn on_request(&self, callback: Py<PyAny>) -> PyResult<()> {
        self.hooks
            .request_hooks
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
            .push(callback);
        Ok(())
    }

    fn on_response(&self, callback: Py<PyAny>) -> PyResult<()> {
        self.hooks
            .response_hooks
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
            .push(callback);
        Ok(())
    }

    fn __repr__(&self) -> String {
        "<Session>".to_string()
    }
}

// ---------------------------------------------------------------------------
// Blocking Session
// ---------------------------------------------------------------------------

#[pyclass(name = "BlockingSession")]
#[derive(Clone)]
pub struct PyBlockingSession {
    pub(crate) inner: lkrequest::Session,
    pub(crate) hooks: EventHooks,
    pub(crate) base_url: Option<String>,
}

impl PyBlockingSession {
    fn make_blocking_request(
        &self,
        py: Python<'_>,
        method: &str,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json_body: Option<String>,
        form_data: Option<StrPairs>,
        raw_body: Option<Vec<u8>>,
        cookies: Option<HashMap<String, String>>,
        cookie_overrides: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        multipart: Option<lkrequest::multipart::Multipart>,
        proxy: Option<String>,
        no_auto_decompress: bool,
        accept_encoding: Option<lkrequest::AcceptEncoding>,
        opts: RequestOpts,
    ) -> PyResult<PyResponse> {
        let headers = headers.map(|p| p.0);
        let params = params.map(|p| p.0);
        let form_data = form_data.map(|p| p.0);
        let url = resolve_base_url(&self.base_url, &url);
        validate_body_params(&json_body, &form_data, &raw_body, &multipart)?;
        let session = self.inner.clone();
        let hooks = self.hooks.clone();
        let prepared = PreparedRequest {
            method: method.to_string(),
            url,
            headers,
            params,
            json_body,
            form_data,
            raw_body,
            cookies,
            cookie_overrides,
            timeout,
            bearer_auth,
            basic_auth,
            multipart,
            proxy,
            no_auto_decompress,
            accept_encoding,
            opts,
        };
        py.allow_threads(|| {
            blocking_runtime()
                .block_on(async move { execute_request(session, prepared, hooks).await })
        })
    }
}

#[pymethods]
impl PyBlockingSession {
    #[pyo3(signature = (url, *, headers=None, params=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn get(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        self.make_blocking_request(
            py,
            "GET",
            url,
            headers,
            params,
            None,
            None,
            None,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn post(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'_, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_blocking_request(
            py,
            "POST",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (method, url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn request(
        &self,
        py: Python<'_>,
        method: String,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'_, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_blocking_request(
            py,
            &method.to_uppercase(),
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn put(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'_, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_blocking_request(
            py,
            "PUT",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn delete(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'_, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        let json_str = serialize_json(py, json)?;
        self.make_blocking_request(
            py,
            "DELETE",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn head(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        self.make_blocking_request(
            py,
            "HEAD",
            url,
            headers,
            params,
            None,
            None,
            None,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            false,
            None,
            RequestOpts {
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
                ..Default::default()
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, no_decompress=false, accept_encoding=None, priority=None, preferred_http_version=None, idempotency=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn patch(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'_, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        no_decompress: bool,
        accept_encoding: Option<PyAcceptEncoding>,
        priority: Option<PyRequestPriority>,
        preferred_http_version: Option<PyPreferredHttpVersion>,
        idempotency: Option<PyIdempotency>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        self.make_blocking_request(
            py,
            "PATCH",
            url,
            headers,
            params,
            json_str,
            data,
            body,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            mp,
            proxy,
            no_decompress,
            accept_encoding.map(|a| a.inner),
            RequestOpts {
                priority: priority.map(|p| p.inner),
                preferred_http_version: preferred_http_version.map(Into::into),
                idempotency: idempotency.map(Into::into),
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
            },
        )
    }

    #[pyo3(signature = (url, *, headers=None, params=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    fn options(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<PyResponse> {
        self.make_blocking_request(
            py,
            "OPTIONS",
            url,
            headers,
            params,
            None,
            None,
            None,
            cookies,
            cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            None,
            proxy,
            false,
            None,
            RequestOpts {
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
                ..Default::default()
            },
        )
    }

    // --- Pool Stats ----------------------------------------------------------

    fn pool_stats(&self) -> crate::types::PyPoolStats {
        crate::types::PyPoolStats::from(self.inner.pool_stats())
    }

    fn pool_clear(&self) {
        self.inner.pool_clear();
    }

    // --- WebSocket -----------------------------------------------------------

    #[pyo3(signature = (url, *, headers=None, protocols=None))]
    fn ws_connect(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<StrPairs>,
        protocols: Option<Vec<String>>,
    ) -> PyResult<PyBlockingWsConnection> {
        let session = self.inner.clone();
        py.allow_threads(|| {
            blocking_runtime().block_on(async move {
                let mut builder = session.websocket(&url);
                if let Some(h) = headers {
                    for (k, v) in h.0 {
                        builder = builder.header(&k, &v);
                    }
                }
                if let Some(protos) = protocols {
                    for p in protos {
                        builder = builder.protocol(&p);
                    }
                }
                let conn = builder.connect().await.map_err(to_py_err)?;
                Ok(PyBlockingWsConnection::new(conn))
            })
        })
    }

    // --- Cookie Management --------------------------------------------------

    fn set_cookie(&self, url: &str, name: &str, value: &str) {
        self.inner.set_cookie(url, name, value);
    }

    #[pyo3(signature = (url, name, value, *, path=None, domain=None, secure=false, http_only=false))]
    fn set_cookie_with_attrs(
        &self,
        url: &str,
        name: &str,
        value: &str,
        path: Option<&str>,
        domain: Option<&str>,
        secure: bool,
        http_only: bool,
    ) {
        self.inner
            .set_cookie_with_attrs(url, name, value, path, domain, secure, http_only);
    }

    fn get_cookie(&self, url: &str, name: &str) -> Option<String> {
        self.inner.get_cookie(url, name)
    }

    fn get_cookies(&self, url: &str) -> Vec<(String, String)> {
        self.inner.get_cookies(url)
    }

    fn get_cookie_values(&self, url: &str, name: &str) -> Vec<String> {
        self.inner.get_cookie_values(url, name)
    }

    fn cookie_header(&self, url: &str) -> Option<String> {
        self.inner.cookie_header(url)
    }

    fn remove_cookie(&self, url: &str, name: &str) {
        self.inner.remove_cookie(url, name);
    }

    fn clear_cookies(&self) {
        self.inner.clear_cookies();
    }

    // --- Connection Preconnect -----------------------------------------------

    fn preconnect(&self, py: Python<'_>, url: String) -> PyResult<()> {
        let session = self.inner.clone();
        py.allow_threads(|| {
            blocking_runtime()
                .block_on(async move { session.preconnect(&url).await.map_err(to_py_err) })
        })
    }

    fn preconnect_many(
        &self,
        py: Python<'_>,
        urls: Vec<String>,
    ) -> PyResult<Vec<Py<pyo3::types::PyDict>>> {
        let session = self.inner.clone();
        py.allow_threads(|| {
            blocking_runtime().block_on(async move {
                let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
                let results = session.preconnect_many(&url_refs).await;
                Python::with_gil(|py| {
                    results
                        .into_iter()
                        .zip(urls.iter())
                        .map(|(r, url)| {
                            let dict = pyo3::types::PyDict::new(py);
                            dict.set_item("url", url)?;
                            dict.set_item("success", r.is_ok())?;
                            dict.set_item("error", r.err().map(|e| e.to_string()))?;
                            Ok(dict.unbind())
                        })
                        .collect::<PyResult<Vec<_>>>()
                })
            })
        })
    }

    // --- Connection Prefetch -------------------------------------------------

    fn prefetch(
        &self,
        py: Python<'_>,
        urls: Vec<String>,
    ) -> PyResult<Vec<Py<pyo3::types::PyDict>>> {
        let session = self.inner.clone();
        py.allow_threads(|| {
            blocking_runtime().block_on(async move {
                let url_refs: Vec<&str> = urls.iter().map(|s| s.as_str()).collect();
                let results = session.prefetch(&url_refs).await;
                Python::with_gil(|py| {
                    results
                        .iter()
                        .map(|r| {
                            let dict = pyo3::types::PyDict::new(py);
                            dict.set_item("url", &r.url)?;
                            dict.set_item("success", r.success)?;
                            dict.set_item("duration_ms", r.duration.as_secs_f64() * 1000.0)?;
                            dict.set_item("error", r.error.as_deref())?;
                            Ok(dict.unbind())
                        })
                        .collect::<PyResult<Vec<_>>>()
                })
            })
        })
    }

    // --- Streaming -----------------------------------------------------------

    #[pyo3(signature = (method, url, *, headers=None, params=None, json=None, data=None, body=None, multipart=None, cookies=None, cookie_override=None, timeout=None, bearer_auth=None, basic_auth=None, proxy=None, accept_encoding=None, header_order=None, cookie_order=None, h3_header_order=None, protocol_policy=None, http_intent=None))]
    #[allow(clippy::too_many_arguments)]
    fn send_streaming(
        &self,
        py: Python<'_>,
        method: &str,
        url: String,
        headers: Option<StrPairs>,
        params: Option<StrPairs>,
        json: Option<Bound<'_, PyAny>>,
        data: Option<StrPairs>,
        body: Option<Vec<u8>>,
        multipart: Option<Py<PyMultipart>>,
        cookies: Option<HashMap<String, String>>,
        cookie_override: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        bearer_auth: Option<String>,
        basic_auth: Option<(String, Option<String>)>,
        proxy: Option<String>,
        accept_encoding: Option<PyAcceptEncoding>,
        header_order: Option<Vec<String>>,
        cookie_order: Option<Vec<String>>,
        h3_header_order: Option<Vec<String>>,
        protocol_policy: Option<PyProtocolPolicy>,
        http_intent: Option<PyHttpIntent>,
    ) -> PyResult<crate::response::PyBlockingStreamingResponse> {
        let json_str = serialize_json(py, json)?;
        let mp = extract_multipart(py, multipart);
        let headers = headers.map(|p| p.0);
        let params = params.map(|p| p.0);
        let data = data.map(|p| p.0);
        let url = resolve_base_url(&self.base_url, &url);
        validate_body_params(&json_str, &data, &body, &mp)?;
        let session = self.inner.clone();
        let prepared = PreparedRequest {
            method: method.to_string(),
            url,
            headers,
            params,
            json_body: json_str,
            form_data: data,
            raw_body: body,
            cookies,
            cookie_overrides: cookie_override,
            timeout,
            bearer_auth,
            basic_auth,
            multipart: mp,
            proxy,
            no_auto_decompress: false,
            accept_encoding: accept_encoding.map(|a| a.inner),
            opts: RequestOpts {
                header_order,
                cookie_order,
                h3_header_order,
                protocol_policy: protocol_policy.map(|p| p.inner),
                http_intent: http_intent.map(|i| i.into()),
                ..Default::default()
            },
        };
        py.allow_threads(|| {
            blocking_runtime().block_on(async move {
                let rb = apply_request_options(&session, prepared)?;
                let resp = rb.send_streaming().await.map_err(to_py_err)?;
                Ok(crate::response::PyBlockingStreamingResponse::new(resp))
            })
        })
    }

    // --- Event Hooks ---------------------------------------------------------

    fn on_request(&self, callback: Py<PyAny>) -> PyResult<()> {
        self.hooks
            .request_hooks
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
            .push(callback);
        Ok(())
    }

    fn on_response(&self, callback: Py<PyAny>) -> PyResult<()> {
        self.hooks
            .response_hooks
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
            .push(callback);
        Ok(())
    }

    fn __repr__(&self) -> String {
        "<BlockingSession>".to_string()
    }
}
