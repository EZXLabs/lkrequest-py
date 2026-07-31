//! WebSocket pyclasses: `WsMessage` plus async `WsConnection` and blocking
//! `BlockingWsConnection` for sending and receiving messages over an upgraded
//! connection.

use pyo3::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::client::blocking_runtime;
use crate::error::to_py_err;

type WsStream = hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>;

// ---------------------------------------------------------------------------
// WsMessage
// ---------------------------------------------------------------------------

#[pyclass(name = "WsMessage", eq)]
#[derive(Clone, PartialEq)]
pub enum PyWsMessage {
    Text { data: String },
    Binary { data: Vec<u8> },
    Ping { data: Vec<u8> },
    Pong { data: Vec<u8> },
    Close { code: Option<u16>, reason: String },
}

#[pymethods]
impl PyWsMessage {
    #[staticmethod]
    fn text(data: String) -> Self {
        PyWsMessage::Text { data }
    }

    #[staticmethod]
    fn binary(data: Vec<u8>) -> Self {
        PyWsMessage::Binary { data }
    }

    fn is_text(&self) -> bool {
        matches!(self, PyWsMessage::Text { .. })
    }

    fn is_binary(&self) -> bool {
        matches!(self, PyWsMessage::Binary { .. })
    }

    fn is_close(&self) -> bool {
        matches!(self, PyWsMessage::Close { .. })
    }

    fn __repr__(&self) -> String {
        match self {
            PyWsMessage::Text { data } => format!("WsMessage.Text({:?})", data),
            PyWsMessage::Binary { data } => format!("WsMessage.Binary({} bytes)", data.len()),
            PyWsMessage::Ping { data } => format!("WsMessage.Ping({} bytes)", data.len()),
            PyWsMessage::Pong { data } => format!("WsMessage.Pong({} bytes)", data.len()),
            PyWsMessage::Close { code, reason } => {
                format!("WsMessage.Close(code={:?}, reason={:?})", code, reason)
            }
        }
    }
}

fn ws_msg_type(msg: &lkrequest::ws::WsMessage) -> &'static str {
    match msg {
        lkrequest::ws::WsMessage::Text(_) => "text",
        lkrequest::ws::WsMessage::Binary(_) => "binary",
        lkrequest::ws::WsMessage::Ping(_) => "ping",
        lkrequest::ws::WsMessage::Pong(_) => "pong",
        lkrequest::ws::WsMessage::Close(_, _) => "close",
    }
}

fn rust_ws_to_py(msg: lkrequest::ws::WsMessage) -> PyWsMessage {
    match msg {
        lkrequest::ws::WsMessage::Text(s) => PyWsMessage::Text { data: s },
        lkrequest::ws::WsMessage::Binary(b) => PyWsMessage::Binary { data: b },
        lkrequest::ws::WsMessage::Ping(b) => PyWsMessage::Ping { data: b },
        lkrequest::ws::WsMessage::Pong(b) => PyWsMessage::Pong { data: b },
        lkrequest::ws::WsMessage::Close(code, reason) => PyWsMessage::Close { code, reason },
    }
}

// ---------------------------------------------------------------------------
// Async WsConnection
// ---------------------------------------------------------------------------

#[pyclass(name = "WsConnection")]
pub struct PyWsConnection {
    inner: Arc<Mutex<Option<lkrequest::ws::WsConnection<WsStream>>>>,
}

impl PyWsConnection {
    pub fn new(conn: lkrequest::ws::WsConnection<WsStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(conn))),
        }
    }
}

#[pymethods]
impl PyWsConnection {
    fn send_text<'py>(&self, py: Python<'py>, text: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            tracing::debug!(len = text.len(), "ws send_text");
            conn.send_text(&text).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn send_binary<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            tracing::debug!(len = data.len(), "ws send_binary");
            conn.send_binary(&data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            let msg = conn.recv().await.map_err(to_py_err)?;
            tracing::debug!(msg_type = %ws_msg_type(&msg), "ws recv");
            Ok(rust_ws_to_py(msg))
        })
    }

    #[pyo3(signature = (code=None, reason=""))]
    fn close<'py>(
        &self,
        py: Python<'py>,
        code: Option<u16>,
        reason: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let reason = reason.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            let close_info = code.map(|c| (c, reason.as_str()));
            tracing::debug!(?code, "ws close");
            conn.close(close_info).await.map_err(to_py_err)?;
            *guard = None;
            Ok(())
        })
    }

    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let conn = match guard.as_mut() {
                Some(c) => c,
                None => return Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            };
            match conn.recv().await {
                Ok(msg) => {
                    if matches!(msg, lkrequest::ws::WsMessage::Close(_, _)) {
                        *guard = None;
                        Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                    } else {
                        Ok(rust_ws_to_py(msg))
                    }
                }
                Err(_) => {
                    *guard = None;
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
            }
        })
    }

    fn __repr__(&self) -> String {
        "<WsConnection>".to_string()
    }
}

// ---------------------------------------------------------------------------
// Blocking WsConnection
// ---------------------------------------------------------------------------

#[pyclass(name = "BlockingWsConnection")]
pub struct PyBlockingWsConnection {
    inner: Arc<std::sync::Mutex<Option<lkrequest::ws::WsConnection<WsStream>>>>,
}

impl PyBlockingWsConnection {
    pub fn new(conn: lkrequest::ws::WsConnection<WsStream>) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(Some(conn))),
        }
    }
}

#[pymethods]
impl PyBlockingWsConnection {
    fn send_text(&self, py: Python<'_>, text: String) -> PyResult<()> {
        let inner = self.inner.clone();
        py.allow_threads(|| {
            let mut guard = inner
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            blocking_runtime()
                .block_on(conn.send_text(&text))
                .map_err(to_py_err)
        })
    }

    fn send_binary(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<()> {
        let inner = self.inner.clone();
        py.allow_threads(|| {
            let mut guard = inner
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            blocking_runtime()
                .block_on(conn.send_binary(&data))
                .map_err(to_py_err)
        })
    }

    fn recv(&self, py: Python<'_>) -> PyResult<PyWsMessage> {
        let inner = self.inner.clone();
        py.allow_threads(|| {
            let mut guard = inner
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            let msg = blocking_runtime()
                .block_on(conn.recv())
                .map_err(to_py_err)?;
            Ok(rust_ws_to_py(msg))
        })
    }

    #[pyo3(signature = (code=None, reason=""))]
    fn close(&self, py: Python<'_>, code: Option<u16>, reason: &str) -> PyResult<()> {
        let inner = self.inner.clone();
        let reason = reason.to_string();
        py.allow_threads(|| {
            let mut guard = inner
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
            let conn = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))?;
            let close_info = code.map(|c| (c, reason.as_str()));
            blocking_runtime()
                .block_on(conn.close(close_info))
                .map_err(to_py_err)?;
            *guard = None;
            Ok(())
        })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<PyWsMessage>> {
        let inner = self.inner.clone();
        py.allow_threads(|| {
            let mut guard = inner
                .lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
            let conn = match guard.as_mut() {
                Some(c) => c,
                None => return Ok(None),
            };
            match blocking_runtime().block_on(conn.recv()) {
                Ok(msg) => {
                    if matches!(msg, lkrequest::ws::WsMessage::Close(_, _)) {
                        *guard = None;
                        Ok(None)
                    } else {
                        Ok(Some(rust_ws_to_py(msg)))
                    }
                }
                Err(_) => {
                    *guard = None;
                    Ok(None)
                }
            }
        })
    }

    fn __repr__(&self) -> String {
        "<BlockingWsConnection>".to_string()
    }
}
