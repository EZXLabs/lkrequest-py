//! WebSocket pyclasses: `WsMessage` plus async `WsConnection` and blocking
//! `BlockingWsConnection` for sending and receiving messages over an upgraded
//! connection.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::client::blocking_runtime;
use crate::error::to_py_err;

type WsStream = hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>;
type Connection = lkrequest::ws::WsConnection<WsStream>;

// ---------------------------------------------------------------------------
// WsMessage
// ---------------------------------------------------------------------------

// `hash` alongside `eq` because `eq` on its own makes CPython set
// `__hash__ = None`, leaving the type unusable as a dict key or set member.
// `frozen` is required by `hash` and holds here: a message is built once, by a
// constructor or by the receive path, and only ever read afterwards.
#[pyclass(name = "WsMessage", eq, hash, frozen)]
#[derive(Clone, PartialEq, Eq, Hash)]
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
// Shared connection
// ---------------------------------------------------------------------------

/// The upgraded connection, shared by the Python object and the operations in
/// flight on it.
///
/// An operation takes a handle with [`open`](Self::open) and runs on it with no
/// lock held, so a `recv()` that is waiting for a message does not hold up a
/// `send_*()` or a `close()`. [`release`](Self::release) drops the object's own
/// handle once the connection is closed; the connection itself goes away when
/// the last operation still using it finishes.
struct SharedConnection {
    slot: Mutex<Option<Arc<Connection>>>,
}

impl SharedConnection {
    fn new(conn: Connection) -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(Some(Arc::new(conn))),
        })
    }

    /// The connection, or `None` once it has been closed.
    fn get(&self) -> Option<Arc<Connection>> {
        lock(&self.slot).clone()
    }

    /// Like [`get`](Self::get), as the error a closed connection raises.
    fn open(&self) -> PyResult<Arc<Connection>> {
        self.get()
            .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("WebSocket is closed"))
    }

    fn release(&self) {
        // Taken out first: dropping the last handle runs arbitrary teardown, which
        // has no business running with the lock held.
        let released = lock(&self.slot).take();
        drop(released);
    }
}

/// Poisoning needs a panic while the lock is held, and nothing here does more
/// than clone or take an `Option`; the data is as valid afterwards as before.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Async WsConnection
// ---------------------------------------------------------------------------

#[pyclass(name = "WsConnection")]
pub struct PyWsConnection {
    shared: Arc<SharedConnection>,
}

impl PyWsConnection {
    pub fn new(conn: Connection) -> Self {
        Self {
            shared: SharedConnection::new(conn),
        }
    }
}

#[pymethods]
impl PyWsConnection {
    fn send_text<'py>(&self, py: Python<'py>, text: String) -> PyResult<Bound<'py, PyAny>> {
        let shared = self.shared.clone();
        crate::bridge::future_into_py(py, async move {
            let conn = shared.open()?;
            tracing::debug!(len = text.len(), "ws send_text");
            conn.send_text(&text).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn send_binary<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let shared = self.shared.clone();
        crate::bridge::future_into_py(py, async move {
            let conn = shared.open()?;
            tracing::debug!(len = data.len(), "ws send_binary");
            conn.send_binary(&data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let shared = self.shared.clone();
        crate::bridge::future_into_py(py, async move {
            let conn = shared.open()?;
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
        let shared = self.shared.clone();
        let reason = reason.to_string();
        crate::bridge::future_into_py(py, async move {
            let conn = shared.open()?;
            let close_info = code.map(|c| (c, reason.as_str()));
            tracing::debug!(?code, "ws close");
            conn.close(close_info).await.map_err(to_py_err)?;
            shared.release();
            Ok(())
        })
    }

    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let shared = self.shared.clone();
        crate::bridge::future_into_py(py, async move {
            let Some(conn) = shared.get() else {
                return Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()));
            };
            match conn.recv().await {
                Ok(lkrequest::ws::WsMessage::Close(_, _)) | Err(_) => {
                    shared.release();
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
                Ok(msg) => Ok(rust_ws_to_py(msg)),
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
    shared: Arc<SharedConnection>,
}

impl PyBlockingWsConnection {
    pub fn new(conn: Connection) -> Self {
        Self {
            shared: SharedConnection::new(conn),
        }
    }
}

#[pymethods]
impl PyBlockingWsConnection {
    fn send_text(&self, py: Python<'_>, text: String) -> PyResult<()> {
        let shared = self.shared.clone();
        py.allow_threads(|| {
            let conn = shared.open()?;
            blocking_runtime()
                .block_on(conn.send_text(&text))
                .map_err(to_py_err)
        })
    }

    fn send_binary(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<()> {
        let shared = self.shared.clone();
        py.allow_threads(|| {
            let conn = shared.open()?;
            blocking_runtime()
                .block_on(conn.send_binary(&data))
                .map_err(to_py_err)
        })
    }

    fn recv(&self, py: Python<'_>) -> PyResult<PyWsMessage> {
        let shared = self.shared.clone();
        py.allow_threads(|| {
            let conn = shared.open()?;
            let msg = blocking_runtime()
                .block_on(conn.recv())
                .map_err(to_py_err)?;
            Ok(rust_ws_to_py(msg))
        })
    }

    #[pyo3(signature = (code=None, reason=""))]
    fn close(&self, py: Python<'_>, code: Option<u16>, reason: &str) -> PyResult<()> {
        let shared = self.shared.clone();
        let reason = reason.to_string();
        py.allow_threads(|| {
            let conn = shared.open()?;
            let close_info = code.map(|c| (c, reason.as_str()));
            blocking_runtime()
                .block_on(conn.close(close_info))
                .map_err(to_py_err)?;
            shared.release();
            Ok(())
        })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<PyWsMessage>> {
        let shared = self.shared.clone();
        py.allow_threads(|| {
            let Some(conn) = shared.get() else {
                return Ok(None);
            };
            match blocking_runtime().block_on(conn.recv()) {
                Ok(lkrequest::ws::WsMessage::Close(_, _)) | Err(_) => {
                    shared.release();
                    Ok(None)
                }
                Ok(msg) => Ok(Some(rust_ws_to_py(msg))),
            }
        })
    }

    fn __repr__(&self) -> String {
        "<BlockingWsConnection>".to_string()
    }
}
