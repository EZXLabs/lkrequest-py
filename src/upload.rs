//! Streaming request bodies.
//!
//! Upstream's `RequestBuilder::body_stream` consumes a
//! `Stream<Item = io::Result<Bytes>>`; this module builds one out of whatever
//! Python hands us. Three source shapes are accepted, probed in this order:
//!
//! 1. a file-like object exposing `read(n) -> bytes`,
//! 2. an async iterable of byte chunks (`__aiter__`),
//! 3. a synchronous iterable of byte chunks (`__iter__`).
//!
//! `read` is probed first because a binary file is *also* iterable — by lines.
//! Iterating one would split the upload on `b"\n"`, and chunk boundaries here
//! survive all the way to the wire as HTTP/2 and HTTP/3 DATA frame sizes, so
//! that would quietly reshape the request. Probing `read` keeps files on fixed
//! chunks and leaves a deliberate chunking scheme (a generator, say) intact:
//! upstream passes a chunk's backing allocation through untouched.
//!
//! Nothing is buffered ahead. A chunk is pulled only when the transport has
//! room for it, so the producer feels the connection's backpressure.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use pyo3::exceptions::{PyStopAsyncIteration, PyStopIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use pyo3_async_runtimes::TaskLocals;

/// Bytes requested per `read(n)` call, matching the chunk size upstream's own
/// reader adapter uses.
const READ_CHUNK_SIZE: usize = 16 * 1024;

/// The stream type `RequestBuilder::body_stream` consumes.
pub(crate) type UploadStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

/// A `body_stream=` argument, classified and ready to be turned into a stream.
///
/// Classification happens eagerly (while the caller still has a stack trace to
/// blame) but reads nothing: a bad argument raises from the request call rather
/// than surfacing mid-upload.
pub(crate) enum UploadSource {
    /// A file-like object, pulled with `read(n)`.
    Reader(Arc<Py<PyAny>>),
    /// A synchronous iterator, pulled with `next()`.
    SyncIter(Arc<Py<PyAny>>),
    /// An asynchronous iterator, driven by awaiting `__anext__()`.
    AsyncIter {
        iterator: Arc<Py<PyAny>>,
        /// Captured at classification time rather than looked up per chunk: by
        /// the time a chunk is pulled we are on a runtime worker with no task
        /// locals of our own, and this also makes "no running loop" fail at the
        /// call rather than halfway through the upload.
        locals: Box<TaskLocals>,
    },
}

impl UploadSource {
    /// Classify a `body_stream=` argument.
    pub(crate) fn extract(source: &Bound<'_, PyAny>) -> PyResult<Self> {
        if source.hasattr("read")? {
            return Ok(Self::Reader(Arc::new(source.clone().unbind())));
        }

        if source.hasattr("__aiter__")? {
            let iterator = source.call_method0("__aiter__")?;
            // The blocking client has no event loop to await `__anext__` on, so
            // this is where an async source used from it is rejected.
            let locals =
                pyo3_async_runtimes::tokio::get_current_locals(source.py()).map_err(|_| {
                    PyTypeError::new_err(
                        "body_stream got an async iterable, which needs a running event loop; \
                         pass a file-like object or a synchronous iterable instead",
                    )
                })?;
            return Ok(Self::AsyncIter {
                iterator: Arc::new(iterator.unbind()),
                locals: Box::new(locals),
            });
        }

        match source.try_iter() {
            Ok(iterator) => Ok(Self::SyncIter(Arc::new(iterator.into_any().unbind()))),
            Err(_) => Err(PyTypeError::new_err(format!(
                "body_stream must be a file-like object with read(), an iterable of bytes, \
                 or an async iterable of bytes; got {}",
                type_name(source)
            ))),
        }
    }

    /// Build the upload stream. Consumes the source: it is single-use, exactly
    /// as upstream describes — once a transport claims it, neither an automatic
    /// retry nor a protocol fallback can replay it.
    pub(crate) fn into_stream(self) -> UploadStream {
        match self {
            Self::Reader(source) => Box::pin(BlockingSource::new(source, BlockingKind::Reader)),
            Self::SyncIter(source) => Box::pin(BlockingSource::new(source, BlockingKind::SyncIter)),
            Self::AsyncIter { iterator, locals } => Box::pin(AsyncSource::new(iterator, *locals)),
        }
    }
}

// ---------------------------------------------------------------------------
// Synchronous sources
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum BlockingKind {
    Reader,
    SyncIter,
}

/// Pulls from a synchronous Python source, one chunk per poll.
///
/// Each pull runs on a blocking worker rather than inline in `poll_next`.
/// Taking the GIL on a runtime worker would stall every other request sharing
/// it, and `read()` on a file — or an arbitrary generator — can block for as
/// long as it likes. This mirrors upstream's own `BlockingReaderStream`: at
/// most one pull in flight, never reading ahead.
struct BlockingSource {
    source: Arc<Py<PyAny>>,
    kind: BlockingKind,
    pending: Option<tokio::task::JoinHandle<PyResult<Option<Bytes>>>>,
    done: bool,
}

impl BlockingSource {
    fn new(source: Arc<Py<PyAny>>, kind: BlockingKind) -> Self {
        Self {
            source,
            kind,
            pending: None,
            done: false,
        }
    }
}

impl Stream for BlockingSource {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        let mut pending = match this.pending.take() {
            Some(handle) => handle,
            None => {
                let source = Arc::clone(&this.source);
                let kind = this.kind;
                tokio::task::spawn_blocking(move || {
                    Python::with_gil(|py| match kind {
                        BlockingKind::Reader => pull_reader(py, &source),
                        BlockingKind::SyncIter => pull_sync_iter(py, &source),
                    })
                })
            }
        };

        match Pin::new(&mut pending).poll(context) {
            Poll::Pending => {
                this.pending = Some(pending);
                Poll::Pending
            }
            Poll::Ready(joined) => {
                this.done = true;
                match joined {
                    Ok(Ok(Some(chunk))) => {
                        this.done = false;
                        Poll::Ready(Some(Ok(chunk)))
                    }
                    Ok(Ok(None)) => Poll::Ready(None),
                    Ok(Err(error)) => Poll::Ready(Some(Err(producer_error(error)))),
                    Err(join) => Poll::Ready(Some(Err(io::Error::other(format!(
                        "body_stream source task failed: {join}"
                    ))))),
                }
            }
        }
    }
}

/// One `read(n)`. An empty result is EOF, which is what a file object returns
/// there; `None` — a non-blocking raw stream with nothing buffered — is treated
/// the same rather than spinning on it.
fn pull_reader(py: Python<'_>, source: &Py<PyAny>) -> PyResult<Option<Bytes>> {
    let chunk = source.bind(py).call_method1("read", (READ_CHUNK_SIZE,))?;
    if chunk.is_none() {
        return Ok(None);
    }
    let chunk = extract_chunk(&chunk)?;
    Ok((!chunk.is_empty()).then_some(chunk))
}

/// One `next()`. Unlike a reader, an empty chunk here is not EOF — upstream
/// skips empty chunks — so it is passed through and only `StopIteration` ends
/// the stream.
fn pull_sync_iter(py: Python<'_>, iterator: &Py<PyAny>) -> PyResult<Option<Bytes>> {
    match iterator.bind(py).call_method0("__next__") {
        Ok(item) => extract_chunk(&item).map(Some),
        Err(error) if error.is_instance_of::<PyStopIteration>(py) => Ok(None),
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// Asynchronous sources
// ---------------------------------------------------------------------------

type PendingChunk = Pin<Box<dyn Future<Output = PyResult<PyObject>> + Send>>;

/// Pulls from a Python async iterator by awaiting `__anext__()` on the event
/// loop that was running when the request was made.
///
/// No blocking worker here: the coroutine belongs to the caller's loop, and
/// `into_future_with_locals` schedules it there and hands back a Rust future.
struct AsyncSource {
    iterator: Arc<Py<PyAny>>,
    locals: TaskLocals,
    pending: Option<PendingChunk>,
    done: bool,
}

impl AsyncSource {
    fn new(iterator: Arc<Py<PyAny>>, locals: TaskLocals) -> Self {
        Self {
            iterator,
            locals,
            pending: None,
            done: false,
        }
    }
}

impl Stream for AsyncSource {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        let mut pending = match this.pending.take() {
            Some(future) => future,
            None => {
                let started = Python::with_gil(|py| {
                    let awaitable = this.iterator.bind(py).call_method0("__anext__")?;
                    pyo3_async_runtimes::into_future_with_locals(&this.locals, awaitable)
                });
                match started {
                    Ok(future) => Box::pin(future) as PendingChunk,
                    Err(error) => {
                        this.done = true;
                        return Poll::Ready(end_or_error(error));
                    }
                }
            }
        };

        match pending.as_mut().poll(context) {
            Poll::Pending => {
                this.pending = Some(pending);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => {
                this.done = true;
                Poll::Ready(end_or_error(error))
            }
            Poll::Ready(Ok(item)) => match Python::with_gil(|py| extract_chunk(item.bind(py))) {
                Ok(chunk) => Poll::Ready(Some(Ok(chunk))),
                Err(error) => {
                    this.done = true;
                    Poll::Ready(Some(Err(producer_error(error))))
                }
            },
        }
    }
}

/// `StopAsyncIteration` ends the stream; anything else is a producer failure.
fn end_or_error(error: PyErr) -> Option<io::Result<Bytes>> {
    if Python::with_gil(|py| error.is_instance_of::<PyStopAsyncIteration>(py)) {
        None
    } else {
        Some(Err(producer_error(error)))
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Convert one produced chunk into `Bytes`.
fn extract_chunk(chunk: &Bound<'_, PyAny>) -> PyResult<Bytes> {
    if let Ok(bytes) = chunk.downcast::<PyBytes>() {
        return Ok(Bytes::copy_from_slice(bytes.as_bytes()));
    }
    // A text-mode file or a str generator is by far the likeliest mistake, so
    // name the fix instead of letting it fall into the generic message.
    if chunk.is_instance_of::<PyString>() {
        return Err(PyTypeError::new_err(
            "body_stream produced str, expected bytes — open the file in binary mode ('rb')",
        ));
    }
    chunk.extract::<Vec<u8>>().map(Bytes::from).map_err(|_| {
        PyTypeError::new_err(format!(
            "body_stream must produce bytes-like chunks, got {}",
            type_name(chunk)
        ))
    })
}

/// Carry a Python-side producer failure into the stream.
///
/// `Stream<Item = io::Result<Bytes>>` has nowhere to put a `PyErr`, so the
/// exception is rendered into the message; it reaches the caller as
/// `RequestError` once upstream aborts the upload.
fn producer_error(error: PyErr) -> io::Error {
    io::Error::other(format!("body_stream source failed: {error}"))
}

/// Best-effort type name for an error message.
fn type_name(object: &Bound<'_, PyAny>) -> String {
    object
        .get_type()
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
}
