//! Browser-style network session policies: how TLS session tickets are reused
//! and how the ticket cache is partitioned.
//!
//! Mirrors upstream `lkrequest::network_partition`. The three types split the
//! problem as follows:
//! - `TlsSessionResumptionPolicy` — *whether* tickets are cached and reused
//!   (client behaviour).
//! - `TlsSessionCachePartitionPolicy` — *along which dimension* the cache is
//!   partitioned (the browser's isolation model).
//! - `NetworkPartitionContext` — the *concrete browsing context* the partition
//!   key is derived from (top-level site / frame site).
//!
//! Do not confuse these with `SessionResumptionConfig`, which lives at the TLS
//! profile layer and decides which resumption modes are *advertised* in the
//! ClientHello (i.e. fingerprint shape). The three types here are client-layer
//! policy: they decide how tickets are actually stored and isolated.

use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// TlsSessionResumptionPolicy
// ---------------------------------------------------------------------------

/// Caching and reuse policy for TLS 1.3 session tickets. Pass to
/// `Client(tls_session_resumption_policy=...)`.
///
/// Distinct from `SessionResumptionConfig`: that one decides which resumption
/// modes the ClientHello advertises (fingerprint shape), while this one decides
/// whether the client actually retains tickets and offers them as a PSK on
/// later connections.
#[pyclass(name = "TlsSessionResumptionPolicy", eq)]
#[derive(Clone, PartialEq)]
pub struct PyTlsSessionResumptionPolicy {
    pub(crate) inner: lkrequest::TlsSessionResumptionPolicy,
}

#[pymethods]
impl PyTlsSessionResumptionPolicy {
    /// Browser-facing default: keep two tickets per server, consuming the most
    /// recently received one first.
    #[classattr]
    #[allow(non_snake_case)]
    fn BROWSER_DEFAULT() -> PyTlsSessionResumptionPolicy {
        PyTlsSessionResumptionPolicy {
            inner: lkrequest::TlsSessionResumptionPolicy::BrowserDefault,
        }
    }

    /// Never store or offer tickets; every connection performs a full handshake.
    #[classattr]
    #[allow(non_snake_case)]
    fn DISABLED() -> PyTlsSessionResumptionPolicy {
        PyTlsSessionResumptionPolicy {
            inner: lkrequest::TlsSessionResumptionPolicy::Disabled,
        }
    }

    /// Enable resumption with an explicit per-server ticket capacity.
    /// `max_tickets_per_server` must be positive — upstream's builder turns 0
    /// into an `assert!` panic, so reject it here with a clean ValueError.
    #[staticmethod]
    fn enabled(max_tickets_per_server: usize) -> PyResult<PyTlsSessionResumptionPolicy> {
        if max_tickets_per_server == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_tickets_per_server must be greater than zero (use TlsSessionResumptionPolicy.DISABLED to turn resumption off)",
            ));
        }
        Ok(PyTlsSessionResumptionPolicy {
            inner: lkrequest::TlsSessionResumptionPolicy::Enabled {
                max_tickets_per_server,
            },
        })
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            lkrequest::TlsSessionResumptionPolicy::BrowserDefault => {
                "TlsSessionResumptionPolicy.BROWSER_DEFAULT".to_string()
            }
            lkrequest::TlsSessionResumptionPolicy::Disabled => {
                "TlsSessionResumptionPolicy.DISABLED".to_string()
            }
            lkrequest::TlsSessionResumptionPolicy::Enabled {
                max_tickets_per_server,
            } => format!("TlsSessionResumptionPolicy.enabled({max_tickets_per_server})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TlsSessionCachePartitionPolicy
// ---------------------------------------------------------------------------

/// Partitioning policy for the TLS / QUIC session ticket cache, deciding
/// whether tickets are visible across browsing contexts. Pass to
/// `Client(tls_session_cache_partition_policy=...)`.
///
/// The browser presets already carry the matching policy (Chrome family →
/// `CHROMIUM`, Firefox → `FIREFOX`, Safari → `UNPARTITIONED`); setting this
/// explicitly is only needed when building a client by hand.
#[pyclass(name = "TlsSessionCachePartitionPolicy", eq)]
#[derive(Clone, Copy, PartialEq)]
pub struct PyTlsSessionCachePartitionPolicy {
    pub(crate) inner: lkrequest::TlsSessionCachePartitionPolicy,
}

#[pymethods]
impl PyTlsSessionCachePartitionPolicy {
    /// Traditional HTTP client behaviour: cache per server, no partitioning.
    #[classattr]
    #[allow(non_snake_case)]
    fn UNPARTITIONED() -> PyTlsSessionCachePartitionPolicy {
        PyTlsSessionCachePartitionPolicy {
            inner: lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned,
        }
    }

    /// Partition by top-level schemeful site.
    #[classattr]
    #[allow(non_snake_case)]
    fn TOP_LEVEL_SITE() -> PyTlsSessionCachePartitionPolicy {
        PyTlsSessionCachePartitionPolicy {
            inner: lkrequest::TlsSessionCachePartitionPolicy::TopLevelSite,
        }
    }

    /// Partition by both the top-level and the frame schemeful site.
    #[classattr]
    #[allow(non_snake_case)]
    fn TOP_LEVEL_AND_FRAME_SITE() -> PyTlsSessionCachePartitionPolicy {
        PyTlsSessionCachePartitionPolicy {
            inner: lkrequest::TlsSessionCachePartitionPolicy::TopLevelAndFrameSite,
        }
    }

    /// Chromium's 2.5-key model: top-level site plus a same-site/cross-site flag.
    #[classattr]
    #[allow(non_snake_case)]
    fn CHROMIUM() -> PyTlsSessionCachePartitionPolicy {
        PyTlsSessionCachePartitionPolicy {
            inner: lkrequest::TlsSessionCachePartitionPolicy::Chromium,
        }
    }

    /// Firefox style: top-level partitioning scoped by OriginAttributes.
    #[classattr]
    #[allow(non_snake_case)]
    fn FIREFOX() -> PyTlsSessionCachePartitionPolicy {
        PyTlsSessionCachePartitionPolicy {
            inner: lkrequest::TlsSessionCachePartitionPolicy::Firefox,
        }
    }

    fn __repr__(&self) -> String {
        let name = match self.inner {
            lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned => "UNPARTITIONED",
            lkrequest::TlsSessionCachePartitionPolicy::TopLevelSite => "TOP_LEVEL_SITE",
            lkrequest::TlsSessionCachePartitionPolicy::TopLevelAndFrameSite => {
                "TOP_LEVEL_AND_FRAME_SITE"
            }
            lkrequest::TlsSessionCachePartitionPolicy::Chromium => "CHROMIUM",
            lkrequest::TlsSessionCachePartitionPolicy::Firefox => "FIREFOX",
        };
        format!("TlsSessionCachePartitionPolicy.{name}")
    }
}

// ---------------------------------------------------------------------------
// NetworkPartitionContext
// ---------------------------------------------------------------------------

/// The browsing context a session cache partition key is derived from. Pass to
/// `Client.session(network_partition_context=...)`.
///
/// Both site arguments must be canonical schemeful sites (e.g.
/// `https://example.com`), not arbitrary document URLs.
#[pyclass(name = "NetworkPartitionContext", eq)]
#[derive(Clone, PartialEq)]
pub struct PyNetworkPartitionContext {
    pub(crate) inner: lkrequest::NetworkPartitionContext,
}

#[pymethods]
impl PyNetworkPartitionContext {
    /// Build a context from a top-level site and a frame site.
    #[new]
    fn new(top_level_site: String, frame_site: String) -> Self {
        PyNetworkPartitionContext {
            inner: lkrequest::NetworkPartitionContext::new(top_level_site, frame_site),
        }
    }

    /// Attach a single-use partition nonce (for ephemeral / isolated contexts).
    /// Returns a new object; the receiver is left unchanged.
    fn nonce(&self, nonce: String) -> Self {
        PyNetworkPartitionContext {
            inner: self.inner.clone().nonce(nonce),
        }
    }

    /// Attach an opaque browser context identifier (e.g. Firefox's
    /// OriginAttributes). Returns a new object; the receiver is left unchanged.
    fn browser_context(&self, context: String) -> Self {
        PyNetworkPartitionContext {
            inner: self.inner.clone().browser_context(context),
        }
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}
