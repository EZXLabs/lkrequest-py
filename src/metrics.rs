//! `MetricsCollector` pyclass: thread-safe per-host request/error/byte counters
//! and latency histograms exportable in Prometheus format.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const HISTOGRAM_BUCKETS: &[f64] = &[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

struct HostMetrics {
    requests: AtomicU64,
    errors: AtomicU64,
    bytes_received: AtomicU64,
    histogram_counts: Vec<AtomicU64>,
    histogram_sum: AtomicU64, // stored as f64 bits
}

impl HostMetrics {
    fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            histogram_counts: HISTOGRAM_BUCKETS
                .iter()
                .map(|_| AtomicU64::new(0))
                .collect(),
            histogram_sum: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: f64, body_size: u64, is_error: bool) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(body_size, Ordering::Relaxed);
        if is_error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        for (i, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if elapsed <= *bucket {
                self.histogram_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // Atomic f64 add via CAS loop
        loop {
            let current = self.histogram_sum.load(Ordering::Relaxed);
            let current_f = f64::from_bits(current);
            let new_f = current_f + elapsed;
            if self
                .histogram_sum
                .compare_exchange_weak(
                    current,
                    new_f.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }
}

struct MetricsInner {
    global_requests: AtomicU64,
    global_errors: AtomicU64,
    global_bytes_received: AtomicU64,
    per_host: Mutex<HashMap<String, Arc<HostMetrics>>>,
}

impl MetricsInner {
    fn new() -> Self {
        Self {
            global_requests: AtomicU64::new(0),
            global_errors: AtomicU64::new(0),
            global_bytes_received: AtomicU64::new(0),
            per_host: Mutex::new(HashMap::new()),
        }
    }

    fn get_host_metrics(&self, host: &str) -> Option<Arc<HostMetrics>> {
        let mut map = self.per_host.lock().ok()?;
        Some(
            map.entry(host.to_string())
                .or_insert_with(|| Arc::new(HostMetrics::new()))
                .clone(),
        )
    }

    fn record(&self, host: &str, elapsed: f64, body_size: u64, is_error: bool) {
        self.global_requests.fetch_add(1, Ordering::Relaxed);
        self.global_bytes_received
            .fetch_add(body_size, Ordering::Relaxed);
        if is_error {
            self.global_errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(hm) = self.get_host_metrics(host) {
            hm.record(elapsed, body_size, is_error);
        }
    }
}

#[pyclass(name = "MetricsCollector")]
pub struct PyMetricsCollector {
    inner: Arc<MetricsInner>,
}

impl PyMetricsCollector {
    pub fn record(&self, url: &str, elapsed: f64, body_size: u64, is_error: bool) {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        self.inner.record(&host, elapsed, body_size, is_error);
    }
}

#[pymethods]
impl PyMetricsCollector {
    fn snapshot<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item(
            "requests_total",
            self.inner.global_requests.load(Ordering::Relaxed),
        )?;
        dict.set_item(
            "errors_total",
            self.inner.global_errors.load(Ordering::Relaxed),
        )?;
        dict.set_item(
            "bytes_received_total",
            self.inner.global_bytes_received.load(Ordering::Relaxed),
        )?;

        let hosts_dict = PyDict::new(py);
        let map = self
            .inner
            .per_host
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Metrics lock poisoned"))?;
        for (host, hm) in map.iter() {
            let host_dict = PyDict::new(py);
            host_dict.set_item("requests", hm.requests.load(Ordering::Relaxed))?;
            host_dict.set_item("errors", hm.errors.load(Ordering::Relaxed))?;
            host_dict.set_item("bytes_received", hm.bytes_received.load(Ordering::Relaxed))?;
            host_dict.set_item(
                "duration_sum",
                f64::from_bits(hm.histogram_sum.load(Ordering::Relaxed)),
            )?;
            let buckets = PyDict::new(py);
            for (i, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
                buckets.set_item(
                    format!("{bucket}"),
                    hm.histogram_counts[i].load(Ordering::Relaxed),
                )?;
            }
            host_dict.set_item("duration_buckets", buckets)?;
            hosts_dict.set_item(host.as_str(), host_dict)?;
        }
        dict.set_item("hosts", hosts_dict)?;
        Ok(dict)
    }

    fn prometheus_text(&self) -> String {
        let mut out = String::new();

        let total = self.inner.global_requests.load(Ordering::Relaxed);
        let errors = self.inner.global_errors.load(Ordering::Relaxed);
        let bytes_recv = self.inner.global_bytes_received.load(Ordering::Relaxed);

        out.push_str("# HELP lkrequest_requests_total Total number of HTTP requests.\n");
        out.push_str("# TYPE lkrequest_requests_total counter\n");
        out.push_str(&format!("lkrequest_requests_total {total}\n"));

        out.push_str("# HELP lkrequest_errors_total Total number of failed HTTP requests.\n");
        out.push_str("# TYPE lkrequest_errors_total counter\n");
        out.push_str(&format!("lkrequest_errors_total {errors}\n"));

        out.push_str(
            "# HELP lkrequest_bytes_received_total Total bytes received across all responses.\n",
        );
        out.push_str("# TYPE lkrequest_bytes_received_total counter\n");
        out.push_str(&format!("lkrequest_bytes_received_total {bytes_recv}\n"));

        out.push_str(
            "# HELP lkrequest_request_duration_seconds HTTP request duration in seconds.\n",
        );
        out.push_str("# TYPE lkrequest_request_duration_seconds histogram\n");

        let map = match self.inner.per_host.lock() {
            Ok(m) => m,
            Err(_) => return out,
        };
        for (host, hm) in map.iter() {
            let escaped_host = host.replace('\\', "\\\\").replace('"', "\\\"");
            for (i, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
                let count = hm.histogram_counts[i].load(Ordering::Relaxed);
                out.push_str(&format!(
                    "lkrequest_request_duration_seconds_bucket{{host=\"{escaped_host}\",le=\"{bucket}\"}} {count}\n"
                ));
            }
            let req_count = hm.requests.load(Ordering::Relaxed);
            out.push_str(&format!(
                "lkrequest_request_duration_seconds_bucket{{host=\"{escaped_host}\",le=\"+Inf\"}} {req_count}\n"
            ));
            let sum = f64::from_bits(hm.histogram_sum.load(Ordering::Relaxed));
            out.push_str(&format!(
                "lkrequest_request_duration_seconds_sum{{host=\"{escaped_host}\"}} {sum}\n"
            ));
            out.push_str(&format!(
                "lkrequest_request_duration_seconds_count{{host=\"{escaped_host}\"}} {req_count}\n"
            ));
        }

        out
    }

    fn reset(&self) -> PyResult<()> {
        self.inner.global_requests.store(0, Ordering::Relaxed);
        self.inner.global_errors.store(0, Ordering::Relaxed);
        self.inner.global_bytes_received.store(0, Ordering::Relaxed);
        let mut map = self
            .inner
            .per_host
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Metrics lock poisoned"))?;
        map.clear();
        Ok(())
    }

    fn __repr__(&self) -> String {
        let total = self.inner.global_requests.load(Ordering::Relaxed);
        let errors = self.inner.global_errors.load(Ordering::Relaxed);
        format!("<MetricsCollector requests={total} errors={errors}>")
    }
}

static GLOBAL_METRICS: std::sync::LazyLock<Arc<MetricsInner>> =
    std::sync::LazyLock::new(|| Arc::new(MetricsInner::new()));

#[pyfunction]
pub fn enable_metrics() -> PyMetricsCollector {
    PyMetricsCollector {
        inner: GLOBAL_METRICS.clone(),
    }
}

/// Called internally by the response hook to record metrics.
pub(crate) fn record_global_metrics(url: &str, elapsed: f64, body_size: u64, is_error: bool) {
    if Arc::strong_count(&GLOBAL_METRICS) > 1 {
        GLOBAL_METRICS.record(
            &url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| "unknown".to_string()),
            elapsed,
            body_size,
            is_error,
        );
    }
}
