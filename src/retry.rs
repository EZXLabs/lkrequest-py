//! Retry-policy pyclasses: `ExponentialBackoff` and `FixedInterval`, plus the
//! `PyCallableRetryPolicy` adapter that drives retries from a Python callable.

use pyo3::prelude::*;
use std::time::Duration;

use crate::types::validated_duration;
use lkrequest::retry::RetryPolicy;

#[pyclass(name = "ExponentialBackoff")]
#[derive(Clone)]
pub struct PyExponentialBackoff {
    pub(crate) inner: lkrequest::ExponentialBackoff,
}

#[pymethods]
impl PyExponentialBackoff {
    #[new]
    #[pyo3(signature = (max_retries=3, base_delay=1.0, max_delay=30.0, jitter=true))]
    fn new(max_retries: u32, base_delay: f64, max_delay: f64, jitter: bool) -> PyResult<Self> {
        let inner = lkrequest::ExponentialBackoff::new(
            max_retries,
            validated_duration(base_delay)?,
            validated_duration(max_delay)?,
        )
        .with_jitter(jitter);
        Ok(PyExponentialBackoff { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "ExponentialBackoff(max_retries={}, jitter={})",
            self.inner.max_retries, self.inner.jitter
        )
    }
}

#[pyclass(name = "FixedInterval")]
#[derive(Clone)]
pub struct PyFixedInterval {
    pub(crate) inner: lkrequest::FixedInterval,
}

#[pymethods]
impl PyFixedInterval {
    #[new]
    #[pyo3(signature = (max_retries=3, interval=1.0))]
    fn new(max_retries: u32, interval: f64) -> PyResult<Self> {
        let inner = lkrequest::FixedInterval::new(max_retries, validated_duration(interval)?);
        Ok(PyFixedInterval { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "FixedInterval(max_retries={}, interval={:?})",
            self.inner.max_retries, self.inner.interval
        )
    }
}

// ---------------------------------------------------------------------------
// Python callable as retry policy
// ---------------------------------------------------------------------------

pub(crate) struct PyCallableRetryPolicy {
    callable: Py<PyAny>,
}

impl std::fmt::Debug for PyCallableRetryPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PyCallableRetryPolicy").finish()
    }
}

impl PyCallableRetryPolicy {
    pub fn new(callable: Py<PyAny>) -> Self {
        Self { callable }
    }
}

impl RetryPolicy for PyCallableRetryPolicy {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&lkrequest::error::Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        Python::with_gil(|py| {
            let error_str: Option<String> = error.map(|e| e.to_string());
            let status_code: Option<u16> = status.map(|s| s.as_u16());

            let result = self
                .callable
                .call1(py, (attempt, error_str, status_code))
                .ok()?;

            if result.is_none(py) {
                tracing::debug!(attempt, "retry policy: no retry");
                return None;
            }
            let delay_secs: f64 = result.extract(py).ok()?;
            if !delay_secs.is_finite() || delay_secs < 0.0 {
                tracing::warn!(
                    delay = delay_secs,
                    "retry callable returned invalid delay, skipping retry"
                );
                return None;
            }
            tracing::info!(attempt, delay_secs, "retry policy: will retry");
            Some(Duration::from_secs_f64(delay_secs))
        })
    }
}
