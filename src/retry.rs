//! Retry-policy pyclasses: `ExponentialBackoff` and `FixedInterval`, plus the
//! `PyCallableRetryPolicy` adapter that drives retries from a Python callable.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::time::Duration;

use crate::types::validated_duration;
use lkrequest::retry::RetryPolicy;

#[pyclass(name = "ExponentialBackoff", from_py_object)]
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

#[pyclass(name = "FixedInterval", from_py_object)]
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
    /// Whether the callable also takes the failure itself, as `exception=`.
    takes_exception: bool,
}

impl std::fmt::Debug for PyCallableRetryPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PyCallableRetryPolicy").finish()
    }
}

impl PyCallableRetryPolicy {
    pub fn new(callable: &Bound<'_, PyAny>) -> Self {
        Self {
            callable: callable.clone().unbind(),
            // A callable whose signature cannot be read gets the three
            // positional arguments alone, as every callable used to.
            takes_exception: takes_keyword(callable, "exception").unwrap_or(false),
        }
    }
}

/// Whether `callable` accepts `name=`: a parameter of that name that can be
/// passed by keyword, or `**kwargs`.
fn takes_keyword(callable: &Bound<'_, PyAny>, name: &str) -> PyResult<bool> {
    let inspect = callable.py().import("inspect")?;
    let kinds = inspect.getattr("Parameter")?;
    let by_keyword = [
        kinds.getattr("POSITIONAL_OR_KEYWORD")?,
        kinds.getattr("KEYWORD_ONLY")?,
    ];
    let var_keyword = kinds.getattr("VAR_KEYWORD")?;
    let parameters = inspect
        .call_method1("signature", (callable,))?
        .getattr("parameters")?
        .call_method0("values")?;
    for parameter in parameters.try_iter()? {
        let parameter = parameter?;
        let kind = parameter.getattr("kind")?;
        if kind.eq(&var_keyword)? {
            return Ok(true);
        }
        if parameter.getattr("name")?.eq(name)?
            && (kind.eq(&by_keyword[0])? || kind.eq(&by_keyword[1])?)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl RetryPolicy for PyCallableRetryPolicy {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&lkrequest::error::Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        Python::attach(|py| {
            let error_str: Option<String> = error.map(|e| e.to_string());
            let status_code: Option<u16> = status.map(|s| s.as_u16());
            let args = (attempt, error_str, status_code);

            let result = if self.takes_exception {
                let exception = error.map(|e| crate::error::exception_for(py, e).into_value(py));
                let kwargs = PyDict::new(py);
                kwargs.set_item("exception", exception).ok()?;
                self.callable.call(py, args, Some(&kwargs)).ok()?
            } else {
                self.callable.call1(py, args).ok()?
            };

            if result.is_none(py) {
                tracing::debug!(attempt, "retry policy: no retry");
                return None;
            }
            let delay_secs: f64 = result.extract(py).ok()?;
            let Ok(delay) = Duration::try_from_secs_f64(delay_secs) else {
                tracing::warn!(
                    delay = delay_secs,
                    "retry callable returned invalid delay, skipping retry"
                );
                return None;
            };
            tracing::info!(attempt, delay_secs, "retry policy: will retry");
            Some(delay)
        })
    }
}
