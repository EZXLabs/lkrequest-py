//! HSTS / scheme-upgrade policy pyclass.
//!
//! Mirrors upstream `lkrequest::hsts` (`NoHsts` / `StaticHsts` / `DynamicHsts`,
//! and a policy written in Python) behind a single `Hsts` type with static
//! constructors, threaded into `Client.session(hsts=...)`. Controls whether an
//! `http://` URL (initial request or redirect target) is upgraded to
//! `https://` before connecting — the customizable equivalent of a browser's
//! HSTS handling (RFC 6797).
//!
//! An `Hsts` object holds one policy, shared by every session it is given to,
//! so a dynamic one learns for all of them, as one browser profile does.
//!
//! A fresh session is stateless ("first visit"), so the default when `hsts` is
//! omitted performs no upgrades, matching `NoHsts`.

use std::sync::Arc;

use lkrequest::hsts::{DynamicHsts, HstsPolicy, NoHsts, StaticHsts};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

use crate::types::is_async_function;

/// HTTP→HTTPS scheme-upgrade (HSTS) policy for a session.
///
/// Because the library emulates a browser's *network* layer, it ships no
/// dynamic HSTS store and no compiled preload list by default: a fresh session
/// is a stateless first visit, so nothing is upgraded. Plug a policy into
/// `Client.session(hsts=...)` to mirror Chrome's preloaded gTLDs, replay a
/// session that already learned HSTS, or enforce your own rules.
///
/// ```python
/// # Learn HSTS from responses, like a long-lived browser profile:
/// session = client.session(hsts=Hsts.dynamic())
/// # Enforce a fixed allowlist (suffix-aware, includeSubDomains):
/// session = client.session(hsts=Hsts.static_(["example.com"]))
/// ```
#[pyclass(name = "Hsts", from_py_object)]
#[derive(Clone)]
pub struct PyHsts {
    /// Shared with every session this object is given to.
    policy: Arc<dyn HstsPolicy>,
}

#[pymethods]
impl PyHsts {
    /// Never upgrade `http://` to `https://` (the default; a stateless
    /// first-visit session with no HSTS history).
    #[staticmethod]
    fn none() -> Self {
        Self::from_policy(NoHsts)
    }

    /// Upgrade a fixed set of hosts. Matching is suffix-aware, so listing
    /// `example.com` also upgrades `api.example.com` (HSTS `includeSubDomains`).
    /// Set `preloaded_tlds=True` to also upgrade every host under a gTLD Chrome
    /// preloads in full (`.dev`, `.app`, …).
    #[staticmethod]
    #[pyo3(signature = (hosts, preloaded_tlds=false))]
    fn static_(hosts: Vec<String>, preloaded_tlds: bool) -> Self {
        let policy = StaticHsts::new(hosts);
        if preloaded_tlds {
            Self::from_policy(policy.with_preloaded_tlds())
        } else {
            Self::from_policy(policy)
        }
    }

    /// Learn HSTS hosts from `Strict-Transport-Security` response headers,
    /// mirroring a browser's dynamic HSTS store, for every session given this
    /// object. Optionally pre-seed with known HSTS hosts (e.g. replaying a
    /// prior session's state).
    #[staticmethod]
    #[pyo3(signature = (seed=None))]
    fn dynamic(seed: Option<Vec<String>>) -> Self {
        match seed {
            Some(seed) if !seed.is_empty() => Self::from_policy(DynamicHsts::with_seed(seed)),
            _ => Self::from_policy(DynamicHsts::new()),
        }
    }

    /// A policy written in Python: `should_upgrade(host)` says whether to
    /// upgrade, and `record_sts(host, header)`, if given, is told of each
    /// `Strict-Transport-Security` header received over HTTPS.
    #[staticmethod]
    #[pyo3(signature = (should_upgrade, record_sts=None))]
    fn custom(
        should_upgrade: &Bound<'_, PyAny>,
        record_sts: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        Ok(Self::from_policy(PythonHsts {
            should_upgrade: plain_function("should_upgrade", should_upgrade)?,
            record_sts: record_sts
                .map(|record| plain_function("record_sts", record))
                .transpose()?,
        }))
    }

    /// Whether a request to `host` would be upgraded to `https://` now, as a
    /// session would ask the policy.
    fn should_upgrade(&self, host: &str) -> bool {
        self.policy.should_upgrade(host)
    }
}

impl PyHsts {
    fn from_policy(policy: impl HstsPolicy + 'static) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// Apply this policy to a session builder, sharing its state.
    pub(crate) fn apply(
        &self,
        builder: lkrequest::session::SessionBuilder,
    ) -> lkrequest::session::SessionBuilder {
        builder.hsts_policy(SharedHsts(Arc::clone(&self.policy)))
    }
}

/// The policy of an `Hsts` object, as each session given it holds it.
struct SharedHsts(Arc<dyn HstsPolicy>);

impl HstsPolicy for SharedHsts {
    fn should_upgrade(&self, host: &str) -> bool {
        self.0.should_upgrade(host)
    }

    fn record_sts(&self, host: &str, sts_header: &str) {
        self.0.record_sts(host, sts_header);
    }
}

/// Upstream's `HstsPolicy` backed by Python functions, which are called on
/// the thread running the request.
struct PythonHsts {
    should_upgrade: Py<PyAny>,
    record_sts: Option<Py<PyAny>>,
}

impl HstsPolicy for PythonHsts {
    /// Only a true answer upgrades; a function that raises is logged.
    fn should_upgrade(&self, host: &str) -> bool {
        let answer =
            Python::try_attach(|py| self.should_upgrade.bind(py).call1((host,))?.is_truthy());
        match answer {
            Some(Ok(upgrade)) => upgrade,
            Some(Err(err)) => {
                tracing::warn!(host, error = %err, "hsts.should_upgrade_failed");
                false
            }
            // The interpreter is gone.
            None => false,
        }
    }

    fn record_sts(&self, host: &str, sts_header: &str) {
        let Some(record) = &self.record_sts else {
            return;
        };
        let outcome = Python::try_attach(|py| record.bind(py).call1((host, sts_header)).map(drop));
        if let Some(Err(err)) = outcome {
            tracing::warn!(host, error = %err, "hsts.record_sts_failed");
        }
    }
}

/// `function`, which upstream calls synchronously, so it must not be async.
fn plain_function(name: &str, function: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    if !function.is_callable() {
        return Err(PyTypeError::new_err(format!("{name} must be callable")));
    }
    if is_async_function(function)? {
        return Err(PyTypeError::new_err(format!(
            "{name} must be a plain function, not an async one"
        )));
    }
    Ok(function.clone().unbind())
}
