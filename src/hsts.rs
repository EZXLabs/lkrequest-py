//! HSTS / scheme-upgrade policy pyclass.
//!
//! Mirrors upstream `lkrequest::hsts` (`NoHsts` / `StaticHsts` / `DynamicHsts`)
//! behind a single `Hsts` type with static constructors, threaded into
//! `Client.session(hsts=...)`. Controls whether an `http://` URL (initial
//! request or redirect target) is upgraded to `https://` before connecting —
//! the customizable equivalent of a browser's HSTS handling (RFC 6797).
//!
//! A fresh session is stateless ("first visit"), so the default when `hsts` is
//! omitted performs no upgrades, matching `NoHsts`.

use pyo3::prelude::*;

/// Which upstream `HstsPolicy` this wraps; carries the data needed to
/// materialize the concrete policy when the session is built.
#[derive(Clone)]
enum HstsKind {
    /// Never upgrade (upstream `NoHsts`).
    None,
    /// Fixed host allowlist (upstream `StaticHsts`).
    Static {
        hosts: Vec<String>,
        preloaded_tlds: bool,
    },
    /// Learn HSTS hosts from `Strict-Transport-Security` headers at runtime
    /// (upstream `DynamicHsts`), optionally pre-seeded.
    Dynamic { seed: Vec<String> },
}

/// HTTP→HTTPS scheme-upgrade (HSTS) policy for a session.
///
/// Because the library emulates a browser's *network* layer, it ships no
/// dynamic HSTS store and no compiled preload list by default: a fresh session
/// is a stateless first visit, so nothing is upgraded. Plug a policy into
/// `Client.session(hsts=...)` to mirror Chrome's preloaded gTLDs, replay a
/// session that already learned HSTS, or enforce your own rules.
///
/// ```python
/// # Learn HSTS from responses within the session, like a long-lived browser:
/// session = client.session(hsts=Hsts.dynamic())
/// # Enforce a fixed allowlist (suffix-aware, includeSubDomains):
/// session = client.session(hsts=Hsts.static_(["example.com"]))
/// ```
#[pyclass(name = "Hsts")]
#[derive(Clone)]
pub struct PyHsts {
    kind: HstsKind,
}

#[pymethods]
impl PyHsts {
    /// Never upgrade `http://` to `https://` (the default; a stateless
    /// first-visit session with no HSTS history).
    #[staticmethod]
    fn none() -> Self {
        PyHsts {
            kind: HstsKind::None,
        }
    }

    /// Upgrade a fixed set of hosts. Matching is suffix-aware, so listing
    /// `example.com` also upgrades `api.example.com` (HSTS `includeSubDomains`).
    /// Set `preloaded_tlds=True` to also upgrade every host under a gTLD Chrome
    /// preloads in full (`.dev`, `.app`, …).
    #[staticmethod]
    #[pyo3(signature = (hosts, preloaded_tlds=false))]
    fn static_(hosts: Vec<String>, preloaded_tlds: bool) -> Self {
        PyHsts {
            kind: HstsKind::Static {
                hosts,
                preloaded_tlds,
            },
        }
    }

    /// Learn HSTS hosts from `Strict-Transport-Security` response headers within
    /// the session, mirroring a browser's dynamic HSTS store. Optionally
    /// pre-seed with known HSTS hosts (e.g. replaying a prior session's state).
    #[staticmethod]
    #[pyo3(signature = (seed=None))]
    fn dynamic(seed: Option<Vec<String>>) -> Self {
        PyHsts {
            kind: HstsKind::Dynamic {
                seed: seed.unwrap_or_default(),
            },
        }
    }
}

impl PyHsts {
    /// Apply this policy to a session builder. Each upstream policy is a
    /// distinct concrete type implementing `HstsPolicy`; the builder wraps it in
    /// an `Arc<dyn HstsPolicy>` internally.
    pub(crate) fn apply(
        &self,
        builder: lkrequest::session::SessionBuilder,
    ) -> lkrequest::session::SessionBuilder {
        match &self.kind {
            HstsKind::None => builder.hsts_policy(lkrequest::hsts::NoHsts),
            HstsKind::Static {
                hosts,
                preloaded_tlds,
            } => {
                let policy = lkrequest::hsts::StaticHsts::new(hosts.clone());
                let policy = if *preloaded_tlds {
                    policy.with_preloaded_tlds()
                } else {
                    policy
                };
                builder.hsts_policy(policy)
            }
            HstsKind::Dynamic { seed } => {
                if seed.is_empty() {
                    builder.hsts_policy(lkrequest::hsts::DynamicHsts::new())
                } else {
                    builder.hsts_policy(lkrequest::hsts::DynamicHsts::with_seed(seed.clone()))
                }
            }
        }
    }
}
