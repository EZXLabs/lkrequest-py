//! Fingerprint randomization policy bindings (`Randomize` / `Layers`).
//!
//! [`PyRandomize`] wraps `lkrequest::Randomize` — the policy passed to
//! `Client(randomize=...)` / `BlockingClient(randomize=...)` that selects *how
//! much* of the client fingerprint varies and *toward what* (real vs synthetic).
//!
//! Tiers 0/1 (`off` / `extension_order`) are always available. The synthetic
//! tiers 3a/3b (`recombine` / `full`, optionally restricted with a [`PyLayers`]
//! mask) require building the extension with the `synthetic-fp` feature
//! (`maturin develop --features synthetic-fp`); they synthesize fingerprints
//! that match *no* real browser, so they are an escape hatch for negative-model
//! / blocklist targets only.
//!
//! A synthetic policy is materialized per session: each `client.session()` draws
//! its own OS seed and presents a distinct (capability-safe) identity, with its
//! own TLS/QUIC ticket cache so two sessions cannot be linked by resumption.

use pyo3::prelude::*;

/// A fingerprint randomization policy. Build one with a named tier constructor
/// and pass it to `Client(randomize=...)` / `BlockingClient(randomize=...)`.
#[pyclass(name = "Randomize")]
#[derive(Clone)]
pub struct PyRandomize {
    pub(crate) inner: lkrequest::Randomize,
    /// Human-readable tier label, used only for `__repr__`.
    label: String,
}

#[pymethods]
impl PyRandomize {
    /// Tier 0 — no added randomization. The preset's own authentic
    /// per-connection behavior (e.g. Chrome's native extension shuffle) still
    /// applies; this adds nothing on top. This is the default.
    #[staticmethod]
    fn off() -> Self {
        Self {
            inner: lkrequest::Randomize::off(),
            label: "off".to_string(),
        }
    }

    /// Tier 1 — force per-connection TLS extension-order permutation
    /// (BoringSSL-style; GREASE bookends pinned, ``pre_shared_key`` last).
    ///
    /// Drifts JA3 per connection while staying a real browser — useful against
    /// per-JA3 blocklists / rate-limits. JA4 is unaffected (it sorts
    /// extensions). This is the safe single-layer option: it never produces a
    /// non-browser shape, so it works against allowlist targets too.
    #[staticmethod]
    fn extension_order() -> Self {
        Self {
            inner: lkrequest::Randomize::extension_order(),
            label: "extension_order".to_string(),
        }
    }

    /// Tier 3a — one novel-but-capability-safe synthetic identity per session,
    /// recombined from the real-preset corpus across **all** layers
    /// (TLS + H2 + H3).
    ///
    /// The result is structurally valid and negotiable but matches no real
    /// browser. Use only against negative-model (blocklist) targets — against an
    /// allowlist this fails instantly. Requires the ``synthetic-fp`` build
    /// feature.
    #[cfg(feature = "synthetic-fp")]
    #[staticmethod]
    fn recombine() -> Self {
        Self {
            inner: lkrequest::Randomize::recombine(),
            label: "recombine".to_string(),
        }
    }

    /// Tier 3a restricted to a [`Layers`](PyLayers) subset — synthesize only the
    /// selected layers; unselected layers keep the client's real preset.
    ///
    /// [`recombine`](Self::recombine) (all layers) is the safe default — "no
    /// layer left constant". A synthesized layer paired with constant
    /// real-browser layers is itself an anomalous combination, easier to flag,
    /// so a subset is a deliberate trade-off. Requires ``synthetic-fp``.
    #[cfg(feature = "synthetic-fp")]
    #[staticmethod]
    fn recombine_layers(layers: PyLayers) -> Self {
        Self {
            inner: lkrequest::Randomize::recombine_layers(layers.inner),
            label: format!("recombine_layers({:?})", layers.inner),
        }
    }

    /// Tier 3b — the widest synthesis: like [`recombine`](Self::recombine), but
    /// the advertise-only layers (H2 SETTINGS, QUIC transport-parameter values)
    /// additionally take novel **out-of-corpus** numbers.
    ///
    /// Maximally divergent from any real browser — use only against
    /// negative-model (blocklist) targets. Requires ``synthetic-fp``.
    #[cfg(feature = "synthetic-fp")]
    #[staticmethod]
    fn full() -> Self {
        Self {
            inner: lkrequest::Randomize::full(),
            label: "full".to_string(),
        }
    }

    /// [`full`](Self::full) restricted to a [`Layers`](PyLayers) subset — see
    /// [`recombine_layers`](Self::recombine_layers) for the per-layer trade-off.
    /// ``Layers.TLS`` alone behaves identically to ``recombine_layers(Layers.TLS)``
    /// (TLS has no wider degree). Requires ``synthetic-fp``.
    #[cfg(feature = "synthetic-fp")]
    #[staticmethod]
    fn full_layers(layers: PyLayers) -> Self {
        Self {
            inner: lkrequest::Randomize::full_layers(layers.inner),
            label: format!("full_layers({:?})", layers.inner),
        }
    }

    /// Set the [`NegotiabilityFloor`](PyNegotiabilityFloor) for this synthetic
    /// policy — the sig-alg guarantee applied after recombination so every
    /// synthesized ClientHello can still complete a real TLS handshake. No-op for
    /// ``off`` / ``extension_order``; defaults to ``NegotiabilityFloor.UNIVERSAL``.
    /// Returns a new policy (does not mutate the receiver). Requires ``synthetic-fp``.
    #[cfg(feature = "synthetic-fp")]
    fn negotiability(&self, floor: PyNegotiabilityFloor) -> Self {
        Self {
            inner: self.inner.clone().negotiability(floor.inner.clone()),
            label: format!("{}.negotiability({})", self.label, floor.__repr__()),
        }
    }

    fn __repr__(&self) -> String {
        format!("Randomize.{}", self.label)
    }
}

/// Which fingerprint layers a synthetic ([`PyRandomize::recombine_layers`] /
/// [`PyRandomize::full_layers`]) policy synthesizes. Compose masks with ``|``
/// (e.g. ``Layers.TLS | Layers.H2``). Only available when the extension is built
/// with the ``synthetic-fp`` feature.
#[cfg(feature = "synthetic-fp")]
#[pyclass(name = "Layers", eq)]
#[derive(Clone, Copy, PartialEq)]
pub struct PyLayers {
    pub(crate) inner: lkrequest::Layers,
}

#[cfg(feature = "synthetic-fp")]
#[pymethods]
impl PyLayers {
    /// The TLS ClientHello layer (JA3/JA4); also drives the QUIC-native TLS.
    #[classattr]
    const TLS: PyLayers = PyLayers {
        inner: lkrequest::Layers::TLS,
    };
    /// The HTTP/2 fingerprint layer (SETTINGS + pseudo-header order).
    #[classattr]
    const H2: PyLayers = PyLayers {
        inner: lkrequest::Layers::H2,
    };
    /// The QUIC transport params + HTTP/3 fingerprint layer (needs ``quic-h3``).
    #[classattr]
    const QUIC: PyLayers = PyLayers {
        inner: lkrequest::Layers::QUIC,
    };

    /// All fingerprint layers — the safe "no layer left constant" default.
    #[staticmethod]
    fn all() -> PyLayers {
        PyLayers {
            inner: lkrequest::Layers::all(),
        }
    }

    /// Union of two layer masks (``Layers.TLS | Layers.H2``).
    fn __or__(&self, other: &PyLayers) -> PyLayers {
        PyLayers {
            inner: self.inner | other.inner,
        }
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// The signature-algorithm negotiability floor for a synthetic
/// [`Randomize`](PyRandomize) policy — the sig-alg guarantee applied *after*
/// recombination so every synthesized ClientHello can still complete a real TLS
/// handshake. Pass to [`Randomize.negotiability`](PyRandomize::negotiability).
/// Only available when the extension is built with the ``synthetic-fp`` feature.
#[cfg(feature = "synthetic-fp")]
#[pyclass(name = "NegotiabilityFloor", eq)]
#[derive(Clone, PartialEq)]
pub struct PyNegotiabilityFloor {
    pub(crate) inner: lkrequest::NegotiabilityFloor,
}

#[cfg(feature = "synthetic-fp")]
#[pymethods]
impl PyNegotiabilityFloor {
    /// Recombine sig algs freely, then guarantee the universal-accept core —
    /// maximum diversity, connects to any server. The resulting sig-alg list
    /// matches no single real browser, so a shape-modeling detector could flag
    /// it. The safe default.
    #[classattr]
    #[allow(non_snake_case)]
    fn UNIVERSAL() -> PyNegotiabilityFloor {
        PyNegotiabilityFloor {
            inner: lkrequest::NegotiabilityFloor::Universal,
        }
    }

    /// Keep the chosen base preset's real ``signature_algorithms`` unchanged —
    /// negotiable AND browser-plausible (no synthetic sig-alg anomaly). Prefer
    /// this against fingerprint-anomaly detectors; other layers still randomize.
    #[classattr]
    #[allow(non_snake_case)]
    fn PRESET_FAMILY() -> PyNegotiabilityFloor {
        PyNegotiabilityFloor {
            inner: lkrequest::NegotiabilityFloor::PresetFamily,
        }
    }

    /// Recombine freely, then guarantee a caller-supplied set of sig-alg code
    /// points. **Advanced**: if the set does not cover the target certificate's
    /// key type, negotiation fails — the caller owns negotiability.
    #[staticmethod]
    fn custom(sig_algs: Vec<u16>) -> PyNegotiabilityFloor {
        PyNegotiabilityFloor {
            inner: lkrequest::NegotiabilityFloor::Custom(sig_algs),
        }
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            lkrequest::NegotiabilityFloor::Universal => "NegotiabilityFloor.UNIVERSAL".to_string(),
            lkrequest::NegotiabilityFloor::PresetFamily => {
                "NegotiabilityFloor.PRESET_FAMILY".to_string()
            }
            lkrequest::NegotiabilityFloor::Custom(algs) => {
                format!("NegotiabilityFloor.custom({algs:?})")
            }
        }
    }
}
