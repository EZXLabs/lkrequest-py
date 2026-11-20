//! What this build of the module offers: the optional features it was
//! compiled with, and the browser presets it knows.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// The optional features, by their Cargo names, and whether this build has
/// each.
const FEATURES: [(&str, bool); 5] = [
    ("quic-h3", cfg!(feature = "quic-h3")),
    ("masque", cfg!(feature = "masque")),
    ("doh", cfg!(feature = "doh")),
    ("telemetry", cfg!(feature = "telemetry")),
    ("synthetic-fp", cfg!(feature = "synthetic-fp")),
];

/// Which optional features this build has, by their Cargo names. The wheels
/// on PyPI have every one; a build from source may lack some.
#[pyfunction]
pub(crate) fn features(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let features = PyDict::new(py);
    for (name, enabled) in FEATURES {
        features.set_item(name, enabled)?;
    }
    Ok(features)
}

/// A browser preset, and the upstream function that builds it.
struct Preset {
    name: &'static str,
    browser: &'static str,
    build: fn() -> lkrequest::preset::ClientPreset,
}

/// The preset table, named after upstream's constructors so that a name and
/// the preset it stands for cannot drift apart.
macro_rules! presets {
    ($($browser:literal: [$($preset:ident),+ $(,)?]),+ $(,)?) => {
        &[$($(
            Preset {
                name: stringify!($preset),
                browser: $browser,
                build: lkrequest::preset::$preset,
            },
        )+)+]
    };
}

/// Every browser preset, in a stable order: the names `Client.<name>()`,
/// `tls_profile=` and `h2_profile=` take. A sync that adds a preset upstream
/// adds it here as well; `tests/test_build_info.py` checks that they agree.
const PRESETS: &[Preset] = presets! {
    "chrome": [
        chrome_131, chrome_144, chrome_145, chrome_146, chrome_147, chrome_148,
        chrome_149, chrome_150, chrome_151, chrome_152, chrome_153, chrome_154,
        chrome_155, chrome_156, chrome_157, chrome_158,
    ],
    "firefox": [firefox_133, firefox_147, firefox_156],
    "safari": [safari_18, safari_26],
};

/// The ClientHello the named preset sends inside QUIC, as `Client.<name>()`
/// does: its QUIC-TLS profile, or its TLS profile for a preset without one.
/// `None` for a name that is not a preset.
pub(crate) fn preset_quic_tls_profile(name: &str) -> Option<lktls::profile::TlsProfile> {
    PRESETS
        .iter()
        .find(|preset| preset.name == name)
        .map(|preset| {
            let preset = (preset.build)();
            preset.quic_tls_profile.unwrap_or(preset.tls_profile)
        })
}

/// The preset names, in `list_presets()` order.
pub(crate) fn preset_names() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|preset| preset.name)
}

/// The browser presets this build knows, in a stable order, each a dict of
/// `name`, `browser` and `http3`: whether its client speaks HTTP/3 here.
#[pyfunction]
pub(crate) fn list_presets(py: Python<'_>) -> PyResult<Vec<Bound<'_, PyDict>>> {
    PRESETS
        .iter()
        .map(|preset| {
            let info = PyDict::new(py);
            info.set_item("name", preset.name)?;
            info.set_item("browser", preset.browser)?;
            info.set_item("http3", (preset.build)().quic_profile.is_some())?;
            Ok(info)
        })
        .collect()
}

/// A browser preset as a complete profile bundle, lkrequest's v2 preset
/// JSON, which `Client.from_preset_json()` reads back. The name is one
/// `list_presets()` gives.
#[pyfunction]
pub(crate) fn export_preset_json(name: &str) -> PyResult<String> {
    let preset = PRESETS
        .iter()
        .find(|preset| preset.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = PRESETS.iter().map(|preset| preset.name).collect();
            PyValueError::new_err(format!(
                "Unknown preset: '{name}'. Available: {}",
                names.join(", ")
            ))
        })?;
    lkrequest::preset::PresetDocument::from_preset(name, &(preset.build)())
        .and_then(|document| document.to_json_string())
        .map_err(|e| preset_error("Cannot export preset", &e))
}

/// A `ValueError` for a bundle upstream refused, saying what was being done:
/// upstream's message names the reason and the JSON pointer of the value.
pub(crate) fn preset_error(context: &str, error: &lkrequest::preset::PresetError) -> PyErr {
    PyValueError::new_err(format!("{context}: {error}"))
}
