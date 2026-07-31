// Re-export pyo3's compile-time configuration cfgs into this crate so we can
// gate code on the active Python ABI mode. With the `abi3-py39` pyo3 feature
// enabled, `Py_LIMITED_API` is set and the buffer-protocol surface on
// PyResponse is excluded (the limited ABI does not expose `Py_buffer`).
fn main() {
    pyo3_build_config::use_pyo3_cfgs();
}
