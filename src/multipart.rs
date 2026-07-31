//! `Multipart` and `Part` pyclasses for building `multipart/form-data` request
//! bodies from text fields and file uploads.

use pyo3::prelude::*;

#[pyclass(name = "Multipart")]
pub struct PyMultipart {
    pub(crate) inner: lkrequest::multipart::Multipart,
}

#[pymethods]
impl PyMultipart {
    #[new]
    fn new() -> Self {
        PyMultipart {
            inner: lkrequest::multipart::Multipart::new(),
        }
    }

    fn text(mut slf: PyRefMut<'_, Self>, name: &str, value: &str) -> PyResult<()> {
        let mp = std::mem::replace(&mut slf.inner, lkrequest::multipart::Multipart::new());
        slf.inner = mp.text(name, value);
        Ok(())
    }

    fn file(
        mut slf: PyRefMut<'_, Self>,
        name: &str,
        filename: &str,
        content_type: &str,
        data: Vec<u8>,
    ) -> PyResult<()> {
        let mp = std::mem::replace(&mut slf.inner, lkrequest::multipart::Multipart::new());
        slf.inner = mp.file(name, filename, content_type, data);
        Ok(())
    }

    fn __repr__(&self) -> String {
        "<Multipart>".to_string()
    }
}

#[pyclass(name = "Part")]
pub struct PyPart {
    pub(crate) inner: Option<lkrequest::multipart::Part>,
}

#[pymethods]
impl PyPart {
    #[new]
    fn new(name: &str, body: Vec<u8>) -> Self {
        PyPart {
            inner: Some(lkrequest::multipart::Part::new(name, body)),
        }
    }

    fn filename(mut slf: PyRefMut<'_, Self>, filename: &str) -> PyResult<()> {
        if let Some(part) = slf.inner.take() {
            slf.inner = Some(part.filename(filename));
        }
        Ok(())
    }

    fn content_type(mut slf: PyRefMut<'_, Self>, ct: &str) -> PyResult<()> {
        if let Some(part) = slf.inner.take() {
            slf.inner = Some(part.content_type(ct));
        }
        Ok(())
    }
}
