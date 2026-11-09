//! `Multipart` and `Part` pyclasses for building `multipart/form-data` request
//! bodies from text fields and file uploads.

use bytes::Bytes;
use pyo3::prelude::*;

/// The fields of a form, kept as they were added so that each request encodes
/// a fresh upstream `Multipart`: upstream's is used up by the request it is
/// sent with, and a new one gets a boundary of its own, as every submission of
/// a form in a browser does.
#[pyclass(name = "Multipart")]
pub struct PyMultipart {
    fields: Vec<Field>,
}

/// One field as it was added, turned into upstream's when a request is built.
enum Field {
    Text {
        name: String,
        value: String,
    },
    File {
        name: String,
        filename: String,
        content_type: String,
        data: Bytes,
    },
    Part(PartFields),
}

impl PyMultipart {
    /// An upstream `Multipart` holding every field added so far.
    pub(crate) fn build(&self) -> lkrequest::multipart::Multipart {
        self.fields.iter().fold(
            lkrequest::multipart::Multipart::new(),
            |form, field| match field {
                Field::Text { name, value } => form.text(name, value),
                Field::File {
                    name,
                    filename,
                    content_type,
                    data,
                } => form.file(name, filename, content_type, data.clone()),
                Field::Part(part) => form.part(part.build()),
            },
        )
    }
}

#[pymethods]
impl PyMultipart {
    #[new]
    fn new() -> Self {
        PyMultipart { fields: Vec::new() }
    }

    fn text(&mut self, name: &str, value: &str) {
        self.fields.push(Field::Text {
            name: name.to_string(),
            value: value.to_string(),
        });
    }

    fn file(&mut self, name: &str, filename: &str, content_type: &str, data: Vec<u8>) {
        self.fields.push(Field::File {
            name: name.to_string(),
            filename: filename.to_string(),
            content_type: content_type.to_string(),
            data: data.into(),
        });
    }

    /// Add a `Part`, as it is now, for what `text()` and `file()` cannot say,
    /// such as binary data without a filename.
    fn part(&mut self, part: PyRef<'_, PyPart>) {
        self.fields.push(Field::Part(part.fields.clone()));
    }

    fn __repr__(&self) -> String {
        "<Multipart>".to_string()
    }
}

/// What an upstream `Part` is built from, which happens afresh for every
/// request, so one `Part` can go into any number of forms.
#[derive(Clone)]
struct PartFields {
    name: String,
    body: Bytes,
    filename: Option<String>,
    content_type: Option<String>,
}

impl PartFields {
    fn build(&self) -> lkrequest::multipart::Part {
        let mut part = lkrequest::multipart::Part::new(&self.name, self.body.clone());
        if let Some(filename) = &self.filename {
            part = part.filename(filename);
        }
        if let Some(content_type) = &self.content_type {
            part = part.content_type(content_type);
        }
        part
    }
}

#[pyclass(name = "Part")]
pub struct PyPart {
    fields: PartFields,
}

#[pymethods]
impl PyPart {
    #[new]
    fn new(name: &str, body: Vec<u8>) -> Self {
        PyPart {
            fields: PartFields {
                name: name.to_string(),
                body: body.into(),
                filename: None,
                content_type: None,
            },
        }
    }

    fn filename(&mut self, filename: &str) {
        self.fields.filename = Some(filename.to_string());
    }

    fn content_type(&mut self, ct: &str) {
        self.fields.content_type = Some(ct.to_string());
    }
}
