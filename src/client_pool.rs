//! `ClientPool` pyclass: rotates requests across multiple `Client` instances
//! using a round-robin or random strategy.

use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

use crate::client::PyClient;

enum RotationStrategy {
    RoundRobin,
    Random,
}

struct ClientPoolInner {
    clients: Vec<lkrequest::Client>,
    index: usize,
    strategy: RotationStrategy,
}

#[pyclass(name = "ClientPool")]
pub struct PyClientPool {
    inner: Arc<Mutex<ClientPoolInner>>,
}

#[pymethods]
impl PyClientPool {
    #[new]
    #[pyo3(signature = (clients, *, rotation="round_robin"))]
    fn new(clients: Vec<PyClient>, rotation: &str) -> PyResult<Self> {
        if clients.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "ClientPool requires at least one client",
            ));
        }
        let strategy = match rotation {
            "round_robin" => RotationStrategy::RoundRobin,
            "random" => RotationStrategy::Random,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown rotation strategy: '{}'. Use: round_robin, random",
                    rotation
                )))
            }
        };
        Ok(PyClientPool {
            inner: Arc::new(Mutex::new(ClientPoolInner {
                clients: clients.into_iter().map(|c| c.inner).collect(),
                index: 0,
                strategy,
            })),
        })
    }

    fn acquire(&self) -> PyResult<PyClient> {
        let mut pool = self
            .inner
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
        let (client, idx) = match pool.strategy {
            RotationStrategy::RoundRobin => {
                let idx = pool.index % pool.clients.len();
                pool.index = pool.index.wrapping_add(1);
                (pool.clients[idx].clone(), idx)
            }
            RotationStrategy::Random => {
                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};
                let idx = RandomState::new().build_hasher().finish() as usize % pool.clients.len();
                (pool.clients[idx].clone(), idx)
            }
        };
        tracing::debug!(
            index = idx,
            total = pool.clients.len(),
            "client_pool.acquire"
        );
        Ok(PyClient { inner: client })
    }

    fn add(&self, client: PyClient) -> PyResult<()> {
        let mut pool = self
            .inner
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?;
        pool.clients.push(client.inner);
        Ok(())
    }

    fn __len__(&self) -> PyResult<usize> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Lock poisoned"))?
            .clients
            .len())
    }

    fn __repr__(&self) -> String {
        let pool = match self.inner.lock() {
            Ok(p) => p,
            Err(_) => return "<ClientPool (lock poisoned)>".to_string(),
        };
        let strategy = match pool.strategy {
            RotationStrategy::RoundRobin => "round_robin",
            RotationStrategy::Random => "random",
        };
        format!(
            "ClientPool(clients={}, rotation='{}')",
            pool.clients.len(),
            strategy,
        )
    }
}
