//! Trust Anchor Identifiers (draft-ietf-tls-trust-anchor-ids): the client
//! options, the identity of a root certificate, and the negotiation snapshot
//! a request's `diagnostics` carries.

use std::collections::BTreeMap;

use lkrequest::{
    TrustAnchorAdvertisement, TrustAnchorBinding, TrustAnchorId, TrustAnchorInfo,
    TrustAnchorPolicy, TrustAnchorRecovery,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// `Client(trust_anchor_advertisement=..., trust_anchor_recovery=...)`, or
/// `None` when neither is given and upstream's default applies.
pub(crate) fn parse_policy(
    advertisement: Option<&str>,
    recovery: Option<&str>,
) -> PyResult<Option<TrustAnchorPolicy>> {
    if advertisement.is_none() && recovery.is_none() {
        return Ok(None);
    }
    let advertisement = match advertisement {
        None | Some("profile") => TrustAnchorAdvertisement::Profile,
        Some("trusted") => TrustAnchorAdvertisement::Trusted,
        Some(other) => {
            return Err(PyValueError::new_err(format!(
                "trust_anchor_advertisement must be 'profile' or 'trusted', got {other:?}"
            )));
        }
    };
    let recovery = match recovery {
        None | Some("disabled") => TrustAnchorRecovery::Disabled,
        Some("once") => TrustAnchorRecovery::Once,
        Some(other) => {
            return Err(PyValueError::new_err(format!(
                "trust_anchor_recovery must be 'disabled' or 'once', got {other:?}"
            )));
        }
    };
    Ok(Some(TrustAnchorPolicy {
        advertisement,
        recovery,
    }))
}

/// `Client(trust_anchor_bindings={id: anchor_identity})`. The IDs are checked
/// here; whether each identity names a root the client trusts is checked when
/// the client is built.
pub(crate) fn parse_bindings(
    bindings: BTreeMap<String, String>,
) -> PyResult<Vec<TrustAnchorBinding>> {
    bindings
        .into_iter()
        .map(|(id, anchor_identity)| {
            let id = TrustAnchorId::from_hex(&id).map_err(|err| {
                // Upstream reports a bad ID as the decode_error alert a bad
                // peer list gets; only its reason applies to a configured one.
                let reason = match &err {
                    lktls::error::TlsError::LocalAlert { message, .. } => message.clone(),
                    other => other.to_string(),
                };
                PyValueError::new_err(format!("invalid trust anchor ID {id:?}: {reason}"))
            })?;
            Ok(TrustAnchorBinding {
                anchor_identity,
                id,
            })
        })
        .collect()
}

/// The identity of the root certificate `der`, to bind a trust anchor ID to.
/// It adds no trust: the root must still be in the client's store.
#[pyfunction]
pub(crate) fn trust_anchor_identity(der: &[u8]) -> PyResult<String> {
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(der).map_err(|err| {
        PyValueError::new_err(format!("not a usable DER root certificate: {err}"))
    })?;
    Ok(lktls::trust_anchor::anchor_identity(&anchor))
}

/// `diagnostics["trust_anchor"]`: the negotiation on the connection a request
/// opened, with the first attempt nested in `previous_attempt` after a recovery.
pub(crate) fn info_dict<'py>(
    py: Python<'py>,
    info: &TrustAnchorInfo,
) -> PyResult<Bound<'py, PyDict>> {
    let hex = |ids: &[TrustAnchorId]| ids.iter().map(TrustAnchorId::to_hex).collect::<Vec<_>>();
    let d = PyDict::new(py);
    d.set_item("requested_ids", hex(&info.requested_ids))?;
    d.set_item("available_ids", hex(&info.available_ids))?;
    d.set_item("matched_request", info.matched_request)?;
    d.set_item("verified_anchor", info.verified_anchor.clone())?;
    d.set_item("authenticated", info.authenticated)?;
    d.set_item("ech_rejected", info.ech_rejected)?;
    d.set_item("recovered", info.recovered)?;
    d.set_item("failure", info.failure.clone())?;
    d.set_item("recovery_eligible", info.recovery_eligible)?;
    let previous = info
        .previous_attempt
        .as_deref()
        .map(|attempt| info_dict(py, attempt))
        .transpose()?;
    d.set_item("previous_attempt", previous)?;
    Ok(d)
}
