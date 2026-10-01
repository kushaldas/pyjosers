//! PKCS#11 handles remain in Rust and retain their session for their full lifetime.
use crate::{error, json, parse, JoseHeader, JwsAlgorithm};
use kryptering::pkcs11 as pk;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::Path;
use std::sync::Arc;

/// Loaded PKCS#11 module with unambiguous token selection.
#[pyclass(module = "pyjosers.hsm")]
struct Pkcs11Provider {
    inner: pk::Pkcs11Provider,
}
#[pymethods]
impl Pkcs11Provider {
    #[new]
    fn new(path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: pk::Pkcs11Provider::new(Path::new(path)).map_err(|e| error(e.into()))?,
        })
    }
    /// Select a token by label and optional serial number.
    #[staticmethod]
    #[pyo3(signature = (path, label, serial=None))]
    fn with_token(path: &str, label: &str, serial: Option<&str>) -> PyResult<Self> {
        Ok(Self {
            inner: pk::Pkcs11Provider::new_with_token(Path::new(path), label, serial)
                .map_err(|e| error(e.into()))?,
        })
    }
    /// Select an initialized slot by numeric identifier.
    #[staticmethod]
    fn with_slot_id(path: &str, slot_id: u64) -> PyResult<Self> {
        Ok(Self {
            inner: pk::Pkcs11Provider::new_with_slot_id(Path::new(path), slot_id)
                .map_err(|e| error(e.into()))?,
        })
    }
    #[getter]
    fn slot_id(&self) -> u64 {
        self.inner.slot_id()
    }
    /// Authenticate a session. The PIN is never included in representations.
    fn open_session(&self, py: Python<'_>, pin: String) -> PyResult<Pkcs11Session> {
        py.detach(|| {
            Ok(Pkcs11Session {
                inner: self.inner.open_session(&pin).map_err(|e| error(e.into()))?,
            })
        })
    }
}
/// Authenticated session; signing handles keep the underlying session alive.
#[pyclass(module = "pyjosers.hsm")]
struct Pkcs11Session {
    inner: pk::Pkcs11Session,
}
/// Token-resident asymmetric or HMAC signing key.
#[pyclass(module = "pyjosers.hsm")]
struct Pkcs11Signer {
    inner: Arc<dyn kryptering::Signer>,
}
#[pymethods]
impl Pkcs11Signer {
    #[new]
    fn new(session: &Pkcs11Session, label: &str, alg: &str) -> PyResult<Self> {
        let a = JwsAlgorithm::from_str(alg)
            .and_then(|a| a.to_crypto())
            .map_err(error)?;
        let inner: Arc<dyn kryptering::Signer> =
            if matches!(a, kryptering::SignatureAlgorithm::Hmac(_)) {
                Arc::new(
                    pk::Pkcs11HmacSigner::new(&session.inner, label, a)
                        .map_err(|e| error(e.into()))?,
                )
            } else {
                Arc::new(
                    pk::Pkcs11Signer::new(&session.inner, label, a).map_err(|e| error(e.into()))?,
                )
            };
        Ok(Self { inner })
    }
    /// Create a flattened JWS; arguments use the private native JSON protocol.
    #[allow(clippy::too_many_arguments)] // Mirrors the software signing boundary.
    #[pyo3(signature = (payload, protected, unprotected, detached, understood, allow_key_reference_headers=false))]
    fn _sign(
        &self,
        py: Python<'_>,
        payload: Vec<u8>,
        protected: String,
        unprotected: Option<String>,
        detached: bool,
        understood: Vec<String>,
        allow_key_reference_headers: bool,
    ) -> PyResult<String> {
        py.detach(|| {
            let h: JoseHeader = parse(&protected)?;
            let opts = jose_rs::jws::SignOptions::new()
                .with_b64(h.extra.get("b64").and_then(|v| v.as_bool()).unwrap_or(true))
                .with_understood_crit(understood)
                .with_key_reference_headers(allow_key_reference_headers);
            let u = unprotected.as_deref().map(parse).transpose()?;
            let j = if detached {
                jose_rs::jws::json::sign_flattened_detached_opts(
                    self.inner.as_ref(),
                    &payload,
                    &h,
                    u,
                    &opts,
                )
            } else {
                jose_rs::jws::json::sign_flattened_opts(self.inner.as_ref(), &payload, &h, u, &opts)
            }
            .map_err(error)?;
            json(&j)
        })
    }
}
/// Token-resident asymmetric or HMAC verification key.
#[pyclass(module = "pyjosers.hsm")]
struct Pkcs11Verifier {
    inner: Arc<dyn kryptering::Verifier>,
}
#[pymethods]
impl Pkcs11Verifier {
    #[new]
    fn new(session: &Pkcs11Session, label: &str, alg: &str) -> PyResult<Self> {
        let a = JwsAlgorithm::from_str(alg)
            .and_then(|a| a.to_crypto())
            .map_err(error)?;
        let inner: Arc<dyn kryptering::Verifier> =
            if matches!(a, kryptering::SignatureAlgorithm::Hmac(_)) {
                Arc::new(
                    pk::Pkcs11HmacSigner::new(&session.inner, label, a)
                        .map_err(|e| error(e.into()))?,
                )
            } else {
                Arc::new(
                    pk::Pkcs11Verifier::new(&session.inner, label, a)
                        .map_err(|e| error(e.into()))?,
                )
            };
        Ok(Self { inner })
    }
    fn _verify(
        &self,
        py: Python<'_>,
        token: String,
        detached: Option<Vec<u8>>,
        understood: Vec<String>,
    ) -> PyResult<Py<PyBytes>> {
        let bytes = py.detach(|| {
            if token.len() > jose_rs::MAX_TOKEN_BYTES {
                return Err(crate::InvalidJWSObject::new_err("token too large"));
            }
            jose_rs::jws::json::verify_flattened_opts(
                self.inner.as_ref(),
                &parse(&token)?,
                detached.as_deref(),
                &jose_rs::jws::VerifyOptions {
                    understood_crit: understood,
                },
            )
            .map_err(error)
        })?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }
}
pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Pkcs11Provider>()?;
    m.add_class::<Pkcs11Session>()?;
    m.add_class::<Pkcs11Signer>()?;
    m.add_class::<Pkcs11Verifier>()?;
    Ok(())
}
