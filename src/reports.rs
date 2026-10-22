//! Batch JWS verification with explicit per-signature candidate selection.
use crate::{category_name, error, json, parse, signature_key, InvalidJWSObject, RustError};
use jose_rs::jws::json::{FlattenedJws, GeneralJws};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::json;
use std::collections::HashMap;

type BatchResult = (Option<Py<PyBytes>>, String);

struct Failure {
    message: String,
    category: String,
    authentication_failure: bool,
}

impl Failure {
    fn from_rust(error: RustError) -> Self {
        Self {
            message: error.to_string(),
            category: category_name(&error).to_owned(),
            authentication_failure: error.is_authentication_failure(),
        }
    }

    fn from_python(error: PyErr) -> Self {
        Python::attach(|py| {
            let value = error.value(py);
            Self {
                message: error.to_string(),
                category: value
                    .getattr("category")
                    .and_then(|v| v.extract())
                    .unwrap_or_else(|_| "invalid_structure".to_owned()),
                authentication_failure: value
                    .getattr("authentication_failure")
                    .and_then(|v| v.extract())
                    .unwrap_or(false),
            }
        })
    }
}

fn record_failure(previous: &mut Option<Failure>, current: Failure) {
    // Metadata/selection errors from later keys must not hide an actual mismatch.
    if !previous.as_ref().is_some_and(|e| e.authentication_failure)
        || current.authentication_failure
    {
        *previous = Some(current);
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn verify_batch(
    py: Python<'_>,
    keys: Vec<String>,
    token: String,
    detached: Option<Vec<u8>>,
    understood: Vec<String>,
    candidates: Vec<Vec<usize>>,
    all: bool,
) -> PyResult<BatchResult> {
    let (payload, report) = py.detach(move || {
        if token.len() > jose_rs::MAX_TOKEN_BYTES {
            return Err(InvalidJWSObject::new_err("token too large"));
        }
        let input: GeneralJws = parse(&token)?;
        if input.signatures.is_empty()
            || input.signatures.len() > jose_rs::jws::json::MAX_GENERAL_SIGNATURES
            || candidates.len() != input.signatures.len()
        {
            return Err(InvalidJWSObject::new_err("invalid signature or candidate count"));
        }
        let opts = jose_rs::jws::VerifyOptions {
            understood_crit: understood,
        };
        let mut verifiers = HashMap::new();
        let mut payload = None;
        let mut results = Vec::with_capacity(input.signatures.len());
        let mut flat = FlattenedJws {
            payload: input.payload,
            protected: String::new(),
            header: None,
            signature: String::new(),
        };
        let mut mode = None;
        // Whole-document encoding policy must hold even after an early Any success.
        for entry in &input.signatures {
            let bytes = jose_rs::base64url::decode(&entry.protected).map_err(error)?;
            let header: jose_rs::JoseHeader = serde_json::from_slice(&bytes)
                .map_err(|_| InvalidJWSObject::new_err("invalid protected header"))?;
            let current = header
                .extra
                .get("b64")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if mode.is_some_and(|previous| previous != current) {
                return Err(InvalidJWSObject::new_err("inconsistent payload encodings"));
            }
            mode = Some(current);
        }
        for (index, entry) in input.signatures.into_iter().enumerate() {
            let bytes = jose_rs::base64url::decode(&entry.protected).map_err(error)?;
            let header: jose_rs::JoseHeader = serde_json::from_slice(&bytes)
                .map_err(|_| InvalidJWSObject::new_err("invalid protected header"))?;
            let protected: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| InvalidJWSObject::new_err("invalid protected header"))?;
            let unprotected = entry.header.clone();
            flat.protected = entry.protected;
            flat.header = entry.header;
            flat.signature = entry.signature;
            let mut verified = false;
            let mut attempted = false;
            let mut key_index = None;
            let mut failure = None;
            let requested = all || payload.is_none();
            if requested {
                for &candidate in &candidates[index] {
                    let s = keys
                        .get(candidate)
                        .ok_or_else(|| InvalidJWSObject::new_err("invalid candidate index"))?;
                    let identity = (candidate, header.alg.clone());
                    if !verifiers.contains_key(&identity) {
                        let verifier = signature_key(s, &header, jose_rs::jwk::JwkOp::Verify)
                            .and_then(|(alg, sw)| {
                                kryptering::SoftwareVerifier::new(alg, sw)
                                    .map_err(|e| error(e.into()))
                            });
                        match verifier {
                            Ok(verifier) => {
                                verifiers.insert(identity.clone(), verifier);
                            }
                            Err(e) => {
                                record_failure(&mut failure, Failure::from_python(e));
                                continue;
                            }
                        }
                    }
                    attempted = true;
                    match jose_rs::jws::json::verify_flattened_opts(
                        &verifiers[&identity],
                        &flat,
                        detached.as_deref(),
                        &opts,
                    ) {
                        Ok(bytes) => {
                            if payload.is_none() {
                                payload = Some(bytes);
                            }
                            verified = true;
                            key_index = Some(candidate);
                            failure = None;
                            break;
                        }
                        Err(e) => record_failure(&mut failure, Failure::from_rust(e)),
                    }
                }
                if !verified && failure.is_none() {
                    failure = Some(Failure {
                        message: "no candidate key verified the signature".to_owned(),
                        category: "invalid_structure".to_owned(),
                        authentication_failure: false,
                    });
                }
            }
            let message = if requested {
                failure.as_ref().map(|e| e.message.as_str())
            } else {
                Some("not attempted: any-signature policy already satisfied")
            };
            results.push(json!({
                "index": index,
                "protected_header": protected,
                "unprotected_header": unprotected,
                "verified": verified,
                "attempted": attempted,
                "key_index": key_index,
                "error": message,
                "category": failure.as_ref().map(|e| e.category.as_str()),
                "authentication_failure": failure.as_ref().is_some_and(|e| e.authentication_failure),
            }));
        }
        if all && !results.iter().all(|r| r["verified"] == true) {
            payload = None;
        }
        Ok((payload, json(&results)?))
    })?;
    Ok((payload.map(|b| PyBytes::new(py, &b).unbind()), report))
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_batch, m)?)?;
    Ok(())
}
