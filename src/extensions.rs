//! Key formats, capability reports and bounded JWK Set diagnostics.
use crate::{error, json, key, InvalidJWKValue, JoseError};
use jose_rs::{jwk, Password};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::json;
use zeroize::Zeroizing;

#[pyfunction]
fn capability_report() -> PyResult<String> {
    use jose_rs::capability::{self, Availability, Kind};
    let rows: Vec<_> = capability::all()
        .into_iter()
        .map(|row| {
            let (status, feature, reason) = match row.availability {
                Availability::Supported => ("supported", None, None),
                Availability::RequiresFeature(f) => ("requires_feature", Some(f), None),
                Availability::RecognizedNotSupported => ("unsupported", None, None),
                Availability::RefusedByPolicy(r) => ("refused", None, Some(r)),
            };
            let kind = match row.kind {
                Kind::JwsAlgorithm => "jws",
                Kind::JweKeyManagement => "jwe",
                Kind::JweContentEncryption => "encryption",
                Kind::KeyFormat => "format",
                Kind::KeyType => "key",
            };
            json!({
                "kind": kind,
                "identifier": row.identifier,
                "status": status,
                "available": row.availability.is_available(),
                "feature": feature,
                "reason": reason,
                "operations": row.operations.iter().map(|op| op.as_str()).collect::<Vec<_>>(),
                "note": row.note,
            })
        })
        .collect();
    json(&rows)
}

/// Password buffers become zeroizing Rust owners before cryptographic work.
#[pyfunction]
#[pyo3(signature = (data, format, password=None, max_iterations=10_000_000))]
fn key_read(
    py: Python<'_>,
    data: Vec<u8>,
    format: String,
    password: Option<Vec<u8>>,
    max_iterations: u32,
) -> PyResult<String> {
    let data = Zeroizing::new(data);
    let password = password.map(Password::from);
    py.detach(move || {
        let options = jwk::Pkcs8ReadOptions::default().with_max_iterations(max_iterations);
        let text = || {
            std::str::from_utf8(&data).map_err(|_| InvalidJWKValue::new_err("PEM must be UTF-8"))
        };
        let k = match (format.as_str(), password.as_ref()) {
            ("pem", Some(p)) => {
                jwk::jwk_from_encrypted_pkcs8_pem_with_options(text()?, p, &options)
            }
            ("pem", None) => jwk::jwk_from_pem(text()?),
            ("pkcs8", Some(p)) => {
                jwk::jwk_from_encrypted_pkcs8_der_with_options(&data, p, &options)
            }
            ("pkcs8", None) => jwk::jwk_from_pkcs8_der(&data),
            (_, Some(_)) => {
                return Err(InvalidJWKValue::new_err("passwords require PKCS#8 or PEM"))
            }
            ("spki", None) => jwk::jwk_from_spki_der(&data),
            ("pkcs1-private", None) => jwk::jwk_from_pkcs1_der(&data),
            ("pkcs1-public", None) => jwk::jwk_from_pkcs1_public_der(&data),
            ("sec1", None) => jwk::jwk_from_sec1_der(&data),
            ("certificate-pem", None) => jwk::public_jwk_from_certificate_pem(text()?),
            ("certificate-der", None) => jwk::public_jwk_from_certificate_der(&data),
            _ => return Err(InvalidJWKValue::new_err("unsupported key format")),
        }
        .map_err(error)?;
        json(&k)
    })
}

#[pyfunction]
#[pyo3(signature = (s, private, pem, password=None, scheme="aes256-cbc", iterations=600_000))]
fn key_write(
    py: Python<'_>,
    s: String,
    private: bool,
    pem: bool,
    password: Option<Vec<u8>>,
    scheme: &str,
    iterations: u32,
) -> PyResult<Py<PyBytes>> {
    let scheme = match scheme {
        "aes256-cbc" => jwk::Pkcs8Encryption::Aes256CbcPbkdf2HmacSha256 { iterations },
        "aes128-cbc" => jwk::Pkcs8Encryption::Aes128CbcPbkdf2HmacSha256 { iterations },
        _ => {
            return Err(InvalidJWKValue::new_err(
                "unsupported PKCS#8 encryption scheme",
            ))
        }
    };
    let password = password.map(Password::from);
    let s = Zeroizing::new(s);
    let bytes = py.detach(move || {
        let k = key(&s)?;
        if k.kty == "oct" || (k.kty == "OKP" && k.crv.as_deref() == Some("X25519")) {
            return Err(InvalidJWKValue::new_err(
                "this key type requires JWK JSON interchange",
            ));
        }
        if let Some(password) = password {
            if !private {
                return Err(InvalidJWKValue::new_err(
                    "only private keys can be password encrypted",
                ));
            }
            if pem {
                return jwk::encrypted_pkcs8_pem_from_jwk(&k, &password, &scheme)
                    .map(|s| Zeroizing::new(s.into_bytes()))
                    .map_err(error);
            }
            return jwk::encrypted_pkcs8_der_from_jwk(&k, &password, &scheme).map_err(error);
        }
        if pem {
            let text = if private {
                jwk::private_pem_from_jwk(&k)
            } else {
                jwk::public_pem_from_jwk(&k)
            }
            .map_err(error)?;
            Ok(Zeroizing::new(text.into_bytes()))
        } else {
            let sw = jwk::jwk_to_software_key(&k).map_err(error)?;
            if private {
                use pkcs8::der::Encode;
                let raw = sw.export_private().map_err(|e| error(e.into()))?;
                let mut info = pkcs8::PrivateKeyInfoRef::try_from(raw.as_slice())
                    .map_err(|_| InvalidJWKValue::new_err("invalid PKCS#8 export"))?;
                info.public_key = None;
                info.to_der()
                    .map(Zeroizing::new)
                    .map_err(|_| InvalidJWKValue::new_err("PKCS#8 encoding failed"))
            } else {
                sw.export_spki_der()
                    .map(Zeroizing::new)
                    .map_err(|e| error(e.into()))
            }
        }
    })?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

#[pyfunction]
fn thumbprint_uri(s: &str, hash_name: &str) -> PyResult<String> {
    let hash = jwk::thumbprint::ThumbprintHash::from_hash_name(hash_name)
        .ok_or_else(|| InvalidJWKValue::new_err("unsupported thumbprint hash"))?;
    jwk::thumbprint::thumbprint_uri(&key(s)?, hash).map_err(error)
}

#[pyfunction]
#[pyo3(signature = (uri, s=None))]
fn thumbprint_uri_parse(uri: &str, s: Option<&str>) -> PyResult<String> {
    let uri = jwk::thumbprint::JwkThumbprintUri::parse(uri).map_err(error)?;
    let matches = s
        .map(|s| uri.matches(&key(s)?).map_err(error))
        .transpose()?;
    json(
        &json!({"uri": uri.to_uri(), "hash_name": uri.hash().hash_name(), "thumbprint": uri.thumbprint(), "matches": matches}),
    )
}

#[pyfunction]
#[pyo3(signature = (own, peer, algorithm_id, length, apu=None, apv=None))]
fn derive_key(
    py: Python<'_>,
    own: String,
    peer: String,
    algorithm_id: String,
    length: usize,
    apu: Option<Vec<u8>>,
    apv: Option<Vec<u8>>,
) -> PyResult<Py<PyBytes>> {
    let bytes = py.detach(move || {
        // JOSE's supported derived key sizes; reject oversized allocation requests.
        if ![16, 24, 32, 48, 64].contains(&length) {
            return Err(InvalidJWKValue::new_err(
                "derived key length must be 16, 24, 32, 48 or 64 bytes",
            ));
        }
        let own = jwk::agreement::agreement_key(&key(&own)?).map_err(error)?;
        let peer = jwk::agreement::peer_key(&key(&peer)?).map_err(error)?;
        let apu = apu.map(|b| jose_rs::base64url::encode(&b));
        let apv = apv.map(|b| jose_rs::base64url::encode(&b));
        own.derive_key(&peer, &algorithm_id, apu.as_deref(), apv.as_deref(), length)
            .map_err(error)
    })?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

#[pyfunction]
fn keyset_read(
    py: Python<'_>,
    s: String,
    max_bytes: usize,
    max_entries: usize,
    strict: bool,
) -> PyResult<String> {
    py.detach(move || {
        let set = jwk::JwkSet::from_json_with_limits(
            &s,
            &jwk::selection::SetLimits {
                max_bytes,
                max_entries,
            },
        )
        .map_err(error)?;
        if strict {
            for k in &set.keys {
                jwk::jwk_to_software_key(k).map_err(error)?;
            }
        }
        json(&set)
    })
}

#[pyfunction]
fn keyset_diagnostics(py: Python<'_>, s: String) -> PyResult<String> {
    py.detach(move || {
        let set = jwk::JwkSet::from_json(&s).map_err(error)?;
        let rows: Vec<_> = jwk::selection::diagnostics(&set)
            .into_iter()
            .map(|d| {
                let (status, reason) = match d.status {
                    jwk::selection::EntryStatus::Usable => ("usable", None),
                    jwk::selection::EntryStatus::Unsupported { reason } => {
                        ("unsupported", Some(reason))
                    }
                    jwk::selection::EntryStatus::Invalid { reason } => ("invalid", Some(reason)),
                };
                json!({
                    "index": d.index,
                    "kid": d.kid,
                    "kty": d.kty,
                    "crv": d.crv,
                    "alg": d.alg,
                    "status": status,
                    "reason": reason,
                })
            })
            .collect();
        json(&rows)
    })
}

#[pyfunction]
fn claims_check(s: &str) -> PyResult<()> {
    jose_rs::jwt::Claims::from_json_bytes(s.as_bytes()).map_err(error)?;
    Ok(())
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    macro_rules! add { ($($f:ident),*) => { $(m.add_function(wrap_pyfunction!($f, m)?)?;)* }; }
    add!(
        capability_report,
        key_read,
        key_write,
        thumbprint_uri,
        thumbprint_uri_parse,
        derive_key,
        keyset_read,
        keyset_diagnostics,
        claims_check
    );
    // Exception attributes are also present on locally raised compatibility errors.
    let base = m.py().get_type::<JoseError>();
    base.setattr("category", "invalid_structure")?;
    base.setattr("authentication_failure", false)?;
    Ok(())
}
