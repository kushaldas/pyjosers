//! Parsed JWE envelopes keep authenticated wire data in Rust across Python calls.
use crate::{encryption_error, error, json, key, parse, InvalidJWEData, InvalidJWKValue};
use jose_rs::{
    jwe::{self, general::GeneralJwe, json::FlattenedJwe},
    JoseHeader, JweAlgorithm, JweEncryption,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Options {
    allowed_algorithms: Vec<String>,
    allowed_encryptions: Vec<String>,
    understood_crit: Vec<String>,
    allow_key_reference_headers: bool,
    max_plaintext: Option<usize>,
    pbes2_iterations: Option<u32>,
    pbes2_max_iterations: Option<u32>,
}

enum Envelope {
    Flat(FlattenedJwe),
    General(GeneralJwe),
}

#[pyclass(frozen)]
pub(crate) struct JweEnvelope {
    inner: Envelope,
}

fn protected_value(encoded: Option<&str>) -> PyResult<Value> {
    let raw = jose_rs::base64url::decode(encoded.unwrap_or("")).map_err(error)?;
    serde_json::from_slice(&raw).map_err(|_| InvalidJWEData::new_err("invalid protected header"))
}
fn protected(flat: &FlattenedJwe) -> PyResult<Value> {
    protected_value(flat.protected.as_deref())
}
fn metadata(flat: &FlattenedJwe) -> PyResult<String> {
    let unprotected: Vec<_> = flat.unprotected.iter().chain(flat.header.iter()).collect();
    json(&json!({"protected": protected(flat)?, "unprotected": unprotected, "aad": flat.aad}))
}
fn pinned(mut k: jose_rs::jwk::Jwk, alg: &str) -> PyResult<jose_rs::jwk::Jwk> {
    if k.alg.as_deref().is_some_and(|pin| pin != alg) {
        return Err(InvalidJWKValue::new_err("JWK alg mismatch"));
    }
    k.alg = Some(alg.to_owned());
    Ok(k)
}

#[pymethods]
impl JweEnvelope {
    #[new]
    fn new(token: &str) -> PyResult<Self> {
        if token.len() > jose_rs::MAX_TOKEN_BYTES {
            return Err(InvalidJWEData::new_err("token too large"));
        }
        let inner = if token.trim_start().starts_with('{') {
            // Try the general parser first only when the envelope names recipients.
            // RawValue avoids decoding the potentially large body during dispatch.
            let shape: std::collections::HashMap<String, &serde_json::value::RawValue> =
                serde_json::from_str(token)
                    .map_err(|_| InvalidJWEData::new_err("invalid JWE JSON"))?;
            if token.len() > jose_rs::MAX_TOKEN_BYTES {
                return Err(InvalidJWEData::new_err("token too large"));
            }
            // jose-rs 0.10's writer emits mandatory ciphertext="" for empty GCM
            // plaintext, but its JSON parser applies the optional-member empty rule.
            // Validate the complete original document with only that empty value
            // replaced, then restore the exact ciphertext before authentication.
            // Borrowed RawValue locates the value without rewriting any other member
            // (including duplicates, protected bytes, or retained extension order).
            let empty = shape.get("ciphertext").filter(|v| v.get() == "\"\"");
            let normalized = empty.map(|value| {
                let offset = value.get().as_ptr() as usize - token.as_ptr() as usize;
                let mut text = token.to_owned();
                text.replace_range(offset..offset + 2, "\"AA\"");
                text
            });
            let text = normalized.as_deref().unwrap_or(token);
            if shape.contains_key("recipients") {
                let mut value = GeneralJwe::from_json(text).map_err(encryption_error)?;
                if empty.is_some() {
                    value.ciphertext.clear();
                }
                Envelope::General(value)
            } else {
                let mut value = FlattenedJwe::from_json(text).map_err(encryption_error)?;
                if empty.is_some() {
                    value.ciphertext.clear();
                }
                Envelope::Flat(value)
            }
        } else {
            Envelope::Flat(FlattenedJwe::from_compact(token).map_err(encryption_error)?)
        };
        Ok(Self { inner })
    }

    fn serialize(&self, compact: bool) -> PyResult<String> {
        match &self.inner {
            Envelope::Flat(flat) if compact => flat.to_compact(),
            Envelope::Flat(flat) => flat.to_json(),
            Envelope::General(general) if compact => {
                if general.recipients.len() != 1 {
                    return Err(InvalidJWEData::new_err(
                        "compact serialization requires one recipient",
                    ));
                }
                general.flatten_for(0).and_then(|flat| flat.to_compact())
            }
            Envelope::General(general) => general.to_json(),
        }
        .map_err(encryption_error)
    }

    #[pyo3(signature = (recipient=None))]
    fn metadata(&self, recipient: Option<usize>) -> PyResult<String> {
        match &self.inner {
            Envelope::Flat(flat) => metadata(flat),
            Envelope::General(general) => {
                let entry = general
                    .recipients
                    .get(recipient.unwrap_or(0))
                    .ok_or_else(|| InvalidJWEData::new_err("recipient index out of range"))?;
                let unprotected: Vec<_> = general
                    .unprotected
                    .iter()
                    .chain(entry.header.iter())
                    .collect();
                json(
                    &json!({"protected": protected_value(general.protected.as_deref())?,
                    "unprotected": unprotected, "aad": general.aad}),
                )
            }
        }
    }

    #[getter]
    fn recipient_count(&self) -> usize {
        match &self.inner {
            Envelope::Flat(_) => 1,
            Envelope::General(g) => g.recipients.len(),
        }
    }

    #[pyo3(signature = (keys, password, options, expected_aad=None, recipient=None))]
    fn decrypt(
        &self,
        py: Python<'_>,
        keys: Vec<String>,
        password: Option<Vec<u8>>,
        options: &str,
        expected_aad: Option<Vec<u8>>,
        recipient: Option<usize>,
    ) -> PyResult<(Py<PyBytes>, String)> {
        let opts: Options = parse(options)?;
        let password = password.map(jose_rs::Password::from);
        let (plaintext, meta) = py.detach(move || {
            if opts.allowed_algorithms.is_empty() || opts.allowed_encryptions.is_empty() {
                return Err(InvalidJWEData::new_err("algorithm allowlist is empty"));
            }
            let mut options = jwe::JweDecryptOptions::new(
                opts.allowed_algorithms
                    .iter()
                    .map(|s| JweAlgorithm::from_str(s).map_err(error))
                    .collect::<PyResult<_>>()?,
                opts.allowed_encryptions
                    .iter()
                    .map(|s| JweEncryption::from_str(s).map_err(error))
                    .collect::<PyResult<_>>()?,
            )
            .with_understood_crit(opts.understood_crit);
            if let Some(n) = opts.max_plaintext {
                options = options.with_max_plaintext(n);
            }
            if let Some(n) = opts.pbes2_max_iterations {
                options = options.with_pbes2_max_iterations(n);
            }
            if let Some(aad) = expected_aad {
                options = options.with_external_aad(aad);
            }
            let select = |k: Option<&jose_rs::jwk::Jwk>| -> PyResult<usize> {
                match &self.inner {
                    Envelope::Flat(_) => {
                        if recipient.is_some_and(|i| i != 0) {
                            return Err(InvalidJWEData::new_err("recipient index out of range"));
                        }
                        Ok(0)
                    }
                    Envelope::General(g) => {
                        if let Some(i) = recipient {
                            return Ok(i);
                        }
                        if g.recipients.len() == 1 {
                            return Ok(0);
                        }
                        let kid = k.and_then(|k| k.kid.as_deref()).ok_or_else(|| {
                            InvalidJWEData::new_err("provide a recipient index or a key with kid")
                        })?;
                        let matches: Vec<_> = g
                            .recipient_kids()
                            .iter()
                            .enumerate()
                            .filter_map(|(i, value)| (*value == Some(kid)).then_some(i))
                            .collect();
                        if matches.len() != 1 {
                            return Err(InvalidJWEData::new_err(
                                "recipient kid must match exactly once",
                            ));
                        }
                        Ok(matches[0])
                    }
                }
            };
            let decrypt_flat = |flat: &FlattenedJwe,
                                k: Option<jose_rs::jwk::Jwk>|
             -> PyResult<(Vec<u8>, String)> {
                let header = protected(flat)?;
                let bytes = if let Some(password) = &password {
                    jwe::json::decrypt_flattened_with_password_options(password, flat, &options)
                        .map_err(encryption_error)?
                } else {
                    let mut k = k.ok_or_else(|| InvalidJWEData::new_err("no decryption key"))?;
                    // Only a protected alg may supply a missing compatibility pin.
                    // An unprotected alg must match an existing trusted key pin.
                    if let Some(alg) = header.get("alg").and_then(Value::as_str) {
                        k = pinned(k, alg)?;
                    }
                    jwe::json::decrypt_flattened_with_jwk_options(&k, flat, &options)
                        .map_err(encryption_error)?
                };
                Ok((bytes, metadata(flat)?))
            };
            if password.is_some() {
                let i = select(None)?;
                return match &self.inner {
                    Envelope::Flat(flat) => decrypt_flat(flat, None),
                    Envelope::General(g) => {
                        decrypt_flat(&g.flatten_for(i).map_err(encryption_error)?, None)
                    }
                };
            }
            let mut last = InvalidJWEData::new_err("no matching key decrypted the token");
            for s in keys {
                let attempt = (|| {
                    let k = key(&s)?;
                    let i = select(Some(&k))?;
                    match &self.inner {
                        Envelope::Flat(flat) => decrypt_flat(flat, Some(k)),
                        Envelope::General(g) => {
                            decrypt_flat(&g.flatten_for(i).map_err(encryption_error)?, Some(k))
                        }
                    }
                })();
                match attempt {
                    Ok(value) => return Ok(value),
                    Err(err) => last = err,
                }
            }
            Err(last)
        })?;
        Ok((PyBytes::new(py, &plaintext).unbind(), meta))
    }
}

#[pyfunction]
#[pyo3(signature = (keys, password, payload, protected, options, aad=None, general=false))]
#[allow(clippy::too_many_arguments)]
fn jwe_encrypt(
    py: Python<'_>,
    keys: Vec<String>,
    password: Option<Vec<u8>>,
    payload: Vec<u8>,
    protected: String,
    options: String,
    aad: Option<Vec<u8>>,
    general: bool,
) -> PyResult<JweEnvelope> {
    let password = password.map(jose_rs::Password::from);
    py.detach(move || {
        let opts: Options = parse(&options)?;
        let header: JoseHeader = parse(&protected)?;
        let alg = JweAlgorithm::from_str(&header.alg).map_err(error)?;
        let enc = JweEncryption::from_str(
            header
                .enc
                .as_deref()
                .ok_or_else(|| InvalidJWEData::new_err("enc required"))?,
        )
        .map_err(error)?;
        let mut options = jwe::JweEncryptOptions::new()
            .with_key_reference_headers(opts.allow_key_reference_headers)
            .with_understood_crit(opts.understood_crit);
        if let Some(aad) = aad {
            options = options.with_external_aad(aad);
        }
        if let Some(n) = opts.pbes2_iterations {
            options = options.with_pbes2_iterations(n);
        }
        let inner = if let Some(password) = password {
            if !keys.is_empty() {
                return Err(InvalidJWEData::new_err(
                    "password and JWK recipients cannot be mixed",
                ));
            }
            if general {
                Envelope::General(
                    jwe::general::encrypt_general_with_passwords_options(
                        &header,
                        &[&password],
                        &payload,
                        alg,
                        enc,
                        &options,
                    )
                    .map_err(encryption_error)?,
                )
            } else {
                Envelope::Flat(
                    jwe::json::encrypt_flattened_with_password_header_options(
                        &password, header, &payload, alg, enc, &options,
                    )
                    .map_err(encryption_error)?,
                )
            }
        } else {
            if keys.is_empty() || keys.len() > jwe::general::MAX_RECIPIENTS {
                return Err(InvalidJWEData::new_err("expected 1 to 32 recipients"));
            }
            let keys = keys
                .iter()
                .map(|s| pinned(key(s)?, &header.alg))
                .collect::<PyResult<Vec<_>>>()?;
            if general || keys.len() > 1 {
                Envelope::General(
                    jwe::general::encrypt_general_with_jwks_options(
                        &header,
                        &keys.iter().collect::<Vec<_>>(),
                        &payload,
                        enc,
                        &options,
                    )
                    .map_err(encryption_error)?,
                )
            } else {
                Envelope::Flat(
                    jwe::json::encrypt_flattened_with_jwk_header_options(
                        &keys[0], header, &payload, enc, &options,
                    )
                    .map_err(encryption_error)?,
                )
            }
        };
        Ok(JweEnvelope { inner })
    })
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<JweEnvelope>()?;
    m.add_function(wrap_pyfunction!(jwe_encrypt, m)?)?;
    Ok(())
}
