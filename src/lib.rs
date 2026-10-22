//! Owned-data Python boundary for jose-rs. Cryptographic work runs without the GIL.
use jose_rs::{jwk, JoseError as RustError, JoseHeader, JwsAlgorithm};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::{de::DeserializeOwned, Serialize};

mod envelopes;
mod extensions;
mod reports;

#[cfg(feature = "pkcs11")]
mod hsm;

pyo3::create_exception!(_native, JoseError, pyo3::exceptions::PyValueError);
pyo3::create_exception!(_native, InvalidJWKValue, JoseError);
pyo3::create_exception!(_native, InvalidJWSObject, JoseError);
pyo3::create_exception!(_native, InvalidJWSSignature, JoseError);
pyo3::create_exception!(_native, InvalidJWEData, JoseError);
pyo3::create_exception!(_native, JWTExpired, JoseError);
pyo3::create_exception!(_native, JWTNotYetValid, JoseError);
pyo3::create_exception!(_native, JWTInvalidClaimValue, JoseError);
pyo3::create_exception!(_native, UnsupportedAlgorithm, JoseError);

fn category_name(e: &RustError) -> &'static str {
    use jose_rs::ErrorCategory;
    match e.category() {
        ErrorCategory::UnsupportedCapability => "unsupported_capability",
        ErrorCategory::InvalidStructure => "invalid_structure",
        ErrorCategory::PolicyRejection => "policy_rejection",
        ErrorCategory::AuthenticationFailure => "authentication_failure",
        ErrorCategory::KeyMaterial => "key_material",
        ErrorCategory::Cryptographic => "cryptographic",
        ErrorCategory::Encoding => "encoding",
        _ => "unknown",
    }
}

/// Translate backend errors without exposing secret key representations.
fn annotate_error(err: PyErr, e: &RustError) -> PyErr {
    let category = category_name(e);
    Python::attach(|py| {
        let value = err.value(py);
        let _ = value.setattr("category", category);
        let _ = value.setattr("authentication_failure", e.is_authentication_failure());
    });
    err
}
fn error(e: RustError) -> PyErr {
    let message = e.to_string();
    let err = match &e {
        RustError::Key(_) => InvalidJWKValue::new_err(message),
        RustError::UnsupportedAlgorithm(_) => UnsupportedAlgorithm::new_err(message),
        RustError::Expired => JWTExpired::new_err(message),
        RustError::NotYetValid => JWTNotYetValid::new_err(message),
        RustError::InvalidClaims(_) | RustError::InvalidIssuer | RustError::InvalidAudience => {
            JWTInvalidClaimValue::new_err(message)
        }
        _ => JoseError::new_err(message),
    };
    annotate_error(err, &e)
}
fn encryption_error(e: RustError) -> PyErr {
    annotate_error(InvalidJWEData::new_err(e.to_string()), &e)
}
fn signature_error(e: RustError) -> PyErr {
    annotate_error(InvalidJWSSignature::new_err(e.to_string()), &e)
}

fn parse<T: DeserializeOwned>(s: &str) -> PyResult<T> {
    serde_json::from_str(s).map_err(|_| JoseError::new_err("invalid JSON or field types"))
}
fn json<T: Serialize>(v: &T) -> PyResult<String> {
    serde_json::to_string(v).map_err(|e| JoseError::new_err(e.to_string()))
}
fn key(s: &str) -> PyResult<jwk::Jwk> {
    parse(s)
}

/// Parse, optionally validate material, and normalize a JWK.
#[pyfunction]
fn key_normalize(s: &str, validate: bool) -> PyResult<String> {
    let k = key(s)?;
    if validate {
        jwk::jwk_to_software_key(&k).map_err(error)?;
    }
    json(&k)
}
/// Generate key material with the operating system random source.
#[pyfunction]
fn key_generate(
    py: Python<'_>,
    kty: String,
    size: usize,
    crv: String,
    alg: String,
) -> PyResult<String> {
    py.detach(move || {
        let k = match kty.as_str() {
            "RSA" => jwk::generate_rsa(size),
            "EC" => jwk::generate_ec(&crv),
            "OKP" if crv == "Ed25519" => jwk::generate_ed25519(),
            "OKP" if crv == "X25519" => jwk::generate_x25519(),
            "oct" if size > 0 && size.is_multiple_of(8) => jwk::generate_symmetric(size / 8),
            #[cfg(feature = "post-quantum")]
            "AKP" => match JwsAlgorithm::from_str(&alg)
                .and_then(|a| a.to_crypto())
                .map_err(error)?
            {
                kryptering::SignatureAlgorithm::MlDsa(v) => jwk::generate_mldsa(v),
                kryptering::SignatureAlgorithm::CompositeMlDsa(v) => {
                    jwk::generate_composite_mldsa(v)
                }
                _ => {
                    return Err(UnsupportedAlgorithm::new_err(
                        "AKP requires an ML-DSA algorithm",
                    ))
                }
            },
            _ => {
                return Err(InvalidJWKValue::new_err(
                    "unsupported key type, curve, or size",
                ))
            }
        }
        .map_err(error)?;
        let _ = alg;
        json(&k)
    })
}
/// Derive the public representation, dropping unknown extension fields.
#[pyfunction]
fn key_public(s: &str) -> PyResult<String> {
    let k = key(s)?;
    if k.kty == "oct" {
        return Err(InvalidJWKValue::new_err(
            "symmetric keys have no public component",
        ));
    }
    json(&k.to_public_jwk())
}
/// Compute an RFC 7638 thumbprint with an explicitly supported SHA-2 hash.
#[pyfunction]
#[pyo3(signature = (s, hash_name="sha256"))]
fn key_thumbprint(s: &str, hash_name: &str) -> PyResult<String> {
    use jwk::thumbprint::ThumbprintHash;
    let hash = match hash_name {
        "sha256" => ThumbprintHash::Sha256,
        "sha384" => ThumbprintHash::Sha384,
        "sha512" => ThumbprintHash::Sha512,
        _ => return Err(UnsupportedAlgorithm::new_err("unsupported thumbprint hash")),
    };
    jwk::thumbprint::thumbprint(&key(s)?, hash).map_err(error)
}
/// Import unencrypted PKCS#8 private or SPKI public DER.
#[pyfunction]
fn key_import(py: Python<'_>, data: Vec<u8>, private: bool) -> PyResult<String> {
    py.detach(move || {
        json(
            &if private {
                jwk::jwk_from_pkcs8_der(&data)
            } else {
                jwk::jwk_from_spki_der(&data)
            }
            .map_err(error)?,
        )
    })
}
/// Export PKCS#8 private or SPKI public DER.
#[pyfunction]
fn key_export(py: Python<'_>, s: String, private: bool) -> PyResult<Py<PyBytes>> {
    let bytes = py.detach(move || {
        let k = key(&s)?;
        if k.kty == "oct" {
            return Err(InvalidJWKValue::new_err(
                "symmetric keys have no DER encoding",
            ));
        }
        let sw = jwk::jwk_to_software_key(&k).map_err(error)?;
        if private {
            let bytes = sw.export_private().map_err(|e| error(e.into()))?;
            // OpenSSL consumers expect PKCS#8 v1 for Ed25519. Omit the optional
            // public field; the private seed still determines the same key.
            if k.kty == "OKP" && k.crv.as_deref() == Some("Ed25519") {
                use pkcs8::der::Encode;
                let mut info = pkcs8::PrivateKeyInfoRef::try_from(bytes.as_slice())
                    .map_err(|_| InvalidJWKValue::new_err("invalid PKCS#8 export"))?;
                info.public_key = None;
                info.to_der()
                    .map_err(|_| InvalidJWKValue::new_err("PKCS#8 encoding failed"))
            } else {
                Ok(bytes.to_vec())
            }
        } else {
            sw.export_spki_der().map_err(|e| error(e.into()))
        }
    })?;
    Ok(PyBytes::new(py, &bytes).unbind())
}
/// Build a signer/verifier only after checking metadata against the actual operation.
fn signature_key(
    s: &str,
    header: &JoseHeader,
    op: jwk::JwkOp,
) -> PyResult<(kryptering::SignatureAlgorithm, kryptering::SoftwareKey)> {
    let k = signature_jwk(s, header)?;
    let alg = JwsAlgorithm::from_str(&header.alg).map_err(error)?;
    let material = jwk::jwk_to_signature_key(&k, alg, op).map_err(error)?;
    Ok((alg.to_crypto().map_err(error)?, material))
}
fn signature_jwk(s: &str, header: &JoseHeader) -> PyResult<jwk::Jwk> {
    let mut k = key(s)?;
    // Preserve the existing one-way metadata alias only for the EdDSA wire
    // name. Explicit Ed25519 headers retain exact backend algorithm pinning.
    if header.alg == "EdDSA"
        && k.kty == "OKP"
        && k.crv.as_deref() == Some("Ed25519")
        && k.alg.as_deref() == Some("Ed25519")
    {
        k.alg = Some("EdDSA".into());
    }
    Ok(k)
}
/// Sign a flattened JWS, including detached and RFC 7797 payload modes.
// Keep the native signature aligned with the Python/PKCS#11 signing protocol.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (s, payload, protected, unprotected, detached, understood, allow_key_reference_headers=false))]
fn sign(
    py: Python<'_>,
    s: String,
    payload: Vec<u8>,
    protected: String,
    unprotected: Option<String>,
    detached: bool,
    understood: Vec<String>,
    allow_key_reference_headers: bool,
) -> PyResult<String> {
    py.detach(move || {
        let header: JoseHeader = parse(&protected)?;
        let mut k = signature_jwk(&s, &header)?;
        // A caller-selected protected algorithm binds an unpinned compatibility key.
        if k.alg.is_none() {
            k.alg = Some(header.alg.clone());
        }
        let options = jose_rs::jws::SignOptions::new()
            .with_b64(
                header
                    .extra
                    .get("b64")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
            )
            .with_understood_crit(understood)
            .with_key_reference_headers(allow_key_reference_headers);
        let unprotected = unprotected.as_deref().map(parse).transpose()?;
        let result = if detached {
            jose_rs::jws::json::sign_flattened_detached_with_jwk_opts(
                &k,
                &payload,
                &header,
                unprotected,
                &options,
            )
        } else {
            jose_rs::jws::json::sign_flattened_with_jwk_opts(
                &k,
                &payload,
                &header,
                unprotected,
                &options,
            )
        }
        .map_err(error)?;
        json(&result)
    })
}
/// Verify the original encoded protected header and signature, returning bytes.
#[pyfunction]
fn verify(
    py: Python<'_>,
    s: String,
    token: String,
    detached: Option<Vec<u8>>,
    understood: Vec<String>,
) -> PyResult<Py<PyBytes>> {
    let bytes = py.detach(move || {
        if token.len() > jose_rs::MAX_TOKEN_BYTES {
            return Err(InvalidJWSObject::new_err("token too large"));
        }
        let jws: jose_rs::jws::json::FlattenedJws = parse(&token)?;
        let header: JoseHeader =
            serde_json::from_slice(&jose_rs::base64url::decode(&jws.protected).map_err(error)?)
                .map_err(|_| InvalidJWSObject::new_err("invalid protected header"))?;
        let k = signature_jwk(&s, &header)?;
        jose_rs::jws::json::verify_flattened_with_jwk_opts(
            &k,
            &jws,
            detached.as_deref(),
            &jose_rs::jws::VerifyOptions {
                understood_crit: understood,
            },
        )
        .map_err(signature_error)
    })?;
    Ok(PyBytes::new(py, &bytes).unbind())
}
/// Encrypt with authenticated application headers and enforced JWK policy.
#[pyfunction]
#[pyo3(signature = (s, payload, protected, allow_key_reference_headers=false))]
fn encrypt(
    py: Python<'_>,
    s: String,
    payload: Vec<u8>,
    protected: String,
    allow_key_reference_headers: bool,
) -> PyResult<String> {
    py.detach(move || {
        let header: JoseHeader = parse(&protected)?;
        let mut k = key(&s)?;
        if k.alg.as_deref().is_some_and(|a| a != header.alg) {
            return Err(InvalidJWKValue::new_err("JWK alg mismatch"));
        }
        k.alg = Some(header.alg.clone());
        let enc = jose_rs::JweEncryption::from_str(
            header
                .enc
                .as_deref()
                .ok_or_else(|| InvalidJWEData::new_err("enc required"))?,
        )
        .map_err(error)?;
        let options = jose_rs::jwe::JweEncryptOptions::new()
            .with_key_reference_headers(allow_key_reference_headers);
        jose_rs::jwe::encrypt_with_jwk_header_options(&k, header, &payload, enc, &options)
            .map_err(error)
    })
}
/// Decrypt with JWK policy and an optional inclusive plaintext-byte limit.
#[pyfunction]
#[pyo3(signature = (s, token, alg, max_plaintext=None))]
fn decrypt(
    py: Python<'_>,
    s: String,
    token: String,
    alg: String,
    max_plaintext: Option<usize>,
) -> PyResult<Py<PyBytes>> {
    let bytes = py.detach(move || {
        let mut k = key(&s)?;
        if k.alg.as_deref().is_some_and(|a| a != alg) {
            return Err(InvalidJWKValue::new_err("JWK alg mismatch"));
        }
        k.alg = Some(alg);
        let mut options = jose_rs::jwe::JweDecryptOptions::permissive();
        if let Some(limit) = max_plaintext {
            options = options.with_max_plaintext(limit);
        }
        let envelope = jose_rs::jwe::json::FlattenedJwe::from_compact(&token).map_err(error)?;
        jose_rs::jwe::json::decrypt_flattened_with_jwk_options(&k, &envelope, &options)
            .map_err(encryption_error)
    })?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

/// Serializable mirror of every upstream JWT validation setting.
#[derive(serde::Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Policy {
    issuer: Option<String>,
    audience: Option<String>,
    subject: Option<String>,
    required_typ: Option<String>,
    max_age: Option<u64>,
    allowed_algorithms: Vec<String>,
    leeway: Option<u64>,
    validate_exp: Option<bool>,
    validate_nbf: Option<bool>,
    validate_iat_not_future: Option<bool>,
    require_exp: bool,
    require_nbf: bool,
    require_iat: bool,
    require_kid: bool,
}
/// Validate already authenticated claims using the complete jose-rs policy.
#[pyfunction]
#[pyo3(signature = (claims, header, options, now=None))]
fn validate_claims(claims: &str, header: &str, options: &str, now: Option<&str>) -> PyResult<()> {
    let p: Policy = parse(options)?;
    let mut v = jose_rs::jwt::Validation::new();
    v.issuer = p.issuer;
    v.audience = p.audience;
    v.subject = p.subject;
    v.required_typ = p.required_typ;
    v.max_age = p.max_age;
    v.allowed_algorithms = p
        .allowed_algorithms
        .iter()
        .map(|s| JwsAlgorithm::from_str(s).map_err(error))
        .collect::<PyResult<_>>()?;
    v.leeway = p.leeway.unwrap_or(60);
    v.validate_exp = p.validate_exp.unwrap_or(true);
    v.validate_nbf = p.validate_nbf.unwrap_or(true);
    v.validate_iat_not_future = p.validate_iat_not_future.unwrap_or(true);
    v.require_exp = p.require_exp;
    v.require_nbf = p.require_nbf;
    v.require_iat = p.require_iat || p.max_age.is_some();
    v.require_kid = p.require_kid;
    let claims = jose_rs::jwt::Claims::from_json_bytes(claims.as_bytes()).map_err(error)?;
    let header = parse(header)?;
    match now {
        Some(now) => v.validate_at(&claims, Some(&header), now.parse().map_err(error)?),
        None => v.validate_with_header(&claims, &header),
    }
    .map_err(error)
}
/// Certificate binding helpers; these do not validate certificate trust chains.
#[pyfunction]
fn certificate(action: &str, header: &str, der: Vec<u8>) -> PyResult<String> {
    let mut h: JoseHeader = parse(header)?;
    match action {
        "bind" => {
            jose_rs::jws::x5::bind_cert_to_header(&mut h, &der);
            json(&h)
        }
        "verify" => {
            jose_rs::jws::x5::verify_cert_binding(&h, &der).map_err(error)?;
            Ok(String::new())
        }
        "thumbprint" => Ok(jose_rs::jws::x5::x5t_s256_of_der(&der)),
        _ => Err(JoseError::new_err("unknown certificate operation")),
    }
}
/// Register the private native implementation; the Python package is the public API.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    extensions::register(m)?;
    envelopes::register(m)?;
    reports::register(m)?;
    macro_rules! functions { ($($f:ident),*) => { $(m.add_function(wrap_pyfunction!($f, m)?)?;)* }; }
    functions!(
        key_normalize,
        key_generate,
        key_public,
        key_thumbprint,
        key_import,
        key_export,
        sign,
        verify,
        encrypt,
        decrypt,
        validate_claims,
        certificate
    );
    macro_rules! exceptions { ($($e:ident),*) => { $(let exception = m.py().get_type::<$e>(); exception.setattr("__module__", "pyjosers._native")?; m.add(stringify!($e), exception)?;)* }; }
    exceptions!(
        JoseError,
        InvalidJWKValue,
        InvalidJWSObject,
        InvalidJWSSignature,
        InvalidJWEData,
        JWTExpired,
        JWTNotYetValid,
        JWTInvalidClaimValue,
        UnsupportedAlgorithm
    );
    m.add("POST_QUANTUM", cfg!(feature = "post-quantum"))?;
    m.add("LEGACY", cfg!(feature = "legacy"))?;
    m.add("PKCS11", cfg!(feature = "pkcs11"))?;
    m.add("MAX_TOKEN_BYTES", jose_rs::MAX_TOKEN_BYTES)?;
    #[cfg(feature = "pkcs11")]
    hsm::register(m)?;
    Ok(())
}
