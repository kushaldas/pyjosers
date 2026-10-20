# Changelog

## 0.2.0 - 2026-10-21

- Use published jose-rs 0.10.0, Kryptering 0.7 and PyO3 0.30.1; remove the
  temporary sibling dependency and synchronize package/runtime/docs versions.
- Expose build-aware capabilities, X25519/ECDH agreement, GCM key wrapping,
  PBES2, external AAD, critical extensions, and flattened/general JWE.
- Add bounded JWKS selection and diagnostics, any/all signature reports,
  authenticated payload/header results, exact checked claims, and error categories.
- Add PKCS#1/SEC1 imports, encrypted PKCS#8, certificate-key extraction,
  validated thumbprint URIs and agreement-key derivation.
- Require an explicit password choice for private PEM exports. Default JWKS
  limits are 4 MiB, 1,024 entries and 64 candidates; overrides remain available.
- Reuse native envelopes and batch signature verification; stage JWE recipients
  and encrypt once. No benchmark or measured performance claim is included.
- Update executable examples, migration guidance, feature/build tests and release
  checks. Document upstream encoding and algorithm restrictions, including the
  narrow workaround for parsing empty GCM ciphertext in JSON envelopes.

## 0.1.0

First release: PyO3 bindings for crates.io jose-rs 0.8.0 and kryptering 0.6,
with jwcrypto-style JWK/JWKSet,
JWS, JWE and JWT APIs; full validation policy; detached, unencoded and
multi-signature JWS; nested JWT; post-quantum signatures; PKCS#11 signing;
PEM/DER and certificate-binding helpers; interoperability tests and Sphinx docs.

Custom protected JWE headers use the public upstream API. No backend source
is vendored. RSA-PSS-specific PKCS#8 and SPKI keys (including PEM wrappers)
are rejected because JWK conversion cannot preserve their restrictions.
Ordinary RSA keys support both RS* and PS* algorithms.

Header emission follows jose-rs 0.8.0 policy: JWS signing rejects JWE-only
members and registered or duplicate critical names; JWE encryption rejects
unsupported registered members. Emitting jku, jwk, x5u or x5c requires the
explicit allow_key_reference_headers opt-in on JWS, JWE, JWT, jwt.encode or
jwt.encode_nested. Software and PKCS#11 signing use the same policy.

See docs/migration.rst for compatibility scope and upstream limitations.
