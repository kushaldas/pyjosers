# Changelog

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
