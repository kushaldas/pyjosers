# Changelog

## 0.4.1 - 2026-11-18

- Store assignments such as `key.kid = key.thumbprint()` in the JWK mapping so
  exported public sets carry the same identifier as signed headers. Attribute
  writes check metadata types. Key material attributes are read-only. Custom
  instance and subclass attributes remain local. Use item syntax for extensions.
- Add `jwt.dumps()` for exact JSON numbers from discovery and authenticated
  claims. It accepts finite `Decimal` values and timezone-aware `datetime`
  values, including in dictionaries supplied for signing. Whole-second
  datetimes serialize as JSON integers.
- Compatibility: dictionary claims now require string keys at every level.
  Earlier versions could silently convert numeric keys to strings.
- Document typed key discovery, the numeric types exposed by each claims API,
  and verification of the original compact token.
- Update the published jose-rs dependency to 0.12.1 for Rust algorithm types'
  `FromStr` implementations. Wire algorithm names and behavior are unchanged.

## 0.4.0 - 2026-11-18

- Refresh the Rust 1.89 lockfile with zeroize 1.9.2, const-oid 0.10.3 and
  target-lexicon 0.13.6. Update the documentation extra to Sphinx 8.1.3
  on Python 3.10, 9.0.4 on 3.11 and 9.1.1 on 3.12.

- Update the published jose-rs backend to 0.12.0. Generate, import, sign and
  verify standalone Ed448 keys with either Ed448 or EdDSA on the wire.
  Ed25519 and Ed448 accept the matching curve name and EdDSA as JWK pins in
  both directions. Algorithm allowlists still match exact header names.
- Return the original JWK Set position in `Authenticated.verified_key_index`.
- Add `jwt.UnverifiedJwt` and `jwt.decode_self_signed` for bounded compact JWT
  discovery. Duplicate claims at any depth are rejected before key selection.
- Add `Validation.signature_only()`, `without_exp()`, `without_nbf()` and
  `without_iat_future_check()` for explicit time-check policy.

## 0.3.0 - 2026-11-10

- Synchronize package, runtime and documentation versions at 0.3.0.
- Refresh the Rust lockfile and dependency minimums; retain PyO3 0.30.1.
- Upgrade to published jose-rs 0.11.0, Kryptering 0.7.1 and stable RSA 0.10.0,
  removing the RSA prerelease dependency and its upgrade blocker.
- Update maturin, pytest, jwcrypto and documentation tooling. Select Sphinx by
  Python version so development extras remain installable on Python 3.10+.

## 0.2.0 - 2026-10-22

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
