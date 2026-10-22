jose-rs 0.10 integration
==========================

pyjosers 0.2.0 uses the published jose-rs 0.10.0, Kryptering 0.7 and PyO3
0.30.1 releases. No sibling checkout, vendored backend or unpublished patch is
required. Cargo's lockfile records registry sources and checksums. PKCS#8 0.11
and the cryptographic trait dependencies follow Kryptering's coordinated family;
Cargo resolver 3 and the Rust 1.89 build check protect the package's minimum.

Feature coverage
------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Backend capability
     - Python interface and validation
   * - Build-aware capability reporting
     - ``capabilities.report()``, ``available()``, ``find()``, ``features()``;
       algorithm constants derive from the installed report
   * - Classical, ML-DSA and composite signatures
     - ``JWK.generate``, ``JWS``, ``JWT``; native feature gates remain authoritative
   * - JWK-aware JSON signatures and explicit any/all policies
     - ``JWS.verify_report``; per-signature candidate selection, attempted status,
       key indices and protected/unprotected metadata
   * - Compact, flattened and general JWE
     - ``JWE``, ``flattened=False``, repeated ``add_recipient`` calls and
       ``recipient_index`` selection
   * - ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW
     - EC P-256/P-384/P-521 and OKP X25519 keys; protected ``apu``/``apv``;
       ``JWK.derive_key`` exposes Concat KDF derivation
   * - A128GCMKW/A192GCMKW/A256GCMKW
     - Standard JWE workflow; wrapping IV/tag are generated in Rust
   * - PBES2-HS256+A128KW / HS384+A192KW / HS512+A256KW
     - Password recipients; explicit generation and decryption work budgets
   * - External AAD, critical extensions and plaintext limits
     - ``aad``, ``expected_aad``, ``understood_crit``, ``max_plaintext``
   * - PKCS#8, SPKI, PKCS#1, SEC1 and encrypted PKCS#8
     - Existing PEM methods; explicit ``format`` for DER, password and work-budget
       keywords; imports preserve backend restrictions
   * - X.509 public-key extraction
     - ``JWK.from_certificate_pem`` / ``from_certificate_der``; independent from
       certificate binding and trust validation
   * - SHA-2 thumbprints and validated RFC 9278 URIs
     - ``thumbprint``, ``thumbprint_uri``, ``JWKThumbprintURI.parse`` / ``matches``
   * - Bounded sets, selection and three-state diagnostics
     - ``SetLimits``, ``SelectionPolicy``, ``JWKSet.select`` / ``diagnostics``;
       explicit diagnostic import with ``strict=False``
   * - Checked claims and exact JSON numbers
     - Native checks on creation, validation and unverified decoding;
       ``JWT.claims`` retains JSON and authenticated results use ``Decimal``
   * - Authenticated results and error categories
     - ``verify_authenticated``, ``decrypt_authenticated``,
       ``validate_authenticated``, ``decode_authenticated`` and
       ``is_authentication_failure``
   * - PKCS#11 signer/verifier support
     - Existing HSM API and disposable SoftHSM integration tests

Binding implementation notes
------------------------------

The old temporary ``decrypt_with_jwk_options`` helper is not part of this
published backend. Compact input is represented as a native flattened envelope
and passed through the published option-aware JWK API. Pins, permissions, AAD,
critical extensions and size limits remain enforced together.

General JWS verification keeps candidate selection scoped to each signature's
protected ``kid``. Native batching reuses prepared verifiers within that
operation; an unrestricted union of a key set is never substituted for those
selections. Authenticated metadata is returned from the same successful operation,
without a second verification or decryption.

jose-rs 0.10.0's JSON writer emits the mandatory empty ``ciphertext`` string for
empty GCM plaintext, but its parser incorrectly rejects that empty string.
The binding validates the entire JSON envelope using a nonempty placeholder for
that one value, then restores the original empty ciphertext **before** any
cryptographic operation. Protected headers, duplicate-member checks, tag checks,
plaintext limits and retained extension members are unchanged. Regression tests
cover flattened/general empty messages and duplicated ciphertext members.

X25519 key generation, JWK interchange and ECDH work, but this backend cannot
import or export X25519 PKCS#8/SPKI files. The upstream capability table's
PKCS#8 note overstates that key type's support; the binding reports the backend
notes verbatim and refuses unsupported file operations. PBES2 unwrap failures
may be classified as ``key_material``; see :doc:`exceptions`.

Performance is addressed through native batching, parsed-envelope reuse, GIL
release, a direct single-signature path and encrypting a staged recipient set
once. Authenticated JWT results retain checked JSON and convert to exact Python
numbers only when their value is requested. This release does not claim
a measured speedup or include a benchmark comparison.

Release checks
----------------

The feature matrix, interoperability tests, strict Sphinx builds, executable
examples, Rust 1.89 check and isolated wheel/sdist tests are release requirements.
See :doc:`development` for commands and :doc:`migration` for behavior changes.
