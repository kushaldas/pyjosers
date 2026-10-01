Algorithm coverage
==================

The Python API uses standard JOSE strings rather than exporting Rust enum
variants. ``pyjosers.algorithms`` provides immutable tuples of the supported
JWS algorithms, JWE key-management algorithms, and content-encryption
algorithms. The tuples reflect build features and usable operations, not every
name the upstream parser can recognize.

Signatures
----------

.. list-table::
   :header-rows: 1

   * - Family
     - JOSE names
     - Key type
   * - HMAC
     - HS256, HS384, HS512
     - oct, at least 256/384/512 bits respectively
   * - RSA PKCS#1 v1.5 signatures
     - RS256, RS384, RS512
     - RSA, at least 2048 bits
   * - RSA-PSS
     - PS256, PS384, PS512
     - RSA, at least 2048 bits
   * - ECDSA
     - ES256, ES384, ES512
     - EC P-256, P-384, P-521 respectively
   * - EdDSA
     - EdDSA
     - OKP Ed25519 only
   * - ML-DSA
     - ML-DSA-44, ML-DSA-65, ML-DSA-87
     - AKP; requires post-quantum feature
   * - Composite ML-DSA/ECDSA
     - ML-DSA-44-ES256, ML-DSA-65-ES256, ML-DSA-87-ES384
     - AKP; requires post-quantum feature
   * - Composite ML-DSA/Edwards
     - ML-DSA-44-Ed25519, ML-DSA-65-Ed25519, ML-DSA-87-Ed448
     - AKP; requires post-quantum feature

ML-DSA primitives follow upstream FIPS 204 support. Composite JOSE encodings
follow the upstream draft-ietf-jose-pq-composite-sigs-03 implementation and
should be treated as draft-version-specific interchange. Neither this package
nor enabling these algorithms claims a validated FIPS cryptographic module.

Encryption
----------

Key management: ``dir``, ``A128KW``, ``A192KW``, ``A256KW``, ``RSA-OAEP-256``.
An optional ``legacy`` build also provides SHA-1-based ``RSA-OAEP``.

Content encryption: ``A128GCM``, ``A192GCM``, ``A256GCM``, ``A128CBC-HS256``,
``A192CBC-HS384``, ``A256CBC-HS512``.

Upstream operation mapping
--------------------------

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - jose-rs functionality
     - Python entry points
   * - JWK types, generation, conversion, JSON and public extraction
     - ``JWK``, ``JWKSet`` and their import/export/generation methods
   * - DER import and SoftwareKey conversion
     - ``JWK.from_der``, ``export_to_der``; software handles stay private
   * - JWK thumbprint
     - ``JWK.thumbprint`` and ``thumbprint_uri``
   * - Compact JWS signing/verification
     - ``JWS.add_signature``, ``verify``, ``serialize(compact=True)``
   * - Flattened/general JWS, detached payloads, sign/verify options
     - ``JWS``, ``detach_payload``, ``understood_crit``, ``verify_all``
   * - Certificate binding
     - ``pyjosers.x509``
   * - Compact JWE, key-bound operations, algorithm policy
     - ``JWE``, ``allowed_algs`` and JWK metadata
   * - JWT encode/decode, key-set verification, claims and validation
     - ``JWT``, ``jwt.encode``, ``jwt.decode``, ``Validation``
   * - Nested JWT, unverified decode
     - ``jwt.encode_nested``, ``decode_nested``, ``decode_unverified``
   * - Generic Signer/Verifier backed by PKCS#11
     - ``hsm.Pkcs11Signer``, ``hsm.Pkcs11Verifier`` passed to JWS/JWT
   * - Algorithm enums and key-size information
     - ``algorithms`` string tuples and ``CEK_BITS``
   * - Base64url helpers
     - ``common.base64url_encode`` / ``base64url_decode``

Rust trait objects and raw software key handles are intentionally internal.
The public API exposes the corresponding JOSE operations instead of requiring
Python applications to assemble Rust cryptographic providers.
