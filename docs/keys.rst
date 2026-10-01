Keys and key sets
=================

Generation
----------

``JWK.generate`` accepts keyword arguments, with ``size`` expressed in bits.
Additional keywords are metadata, such as ``kid``, ``alg``, ``use`` and
``key_ops``. They cannot replace generated private or public material.

.. code-block:: python

   from pyjosers import JWK

   rsa = JWK.generate(kty="RSA", size=3072, alg="PS256")
   ec = JWK.generate(kty="EC", crv="P-384", alg="ES384")
   ed = JWK.generate(kty="OKP", crv="Ed25519", alg="EdDSA")
   hmac = JWK.generate(kty="oct", size=512, alg="HS512")
   pq = JWK.generate(kty="AKP", alg="ML-DSA-65")
   composite = JWK.generate(kty="AKP", alg="ML-DSA-65-ES256")

RSA defaults to 2048 bits and cannot be generated below that minimum. Octet
keys default to 256 bits; select 384 or 512 bits for HS384 or HS512. EC requires
one of P-256, P-384 or P-521. OKP generation supports Ed25519. AKP generation
requires a post-quantum build and an explicit supported algorithm.

Import, export and metadata
---------------------------

.. code-block:: python

   key = JWK.from_json(key_json)
   key = JWK(**key_dictionary)
   key["kid"] = "rotation-2026"
   assert key.kid == key.get("kid")
   public_key = key.public()
   private_json = key.export()       # contains private material
   public_json = key.export_public()
   thumbprint = key.thumbprint()     # RFC 7638, SHA-256
   uri = key.thumbprint_uri()        # RFC 9278

Imports validate key material through jose-rs. Mapping mutations are validated
when the key is next used. Each cryptographic operation checks ``alg``, ``use``
and ``key_ops``. Assigning incompatible metadata never overrides these checks.
The sole compatibility alias is an Ed25519 OKP key's ``alg=Ed25519`` metadata,
accepted for wire ``alg=EdDSA``. Wire ``alg=Ed25519`` is not supported upstream.

``public()`` drops private material and unknown extension parameters, and
retains only public operations from ``key_ops``. ``export_public()`` preserves
operation metadata as upstream does. Consider ``public().export()`` when
converting a key whose operation permissions include signing.

``repr(key)`` is redacted. Explicit exports are ordinary Python strings or
dictionaries; Python cannot guarantee that such copies are zeroized. Do not
log key exports. JWK thumbprints identify the public parameters (or the secret
of an octet key); they do not grant trust.

PEM and DER
-----------

.. code-block:: python

   with open("private.pem", "rb") as stream:
       key = JWK.from_pem(stream.read())
   private_der = key.export_to_der(private_key=True)
   public_der = key.export_to_der()
   restored = JWK.from_der(private_der, private=True)
   public_pem = key.export_to_pem()

Classical RSA, EC and Ed25519 imports accept unencrypted PKCS#8 private keys or
SPKI public keys. Exports use those formats; Ed25519 private exports use PKCS#8
v1 for OpenSSL interoperability. Password-encrypted PEM, PKCS#1, SEC1 and
certificate PEM import are unsupported. Convert these formats before migration.
RSA-PSS-specific PKCS#8 and SPKI keys are rejected, even with absent parameters,
because generic RSA JWKs cannot preserve their PSS-only and parameter
restrictions. This also applies to PEM wrappers. Ordinary ``rsaEncryption``
keys remain supported with both RS* and PS* signing algorithms.
Use JWK JSON for post-quantum interchange; upstream DER import does not cover
AKP keys, and composite keys have no SPKI representation.

Key sets and rotation
---------------------

``JWKSet`` supports ``add``, iteration, ``get_key``, ``get_keys``, ``from_json``,
``import_keyset`` and ``export``. Duplicate equal dictionaries are deduplicated
by ``add``. ``get_key`` raises on multiple matches; ``get_keys`` returns all
matching keys for rotation.

During verification, a token's protected ``kid`` selects matching keys. If any
key in the set has a ``kid``, an unknown token ``kid`` fails without fallback.
If the entire set is unlabelled, or the token omits ``kid``, every key can be
tried. Set ``Validation(require_kid=True)`` and label all published keys when
strict key selection is required. Key sets do not encode issuer trust: select
the appropriate issuer's trusted set in the application.
