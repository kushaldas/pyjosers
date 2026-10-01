Migrating from jwcrypto
=======================

Start with imports
------------------

For supported operations, change imports while retaining the object workflow:

.. code-block:: python

   # Before:
   # from jwcrypto import jwk, jws, jwe, jwt
   # from jwcrypto.common import json_decode
   # from jwcrypto.jwk import JWK, JWKSet

   from pyjosers import jwk, jws, jwe, jwt
   from pyjosers.common import json_decode
   from pyjosers.jwk import JWK, JWKSet

Install pyjosers instead of the ``jwcrypto`` runtime dependency. Remove
``types-jwcrypto`` when it is no longer needed; pyjosers ships Python annotations,
a ``py.typed`` marker, and native-interface stubs. It does not install a package
named ``jwcrypto``, so both libraries can coexist for migration testing.

Compatibility was designed against the public
`jwcrypto JWT API <https://jwcrypto.readthedocs.io/en/latest/jwt.html>`_ and
checked with bidirectional wire tests, not just same-library round trips.

Supported patterns
------------------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Existing pattern
     - pyjosers behavior
   * - ``JWK.from_json``, ``JWK(**data)``, mapping access, ``key.kid``
     - Supported; key material is validated during import
   * - ``JWK.generate``; public/private exports; SHA-256 thumbprints
     - Supported for the algorithm families in :doc:`algorithms`
   * - ``JWKSet.add``, ``from_json``, ``export``, ``get_key``
     - Supported; ambiguous ``get_key`` raises
   * - ``JWT(header=..., claims=...)`` and ``make_signed_token``
     - Supported with dict or JSON object input
   * - ``JWT(jwt=..., key=key_or_set)``
     - Verify JWS and validate claims before exposing ``claims``
   * - ``JWT.from_jose_token`` then ``validate``
     - Supported; parsing alone does not expose trusted ``claims``
   * - ``token.token.objects.get("payload")``
     - Returns a snapshot containing unverified bytes for discovery
   * - ``JWT.make_encrypted_token``
     - Supported; read with ``expected_type="JWE"``
   * - ``JWS`` compact/flattened/general and detached signatures
     - Supported with protected algorithm and identifier headers
   * - ``JWE`` compact/flattened, protected headers, one recipient
     - Supported
   * - ``from_pem`` / ``export_to_pem``
     - Unencrypted classical PKCS#8 and SPKI only

Inmor admin migration
---------------------

The repository at ``~/code/research/inmor/admin`` was used to identify the
required call patterns. No files in that application are changed by this
library project. Its migration touches:

* ``inmoradmin/settings.py``: import ``jwk`` from pyjosers; existing private JSON
  loading and public-key loading retain the same calls.
* ``common/signing.py``: import ``jwt`` and ``JWK`` from pyjosers. Its algorithm
  selection, ``kid``/thumbprint fallback and custom ``typ`` remain supported.
* ``entities/lib.py``: switch module and class imports. Key-set parsing,
  direct verification, and the inline-JWKS ``self_validate`` sequence retain
  their call patterns.
* ``trustmarks/lib.py``, ``api_demo/demo.py`` and tests: switch ``jwt`` and
  ``common.json_decode`` imports.
* Dependency metadata: replace ``jwcrypto`` and remove ``types-jwcrypto``;
  regenerate the application's lockfile after choosing the pyjosers version.

For example, its federation signing workflow can remain:

.. code-block:: python

   from pyjosers import jwt

   def create_signed_jwt(claims, key, token_type=None):
       alg = key.get("alg") or "RS256"
       if alg == "Ed25519":
           alg = "EdDSA"
       header = {"alg": alg, "kid": key.get("kid") or key.thumbprint()}
       if token_type:
           header["typ"] = token_type
       token = jwt.JWT(header=header, claims=claims)
       token.make_signed_token(key)
       return token.serialize()

``datetime.timestamp()`` values retain their fractional seconds in serialized
and returned claims. Time validation follows jose-rs's whole-second semantics.
Ed25519 keys labelled ``alg=Ed25519`` are accepted with an ``EdDSA`` protected
header without rewriting the persisted JSON key. The algorithm alias is
restricted to OKP Ed25519 keys.

The current admin tests also expect **Ed448** keys. Standalone Ed448 is not
implemented by jose-rs and cannot migrate by an import change. Keep that path
on jwcrypto, rotate to a supported algorithm according to your federation's
policy, or add upstream Ed448 support before switching the entire deployment.
Composite ML-DSA-87-Ed448 is a distinct supported draft algorithm; it does not
make standalone Ed448 available.

The admin's self-validation pattern remains usable:

.. code-block:: python

   import json
   from pyjosers import jwt
   from pyjosers.jwk import JWK, JWKSet

   parsed = jwt.JWT.from_jose_token(wire)
   discovered = json.loads(parsed.token.objects["payload"])
   keys = JWKSet()
   for data in discovered["jwks"]["keys"]:
       keys.add(JWK(**data))
   parsed.validate(keys)
   authenticated = json.loads(parsed.claims)

This authenticates the statement against its advertised keys. It does not
establish that the advertised issuer belongs to a trusted federation. Keep the
application's trust-chain validation and fetch controls. pyjosers does not
fetch embedded ``jwks_uri``, ``jku`` or ``x5u`` URLs.

Intentional differences
-----------------------

* Standalone Ed448, secp256k1, X25519/X448, ECDH-ES, PBES2, RSA1_5, JWE
  compression, multiple recipients and external AAD are unsupported.
* SHA-1 RSA-OAEP needs an explicit ``legacy`` build. Unsigned tokens remain
  unavailable.
* Key exports default to including private data for API compatibility, but
  public export drops unknown extension members and rejects symmetric keys.
* PEM password encryption, certificate import, cryptography-object access
  (``get_op_key``), arbitrary hash objects for thumbprints, custom algorithm
  registration, and jwcrypto header registries are unsupported.
* ``alg``, ``kid``, ``crit`` and ``b64`` must be protected in JWS. JSON duplicate
  members, noncanonical base64url, non-finite numbers and oversized tokens
  are rejected.
* Emitting ``jku``, ``jwk``, ``x5u`` or ``x5c`` requires
  ``allow_key_reference_headers=True`` on the signing or encryption object
  (or ``jwt.encode`` / ``jwt.encode_nested``). JWS signing rejects JWE-only
  headers and registered or duplicate names in ``crit``. See :doc:`signatures`.
* Claims must be JSON objects. Numeric-date strings, booleans and negative
  values are rejected. ``check_claims=False`` is unsupported; use an explicit
  policy or ``check_claims={}`` for deliberate compatibility behavior.
* ``expected_type`` defaults to JWS rather than inferring JWE from key metadata.
* ``objects`` returns a snapshot rather than a mutable view of internal state.
  ``JWKSet.get_keys`` returns a list; keys themselves remain mutable mappings.
* Exceptions share :class:`pyjosers.JoseError`; message text and the complete
  jwcrypto exception/registry surface are not reproduced.

See :doc:`tokens` for compatibility versus strict validation defaults. Pin
algorithms at the consuming boundary and require expiration where appropriate.

Testing the transition
----------------------

``tests/test_interop.py`` signs/encrypts in each library and verifies/decrypts
in the other for every supported classical family. It also checks PEM and
thumbprint interoperability. ``tests/test_admin_migration.py`` preserves the
admin's signing and inline-JWKS validation call sequences with generated test
keys, including fractional times and the Ed25519 metadata alias. No production
keys are needed for these tests.

To exercise the actual signing and inline-validation functions from a local
admin checkout, without importing Django settings or reading application keys::

   PYJOSERS_ADMIN_CHECKOUT=~/code/research/inmor/admin pytest tests/test_admin_checkout.py

This optional test compiles only those two function definitions with pyjosers
imports and generated keys. It does not replace running the complete admin
application test suite as part of its eventual migration.
