Errors and failed operations
============================

All native JOSE errors inherit from ``pyjosers.JoseError``, which inherits
``ValueError``. This gives callers one stable catch point. Specific classes
are also available in the corresponding modules:

.. list-table::
   :header-rows: 1

   * - Exception
     - Meaning
   * - ``jwk.InvalidJWKValue``
     - Invalid key material, metadata, or operation
   * - ``jwk.InvalidJWKType``
     - Compatibility key-type exception subclass
   * - ``jwk.JWKeyNotFound``
     - Ambiguous key lookup
   * - ``jws.InvalidJWSObject``
     - Invalid serialization, header, or object state
   * - ``jws.InvalidJWSSignature``
     - No allowed key/signature pair verified
   * - ``jwe.InvalidJWEData``
     - Invalid encrypted token, policy, or authentication failure
   * - ``jwt.JWTExpired``
     - Expiration failed
   * - ``jwt.JWTNotYetValid``
     - Not-before failed
   * - ``jwt.JWTInvalidClaimValue``
     - Required claim value or policy did not match
   * - ``jwt.JWTInvalidClaimFormat``
     - Claim JSON or registered type is invalid
   * - ``jwt.JWTMissingClaim``
     - A compatibility-required claim is missing
   * - ``pyjosers.UnsupportedAlgorithm``
     - Algorithm absent or unsupported by the native backend

Python argument/JSON helpers may raise ordinary ``TypeError`` or ``ValueError``.
Unsupported compatibility features raise ``NotImplementedError``. Accessing
unvalidated ``JWT.claims`` raises ``AttributeError``, preserving the familiar
property-unavailable pattern. Error message text is not a compatibility API.

.. code-block:: python

   from pyjosers import JWT, JoseError

   try:
       token = JWT(jwt=wire, key=trusted_keys, algs=["ES256"])
   except (JoseError, ValueError):
       # Reject the token. Do not consume its unverified payload.
       raise

Failed deserialization clears prior claims and validated state. Failed
verification/decryption never returns a previously authenticated payload as
though it belonged to the failed operation. Explicit unverified inspection
remains available on parsed JWS objects for discovery workflows.
