JWT claims and validation
=========================

Compatibility objects
---------------------

``JWT`` accepts the familiar ``header``, ``claims``, ``jwt``, ``key``, ``algs``,
``default_claims``, ``check_claims`` and ``expected_type`` parameters. Header and
claims accept dictionaries or JSON object strings. Reading them returns JSON
strings. Custom nested claims are preserved, including fractional timestamps.

Creation uses ``make_signed_token`` or ``make_encrypted_token`` followed by
``serialize``. Deserialization uses ``JWT(jwt=wire, key=key)`` or ``deserialize``.
Parsing without a key leaves ``claims`` unavailable. Call ``validate`` to
verify/decrypt and validate before consuming trusted claims.

Emitting ``jku``, ``jwk``, ``x5u`` or ``x5c`` requires
``allow_key_reference_headers=True`` on ``JWT`` or ``jwt.encode``.
For ``jwt.encode_nested`` the same keyword permits these members in the
inner signed JWT only. Defaults reject their emission; validation still uses
the key supplied by the caller.

A deserialized token is expected to be a **JWS** unless
``expected_type="JWE"`` was supplied. Encrypted claims cannot accidentally
satisfy a signed-token expectation. ``expected_type`` describes the JOSE
container; ``Validation.required_typ`` checks the protected token type string.

Compatibility claim checks
--------------------------

With ``check_claims=None`` (the default), present ``exp`` and ``nbf`` are checked
with 60 seconds of clock tolerance. Missing expiration is permitted. Other
registered claims are checked for type. ``iat`` is not checked against the
current time by this compatibility default.

``check_claims`` can require named claims and optionally values:

.. code-block:: python

   token = JWT(jwt=wire, key=keys, algs=["ES256"], check_claims={
       "iss": "https://issuer.example", "aud": "admin", "exp": None,
   })

A ``None`` value requires presence. ``exp``/``nbf`` with ``None`` also check
current time. A numeric check value compares against that specified time
without clock tolerance. ``aud`` matches at least one audience, ``scope``
matches a whitespace-delimited scope, and ``typ`` normalizes case and an
optional ``application/`` prefix. Other values match exactly.

An empty ``check_claims={}`` disables compatibility time checks, while retaining
claim type checks. ``check_claims=False`` is deliberately unsupported. A supplied
``Validation`` policy is additive, so compatibility options cannot disable it.

``default_claims`` fills only missing registered claims at assignment time.
With ``None``, ``iat`` and ``nbf`` use current time, ``exp`` uses current time
plus ``validity`` (default 600 seconds), and ``jti`` gets a UUID. Explicit values
are copied. Application claims should be supplied directly through ``claims``.

Complete Rust policy
--------------------

``Validation`` exposes all upstream policy fields:

.. list-table::
   :header-rows: 1
   :widths: 35 20 45

   * - Field
     - Default
     - Meaning
   * - issuer, audience, subject
     - None
     - Require a matching claim when configured
   * - required_typ
     - None
     - Exact protected ``typ`` match
   * - allowed_algorithms
     - []
     - Explicit JWS algorithm allow-list; empty adds no restriction
   * - leeway
     - 60
     - Clock tolerance, in seconds
   * - validate_exp, validate_nbf
     - True
     - Check present expiration and not-before claims
   * - validate_iat_not_future
     - True
     - Reject future issued-at times
   * - require_exp, require_nbf, require_iat
     - False
     - Require corresponding claim presence
   * - require_kid
     - False
     - Require a protected key identifier
   * - max_age
     - None
     - Bound token age in seconds; also requires ``iat``

``decode`` uses this policy, including the future-``iat`` check. It verifies
the signature first. ``Validation.validate`` is provided for already
authenticated claims; it is not a signature verifier. Numeric dates must be
nonnegative finite JSON numbers within the upstream range; fractional values
are floored for Rust's second-resolution checks, but original claims retain
the fractional value. Strings and booleans are not accepted as numeric dates.

Nested JWTs
-----------

.. doctest::

   >>> from pyjosers import JWK
   >>> from pyjosers.jwt import encode_nested, decode_nested, Validation
   >>> signing = JWK.generate(kty="EC", crv="P-256")
   >>> encryption = JWK.generate(kty="oct", size=256, alg="dir")
   >>> wire = encode_nested(signing, encryption, {"sub": "alice"},
   ...                      algorithm="ES256", encryption_algorithm="dir", encryption="A256GCM")
   >>> decode_nested(wire, signing.public(), encryption,
   ...               algorithms=["dir"], encryptions=["A256GCM"],
   ...               validation=Validation(allowed_algorithms=["ES256"]))
   {'sub': 'alice'}

Nested encoding signs first and encrypts second. Decoding requires the outer
``cty=JWT`` header, decrypts, then verifies the inner JWS and checks its claims.
Outer encryption and inner signature policies are independent.

Unverified inspection
---------------------

``decode_unverified`` returns a header and claims dictionary without checking
the signature, issuer, audience or timestamps. Similarly,
``JWT.from_jose_token(wire).token.objects["payload"]`` returns unverified bytes.
These are discovery tools, not authorization decisions. Do not use a payload's
embedded key as an application trust anchor merely because it verifies the
same payload; federation trust still needs to be established separately.
