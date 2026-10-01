Signatures and serialization
============================

Compact and JSON forms
----------------------

.. doctest::

   >>> from pyjosers import JWK, JWS
   >>> key = JWK.generate(kty="EC", crv="P-256")
   >>> signed = JWS(b"arbitrary payload")
   >>> signed.add_signature(key, protected={"alg": "ES256"})
   >>> compact = signed.serialize(compact=True)
   >>> received = JWS.from_jose_token(compact)
   >>> received.allowed_algs = ["ES256"]
   >>> received.verify(key.public())
   >>> received.payload
   b'arbitrary payload'

``serialize()`` defaults to flattened JSON for one signature and general JSON
for multiple signatures. Compact form requires exactly one signature and no
unprotected header. A JSON token may carry an unprotected header, but ``alg``,
``kid``, ``crit`` and ``b64`` must be protected. Overlapping protected and
unprotected names are rejected.

Call ``add_signature`` again to add another signer over the same payload.
Every signature must agree on the payload's base64url mode. ``verify`` succeeds
if at least one signature verifies with the supplied key or key set.
``verify_all`` returns a ``SignatureResult`` for every entry, including failures;
``is_valid`` is true only if all entries verify. It does not raise merely
because an individual signature fails.

At most 64 signatures and 1 MiB of serialized token data are accepted. JSON
members must be unique, and base64url encodings must use the canonical,
unpadded JOSE alphabet. These restrictions also apply to untrusted parsing.

Detached signatures
-------------------

.. doctest::

   >>> payload = b"external binary data\x00\xff"
   >>> signed = JWS(payload)
   >>> signed.detach_payload()
   >>> signed.add_signature(key, protected={"alg": "ES256"})
   >>> received = JWS.from_jose_token(signed.serialize())
   >>> received.verify(key.public(), detached_payload=payload)
   >>> received.payload == payload
   True

In JSON form the detached payload member is omitted. In compact form the
middle segment is empty. Supply ``detached_payload`` during verification;
passing it alongside an attached, nonempty compact payload or an attached
JSON payload is rejected.

RFC 7797 unencoded payloads
---------------------------

.. code-block:: python

   signed = JWS(b"payload")
   signed.add_signature(key, protected={
       "alg": "ES256", "b64": False, "crit": ["b64"],
   })

Attached unencoded payloads must be UTF-8; compact attached payloads cannot
contain a dot. Detached unencoded payloads can contain arbitrary bytes.
JWT objects deliberately reject unencoded JWT payloads.

Critical extensions
-------------------

The implementation understands ``b64``. Additional critical parameters are
accepted only when listed in ``JWS(understood_crit=[...])`` or assigned to
``understood_crit`` before verification. This list asserts that the application
has actually processed the named extensions; it does not implement their
semantics. Unknown critical parameters fail verification.

Signing rejects duplicate names in ``crit`` and names registered by the
original JOSE specifications (such as ``kid``), even if they are listed in
``understood_crit``. RFC 7797 ``b64`` and understood application extensions
remain supported. Verification of peer tokens retains the existing policy.
Signing also rejects JWE-only members such as ``enc``, ``zip`` and ``epk``
in protected or unprotected headers.

Trust and object state
----------------------

``payload`` requires successful signing or verification. ``objects`` is a
compatibility snapshot with potentially **unverified** bytes; changing it does
not modify the token. ``jose_header`` is also a snapshot and is untrusted until
verification succeeds. A failed verification or deserialization clears the
validated state. ``verifylog`` gives per-attempt summaries without key exports.

Certificate binding
-------------------

``pyjosers.x509`` wraps jose-rs's certificate helpers:
``bind_certificate``, ``leaf_certificate``, ``thumbprint_sha256`` and
``verify_certificate_binding``. Binding checks compare certificate bytes and
SHA-256 thumbprints. They do not validate certificate syntax, CA chains,
revocation, hostname, or key usage. No ``x5u`` or ``jku`` URL is fetched.

Signing rejects ``jku``, ``jwk``, ``x5u`` and ``x5c`` in protected or
unprotected headers by default. To emit application-approved key references
(including an ``x5c`` chain from ``bind_certificate``), construct
``JWS(payload, allow_key_reference_headers=True)``. This also applies to
PKCS#11 signing. ``kid``, ``x5t`` and ``x5t#S256`` do not require an opt-in.
The option controls emission only; verification still uses the caller's key.
