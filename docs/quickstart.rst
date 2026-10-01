Quickstart
==========

Sign and validate application claims
------------------------------------

The functional API uses the complete jose-rs validation policy. Set the issuer,
audience and token type expected by the consuming application.

.. doctest::

   >>> import time
   >>> from pyjosers import JWK
   >>> from pyjosers.jwt import encode, decode, Validation
   >>> key = JWK.generate(kty="EC", crv="P-256", kid="current")
   >>> claims = {"iss": "issuer", "aud": "api", "sub": "alice", "exp": int(time.time()) + 300}
   >>> token = encode(key, claims, algorithm="ES256", headers={"kid": "current"})
   >>> policy = Validation(issuer="issuer", audience="api", required_typ="JWT",
   ...                     allowed_algorithms=["ES256"], require_exp=True, require_kid=True)
   >>> decode(token, key.public(), validation=policy)["sub"]
   'alice'

Encrypt arbitrary bytes
-----------------------

.. doctest::

   >>> from pyjosers import JWE
   >>> secret = JWK.generate(kty="oct", size=256, alg="dir")
   >>> encrypted = JWE(b"private message", protected={"alg": "dir", "enc": "A256GCM"})
   >>> encrypted.add_recipient(secret)
   >>> received = JWE(algs=["dir", "A256GCM"])
   >>> received.deserialize(encrypted.serialize(compact=True), secret)
   >>> received.payload
   b'private message'

Publish verification keys
-------------------------

.. doctest::

   >>> from pyjosers import JWKSet
   >>> keys = JWKSet()
   >>> keys.add(key)
   >>> public_document = keys.export(private_keys=False)
   >>> public_keys = JWKSet.from_json(public_document)
   >>> public_keys.get_key("current").has_private
   False

The jwcrypto-compatible export defaults include private keys. Always pass
``private_keys=False`` when publishing a key set. Symmetric secrets have no
public export and cannot be included in a public key set.
