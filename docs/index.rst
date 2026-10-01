pyjosers
========

pyjosers provides Python bindings to jose-rs through PyO3. It supports JSON
Web Keys, signatures, encryption and tokens, including post-quantum signatures
and PKCS#11 signing. The Python objects deliberately resemble jwcrypto's
``jwk``, ``jws``, ``jwe`` and ``jwt`` modules.

Cryptographic operations run in Rust with the Python GIL released. The Python
layer handles object lifecycle, JSON serialization, compatibility conventions
and application policy. There are no required Python runtime dependencies.

.. toctree::
   :maxdepth: 2

   installation
   quickstart
   keys
   signatures
   encryption
   tokens
   migration
   algorithms
   hsm
   api
   exceptions
   development

A first signed token
--------------------

.. doctest::

   >>> from pyjosers import jwk, jwt
   >>> key = jwk.JWK.generate(kty="EC", crv="P-256")
   >>> token = jwt.JWT(header={"alg": "ES256"}, claims={"sub": "alice"})
   >>> token.make_signed_token(key)
   >>> verified = jwt.JWT(jwt=token.serialize(), key=key.public(), algs=["ES256"])
   >>> from pyjosers.common import json_decode
   >>> json_decode(verified.claims)
   {'sub': 'alice'}
