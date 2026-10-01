PKCS#11 signing and verification
================================

A build with the default ``pkcs11`` feature exposes provider, session, signer
and verifier classes under ``pyjosers.hsm``. The operations use the same JWS
and JWT interfaces as software keys. Private keys never need to be exported
from the token.

.. code-block:: python

   import os
   from pyjosers import JWS, JWT
   from pyjosers.hsm import Pkcs11Provider, Pkcs11Signer, Pkcs11Verifier

   provider = Pkcs11Provider.with_token(
       "/usr/lib/softhsm/libsofthsm2.so", "application-token"
   )
   session = provider.open_session(os.environ["TOKEN_PIN"])
   signer = Pkcs11Signer(session, "signing-key", "RS256")
   verifier = Pkcs11Verifier(session, "signing-key", "RS256")

   token = JWT(header={"alg": "RS256", "kid": "token-key"}, claims={"sub": "alice"})
   token.make_signed_token(signer)
   received = JWT(jwt=token.serialize(), key=verifier, algs=["RS256"])

Provider selection
------------------

``Pkcs11Provider(path)`` requires one unambiguous initialized token.
``with_token(path, label, serial=None)`` selects by token label and optionally
serial. ``with_slot_id(path, slot_id)`` selects a numeric slot.
``provider.slot_id`` reports the selected slot.

Signers and verifiers locate a unique key by label in an authenticated session.
For ``HS*``, the label identifies a secret HMAC key. Other supported algorithms
use private/public key objects. Actual mechanism availability depends on the
module and token. A configured JOSE algorithm is bound to the handle and must
match the token's protected header.

Object lifetime and scope
-------------------------

Native handles retain the underlying session. Dropping the Python provider or
session variable does not invalidate a live signer. Signing and verification
release the GIL; the underlying session is serialized by the backend. Treat
handles as process-local and reopen sessions after a process fork.

This API does not provision tokens, generate token keys, export token objects,
or perform JWE encryption through PKCS#11. Use vendor tools to provision keys.
Use JWK public keys to verify signatures in software if desired.

Testing
-------

``tests/test_hsm.py`` creates a temporary SoftHSM token directory, provisions
fresh test RSA/HMAC keys, and checks signing, verification, software
interoperability and handle lifetime in a child process. It runs automatically
when SoftHSM2 and OpenSC tools are installed; otherwise it skips explicitly.
It never opens or changes the user's existing tokens.
