Encryption
==========

The JWE class authenticates and encrypts bytes using one recipient. It supports
compact serialization and an equivalent flattened JSON representation whose
headers are all protected. All cryptography is performed by jose-rs.

.. doctest::

   >>> from pyjosers import JWK, JWE
   >>> key = JWK.generate(kty="oct", size=256, alg="A256KW", use="enc")
   >>> message = JWE(b"confidential", protected={"alg": "A256KW", "enc": "A256GCM", "kid": "encryption-1"})
   >>> message.add_recipient(key)
   >>> wire = message.serialize(compact=True)
   >>> received = JWE(algs=["A256KW", "A256GCM"])
   >>> received.deserialize(wire, key)
   >>> received.payload
   b'confidential'

``algs`` contains both key-management and content-encryption names. Narrow this
list to the pair(s) expected by the application. A JWK's pinned ``alg`` must
match the protected key-management algorithm. For an unpinned key, the selected
algorithm must pass the object's allow-list before being bound for the native
decryption operation. The default allow-list contains all compiled supported
algorithms, for compatibility.

Encryption rejects ``jku``, ``jwk``, ``x5u`` and ``x5c`` by default. Use
``JWE(plaintext, protected=header, allow_key_reference_headers=True)`` to
emit application-approved key references. The option does not fetch URLs,
select a key from the header, or change decryption policy.

Direct encryption
-----------------

For ``alg=dir``, the octet key is the content encryption key. Match its size to
``enc``:

.. list-table::
   :header-rows: 1

   * - Content encryption
     - Required key bits
   * - A128GCM
     - 128
   * - A192GCM
     - 192
   * - A256GCM
     - 256
   * - A128CBC-HS256
     - 256
   * - A192CBC-HS384
     - 384
   * - A256CBC-HS512
     - 512

For AES key wrapping, the wrapping key size is 128, 192 or 256 bits according
to ``A128KW``, ``A192KW`` or ``A256KW``. For RSA-OAEP-256, encrypt with a public
RSA JWK and decrypt with its private counterpart. The library generates fresh
content keys and IVs as required; the API does not accept caller-selected IVs.

Permissions and failures
------------------------

Direct encryption checks ``encrypt`` / ``decrypt`` key operations; wrapping and
RSA key transport check ``wrapKey`` / ``unwrapKey``. Key-set selection follows
the same protected ``kid`` rules as JWS.

Authentication failure exposes no plaintext. A failed decryption clears any
previous plaintext and ``payload`` raises. ``jose_header`` can be inspected
before decryption but is untrusted at that point.

Upstream limits
---------------

Multiple recipients, external AAD, unprotected headers, compression, ECDH-ES
and PBES2 are unsupported. Unsupported constructor arguments fail explicitly.
JWE ``crit``, ``zip``, ``b64``, ``epk``, ``apu``, ``apv``, ``p2s``, ``p2c``,
``iv`` and ``tag`` headers are rejected during encryption. These limits are not silently
emulated with a different cryptographic library. PKCS#11 JWE is not offered:
the upstream JWE API operates on software key material.
