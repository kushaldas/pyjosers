Keys and key sets
=================

Generation and metadata
-------------------------

``JWK.generate`` uses bit sizes and standard JOSE names. RSA defaults to 2048
bits; supported RSA sizes are 2048 through 8192 bits, with exponent 65537.
EC requires P-256, P-384 or P-521. OKP supports Ed25519 and X25519. AKP generation
requires a post-quantum build and an explicit ML-DSA/composite algorithm.
Octet sizes are inferred from HMAC/AES algorithm names, otherwise defaulting to
256 bits. Explicit sizes still undergo operation checks.

.. doctest::

   >>> from pyjosers import JWK, JWKThumbprintURI
   >>> key = JWK.generate(kty="EC", crv="P-256", alg="ES256", kid="current")
   >>> imported = JWK.from_json(key.export())
   >>> imported.thumbprint() == key.thumbprint()
   True
   >>> JWKThumbprintURI.parse(key.thumbprint_uri("sha-384")).matches(key.public())
   True

Mapping mutations are validated when a key is next used. ``alg``, ``use`` and
``key_ops`` are enforced for every operation. ``public()`` removes private-only
operations and retains agreement operations for EC/X25519 keys.
The compatibility alias accepts Ed25519-key ``alg=Ed25519`` metadata with an
``EdDSA`` wire header. The reverse alias is refused; allowlists distinguish them.

``export()`` includes private material by default for JWCrypto compatibility.
Use ``export_public()`` or ``public().export()`` for public interchange. Symmetric
keys have no public representation. Key representations redact secrets, but
explicitly exported Python bytes, strings and dictionaries cannot be guaranteed
to be zeroized. Thumbprints identify material; they do not confer trust.

``thumbprint`` supports SHA-256 (default), SHA-384 and SHA-512, as strings or
objects with the corresponding ``name``. Thumbprint URIs use hyphenated hash
names and are validated for prefix, encoding and digest length.

PEM, DER and encrypted key files
----------------------------------

.. doctest::

   >>> pem = key.export_to_pem(private_key=True, password=None)
   >>> JWK.from_pem(pem).thumbprint() == key.thumbprint()
   True
   >>> der = key.export_to_der(private_key=True)
   >>> JWK.from_der(der, private=True).thumbprint() == key.thumbprint()
   True

Private PEM export now requires an explicit choice: ``password=None`` exports
plaintext, while password bytes request encryption. Omitting the password raises
``ValueError``. Public PEM export still needs no password argument.

PEM labels select PKCS#8 private, SPKI public, PKCS#1 RSA private/public or SEC1
EC private input. DER defaults to SPKI, or PKCS#8 with ``private=True``; explicit
``format`` accepts ``spki``, ``pkcs8``, ``pkcs1-private``, ``pkcs1-public`` or
``sec1``. Formats are not guessed. SEC1 must carry a supported named curve.
PKCS#1 CRT consistency, RSA size limits and RSA-PSS-specific wrapper refusals
remain enforced. Exports use PKCS#8/SPKI, with portable Ed25519 private encoding.
X25519 uses JWK JSON interchange; PKCS#8/SPKI import and export are unavailable upstream.
Composite keys use JWK JSON interchange.

Encrypted PKCS#8 uses the existing password arguments. ``max_iterations`` bounds
import work (default 10,000,000). Export defaults to 600,000 iterations and
``scheme="aes256-cbc"``; ``aes128-cbc`` is also supported. Both export schemes
use PBKDF2-HMAC-SHA256. Import additionally accepts SHA384/SHA512 PRFs with the
backend's supported AES-CBC schemes. PBES1, scrypt, legacy encrypted PEM, SHA-1
PRFs and unsupported ciphers are refused without fallback.

``from_certificate_pem`` and ``from_certificate_der`` explicitly extract an
X.509 subject public key. They perform no signature, validity, chain or trust
validation. A certificate chain is not accepted as a single certificate.

The complete runnable key-format example includes password encryption and
certificate extraction; it uses the development dependency ``cryptography``
only to generate a disposable certificate:

.. literalinclude:: ../examples/key_formats.py
   :language: python

Bounded key sets and rotation
-------------------------------

Imports are strict and atomic. ``add`` deduplicates equal dictionaries; JSON
imports retain duplicate entries so ambiguous identifiers remain visible.
Defaults bound imports to 4 MiB and 1,024 entries, and selection to 64 candidate
keys. Limits fail rather than truncating the set. ``SetLimits`` and
``SelectionPolicy`` expose overrides.

.. doctest::

   >>> from pyjosers import JWKSet, SetLimits, SelectionPolicy
   >>> keys = JWKSet(limits=SetLimits(max_entries=10), selection_policy=SelectionPolicy.strict())
   >>> keys.add(key.public())
   >>> keys.select("current").matched_by_kid
   True
   >>> keys.diagnostics()[0]["status"]
   'usable'

The default ``fallback="compat"`` retains existing behavior: a protected ``kid``
selects a unique match; an unknown identifier fails if any key is labelled;
a kid-less token or an entirely unlabelled set permits a bounded sweep.
``SelectionPolicy.strict()`` requires exactly one named match.
``fallback="unaddressable"`` permits a sweep only for entirely unlabelled sets;
``fallback="all"`` deliberately permits unknown-identifier fallback.

``JWKSet.from_json(..., strict=False)`` retains structurally valid entries with
unsupported or invalid material for ``diagnostics()``. Diagnostics preserve
identifiers and classify every entry as usable, unsupported or invalid. They
never turn invalid material into a usable key or remove ambiguous matches.
Issuer trust remains the application's responsibility.
