"""Authenticated encryption with native compact, flattened and general envelopes."""
from __future__ import annotations

from . import _native
from ._native import InvalidJWEData
from .algorithms import JWE_ALGORITHMS, JWE_ENCRYPTIONS
from .common import _bytes, _object, base64url_decode, json_decode, json_encode
from .jwk import JWK, SelectionPolicy, _candidates, _nonnegative
from .results import Authenticated

default_allowed_algs = list(JWE_ALGORITHMS + JWE_ENCRYPTIONS)
_KEY_REFERENCES = {"jku", "jwk", "x5u", "x5c"}
_REGISTERED = {"alg", "enc", "kid", "typ", "cty", "crit", "zip", "epk", "apu", "apv",
               "iv", "tag", "p2s", "p2c", "b64", "x5t", "x5t#S256"} | _KEY_REFERENCES


class JWE:
    """Encrypt bytes using JWK recipients or an explicit PBES2 password.

    Recipients are snapshotted by add_recipient; serialization performs encryption
    once for the complete set. Shared unprotected header emission is unsupported.
    JSON messages with external AAD require that AAD again during decryption.
    """
    def __init__(self, plaintext: bytes | str | None = None, protected=None,
                 unprotected=None, aad=None, algs=None, recipient=None, header=None,
                 header_registry=None, flattened: bool = True, *,
                 allow_key_reference_headers: bool = False, understood_crit=(),
                 pbes2_iterations: int = 8192, pbes2_max_iterations: int = 1_000_000,
                 selection_policy: SelectionPolicy | None = None):
        if unprotected is not None or header_registry is not None:
            raise NotImplementedError("unprotected header emission and custom registries are unsupported")
        _nonnegative(pbes2_iterations, "pbes2_iterations")
        _nonnegative(pbes2_max_iterations, "pbes2_max_iterations")
        self._plaintext = None if plaintext is None else _bytes(plaintext)
        self._header = {} if protected is None else _object(protected)
        self._envelope = None
        self._recipients: list[str] = []
        self._password: bytes | None = None
        self._valid = False
        self._authenticated = None
        self.allowed_algs = list(default_allowed_algs if algs is None else algs)
        self.decryptlog: list[str] = []
        self.allow_key_reference_headers = allow_key_reference_headers
        self.understood_crit = list(understood_crit)
        self.aad = None if aad is None else _bytes(aad)
        self.flattened = flattened
        self.pbes2_iterations = pbes2_iterations
        self.pbes2_max_iterations = pbes2_max_iterations
        self.selection_policy = selection_policy
        if recipient is not None:
            self.add_recipient(recipient, header)
        elif header is not None:
            raise ValueError("a recipient header requires a recipient")

    def _check_header(self, *, emitting=False):
        alg = self._header.get("alg")
        if (alg is not None or emitting) and (alg not in JWE_ALGORITHMS or alg not in self.allowed_algs):
            raise InvalidJWEData("key management algorithm is not allowed")
        if self._header.get("enc") not in JWE_ENCRYPTIONS or self._header["enc"] not in self.allowed_algs:
            raise InvalidJWEData("content encryption algorithm is not allowed")
        if not emitting:
            return
        if set(self._header) & {"zip", "b64", "epk", "p2s", "p2c", "iv", "tag"}:
            raise InvalidJWEData("unsupported or library-generated protected parameter")
        if not alg.startswith("ECDH-ES") and set(self._header) & {"apu", "apv"}:
            raise InvalidJWEData("apu and apv require ECDH")
        if not self.allow_key_reference_headers and set(self._header) & _KEY_REFERENCES:
            raise InvalidJWEData("key reference headers require explicit opt-in")
        if "crit" in self._header:
            names = self._header["crit"]
            if (not isinstance(names, list) or not names or
                any(not isinstance(n, str) for n in names) or len(set(names)) != len(names) or
                any(n not in self._header or n not in self.understood_crit or n in _REGISTERED for n in names)):
                raise InvalidJWEData("invalid or unsupported critical extensions")

    @property
    def payload(self) -> bytes:
        """Authenticated plaintext; pending outgoing messages are encrypted first."""
        if not self._valid and (self._recipients or self._password is not None):
            self._finalize()
        if not self._valid or self._plaintext is None:
            raise InvalidJWEData("plaintext has not been authenticated")
        return self._plaintext

    @property
    def jose_header(self) -> dict:
        """Protected header snapshot, untrusted until authentication succeeds."""
        return (json_decode(self._envelope.metadata())["protected"] if self._envelope is not None
                else _object(self._header))

    def add_recipient(self, key, header=None) -> None:
        """Stage a recipient snapshot; cryptographic errors can arise on serialization.

        Per-recipient headers may specify kid only. Multiple recipients share one
        protected algorithm and ciphertext; backend restrictions remain enforced.
        """
        if self._plaintext is None:
            raise InvalidJWEData("plaintext is required")
        if self._envelope is not None and not (self._recipients or self._password is not None):
            raise InvalidJWEData("cannot add recipients to an imported envelope")
        self._check_header(emitting=True)
        if len(self._recipients) >= 32:
            raise InvalidJWEData("at most 32 recipients are permitted")
        alg = self._header["alg"]
        if isinstance(key, (str, bytes)):
            if not alg.startswith("PBES2-"):
                raise InvalidJWEData("password input requires PBES2")
            if self._recipients or self._password is not None or header is not None:
                raise InvalidJWEData("PBES2 supports one password and no recipient header")
            self._password = _bytes(key)
        else:
            if not isinstance(key, JWK):
                raise TypeError("expected a JWK or PBES2 password")
            if alg.startswith("PBES2-"):
                raise InvalidJWEData("PBES2 requires a password, not an octet JWK")
            if self._password is not None:
                raise InvalidJWEData("cannot mix password and JWK recipients")
            if self._recipients and (alg == "dir" or alg.startswith("ECDH-ES") or alg.endswith("GCMKW")):
                raise InvalidJWEData("algorithm does not support multiple recipients")
            data = key.export(as_dict=True)
            if data.get("alg", alg) != alg or data.get("use", "enc") != "enc":
                raise InvalidJWEData("JWK algorithm or use mismatch")
            op = "deriveKey" if alg.startswith("ECDH-ES") else "encrypt" if alg == "dir" else "wrapKey"
            if "key_ops" in data and op not in data["key_ops"]:
                raise InvalidJWEData("JWK operation is not permitted")
            if header is not None:
                h = _object(header)
                if set(h) != {"kid"} or not isinstance(h["kid"], str):
                    raise InvalidJWEData("recipient header may contain only kid")
                if "kid" in self._header or data.get("kid", h["kid"]) != h["kid"]:
                    raise InvalidJWEData("recipient kid conflicts with protected header or key")
                data["kid"] = h["kid"]
                self.flattened = False
            self._recipients.append(json_encode(data))
        self._envelope = None
        self._valid = False
        self._authenticated = None

    def _options(self):
        return {"allowed_algorithms": [a for a in self.allowed_algs if a in JWE_ALGORITHMS],
                "allowed_encryptions": [a for a in self.allowed_algs if a in JWE_ENCRYPTIONS],
                "understood_crit": self.understood_crit,
                "allow_key_reference_headers": self.allow_key_reference_headers,
                "pbes2_iterations": self.pbes2_iterations,
                "pbes2_max_iterations": self.pbes2_max_iterations}

    def _finalize(self):
        if self._envelope is not None:
            return
        self._check_header(emitting=True)
        envelope = _native.jwe_encrypt(self._recipients, self._password, self._plaintext,
                                      json_encode(self._header), json_encode(self._options()),
                                      self.aad, not self.flattened or len(self._recipients) > 1)
        self._envelope = envelope
        self._valid = True
        # Keep the caller's original emission header for subsequent recipient additions.

    def serialize(self, compact: bool = False) -> str:
        """Serialize once-encrypted data; reject lossy compact conversions."""
        if not self._recipients and self._password is None and self._envelope is None:
            raise InvalidJWEData("no encrypted token")
        self._finalize()
        return self._envelope.serialize(compact)

    def deserialize(self, raw_jwe: str | bytes, key=None, *, max_plaintext: int | None = None,
                    expected_aad: bytes | None = None, recipient_index: int | None = None) -> None:
        """Parse a native envelope and optionally authenticate its selected recipient."""
        self._valid = False
        self._plaintext = None
        self._authenticated = None
        self._envelope = None
        self._recipients = []
        self._password = None
        self._header = {}
        self.decryptlog = []
        envelope = _native.JweEnvelope(_bytes(raw_jwe).decode())
        self._header = json_decode(envelope.metadata())["protected"]
        self._check_header()
        self._envelope = envelope
        if key is not None:
            self.decrypt(key, max_plaintext, expected_aad=expected_aad, recipient_index=recipient_index)

    def decrypt(self, key, max_plaintext: int | None = None, *, expected_aad: bytes | None = None,
                recipient_index: int | None = None, pbes2_max_iterations: int | None = None) -> None:
        """Authenticate one recipient; all failures clear previously trusted plaintext.

        max_plaintext is inclusive; zero permits only empty plaintext. JSON AAD
        must be provided through expected_aad or the constructor's aad argument.
        """
        self._valid = False
        self._authenticated = None
        self.decryptlog = []
        # An outgoing envelope must be finalized before discarding its plaintext.
        try:
            if self._envelope is None and (self._recipients or self._password is not None):
                self._finalize()
        finally:
            self._valid = False
            self._plaintext = None
            self._recipients = []
            self._password = None
        if max_plaintext is not None:
            _nonnegative(max_plaintext, "max_plaintext")
        if recipient_index is not None:
            _nonnegative(recipient_index, "recipient_index")
        if pbes2_max_iterations is not None:
            _nonnegative(pbes2_max_iterations, "pbes2_max_iterations")
        if self._envelope is None:
            raise InvalidJWEData("no encrypted token")
        self._check_header()
        options = self._options()
        options["max_plaintext"] = max_plaintext
        if pbes2_max_iterations is not None:
            options["pbes2_max_iterations"] = pbes2_max_iterations
        try:
            password = _bytes(key) if isinstance(key, (str, bytes)) else None
            keys = [] if password is not None else [k.export() for k in _candidates(key, self._header, self.selection_policy)]
            plaintext, metadata = self._envelope.decrypt(keys, password, json_encode(options),
                                                        self.aad if expected_aad is None else _bytes(expected_aad), recipient_index)
            meta = json_decode(metadata)
        except _native.JoseError as exc:
            self.decryptlog.append(str(exc))
            if isinstance(exc, InvalidJWEData):
                raise
            converted = InvalidJWEData(str(exc))
            converted.category = exc.category
            converted.authentication_failure = exc.authentication_failure
            raise converted from exc
        self._plaintext = plaintext
        self._header = meta["protected"]
        self._authenticated = Authenticated._from_verified(plaintext, meta["protected"], meta["unprotected"])
        self._valid = True
        self.decryptlog.append("Success")

    def decrypt_authenticated(self, key, max_plaintext: int | None = None, **options) -> Authenticated[bytes]:
        """Decrypt once and return protected metadata separately from unprotected headers."""
        self.decrypt(key, max_plaintext, **options)
        return self._authenticated

    @classmethod
    def from_jose_token(cls, token: str | bytes) -> JWE:
        """Parse a token without decryption."""
        result = cls()
        result.deserialize(token)
        return result
