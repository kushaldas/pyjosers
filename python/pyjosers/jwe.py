"""Authenticated encryption with compact and single-recipient JSON serialization."""
from __future__ import annotations

from . import _native
from ._native import InvalidJWEData
from .algorithms import JWE_ALGORITHMS, JWE_ENCRYPTIONS
from .common import _bytes, _object, base64url_decode, json_decode, json_encode
from .jwk import _candidates

default_allowed_algs = list(JWE_ALGORITHMS + JWE_ENCRYPTIONS)
_FIELDS = ("protected", "encrypted_key", "iv", "ciphertext", "tag")


class JWE:
    """Encrypt bytes to one recipient using jose-rs.

    All headers must be protected. Compression, external AAD, unprotected
    headers and multiple recipients are explicitly unsupported upstream.
    ``allow_key_reference_headers=True`` permits emitting ``jku``, ``jwk``,
    ``x5u``, and ``x5c``; the default rejects them during encryption.
    """

    def __init__(self, plaintext: bytes | str | None = None, protected=None,
                 unprotected=None, aad=None, algs=None, recipient=None, header=None,
                 header_registry=None, *, allow_key_reference_headers: bool = False):
        if any(v is not None for v in (unprotected, aad, header, header_registry)):
            raise NotImplementedError("only protected headers and one recipient are supported")
        self._plaintext = None if plaintext is None else _bytes(plaintext)
        self._header = {} if protected is None else _object(protected)
        self._token: str | None = None
        self._valid = False
        self.allowed_algs = list(default_allowed_algs if algs is None else algs)
        self.decryptlog: list[str] = []
        self.allow_key_reference_headers = allow_key_reference_headers
        if recipient is not None:
            self.add_recipient(recipient)

    def _check_header(self):
        if self._header.get("alg") not in JWE_ALGORITHMS or self._header.get("alg") not in self.allowed_algs:
            raise InvalidJWEData("key management algorithm is not allowed")
        if self._header.get("enc") not in JWE_ENCRYPTIONS or self._header.get("enc") not in self.allowed_algs:
            raise InvalidJWEData("content encryption algorithm is not allowed")
        if "zip" in self._header or "crit" in self._header:
            raise InvalidJWEData("compression and critical JWE extensions are unsupported")

    @property
    def payload(self) -> bytes:
        """Authenticated plaintext, available only after encryption or decryption."""
        if not self._valid or self._plaintext is None:
            raise InvalidJWEData("plaintext has not been authenticated")
        return self._plaintext

    @property
    def jose_header(self) -> dict:
        """Copy of the protected header; untrusted until decryption succeeds."""
        return _object(self._header)

    def add_recipient(self, key, header=None) -> None:
        """Encrypt for one JWK recipient. A second recipient is unsupported."""
        if header is not None or self._token is not None:
            raise NotImplementedError("only one recipient with protected headers is supported")
        if self._plaintext is None:
            raise InvalidJWEData("plaintext is required")
        self._check_header()
        token = _native.encrypt(key.export(), self._plaintext, json_encode(self._header),
                                self.allow_key_reference_headers)
        if len(token.encode()) > _native.MAX_TOKEN_BYTES:
            raise InvalidJWEData("token too large")
        self._token = token
        self._valid = True

    def serialize(self, compact: bool = False) -> str:
        """Serialize as compact or equivalent flattened JSON."""
        if self._token is None:
            raise InvalidJWEData("no encrypted token")
        result = self._token if compact else json_encode(dict(zip(_FIELDS, self._token.split("."))))
        if len(result.encode()) > _native.MAX_TOKEN_BYTES:
            raise InvalidJWEData("token too large")
        return result

    def deserialize(self, raw_jwe: str | bytes, key=None) -> None:
        """Parse a token and optionally authenticate/decrypt it with a key or set."""
        self._valid = False
        self._plaintext = None
        self._token = None
        self._header = {}
        self.decryptlog = []
        raw = _bytes(raw_jwe)
        if len(raw) > _native.MAX_TOKEN_BYTES:
            raise InvalidJWEData("token too large")
        try:
            token = raw.decode()
            if token.lstrip().startswith("{"):
                data = _object(token)
                if set(data) - set(_FIELDS):
                    raise InvalidJWEData("only flattened single-recipient JWE JSON is supported")
                token = ".".join(data.get(field, "") for field in _FIELDS)
            parts = token.split(".")
            if len(parts) != 5:
                raise InvalidJWEData("expected five compact segments")
            for part in parts:
                base64url_decode(part)
            header = _object(base64url_decode(parts[0]))
        except (ValueError, TypeError, KeyError) as exc:
            raise InvalidJWEData("invalid JWE serialization") from exc
        self._header = header
        self._check_header()
        self._token = token
        if key is not None:
            self.decrypt(key)

    def decrypt(self, key) -> None:
        """Authenticate and decrypt with a JWK or matching JWKSet key."""
        self._valid = False
        self._plaintext = None
        self.decryptlog = []
        self._check_header()
        if self._token is None:
            raise InvalidJWEData("no encrypted token")
        for candidate in _candidates(key, self._header):
            try:
                plaintext = _native.decrypt(candidate.export(), self._token, self._header["alg"])
            except _native.JoseError as exc:
                self.decryptlog.append(str(exc))
                continue
            self._plaintext = plaintext
            self._valid = True
            self.decryptlog.append("Success")
            return
        raise InvalidJWEData("no matching key decrypted the token")

    @classmethod
    def from_jose_token(cls, token: str | bytes) -> JWE:
        """Parse without decryption."""
        result = cls()
        result.deserialize(token)
        return result
