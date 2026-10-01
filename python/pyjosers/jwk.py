"""JSON Web Keys, key generation, DER/PEM import, and key sets."""
from __future__ import annotations

import base64
from collections.abc import MutableMapping, Iterator
from typing import Any

from . import _native
from ._native import InvalidJWKValue
from .common import _object, json_decode, json_encode


class InvalidJWKType(InvalidJWKValue):
    """The requested key type is unsupported."""


class JWKeyNotFound(InvalidJWKValue):
    """No unambiguous key matches the requested identifier."""


class JWK(MutableMapping):
    """A mutable JWK mapping. Use :meth:`generate` for fresh key material.

    Explicit exports can contain secrets. ``repr`` never includes key material.
    Metadata (``alg``, ``use``, ``key_ops``) is enforced for every operation.
    """

    def __init__(self, **kwargs: Any):
        self._data: dict = {}
        if kwargs:
            self.import_key(**kwargs)

    def __getitem__(self, name: str) -> Any:
        return self._data[name]

    def __setitem__(self, name: str, value: Any) -> None:
        self._data[name] = value

    def __delitem__(self, name: str) -> None:
        del self._data[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name) from None

    def __repr__(self) -> str:
        return "JWK(<redacted>)"

    @property
    def key_type(self) -> str | None:
        """The ``kty`` parameter."""
        return self.get("kty")

    @property
    def key_id(self) -> str | None:
        """The optional ``kid`` parameter."""
        return self.get("kid")

    @property
    def is_symmetric(self) -> bool:
        """Whether this is an octet key."""
        return self.get("kty") == "oct"

    @property
    def has_private(self) -> bool:
        """Whether asymmetric private material is present."""
        return "d" in self or "priv" in self

    @property
    def has_public(self) -> bool:
        """Whether asymmetric public material is present."""
        return not self.is_symmetric and any(x in self for x in ("n", "x", "pub"))

    @classmethod
    def generate(cls, *, kty: str, size: int | None = None, crv: str | None = None, **kwargs) -> JWK:
        """Generate RSA, EC, Ed25519, octet, or AKP (ML-DSA/composite) keys.

        ``size`` is in bits. RSA defaults to 2048; octet keys default to 256.
        AKP generation requires ``alg``. EC generation requires ``crv``.
        """
        if "e" in kwargs and kwargs["e"] != 65537:
            raise InvalidJWKValue("only RSA exponent 65537 is supported")
        kwargs.pop("e", None)
        raw = _native.key_generate(kty, size if size is not None else (2048 if kty == "RSA" else 256), crv or "", kwargs.get("alg", ""))
        data = json_decode(raw)
        # Additional keywords are metadata, never replacements for generated secrets.
        if set(kwargs) & {"k", "n", "d", "p", "q", "dp", "dq", "qi", "x", "y", "pub", "priv"}:
            raise InvalidJWKValue("cannot override generated key material")
        data.update(kwargs)
        return cls(**data)

    @classmethod
    def from_json(cls, value: str | bytes) -> JWK:
        """Import a JSON key, preserving application metadata."""
        return cls(**_object(value))

    def import_key(self, **kwargs) -> None:
        """Replace this key with a structurally and cryptographically valid key."""
        try:
            data = json_decode(_native.key_normalize(json_encode(kwargs), True))
        except _native.JoseError as exc:
            raise InvalidJWKValue(str(exc)) from exc
        self._data = data

    def import_from_json(self, value: str | bytes) -> None:
        """Replace this key from its JSON representation."""
        self.import_key(**_object(value))

    def export(self, private_key: bool = True, as_dict: bool = False) -> str | dict:
        """Export a copy; default includes private material for jwcrypto compatibility."""
        data = _object(self._data) if private_key else json_decode(_native.key_public(json_encode(self._data)))
        return data if as_dict else json_encode(data)

    def export_public(self, as_dict: bool = False) -> str | dict:
        """Export only public material; symmetric keys have no public export."""
        return self.export(False, as_dict)

    def export_private(self, as_dict: bool = False) -> str | dict:
        """Export private material, rejecting a public-only key."""
        if not self.has_private and not self.is_symmetric:
            raise InvalidJWKValue("private key material is absent")
        return self.export(True, as_dict)

    def public(self) -> JWK:
        """Return a public key with private-only operation permissions removed."""
        data = self.export_public(as_dict=True)
        if "key_ops" in data:
            data["key_ops"] = [op for op in data["key_ops"] if op in ("verify", "encrypt", "wrapKey")]
        return JWK(**data)

    def thumbprint(self) -> str:
        """Return the RFC 7638 SHA-256 thumbprint, as unpadded base64url."""
        return _native.key_thumbprint(self.export())

    def thumbprint_uri(self) -> str:
        """Return the RFC 9278 SHA-256 JWK thumbprint URI."""
        return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + self.thumbprint()

    @classmethod
    def from_der(cls, data: bytes, *, private: bool = False, **metadata) -> JWK:
        """Import SPKI public or unencrypted PKCS#8 private DER."""
        value = json_decode(_native.key_import(data, private))
        value.update(metadata)
        return cls(**value)

    def export_to_der(self, private_key: bool = False) -> bytes:
        """Export SPKI or unencrypted PKCS#8 DER."""
        return _native.key_export(self.export(), private_key)

    @classmethod
    def from_pem(cls, data: bytes, password: bytes | None = None) -> JWK:
        """Import an unencrypted ``PRIVATE KEY`` or ``PUBLIC KEY`` PEM block.

        Encrypted PEM, PKCS#1, SEC1, and certificates are not accepted.
        """
        if password is not None:
            raise NotImplementedError("encrypted PEM is not supported")
        lines = data.strip().splitlines()
        if len(lines) < 3 or lines[0] not in (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN PUBLIC KEY-----"):
            raise InvalidJWKValue("expected PKCS#8 or SPKI PEM")
        private = lines[0] == b"-----BEGIN PRIVATE KEY-----"
        if lines[-1] != lines[0].replace(b"BEGIN", b"END"):
            raise InvalidJWKValue("PEM footer mismatch")
        return cls.from_der(base64.b64decode(b"".join(lines[1:-1]), validate=True), private=private)

    def import_from_pem(self, data: bytes, password: bytes | None = None, kid: str | None = None) -> None:
        """Replace this key from PEM, optionally assigning ``kid``."""
        key = self.from_pem(data, password)
        if kid is not None:
            key["kid"] = kid
        self._data = key._data

    def export_to_pem(self, private_key: bool = False, password: bytes | None = None) -> bytes:
        """Export unencrypted PKCS#8 or SPKI PEM; password encryption is unsupported."""
        if password is not None:
            raise NotImplementedError("encrypted PEM is not supported")
        der = base64.b64encode(self.export_to_der(private_key))
        label = b"PRIVATE KEY" if private_key else b"PUBLIC KEY"
        return b"-----BEGIN " + label + b"-----\n" + b"\n".join(der[i:i+64] for i in range(0, len(der), 64)) + b"\n-----END " + label + b"-----\n"


class JWKSet:
    """An ordered collection of JWKs with deterministic ``kid`` selection."""

    def __init__(self):
        self._keys: list[JWK] = []

    def __iter__(self) -> Iterator[JWK]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __getitem__(self, name: str):
        if name != "keys":
            raise KeyError(name)
        return list(self._keys)

    def add(self, key: JWK) -> None:
        """Add a key. Equal key dictionaries are deduplicated."""
        if not isinstance(key, JWK):
            raise TypeError("expected JWK")
        if key not in self._keys:
            self._keys.append(key)

    def get_keys(self, kid: str) -> list[JWK]:
        """Return all keys matching ``kid`` (rotation may reuse identifiers)."""
        return [key for key in self if key.get("kid") == kid]

    def get_key(self, kid: str) -> JWK | None:
        """Return a unique match, None if absent, or raise on ambiguity."""
        keys = self.get_keys(kid)
        if len(keys) > 1:
            raise JWKeyNotFound("multiple keys match kid")
        return keys[0] if keys else None

    def export(self, private_keys: bool = True, as_dict: bool = False) -> str | dict:
        """Export the set; request ``private_keys=False`` before publishing."""
        data = {"keys": [key.export(private_keys, True) for key in self]}
        return data if as_dict else json_encode(data)

    @classmethod
    def from_json(cls, value: str | bytes) -> JWKSet:
        """Construct a key set from JSON."""
        result = cls()
        result.import_keyset(value)
        return result

    def import_keyset(self, value: str | bytes) -> None:
        """Replace the set atomically from a JSON object with a ``keys`` array."""
        data = _object(value)
        if not isinstance(data.get("keys"), list):
            raise InvalidJWKValue("keys must be an array")
        keys = [JWK(**_object(k)) for k in data["keys"]]
        self._keys = keys


def _candidates(key, header):
    """Never fall back to a differently labelled key for an unknown kid."""
    if not isinstance(key, JWKSet):
        return [key]
    kid = header.get("kid")
    if kid is not None and any(k.get("kid") is not None for k in key):
        return key.get_keys(kid)
    return list(key)
