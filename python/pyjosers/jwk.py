"""JSON Web Keys, key generation, DER/PEM import, and key sets."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
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
        """Generate RSA, EC, Ed25519/X25519, octet, or AKP (ML-DSA/composite) keys.

        ``size`` is in bits. RSA defaults to 2048; octet sizes are inferred
        from supported HMAC/AES algorithms, otherwise defaulting to 256.
        AKP generation requires ``alg``. EC generation requires ``crv``.
        """
        for name in ("e", "public_exponent"):
            if name in kwargs and (kty != "RSA" or type(kwargs[name]) is not int or kwargs[name] != 65537):
                raise InvalidJWKValue("only RSA exponent 65537 is supported")
            kwargs.pop(name, None)
        if kty == "oct" and size is None:
            from .algorithms import CEK_BITS
            sizes = {"HS256": 256, "HS384": 384, "HS512": 512,
                     "A128KW": 128, "A192KW": 192, "A256KW": 256,
                     "A128GCMKW": 128, "A192GCMKW": 192, "A256GCMKW": 256, **CEK_BITS}
            size = sizes.get(kwargs.get("alg"), 256)
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
            failure = InvalidJWKValue(str(exc))
            failure.category = exc.category
            failure.authentication_failure = exc.authentication_failure
            raise failure from exc
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
            data["key_ops"] = [op for op in data["key_ops"] if op in ("verify", "encrypt", "wrapKey", "deriveKey", "deriveBits")]
        return JWK(**data)

    def thumbprint(self, hashalg: Any = None) -> str:
        """Return an RFC 7638 SHA-2 thumbprint; SHA-256 is the default.

        Accepts ``sha256``, ``sha384``, ``sha512`` or an object with the
        corresponding ``name`` (including cryptography hash objects).
        Hashing is always performed by Rust; other hashes are rejected.
        """
        name = "sha256" if hashalg is None else (hashalg if isinstance(hashalg, str) else getattr(hashalg, "name", None))
        if name not in ("sha256", "sha384", "sha512"):
            raise ValueError("supported thumbprint hashes are sha256, sha384, sha512")
        return _native.key_thumbprint(self.export(), name)

    def thumbprint_uri(self, hname: str = "sha-256") -> str:
        """Return an RFC 9278 URI using sha-256, sha-384, or sha-512."""
        return _native.thumbprint_uri(self.export(), hname)

    @classmethod
    def from_der(cls, data: bytes, *, private: bool = False, format: str | None = None,
                 password: bytes | None = None, max_iterations: int = 10_000_000, **metadata) -> JWK:
        """Import explicit DER: spki, pkcs8, pkcs1-private, pkcs1-public, or sec1.

        Without format, private=True selects PKCS#8; otherwise SPKI is used.
        A password selects encrypted PKCS#8, subject to the work budget.
        """
        _nonnegative(max_iterations, "max_iterations")
        value = json_decode(_native.key_read(data, format or ("pkcs8" if private else "spki"),
                                            _password(password), max_iterations))
        value.update(metadata)
        return cls(**value)

    def export_to_der(self, private_key: bool = False, *, password: bytes | None = None,
                      scheme: str = "aes256-cbc", iterations: int = 600_000) -> bytes:
        """Export SPKI or PKCS#8 DER, optionally encrypting a private key."""
        _nonnegative(iterations, "iterations")
        return _native.key_write(self.export(), private_key, False, _password(password), scheme, iterations)

    @classmethod
    def from_pem(cls, data: bytes, password: bytes | None = None, *,
                 max_iterations: int = 10_000_000) -> JWK:
        """Import one labelled PEM key, including encrypted PKCS#8, PKCS#1 and SEC1."""
        _nonnegative(max_iterations, "max_iterations")
        return cls(**json_decode(_native.key_read(data, "pem", _password(password), max_iterations)))

    def import_from_pem(self, data: bytes, password: bytes | None = None, kid: str | None = None,
                        *, max_iterations: int = 10_000_000) -> None:
        """Atomically replace this key from PEM, optionally assigning kid."""
        key = self.from_pem(data, password, max_iterations=max_iterations)
        if kid is not None:
            key["kid"] = kid
        self._data = key._data

    def export_to_pem(self, private_key: bool = False, password: bytes | None | Literal[False] = False,
                      *, scheme: str = "aes256-cbc", iterations: int = 600_000) -> bytes:
        """Export PEM; private export requires password=None or password bytes.

        Encrypted exports use PBKDF2-HMAC-SHA256 with AES-256-CBC by default;
        scheme="aes128-cbc" selects the other supported export scheme.
        """
        if private_key and password is False:
            raise ValueError("explicitly pass password=None or password bytes for private PEM export")
        _nonnegative(iterations, "iterations")
        return _native.key_write(self.export(), private_key, True,
                                 _password(None if password is False else password), scheme, iterations)

    @classmethod
    def from_certificate_pem(cls, data: bytes) -> JWK:
        """Extract a certificate public key; no certificate trust checks are performed."""
        return cls(**json_decode(_native.key_read(data, "certificate-pem")))

    @classmethod
    def from_certificate_der(cls, data: bytes) -> JWK:
        """Extract a DER certificate public key, without validating its trust."""
        return cls(**json_decode(_native.key_read(data, "certificate-der")))

    def derive_key(self, peer: JWK, *, algorithm_id: str, length: int,
                   apu: bytes | None = None, apv: bytes | None = None) -> bytes:
        """Derive length bytes with ECDH and the JOSE Concat KDF (never raw ECDH)."""
        _nonnegative(length, "length")
        return _native.derive_key(self.export(), peer.export(), algorithm_id, length, apu, apv)


def _password(value):
    if value is not None and not isinstance(value, bytes):
        raise TypeError("key-file passwords must be bytes or None")
    return value


def _nonnegative(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


@dataclass(frozen=True)
class JWKThumbprintURI:
    """A validated RFC 9278 SHA-2 thumbprint URI."""
    uri: str

    def __post_init__(self):
        _native.thumbprint_uri_parse(self.uri)

    @classmethod
    def parse(cls, uri: str) -> JWKThumbprintURI:
        """Reject invalid prefixes, hash names, digest lengths and base64url."""
        return cls(uri)

    def matches(self, key: JWK) -> bool:
        """Compare using the hash algorithm named by this URI."""
        return json_decode(_native.thumbprint_uri_parse(self.uri, key.export()))["matches"]

    def __str__(self) -> str:
        return self.uri


@dataclass(frozen=True)
class SetLimits:
    """Import budgets; byte limits apply before JSON parsing."""
    max_bytes: int = 4 * _native.MAX_TOKEN_BYTES
    max_entries: int = 1024

    def __post_init__(self):
        _nonnegative(self.max_bytes, "max_bytes")
        _nonnegative(self.max_entries, "max_entries")


@dataclass(frozen=True)
class SelectionPolicy:
    """Bound candidate selection; compat preserves pyjosers' kid-less fallback.

    Other fallbacks are refuse (exact match), unaddressable (only unnamed sets),
    and all (deliberately allow fallback for unknown identifiers).
    """
    max_candidates: int = 64
    fallback: str = "compat"
    require_kid: bool = False

    def __post_init__(self):
        _nonnegative(self.max_candidates, "max_candidates")
        if self.fallback not in ("compat", "refuse", "unaddressable", "all"):
            raise ValueError("unknown selection fallback")

    @classmethod
    def strict(cls) -> SelectionPolicy:
        """Require an exact, unique kid match and at most one candidate."""
        return cls(1, "refuse", True)


@dataclass(frozen=True)
class Selection:
    """Deterministic candidate keys and selection context."""
    candidates: tuple[JWK, ...]
    matched_kid: str | None
    matched_by_kid: bool
    set_size: int


class JWKSet:
    """Ordered, bounded keys with strict atomic import and explicit diagnostics."""
    def __init__(self, *, limits: SetLimits | None = None, selection_policy: SelectionPolicy | None = None):
        self._keys: list[JWK] = []
        self.limits = limits if limits is not None else SetLimits()
        self.selection_policy = selection_policy if selection_policy is not None else SelectionPolicy()

    def __iter__(self) -> Iterator[JWK]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __getitem__(self, name: str):
        if name != "keys":
            raise KeyError(name)
        return list(self._keys)

    def add(self, key: JWK) -> None:
        """Add a key, deduplicating equal dictionaries and enforcing entry limits."""
        if not isinstance(key, JWK):
            raise TypeError("expected JWK")
        if key not in self._keys:
            if len(self._keys) >= self.limits.max_entries:
                raise InvalidJWKValue("JWK Set entry limit exceeded")
            self._keys.append(key)

    def get_keys(self, kid: str) -> list[JWK]:
        """Return every matching key, retaining ambiguity for callers to inspect."""
        return [key for key in self if key.get("kid") == kid]

    def get_key(self, kid: str) -> JWK | None:
        """Return a unique match, None if absent, or raise on ambiguity."""
        keys = self.get_keys(kid)
        if len(keys) > 1:
            raise JWKeyNotFound("multiple keys match kid")
        return keys[0] if keys else None

    def export(self, private_keys: bool = True, as_dict: bool = False) -> str | dict:
        """Export the set; pass private_keys=False before publishing."""
        data = {"keys": [key.export(private_keys, True) for key in self]}
        return data if as_dict else json_encode(data)

    @classmethod
    def from_json(cls, value: str | bytes, *, limits: SetLimits | None = None,
                  selection_policy: SelectionPolicy | None = None, strict: bool = True) -> JWKSet:
        """Import bounded JSON; strict=False retains unsupported/invalid material."""
        result = cls(limits=limits, selection_policy=selection_policy)
        result.import_keyset(value, strict=strict)
        return result

    def import_keyset(self, value: str | bytes, *, strict: bool = True) -> None:
        """Replace atomically. Diagnostic imports never filter or deduplicate entries."""
        raw = value.decode("utf-8") if isinstance(value, bytes) else value
        if not isinstance(raw, str):
            raise TypeError("expected JSON text")
        if len(raw.encode()) > self.limits.max_bytes:
            raise InvalidJWKValue("JWK Set byte limit exceeded")
        # Reject duplicate members before normalization; native import checks budgets
        # and material without constructing Python cryptographic objects.
        _object(raw)
        data = json_decode(_native.keyset_read(raw, self.limits.max_bytes, self.limits.max_entries, strict))
        keys = []
        for value in data["keys"]:
            key = JWK()
            key._data = value
            keys.append(key)
        self._keys = keys

    def diagnostics(self) -> list[dict]:
        """Describe every entry as usable, unsupported or invalid without key material."""
        return json_decode(_native.keyset_diagnostics(self.export()))

    def select(self, kid: str | None = None, *, policy: SelectionPolicy | None = None) -> Selection:
        """Select bounded candidates without trying cryptography or hiding ambiguity."""
        policy = policy if policy is not None else self.selection_policy
        if policy.require_kid and kid is None:
            raise JWKeyNotFound("missing required kid")
        addressable = any(k.get("kid") is not None for k in self)
        found = self.get_keys(kid) if kid is not None else []
        if len(found) > 1:
            raise JWKeyNotFound("multiple keys match kid")
        matched = bool(found)
        if not matched:
            fallback = policy.fallback
            allowed = (fallback == "all" or
                       fallback == "compat" and (kid is None or not addressable) or
                       fallback == "unaddressable" and not addressable)
            if not allowed:
                raise JWKeyNotFound("no unique key matches kid; fallback refused")
            found = list(self)
        if len(found) > policy.max_candidates:
            raise JWKeyNotFound("candidate key budget exceeded")
        if not found:
            raise JWKeyNotFound("JWK Set is empty")
        return Selection(tuple(found), kid if matched else None, matched, len(self))


def _candidates(key, header, policy=None):
    if not isinstance(key, JWKSet):
        return [key]
    return list(key.select(header.get("kid"), policy=policy).candidates)
