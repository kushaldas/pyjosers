"""Compact, flattened, general, detached, and unencoded JSON Web Signatures."""
from __future__ import annotations
from dataclasses import dataclass

from . import _native
from ._native import InvalidJWSObject, InvalidJWSSignature
from .algorithms import JWS_ALGORITHMS
from .common import _bytes, _object, base64url_decode, base64url_encode, json_decode, json_encode
from .jwk import JWK, _candidates

default_allowed_algs = list(JWS_ALGORITHMS)


def _header(entry: dict) -> dict:
    protected = _object(base64url_decode(entry["protected"]))
    unprotected = entry.get("header", {})
    if not isinstance(unprotected, dict) or set(protected) & set(unprotected):
        raise InvalidJWSObject("overlapping or invalid unprotected headers")
    if any(name in unprotected for name in ("alg", "crit", "b64", "kid")):
        raise InvalidJWSObject("alg, kid, crit and b64 must be protected")
    if not isinstance(protected.get("alg"), str):
        raise InvalidJWSObject("protected alg is required")
    if "b64" in protected and not isinstance(protected["b64"], bool):
        raise InvalidJWSObject("b64 must be boolean")
    return protected


@dataclass(frozen=True)
class SignatureResult:
    """Outcome of one signature, without implying every signature is valid."""
    index: int
    protected_header: dict
    verified: bool
    error: str | None = None


class JWS:
    """A JWS carrying arbitrary bytes and one or more signatures.

    ``allowed_algs`` defaults to the supported algorithms. Pin a narrow list
    for application verification. ``understood_crit`` asserts that the caller
    has processed those additional critical parameters.
    ``allow_key_reference_headers=True`` permits emitting ``jku``, ``jwk``,
    ``x5u``, and ``x5c``; the default rejects them during signing.
    """

    def __init__(self, payload: bytes | str | None = None, header_registry=None, *, understood_crit=(),
                 allow_key_reference_headers: bool = False):
        if header_registry is not None:
            raise NotImplementedError("custom header registries are unsupported; use understood_crit")
        self._payload = None if payload is None else _bytes(payload)
        self._entries: list[dict] = []
        self._detached = False
        self._valid = False
        self._compact_input = False
        self.allowed_algs = list(default_allowed_algs)
        self.understood_crit = list(understood_crit)
        self.allow_key_reference_headers = allow_key_reference_headers
        self.verifylog: list[str] = []

    @property
    def payload(self) -> bytes:
        """Authenticated payload; raises until signing or verification succeeds."""
        if not self._valid or self._payload is None:
            raise InvalidJWSObject("payload has not been verified")
        return self._payload

    @property
    def is_valid(self) -> bool:
        """Whether the most recent signing/verification operation succeeded."""
        return self._valid

    @property
    def objects(self) -> dict:
        """Compatibility snapshot, including explicitly UNVERIFIED payload bytes.

        Mutating this snapshot does not change the signed object.
        """
        result = {"payload": self._payload}
        if len(self._entries) == 1:
            entry = self._entries[0]
            result.update(protected=base64url_decode(entry["protected"]).decode(),
                          signature=base64url_decode(entry["signature"]), valid=self._valid)
            if "header" in entry:
                result["header"] = _object(entry["header"])
        else:
            result["signatures"] = _object({"items": self._entries})["items"]
        return result

    @property
    def jose_header(self) -> dict:
        """Single-signature header snapshot; it is untrusted until verified."""
        if len(self._entries) != 1:
            raise InvalidJWSObject("a single signature is required")
        e = self._entries[0]
        return _object({**_header(e), **e.get("header", {})})

    def add_signature(self, key, alg: str | None = None, protected=None, header=None) -> None:
        """Append a signature using a JWK or PKCS#11 signer.

        The algorithm and key identifier must be protected. All signatures
        must agree on payload encoding. At most 64 signatures are permitted.
        """
        if self._payload is None:
            raise InvalidJWSObject("payload is required")
        if len(self._entries) >= 64:
            raise InvalidJWSObject("at most 64 signatures are permitted")
        p = _object(protected) if protected is not None else {}
        if alg is not None:
            if "alg" in p and p["alg"] != alg:
                raise InvalidJWSObject("algorithm mismatch")
            p["alg"] = alg
        if p.get("alg") not in self.allowed_algs:
            raise InvalidJWSObject("algorithm is not allowed")
        u = _object(header) if header is not None else None
        candidate = {"protected": base64url_encode(json_encode(p).encode())}
        if u is not None:
            candidate["header"] = u
        _header(candidate)
        if self._entries and p.get("b64", True) != _header(self._entries[0]).get("b64", True):
            raise InvalidJWSObject("all signatures must agree on b64")
        args = (self._payload, json_encode(p), None if u is None else json_encode(u), self._detached,
                self.understood_crit, self.allow_key_reference_headers)
        raw = key._sign(*args) if hasattr(key, "_sign") else _native.sign(key.export(), *args)
        entry = json_decode(raw)
        entry.pop("payload", None)
        self._entries.append(entry)
        self._valid = True

    def detach_payload(self) -> None:
        """Omit payload on serialization; retain bytes for local signing."""
        self._detached = True

    def serialize(self, compact: bool = False) -> str:
        """Serialize existing signatures. Compact form requires one protected signature."""
        if not self._entries:
            raise InvalidJWSObject("no signatures")
        encoded = _header(self._entries[0]).get("b64", True)
        payload = "" if self._payload is None or self._detached else (base64url_encode(self._payload) if encoded else self._payload.decode("utf-8"))
        if compact:
            if len(self._entries) != 1 or "header" in self._entries[0]:
                raise InvalidJWSObject("compact form requires one signature without an unprotected header")
            if not self._detached and not encoded and "." in payload:
                raise InvalidJWSObject("unencoded compact payload cannot contain a dot")
            e = self._entries[0]
            result = e["protected"] + "." + ("" if self._detached else payload) + "." + e["signature"]
        else:
            data = dict(self._entries[0]) if len(self._entries) == 1 else {"signatures": self._entries}
            if not self._detached:
                data["payload"] = payload
            result = json_encode(data)
        if len(result.encode()) > _native.MAX_TOKEN_BYTES:
            raise InvalidJWSObject("token too large")
        return result

    def deserialize(self, raw_jws: str | bytes, key=None, alg: str | None = None) -> None:
        """Replace the object from compact or JSON serialization, optionally verifying."""
        # Clear previous authenticated state before processing any new input.
        self._valid = False
        self._payload = None
        self._entries = []
        self.verifylog = []
        raw = _bytes(raw_jws)
        if len(raw) > _native.MAX_TOKEN_BYTES:
            raise InvalidJWSObject("token too large")
        try:
            text = raw.decode("utf-8")
            self._compact_input = not text.lstrip().startswith("{")
            if self._compact_input:
                parts = text.split(".")
                if len(parts) != 3:
                    raise InvalidJWSObject("expected three compact segments")
                data = dict(zip(("protected", "payload", "signature"), parts))
            else:
                data = _object(text)
            if "signatures" in data:
                if set(data) - {"payload", "signatures"}:
                    raise InvalidJWSObject("mixed flattened/general serialization")
                entries = data["signatures"]
            else:
                entries = [{k: v for k, v in data.items() if k != "payload"}]
            if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
                raise InvalidJWSObject("expected 1 to 64 signatures")
            modes = set()
            for e in entries:
                if not isinstance(e, dict) or set(e) - {"protected", "header", "signature"}:
                    raise InvalidJWSObject("invalid signature members")
                modes.add(_header(e).get("b64", True))
                base64url_decode(e["signature"])
            if len(modes) != 1:
                raise InvalidJWSObject("inconsistent payload encodings")
            detached = "payload" not in data
            payload = None if detached else (base64url_decode(data["payload"]) if modes.pop() else data["payload"].encode("utf-8"))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise InvalidJWSObject("invalid JWS serialization") from exc
        self._entries = entries
        self._detached = detached
        self._payload = payload
        if key is not None:
            self.verify(key, alg)

    @classmethod
    def from_jose_token(cls, token: str | bytes) -> JWS:
        """Parse without authentication. Use ``verify`` before consuming payload."""
        result = cls()
        result.deserialize(token)
        return result

    def _verify_entry(self, entry, key, alg, detached_payload):
        p = _header(entry)
        if p["alg"] not in self.allowed_algs or (alg is not None and alg != p["alg"]):
            raise InvalidJWSSignature("algorithm is not allowed")
        e = dict(entry)
        detached = None if detached_payload is None else _bytes(detached_payload)
        if detached is not None:
            if not self._detached and not (self._compact_input and self._payload == b""):
                raise InvalidJWSObject("cannot supply detached payload with an attached payload")
        elif not self._detached:
            e["payload"] = base64url_encode(self._payload) if p.get("b64", True) else self._payload.decode("utf-8")
        for candidate in _candidates(key, p):
            try:
                args = (json_encode(e), detached, self.understood_crit)
                return candidate._verify(*args) if hasattr(candidate, "_verify") else _native.verify(candidate.export(), *args)
            except _native.JoseError:
                continue
        raise InvalidJWSSignature("no matching key verified the signature")

    def verify(self, key, alg: str | None = None, detached_payload: bytes | str | None = None) -> None:
        """Authenticate at least one signature; raise if none verify.

        Unknown ``kid`` values never select a differently labelled key.
        Use :meth:`verify_all` if every signature must be checked.
        """
        self._valid = False
        self.verifylog = []
        for entry in self._entries:
            try:
                payload = self._verify_entry(entry, key, alg, detached_payload)
            except _native.JoseError as exc:
                self.verifylog.append(str(exc))
                continue
            if detached_payload is not None:
                self._detached = True
            self._payload = payload
            self._valid = True
            self.verifylog.append("Success")
            return
        raise InvalidJWSSignature("no signature verified")

    def verify_all(self, key, alg: str | None = None, detached_payload: bytes | str | None = None) -> list[SignatureResult]:
        """Return a result for each signature; ``is_valid`` requires all to succeed."""
        self._valid = False
        results = []
        payload = None
        for index, entry in enumerate(self._entries):
            try:
                payload = self._verify_entry(entry, key, alg, detached_payload)
                results.append(SignatureResult(index, _header(entry), True))
            except _native.JoseError as exc:
                results.append(SignatureResult(index, _header(entry), False, str(exc)))
        self._valid = bool(results) and all(r.verified for r in results)
        if self._valid:
            if detached_payload is not None:
                self._detached = True
            self._payload = payload
        return results
