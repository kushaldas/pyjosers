"""JWT compatibility objects, complete Rust validation policy, and nested tokens."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from decimal import Decimal
import json
import time
import uuid

from . import _native, jwe, jws
from ._native import JWTExpired, JWTNotYetValid, JWTInvalidClaimValue
from .common import _object, _pairs, json_decode, json_encode
from .jwk import SelectionPolicy
from .results import Authenticated


class JWTMissingClaim(JWTInvalidClaimValue):
    """A required claim is absent."""


class JWTInvalidClaimFormat(JWTInvalidClaimValue):
    """Claims do not conform to the required JSON types."""


def _claims_json(value: dict | str | bytes) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else value if isinstance(value, str) else json_encode(value)


def _claims_text(value: dict | str | bytes) -> str:
    """Validate JSON structure without reserializing original numeric tokens."""
    raw = _claims_json(value)
    _native.claims_check(raw)
    return raw


def _claims_object(raw):
    # Decimal is only an inspection view; original numeric tokens stay on the wire.
    value = json.loads(raw, object_pairs_hook=_pairs, parse_float=Decimal)
    if not isinstance(value, dict):
        raise JWTInvalidClaimFormat("JWT claims must be a JSON object")
    return value


@dataclass
class Validation:
    """Every jose-rs JWT validation option, with its secure upstream default.

    Numeric dates accept exact nonnegative values through nanosecond precision.
    Pass original JSON to preserve numeric text; Python floats may already
    have lost precision. ``max_age`` requires ``iat``.
    ``allowed_algorithms`` should be pinned for each application context.
    """
    issuer: str | None = None
    audience: str | None = None
    subject: str | None = None
    required_typ: str | None = None
    max_age: int | None = None
    allowed_algorithms: list[str] = field(default_factory=list)
    leeway: int = 60
    validate_exp: bool = True
    validate_nbf: bool = True
    validate_iat_not_future: bool = True
    require_exp: bool = False
    require_nbf: bool = False
    require_iat: bool = False
    require_kid: bool = False

    def validate(self, claims: dict | str, header: dict | str) -> None:
        """Validate already-authenticated claims and their protected header."""
        self._validate(claims, header, None)

    def validate_at(self, claims: dict | str, header: dict | str, now: int | float | str) -> None:
        """Validate using a trusted clock value, never a token-provided time.

        A decimal JSON-number string preserves exact nanoseconds. Expiration
        is exclusive: now equal to exp plus leeway is rejected.
        """
        if type(now) not in (int, float, str):
            raise ValueError("now must be a number or decimal JSON-number string")
        self._validate(claims, header, now if isinstance(now, str) else json_encode(now))

    def _validate(self, claims, header, now) -> None:
        # validate_claims performs the checked native parse once, with its policy.
        raw = _claims_json(claims)
        data = _claims_object(raw)
        for name in ("iss", "sub", "jti", "typ"):
            if name in data and not isinstance(data[name], str):
                raise JWTInvalidClaimFormat(f"{name} must be a string")
        for name in ("exp", "nbf", "iat"):
            if name in data and (type(data[name]) not in (int, float, Decimal) or data[name] < 0):
                raise JWTInvalidClaimFormat(f"{name} must be a nonnegative number")
        if "aud" in data:
            aud = data["aud"]
            if not isinstance(aud, str) and not (isinstance(aud, list) and all(isinstance(a, str) for a in aud)):
                raise JWTInvalidClaimFormat("aud must be a string or an array of strings")
        _native.validate_claims(raw, json_encode(_object(header)), json_encode(asdict(self)), now)


class JWT:
    """A signed or encrypted JWT with a jwcrypto-style interface.

    ``JWT(jwt=token, key=key)`` verifies a JWS by default. Specify
    ``expected_type='JWE'`` for encrypted tokens. Parsing without a key does
    not expose trusted claims. ``token.objects`` offers explicit unverified
    inspection for federation discovery, matching the admin project's usage.
    ``allow_key_reference_headers=True`` permits emitting ``jku``, ``jwk``,
    ``x5u``, and ``x5c`` when signing or encrypting; it does not affect validation.
    ``max_plaintext`` optionally limits decrypted claims bytes, inclusively.
    """

    def __init__(self, header=None, claims=None, jwt=None, key=None, algs=None,
                 default_claims=None, check_claims=None, expected_type=None, strict_serialization: bool = False, *,
                 validation: Validation | None = None, allow_key_reference_headers: bool = False,
                 max_plaintext: int | None = None, selection_policy: SelectionPolicy | None = None,
                 understood_crit=(), pbes2_iterations: int = 8192,
                 pbes2_max_iterations: int = 1_000_000):
        if expected_type not in (None, "JWS", "JWE"):
            raise ValueError("expected_type must be JWS or JWE")
        self._header = None
        self._claims = None
        self.token: jws.JWS | jwe.JWE | None = None
        self.algs = None if algs is None else list(algs)
        self.expected_type = expected_type or "JWS"
        self.default_claims = None if default_claims is None else _object(default_claims)
        self.check_claims = None if check_claims is None else _object(check_claims)
        self.validation = validation
        self.allow_key_reference_headers = allow_key_reference_headers
        self.max_plaintext = max_plaintext
        self.selection_policy = selection_policy
        self.strict_serialization = strict_serialization
        self.understood_crit = list(understood_crit)
        self.pbes2_iterations = pbes2_iterations
        self.pbes2_max_iterations = pbes2_max_iterations
        self._authenticated = None
        self.leeway = 60
        self.validity = 600
        if header is not None:
            self.header = header
        if claims is not None:
            self.claims = claims
        if jwt is not None:
            self.deserialize(jwt, key)

    @property
    def header(self) -> str:
        """JSON header. A parsed header is untrusted until validation succeeds."""
        if self._header is None:
            raise AttributeError("header is not available")
        return self._header

    @header.setter
    def header(self, value) -> None:
        self._header = json_encode(_object(value))
        self.token = None
        self._authenticated = None

    @property
    def claims(self) -> str:
        """JSON claims supplied by the caller or authenticated by ``validate``."""
        if self._claims is None:
            raise AttributeError("claims are unavailable until validation succeeds")
        return self._claims

    @claims.setter
    def claims(self, value) -> None:
        raw = _claims_text(value)
        data = _claims_object(raw)
        additions = {}
        if self.default_claims:
            now = int(time.time())
            for name, default in self.default_claims.items():
                if name in data:
                    continue
                if name not in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti"):
                    continue
                if default is None:
                    if name in ("iat", "nbf"):
                        default = now
                    elif name == "exp":
                        default = now + self.validity
                    elif name == "jti":
                        default = str(uuid.uuid4())
                    else:
                        continue
                additions[name] = default
        if additions:
            # Append only absent defaults; never round existing JSON dates.
            raw = raw.rstrip()[:-1] + ("," if data else "") + json_encode(additions)[1:]
            _native.claims_check(raw)
        self._claims = raw
        self._authenticated = None
        self.token = None

    def make_signed_token(self, key) -> None:
        """Sign current header and claims with a JWK or PKCS#11 signer."""
        header = _object(self.header)
        if header.get("b64", True) is not True:
            raise ValueError("JWT requires base64url-encoded payloads")
        token = jws.JWS(self.claims, allow_key_reference_headers=self.allow_key_reference_headers,
                        understood_crit=self.understood_crit, selection_policy=self.selection_policy)
        if self.algs is not None:
            token.allowed_algs = list(self.algs)
        token.add_signature(key, protected=header)
        self.token = token
        self.expected_type = "JWS"

    def make_encrypted_token(self, key) -> None:
        """Encrypt current claims with a JWK and protected alg/enc header."""
        token = jwe.JWE(self.claims, protected=self.header, algs=self.algs,
                        allow_key_reference_headers=self.allow_key_reference_headers,
                        understood_crit=self.understood_crit, pbes2_iterations=self.pbes2_iterations,
                        pbes2_max_iterations=self.pbes2_max_iterations, selection_policy=self.selection_policy)
        token.add_recipient(key)
        self.token = token
        self.expected_type = "JWE"

    def serialize(self, compact: bool = True) -> str:
        """Serialize the signed/encrypted token; JWT defaults to compact form."""
        if not compact:
            raise ValueError("JWT creation requires compact serialization")
        if self.token is None:
            raise ValueError("token has not been signed or encrypted")
        return self.token.serialize(compact)

    def deserialize(self, jwt: str | bytes, key=None) -> None:
        """Parse a token, clearing any previous claims, and optionally validate."""
        self.token = None
        self._claims = None
        self._header = None
        self._authenticated = None
        text = jwt.decode() if isinstance(jwt, bytes) else jwt
        if len(text.encode()) > _native.MAX_TOKEN_BYTES:
            raise ValueError("token too large")
        if text.lstrip().startswith("{"):
            if self.strict_serialization:
                raise ValueError("strict_serialization requires compact JWT input")
            data = _object(text)
            encrypted = "ciphertext" in data
        else:
            encrypted = text.count(".") == 4
        token = (jwe.JWE(understood_crit=self.understood_crit, pbes2_max_iterations=self.pbes2_max_iterations,
                         selection_policy=self.selection_policy) if encrypted else
                 jws.JWS(understood_crit=self.understood_crit, selection_policy=self.selection_policy))
        if self.algs is not None:
            token.allowed_algs = list(self.algs)
        token.deserialize(text)
        if isinstance(token, jws.JWS) and len(token._entries) != 1:
            raise ValueError("JWT requires exactly one signature")
        self._header = json_encode(token.jose_header)
        self.token = token
        if key is not None:
            self.validate(key)

    @classmethod
    def from_jose_token(cls, token: str | bytes) -> JWT:
        """Parse only; ``claims`` remains unavailable until ``validate`` succeeds."""
        return cls(jwt=token)

    def validate(self, key) -> None:
        """Authenticate first, then check claim types, time bounds and policy.

        ``check_claims=None`` checks present exp/nbf. An empty dictionary
        disables compatibility time checks. A separate ``Validation`` policy
        is additive and cannot be disabled by ``check_claims``.
        """
        self._claims = None
        self._authenticated = None
        if self.token is None:
            raise ValueError("no token")
        actual = "JWE" if isinstance(self.token, jwe.JWE) else "JWS"
        if actual != self.expected_type:
            raise ValueError(f"expected {self.expected_type}, got {actual}")
        if self.algs is not None:
            self.token.allowed_algs = list(self.algs)
        if actual == "JWS":
            if self.token.jose_header.get("b64", True) is not True:
                raise ValueError("JWT requires base64url-encoded payloads")
            self.token.verify(key)
        else:
            self.token.decrypt(key, max_plaintext=self.max_plaintext)
        try:
            raw = _claims_json(self.token.payload)
            data = _claims_object(raw)
        except (ValueError, TypeError) as exc:
            raise JWTInvalidClaimFormat("JWT claims must be a JSON object") from exc
        header = self.token._authenticated.protected
        checks = self.check_claims
        # Rust enforces registered-claim types even when time checks are disabled.
        options = Validation(leeway=self.leeway, validate_iat_not_future=False,
                             validate_exp=checks is None or ("exp" in checks and checks["exp"] is None),
                             validate_nbf=checks is None or ("nbf" in checks and checks["nbf"] is None))
        options.validate(raw, header)
        if checks:
            # Compare JSON numbers in the same exact representation, recursively.
            # Preserve original numeric expectations for exp/nbf time comparisons.
            equality_checks = _claims_object(json_encode(checks))
            for name, expected in checks.items():
                if name not in data:
                    raise JWTMissingClaim(f"missing claim: {name}")
                if expected is None:
                    continue
                if name in ("exp", "nbf"):
                    if type(expected) not in (int, float):
                        raise JWTInvalidClaimFormat("date check values must be numbers")
                    # Compare original decimal values, not rounded floats.
                    exact = data[name]
                    expected = Decimal(str(expected))
                    if name == "exp" and exact <= expected:
                        raise JWTExpired("token expired at specified check time")
                    if name == "nbf" and exact > expected:
                        raise JWTNotYetValid("token not yet valid at specified check time")
                elif name == "aud":
                    audiences = data[name] if isinstance(data[name], list) else [data[name]]
                    wanted = expected if isinstance(expected, list) else [expected]
                    if not any(a in audiences for a in wanted):
                        raise JWTInvalidClaimValue("audience mismatch")
                elif name == "typ":
                    def norm(value):
                        if not isinstance(value, str):
                            raise JWTInvalidClaimFormat("typ must be a string")
                        return (value if "/" in value else "application/" + value).lower()
                    if norm(data[name]) != norm(expected):
                        raise JWTInvalidClaimValue("type claim mismatch")
                elif name == "scope":
                    if not isinstance(data[name], str) or expected not in data[name].split():
                        raise JWTInvalidClaimValue("required scope is absent")
                elif data[name] != equality_checks[name]:
                    raise JWTInvalidClaimValue(f"claim mismatch: {name}")
        if self.validation is not None:
            self.validation.validate(raw, header)
        self._header = json_encode(header)
        self._claims = raw
        self._authenticated = Authenticated._from_verified_json(raw, header, self.token._authenticated.unprotected)

    def validate_authenticated(self, key) -> Authenticated[dict]:
        """Authenticate and validate claims once, returning their protected context."""
        self.validate(key)
        return self._authenticated


def encode(key, claims: dict, *, algorithm: str, headers: dict | None = None,
           allow_key_reference_headers: bool = False, understood_crit=()) -> str:
    """Sign a compact JWT. ``algorithm`` is an explicit caller choice.

    Emitting ``jku``, ``jwk``, ``x5u``, or ``x5c`` requires
    ``allow_key_reference_headers=True``.
    """
    header = {"typ": "JWT", **(headers or {})}
    if "alg" in header and header["alg"] != algorithm:
        raise ValueError("algorithm mismatch")
    header["alg"] = algorithm
    token = JWT(header=header, claims=claims, allow_key_reference_headers=allow_key_reference_headers, understood_crit=understood_crit)
    token.make_signed_token(key)
    return token.serialize()


def decode(token: str, key, *, validation: Validation | None = None,
           selection_policy: SelectionPolicy | None = None, understood_crit=(),
           strict_serialization: bool = False) -> dict:
    """Authenticate a JWS and apply the full Rust validation policy."""
    policy = validation if validation is not None else Validation()
    return json_decode(JWT(jwt=token, key=key, validation=policy,
                           algs=policy.allowed_algorithms or None, check_claims={},
                           selection_policy=selection_policy, understood_crit=understood_crit,
                           strict_serialization=strict_serialization).claims)


def decode_unverified(token: str) -> tuple[dict, dict]:
    """Return UNTRUSTED header and claims without authentication or validation."""
    parsed = JWT.from_jose_token(token)
    if not isinstance(parsed.token, jws.JWS):
        raise ValueError("encrypted tokens cannot be decoded without a key")
    raw = _claims_text(parsed.token.objects["payload"])
    return json_decode(parsed.header), json_decode(raw)


def encode_nested(signing_key, encryption_key, claims: dict, *, algorithm: str,
                  encryption_algorithm: str, encryption: str, headers: dict | None = None,
                  allow_key_reference_headers: bool = False, encryption_headers: dict | None = None,
                  understood_crit=(), encryption_understood_crit=(), pbes2_iterations: int = 8192) -> str:
    """Sign then encrypt a JWT, authenticating ``cty=JWT`` on the outer token.

    ``allow_key_reference_headers`` applies to the inner signed JWT header.
    """
    inner = encode(signing_key, claims, algorithm=algorithm, headers=headers,
                   allow_key_reference_headers=allow_key_reference_headers, understood_crit=understood_crit)
    outer_header = {"alg": encryption_algorithm, "enc": encryption, "cty": "JWT"}
    for name, value in (encryption_headers or {}).items():
        if name in outer_header and outer_header[name] != value:
            raise ValueError("nested encryption header mismatch")
        outer_header[name] = value
    outer = jwe.JWE(inner, protected=outer_header, understood_crit=encryption_understood_crit,
                    pbes2_iterations=pbes2_iterations)
    outer.add_recipient(encryption_key)
    return outer.serialize(compact=True)


def decode_nested(token: str, verification_key, decryption_key, *,
                  algorithms: list[str], encryptions: list[str], validation: Validation | None = None,
                  max_plaintext: int | None = None, pbes2_max_iterations: int = 1_000_000,
                  understood_crit=(), encryption_understood_crit=(),
                  selection_policy: SelectionPolicy | None = None) -> dict:
    """Decrypt then verify; max_plaintext bounds the complete inner signed JWT."""
    outer = jwe.JWE(algs=list(algorithms) + list(encryptions), understood_crit=encryption_understood_crit,
                    pbes2_max_iterations=pbes2_max_iterations, selection_policy=selection_policy)
    outer.deserialize(token, decryption_key, max_plaintext=max_plaintext)
    if outer.jose_header.get("cty") != "JWT":
        raise ValueError("nested token requires cty=JWT")
    return decode(outer.payload.decode(), verification_key, validation=validation,
                  selection_policy=selection_policy, understood_crit=understood_crit)


def decode_authenticated(token: str, key, *, validation: Validation | None = None,
                         selection_policy: SelectionPolicy | None = None, understood_crit=(),
                         strict_serialization: bool = False) -> Authenticated[dict]:
    """Decode once with protected metadata; fractional claims use Decimal exactly."""
    policy = validation if validation is not None else Validation()
    obj = JWT(jwt=token, key=key, validation=policy, algs=policy.allowed_algorithms or None,
              check_claims={}, selection_policy=selection_policy, understood_crit=understood_crit,
              strict_serialization=strict_serialization)
    return obj._authenticated
