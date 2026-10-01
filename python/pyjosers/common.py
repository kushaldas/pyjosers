"""JSON and base64url helpers shared by the compatibility modules."""
from __future__ import annotations

import base64
import json
import math
import re
from typing import Any

from ._native import JoseError

JWException = JoseError


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def json_encode(value: Any) -> str:
    """Encode compact, deterministic JSON; reject non-finite numbers."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)


def json_decode(value: str | bytes) -> Any:
    """Decode JSON, rejecting duplicate members and non-finite numbers."""
    def invalid(value):
        raise ValueError("non-finite JSON number")
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("non-finite JSON number")
        return result
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=invalid, parse_float=finite_float)


def base64url_encode(value: bytes) -> str:
    """Encode bytes without base64 padding."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str | bytes) -> bytes:
    """Decode an unpadded JOSE base64url value with strict alphabet checking."""
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid base64url alphabet")
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64url_encode(decoded) != value:
        raise ValueError("noncanonical base64url encoding")
    return decoded


def _object(value: dict | str | bytes) -> dict:
    result = json_decode(value) if isinstance(value, (str, bytes)) else json_decode(json_encode(value))
    if not isinstance(result, dict):
        raise ValueError("expected a JSON object")
    return result


def _bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError("expected bytes or str")
