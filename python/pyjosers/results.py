"""Results whose protected metadata came from successful authentication."""
from __future__ import annotations
from copy import deepcopy
from decimal import Decimal
import json
from typing import Generic, TypeVar

T = TypeVar("T")


class Authenticated(Generic[T]):
    """Verified value with separate protected and unprotected header snapshots.

    Instances are returned by authentication methods, not constructed by callers.
    Header access returns copies; unprotected metadata is never a trust assertion.
    """
    __slots__ = ("_value", "_protected", "_unprotected", "_claims_json")

    def __init__(self):
        raise TypeError("Authenticated results are returned by verification or decryption")

    @classmethod
    def _from_verified(cls, value: T, protected: dict, unprotected=()) -> Authenticated[T]:
        result = object.__new__(cls)
        result._value = deepcopy(value)
        result._claims_json = False
        result._protected = deepcopy(protected)
        result._unprotected = tuple(deepcopy(list(unprotected)))
        return result

    @classmethod
    def _from_verified_json(cls, raw: str, protected: dict, unprotected=()) -> Authenticated[dict]:
        # Retain already checked JSON. Ordinary JWT validation needs no extra
        # claims copy; exact Decimal conversion happens only when requested.
        result = cls._from_verified(raw, protected, unprotected)
        result._claims_json = True
        return result

    @property
    def value(self) -> T:
        """The authenticated payload or claims."""
        if self._claims_json:
            return json.loads(self._value, parse_float=Decimal)
        return deepcopy(self._value)

    @property
    def protected(self) -> dict:
        """Only the header parameters covered by authentication."""
        return deepcopy(self._protected)

    @property
    def unprotected(self) -> tuple[dict, ...]:
        """Unauthenticated metadata, kept separate and returned as copies."""
        return deepcopy(self._unprotected)

    def __repr__(self) -> str:
        return "Authenticated(<verified value>)"


def is_authentication_failure(error: BaseException) -> bool:
    """Test the backend's coarse integrity/backend-failure category."""
    return bool(getattr(error, "authentication_failure", False))
