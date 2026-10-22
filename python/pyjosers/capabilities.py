"""Read-only capabilities of the installed native extension."""
from __future__ import annotations
from dataclasses import dataclass
from . import _native
from .common import json_decode


@dataclass(frozen=True)
class Capability:
    """One backend capability, including unavailable and deliberately refused names."""
    kind: str
    identifier: str
    status: str
    available: bool
    feature: str | None
    reason: str | None
    operations: tuple[str, ...]
    note: str


_REPORT = tuple(Capability(**{**row, "operations": tuple(row["operations"])})
                for row in json_decode(_native.capability_report()))


def report() -> tuple[Capability, ...]:
    """Return immutable capability rows for this build."""
    return _REPORT


def available(kind: str | None = None) -> tuple[Capability, ...]:
    """Return usable capabilities, optionally filtered by kind."""
    return tuple(row for row in _REPORT if row.available and (kind is None or row.kind == kind))


def find(kind: str, identifier: str) -> Capability | None:
    """Look up a jws, jwe, encryption, format, or key identifier."""
    return next((row for row in _REPORT if (row.kind, row.identifier) == (kind, identifier)), None)


def features() -> dict[str, bool]:
    """Report installed Cargo features using pyjosers feature names."""
    return {"post-quantum": _native.POST_QUANTUM, "pkcs11": _native.PKCS11, "legacy": _native.LEGACY}
