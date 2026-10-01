"""JOSE certificate binding helpers, without certificate chain trust validation."""
import base64
from . import _native
from .common import _object, json_encode, json_decode


def thumbprint_sha256(certificate_der: bytes) -> str:
    """Compute ``x5t#S256`` over a DER certificate."""
    return _native.certificate("thumbprint", '{"alg":"RS256"}', certificate_der)


def bind_certificate(header: dict, certificate_der: bytes) -> dict:
    """Return a copy with ``x5c`` and ``x5t#S256`` bound to a certificate."""
    return json_decode(_native.certificate("bind", json_encode(_object(header)), certificate_der))


def verify_certificate_binding(header: dict, certificate_der: bytes) -> None:
    """Check the header's certificate binding; does not establish CA trust."""
    _native.certificate("verify", json_encode(_object(header)), certificate_der)


def leaf_certificate(header: dict) -> bytes:
    """Decode the first standard-base64 certificate from ``x5c``."""
    chain = header.get("x5c")
    if not isinstance(chain, list) or not chain:
        raise ValueError("x5c certificate chain is missing")
    return base64.b64decode(chain[0], validate=True)
