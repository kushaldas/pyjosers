"""Supported JOSE names, deliberately excluding unsecured and legacy algorithms."""
from ._native import POST_QUANTUM, LEGACY

from .capabilities import available

JWS_ALGORITHMS = tuple(row.identifier for row in available("jws"))
JWE_ALGORITHMS = tuple(row.identifier for row in available("jwe"))
JWE_ENCRYPTIONS = tuple(row.identifier for row in available("encryption"))
CEK_BITS = {"A128GCM": 128, "A192GCM": 192, "A256GCM": 256,
            "A128CBC-HS256": 256, "A192CBC-HS384": 384, "A256CBC-HS512": 512}
