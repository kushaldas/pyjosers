"""Rust-backed JOSE with jwcrypto-style JWK, JWS, JWE and JWT APIs."""
from . import algorithms, common, jwk, jws, jwe, jwt, x509
from ._native import JoseError, UnsupportedAlgorithm, POST_QUANTUM, PKCS11, MAX_TOKEN_BYTES
from .jwk import JWK, JWKSet
from .jws import JWS
from .jwe import JWE
from .jwt import JWT, Validation

__version__ = "0.1.0"
__all__ = ["jwk", "jws", "jwe", "jwt", "common", "algorithms", "x509",
           "JWK", "JWKSet", "JWS", "JWE", "JWT", "Validation", "JoseError",
           "UnsupportedAlgorithm", "POST_QUANTUM", "PKCS11", "MAX_TOKEN_BYTES"]
