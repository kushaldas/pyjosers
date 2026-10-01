"""PKCS#11 signing and verification; the private key remains on the token."""
from ._native import PKCS11

if PKCS11:
    from ._native import Pkcs11Provider, Pkcs11Session, Pkcs11Signer, Pkcs11Verifier

__all__ = ["Pkcs11Provider", "Pkcs11Session", "Pkcs11Signer", "Pkcs11Verifier"] if PKCS11 else []
