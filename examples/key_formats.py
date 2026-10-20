"""Run with: python examples/key_formats.py (requires cryptography for the certificate)."""
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pyjosers import JWK, JWKThumbprintURI

key = JWK.generate(kty="EC", crv="P-256", alg="ES256")
password = b"disposable file password"
encrypted = key.export_to_pem(private_key=True, password=password)
restored = JWK.from_pem(encrypted, password=password, max_iterations=600_000)
assert restored.thumbprint() == key.thumbprint()
der = key.export_to_der(private_key=True, password=password)
assert JWK.from_der(der, private=True, password=password).thumbprint() == key.thumbprint()
assert JWKThumbprintURI.parse(key.thumbprint_uri("sha-512")).matches(restored)

# Explicit None acknowledges a plaintext private export.
private = serialization.load_pem_private_key(key.export_to_pem(True, password=None), None)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disposable.example")])
now = datetime.now(timezone.utc)
certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(private.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + timedelta(days=1))
               .sign(private, hashes.SHA256()))
public = JWK.from_certificate_pem(certificate.public_bytes(serialization.Encoding.PEM))
assert public.thumbprint() == key.thumbprint()
# Extraction does not establish certificate trust or validate its chain.
print("Encrypted PEM/DER, thumbprint URI and certificate extraction verified")
