"""Fresh, process-local test keys. No application key files are read."""
import pytest
from pyjosers import JWK


@pytest.fixture(scope="session")
def rsa_key():
    return JWK.generate(kty="RSA", size=2048)


@pytest.fixture(scope="session")
def signing_keys(rsa_key):
    return {
        "RSA": rsa_key,
        "P-256": JWK.generate(kty="EC", crv="P-256"),
        "P-384": JWK.generate(kty="EC", crv="P-384"),
        "P-521": JWK.generate(kty="EC", crv="P-521"),
        "Ed25519": JWK.generate(kty="OKP", crv="Ed25519"),
        "oct": JWK.generate(kty="oct", size=512),
    }
