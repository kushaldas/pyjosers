"""Restricted RSA-PSS keys must not lose their policy at the Python boundary."""
import shutil
import subprocess

import pytest

from pyjosers import JWK
from pyjosers.jwk import InvalidJWKValue


@pytest.fixture(scope="module", params=[False, True], ids=["absent-params", "sha256-params"])
def pss_pem(request):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL is required to generate RSA-PSS-specific keys")
    command = [openssl, "genpkey", "-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048"]
    if request.param:
        command.extend(["-pkeyopt", "rsa_pss_keygen_md:sha256", "-pkeyopt", "rsa_pss_keygen_saltlen:32"])
    private = subprocess.run(command, check=True, capture_output=True).stdout
    public = subprocess.run([openssl, "pkey", "-pubout"], input=private, check=True, capture_output=True).stdout
    return private, public


@pytest.mark.parametrize("private", [False, True])
@pytest.mark.parametrize("encoding", ["PEM", "DER"])
def test_pss_specific_import_rejected(pss_pem, private, encoding):
    data = pss_pem[0 if private else 1]
    if encoding == "DER":
        command = [shutil.which("openssl"), "pkey", "-outform", "DER"]
        if not private:
            command.append("-pubin")
        data = subprocess.run(command, input=data, check=True, capture_output=True).stdout
    with pytest.raises(InvalidJWKValue, match="cannot preserve their restrictions"):
        if encoding == "PEM":
            JWK.from_pem(data)
        else:
            JWK.from_der(data, private=private)
