"""Exercise token handles with an isolated, disposable SoftHSM installation."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from pyjosers import PKCS11


@pytest.mark.skipif(not PKCS11, reason="PKCS#11 feature disabled")
def test_softhsm(tmp_path, rsa_key):
    library = next((p for p in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if Path(p).exists()), None)
    if not library or not shutil.which("softhsm2-util") or not shutil.which("pkcs11-tool"):
        pytest.skip("SoftHSM2 and OpenSC are required")
    tokens = tmp_path / "tokens"
    tokens.mkdir()
    conf = tmp_path / "softhsm.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
    env = {**os.environ, "SOFTHSM2_CONF": str(conf)}
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "pyjosers-test", "--so-pin", "12345678", "--pin", "1234"], env=env, check=True, capture_output=True)
    pem = tmp_path / "rsa.pem"
    pem.write_bytes(rsa_key.export_to_pem(private_key=True))
    pem.chmod(0o600)
    subprocess.run(["softhsm2-util", "--import", str(pem), "--token", "pyjosers-test", "--label", "signing", "--id", "01", "--pin", "1234"], env=env, check=True, capture_output=True)
    secret = tmp_path / "hmac.bin"
    secret.write_bytes(bytes(range(32)))
    secret.chmod(0o600)
    subprocess.run(["pkcs11-tool", "--module", library, "--token-label", "pyjosers-test", "--login", "--pin", "1234", "--write-object", str(secret), "--type", "secrkey", "--key-type", "GENERIC:32", "--label", "hmac", "--id", "02"], env=env, check=True, capture_output=True)
    # A child interpreter avoids global PKCS#11 initialization affecting other tests.
    script = '''
import gc, json, sys
from pyjosers import JWK, JWS, JWT, JoseError
from pyjosers.hsm import Pkcs11Provider, Pkcs11Signer, Pkcs11Verifier
provider = Pkcs11Provider.with_token(sys.argv[1], "pyjosers-test")
assert provider.slot_id >= 0
session = provider.open_session("1234")
public = JWK.from_pem(open(sys.argv[2], "rb").read()).public()
for alg, label in [("RS256", "signing"), ("PS256", "signing"), ("HS256", "hmac")]:
    signer = Pkcs11Signer(session, label, alg)
    verifier = Pkcs11Verifier(session, label, alg)
    obj = JWS(b"payload")
    obj.add_signature(signer, protected={"alg": alg})
    parsed = JWS.from_jose_token(obj.serialize())
    parsed.verify(verifier)
    assert parsed.payload == b"payload"
    restricted = JWS(b"header policy")
    try:
        restricted.add_signature(signer, protected={"alg": alg, "x5c": ["Y2VydA=="]})
    except JoseError:
        assert not restricted.is_valid
    else:
        raise AssertionError("key references must require an explicit opt-in")
    permitted = JWS(b"header policy", allow_key_reference_headers=True)
    permitted.add_signature(signer, protected={"alg": alg, "x5c": ["Y2VydA=="]})
    parsed = JWS.from_jose_token(permitted.serialize())
    parsed.verify(verifier)
    assert parsed.payload == b"header policy"
    if alg != "HS256":
        parsed.verify(public)
    jwt = JWT(header={"alg": alg}, claims={"sub": "alice"})
    jwt.make_signed_token(signer)
    assert json.loads(JWT(jwt=jwt.serialize(), key=verifier).claims)["sub"] == "alice"
signer = Pkcs11Signer(session, "signing", "RS256")
del session, provider
gc.collect()
obj = JWS(b"session still alive")
obj.add_signature(signer, protected={"alg": "RS256"})
obj.verify(public)
'''
    subprocess.run([sys.executable, "-c", script, library, str(pem)], env=env, check=True, capture_output=True, text=True)
