"""Bidirectional wire compatibility, independently checked by jwcrypto."""
import json
import time
import pytest
from jwcrypto import jwk as old_jwk, jws as old_jws, jwe as old_jwe, jwt as old_jwt
from pyjosers import JWK, JWS, JWE, JWT
from pyjosers.algorithms import JWE_ALGORITHMS, JWE_ENCRYPTIONS, CEK_BITS

CLASSICAL = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
             "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]


def get_key(alg, keys):
    if alg.startswith(("RS", "PS")):
        return keys["RSA"]
    if alg.startswith("HS"):
        return keys["oct"]
    return keys[{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521", "EdDSA": "Ed25519"}[alg]]


@pytest.mark.parametrize("alg", CLASSICAL)
@pytest.mark.parametrize("compact", [True, False])
def test_jws_both_directions(signing_keys, alg, compact):
    key = get_key(alg, signing_keys)
    other = old_jwk.JWK.from_json(key.export())
    payload = b"\x00binary\xffpayload"
    ours = JWS(payload)
    ours.add_signature(key, protected={"alg": alg})
    theirs = old_jws.JWS()
    theirs.deserialize(ours.serialize(compact), other)
    assert theirs.payload == payload
    theirs = old_jws.JWS(payload)
    theirs.add_signature(other, protected={"alg": alg})
    ours = JWS()
    ours.deserialize(theirs.serialize(compact), key)
    assert ours.payload == payload


@pytest.mark.parametrize("alg", JWE_ALGORITHMS)
@pytest.mark.parametrize("enc", JWE_ENCRYPTIONS)
def test_jwe_both_directions(rsa_key, alg, enc):
    size = CEK_BITS[enc] if alg == "dir" else {"A128KW": 128, "A192KW": 192, "A256KW": 256}.get(alg, 256)
    key = rsa_key if alg.startswith("RSA") else JWK.generate(kty="oct", size=size)
    other = old_jwk.JWK.from_json(key.export())
    payload = b"encrypted\x00\xffdata"
    header = {"alg": alg, "enc": enc, "typ": "application/example", "kid": "one"}
    ours = JWE(payload, protected=header, recipient=key)
    theirs = old_jwe.JWE()
    theirs.deserialize(ours.serialize(True), other)
    assert theirs.payload == payload
    assert theirs.jose_header == header
    theirs = old_jwe.JWE(payload, protected=header, recipient=other)
    ours = JWE()
    ours.deserialize(theirs.serialize(True), key)
    assert ours.payload == payload
    # The flattened JSON adapters preserve exactly the authenticated compact bytes.
    clone = JWE()
    clone.deserialize(ours.serialize(False), key)
    assert clone.payload == payload


@pytest.mark.parametrize("alg", CLASSICAL)
def test_jwt_claims_interop(signing_keys, alg):
    key = get_key(alg, signing_keys)
    other = old_jwk.JWK.from_json(key.export())
    claims = {"iss": "https://issuer.example", "sub": "alice", "iat": time.time(),
              "exp": time.time() + 3600, "aud": ["admin", "api"]}
    ours = JWT(header={"alg": alg, "typ": "entity-statement+jwt"}, claims=claims)
    ours.make_signed_token(key)
    assert json.loads(old_jwt.JWT(jwt=ours.serialize(), key=other).claims) == claims
    theirs = old_jwt.JWT(header={"alg": alg}, claims=claims)
    theirs.make_signed_token(other)
    assert json.loads(JWT(jwt=theirs.serialize(), key=key).claims) == claims


@pytest.mark.parametrize("kind", ["RSA", "P-256", "P-384", "P-521", "Ed25519"])
def test_pem_and_thumbprints(signing_keys, kind):
    key = signing_keys[kind]
    other = old_jwk.JWK.from_json(key.export())
    assert key.thumbprint() == other.thumbprint()
    for private in (True, False):
        pem = key.export_to_pem(private_key=private)
        imported = old_jwk.JWK.from_pem(pem)
        assert imported.thumbprint() == key.thumbprint()
        theirs = other.export_to_pem(private_key=private, password=None)
        assert JWK.from_pem(theirs).thumbprint() == key.thumbprint()
