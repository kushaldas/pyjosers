"""Portable replicas of Inmor's signing and inline-JWKS validation contracts."""
import json
import time
import pytest
from pyjosers import jwk, jwt
from pyjosers.common import json_decode


def create_signed_jwt(claims, key, token_type=None):
    """Same call sequence as admin/common/signing.py, with only imports changed."""
    alg = key.get("alg") or "RS256"
    if alg in ("Ed25519", "Ed448"):
        alg = "EdDSA"
    header = {"alg": alg, "kid": key.get("kid") or key.thumbprint()}
    if token_type:
        header["typ"] = token_type
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def self_validate(token):
    """Same inline discovery/validation call sequence as admin/entities/lib.py."""
    payload = json.loads(token.token.objects.get("payload").decode("utf-8"))
    keyset = jwk.JWKSet()
    for key in payload["jwks"]["keys"]:
        keyset.add(jwk.JWK(**key))
    token.validate(keyset)
    return payload


@pytest.mark.parametrize("params,alg", [({"kty": "EC", "crv": "P-256"}, "ES256"),
                                       ({"kty": "OKP", "crv": "Ed25519"}, "Ed25519")])
def test_admin_workflow(params, alg):
    key = jwk.JWK.generate(**params, alg=alg)
    keyset = jwk.JWKSet()
    keyset.add(key)
    claims = {"iss": "https://entity.example", "sub": "https://entity.example", "iat": time.time(),
              "exp": time.time() + 3600, "jwks": keyset.export(private_keys=False, as_dict=True)}
    text = create_signed_jwt(claims, key, "entity-statement+jwt")
    parsed = jwt.JWT.from_jose_token(text)
    assert self_validate(parsed) == claims
    assert json_decode(parsed.claims) == claims
    assert json_decode(parsed.header)["typ"] == "entity-statement+jwt"
