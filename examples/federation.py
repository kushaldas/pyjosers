"""Run with: python examples/federation.py. Uses only newly generated keys."""
import time
from pyjosers import JWK, JWKSet, JWT, Validation
from pyjosers.common import json_decode

key = JWK.generate(kty="EC", crv="P-256", alg="ES256", kid="current")
keys = JWKSet()
keys.add(key)
claims = {
    "iss": "https://entity.example", "sub": "https://entity.example",
    "iat": time.time(), "exp": time.time() + 300,
    "jwks": keys.export(private_keys=False, as_dict=True),
}
token = JWT(header={"alg": "ES256", "kid": key.kid, "typ": "entity-statement+jwt"}, claims=claims)
token.make_signed_token(key)
# Trust is supplied separately here; publishing keys inside claims is not trust.
trusted = JWKSet.from_json(keys.export(private_keys=False))
verified = JWT(jwt=token.serialize(), key=trusted, algs=["ES256"],
               validation=Validation(issuer="https://entity.example", require_exp=True,
                                     required_typ="entity-statement+jwt"))
print(json_decode(verified.claims)["iss"])
