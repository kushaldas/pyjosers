"""Run with: python examples/verification.py."""
from pyjosers import JWK, JWKSet, JWS, SelectionPolicy, capabilities

assert capabilities.find("jws", "ES256").available
keys = [JWK.generate(kty="EC", crv="P-256", alg="ES256", kid=name)
        for name in ("current", "next")]
trusted = JWKSet(selection_policy=SelectionPolicy.strict())
message = JWS(b"rotation")
for key in keys:
    trusted.add(key.public())
    message.add_signature(key, protected={"alg": "ES256", "kid": key.kid})
received = JWS.from_jose_token(message.serialize())
received.allowed_algs = ["ES256"]
report = received.verify_report(trusted, policy="all")
assert report.satisfied and report.payload == b"rotation"
assert all(entry.verified for entry in report.results)
result = received.verify_authenticated(trusted)
assert result.value == b"rotation"
assert result.protected["kid"] == "current"
print("Bounded rotation, all-signature report and authenticated context verified")
