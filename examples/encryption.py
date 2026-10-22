"""Run with: python examples/encryption.py. All keys/passwords are disposable."""
from pyjosers import JWK, JWE

# A single native encryption wraps one content key for two recipients.
keys = [JWK.generate(kty="oct", alg="A256KW", kid=name) for name in ("alice", "bob")]
message = JWE(b"invoice contents", protected={"alg": "A256KW", "enc": "A256GCM"},
              aad=b"invoice-42", flattened=False)
for key in keys:
    message.add_recipient(key)
wire = message.serialize()
received = JWE(algs=["A256KW", "A256GCM"])
received.deserialize(wire)
result = received.decrypt_authenticated(keys[1], expected_aad=b"invoice-42")
assert result.value == b"invoice contents"
assert result.protected["enc"] == "A256GCM"
assert result.unprotected == ({"kid": "bob"},)  # Routing metadata, not trusted claims.

# ECDH uses fresh ephemeral X25519 material for each encryption.
recipient = JWK.generate(kty="OKP", crv="X25519", alg="ECDH-ES", key_ops=["deriveKey"])
agreement = JWE(b"agreement", protected={"alg": "ECDH-ES", "enc": "A256GCM"},
                recipient=recipient.public())
received = JWE(algs=["ECDH-ES", "A256GCM"])
received.deserialize(agreement.serialize(compact=True), recipient)
assert received.payload == b"agreement"

# Choose a work factor and enforce a matching maximum on received passwords.
password = b"disposable example password"
password_message = JWE(b"password payload", recipient=password,
                       protected={"alg": "PBES2-HS256+A128KW", "enc": "A128GCM"},
                       pbes2_iterations=8192)
received = JWE(algs=["PBES2-HS256+A128KW", "A128GCM"], pbes2_max_iterations=8192)
received.deserialize(password_message.serialize(compact=True), password)
assert received.payload == b"password payload"
print("General JWE, AAD, X25519 and PBES2 verified")
