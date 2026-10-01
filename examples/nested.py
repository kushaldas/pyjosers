"""Run with: python examples/nested.py."""
from pyjosers import JWK
from pyjosers.jwt import encode_nested, decode_nested, Validation

signer = JWK.generate(kty="OKP", crv="Ed25519")
recipient = JWK.generate(kty="oct", size=256, alg="dir")
wire = encode_nested(signer, recipient, {"sub": "alice"}, algorithm="EdDSA",
                     encryption_algorithm="dir", encryption="A256GCM")
print(decode_nested(wire, signer.public(), recipient, algorithms=["dir"],
                    encryptions=["A256GCM"], validation=Validation(allowed_algorithms=["EdDSA"])))
