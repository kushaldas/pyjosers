"""Python migration contracts with the published jose-rs 0.12 backend."""
from decimal import Decimal

import pytest
from jwcrypto import jwk as peer_jwk, jws as peer_jws
from pyjosers import JWK, JWKSet, JWS, JoseError, SelectionPolicy, jwt
from pyjosers.common import base64url_decode


@pytest.mark.parametrize("curve", ["Ed25519", "Ed448"])
@pytest.mark.parametrize("legacy_header", [False, True])
def test_edwards_pins_across_libraries(curve, legacy_header):
    alg, pin = ("EdDSA", curve) if legacy_header else (curve, "EdDSA")
    key = JWK.generate(kty="OKP", crv=curve, alg=pin, kid="second")
    other_curve = "Ed25519" if curve == "Ed448" else "Ed448"
    other = JWK.generate(kty="OKP", crv=other_curve)
    keys = JWKSet()
    keys.add(other.public())
    keys.add(key.public())
    peer = peer_jwk.JWK.from_json(key.export())
    token = jwt.encode(key, {"sub": "alice"}, algorithm=alg, headers={"kid": "second"})
    read = peer_jws.JWS()
    read.deserialize(token, peer)
    assert read.payload == b'{"sub":"alice"}'
    signed = peer_jws.JWS(b'{"sub":"alice"}')
    signed.add_signature(peer, protected={"alg": alg, "kid": "second"})
    result = jwt.decode_authenticated(signed.serialize(compact=True), keys)
    assert result.value == {"sub": "alice"}
    assert result.protected == {"alg": alg, "kid": "second"}
    assert result.verified_key_index == 1
    assert jwt.decode_authenticated(token, key.public()).verified_key_index is None
    with pytest.raises(JoseError):
        jwt.decode(token, keys, validation=jwt.Validation(allowed_algorithms=[pin]))
    with pytest.raises(JoseError):
        jwt.decode(token, other)
    with pytest.raises(JoseError):
        jwt.encode(key, {}, algorithm=other_curve)


def test_ed448_key_formats():
    key = JWK.generate(kty="OKP", crv="Ed448")
    assert len(base64url_decode(key["d"])) == len(base64url_decode(key["x"])) == 57
    peer = peer_jwk.JWK.from_json(key.export())
    assert key.thumbprint() == peer.thumbprint()
    for private in [True, False]:
        pem = key.export_to_pem(private_key=private, password=None)
        assert peer_jwk.JWK.from_pem(pem).thumbprint() == key.thumbprint()
        assert JWK.from_pem(peer.export_to_pem(private_key=private, password=None)).thumbprint() == key.thumbprint()


def test_discovery_verifies_original_and_applies_policy():
    key = JWK.generate(kty="OKP", crv="Ed448", kid="fed")
    keys = JWKSet()
    keys.add(key.public())
    raw = '{"sub":"original","custom":1.00000000000000001,"exp":1}'
    token = jwt.encode(key, raw, algorithm="EdDSA", headers={"kid": "fed"})
    seen = []

    def select(claims):
        seen.append(claims["custom"])
        claims["sub"] = "mutated"
        return keys

    with pytest.raises(jwt.JWTExpired):
        jwt.decode_self_signed(token, select)
    policy = jwt.Validation.signature_only()
    result = jwt.decode_self_signed(token, select, validation=policy, selection_policy=SelectionPolicy.strict())
    assert seen == [Decimal("1.00000000000000001")] * 2
    assert result.value["sub"] == "original"
    assert result.verified_key_index == 0
    inspected = jwt.UnverifiedJwt(token)
    inspected.header.clear()
    assert inspected.header["kid"] == "fed"
    with pytest.raises(JoseError):
        inspected.verify_with(JWKSet(), validation=policy)
    wrong_keys = JWKSet()
    wrong_keys.add(JWK.generate(kty="OKP", crv="Ed448", kid="fed").public())
    with pytest.raises(JoseError):
        jwt.decode_self_signed(token, lambda _: wrong_keys, validation=policy)
    assert inspected.verify_with(keys, validation=policy).value == result.value
    with pytest.raises(JoseError):
        jwt.decode_self_signed(token, lambda _: keys, validation=policy, selection_policy=SelectionPolicy(max_candidates=0))


def test_discovery_refuses_duplicate_before_selector():
    key = JWK.generate(kty="OKP", crv="Ed448")
    signed = JWS(br'{"jwks":{"keys":[{"alg":"EdDSA","\u0061lg":"Ed448"}]}}')
    signed.add_signature(key, protected={"alg": "Ed448"})
    with pytest.raises(jwt.JWTInvalidClaimValue):
        jwt.decode_self_signed(signed.serialize(compact=True), lambda _: pytest.fail("selector called"))


def test_validation_builders_keep_other_policy_and_defaults():
    original = jwt.Validation(issuer="entity", require_exp=True, allowed_algorithms=["Ed448"], leeway=0)
    relaxed = original.without_exp().without_nbf().without_iat_future_check()
    claims = {"exp": 1, "nbf": 99, "iat": 99, "iss": "entity"}
    header = {"alg": "Ed448"}
    relaxed.validate_at(claims, header, 5)
    with pytest.raises(JoseError):
        original.validate_at(claims, header, 5)
    with pytest.raises(JoseError):
        relaxed.validate_at({"iss": "entity"}, header, 5)
    with pytest.raises(JoseError):
        relaxed.validate_at(claims, {"alg": "EdDSA"}, 5)


def test_deterministic_ed448_signing_with_rfc8032_key():
    # RFC 8032 section 7.4, "Blank". JWS always signs a nonempty protected
    # input; compare that signature with an independent pure Ed448 signer.
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
    from pyjosers.common import base64url_encode

    seed = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348"
                         "a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")
    public = bytes.fromhex("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e967"
                           "78edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180")
    key = JWK(kty="OKP", crv="Ed448", x=base64url_encode(public), d=base64url_encode(seed))
    assert key.thumbprint() == "zQstisLFDWZb-FiVsZl6490ATVgxw_63L-xYldKyuUY"
    token = jwt.encode(key, {"z": 1, "a": 2}, algorithm="Ed448", headers={"y": 3, "b": 4})
    assert token == jwt.encode(key, {"a": 2, "z": 1}, algorithm="Ed448", headers={"b": 4, "y": 3})
    signed, signature = token.rsplit(".", 1)
    assert base64url_decode(signature) == Ed448PrivateKey.from_private_bytes(seed).sign(signed.encode("ascii"))


def test_discovery_requires_a_kid_for_named_sets_by_default():
    key = JWK.generate(kty="OKP", crv="Ed448", kid="named")
    keys = JWKSet()
    keys.add(key.public())
    token = jwt.encode(key, {}, algorithm="Ed448")
    with pytest.raises(JoseError):
        jwt.decode_self_signed(token, lambda _: keys)
    result = jwt.decode_self_signed(token, lambda _: keys, selection_policy=SelectionPolicy(fallback="all"))
    assert result.verified_key_index == 0
