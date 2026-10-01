"""Bindings expose jose-rs 0.8 header policy without weakening its defaults."""
import pytest
from jwcrypto import jwk as other_jwk, jwe as other_jwe, jws as other_jws

from pyjosers import JWK, JWS, JWE, JWT, JoseError
from pyjosers import jwt, x509
from pyjosers.common import json_decode


@pytest.fixture
def signing_key():
    return JWK.generate(kty="oct", size=256, alg="HS256")


@pytest.fixture
def encryption_key():
    return JWK.generate(kty="oct", size=256, alg="dir")


REFERENCES = [
    {"jku": "https://example.invalid/jwks"},
    {"jwk": {"kty": "RSA", "n": "AQ", "e": "AQAB"}},
    {"x5u": "https://example.invalid/cert"},
    {"x5c": ["Y2VydGlmaWNhdGU="]},
]


@pytest.mark.parametrize("reference", REFERENCES)
@pytest.mark.parametrize("unprotected", [False, True])
def test_jws_key_references_require_opt_in(signing_key, reference, unprotected):
    protected = {"alg": "HS256", **({} if unprotected else reference)}
    header = reference if unprotected else None
    strict = JWS(b"payload")
    with pytest.raises(JoseError):
        strict.add_signature(signing_key, protected=protected, header=header)
    assert not strict.is_valid
    with pytest.raises(JoseError):
        _ = strict.payload
    assert "signature" not in strict.objects

    permitted = JWS(b"payload", allow_key_reference_headers=True)
    permitted.add_signature(signing_key, protected=protected, header=header)
    received = JWS.from_jose_token(permitted.serialize())
    received.verify(signing_key)
    assert received.payload == b"payload"
    assert all(received.jose_header[name] == value for name, value in reference.items())


@pytest.mark.parametrize("reference", REFERENCES)
def test_jwe_key_references_require_opt_in(encryption_key, reference):
    header = {"alg": "dir", "enc": "A256GCM", **reference}
    strict = JWE(b"payload", protected=header)
    with pytest.raises(JoseError):
        strict.add_recipient(encryption_key)
    with pytest.raises(JoseError):
        _ = strict.payload
    with pytest.raises(JoseError):
        strict.serialize()

    permitted = JWE(b"payload", protected=header, recipient=encryption_key,
                    allow_key_reference_headers=True)
    received = JWE()
    received.deserialize(permitted.serialize(True), encryption_key)
    assert received.payload == b"payload"
    assert received.jose_header == header


def test_certificate_bound_jwt_and_nested_jwt(signing_key, encryption_key):
    header = x509.bind_certificate({"alg": "HS256"}, b"binding bytes only")
    with pytest.raises(JoseError):
        jwt.encode(signing_key, {"sub": "alice"}, algorithm="HS256", headers=header)
    wire = jwt.encode(signing_key, {"sub": "alice"}, algorithm="HS256", headers=header,
                      allow_key_reference_headers=True)
    assert jwt.decode(wire, signing_key)["sub"] == "alice"
    x509.verify_certificate_binding(json_decode(JWT(jwt=wire, key=signing_key).header),
                                     b"binding bytes only")
    with pytest.raises(JoseError):
        jwt.encode_nested(signing_key, encryption_key, {"sub": "alice"}, algorithm="HS256",
                          encryption_algorithm="dir", encryption="A256GCM", headers=header)
    nested = jwt.encode_nested(signing_key, encryption_key, {"sub": "alice"}, algorithm="HS256",
                                encryption_algorithm="dir", encryption="A256GCM", headers=header,
                                allow_key_reference_headers=True)
    assert jwt.decode_nested(nested, signing_key, encryption_key, algorithms=["dir"],
                              encryptions=["A256GCM"])["sub"] == "alice"
    outer = JWE()
    outer.deserialize(nested, encryption_key)
    x509.verify_certificate_binding(jwt.decode_unverified(outer.payload.decode())[0],
                                     b"binding bytes only")


@pytest.mark.parametrize("encrypted", [False, True])
def test_jwt_object_propagates_opt_in(signing_key, encryption_key, encrypted):
    header = {"alg": "dir", "enc": "A256GCM"} if encrypted else {"alg": "HS256"}
    header.update(REFERENCES[0])
    key = encryption_key if encrypted else signing_key
    token = JWT(header=header, claims={"sub": "alice"})
    operation = token.make_encrypted_token if encrypted else token.make_signed_token
    with pytest.raises(JoseError):
        operation(key)
    assert token.token is None
    token.allow_key_reference_headers = True
    operation(key)
    received = JWT(jwt=token.serialize(), key=key, expected_type="JWE" if encrypted else "JWS")
    assert json_decode(received.claims)["sub"] == "alice"


JWE_MEMBERS = ["enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"]


@pytest.mark.parametrize("member", JWE_MEMBERS)
@pytest.mark.parametrize("unprotected", [False, True])
def test_jws_rejects_jwe_only_members(signing_key, member, unprotected):
    protected = {"alg": "HS256", **({} if unprotected else {member: "unused"})}
    obj = JWS(b"payload", allow_key_reference_headers=True)
    with pytest.raises(JoseError):
        obj.add_signature(signing_key, protected=protected,
                           header={member: "unused"} if unprotected else None)
    assert not obj.is_valid


@pytest.mark.parametrize("crit,extra", [(["kid"], {"kid": "one"}),
                                         (["custom", "custom"], {"custom": True})])
def test_jws_rejects_invalid_crit_even_if_understood(signing_key, crit, extra):
    obj = JWS(b"payload", understood_crit=crit)
    with pytest.raises(JoseError):
        obj.add_signature(signing_key, protected={"alg": "HS256", "crit": crit, **extra})
    assert not obj.is_valid


@pytest.mark.parametrize("member", ["zip", "b64", "epk", "apu", "apv", "p2s", "p2c", "iv", "tag", "crit"])
def test_jwe_rejects_unimplemented_members(encryption_key, member):
    obj = JWE(b"payload", protected={"alg": "dir", "enc": "A256GCM", member: True},
              allow_key_reference_headers=True)
    with pytest.raises(JoseError):
        obj.add_recipient(encryption_key)
    with pytest.raises(JoseError):
        _ = obj.payload


def test_key_reference_opt_in_interoperability(signing_key, encryption_key):
    # Verify both directions independently; verification needs no emit opt-in.
    header = {"alg": "HS256", **REFERENCES[0]}
    other_signing = other_jwk.JWK.from_json(signing_key.export())
    ours = JWS(b"payload", allow_key_reference_headers=True)
    ours.add_signature(signing_key, protected=header)
    theirs = other_jws.JWS()
    theirs.deserialize(ours.serialize(True), other_signing)
    assert theirs.payload == b"payload"
    theirs = other_jws.JWS(b"payload")
    theirs.add_signature(other_signing, protected=header)
    received = JWS.from_jose_token(theirs.serialize(True))
    received.verify(signing_key)
    assert received.payload == b"payload"

    header = {"alg": "dir", "enc": "A256GCM", **REFERENCES[0]}
    other_encryption = other_jwk.JWK.from_json(encryption_key.export())
    ours = JWE(b"payload", protected=header, recipient=encryption_key,
               allow_key_reference_headers=True)
    theirs = other_jwe.JWE()
    theirs.deserialize(ours.serialize(True), other_encryption)
    assert theirs.payload == b"payload"
    theirs = other_jwe.JWE(b"payload", protected=header, recipient=other_encryption)
    received = JWE()
    received.deserialize(theirs.serialize(True), encryption_key)
    assert received.payload == b"payload"
