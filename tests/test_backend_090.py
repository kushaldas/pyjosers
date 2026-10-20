"""Regression and interoperability coverage for the jose-rs 0.9 integration."""
import json

import pytest
from cryptography.hazmat.primitives import hashes
from jwcrypto import jwk as other_jwk, jws as other_jws
from pyjosers import JWK, JWKSet, JWS, JWE, JWT
from pyjosers import jwt
from pyjosers.algorithms import CEK_BITS
from pyjosers.common import base64url_decode


@pytest.mark.parametrize("alg,bits", [("HS256", 256), ("HS384", 384), ("HS512", 512)])
def test_operation_aware_hmac_and_generation(alg, bits):
    key = JWK.generate(kty="oct", alg=alg)
    assert len(base64url_decode(key["k"])) * 8 == bits
    del key["alg"]
    old = other_jwk.JWK.from_json(key.export())
    ours = JWS(b"payload")
    ours.add_signature(key, protected={"alg": alg})
    theirs = other_jws.JWS()
    theirs.deserialize(ours.serialize(True), old)
    assert theirs.payload == b"payload"
    theirs = other_jws.JWS(b"payload")
    theirs.add_signature(old, protected={"alg": alg})
    JWS().deserialize(theirs.serialize(True), key)
    short = JWK.generate(kty="oct", size=192 if bits == 256 else bits - 128)
    with pytest.raises(ValueError):
        JWS(b"payload").add_signature(short, protected={"alg": alg})
    with pytest.raises(ValueError):
        JWS().deserialize(theirs.serialize(True), short)
    key["key_ops"] = ["verify"]
    with pytest.raises(ValueError):
        JWS(b"payload").add_signature(key, protected={"alg": alg})


@pytest.mark.parametrize("alg", ["Ed25519", "EdDSA"])
def test_explicit_ed25519_interop_and_pins(alg):
    key = JWK.generate(kty="OKP", crv="Ed25519", alg=alg)
    old = other_jwk.JWK.from_json(key.export())
    ours = JWS(b"payload")
    ours.add_signature(key, protected={"alg": alg})
    theirs = other_jws.JWS()
    theirs.deserialize(ours.serialize(True), old)
    theirs = other_jws.JWS(b"payload")
    theirs.add_signature(old, protected={"alg": alg})
    JWS().deserialize(theirs.serialize(True), key.public())
    parsed = JWS()
    parsed.allowed_algs = ["EdDSA" if alg == "Ed25519" else "Ed25519"]
    with pytest.raises(ValueError):
        parsed.deserialize(ours.serialize(True), key)
    if alg == "EdDSA":
        with pytest.raises(ValueError):
            JWS(b"payload").add_signature(key, protected={"alg": "Ed25519"})


@pytest.mark.parametrize("hashalg,hname", [(hashes.SHA256(), "sha-256"), (hashes.SHA384(), "sha-384"), (hashes.SHA512(), "sha-512")])
def test_thumbprint_hashes(signing_keys, hashalg, hname):
    for key in signing_keys.values():
        old = other_jwk.JWK.from_json(key.export())
        assert key.thumbprint(hashalg) == old.thumbprint(hashalg)
        assert key.thumbprint(hashalg.name) == old.thumbprint(hashalg)
        assert key.thumbprint_uri(hname) == old.thumbprint_uri(hname)
    assert key.thumbprint() == key.thumbprint(hashes.SHA256())
    assert key.thumbprint_uri() == key.thumbprint_uri("sha-256")
    with pytest.raises(ValueError):
        key.thumbprint(hashes.SHA1())


def test_exact_numeric_dates_and_trusted_clock():
    policy = jwt.Validation(leeway=0)
    raw = '{"exp":9007199254740993.123456789}'
    policy.validate_at(raw, {"alg": "HS256"}, "9007199254740993.123456788")
    with pytest.raises(ValueError):
        policy.validate_at(raw, {"alg": "HS256"}, "9007199254740993.123456789")
    for field in ("nbf", "iat"):
        raw = '{"' + field + '":10.000000001}'
        with pytest.raises(ValueError):
            policy.validate_at(raw, {"alg": "HS256"}, "10")
        policy.validate_at(raw, {"alg": "HS256"}, "10.000000001")
    for date in ("1.0000000001", "-0", "18446744073709551616", "null", "true", '"1"'):
        with pytest.raises(ValueError):
            policy.validate_at('{"exp":' + date + '}', {"alg": "HS256"}, 0)


def test_original_claims_json_survives_defaults_signing_and_validation():
    key = JWK.generate(kty="oct", alg="HS256")
    raw = '{"exp":9007199254740993.123456789,"iat":0.000000001}'
    obj = JWT(header={"alg": "HS256"}, claims=raw, default_claims={"sub": "alice"})
    assert "9007199254740993.123456789" in obj.claims
    obj.make_signed_token(key)
    parsed = JWT(jwt=obj.serialize(), key=key, validation=jwt.Validation())
    assert parsed.claims == obj.claims
    bad = JWS('{"exp":9007199254740993.1234567891}')
    bad.add_signature(key, protected={"alg": "HS256"})
    with pytest.raises(ValueError):
        parsed.deserialize(bad.serialize(True), key)
    with pytest.raises(AttributeError):
        _ = parsed.claims


def test_ambiguous_jwks_fail_and_clear_trusted_state():
    key = JWK.generate(kty="oct", alg="HS256", kid="shared")
    other = JWK.generate(kty="oct", alg="HS256", kid="shared")
    token = jwt.encode(key, {"sub": "alice"}, algorithm="HS256", headers={"kid": "shared"})
    for keys in ([key, other], [other, key]):
        keyset = JWKSet()
        for candidate in keys:
            keyset.add(candidate)
        parsed = JWT(jwt=token, key=key)
        with pytest.raises(ValueError):
            parsed.validate(keyset)
        with pytest.raises(AttributeError):
            _ = parsed.claims
    # Import preserves duplicate entries even when material is identical.
    duplicated = JWKSet.from_json(json.dumps({"keys": [key.export(as_dict=True)] * 2}))
    with pytest.raises(ValueError):
        jwt.decode(token, duplicated)


@pytest.mark.parametrize("enc", CEK_BITS)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17])
def test_plaintext_limits_and_failure_state(enc, length):
    key = JWK.generate(kty="oct", size=CEK_BITS[enc])
    obj = JWE(b"x" * length, protected={"alg": "dir", "enc": enc}, recipient=key)
    parsed = JWE()
    parsed.deserialize(obj.serialize(), key, max_plaintext=length)
    assert parsed.payload == b"x" * length
    if length:
        with pytest.raises(ValueError):
            parsed.decrypt(key, max_plaintext=length - 1)
        with pytest.raises(ValueError):
            _ = parsed.payload
    for invalid in (-1, True, 1.5, "1"):
        with pytest.raises(ValueError):
            parsed.decrypt(key, max_plaintext=invalid)
    key["key_ops"] = ["encrypt"]
    with pytest.raises(ValueError):
        parsed.decrypt(key, max_plaintext=length)


def test_nested_and_encrypted_jwt_limits():
    key = JWK.generate(kty="oct", alg="HS256")
    enc = JWK.generate(kty="oct", size=256)
    token = jwt.encode_nested(key, enc, {"sub": "alice"}, algorithm="HS256",
                              encryption_algorithm="dir", encryption="A256GCM")
    kwargs = dict(algorithms=["dir"], encryptions=["A256GCM"])
    assert jwt.decode_nested(token, key, enc, max_plaintext=1024, **kwargs)["sub"] == "alice"
    with pytest.raises(ValueError):
        jwt.decode_nested(token, key, enc, max_plaintext=1, **kwargs)
    obj = JWT(header={"alg": "dir", "enc": "A256GCM"}, claims={"sub": "alice"})
    obj.make_encrypted_token(enc)
    with pytest.raises(ValueError):
        JWT(jwt=obj.serialize(), key=enc, expected_type="JWE", max_plaintext=1)


def test_unsupported_rsa_exponent_is_not_silently_ignored():
    with pytest.raises(ValueError):
        JWK.generate(kty="RSA", public_exponent=3)


def test_jwe_ambiguous_kid_clears_plaintext():
    key = JWK.generate(kty="oct", size=256, kid="shared")
    other = JWK.generate(kty="oct", size=256, kid="shared")
    obj = JWE(b"payload", protected={"alg": "dir", "enc": "A256GCM", "kid": "shared"}, recipient=key)
    keyset = JWKSet()
    keyset.add(key)
    keyset.add(other)
    with pytest.raises(ValueError):
        obj.decrypt(keyset, max_plaintext=7)
    with pytest.raises(ValueError):
        _ = obj.payload


def test_mixed_jwks_import_stays_strict_and_atomic():
    key = JWK.generate(kty="oct", size=256)
    keyset = JWKSet()
    keyset.add(key)
    before = keyset.export()
    mixed = {"keys": [key.export(as_dict=True), {"kty": "future-type", "kid": "unknown"}]}
    with pytest.raises(ValueError):
        keyset.import_keyset(json.dumps(mixed))
    assert keyset.export() == before
