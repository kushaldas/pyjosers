"""Bindings, serialization, metadata contracts, and failed-operation state."""
import json
import time
import pytest
from pyjosers import JWK, JWKSet, JWS, JWE, JWT, Validation, JoseError, POST_QUANTUM
from pyjosers import jwt, x509
from pyjosers.algorithms import JWS_ALGORITHMS
from pyjosers.common import base64url_encode, json_decode
from pyjosers.jws import InvalidJWSSignature, InvalidJWSObject
from pyjosers.jwe import InvalidJWEData
from pyjosers.jwt import JWTExpired, JWTMissingClaim


@pytest.fixture
def key():
    return JWK.generate(kty="EC", crv="P-256", kid="one")


def test_public_export_and_metadata(key):
    key["private_extension"] = "secret"
    key["key_ops"] = ["sign", "verify"]
    public = key.public()
    assert "d" not in public and "private_extension" not in public
    assert public["key_ops"] == ["verify"]
    assert public.kid == "one" and public.key_type == "EC"
    assert "secret" not in repr(key) and key["d"] not in repr(key)
    copy = key.export(as_dict=True)
    copy["key_ops"].clear()
    assert key["key_ops"] == ["sign", "verify"]
    with pytest.raises(JoseError):
        JWK.generate(kty="oct").public()


def test_keyset(key):
    keys = JWKSet()
    keys.add(key)
    keys.add(key)
    assert len(keys) == 1 and keys.get_key("one") is key
    clone = JWKSet.from_json(keys.export(private_keys=False))
    assert not clone.get_key("one").has_private
    token = jwt.encode(key, {"sub": "alice"}, algorithm="ES256", headers={"kid": "unknown"})
    with pytest.raises(InvalidJWSSignature):
        JWT(jwt=token, key=clone)
    token = jwt.encode(key, {"sub": "alice"}, algorithm="ES256")
    assert json_decode(JWT(jwt=token, key=clone).claims)["sub"] == "alice"
    with pytest.raises(JoseError):
        JWT(jwt=token, key=clone, validation=Validation(require_kid=True))


def test_signing_permissions(key):
    for metadata in ({"use": "enc"}, {"key_ops": ["verify"]}, {"alg": "ES384"}):
        changed = JWK.from_json(key.export())
        changed.update(metadata)
        with pytest.raises(JoseError):
            jwt.encode(changed, {}, algorithm="ES256")
    key["key_ops"] = ["sign"]
    token = jwt.encode(key, {}, algorithm="ES256")
    with pytest.raises(InvalidJWSSignature):
        JWT(jwt=token, key=key)


def test_parse_authenticate_and_failure_state(key):
    token = jwt.encode(key, {"sub": "alice"}, algorithm="ES256")
    parsed = JWT.from_jose_token(token)
    with pytest.raises(AttributeError):
        _ = parsed.claims
    assert json.loads(parsed.token.objects["payload"])["sub"] == "alice"
    parsed.validate(key)
    assert json.loads(parsed.claims)["sub"] == "alice"
    with pytest.raises(InvalidJWSSignature):
        parsed.validate(JWK.generate(kty="EC", crv="P-256"))
    with pytest.raises(AttributeError):
        _ = parsed.claims
    with pytest.raises(JoseError):
        parsed.deserialize("invalid")
    assert parsed.token is None


def test_jws_snapshot_and_failed_deserialize(key):
    obj = JWS(b"payload")
    obj.add_signature(key, protected={"alg": "ES256"})
    obj.objects["payload"] = b"changed"
    assert obj.payload == b"payload"
    with pytest.raises(JoseError):
        obj.deserialize("invalid")
    with pytest.raises(JoseError):
        _ = obj.payload


@pytest.mark.parametrize("b64", [True, False])
@pytest.mark.parametrize("compact", [True, False])
def test_detached_and_unencoded(key, b64, compact):
    payload = b"external.payload\x00\xff" if not b64 else b"external payload"
    header = {"alg": "ES256"}
    if not b64:
        header.update(b64=False, crit=["b64"])
    obj = JWS(payload)
    obj.detach_payload()
    obj.add_signature(key, protected=header)
    text = obj.serialize(compact)
    parsed = JWS.from_jose_token(text)
    parsed.verify(key, detached_payload=payload)
    assert parsed.payload == payload
    with pytest.raises(InvalidJWSSignature):
        parsed.verify(key, detached_payload=b"wrong")


def test_attached_unencoded(key):
    obj = JWS("héllo")
    obj.add_signature(key, protected={"alg": "ES256", "b64": False, "crit": ["b64"]})
    parsed = JWS.from_jose_token(obj.serialize(True))
    parsed.verify(key)
    assert parsed.payload == "héllo".encode()
    with pytest.raises(InvalidJWSSignature):
        parsed.verify(key, detached_payload=b"different")


def test_general_signatures(key):
    other = JWK.generate(kty="EC", crv="P-256", kid="two")
    obj = JWS(b"payload")
    for k in (key, other):
        obj.add_signature(k, protected={"alg": "ES256", "kid": k.kid})
    parsed = JWS.from_jose_token(obj.serialize())
    parsed.verify(key)
    results = parsed.verify_all(key)
    assert [r.verified for r in results] == [True, False]
    assert not parsed.is_valid
    keys = JWKSet()
    keys.add(key)
    keys.add(other)
    assert all(r.verified for r in parsed.verify_all(keys))
    assert parsed.payload == b"payload"
    with pytest.raises(InvalidJWSObject):
        parsed.serialize(True)


def test_critical_headers(key):
    obj = JWS(b"payload")
    with pytest.raises(JoseError):
        obj.add_signature(key, protected={"alg": "ES256", "crit": ["custom"], "custom": True})
    obj = JWS(b"payload", understood_crit=["custom"])
    obj.add_signature(key, protected={"alg": "ES256", "crit": ["custom"], "custom": True})
    parsed = JWS.from_jose_token(obj.serialize())
    with pytest.raises(InvalidJWSSignature):
        parsed.verify(key)
    parsed.understood_crit = ["custom"]
    parsed.verify(key)
    with pytest.raises(InvalidJWSObject):
        obj.add_signature(key, protected={"alg": "ES256"}, header={"alg": "ES256"})


def test_tampered_payload_and_algorithm(key):
    obj = JWS(b"original")
    obj.add_signature(key, protected={"alg": "ES256"})
    data = json.loads(obj.serialize())
    data["payload"] = base64url_encode(b"changed")
    with pytest.raises(InvalidJWSSignature):
        JWS.from_jose_token(json.dumps(data)).verify(key)
    obj.allowed_algs = ["RS256"]
    with pytest.raises(InvalidJWSSignature):
        obj.verify(key)


def test_jwe_policy_and_failed_authentication():
    key = JWK.generate(kty="oct", size=256, alg="dir")
    token = JWE(b"message", protected={"alg": "dir", "enc": "A256GCM"}, recipient=key)
    parsed = JWE()
    parsed.deserialize(token.serialize(), key)
    assert parsed.payload == b"message"
    with pytest.raises(InvalidJWEData):
        parsed.decrypt(JWK.generate(kty="oct", size=256))
    with pytest.raises(InvalidJWEData):
        _ = parsed.payload
    restricted = JWE(algs=["A128KW", "A256GCM"])
    with pytest.raises(InvalidJWEData):
        restricted.deserialize(token.serialize())
    wrong_pin = JWK.from_json(key.export())
    wrong_pin["alg"] = "A256KW"
    with pytest.raises(InvalidJWEData):
        parsed.decrypt(wrong_pin)
    key["key_ops"] = ["encrypt"]
    with pytest.raises(InvalidJWEData):
        parsed.decrypt(key)


def test_jwt_type_separation():
    key = JWK.generate(kty="oct", size=256)
    token = JWT(header={"alg": "dir", "enc": "A256GCM"}, claims={"sub": "alice"})
    token.make_encrypted_token(key)
    with pytest.raises(ValueError, match="expected JWS"):
        JWT(jwt=token.serialize(), key=key)
    assert json_decode(JWT(jwt=token.serialize(), key=key, expected_type="JWE").claims)["sub"] == "alice"


def test_validation(key):
    now = int(time.time())
    claims = {"iss": "issuer", "sub": "alice", "aud": ["api"], "exp": now + 60, "iat": now - 1, "nbf": now - 1}
    policy = Validation(issuer="issuer", audience="api", subject="alice", required_typ="entity-statement+jwt",
                        max_age=30, allowed_algorithms=["ES256"], leeway=0, require_exp=True, require_nbf=True,
                        require_iat=True, require_kid=True)
    token = jwt.encode(key, claims, algorithm="ES256", headers={"kid": "one", "typ": "entity-statement+jwt"})
    assert jwt.decode(token, key, validation=policy) == claims
    for field, value in [("issuer", "other"), ("audience", "other"), ("subject", "other"), ("required_typ", "JWT"), ("max_age", 0)]:
        opts = dict(policy.__dict__)
        opts[field] = value
        with pytest.raises(JoseError):
            jwt.decode(token, key, validation=Validation(**opts))
    expired = jwt.encode(key, {"exp": now - 1000}, algorithm="ES256")
    with pytest.raises(JWTExpired):
        JWT(jwt=expired, key=key)
    assert json_decode(JWT(jwt=expired, key=key, check_claims={}).claims)["exp"] == now - 1000
    with pytest.raises(JWTMissingClaim):
        JWT(jwt=token, key=key, check_claims={"missing": None})


def test_nested(key):
    encryption_key = JWK.generate(kty="oct", size=256)
    token = jwt.encode_nested(key, encryption_key, {"sub": "alice"}, algorithm="ES256",
                              encryption_algorithm="dir", encryption="A256GCM")
    assert jwt.decode_nested(token, key.public(), encryption_key, algorithms=["dir"], encryptions=["A256GCM"])["sub"] == "alice"


def test_certificate_helpers():
    der = b"certificate bytes for binding only"
    header = x509.bind_certificate({"alg": "RS256"}, der)
    assert x509.leaf_certificate(header) == der
    assert header["x5t#S256"] == x509.thumbprint_sha256(der)
    x509.verify_certificate_binding(header, der)
    with pytest.raises(JoseError):
        x509.verify_certificate_binding(header, b"different")


@pytest.mark.skipif(not POST_QUANTUM, reason="post-quantum feature disabled")
@pytest.mark.parametrize("alg", [a for a in JWS_ALGORITHMS if a.startswith("ML-")])
def test_post_quantum(alg):
    key = JWK.generate(kty="AKP", alg=alg)
    token = jwt.encode(key, {"sub": "alice"}, algorithm=alg)
    assert jwt.decode(token, key.public())["sub"] == "alice"


def test_malformed_input_limits(key):
    with pytest.raises(JoseError):
        JWK.generate(kty="RSA", size=1024)
    with pytest.raises(JoseError):
        JWS.from_jose_token("x" * (1024 * 1024 + 1))
    with pytest.raises(ValueError):
        JWK.from_json('{"kty":"EC","kty":"RSA"}')
    with pytest.raises(JoseError):
        JWK.generate(kty="OKP", crv="Ed448")
    with pytest.raises(JoseError):
        jwt.encode(key, {}, algorithm="none")


@pytest.mark.parametrize("claim,value", [("exp", True), ("iat", "123"), ("nbf", -1), ("sub", None), ("aud", [42])])
def test_claim_type_checks(key, claim, value):
    token = jwt.encode(key, {claim: value}, algorithm="ES256")
    with pytest.raises(JoseError):
        JWT(jwt=token, key=key)


def test_compatibility_claim_options(key):
    token = jwt.encode(key, {"exp": 1000, "scope": "read write", "typ": "JWT"}, algorithm="ES256")
    assert JWT(jwt=token, key=key, check_claims={"exp": 999, "scope": "read", "typ": "application/jwt"}).claims
    with pytest.raises(JWTExpired):
        JWT(jwt=token, key=key, check_claims={"exp": 1001})
    with pytest.raises(JoseError):
        JWT(jwt=token, key=key, check_claims={"scope": "admin"})
    created = JWT(header={"alg": "ES256"}, claims={"sub": "alice"},
                  default_claims={"exp": None, "iat": None, "jti": None})
    created.make_signed_token(key)
    data = json_decode(JWT(jwt=created.serialize(), key=key).claims)
    assert data["exp"] - data["iat"] == 600 and isinstance(data["jti"], str)


def test_claim_failure_clears_previous_claims(key):
    token = jwt.encode(key, {"sub": "alice"}, algorithm="ES256")
    parsed = JWT(jwt=token, key=key)
    parsed.check_claims = {"sub": "other"}
    with pytest.raises(JoseError):
        parsed.validate(key)
    with pytest.raises(AttributeError):
        _ = parsed.claims


@pytest.mark.parametrize("value", ['{"x":NaN}', '{"x":Infinity}', '{"x":1e400}', '{"x":1,"x":2}'])
def test_strict_json(value):
    with pytest.raises(ValueError):
        json_decode(value)


def test_exception_roundtrip():
    import pickle
    error = JWTExpired("expired")
    assert isinstance(pickle.loads(pickle.dumps(error)), JWTExpired)
