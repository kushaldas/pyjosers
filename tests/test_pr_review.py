"""Regression coverage for error categories and exact JSON compatibility checks."""
from decimal import Decimal

import pytest

from pyjosers import JWK, JWKSet, JWS, JWT, SelectionPolicy, is_authentication_failure
from pyjosers import _native
from pyjosers.common import base64url_encode, json_decode, json_encode
from pyjosers.jws import InvalidJWSSignature
from pyjosers.jwt import JWTExpired, JWTInvalidClaimValue, JWTNotYetValid


class ProtocolVerifier:
    """Exercise the PKCS#11 verifier protocol with disposable software material."""
    def __init__(self, key):
        self.key = key
        self.calls = 0

    def _verify(self, token, detached, understood):
        self.calls += 1
        return _native.verify(self.key.export(), token, detached, understood)


def wrap_key(key, mode):
    if mode == "single":
        return key
    if mode == "set":
        keys = JWKSet()
        keys.add(key)
        return keys
    return ProtocolVerifier(key)


def signed(key, **header):
    obj = JWS(b"payload", understood_crit=["custom"])
    obj.add_signature(key, protected={"alg": "HS256", **header})
    return JWS.from_jose_token(obj.serialize(True))


@pytest.mark.parametrize("mode", ["single", "set", "protocol"])
@pytest.mark.parametrize("case", ["allowlist", "algorithm", "critical", "key_ops", "unsupported", "wrong_key"])
def test_signature_failure_categories_match_single_key(mode, case):
    key = JWK.generate(kty="oct", alg="HS256")
    obj = signed(key, **({"custom": True, "crit": ["custom"]} if case == "critical" else {}))
    obj.understood_crit = ["custom"]
    obj.verify(key)
    assert obj.payload == b"payload"
    options = {}
    if case == "allowlist":
        obj.allowed_algs = []
    elif case == "algorithm":
        options["alg"] = "HS512"
    elif case == "critical":
        obj.understood_crit = []
    elif case == "key_ops":
        key["key_ops"] = ["sign"]
    elif case == "unsupported":
        data = json_decode(obj.serialize())
        data["protected"] = base64url_encode(json_encode({"alg": "ES256K"}).encode())
        obj.deserialize(json_encode(data))
        obj.allowed_algs = ["ES256K"]
    else:
        key = JWK.generate(kty="oct", alg="HS256")
    candidate = wrap_key(key, mode)
    with pytest.raises(InvalidJWSSignature) as single:
        obj.verify(key, **options)
    with pytest.raises(InvalidJWSSignature) as failure:
        obj.verify(candidate, **options)
    assert failure.value.category == single.value.category
    if case == "unsupported":
        assert failure.value.category == "unsupported_capability"
    assert is_authentication_failure(failure.value) == (case == "wrong_key")
    assert obj._authenticated is None
    with pytest.raises(ValueError):
        _ = obj.payload
    report = obj.verify_report(candidate, **options)
    entry = report.results[0]
    assert not report.satisfied
    assert entry.category == single.value.category
    assert entry.authentication_failure == is_authentication_failure(single.value)
    assert entry.error
    if case in ("allowlist", "algorithm", "key_ops") and mode != "protocol":
        assert not entry.attempted
    if mode == "protocol" and case in ("allowlist", "algorithm"):
        assert candidate.calls == 0
        assert not entry.attempted


@pytest.mark.parametrize("case", ["missing", "unknown", "ambiguous", "budget"])
def test_selection_errors_never_become_authentication_failures(case):
    key = JWK.generate(kty="oct", alg="HS256", kid="trusted")
    obj = signed(key, **({"kid": "unknown"} if case == "unknown" else
                         {"kid": "trusted"} if case == "ambiguous" else {}))
    keys = JWKSet()
    keys.add(key)
    if case == "missing":
        keys.selection_policy = SelectionPolicy.strict()
    elif case == "ambiguous":
        keys.add(JWK.generate(kty="oct", alg="HS256", kid="trusted"))
    elif case == "budget":
        keys.selection_policy = SelectionPolicy(max_candidates=0)
    report = obj.verify_report(keys)
    entry = report.results[0]
    assert not entry.attempted
    assert entry.category == "invalid_structure"
    assert not entry.authentication_failure
    with pytest.raises(InvalidJWSSignature) as failure:
        obj.verify(keys)
    assert failure.value.category == entry.category
    assert not is_authentication_failure(failure.value)


@pytest.mark.parametrize("reverse", [False, True])
def test_mixed_candidate_errors_keep_the_observed_mismatch(reverse):
    signer = JWK.generate(kty="oct", alg="HS256")
    obj = signed(signer)
    wrong = JWK.generate(kty="oct", alg="HS256")
    refused = JWK.generate(kty="oct", alg="HS512")
    keys = JWKSet()
    for key in ([refused, wrong] if reverse else [wrong, refused]):
        keys.add(key)
    entry = obj.verify_report(keys).results[0]
    assert entry.attempted and entry.authentication_failure
    with pytest.raises(InvalidJWSSignature) as failure:
        obj.verify(keys)
    assert is_authentication_failure(failure.value)
    assert failure.value.category == entry.category
    keys.add(signer)
    report = obj.verify_report(keys)
    assert report.satisfied
    assert report.results[0].category is None
    assert not report.results[0].authentication_failure


def test_mixed_signature_errors_preserve_causes_and_skipped_entries():
    key = JWK.generate(kty="oct", size=512)
    obj = JWS(b"payload")
    obj.add_signature(key, protected={"alg": "HS256"})
    obj.add_signature(key, protected={"alg": "HS512"})
    obj.allowed_algs = ["HS256"]
    wrong = JWK.generate(kty="oct", size=512)
    report = obj.verify_report(wrong, policy="all")
    assert report.results[0].authentication_failure
    assert not report.results[1].authentication_failure
    assert not report.results[1].attempted
    with pytest.raises(InvalidJWSSignature) as failure:
        obj.verify(wrong)
    assert is_authentication_failure(failure.value)
    obj.allowed_algs = ["HS256", "HS512"]
    report = obj.verify_report(key)
    assert report.satisfied and report.results[0].verified
    assert not report.results[1].attempted
    assert report.results[1].category is None
    assert not report.results[1].authentication_failure


@pytest.mark.parametrize("claims", [
    {"score": 0.1},
    {"iat": 1700000000.1},
    {"nested": {"scores": [0.1, {"weight": 0.3}]}},
    {"values": [0.1, 0.2, 0.3]},
])
def test_fractional_claim_expectations_match_exact_json(claims):
    key = JWK.generate(kty="oct", alg="HS256")
    obj = JWT(header={"alg": "HS256"}, claims=claims)
    obj.make_signed_token(key)
    received = JWT(jwt=obj.serialize(), key=key, check_claims=claims)
    assert received.claims == obj.claims
    # Also cover callers replacing check_claims after construction.
    received.check_claims = dict(claims)
    assert received.validate_authenticated(key).value
    name = next(iter(claims))
    received.check_claims = {name: "different"}
    with pytest.raises(JWTInvalidClaimValue):
        received.validate(key)
    with pytest.raises(AttributeError):
        _ = received.claims
    assert received._authenticated is None


def test_claim_equality_does_not_round_authenticated_numbers():
    key = JWK.generate(kty="oct", alg="HS256")
    obj = JWT(header={"alg": "HS256"}, claims='{"score":0.100000000000000000001}')
    obj.make_signed_token(key)
    received = JWT(jwt=obj.serialize(), key=key, check_claims={"score": None})
    assert received.validate_authenticated(key).value["score"] == Decimal("0.100000000000000000001")
    received.check_claims = {"score": 0.1}
    with pytest.raises(JWTInvalidClaimValue):
        received.validate(key)


@pytest.mark.parametrize("name,expected,error", [
    ("exp", 1000.299, None),
    ("exp", 1000.3, JWTExpired),
    ("nbf", 1000.299, JWTNotYetValid),
    ("nbf", 1000.3, None),
])
def test_fractional_date_comparisons_keep_their_boundaries(name, expected, error):
    key = JWK.generate(kty="oct", alg="HS256")
    obj = JWT(header={"alg": "HS256"}, claims={name: 1000.3})
    obj.make_signed_token(key)
    received = JWT(jwt=obj.serialize(), check_claims={name: expected})
    if error is None:
        received.validate(key)
    else:
        with pytest.raises(error):
            received.validate(key)
