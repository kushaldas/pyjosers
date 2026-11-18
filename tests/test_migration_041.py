"""JWK assignment and exact JSON serialization through the public Python API."""
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext

import pytest

from pyjosers import JWK, JWKSet, SelectionPolicy, jwt


def test_assigned_kid_is_published_and_selects_the_signing_key():
    key = JWK.generate(kty="OKP", crv="Ed448")
    key.kid = key.thumbprint()
    assert key.kid == key["kid"] == key.key_id
    keys = JWKSet()
    keys.add(key)
    published = JWKSet.from_json(keys.export(private_keys=False))
    wire = jwt.encode(key, {"sub": "issuer"}, algorithm="Ed448", headers={"kid": key.kid})
    assert jwt.decode_authenticated(wire, published, selection_policy=SelectionPolicy.strict()).value["sub"] == "issuer"
    key["kid"] = "rotated"
    assert key.kid == "rotated"
    del key.kid
    assert "kid" not in key and not hasattr(key, "kid")


def test_attribute_writes_cannot_shadow_methods_or_create_typo_members():
    key = JWK.generate(kty="OKP", crv="Ed25519")
    key.alg = "Ed25519"
    assert key["alg"] == "Ed25519"
    for name in ("kdi", "export", "key_id"):
        with pytest.raises(AttributeError):
            setattr(key, name, "typo")
        assert name not in key
    key["tenant"] = "example"
    assert key["tenant"] == "example"


def test_exact_discovery_and_authenticated_json():
    key = JWK.generate(kty="OKP", crv="Ed448")
    claims = {"iat": Decimal("1700000000.123456789"),
              "nested": [{"score": Decimal("1.0000000000000000001"), "label": '"quoted"'}]}
    wire = jwt.encode(key, claims, algorithm="Ed448")
    inspected = jwt.UnverifiedJwt(wire)
    header, plain = jwt.decode_unverified(wire)
    assert header["alg"] == "Ed448"
    assert isinstance(plain["iat"], float)
    keys = JWKSet()
    keys.add(key.public())
    verified = inspected.verify_with(keys)
    for data in [inspected.claims, verified.value]:
        with localcontext() as context:
            context.prec = 3
            raw = jwt.dumps(data)
        assert json.loads(raw, parse_float=Decimal) == claims
        assert '"iat":1700000000.123456789' in raw


def test_aware_datetimes_as_exact_numeric_dates():
    stamp = datetime(2050, 1, 1, 1, 0, 0, 123456, tzinfo=timezone(timedelta(hours=1)))
    assert jwt.dumps({"iat": stamp}) == '{"iat":2524608000.123456}'
    before_epoch = datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
    assert json.loads(jwt.dumps(before_epoch), parse_float=Decimal) == Decimal("-0.000001")
    with pytest.raises(ValueError):
        jwt.dumps(stamp.replace(tzinfo=None))


@pytest.mark.parametrize("bad", [Decimal("sNaN"), Decimal("NaN"), Decimal("Infinity"),
                                 Decimal("-Infinity"), float("nan"), float("inf")])
def test_dumps_refuses_non_finite_values(bad):
    with pytest.raises(ValueError):
        jwt.dumps({"nested": [bad]})


def test_dumps_rejects_cycles_and_unsupported_values():
    shared = [Decimal("1E+400")]
    assert jwt.dumps([shared, shared]) == "[[1E+400],[1E+400]]"
    shared.append(shared)
    with pytest.raises(ValueError):
        jwt.dumps(shared)
    with pytest.raises(TypeError):
        jwt.dumps(object())
