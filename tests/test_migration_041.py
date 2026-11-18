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


def test_unknown_public_attribute_on_plain_jwk_is_rejected():
    key = JWK.generate(kty="OKP", crv="Ed25519", kid="original")
    with pytest.raises(AttributeError, match="kdi"):
        key.kdi = "rotated"

    assert not hasattr(key, "kdi")
    assert key.export_public(as_dict=True)["kid"] == "original"
    key["tenant"] = "example"
    assert key.export(as_dict=True)["tenant"] == "example"


def test_subclass_attributes_stay_local_and_extensions_are_exported():
    class LabeledKey(JWK):
        def __init__(self, **kwargs):
            self.label = "local"
            super().__init__(**kwargs)

    key = LabeledKey.generate(kty="OKP", crv="Ed25519")
    assert key.label == "local"
    key["tenant"] = "example"
    exported = key.export(as_dict=True)
    assert exported["tenant"] == "example"
    assert "label" not in exported
    del key.label
    assert not hasattr(key, "label")


def test_key_material_attribute_edits_preserve_signing_key():
    key = JWK.generate(kty="OKP", crv="Ed25519")
    other = JWK.generate(kty="OKP", crv="Ed25519")
    original = key.thumbprint()
    with pytest.raises(AttributeError):
        key.x = other.x
    with pytest.raises(AttributeError):
        del key.d
    assert key.thumbprint() == key.public().thumbprint() == original
    wire = jwt.encode(key, {"sub": "issuer"}, algorithm="Ed25519")
    assert jwt.decode(wire, key.public())["sub"] == "issuer"


@pytest.mark.parametrize(("name", "valid", "invalid"), [
    ("kid", "first", 123), ("alg", "Ed25519", False), ("use", "sig", None),
    ("key_ops", ["sign", "verify"], "sign"), ("x5c", ["YQ=="], [1]),
    ("x5u", "https://example.org/cert", []), ("x5t", "abc", 5),
    ("x5t#S256", "abc", {}),
])
def test_bad_metadata_attribute_preserves_exportable_key_set(name, valid, invalid):
    key = JWK.generate(kty="OKP", crv="Ed25519")
    setattr(key, name, valid)
    keys = JWKSet()
    keys.add(key)
    before = keys.export(private_keys=False)
    with pytest.raises(TypeError):
        setattr(key, name, invalid)
    assert key[name] == valid
    assert keys.export(private_keys=False) == before


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


@pytest.mark.parametrize("seconds", [-1, 0, 1795003534])
def test_whole_second_datetime_is_a_json_integer(seconds):
    stamp = datetime.fromtimestamp(seconds, timezone.utc)
    assert jwt.dumps(stamp) == str(seconds)
    key = JWK.generate(kty="oct", alg="HS256")
    wire = jwt.encode(key, {"issued": stamp}, algorithm="HS256")
    value = jwt.decode(wire, key)["issued"]
    assert type(value) is int and value == seconds


@pytest.mark.parametrize("value", ["a", datetime(2026, 1, 1, tzinfo=timezone.utc)])
@pytest.mark.parametrize("nested", [False, True])
def test_non_string_claim_names_are_rejected_consistently(value, nested):
    obj = {1: value}
    claims = {"items": [obj]} if nested else obj
    key = JWK.generate(kty="oct", alg="HS256")
    with pytest.raises(TypeError, match="keys must be strings"):
        jwt.encode(key, claims, algorithm="HS256")
