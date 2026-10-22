"""Published jose-rs 0.10 features and binding-specific compatibility contracts."""
import datetime
import json
from decimal import Decimal

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from jwcrypto import jwk as peer_jwk, jwe as peer_jwe

from pyjosers import (JWK, JWKSet, JWE, JWS, JWT, SetLimits, SelectionPolicy,
                      JWKThumbprintURI, Authenticated, capabilities, jwt,
                      is_authentication_failure)
from pyjosers.common import base64url_encode, base64url_decode, json_encode
from pyjosers.algorithms import JWE_ALGORITHMS, JWE_ENCRYPTIONS, JWS_ALGORITHMS


def test_capability_tables_match_build():
    assert tuple(r.identifier for r in capabilities.available("jwe")) == JWE_ALGORITHMS
    assert tuple(r.identifier for r in capabilities.available("jws")) == JWS_ALGORITHMS
    assert tuple(r.identifier for r in capabilities.available("encryption")) == JWE_ENCRYPTIONS
    assert capabilities.find("jwe", "RSA1_5").status == "refused"
    assert capabilities.find("jws", "ES256K").status == "unsupported"
    assert capabilities.find("jws", "none").available is False
    assert capabilities.find("jws", "ML-DSA-65").available == capabilities.features()["post-quantum"]
    assert capabilities.find("jwe", "unknown") is None


@pytest.mark.parametrize("curve", ["P-256", "P-384", "P-521", "X25519"])
@pytest.mark.parametrize("alg", ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"])
def test_agreement_json_and_compact(curve, alg):
    key = JWK.generate(kty="OKP" if curve == "X25519" else "EC", crv=curve,
                       alg=alg, key_ops=["deriveKey"])
    public = key.public()
    assert public["key_ops"] == ["deriveKey"]
    protected = {"alg": alg, "enc": "A256GCM", "apu": base64url_encode(b"sender"),
                 "apv": base64url_encode(b"receiver")}
    message = JWE(b"agreement", protected=protected, recipient=public)
    for compact in (False, True):
        wire = message.serialize(compact)
        received = JWE.from_jose_token(wire)
        assert received.decrypt_authenticated(key).value == b"agreement"
        peer = peer_jwe.JWE()
        # JWCrypto requests unwrapKey for ECDH; jose-rs requires deriveKey.
        peer_material = key.export(as_dict=True)
        peer_material.pop("key_ops")
        peer.deserialize(wire, peer_jwk.JWK(**peer_material))
        peer_out = peer_jwe.JWE(b"peer agreement", protected=protected,
                                recipient=peer_jwk.JWK(**peer_material))
        peer_wire = peer_out.serialize(compact=compact)
        if compact:
            ours = JWE.from_jose_token(peer_wire)
            ours.decrypt(key)
            assert ours.payload == b"peer agreement"
        else:
            # jose-rs intentionally requires epk in the protected header.
            with pytest.raises(ValueError, match="epk must be integrity protected"):
                JWE.from_jose_token(peer_wire)
        assert peer.payload == b"agreement"
    wrong = JWK.generate(kty="EC", crv="P-256")
    with pytest.raises(ValueError):
        received.decrypt(wrong)
    with pytest.raises(ValueError):
        _ = received.payload


def test_x25519_import_export_and_derived_keys():
    a = JWK.generate(kty="OKP", crv="X25519", key_ops=["deriveKey"])
    b = JWK.generate(kty="OKP", crv="X25519", key_ops=["deriveKey"])
    assert a.derive_key(b.public(), algorithm_id="A256GCM", length=32) == b.derive_key(a.public(), algorithm_id="A256GCM", length=32)
    assert JWK.from_json(a.export()).thumbprint() == a.thumbprint()
    # The published backend has no X25519 key-file encodings.
    with pytest.raises(ValueError):
        a.export_to_pem(True, password=None)
    with pytest.raises(ValueError):
        a.export_to_der(True)
    with pytest.raises(ValueError):
        a.export_to_pem()
    data = a.export(as_dict=True)
    data["x"] = b["x"]
    with pytest.raises(ValueError):
        JWK(**data)
    with pytest.raises(ValueError):
        a.derive_key(b.public(), algorithm_id="A256GCM", length=1_000_000_000)


@pytest.mark.parametrize("alg", ["A128GCMKW", "A192GCMKW", "A256GCMKW"])
def test_gcmkw_json_headers(alg):
    key = JWK.generate(kty="oct", alg=alg)
    assert len(base64url_decode(key["k"])) == int(alg[1:4]) // 8
    outgoing = JWE(b"gcm wrap", protected={"alg": alg, "enc": "A256GCM"}, recipient=key)
    wire = outgoing.serialize()
    parsed = json.loads(wire)
    protected = json.loads(base64url_decode(parsed["protected"]))
    assert protected["iv"] != parsed["iv"]
    assert protected["tag"] != parsed["tag"]
    peer = peer_jwe.JWE()
    peer.deserialize(wire, peer_jwk.JWK.from_json(key.export()))
    assert peer.payload == b"gcm wrap"
    received = JWE.from_jose_token(wire)
    received.decrypt(key)
    assert received.payload == b"gcm wrap"


@pytest.mark.parametrize("alg", ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"])
@pytest.mark.parametrize("flattened", [True, False])
def test_password_envelopes_and_work_budget(alg, flattened):
    message = JWE(b"password message", protected={"alg": alg, "enc": "A128GCM"},
                  recipient="disposable password", pbes2_iterations=1000, flattened=flattened)
    wire = message.serialize()
    received = JWE.from_jose_token(wire)
    received.decrypt("disposable password", pbes2_max_iterations=1000)
    assert received.payload == b"password message"
    for options, password in [({"pbes2_max_iterations": 999}, "disposable password"), ({}, "incorrect")]:
        with pytest.raises(ValueError):
            received.decrypt(password, **options)
        with pytest.raises(ValueError):
            _ = received.payload
    with pytest.raises(ValueError):
        JWE(b"x", protected={"alg": alg, "enc": "A128GCM"}, recipient=JWK.generate(kty="oct"))


@pytest.mark.parametrize("general", [False, True])
def test_aad_crit_and_authenticated_metadata(general):
    keys = [JWK.generate(kty="oct", alg="A256KW", kid=str(i)) for i in range(2 if general else 1)]
    message = JWE(b"payload", protected={"alg": "A256KW", "enc": "A256GCM", "custom": True, "crit": ["custom"]},
                  aad=b"invoice", understood_crit=["custom"])
    for key in keys:
        message.add_recipient(key)
    wire = message.serialize()
    assert wire == message.serialize()
    with pytest.raises(ValueError):
        message.serialize(True)
    received = JWE(understood_crit=["custom"])
    received.deserialize(wire)
    for key in keys:
        result = received.decrypt_authenticated(key, expected_aad=b"invoice", max_plaintext=7)
        assert result.value == b"payload"
        assert "kid" not in result.protected
        if general:
            assert result.unprotected == ({"kid": key["kid"]},)
    for options in ({}, {"expected_aad": b"wrong"}, {"expected_aad": b"invoice", "max_plaintext": 6}):
        with pytest.raises(ValueError):
            received.decrypt(keys[0], **options)
        assert received._authenticated is None
        with pytest.raises(ValueError):
            _ = received.payload
    with pytest.raises(ValueError):
        JWE().deserialize(wire, keys[0], expected_aad=b"invoice")


def test_general_recipient_selection_and_limits():
    keys = [JWK.generate(kty="oct", alg="A128KW", kid=str(i)) for i in range(32)]
    outgoing = JWE(b"many", protected={"alg": "A128KW", "enc": "A128GCM"})
    for key in keys:
        outgoing.add_recipient(key)
    with pytest.raises(ValueError):
        outgoing.add_recipient(keys[0])
    wire = outgoing.serialize()
    received = JWE.from_jose_token(wire)
    received.decrypt(keys[-1])
    assert received.payload == b"many"
    anonymous = JWK.from_json(keys[-1].export())
    del anonymous["kid"]
    with pytest.raises(ValueError):
        received.decrypt(anonymous)
    received.decrypt(anonymous, recipient_index=31)
    for index in (-1, 32, True):
        with pytest.raises(ValueError):
            received.decrypt(anonymous, recipient_index=index)
    duplicate = json.loads(wire)
    duplicate["recipients"][0]["header"]["kid"] = "31"
    with pytest.raises(ValueError):
        JWE().deserialize(json.dumps(duplicate), keys[-1])


def test_empty_gcm_json_and_duplicate_members():
    key = JWK.generate(kty="oct", alg="A128KW")
    for flattened in (True, False):
        message = JWE(b"", protected={"alg": "A128KW", "enc": "A128GCM"}, recipient=key, flattened=flattened)
        wire = message.serialize()
        result = JWE.from_jose_token(wire)
        result.decrypt(key, max_plaintext=0)
        assert result.payload == b""
        bad = wire[:-1] + ',"ciphertext":""}'
        with pytest.raises(ValueError):
            result.deserialize(bad, key)
        with pytest.raises(ValueError):
            _ = result.payload


def test_unprotected_alg_requires_trusted_pin():
    key = JWK.generate(kty="oct", alg="A128KW")
    peer = peer_jwe.JWE(b"external", protected={"enc": "A128GCM"},
                        unprotected={"alg": "A128KW", "kid": "untrusted"})
    peer.add_recipient(peer_jwk.JWK.from_json(key.export()))
    obj = JWE.from_jose_token(peer.serialize())
    result = obj.decrypt_authenticated(key)
    assert "alg" not in result.protected and "kid" not in result.protected
    assert result.unprotected == ({"alg": "A128KW", "kid": "untrusted"},)
    del key["alg"]
    with pytest.raises(ValueError):
        obj.decrypt(key)


def test_keyset_budgets_diagnostics_and_atomicity():
    key = JWK.generate(kty="oct", alg="HS256", kid="known")
    raw = json.dumps({"keys": [key.export(as_dict=True), {"kty": "future", "kid": "unknown"},
                                {"kty": "oct", "k": "?", "kid": "bad"}]})
    with pytest.raises(ValueError):
        JWKSet.from_json(raw)
    keys = JWKSet.from_json(raw, strict=False)
    assert [d["status"] for d in keys.diagnostics()] == ["usable", "unsupported", "invalid"]
    assert keys.select("known").candidates[0].thumbprint() == key.thumbprint()
    before = keys.export()
    with pytest.raises(ValueError):
        keys.import_keyset(raw)
    assert keys.export() == before
    for limits in (SetLimits(max_bytes=len(raw.encode()) - 1), SetLimits(max_entries=2)):
        with pytest.raises(ValueError):
            JWKSet.from_json(raw, strict=False, limits=limits)
    assert len(JWKSet.from_json(raw, strict=False, limits=SetLimits(max_bytes=len(raw.encode()), max_entries=3))) == 3
    with pytest.raises(ValueError):
        keys.select(None, policy=SelectionPolicy(max_candidates=2))
    with pytest.raises(ValueError):
        keys.select(None, policy=SelectionPolicy.strict())
    with pytest.raises(ValueError):
        keys.select("missing")
    assert len(keys.select("missing", policy=SelectionPolicy(fallback="all")).candidates) == 3
    with pytest.raises(ValueError):
        keys.select(None, policy=SelectionPolicy(fallback="unaddressable"))
    assert len(keys.select().candidates) == 3


def test_signature_selection_reports_and_authenticated_context():
    a = JWK.generate(kty="oct", alg="HS256", kid="a")
    b = JWK.generate(kty="oct", alg="HS256", kid="b")
    message = JWS(b"report")
    message.add_signature(a, protected={"alg": "HS256", "kid": "a"}, header={"display": "not trusted"})
    message.add_signature(b, protected={"alg": "HS256", "kid": "b"})
    keys = JWKSet()
    keys.add(a)
    keys.add(b)
    parsed = JWS.from_jose_token(message.serialize())
    report = parsed.verify_report(keys)
    assert report.satisfied
    assert report.results[0].attempted and report.results[0].verified
    assert not report.results[1].attempted
    result = parsed.verify_authenticated(keys)
    assert result.protected["kid"] == "a"
    assert result.unprotected == ({"display": "not trusted"},)
    altered = result.protected
    altered["kid"] = "b"
    assert result.protected["kid"] == "a"
    assert all(r.verified for r in parsed.verify_all(keys))
    # Same secret, wrong labelled key must not authenticate a labelled signature.
    impersonator = JWK.from_json(a.export())
    impersonator["kid"] = "b"
    wrong_set = JWKSet()
    wrong_set.add(impersonator)
    assert not parsed.verify_report(wrong_set, policy="all").satisfied
    with pytest.raises(ValueError):
        _ = parsed.payload
    assert parsed._authenticated is None
    with pytest.raises(TypeError):
        Authenticated()


def test_jwt_checked_claims_exact_numbers_and_serialization():
    key = JWK.generate(kty="oct", alg="HS256")
    raw = '{"custom":12345678901234567890.1234567890123456789,"large":1e400,"sub":"alice"}'
    token = JWT(header={"alg": "HS256"}, claims=raw)
    token.make_signed_token(key)
    received = JWT(jwt=token.serialize(), key=key)
    assert received.claims == raw
    result = received.validate_authenticated(key)
    assert result.value["custom"] == Decimal("12345678901234567890.1234567890123456789")
    assert result.value["large"] == Decimal("1e400")
    with pytest.raises(ValueError):
        JWT(claims='{"sub":"one","sub":"two"}')
    with pytest.raises(ValueError):
        JWT(claims='{"exp":true}')
    general = token.token.serialize()
    assert JWT(jwt=general, key=key).claims == raw
    with pytest.raises(ValueError):
        JWT(jwt=general, key=key, strict_serialization=True)
    bad = JWS('{"custom":1,"custom":2}')
    bad.add_signature(key, protected={"alg": "HS256"})
    with pytest.raises(ValueError):
        jwt.decode_unverified(bad.serialize(True))
    with pytest.raises(ValueError):
        received.deserialize(bad.serialize(True), key)
    with pytest.raises(AttributeError):
        _ = received.claims


@pytest.mark.parametrize("hash_name", ["sha-256", "sha-384", "sha-512"])
def test_thumbprint_uris(hash_name):
    key = JWK.generate(kty="EC", crv="P-256")
    uri = JWKThumbprintURI.parse(key.thumbprint_uri(hash_name))
    assert uri.matches(key.public())
    assert not uri.matches(JWK.generate(kty="EC", crv="P-256"))
    for wrong in (str(uri) + "=", str(uri)[:-1], str(uri).replace(hash_name, "sha-1")):
        with pytest.raises(ValueError):
            JWKThumbprintURI.parse(wrong)


@pytest.mark.parametrize("kind", ["RSA", "P-256", "Ed25519"])
@pytest.mark.parametrize("pem", [True, False])
def test_encrypted_key_files(signing_keys, kind, pem):
    key = signing_keys[kind]
    export = key.export_to_pem if pem else key.export_to_der
    protected = export(private_key=True, password=b"test password", iterations=2048)
    restored = (JWK.from_pem(protected, b"test password", max_iterations=2048) if pem else
                JWK.from_der(protected, private=True, password=b"test password", max_iterations=2048))
    assert restored.thumbprint() == key.thumbprint()
    for password, maximum in [(b"wrong", 2048), (b"test password", 2047)]:
        with pytest.raises(ValueError):
            if pem:
                JWK.from_pem(protected, password, max_iterations=maximum)
            else:
                JWK.from_der(protected, private=True, password=password, max_iterations=maximum)
    with pytest.raises(ValueError):
        key.export_to_pem(private_key=True)
    if pem:
        peer = peer_jwk.JWK.from_pem(protected, password=b"test password")
        assert peer.thumbprint() == key.thumbprint()
        assert JWK.from_pem(peer.export_to_pem(True, b"another password"), b"another password").thumbprint() == key.thumbprint()


def test_pkcs1_sec1_and_certificate_imports():
    now = datetime.datetime.now(datetime.timezone.utc)
    for private in (rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP256R1())):
        pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        key = JWK.from_pem(pem)
        der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        fmt = "pkcs1-private" if isinstance(private, rsa.RSAPrivateKey) else "sec1"
        assert JWK.from_der(der, format=fmt).thumbprint() == key.thumbprint()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disposable test")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
                .serial_number(1).not_valid_before(now - datetime.timedelta(days=2))
                .not_valid_after(now - datetime.timedelta(days=1)).sign(private, hashes.SHA256()))
        # Expired self-signed certificates still permit extraction, not trust validation.
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        assert JWK.from_certificate_pem(cert_pem).thumbprint() == key.thumbprint()
        assert JWK.from_certificate_der(cert.public_bytes(serialization.Encoding.DER)).thumbprint() == key.thumbprint()
        with pytest.raises(ValueError):
            JWK.from_certificate_pem(cert_pem + cert_pem)
        with pytest.raises(ValueError):
            JWK.from_pem(cert_pem)


def test_nested_password_and_error_categories():
    signer = JWK.generate(kty="oct", alg="HS256")
    wire = jwt.encode_nested(signer, b"password", {"sub": "alice"}, algorithm="HS256",
                             encryption_algorithm="PBES2-HS256+A128KW", encryption="A256GCM",
                             pbes2_iterations=1000)
    assert jwt.decode_nested(wire, signer, b"password", algorithms=["PBES2-HS256+A128KW"],
                             encryptions=["A256GCM"], pbes2_max_iterations=1000)["sub"] == "alice"
    with pytest.raises(ValueError) as failure:
        JWE().deserialize(wire, b"wrong")
    # The upstream PBES2 wrapper currently reports unwrap failure as Key.
    assert failure.value.category == "key_material"
    assert not is_authentication_failure(failure.value)
    direct = JWK.generate(kty="oct", alg="dir")
    token = JWE(b"payload", protected={"alg": "dir", "enc": "A256GCM"}, recipient=direct)
    with pytest.raises(ValueError) as failure:
        JWE().deserialize(token.serialize(True), JWK.generate(kty="oct", alg="dir"))
    assert is_authentication_failure(failure.value)
    assert failure.value.category == "cryptographic"


@pytest.mark.parametrize("raw", ["null", "123", "true", "[]", '{"exp":NaN}'])
def test_received_checked_claims_reject_nonobjects_and_nonfinite(raw):
    key = JWK.generate(kty="oct", alg="HS256")
    message = JWS(raw)
    message.add_signature(key, protected={"alg": "HS256"})
    received = JWT(jwt=message.serialize(True))
    with pytest.raises(ValueError):
        received.validate(key)
    with pytest.raises(AttributeError):
        _ = received.claims
    assert received._authenticated is None
