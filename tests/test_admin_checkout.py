"""Opt-in integration against actual admin functions, without Django or app secrets."""
import ast
import json
import os
from pathlib import Path
import time

import pytest
from pyjosers import jwk, jwt


def _load_function(path, name, namespace):
    """Compile only the selected function; do not import application settings."""
    tree = ast.parse(path.read_text(), filename=str(path))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    module = ast.Module(body=[node], type_ignores=[])
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[name]


def test_actual_admin_functions():
    location = os.environ.get("PYJOSERS_ADMIN_CHECKOUT")
    if not location:
        pytest.skip("set PYJOSERS_ADMIN_CHECKOUT to test an existing admin checkout")
    root = Path(location)
    namespace = {"jwt": jwt, "JWK": jwk.JWK, "JWKSet": jwk.JWKSet, "Any": object, "json": json}
    signing = _load_function(root / "common/signing.py", "create_signed_jwt", namespace)
    validate = _load_function(root / "entities/lib.py", "self_validate", namespace)
    for params, alg in [({"kty": "EC", "crv": "P-256"}, "ES256"),
                        ({"kty": "OKP", "crv": "Ed25519"}, "Ed25519")]:
        key = jwk.JWK.generate(**params, alg=alg)
        keys = jwk.JWKSet()
        keys.add(key)
        claims = {"iss": "https://entity.example", "sub": "https://entity.example",
                  "iat": time.time(), "exp": time.time() + 3600,
                  "jwks": keys.export(private_keys=False, as_dict=True)}
        token = signing(claims, key, "entity-statement+jwt")
        received = jwt.JWT.from_jose_token(token)
        assert validate(received) == claims
        assert json.loads(received.claims) == claims
