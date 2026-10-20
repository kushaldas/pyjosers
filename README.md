# pyjosers

Python JOSE (JWK, JWS, JWE, JWT) backed by jose-rs and PyO3, with a familiar
`jwcrypto`-style API. Requires Python 3.10+; building requires Rust 1.89+.

```python
from pyjosers import jwk, jwt
key = jwk.JWK.generate(kty="EC", crv="P-256")
token = jwt.JWT(header={"alg": "ES256"}, claims={"sub": "alice"})
token.make_signed_token(key)
verified = jwt.JWT(jwt=token.serialize(), key=key.public(), algs=["ES256"])
print(verified.claims)
```

Development:

Release 0.2.0 uses published crates.io `jose-rs =0.10.0`, Kryptering 0.7,
and `pyo3 =0.30.1`. Wheels and source builds need no sibling checkout.
See `docs/backend-0100.rst` for coverage and backend limitations.

New APIs cover ECDH/X25519, AES-GCM key wrapping, password encryption,
general JWE, external AAD, encrypted key files, bounded JWKS selection,
capability reports, and authenticated payload/header results. Private PEM
export requires an explicit password choice (`None` for plaintext).

```sh
uv venv
uv pip install -e '.[dev]'
uv run pytest
uv run sphinx-build -W --keep-going -b html docs docs/_build/html
```

See `docs/` for the API reference, algorithms, examples, build instructions,
and migration guide, including the Inmor admin call patterns. Compatibility is
explicitly scoped; this is not a complete replacement for every jwcrypto API.
