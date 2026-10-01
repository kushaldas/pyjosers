# Repository Guidelines

## Project Structure & Module Organization

- `src/lib.rs` implements the PyO3 boundary; `src/hsm.rs` owns PKCS#11 handles.
- `python/pyjosers/` contains the public JWK, JWS, JWE, and JWT APIs, native stubs, and `py.typed` marker.
- `jose-rs` and `kryptering` are crates.io dependencies. Their source checkouts are `../jose-rs/` and `../kryptering/`; do not vendor their source in this repository.
- `tests/` covers interoperability, validation, admin migration, and SoftHSM integration.
- `docs/` contains Sphinx sources; `examples/` contains runnable demonstrations. Generated files belong in `target/`, `dist/`, and `docs/_build/`.

## Build, Test, and Development Commands

Requires Python 3.10+ and Rust 1.89+. Set up and activate the environment:

```sh
uv venv
source .venv/bin/activate
uv pip install -e '.[dev]'
```

- `maturin develop`: rebuild and install the editable native extension after Rust changes.
- `pytest -q`: run the Python test suite.
- `cargo fmt --check`: check Rust formatting.
- `cargo clippy --all-features -- -D warnings`: lint Rust with all features enabled.
- `sphinx-build -W --keep-going -b html docs docs/_build/html`: build documentation strictly.
- `sphinx-build -W -b doctest docs docs/_build/doctest`: execute documentation examples.
- `maturin build --release --locked` and `maturin sdist`: create distribution artifacts.

## Coding Style & Naming Conventions

Use four-space Python indentation, `snake_case` functions/modules, and descriptive class names; preserve established JOSE acronyms such as `JWK`. Add type annotations and public docstrings, and synchronize `_native.pyi` with Rust signatures. Use rustfmt for Rust; no Python formatter is currently configured. Keep cryptography in Rust and compatibility behavior in Python. Update documentation whenever public APIs change.

## Testing Guidelines

Name pytest files `test_*.py` and tests `test_*`. Add regression coverage for changed behavior, including failed authentication and object-state clearing. Cryptographic changes should include bidirectional jwcrypto interoperability where supported. No numeric coverage threshold is configured. Generate disposable keys; never use application secrets. SoftHSM tests skip when dependencies are unavailable. Set `PYJOSERS_ADMIN_CHECKOUT` to exercise actual admin functions. Check minimal and legacy feature builds when relevant; restore defaults afterward.

## Commit & Pull Request Guidelines

Use concise, imperative commit subjects. Pull requests should
explain the problem, behavior changes, compatibility implications, related
issues when applicable, and validation commands/results. Document backend
patches and algorithm limitations explicitly. Exclude generated binaries, build
output, and private keys.
