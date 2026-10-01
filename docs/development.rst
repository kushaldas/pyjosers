Development and maintenance
===========================

Repository layout
-----------------

.. code-block:: text

   Cargo.toml / Cargo.lock     Native crate and pinned dependencies
   pyproject.toml             Python metadata and maturin configuration
   src/lib.rs                 Owned JSON/bytes boundary, errors, GIL release
   src/hsm.rs                 Native PKCS#11 provider/session/operation handles
   python/pyjosers/            Public compatibility API and annotations
   tests/                     Interoperability, policy and migration tests
   docs/                      Sphinx guides and reference
   examples/                  Runnable usage examples

JSON and byte buffers cross the PyO3 boundary as owned values. Native code
constructs keys and checks operation metadata before invoking jose-rs.
Cryptographic work releases the GIL using ``Python.detach``; it does not retain
borrowed Python references. Native errors are translated into Python exception
classes. A Rust SoftwareKey is never exposed as a Python cryptography object.

The JWS Python layer handles object lifecycle and general-serialization
aggregation. Each signature is produced/verified by the Rust flattened-JWS
implementation, preserving the original protected-header encoding. The JWE
JSON adapter preserves the five authenticated compact segments.

Validation commands
-------------------

.. code-block:: sh

   uv pip install -e '.[dev]'
   cargo fmt --check
   cargo clippy --all-features -- -D warnings
   pytest -q
   sphinx-build -W --keep-going -b html docs docs/_build/html
   sphinx-build -W -b doctest docs docs/_build/doctest
   maturin build --release --locked
   maturin sdist

The interop suite requires jwcrypto as a **test** dependency, not a runtime
fallback. Tests use newly generated keys and do not read the admin application's
key files. Optional HSM tests provision a disposable software token.

Feature checks
--------------

.. code-block:: sh

   maturin develop --no-default-features
   pytest -q
   maturin develop --features legacy
   pytest -q
   maturin develop

The last command restores the default feature build. Tests for post-quantum and
HSM operations skip when their corresponding feature is unavailable.

Updating the upstream dependencies
----------------------------------

Use crates.io dependencies for normal builds. The upstream source checkouts
are ``../jose-rs`` and ``../kryptering``; do not copy their source into this
repository. To test an unpublished jose-rs release, use a temporary Cargo
override such as ``--config 'patch.crates-io.jose-rs.path="../jose-rs"'``.
After publishing the upstream release, run ``cargo update`` without
the override to record its registry checksum in ``Cargo.lock``.
The backend exposes ``jwe::encrypt_with_jwk_header`` publicly, so custom JWE headers
require no local visibility patch.
Review algorithm/feature changes and regenerate the lockfile deliberately.
Re-run interop, feature, documentation, and clean source-distribution builds.

Package verification
--------------------

A source distribution must build after extraction without either sibling project.
A wheel should import and run tests from a fresh virtual environment.
Keep generated extension binaries and documentation
output out of source control. The ``.github/workflows/ci.yml`` workflow tests
Python 3.10 and 3.14, minimal and legacy features, and strict documentation.
The reusable ``wheels.yml`` workflow builds and tests manylinux x86_64 and
aarch64, macOS aarch64, and Windows x86_64 and aarch64 wheels. It also builds
and tests the source distribution outside the checkout. Linux jobs provision
SoftHSM and OpenSC for the PKCS#11 integration tests.
The Windows ARM64 job provisions statically linked ARM64 OpenSSL through
vcpkg so that the test-only ``jwcrypto`` dependency can build ``cryptography``
when no compatible binary wheel is available. This is not a pyjosers runtime
dependency; the job still builds and tests a native ARM64 pyjosers wheel.

Releases
--------

``release.yml`` checks that ``Cargo.toml`` and ``pyproject.toml`` agree and
that a release tag matches their version (for example ``v0.1.0`` for the
first release). It runs the complete CI workflow before publishing the tested
wheels and source distribution, and checks ``Cargo.lock`` with
``cargo metadata --locked`` before starting the build matrix.
Manual dispatch on a branch builds and tests
without publishing; dispatch on a matching release tag also publishes.

Configure the PyPI trusted publisher for this repository, workflow
``release.yml``, and GitHub environment ``pypi`` before tagging a release.
The publishing job uses OIDC; no PyPI API token is required. Build jobs have
read-only repository permissions and do not receive publishing credentials.
Ensure ``Cargo.lock`` contains the crates.io jose-rs release and its registry
checksum before committing a release tag; builds use ``--locked``.
