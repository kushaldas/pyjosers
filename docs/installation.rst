Installation and builds
=======================

Python 3.10 or newer is required. Source builds require Rust 1.89 or newer and
its platform linker. The extension targets CPython's stable ABI from 3.10.
The repository uses maturin, following the pybergshamra build structure, with
an additional ``python/pyjosers`` package for the compatibility API.

From a checkout::

   uv venv
   uv pip install -e '.[dev]'
   uv run pytest

Or with pip::

   python -m venv .venv
   . .venv/bin/activate
   python -m pip install -e '.[dev]'

Build a wheel and source distribution::

   maturin build --release --locked
   maturin sdist

Builds download jose-rs 0.8.0 and kryptering 0.6 from crates.io; sibling
source checkouts are not required. No backend source is vendored in this repository.
Custom protected JWE headers use the public upstream encryption helpers.
``Cargo.lock`` pins Rust dependencies for reproducible builds.

Features
--------

Default builds enable ``post-quantum`` and ``pkcs11``. To build only classical
software operations::

   maturin build --release --locked --no-default-features

For optional SHA-1-based RSA-OAEP interoperability::

   maturin build --release --locked --features legacy

The ``legacy`` feature enables upstream deprecated support, but the public
Python API still rejects unsigned ``alg=none`` tokens. New deployments should
use ``RSA-OAEP-256``. ``pyjosers.algorithms`` reflects the compiled features;
``pyjosers.POST_QUANTUM`` and ``pyjosers.PKCS11`` expose capabilities.

A PKCS#11 build does not require a hardware token or vendor library at build
time. The vendor shared library is loaded only when creating a provider.

Documentation
-------------

Build HTML with warnings treated as errors::

   sphinx-build -W --keep-going -b html docs docs/_build/html
   sphinx-build -W -b doctest docs docs/_build/doctest

The extension must be installed first so autodoc can import the public API.
