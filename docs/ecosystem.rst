Dependency status for 0.3.0
===========================

Checked against crates.io and PyPI on 2026-11-10. Dependencies remain published
registry packages; no sibling checkout or vendored code is required.

Direct Rust dependencies
------------------------

.. list-table::
   :header-rows: 1

   * - Crate
     - Selected
     - Latest stable
   * - jose-rs
     - 0.11.0
     - 0.11.0
   * - kryptering
     - 0.7.1
     - 0.7.1
   * - pyo3
     - 0.30.1
     - 0.30.1
   * - serde
     - 1.0.229
     - 1.0.229
   * - serde_json
     - 1.0.154
     - 1.0.154
   * - pkcs8
     - 0.11.0
     - 0.11.0
   * - zeroize
     - 1.9.1
     - 1.9.1

RSA migration
-------------

jose-rs 0.11.0 and Kryptering 0.7.1 both accept stable RSA 0.10. Cargo now
selects RSA 0.10.0 instead of 0.10.0-rc.19, removing the former dependency
conflict and allowing Kryptering's patch update. No cryptographic trait
dependency is overridden.

``cargo outdated --depth 1`` reports that all dependencies are up to date.
``cargo audit --deny warnings`` passes without exceptions, including for the
RSA advisory reported with the previous prerelease dependency.

Lockfile refresh
----------------

``cargo update`` applied these compatible updates while retaining Rust 1.89:

* jose-rs 0.10.0 -> 0.11.0
* kryptering 0.7.0 -> 0.7.1
* rsa 0.10.0-rc.19 -> 0.10.0
* base64 0.22.1 -> 0.23.1
* aes 0.9.3 -> 0.9.4
* crypto-bigint 0.7.5 -> 0.7.11
* ctutils 0.4.3 -> 0.4.8
* der 0.8.2 -> 0.8.3
* elliptic-curve 0.14.1 -> 0.14.3
* inout 0.2.5 -> 0.2.6
* itoa 1.0.18 -> 1.0.19
* log 0.4.34 -> 0.4.35
* ml-dsa 0.1.1 -> 0.1.2
* ml-kem 0.3.3 -> 0.3.4
* module-lattice 0.2.3 -> 0.2.4
* pkcs1 0.8.0-rc.5 -> 0.8.0
* syn 3.0.9 -> 3.0.10

Python tooling
--------------

Builds require maturin >=1.16,<2. Development extras require pytest >=9.2 and
jwcrypto >=1.6.1; documentation uses Furo >=2025.12.19. Sphinx is selected by
interpreter: >=9.2 on Python 3.13+, >=8.2.3,<9 on Python 3.11/3.12, and
>=7.4.7,<8 on Python 3.10. This preserves the package's Python 3.10 minimum.

Verification
------------

* Python 3.14 suite: 366 passed, 1 skipped (external admin checkout unset).
* Strict Sphinx HTML build and all 75 documentation examples passed.
* Rust formatting, Clippy with all features and minimal-feature checking passed.
  The all-feature check also passed on Rust 1.89.0.
* Release wheel and source distribution builds passed with registry dependencies.
* Development dependency resolution passed for Python 3.10 and 3.11;
  documentation dependency resolution also passed for Python 3.12 and 3.13.
* Cargo audit passed without exceptions; cargo outdated reported all dependencies
  up to date.
