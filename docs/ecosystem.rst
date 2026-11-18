Dependency status for 0.4.1
===========================

Checked against crates.io and PyPI on 2026-11-18. All Rust dependencies
come from the registry. Source builds require Rust 1.89 or later.

Direct Rust dependencies
------------------------

.. list-table::
   :header-rows: 1

   * - Crate
     - Selected
     - Latest stable
   * - jose-rs
     - 0.12.1
     - 0.12.1
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
     - 1.9.2
     - 1.9.2

RSA security
------------

The locked RSA 0.10.0 contains the fix for RUSTSEC-2023-0071 for private-key
operations, including signing and decryption. The audit requires no advisory
exception. See :doc:`hsm` for signing with token-resident authority keys.

Python tooling
--------------

Builds require maturin >=1.16,<2. Development extras require pytest >=9.2 and
jwcrypto >=1.6.1; documentation uses Furo >=2025.12.19. Sphinx is selected by
interpreter. The minimum versions are 8.1.3 for Python 3.10, 9.0.4 for
Python 3.11, 9.1.1 for Python 3.12 and 9.2.0 for Python 3.13 and newer.
