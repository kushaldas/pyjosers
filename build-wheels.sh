#!/usr/bin/env bash
# Called by the native x86_64/aarch64 manylinux containers in wheels.yml.
set -euo pipefail

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
export PATH="$HOME/.cargo/bin:$PATH"

wheel_python=/opt/python/cp314-cp314/bin/python3.14
"$wheel_python" -m pip install --disable-pip-version-check 'maturin>=1.9,<2'
cd /io
"$wheel_python" -m maturin build --release --strip --locked --manylinux 2_28 \
    --interpreter "$wheel_python" --out dist
