"""Execute the actual files included in the documentation, against the installed package."""
from pathlib import Path
import subprocess
import sys

import pytest

EXAMPLES = sorted((Path(__file__).resolve().parents[1] / "examples").glob("*.py"))


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.name)
def test_documented_example(example, tmp_path):
    result = subprocess.run([sys.executable, str(example)], cwd=tmp_path,
                            text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
