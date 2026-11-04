"""The Colab notebook is generated; these tests keep it honest.

* fast: the committed notebook equals what the generator produces, and every code cell is valid Python;
* slow (HUNTCREW_SLOW=1): run the whole notebook on the real data against a stand-in model (no API key needed).
"""
import ast
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "huntcrew_colab.ipynb"


def _builder():
    spec = importlib.util.spec_from_file_location("build_notebook", ROOT / "scripts" / "build_notebook.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_notebook_is_in_sync_with_its_generator(tmp_path):
    out = _builder().build(tmp_path / "nb.ipynb")
    assert json.loads(out.read_text()) == json.loads(NOTEBOOK.read_text()), "run: python scripts/build_notebook.py"


def test_every_code_cell_is_valid_python_and_standalone():
    nb = json.loads(NOTEBOOK.read_text())
    code = ["".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"]
    for src in code:
        ast.parse(src)
    joined = "\n".join(code)
    assert "git clone" not in joined and "from huntcrew" not in joined and "import huntcrew" not in joined


@pytest.mark.skipif(os.environ.get("HUNTCREW_SLOW") != "1", reason="set HUNTCREW_SLOW=1 (needs the datasets)")
def test_notebook_runs_end_to_end_with_a_stand_in_model(tmp_path):
    res = subprocess.run([sys.executable, str(ROOT / "tests" / "support" / "notebook_standin.py"), str(ROOT), str(tmp_path)],
                         capture_output=True, text=True, timeout=900)
    assert res.returncode == 0, res.stderr[-2000:]
    out = res.stdout
    assert "CONFIRMED 172.16.0.1" in out and "protected asset" in out and "technique CORRECT" in out
    assert "DENIED    force_password_reset" in out and "unknown action type" in out
    assert "no target given" in out and "not seen in this incident" in out
