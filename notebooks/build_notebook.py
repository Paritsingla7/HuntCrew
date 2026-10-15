"""Generate the Colab submission notebook from the repository (single source of truth: the package).

    python notebooks/build_notebook.py        # writes notebooks/huntcrew_colab.ipynb
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = "https://github.com/Paritsingla7/HuntCrew.git"


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.strip("\n").splitlines(keepends=True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": text.strip("\n").splitlines(keepends=True)}


CELLS = [
    md("""
# HuntCrew: agent-led threat detection and response

A crew of agents (CrewAI + RAG over MITRE ATT&CK) detects attacks in **replayed real network traffic**
(CIC-IDS2017), names the technique, plans a policy-checked response, asks a human before risky actions and
writes an incident report. **Grading is done by code against the dataset's own labels**, never by the agents.

Architecture and decisions: see `docs/` in the repository. Run all cells top to bottom (about 10-15 minutes).
Requires a Colab Secret named `MISTRAL_API_KEY` with notebook access enabled.
"""),
    code(f"""
%cd /content
!git clone -q {REPO} 2>/dev/null || (cd HuntCrew && git pull -q)
%cd /content/HuntCrew
"""),
    code("""
# Install once. Colab must restart its Python process after packages such as Pillow change, so on the
# first run this cell installs and then restarts the session; just run "Run all" again afterwards.
import importlib.util, os, signal, subprocess, sys
if importlib.util.find_spec("crewai") is None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", "requirements-colab.txt"], check=True)
    print("Packages installed. Restarting the session now - run all cells again.")
    os.kill(os.getpid(), signal.SIGKILL)
print("dependencies ready")
"""),
    code("""
# Fetch the two external datasets (about 425 MB) with checksums; they are never stored in the repository.
!python -I scripts/fetch_data.py
"""),
    code("""
import sys, warnings; warnings.filterwarnings("ignore")
sys.path.insert(0, "src")          # use the cloned package directly
from huntcrew import demo
d = demo.setup()          # loads data, builds the ATT&CK knowledge base, wires agents (key from Colab Secrets)
print("model:", d.cfg["llm"]["model"], "| ATT&CK chunks:", len(d.kb.chunks))
"""),
    md("""
## 1. Replay a window of real traffic through the detector
Windows are revealed one at a time; agents can look back but never forward, and never see labels.
"""),
    code("""
import pandas as pd
truth = demo.windows_labelled(d, "test", "ssh_patator")        # grader's view, only to pick windows to show
pick = sorted(truth.window_index.unique())[:2]
results, incidents = demo.detect(d, "test", "ssh_patator", windows=pick, mode="rules")
for r in results:
    print(f"window {r.window.label()}: {len(r.findings)} verified finding(s), {len(r.rejected)} rejected")
    for f in r.findings:
        print("  ", f.entity, [h.id for h in f.technique_hints], "|", f.behaviour)
"""),
    md("## 2. Name the technique, plan the response, and ask before risky actions"),
    code("""
from huntcrew.response import console_approver
outcomes, env = demo.respond(d, incidents, approver=console_approver)   # asks you to approve medium/high risk
for o in outcomes:
    print(o.incident.id, o.incident.entity, "->", [t.id for t in o.assessment.techniques], o.plan.severity)
    for rec in o.log.records:
        print("   ", rec.status.upper(), rec.action.type, rec.action.target, "|", rec.reason)
print("simulated environment:", env.snapshot())
"""),
    code("""
from IPython.display import Markdown, display
for o in outcomes[:1]:
    display(Markdown(o.report))
"""),
    md("## 3. Results (graded by code against dataset labels)"),
    code("""
import json, pathlib
p = pathlib.Path("results/final.json")
if p.exists():
    res = json.loads(p.read_text())
    rows = []
    for sl, systems in res["slices"].items():
        for sysname, e in systems.items():
            if isinstance(e, dict) and "detection" in e:
                rows.append({"slice": sl, "system": sysname,
                             **{k: e["detection"][k] for k in ("recall", "precision", "f1", "fp")}})
    display(pd.DataFrame(rows))
    print("pooled over test slices:")
    display(pd.DataFrame(res["micro_average"]).T)
    print("hybrid, full pipeline:", res["hybrid_response"])
else:
    print("results/final.json not found - run scripts/run_eval.py first")
"""),
]


def build(out: str | Path = "notebooks/huntcrew_colab.ipynb") -> Path:
    nb = {"cells": CELLS, "nbformat": 4, "nbformat_minor": 5,
          "metadata": {"colab": {"provenance": []}, "kernelspec": {"name": "python3", "display_name": "Python 3"},
                       "language_info": {"name": "python"}}}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    return out


if __name__ == "__main__":
    print("wrote", build())
