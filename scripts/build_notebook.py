"""Generate the single self-contained Colab notebook from the repository.

    python scripts/build_notebook.py      # writes notebooks/huntcrew_colab.ipynb

The notebook embeds every project file (package, config, policy, fetch script, saved results) as a
`%%writefile` cell and lists its own requirements, so one .ipynb is the whole project: no git clone, no extra
files. The repository stays the single source of truth; this script only copies it into the notebook.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = "/content/HuntCrew"
REQUIREMENTS = ["crewai==1.15.28", "chromadb==1.5.9", "litellm==1.103.1", "sentence-transformers", "PyYAML"]

# Files embedded in the notebook, in the order they appear. Paths are relative to the repository root.
CONFIG_AND_DATA = ["config.yaml", "data/policy/policy.json", "results/final.json"]
SCRIPTS = ["scripts/fetch_data.py", "scripts/run_eval.py"]


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.strip("\n").splitlines(keepends=True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": text.strip("\n").splitlines(keepends=True)}


def write_cell(rel: str) -> dict:
    body = (ROOT / rel).read_text(encoding="utf-8").rstrip("\n")
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": f"%%writefile {APP}/{rel}\n{body}\n".splitlines(keepends=True)}


def package_files() -> list[str]:
    files = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "src" / "huntcrew").glob("*.py"))
    files.remove("src/huntcrew/__init__.py")
    return ["src/huntcrew/__init__.py", *files]


def cells() -> list[dict]:
    pkg = package_files()
    out = [
        md("""
# HuntCrew: agent-led threat detection and response

A crew of agents (CrewAI + RAG over MITRE ATT&CK) detects attacks in **replayed real network traffic**
(CIC-IDS2017), names the technique, plans a policy-checked response, asks a human before risky actions and
writes an incident report. **Grading is done by code against the dataset's own labels**, never by the agents.

**This one notebook is the whole project.** Every source file is written out by the cells below; nothing is
cloned. The repository (https://github.com/Paritsingla7/HuntCrew) holds the same files plus docs and tests.

**How to run (about 10-15 minutes, free CPU runtime is enough)**
1. Add a Colab Secret named `MISTRAL_API_KEY` (key icon in the left sidebar) and switch *Notebook access* on.
2. Click **Runtime -> Run all**. The first pass installs packages and then restarts the session on purpose
   (Colab says "session crashed"); click **Run all** again.
3. Click **Grant access** when Colab asks about the secret. If a risky action is proposed, answer the
   `approve? [y/N]` prompt under section 3.
"""),
        md("## 1. Install packages (once)"),
        code(f"""
# Colab must restart its Python process after packages such as Pillow change, so on the first run this cell
# installs and then restarts the session; just run all cells again afterwards.
import importlib.util, os, signal, subprocess, sys
REQUIREMENTS = {REQUIREMENTS!r}
if importlib.util.find_spec("crewai") is None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", *REQUIREMENTS], check=True)
    print("Packages installed. Restarting the session now - run all cells again.")
    os.kill(os.getpid(), signal.SIGKILL)
print("dependencies ready")
"""),
        md("## 2. The project's files\nEach cell below writes one file of the project to disk, exactly as it is in the repository."),
        code(f"""
import os
for d in ["src/huntcrew", "scripts", "data/policy", "results"]:
    os.makedirs(f"{APP}/{{d}}", exist_ok=True)
%cd {APP}
"""),
        md("### Configuration, policy and saved results\n`config.yaml` holds every tunable (model, throttle, pre-registered splits, "
           "label mapping, gate bar). `policy.json` is the action catalog and protected assets. `results/final.json` "
           "holds the numbers of the one frozen evaluation run."),
        *[write_cell(f) for f in CONFIG_AND_DATA],
        md("### The `huntcrew` package\n"
           "`schema`, `config`: data contracts and settings. `data_cic`, `replay`, `digest`, `profile`: real traffic, "
           "one window at a time, summarised as statistics. `attack_kb`: ATT&CK knowledge base (RAG). "
           "`detector_tools`, `evidence`, `detector`: the detector agent and its code verification. "
           "`crew`, `pipeline`, `response`: technique naming, response planning, policy, simulated environment, "
           "approval gate. `baselines`, `evaluate`: the comparison systems and the grader (code only). "
           "`llm`, `syncutil`, `demo`: model plumbing and notebook helpers."),
        *[write_cell(f) for f in pkg],
        md("### Scripts\n`fetch_data.py` downloads the two external datasets with checksums; `run_eval.py` re-runs the "
           "full evaluation (optional, about an hour of API calls)."),
        *[write_cell(f) for f in SCRIPTS],
        md("## 3. Download the data and set up\nFetches CIC-IDS2017 flows and the MITRE ATT&CK bundle (about 425 MB, "
           "checksum-verified; never stored in the repository), then builds the 706-chunk knowledge base."),
        code(f"""
!python -I {APP}/scripts/fetch_data.py
"""),
        code(f"""
import sys, warnings; warnings.filterwarnings("ignore")
%cd {APP}
sys.path.insert(0, "{APP}/src")
from huntcrew import demo
d = demo.setup()          # checks the key, loads data, builds the ATT&CK knowledge base, wires the agents
print("model:", d.cfg["llm"]["model"], "| ATT&CK chunks:", len(d.kb.chunks))
"""),
        md("## 4. Replay real traffic through the detector\nWindows are revealed one at a time; agents can look back but "
           "never forward, and never see labels. Hybrid mode: rules propose candidates, the agent verifies them."),
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
        md("## 5. Name the technique, plan the response, ask before risky actions"),
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
        md("## 6. Results (graded by code against dataset labels)\nFrom the one frozen evaluation run on the untouched test slices "
           "(SSH-Patator, Bot, PortScan). To re-run it yourself, uncomment the last line (about an hour of API calls)."),
        code("""
import json, pathlib
res = json.loads(pathlib.Path("results/final.json").read_text())
rows = []
for sl, systems in res["slices"].items():
    for sysname, e in systems.items():
        if isinstance(e, dict) and "detection" in e:
            rows.append({"slice": sl, "system": sysname, **{k: e["detection"][k] for k in ("recall", "precision", "f1", "fp")}})
display(pd.DataFrame(rows))
print("pooled over test slices:")
display(pd.DataFrame(res["micro_average"]).T)
print("hybrid, full pipeline:", res["hybrid_response"])
# !python scripts/run_eval.py test --systems b0 b1 hybrid        # optional: re-run the full evaluation
"""),
    ]
    return out


def build(out: str | Path = ROOT / "notebooks" / "huntcrew_colab.ipynb") -> Path:
    nb = {"cells": cells(), "nbformat": 4, "nbformat_minor": 5,
          "metadata": {"colab": {"provenance": []}, "kernelspec": {"name": "python3", "display_name": "Python 3"},
                       "language_info": {"name": "python"}}}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    return out


if __name__ == "__main__":
    p = build()
    print("wrote", p, f"({p.stat().st_size / 1024:.0f} KB, {len(cells())} cells)")
