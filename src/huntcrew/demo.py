"""Notebook-friendly helpers: one call to set everything up, one to run a few windows end to end."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import pandas as pd

from . import llm as llmmod
from .attack_kb import AttackKB, load_chunks
from .baselines import known_destinations
from .config import load_config
from .crew import DownstreamCrew, incident_profile
from .data_cic import CicData, load_cic
from .detector import WindowResult, merge_into_incidents, run_detector
from .pipeline import IncidentOutcome, process_incident
from .profile import BaselineProfile
from .replay import Replay
from .response import Approver, Policy, SimulatedEnvironment, auto_deny
from .schema import Incident


@dataclass
class Demo:
    cfg: dict
    data: CicData
    kb: AttackKB
    profile: BaselineProfile
    known: set[str]
    policy: Policy
    crew: DownstreamCrew
    llm: Any
    mw: llmmod.Middleware


def setup(config_path: str | None = None, model: str | None = None, use_colab_secret: bool = True) -> Demo:
    """Load config, data, knowledge base and agents. On Colab the key comes from Colab Secrets."""
    if use_colab_secret and not os.environ.get("MISTRAL_API_KEY"):
        try:
            from google.colab import userdata
            os.environ["MISTRAL_API_KEY"] = userdata.get("MISTRAL_API_KEY")
        except Exception:                               # noqa: BLE001 - not on Colab / secret missing
            llmmod.load_dotenv()
    cfg = load_config(config_path)
    c = cfg["llm"]
    mw = llmmod.install(c["min_interval_s"], c["tokens_per_minute"], c["max_retries"], c["cache_dir"])
    llm = llmmod.make_llm(cfg, model)
    data = load_cic(cfg["data"]["cic_parquet"])
    b = cfg["splits"]["baseline_benign"]
    base = data.select(pd.Timestamp(b["start"]), pd.Timestamp(b["end"])).flows
    kb = AttackKB(load_chunks(cfg["data"]["attack_stix"]), cfg["rag"]["embedding_model"], cfg["rag"]["persist_dir"])
    policy = Policy.from_file(cfg["data"]["policy"])
    return Demo(cfg, data, kb, BaselineProfile(base, cfg["replay"]["window_minutes"]), known_destinations(base),
                policy, DownstreamCrew(kb, policy, llm), llm, mw)


def slice_for(d: Demo, split: str, name: str) -> tuple[dict, CicData]:
    s = next(x for x in d.cfg["splits"][split] if x["name"] == name)
    return s, d.data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))


def detect(d: Demo, split: str, name: str, windows: list[int], mode: str = "rules") -> tuple[list[WindowResult], list[Incident]]:
    """Run the detector on selected windows. mode: 'rules' (hybrid) or 'screen' (agent-led)."""
    s, sl = slice_for(d, split, name)
    path = f".cache/runs/demo_{mode}_{split}_{name}.jsonl"
    res = run_detector(sl.flows, s["start"], s["end"], d.cfg, d.kb, d.profile, d.llm, path, d.mw,
                       only_windows=windows, candidates_from=mode, known_dsts=d.known)
    findings = [f for r in res for f in r.findings]
    return res, merge_into_incidents(findings, d.cfg["replay"]["window_minutes"])


def respond(d: Demo, incidents: list[Incident], approver: Approver = auto_deny, flows: Any = None
            ) -> tuple[list[IncidentOutcome], SimulatedEnvironment]:
    env = SimulatedEnvironment()
    prof = (lambda i: incident_profile(flows, i)) if flows is not None else (lambda i: "")
    return [process_incident(i, d.crew, d.policy, env, approver, profile=prof(i)) for i in incidents], env


def windows_labelled(d: Demo, split: str, name: str) -> pd.DataFrame:
    """For choosing demo windows: which windows contain attack-labelled flows (grader view, not for agents)."""
    from .evaluate import attack_truth

    s, sl = slice_for(d, split, name)
    rp = Replay(sl.flows, s["start"], s["end"], d.cfg["replay"]["window_minutes"], d.cfg["replay"]["history_windows"])
    return attack_truth(sl.flows, sl.labels, rp.windows(), d.cfg["labels"]["to_technique"],
                        d.cfg["grading"]["min_attack_flows"])
