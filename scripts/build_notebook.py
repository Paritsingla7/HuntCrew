"""Generate the standalone assignment notebook (notebooks/huntcrew_colab.ipynb).

    python scripts/build_notebook.py

The notebook is a condensed, readable, self-contained version of the agentic pipeline: no repository clone, no
helper files. It downloads its own data, builds the ATT&CK knowledge base, and runs four agents (detector,
threat-intel, strategist, reporter) with code guardrails, a policy and an approval gate. The full, tested
project (replay simulator, evaluation harness, 78 tests, docs) is the GitHub repository.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = "https://github.com/Paritsingla7/HuntCrew"


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.strip("\n").splitlines(keepends=True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": text.strip("\n").splitlines(keepends=True)}


CELLS: list[dict] = [
    md(f'''
# Agentic cyber-threat detection and response (CrewAI + RAG + Mistral)

**What this notebook does.** It replays real network traffic (the CIC-IDS2017 dataset) one 5-minute window at a
time and runs a small crew of AI agents on it:

| Agent | Job | Tools / knowledge |
|---|---|---|
| **Detector** | Decide which suspicious sources are real attacks and which are false alarms | flow statistics, **RAG** over MITRE ATT&CK |
| **Threat-Intel** | Name the ATT&CK technique behind an incident | **RAG** (several competing hypotheses, then an evidence-scoring judge) |
| **Strategist** | Plan a response from the official ATT&CK mitigations | policy, protected assets |
| **Reporter** | Write the incident report | - |

Around the agents, **plain code** checks every claim (cited technique IDs must exist *and* have been retrieved;
actions must be in an allow-list and never touch protected assets), a **human approval gate** stands in front of
risky actions, everything runs on a **simulated** firewall, and the result is **graded by code against the
dataset's own labels**, which the agents never see.

**How to run (about 10 minutes, a free CPU runtime is enough)**
1. Add a Colab Secret named `MISTRAL_API_KEY` (key icon in the left sidebar) and switch *Notebook access* on.
2. **Runtime -> Run all.** The first pass installs packages and restarts the session on purpose
   (Colab says "session crashed"); run all again and click **Grant access** when asked.
3. If a risky action is proposed, answer the `approve? [y/N]` prompt in section 6.

This notebook is a condensed standalone version. The full project (replay simulator, evaluation harness, 78 tests,
decision records) is at {REPO_URL}.
'''),
    md("## 1. Install packages (once)"),
    code('''
# Colab must restart its Python process after packages such as Pillow change. On the first run this cell installs
# and restarts the session; after that it only prints "ready".
import importlib.util, os, signal, subprocess, sys
if importlib.util.find_spec("crewai") is None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "crewai==1.15.28", "chromadb==1.5.9",
                    "litellm==1.103.1", "sentence-transformers", "pyarrow"], check=True)
    print("Packages installed. Restarting the session now - run all cells again.")
    os.kill(os.getpid(), signal.SIGKILL)
print("ready")
'''),
    md('''
## 2. Language model plumbing
The agents use `ministral-14b-latest` through CrewAI. Three small workarounds keep it reliable: a request throttle
with retries (the free tier allows about 30 requests a minute), removal of a prompt-caching field CrewAI adds that the
Mistral API rejects, and running crews in a worker thread (Jupyter already runs an event loop, which CrewAI refuses).
'''),
    code('''
import asyncio, hashlib, ipaddress, json, os, re, time, urllib.error, urllib.request, warnings
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings("ignore")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true"); os.environ.setdefault("OTEL_SDK_DISABLED", "true")
MODEL = "mistral/ministral-14b-latest"

try:
    from google.colab import userdata
except ImportError:
    userdata = None                                           # not on Colab: use the key already in the environment
if userdata is not None:
    os.environ["MISTRAL_API_KEY"] = userdata.get("MISTRAL_API_KEY").strip()      # asks you to grant access once
KEY = os.environ.get("MISTRAL_API_KEY", "").strip()
FINGERPRINT = hashlib.sha256(KEY.encode()).hexdigest()[:8]            # short hash to tell two keys apart; not the key
try:
    urllib.request.urlopen(urllib.request.Request("https://api.mistral.ai/v1/models",
                           headers={"Authorization": f"Bearer {KEY}"}), timeout=30)
    print(f"Mistral key accepted (length {len(KEY)}, fingerprint {FINGERPRINT})")
except urllib.error.HTTPError as e:
    raise SystemExit(f"Mistral rejected the key (HTTP {e.code}, length {len(KEY)}, fingerprint {FINGERPRINT}). Create a NEW key in the Mistral console and re-create the Colab secret MISTRAL_API_KEY.")

import litellm
_complete, _last = getattr(litellm.completion, "_orig", litellm.completion), [0.0]      # safe to re-run this cell
def _strip(o):                                                # drop fields the Mistral API rejects
    if isinstance(o, dict): return {k: _strip(v) for k, v in o.items() if k not in ("cache_breakpoint", "cache_control")}
    return [_strip(x) for x in o] if isinstance(o, list) else o
def throttled_completion(*a, **kw):
    if "messages" in kw: kw["messages"] = _strip(kw["messages"])
    for attempt in range(6):
        time.sleep(max(0.0, 2.1 - (time.time() - _last[0]))); _last[0] = time.time()
        try: return _complete(*a, **kw)
        except Exception as e:
            if getattr(e, "status_code", None) in (408, 429, 500, 502, 503, 504) and attempt < 5: time.sleep(2 ** (attempt + 1)); continue
            raise
throttled_completion._orig = _complete
litellm.completion = throttled_completion

from crewai import Agent, Task, Crew, Process, LLM
from crewai.tools import tool
llm = LLM(model=MODEL, temperature=0.0, max_tokens=4000, max_retries=0)

def run_agent(role, goal, prompt, tools=(), max_iter=6):
    """Run one CrewAI agent on one task and return its final text."""
    agent = Agent(role=role, goal=goal, backstory=goal, tools=list(tools), llm=llm, max_iter=max_iter,
                  allow_delegation=False, verbose=False)
    crew = Crew(agents=[agent], tasks=[Task(description=prompt, expected_output="Exactly the requested format.", agent=agent)],
                process=Process.sequential, verbose=False)
    try: asyncio.get_running_loop()
    except RuntimeError: out = crew.kickoff()
    else:
        with ThreadPoolExecutor(1) as pool: out = pool.submit(crew.kickoff).result()
    return str(getattr(out, "raw", out))

def as_json(text):
    i, j = text.find("{"), text.rfind("}")
    try: return json.loads(text[i:j + 1]) if i >= 0 and j > i else None
    except json.JSONDecodeError: return None

def fill(template, **kw):
    for k, v in kw.items(): template = template.replace(f"<<{k}>>", str(v))
    return template
'''),
    md('''
## 3. Real data
* **Traffic:** CIC-IDS2017 labelled network flows (University of New Brunswick, 2.83 million flows). The labels are
  kept in a separate variable and are used only by the grader in section 8.
* **Knowledge:** the official MITRE ATT&CK Enterprise bundle (techniques, sub-techniques, mitigations).

Downloads about 425 MB the first time. Timestamps in this dataset are day-first, in mixed formats, on a 12-hour clock
without AM/PM, so they are repaired when loading.
'''),
    code('''
DATA = Path("data"); DATA.mkdir(exist_ok=True)
SOURCES = {"traffic": ("https://huggingface.co/datasets/rdpahalavan/CIC-IDS2017/resolve/main/Network-Flows/CICIDS_Flow.parquet", DATA / "cic.parquet"),
           "ATT&CK": ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json", DATA / "attack.json")}
opener = urllib.request.build_opener(); opener.addheaders = [("User-Agent", "huntcrew-notebook/1.0")]; urllib.request.install_opener(opener)
for name, (url, dest) in SOURCES.items():
    if not dest.exists(): print("downloading", name, "..."); urllib.request.urlretrieve(url, dest)
    print(f"{name}: {dest.stat().st_size / 1e6:.0f} MB")

COLS = {"source_ip": "src", "destination_ip": "dst", "destination_port": "dport", "Timestamp": "ts_raw",
        "Total Fwd Packets": "fwd_pkts", "Total Backward Packets": "bwd_pkts", "Total Length of Fwd Packets": "fwd_B",
        "Total Length of Bwd Packets": "bwd_B", "attack_label": "label"}
flows = pd.read_parquet(DATA / "cic.parquet", columns=list(COLS)).rename(columns=COLS)
ts = pd.to_datetime(flows.pop("ts_raw"), dayfirst=True, format="mixed")
flows["ts"] = ts.where(ts.dt.hour >= 8, ts + pd.Timedelta(hours=12))        # 12-hour clock without AM/PM
flows = flows.sort_values("ts").reset_index(drop=True)
print(f"{len(flows):,} flows, {flows.ts.min():%Y-%m-%d %H:%M} to {flows.ts.max():%Y-%m-%d %H:%M}")

def cut(a, b): return flows[(flows.ts >= a) & (flows.ts < b)].reset_index(drop=True)
base = cut("2017-07-03 10:00", "2017-07-03 11:00").drop(columns="label")      # Monday: benign-only, "what normal looks like"
live = cut("2017-07-04 13:00", "2017-07-04 14:20")                          # Tuesday afternoon: the demo traffic
labels = live.pop("label")                                                  # answer key: only the grader (section 8) uses it
del flows
STEP = pd.Timedelta(minutes=5)
WINDOWS = [pd.Timestamp("2017-07-04 14:00") + i * STEP for i in range(4)]     # four 5-minute windows to replay
print(f"replaying {len(WINDOWS)} windows from {WINDOWS[0]:%H:%M} to {WINDOWS[-1] + STEP:%H:%M}; labels hidden from the agents")
'''),
    md('''
## 4. Retrieval-augmented knowledge base (RAG)
One chunk per ATT&CK technique or sub-technique (name, tactics, description, official mitigations), embedded with a local
sentence-transformer and stored in ChromaDB. **Every search is recorded**, so a guardrail can later check that a technique
an agent cites was really retrieved and not invented.
'''),
    code('''
def clean(t):
    t = re.sub(r"\\(Citation:[^)]*\\)", "", t or ""); t = re.sub(r"</?code>", " ", t)
    return re.sub(r"\\s+", " ", re.sub(r"\\[([^\\]]+)\\]\\([^)]+\\)", r"\\1", t)).strip()

objs = json.load(open(DATA / "attack.json"))["objects"]; by_id = {o["id"]: o for o in objs}
alive = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
attack_id = lambda o: next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
mit, parent = {}, {}
for r in objs:
    if r["type"] != "relationship" or r.get("revoked"): continue
    s, t = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
    if s and t and r["relationship_type"] == "mitigates" and s["type"] == "course-of-action" and alive(s):
        mit.setdefault(t["id"], set()).add((attack_id(s), s["name"]))
    elif s and t and r["relationship_type"] == "subtechnique-of":
        parent[s["id"]] = attack_id(t)
KB = {attack_id(o): dict(name=o["name"], tactics=[p["phase_name"] for p in o.get("kill_chain_phases", [])], desc=clean(o.get("description")),
                         mitigations=sorted(mit.get(o["id"], []), key=str), parent=parent.get(o["id"]))
      for o in objs if o["type"] == "attack-pattern" and alive(o) and attack_id(o)}
def mitigations_for(tid):                                            # sub-techniques inherit their parent's mitigations
    k = KB[tid]; return k["mitigations"] or (KB[k["parent"]]["mitigations"] if k["parent"] in KB else [])
print(f"{len(KB)} techniques and sub-techniques, {sum(1 for t in KB if mitigations_for(t))} with official mitigations")

from sentence_transformers import SentenceTransformer
import chromadb
embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
ids = sorted(KB)
docs = [f"{KB[i]['name']} ({i}). Tactics: {', '.join(KB[i]['tactics'])}. {KB[i]['desc'][:900]} Mitigations: {', '.join(n for _, n in mitigations_for(i))}" for i in ids]
client = chromadb.EphemeralClient()
try: client.delete_collection("attack")
except Exception: pass
store = client.create_collection("attack", metadata={"hnsw:space": "cosine"})
store.add(ids=ids, documents=docs, embeddings=embedder.encode(docs, batch_size=32, normalize_embeddings=True, show_progress_bar=False).tolist())

TRACE = []                                                           # every search, for the grounding guardrail
def search(query, k=5):
    res = store.query(query_embeddings=embedder.encode([query], normalize_embeddings=True, show_progress_bar=False).tolist(), n_results=k)
    hits = [(i, round(1 - d, 2)) for i, d in zip(res["ids"][0], res["distances"][0])]
    TRACE.append({"query": query, "hits": hits}); return hits

print("\\nretrieval check:")
for q in ["many failed password attempts against a remote login service", "one host connecting to many ports to find open services"]:
    print(" ", q, "->", [f"{i} {KB[i]['name']}" for i, _ in search(q, 3)])
'''),
    md('''
## 5. Statistics and a cheap first pass
Code (no AI) turns each window into per-source statistics and applies three classic rules to **propose** candidates:
password guessing, port scanning, and regular beaconing to rarely seen destinations. Rules are fast but produce many false
alarms; the **Detector agent** then verifies each candidate. Replay safety: the agents' view contains only traffic up to
the end of the current window and no labels.
'''),
    code('''
NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
@lru_cache(maxsize=None)
def is_private(ip): return any(ipaddress.ip_address(ip) in n for n in NETS)

class View:
    """What agents may see at replay time: the current window plus a look-back, never the future, never labels."""
    def __init__(self, start): self.start, self.end = start, start + STEP; self.seen = live[live.ts < self.end]
    @property
    def now(self): return self.seen[self.seen.ts >= self.start]
    @property
    def past(self): return self.seen[(self.seen.ts < self.start) & (self.seen.ts >= self.start - 12 * STEP)]

def src_stats(df):
    g, top = df.groupby("src"), df.groupby(["src", "dport"]).size().groupby(level=0).max()
    return pd.DataFrame({"flows": g.size(), "dst_ips": g.dst.nunique(), "dst_ports": g.dport.nunique(),
                         "top_port_share": (top / g.size()).round(2), "unanswered": df.bwd_pkts.eq(0).groupby(df.src).mean().round(2),
                         "fwd_B": g.fwd_B.sum(), "bwd_B": g.bwd_B.sum()}).sort_index()

KNOWN_DST = set(base.dst)
BASE_MEDIAN = base.groupby(["src", base.ts.dt.floor("5min")]).size().groupby(level=0).median()      # normal flows per 5 min

def propose(df):
    """Classic rules: which sources deserve an agent's attention? Returns {source: reason}."""
    out = {}
    svc = df[df.dport.isin([21, 22])].groupby(["src", "dport"]).size()
    for (s, p), n in svc[svc >= 50].items(): out.setdefault(s, f"{n} flows to port {p}")
    pairs = df.groupby(["src", "dst"]).dport.nunique()
    for (s, d), n in pairs[pairs >= 100].items(): out.setdefault(s, f"{n} distinct ports on {d}")
    ext = df[~df.dst.map(is_private) & ~df.dst.isin(KNOWN_DST)]
    if len(ext):
        m = ext.assign(m=ext.ts.dt.floor("min")).groupby(["src", "dst", "dport", "m"]).size().reset_index(name="n")
        for (s, d, p), g in m.groupby(["src", "dst", "dport"]):
            if len(g) >= 3 and g.n.sum() >= 10 and g.n.std(ddof=0) / g.n.mean() <= 0.3: out.setdefault(s, f"regular flows to {d}:{p}")
    return out

for w in WINDOWS:
    v = View(w); c = propose(v.now)
    print(f"{w:%H:%M}-{(w + STEP):%H:%M}  {len(v.now):5d} flows, {v.now.src.nunique():3d} sources  ->  rule candidates: {c if c else 'none'}")
'''),
    md('''
## 6. The agents
### Agent 1: Detector (verifies the rule candidates)
It has two tools: `source_profile` (this window, the previous hour, top destinations and the source's normal baseline) and
`search_attack_kb` (RAG). Tool calls are printed so you can watch it work. Its verdicts pass an **evidence check**: the
entity must really appear in the window, and the numbers attached to a finding are computed by code, never taken from the
model.
'''),
    code('''
CTX = {}
def show(name, arg, result): print(f"      [tool] {name}({arg!r}) -> {result.splitlines()[0][:95]}")

@tool("source_profile")
def source_profile(ip: str) -> str:
    """Statistics for one source address: this window, the previous hour, its top destinations and its normal baseline."""
    v = CTX["view"]; now = v.now[v.now.src == ip]
    if now.empty: r = f"{ip}: no flows as a source in this window"
    else:
        s = src_stats(now).iloc[0]; dest = now.groupby(["dst", "dport"]).size().sort_values(ascending=False).head(3)
        med = BASE_MEDIAN.get(ip)
        r = (f"{ip}: flows={s.flows:g} dst_ips={s.dst_ips:g} dst_ports={s.dst_ports:g} top_port_share={s.top_port_share:g} unanswered_share={s.unanswered:g} "
             f"fwd_bytes={s.fwd_B:g} bwd_bytes={s.bwd_B:g}\\nprevious hour: {len(v.past[v.past.src == ip])} flows\\n"
             f"top destinations: " + "; ".join(f"{d}:{p} x{n}" for (d, p), n in dest.items()) + "\\n"
             + (f"normal baseline: median {med:g} flows per 5 minutes" if med is not None else "normal baseline: never seen in normal traffic"))
    show("source_profile", ip, r); return r

@tool("search_attack_kb")
def search_attack_kb(query: str) -> str:
    """Search the MITRE ATT&CK knowledge base by meaning, e.g. 'many failed logins to one service'. Returns technique IDs you may cite."""
    hits = search(query, 4)
    r = "\\n".join(f"{i} {KB[i]['name']} [{', '.join(KB[i]['tactics'])}] score={sc}: {KB[i]['desc'][:140]}" for i, sc in hits)
    show("search_attack_kb", query, r); return r

DETECT = """A rule engine flagged these sources in one 5-minute window (<<label>>). Decide which are REAL attacks or compromised hosts
and which are false alarms.

CANDIDATES
<<rows>>

Method: call source_profile for each candidate and compare it with its normal baseline and recent history. Describe what it is
doing in plain words and call search_attack_kb with that description; confirm a candidate only if a retrieved ATT&CK technique
genuinely matches. High volume alone is not an attack, and a destination never seen before is common for ordinary browsing.
You MUST give a verdict for EVERY candidate. Answer with ONLY this JSON:
{"verdicts": [{"entity": "<ip>", "attack": true, "behaviour": "<=20 words"}]}"""

def detect(view, candidates):
    CTX["view"] = view; stats = src_stats(view.now)
    rows = "\\n".join(f"- {ip}: rule fired: {why} | " + ", ".join(f"{k}={v:g}" for k, v in stats.loc[ip].items()) for ip, why in candidates.items())
    data = as_json(run_agent("Network threat detector", "Separate real attacks from false alarms using baselines and ATT&CK.",
                             fill(DETECT, label=f"{view.start:%H:%M}-{view.end:%H:%M}", rows=rows), [source_profile, search_attack_kb])) or {}
    findings = []
    for v in data.get("verdicts", []):
        ip = str(v.get("entity", "")).strip()
        if v.get("attack") is True and ip in candidates and ip in stats.index:            # evidence check: entity must be in this window
            findings.append({"window": view.start, "entity": ip, "behaviour": str(v.get("behaviour", ""))[:160], **stats.loc[ip].to_dict()})
        elif ip in candidates: print(f"      dismissed {ip}: {str(v.get('behaviour', ''))[:90]}")
    return findings

findings = []
for w in WINDOWS:
    v = View(w); c = propose(v.now)
    print(f"\\nwindow {w:%H:%M}-{(w + STEP):%H:%M}: {len(c)} candidate(s)")
    if c: findings += detect(v, c)
    for f in [f for f in findings if f["window"] == w]: print(f"   CONFIRMED {f['entity']}: {f['behaviour']}")
print(f"\\n{len(findings)} confirmed finding(s)")
'''),
    md('''
### Agent 2: Threat-Intel (names the technique)
Findings of the same source in consecutive windows are merged into an **incident**. The agent forms competing hypotheses
across different ATT&CK tactics and searches for each. A second step then **scores every retrieved candidate against the
facts**, using the real ATT&CK descriptions, and code keeps only techniques that exist *and* were retrieved.
'''),
    code('''
def merge(findings):
    out = []
    for ent in sorted({f["entity"] for f in findings}):
        cur = []
        for f in sorted((f for f in findings if f["entity"] == ent), key=lambda f: f["window"]):
            if cur and f["window"] - cur[-1]["window"] > 2 * STEP: out.append(cur); cur = []
            cur.append(f)
        out.append(cur)
    return [dict(id=f"INC-{n + 1:03d}", entity=fs[0]["entity"], start=fs[0]["window"], end=fs[-1]["window"] + STEP, findings=fs) for n, fs in enumerate(out)]

def incident_facts(inc):
    d = live[(live.ts >= inc["start"]) & (live.ts < inc["end"]) & (live.src == inc["entity"])]
    mins = max(1.0, (inc["end"] - inc["start"]).total_seconds() / 60)
    top = ", ".join(f"{int(p)}:{c / len(d):.0%}" for p, c in d.dport.value_counts().head(3).items())
    return (f"Aggregate facts for {inc['entity']} ({inc['start']:%H:%M}-{inc['end']:%H:%M}): flows={len(d)}, flows_per_minute={len(d) / mins:.1f}, "
            f"distinct_dst_ips={d.dst.nunique()}, distinct_dst_ports={d.dport.nunique()}, top_dst_ports(share)={top}, "
            f"unanswered_flow_share={(d.bwd_pkts == 0).mean():.2f}, mean_fwd_bytes_per_flow={d.fwd_B.mean():.0f}, mean_bwd_bytes_per_flow={d.bwd_B.mean():.0f}")

INTEL = """Identify which MITRE ATT&CK technique this incident corresponds to.

<<facts>>
Behaviour notes from the detector: <<notes>>

Steps: (1) read the aggregate facts (answered or unanswered flows, size per flow, concentration on one port or destination, regularity);
(2) form at least THREE competing hypotheses spanning different ATT&CK tactics (e.g. credential access, discovery, command and control,
exfiltration, impact) and call search_attack_kb once per hypothesis; (3) choose the best-matching technique ID(s), at most 2, citing only IDs
returned by search_attack_kb. Answer with ONLY this JSON: {"techniques": [{"id": "T0000", "confidence": 0.0}]}"""

JUDGE = """Decide which MITRE ATT&CK technique best explains an incident, judging ONLY from the facts and the descriptions below.

<<facts>>

CANDIDATES
<<cands>>

Score each candidate 0-10 for how well its description explains ALL the facts. Network flows never show payloads or login results:
absence of such direct evidence is NOT a contradiction. Penalise only real conflicts (e.g. a data-theft technique when each flow carries
a few bytes). Answer with ONLY this JSON: {"scores": [{"id": "T0000", "score": 0}]}"""

def name_technique(inc):
    start = len(TRACE); facts = incident_facts(inc)
    notes = " | ".join(sorted({f["behaviour"] for f in inc["findings"]}))[:400]
    first = (as_json(run_agent("Threat intelligence analyst", "Map the incident to the right ATT&CK technique using retrieved evidence.",
                               fill(INTEL, facts=facts, notes=notes), [search_attack_kb])) or {}).get("techniques", [])
    retrieved = {i for t in TRACE[start:] for i, _ in t["hits"]}
    picks = [t["id"] for t in first if isinstance(t, dict) and t.get("id") in KB and t.get("id") in retrieved]
    cands = []                                                                       # top 2 of EVERY hypothesis search, then the agent's picks
    for t in TRACE[start:]:
        cands += [i for i, _ in t["hits"][:2] if i not in cands]
    cands = (cands + [p for p in picks if p not in cands])[:8]
    txt = "\\n".join(f"- {c}: {KB[c]['name']} [{', '.join(KB[c]['tactics'])}]: {KB[c]['desc'][:380]}" for c in cands)
    scores = (as_json(run_agent("ATT&CK technique judge", "Score candidate techniques against the facts.", fill(JUDGE, facts=facts, cands=txt), max_iter=2)) or {}).get("scores", [])
    ranked = sorted(((float(s.get("score", 0)), s["id"]) for s in scores if isinstance(s, dict) and s.get("id") in cands), key=lambda x: -x[0])
    final = [i for sc, i in ranked if sc >= 5][:2] or picks[:2]
    dropped = [t.get("id") for t in first if isinstance(t, dict) and t.get("id") not in retrieved]
    return final, dict(facts=facts, candidates=cands, scores=ranked[:4], dropped=dropped)

name_of = lambda t: KB[t]["name"] + " (" + t + ")"
incidents = merge(findings)
for inc in incidents:
    inc["techniques"], inc["intel"] = name_technique(inc)
    print(f"\\n{inc['id']} {inc['entity']} ({inc['start']:%H:%M}-{inc['end']:%H:%M}): {[name_of(t) for t in inc['techniques']]}")
    print("   facts:", inc["intel"]["facts"].split(': ', 1)[1])
    print("   judge scores:", inc["intel"]["scores"], "| ungrounded IDs dropped by the guardrail:", inc["intel"]["dropped"] or "none")
'''),
    md('''
### Agent 3: Strategist, with policy, approval gate and a simulated firewall
The Strategist proposes up to four actions and may cite only **official ATT&CK mitigations** for the named techniques.
Code then enforces the rules: unknown action types and actions without a target are rejected, an IP target must appear in the
incident's own traffic, protected assets (the DNS server and gateway) can never be blocked or isolated, low-risk actions run automatically, and **medium and high risk actions wait for you**. Nothing leaves
this notebook: the environment is a Python object.
'''),
    code('''
CATALOG = {"block_ip": "low", "rate_limit_ip": "low", "open_ticket": "low",          # no domain action: flows contain no domain names
           "enable_waf_rule": "medium", "force_password_reset": "medium", "disable_account": "medium", "isolate_host": "high"}
PROTECTED = {"192.168.10.3": "DNS / domain controller", "192.168.10.1": "gateway / secondary DNS"}     # derived from the DNS traffic
IP_ACTIONS = {"block_ip", "rate_limit_ip", "isolate_host"}
APPROVAL = "ask"            # "ask" = prompt you | "deny" / "approve" = unattended runs
ENV = {"blocked_ips": [], "rate_limited": [], "isolated_hosts": [], "tickets": [], "other": []}

PLAN = """Plan the response to this incident.

<<facts>>
Assessed techniques: <<techs>>
Allowed action types (type: risk): <<catalog>>
Official ATT&CK mitigations you may cite (id: name): <<mits>>

Rules: at most 4 actions; only the action types above; cite a mitigation_id only from the official list and only when the action implements it
(otherwise null); the target of block_ip / rate_limit_ip / isolate_host must be an IP address from the facts. Never target: <<protected>>.
Answer with ONLY this JSON:
{"severity": "low|medium|high|critical", "rationale": "<=30 words", "actions": [{"type": "block_ip", "target": "<ip>", "justification": "<=20 words", "mitigation_id": null}]}"""

def approve(a, reason):
    if APPROVAL in ("approve", "deny"): return APPROVAL == "approve"
    return input(f"   APPROVAL NEEDED: {a['type']} -> {a['target']} ({reason}). Approve? [y/N] ").strip().lower() in ("y", "yes")

def execute(a):
    kind = a["type"]
    if kind == "block_ip": ENV["blocked_ips"].append(a["target"])
    elif kind == "rate_limit_ip": ENV["rate_limited"].append(a["target"])
    elif kind == "isolate_host": ENV["isolated_hosts"].append(a["target"])
    elif kind == "open_ticket": ENV["tickets"].append(f"{a['target']}: {a['justification']}")
    else: ENV["other"].append(f"{kind} {a['target']}")

def respond(inc):
    mits = {m: n for t in inc["techniques"] for m, n in mitigations_for(t)}
    data = as_json(run_agent("Incident response strategist", "Propose a proportionate, policy-compliant response grounded in official ATT&CK mitigations.",
        fill(PLAN, facts=inc["intel"]["facts"], techs=", ".join(inc["techniques"]) or "none identified", catalog="; ".join(f"{k}: {v}" for k, v in CATALOG.items()),
             mits="; ".join(f"{k}: {v}" for k, v in mits.items()) or "none", protected=", ".join(PROTECTED)))) or {}
    seen = set(live[(live.ts >= inc["start"]) & (live.ts < inc["end"]) & (live.src == inc["entity"])].dst) | {inc["entity"]}   # IPs in this incident
    log = []
    for a in data.get("actions", [])[:6]:                                        # safety cap (the prompt asks for at most 4)
        if not isinstance(a, dict): continue
        a = {"type": str(a.get("type", "")), "target": str(a.get("target", "")).strip(), "justification": str(a.get("justification", ""))[:120],
             "mitigation_id": a.get("mitigation_id") if a.get("mitigation_id") in mits else None}              # grounding guardrail
        if a["type"] not in CATALOG: status, why = "REJECTED", "unknown action type"
        elif a["target"].lower() in ("", "none", "null", "n/a", "unknown"): status, why = "REJECTED", "no target given"
        elif a["type"] in IP_ACTIONS and not re.fullmatch(r"\\d+\\.\\d+\\.\\d+\\.\\d+", a["target"]): status, why = "REJECTED", "target is not an IP address"
        elif a["type"] in IP_ACTIONS and a["target"] in PROTECTED: status, why = "REJECTED", f"{a['target']} is a protected asset ({PROTECTED[a['target']]})"
        elif a["type"] in IP_ACTIONS and a["target"] not in seen: status, why = "REJECTED", "IP address not seen in this incident's traffic"
        elif CATALOG[a["type"]] == "low": execute(a); status, why = "EXECUTED", "low risk, automatic"
        elif approve(a, f"{CATALOG[a['type']]} risk"): execute(a); status, why = "EXECUTED", "approved by a human"
        else: status, why = "DENIED", "approval denied"
        log.append({**a, "status": status, "why": why})
    return {"severity": str(data.get("severity", "medium")).lower(), "rationale": str(data.get("rationale", "")), "log": log}

for inc in incidents:
    inc["plan"] = respond(inc)
    print(f"\\n{inc['id']} {inc['entity']}: severity {inc['plan']['severity']} - {inc['plan']['rationale']}")
    for a in inc["plan"]["log"]: print(f"   {a['status']:9s} {a['type']} {a['target']}  [{a['why']}]  mitigation={a['mitigation_id']}")
print("\\nsimulated environment:", {k: v for k, v in ENV.items() if v})
'''),
    md("### Agent 4: Reporter"),
    code('''
REPORT = """Write a concise incident report in Markdown for a security manager. Sections: Summary, Evidence, ATT&CK mapping, Actions taken
(executed / denied / rejected), Recommendations. Do not invent facts beyond what is given.

<<facts>>
Detector notes: <<notes>>
Techniques: <<techs>>
Severity: <<sev>>. Response log: <<log>>"""

from IPython.display import Markdown, display
for inc in incidents:
    if len(inc["findings"]) < 2 and len(incidents) > 1: continue                 # report the substantial incident(s) first
    text = run_agent("Incident report writer", "Write a clear, factual incident report.",
        fill(REPORT, facts=inc["intel"]["facts"], notes=" | ".join(sorted({f["behaviour"] for f in inc["findings"]}))[:400],
             techs=", ".join(f"{t} ({KB[t]['name']})" for t in inc["techniques"]), sev=inc["plan"]["severity"],
             log="; ".join(f"{a['type']} {a['target']} -> {a['status']}" for a in inc["plan"]["log"]) or "none"))
    display(Markdown(f"### Incident report {inc['id']}\\n\\n" + text))
'''),
    md('''
## 7. Grading by code against the dataset's own labels
Now the answer key (hidden until now) is used, by plain code only. A source in a window is *attack-positive* when it has at least 5
attack-labelled flows in that window. The mapping from dataset label to ATT&CK technique has four entries
(SSH-Patator and FTP-Patator -> T1110, Bot -> T1071, PortScan -> T1046).
'''),
    code('''
TECH = {"SSH-Patator": "T1110", "FTP-Patator": "T1110", "Bot": "T1071", "PortScan": "T1046"}
win = ((live.ts - WINDOWS[0]) // STEP).astype(int)
att = pd.DataFrame({"win": win, "src": live.src, "tech": labels.map(TECH)}).dropna()
cnt = att[(att.win >= 0) & (att.win < len(WINDOWS))].groupby(["win", "src", "tech"]).size()
truth = {(w, s): t for (w, s, t), n in cnt.items() if n >= 5}
pred = {(int((f["window"] - WINDOWS[0]) // STEP), f["entity"]) for f in findings}
tp, fp, fn = pred & set(truth), pred - set(truth), set(truth) - pred
P = len(tp) / max(1, len(tp) + len(fp)); R = len(tp) / max(1, len(tp) + len(fn))
print(f"(window, source) pairs: truth={len(truth)}  predicted={len(pred)}  correct={len(tp)}  false alarms={len(fp)}  missed={len(fn)}")
print(f"precision={P:.2f}  recall={R:.2f}   (rule candidates alone would have flagged {sum(len(propose(View(w).now)) for w in WINDOWS)} pairs)")
for inc in incidents:
    want = {truth[k] for k in truth if k[1] == inc["entity"]}
    got = {t.split(".")[0] for t in inc["techniques"]}
    print(f"{inc['id']} {inc['entity']}: named {inc['techniques']}  |  dataset label says {sorted(want) or 'no attack (false alarm)'}  ->  "
          + ("technique CORRECT" if want and got & want else "technique WRONG" if want else "false-alarm incident"))
'''),
    md(f'''
## 8. Results of the full evaluation, and honest limits
The demo above is four windows. The full project ran the same pipeline, plus three baselines, **once** on three untouched test slices
(SSH-Patator, Bot, PortScan; 60 windows; 95 attack-positive (window, source) pairs) with the code frozen beforehand. All numbers are
graded by code (`ministral-14b-latest`):

| System | Recall | Precision | False positives |
|---|---|---|---|
| Classic rules only | 0.29 | 0.27 | 76 |
| Single prompt, no tools or retrieval | 0.03 | 0.01 | 401 |
| Agent-led detection (no rules) | 0.36 | 0.11 | 273 |
| **Hybrid: rules propose, agents verify (this notebook)** | 0.29 | **0.41** | **40** |

* Agents with baselines and retrieval **roughly halve the rules' false positives without losing a detection**.
* Every cited technique was grounded (1.00) and every proposed action stayed inside policy (1.00).
* **Limits:** naming the technique is the weak step (1 of 9 attack-linked incidents correct in the full run), because flows carry no
  payloads or login results; slow, low-volume beaconing is mostly missed; samples are small and results are for one model.

Full code, tests, protocol and decision records: {REPO_URL}
'''),
]


def build(out: str | Path = ROOT / "notebooks" / "huntcrew_colab.ipynb") -> Path:
    nb = {"cells": CELLS, "nbformat": 4, "nbformat_minor": 5,
          "metadata": {"colab": {"provenance": []}, "kernelspec": {"name": "python3", "display_name": "Python 3"},
                       "language_info": {"name": "python"}}}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    return out


if __name__ == "__main__":
    p = build()
    n_code = sum(1 for c in CELLS if c["cell_type"] == "code")
    print("wrote", p, f"({p.stat().st_size / 1024:.0f} KB, {len(CELLS)} cells, {n_code} code cells)")
