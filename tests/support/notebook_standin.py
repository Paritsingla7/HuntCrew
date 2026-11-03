"""Run every code cell of the notebook with a stand-in model (no network for the LLM). Usage: script <repo_root> <workdir>"""
import builtins
import json
import os
import re
import sys
import types
import urllib.request

repo, work = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(work, "data"), exist_ok=True); os.chdir(work)
for name, src in (("cic.parquet", "data/external/cic-ids2017/CICIDS_Flow.parquet"), ("attack.json", "data/external/attack-stix/enterprise-attack.json")):
    dst = os.path.join("data", name)
    if not os.path.exists(dst): os.symlink(os.path.join(repo, src), dst)
os.environ["MISTRAL_API_KEY"] = "offline-test-key"
try:
    import IPython.display  # noqa
except ImportError:
    m = types.ModuleType("IPython"); d = types.ModuleType("IPython.display")
    d.Markdown = lambda t: t; d.display = lambda x: print("[display]", str(x)[:300]); m.display = d
    sys.modules["IPython"], sys.modules["IPython.display"] = m, d

_real_urlopen = urllib.request.urlopen
class _Ok:                                  # the key preflight must not hit the network in this offline run
    def read(self, *a): return b"{}"
def fake_urlopen(req, *a, **k):
    url = getattr(req, "full_url", req)
    return _Ok() if "api.mistral.ai" in str(url) else _real_urlopen(req, *a, **k)
urllib.request.urlopen = fake_urlopen
builtins.input = lambda prompt="": (print(prompt + "n  <- stand-in human answers 'n'"), "n")[1]

import litellm


def resp(content=None, tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls: msg["tool_calls"] = tool_calls
    return litellm.ModelResponse(**{"id": "fake", "object": "chat.completion", "model": "fake",
        "choices": [{"index": 0, "finish_reason": "tool_calls" if tool_calls else "stop", "message": msg}],
        "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}})
def call(name, **args): return {"id": f"c{abs(hash(name + json.dumps(args))) % 10**6}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
N = {"calls": 0}
def fake_completion(*a, **kw):
    N["calls"] += 1
    msgs = kw["messages"]; text = "\n".join(str(m.get("content")) for m in msgs)
    assert "cache_breakpoint" not in json.dumps(msgs), "unsupported field reached the provider"
    got_tool = any(m.get("role") == "tool" for m in msgs)
    if "A rule engine flagged these sources" in text:
        ips = re.findall(r"^- (\d+\.\d+\.\d+\.\d+): rule fired", text, re.M)
        if not got_tool: return resp(tool_calls=[call("source_profile", ip=ips[0]), call("search_attack_kb", query="many connections to one service port from one source")])
        return resp(json.dumps({"verdicts": [{"entity": ip, "attack": ip.startswith("172.16."), "behaviour": "stand-in verdict"} for ip in ips]}))
    if "Identify which MITRE ATT&CK technique" in text:
        if not got_tool: return resp(tool_calls=[call("search_attack_kb", query=q) for q in ("brute force password guessing against a service", "network service discovery scanning", "denial of service flood")])
        return resp(json.dumps({"techniques": [{"id": "T1110", "confidence": 0.8}, {"id": "T9999", "confidence": 0.9}]}))
    if "Decide which MITRE ATT&CK technique best explains" in text:
        cands = re.findall(r"^- (T\d+(?:\.\d+)?):", text, re.M)
        return resp(json.dumps({"scores": [{"id": c, "score": 9 if c == "T1110" else 3} for c in cands]}))
    if "Plan the response to this incident" in text:
        return resp(json.dumps({"severity": "high", "rationale": "stand-in plan", "actions": [
            {"type": "block_ip", "target": "172.16.0.1", "justification": "block attacker", "mitigation_id": "M1032"},
            {"type": "isolate_host", "target": "192.168.10.3", "justification": "protected DNS", "mitigation_id": None},
            {"type": "force_password_reset", "target": "alice", "justification": "reset", "mitigation_id": "M9999"},
            {"type": "launch_missiles", "target": "x", "justification": "bad", "mitigation_id": None}]}))
    if "Write a concise incident report" in text: return resp("## Summary\nStand-in report for the offline test.")
    raise AssertionError("unrecognised prompt: " + text[:200])
litellm.completion = fake_completion

nb = json.load(open(os.path.join(repo, "notebooks/huntcrew_colab.ipynb")))
ns = {"__name__": "__main__"}
for i, c in enumerate(nb["cells"], 1):
    if c["cell_type"] != "code": continue
    print(f"\n===== cell {i} =====", flush=True)
    exec(compile("".join(c["source"]), f"<cell {i}>", "exec"), ns)
print(f"\n[offline test finished; stand-in model calls: {N['calls']}]")
