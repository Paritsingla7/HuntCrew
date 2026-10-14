from pathlib import Path

import pytest

from huntcrew.attack_kb import AttackKB, clean, load_chunks

STIX = Path(__file__).resolve().parents[1] / "data" / "external" / "attack-stix" / "enterprise-attack.json"
needs_data = pytest.mark.skipif(not STIX.exists(), reason="run scripts/fetch_data.py first")

# Hand-written smoke-test queries: plain-language behaviour descriptions -> expected parent technique.
# This checks retrieval works; it is NOT an independent benchmark (documented in docs/03-architecture.md).
QUERIES = [
    ("many failed login attempts guessing passwords against a remote service", "T1110"),
    ("repeated authentication failures from one address against ssh or ftp", "T1110"),
    ("a host connects to many different ports on another host to find open services", "T1046"),
    ("scanning a network to enumerate listening services", "T1046"),
    ("malware checks in at regular intervals with a command and control server over web protocols", "T1071"),
    ("periodic beaconing over HTTP to an external server", "T1071"),
    ("large amount of data sent out to an external server over ftp", "T1048"),
    ("data exfiltration using an alternative protocol different from the c2 channel", "T1048"),
    ("encrypting files on systems to demand ransom", "T1486"),
    ("email with a malicious attachment sent to users", "T1566"),
    ("exploiting a vulnerability in an internet facing web application for initial access", "T1190"),
    ("flooding a target with traffic to make a service unavailable", "T1498"),
    ("using stolen legitimate credentials to log in", "T1078"),
    ("dumping credentials from operating system memory", "T1003"),
    ("moving laterally using remote desktop or ssh with valid accounts", "T1021"),
    ("running commands through a shell or scripting interpreter on a compromised host", "T1059"),
    ("deleting backups and shadow copies to prevent recovery", "T1490"),
    ("using a proxy to hide the origin of command and control traffic", "T1090"),
    ("compressing and encrypting data before sending it out", "T1560"),
    ("creating a scheduled task to maintain persistence", "T1053"),
]


def test_clean_removes_citation_markup():
    s = "Brute force (Citation: Foo 2020) is <code>bad</code> [see](https://x.y)."
    assert clean(s) == "Brute force is bad see."


@needs_data
def test_chunks_reflect_official_structure():
    chunks = {c.id: c for c in load_chunks(STIX)}
    assert len(chunks) > 600
    bf = chunks["T1110"]
    assert bf.name == "Brute Force" and not bf.is_subtechnique and "credential-access" in bf.tactics
    assert {"M1032", "M1027"} <= {m.id for m in bf.mitigations}
    sub = chunks["T1110.001"]
    assert sub.is_subtechnique and sub.parent_id == "T1110"
    assert "Citation" not in bf.description
    assert bf.detection, "detection analytics should be joined from detection strategies"


@pytest.fixture(scope="module")
def kb(tmp_path_factory):
    if not STIX.exists():
        pytest.skip("run scripts/fetch_data.py first")
    return AttackKB(load_chunks(STIX), "sentence-transformers/all-MiniLM-L6-v2",
                    persist_dir=tmp_path_factory.mktemp("chroma"))


def test_search_returns_scored_hits_and_records_trace(kb):
    kb.trace.clear()
    hits = kb.search("many failed password attempts from one source", k=5)
    assert len(hits) == 5 and all(0 <= h.score <= 1.0 for h in hits)
    assert hits[0].score >= hits[-1].score
    assert kb.trace[-1]["ids"] == [h.id for h in hits]
    assert {h.id for h in hits} <= kb.retrieved_ids()


def test_mitigations_fall_back_to_parent(kb):
    sub = kb.get("T1110.001")
    assert kb.mitigations_for("T1110.001") == (sub.mitigations or kb.get("T1110").mitigations)
    assert kb.mitigations_for("TXXXX") == []


def test_retrieval_hit_rates(kb):
    def rank(query, expected):
        ids = [h.id.split(".")[0] for h in kb.search(query, k=5)]
        return ids.index(expected) + 1 if expected in ids else None
    ranks = [rank(q, e) for q, e in QUERIES]
    n = len(QUERIES)
    hit1 = sum(r == 1 for r in ranks) / n
    hit3 = sum(r is not None and r <= 3 for r in ranks) / n
    hit5 = sum(r is not None for r in ranks) / n
    print(f"\nretrieval hit@1={hit1:.2f} hit@3={hit3:.2f} hit@5={hit5:.2f}")
    misses = [(q, e) for (q, e), r in zip(QUERIES, ranks, strict=False) if r is None]
    assert hit5 >= 0.85, f"hit@5={hit5:.2f}; misses: {misses}"
