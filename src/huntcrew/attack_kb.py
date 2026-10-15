"""ATT&CK knowledge base: official STIX -> one chunk per (sub-)technique -> embeddings -> ChromaDB.

Design points (docs/DECISIONS.md ADR-003, ADR-021):
  * built from the official MITRE STIX bundle, nothing hand-written;
  * each chunk joins the technique with its official mitigations and detection analytics;
  * every search is recorded in `trace`, so guardrails can verify a cited ID was really retrieved.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_TAGS = re.compile(r"</?code>|<br\s*/?>")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def clean(text: str) -> str:
    text = _CITATION.sub("", text or "")
    text = _TAGS.sub(" ", text)
    text = _MD_LINK.sub(r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


@dataclass(frozen=True)
class Mitigation:
    id: str
    name: str
    how: str


@dataclass
class Chunk:
    id: str                       # ATT&CK ID, e.g. T1110 or T1110.001
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_id: str | None
    platforms: list[str]
    description: str
    detection: list[str]          # analytic descriptions
    mitigations: list[Mitigation]

    def text(self, max_description: int = 900) -> str:
        """Text that gets embedded. Most informative content first (embedding models truncate)."""
        parts = [f"{self.name} ({self.id}). Tactics: {', '.join(self.tactics)}.",
                 self.description[:max_description]]
        if self.detection:
            parts.append("Detection: " + " ".join(self.detection[:3]))
        if self.mitigations:
            parts.append("Mitigations: " + ", ".join(m.name for m in self.mitigations))
        return " ".join(parts)


@dataclass
class Hit:
    id: str
    name: str
    score: float                  # cosine similarity, higher is better
    tactics: list[str]
    snippet: str
    mitigations: list[Mitigation] = field(default_factory=list)


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def load_chunks(stix_path: str | Path) -> list[Chunk]:
    with open(stix_path, encoding="utf-8") as f:
        objs = json.load(f)["objects"]
    by_id = {o["id"]: o for o in objs}

    mitig: dict[str, list[Mitigation]] = {}
    detect: dict[str, list[str]] = {}
    parent_of: dict[str, str] = {}
    for r in objs:
        if r["type"] != "relationship" or r.get("revoked"):
            continue
        src, tgt = by_id.get(r["source_ref"]), by_id.get(r["target_ref"])
        if not src or not tgt:
            continue
        kind = r["relationship_type"]
        if kind == "mitigates" and src["type"] == "course-of-action" and _live(src):
            mitig.setdefault(tgt["id"], []).append(
                Mitigation(_attack_id(src) or "", src["name"], clean(r.get("description", ""))[:300]))
        elif kind == "detects" and src["type"] == "x-mitre-detection-strategy" and _live(src):
            for ref in src.get("x_mitre_analytic_refs", []):
                a = by_id.get(ref)
                if a and a.get("description"):
                    detect.setdefault(tgt["id"], []).append(clean(a["description"]))
        elif kind == "subtechnique-of":
            parent_of[src["id"]] = tgt["id"]

    chunks: list[Chunk] = []
    for o in objs:
        if o["type"] != "attack-pattern" or not _live(o):
            continue
        aid = _attack_id(o)
        if not aid:
            continue
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        parent = by_id.get(parent_of.get(o["id"], ""))
        own = {m.id: m for m in mitig.get(o["id"], [])}
        chunks.append(Chunk(
            id=aid, name=o["name"], tactics=tactics,
            is_subtechnique=bool(o.get("x_mitre_is_subtechnique")),
            parent_id=_attack_id(parent) if parent else None,
            platforms=o.get("x_mitre_platforms", []),
            description=clean(o.get("description", "")),
            detection=list(dict.fromkeys(detect.get(o["id"], []))),
            mitigations=sorted(own.values(), key=lambda m: m.id),
        ))
    chunks.sort(key=lambda c: c.id)
    return chunks


class AttackKB:
    def __init__(self, chunks: list[Chunk], embedding_model: str, persist_dir: str | Path | None = None):
        import chromadb
        from sentence_transformers import SentenceTransformer

        self.chunks = {c.id: c for c in chunks}
        self.model = SentenceTransformer(embedding_model)
        self.trace: list[dict] = []                  # one entry per search: query + returned IDs

        client = chromadb.PersistentClient(path=str(persist_dir)) if persist_dir else chromadb.EphemeralClient()
        name = "attack_" + re.sub(r"\W+", "_", embedding_model)[-40:]
        existing = {c.name for c in client.list_collections()}
        if name in existing:
            col = client.get_collection(name)
            if col.count() != len(chunks):
                client.delete_collection(name)
                existing.discard(name)
        if name not in existing:
            col = client.create_collection(name, metadata={"hnsw:space": "cosine"})
            texts = [c.text() for c in chunks]
            emb = self.model.encode(texts, batch_size=32, normalize_embeddings=True, show_progress_bar=False)
            col.add(ids=[c.id for c in chunks], embeddings=emb.tolist(),
                    documents=texts, metadatas=[{"name": c.name, "sub": c.is_subtechnique} for c in chunks])
        self.col = client.get_collection(name)

    def search(self, query: str, k: int = 5, include_subtechniques: bool = True) -> list[Hit]:
        q = self.model.encode([query], normalize_embeddings=True, show_progress_bar=False)
        where: dict[str, Any] | None = None if include_subtechniques else {"sub": False}
        res = self.col.query(query_embeddings=q.tolist(), n_results=k,
                             where=where)
        dists = (res["distances"] or [[]])[0]
        hits = []
        for cid, dist in zip(res["ids"][0], dists, strict=True):
            c = self.chunks[cid]
            hits.append(Hit(id=c.id, name=c.name, score=round(1.0 - float(dist), 4), tactics=c.tactics,
                            snippet=c.description[:400], mitigations=c.mitigations))
        self.trace.append({"query": query, "ids": [h.id for h in hits], "scores": [h.score for h in hits]})
        return hits

    def retrieved_ids(self) -> set[str]:
        return {i for t in self.trace for i in t["ids"]}

    def get(self, attack_id: str) -> Chunk | None:
        return self.chunks.get(attack_id)

    def mitigations_for(self, attack_id: str) -> list[Mitigation]:
        """Official mitigations for a technique; falls back to the parent technique for sub-techniques."""
        c = self.chunks.get(attack_id)
        if not c:
            return []
        if c.mitigations or not c.parent_id:
            return c.mitigations
        parent = self.chunks.get(c.parent_id)
        return parent.mitigations if parent else []
