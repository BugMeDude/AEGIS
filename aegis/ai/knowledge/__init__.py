"""RAG knowledge base for attack techniques, CVEs, and payloads.

Retrieval over a red-team corpus (WAF bypasses, payload variants, JWT /
smuggling / GraphQL / XXE / race-condition techniques). Uses ChromaDB
semantic search when installed, and **always** falls back to an in-memory
keyword search so the feature works offline (chromadb optional). The corpus
is auto-seeded on construction so it is useful out of the box.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_DEFAULT_CORPUS: list[dict[str, Any]] = [
    {"id": "waf-cloudflare-1", "text": "Cloudflare WAF bypass via HTTP/2 connection coalescing and chunked transfer encoding with randomized chunk sizes.",
     "metadata": {"type": "waf_bypass", "waf": "cloudflare"}},
    {"id": "waf-modsec-1", "text": "ModSecurity bypass via Content-Type manipulation (urlencoded vs multipart boundary confusion).",
     "metadata": {"type": "waf_bypass", "waf": "modsecurity"}},
    {"id": "sqli-mysql-1", "text": "MySQL blind SQLi via conditional errors and time-based BENCHMARK/SLEEP probing.",
     "metadata": {"type": "payload", "class": "sqli"}},
    {"id": "xss-dom-1", "text": "DOM-based XSS via URL fragment and CSP bypass through JSONP endpoints, open redirects and upload polyglots.",
     "metadata": {"type": "payload", "class": "xss"}},
    {"id": "ssrf-1", "text": "SSRF detection via cloud metadata endpoints (169.254.169.254, metadata.google.internal) and blind out-of-band DNS.",
     "metadata": {"type": "payload", "class": "ssrf"}},
    {"id": "jwt-none-1", "text": "JWT algorithm confusion RS256 to HS256, none algorithm, and kid injection (SQLi / path traversal).",
     "metadata": {"type": "technique", "class": "jwt"}},
    {"id": "smuggling-1", "text": "HTTP request smuggling CL.TE / TE.CL / TE.TE variants detected via differential proxy vs backend responses.",
     "metadata": {"type": "technique", "class": "smuggling"}},
    {"id": "graphql-1", "text": "GraphQL introspection query, field suggestion abuse, deep-nesting DoS and alias argument injection.",
     "metadata": {"type": "technique", "class": "graphql"}},
    {"id": "xxe-1", "text": "XXE via SVG / XML upload with SYSTEM file entities and blind out-of-band DTD retrieval.",
     "metadata": {"type": "payload", "class": "xxe"}},
    {"id": "race-1", "text": "Race condition via concurrent request bursts against single-use operations like coupons and referrals.",
     "metadata": {"type": "technique", "class": "race_condition"}},
]

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> set[str]:
    return set(_WORD.findall(s.lower()))


class KnowledgeBase:
    """Knowledge base with optional ChromaDB vector search + keyword fallback.

    ``available`` is True whenever there is a corpus to query — i.e. always,
    because the in-memory fallback is auto-seeded. ChromaDB merely upgrades
    search quality when installed.
    """

    def __init__(self, collection_name: str = "aegis_knowledge",
                 persist_dir: str = "", auto_seed: bool = True) -> None:
        self.collection_name = collection_name
        self.persist_dir = persist_dir or str(Path.home() / ".aegis" / "knowledge")
        self._collection = None
        self._chroma = None
        self._docs: list[dict[str, Any]] = []
        self._init_db()
        if auto_seed:
            self.seed_default_knowledge()

    def _init_db(self) -> None:
        try:
            import chromadb
            self._chroma = chromadb.PersistentClient(path=self.persist_dir)
            try:
                self._collection = self._chroma.get_collection(self.collection_name)
            except Exception:
                self._collection = self._chroma.create_collection(self.collection_name)
        except Exception:
            self._chroma = None
            self._collection = None

    @property
    def vector_backed(self) -> bool:
        return self._collection is not None

    @property
    def available(self) -> bool:
        return self._collection is not None or bool(self._docs)

    def add_documents(self, documents: list[dict[str, Any]]) -> None:
        if not documents:
            return
        seen = {d["id"] for d in self._docs}
        for d in documents:
            did = d.get("id") or str(hash(d.get("text", "")))
            if did not in seen:
                self._docs.append({"id": did, "text": d.get("text", ""),
                                   "metadata": d.get("metadata", {})})
                seen.add(did)
        if self._collection is not None:
            try:
                self._collection.add(
                    documents=[d.get("text", "") for d in documents],
                    ids=[d.get("id", str(hash(d.get("text", ""))))
                         for d in documents],
                    metadatas=[d.get("metadata", {}) for d in documents])
            except Exception:
                pass

    def search(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search (ChromaDB) with a keyword-overlap fallback."""
        if self._collection is not None:
            try:
                res = self._collection.query(query_texts=[query],
                                             n_results=n_results)
                out = []
                if res.get("documents"):
                    for i, doc in enumerate(res["documents"][0]):
                        meta = (res["metadatas"][0][i]
                                if res.get("metadatas") else {})
                        out.append({"text": doc, "metadata": meta})
                if out:
                    return out
            except Exception:
                pass
        q = _tokens(query)
        if not q or not self._docs:
            return []
        scored = []
        for d in self._docs:
            overlap = len(q & _tokens(
                d["text"] + " " + " ".join(map(str, d["metadata"].values()))))
            if overlap:
                scored.append((overlap, d))
        scored.sort(key=lambda x: -x[0])
        return [{"text": d["text"], "metadata": d["metadata"]}
                for _, d in scored[:n_results]]

    retrieve = search  # back-compat alias

    def seed_default_knowledge(self) -> None:
        self.add_documents(_DEFAULT_CORPUS)
