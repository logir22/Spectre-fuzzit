"""Memory node: pgvector false-positive cache.

Before an expensive LLM triage call, this node queries a pgvector-backed
cache of previously-adjudicated findings. If a semantically similar finding
was already marked a false positive, we short-circuit and skip the LLM.

Design principles:
  * Fail-open: if PostgreSQL/Ollama are unreachable or misconfigured, the
    node logs a warning and returns no matches, letting the workflow proceed
    (the LLM simply re-triages the finding).
  * Lazy imports: langchain-postgres / sqlalchemy / langchain-ollama are only
    imported when the store is actually built, so the module can be imported
    even when those dependencies are absent.
  * Cosine distance is used as the similarity metric (0 == identical).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from .state import AnalysisStage, MemoryMatch, SemgrepFinding, SpectreState, Verdict

logger = logging.getLogger(__name__)

# --- Configuration (environment-overridable for Docker) ---------------------

PGVECTOR_CONNECTION = os.environ.get(
    "PGVECTOR_CONNECTION", os.environ.get("DATABASE_URL", "")
)
PGVECTOR_COLLECTION = os.environ.get("PGVECTOR_COLLECTION", "spectre_false_positives")

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")

# Cosine distance below which a cached hit is considered a match.
DISTANCE_THRESHOLD = float(os.environ.get("MEMORY_DISTANCE_THRESHOLD", "0.35"))
MAX_K = int(os.environ.get("MEMORY_K", "3"))

# --- Singleton cache ---------------------------------------------------------

_store: Optional["MemoryStore"] = None
_store_initialized = False


def build_finding_text(finding: SemgrepFinding) -> str:
    """Produce the text block that gets embedded for a finding."""
    parts = [
        f"rule: {finding.rule_id}",
        f"severity: {finding.severity.value}",
        f"file: {finding.path}:{finding.start_line}",
        f"message: {finding.message}",
    ]
    if finding.source:
        parts.append(f"source: {finding.source}")
    if finding.sink:
        parts.append(f"sink: {finding.sink}")
    if finding.code_snippet:
        parts.append(f"code: {finding.code_snippet}")
    return "\n".join(parts)


def _ensure_extension(connection: str) -> None:
    """Create the ``vector`` extension if it does not already exist."""
    from sqlalchemy import create_engine, text

    engine = create_engine(connection)
    try:
        with engine.connect() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            conn.commit()
    finally:
        engine.dispose()


class MemoryStore:
    """Thin wrapper over langchain-postgres ``PGVector`` for FP caching."""

    def __init__(self, connection: str, collection: str, embeddings: Any) -> None:
        self.connection = connection
        self.collection = collection
        self._embeddings = embeddings
        self._vectorstore: Optional[Any] = None

    @property
    def vectorstore(self) -> Any:
        if self._vectorstore is None:
            from langchain_postgres import PGVector

            self._vectorstore = PGVector(
                embeddings=self._embeddings,
                collection_name=self.collection,
                connection=self.connection,
                use_jsonb=True,
            )
        return self._vectorstore

    def search(self, finding: SemgrepFinding, k: int = MAX_K) -> list[MemoryMatch]:
        """Return cached neighbors similar to ``finding``, nearest first."""
        embedding = self._embeddings.embed_query(build_finding_text(finding))
        results = self.vectorstore.similarity_search_with_score_by_vector(
            embedding, k=k
        )
        matches: list[MemoryMatch] = []
        for doc, score in results:
            meta = doc.metadata or {}
            try:
                verdict = Verdict(meta.get("verdict", "unknown"))
            except ValueError:
                verdict = Verdict.UNKNOWN
            matches.append(
                MemoryMatch(
                    signature=meta.get("signature", ""),
                    verdict=verdict,
                    confidence=max(0.0, 1.0 - float(score)),
                    distance=float(score),
                    cached_report=meta.get("cached_report", "") or doc.page_content or "",
                )
            )
        return matches

    def add(
        self,
        finding: SemgrepFinding,
        verdict: Verdict,
        report_text: str = "",
    ) -> None:
        """Cache a finding with its adjudicated verdict for future lookups."""
        metadata = {
            "signature": finding.signature,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "verdict": verdict.value,
            "cached_report": report_text,
        }
        self.vectorstore.add_texts([build_finding_text(finding)], metadatas=[metadata])


def get_store() -> Optional[MemoryStore]:
    """Return the shared memory store, or ``None`` if unavailable (fail-open)."""
    global _store, _store_initialized

    if _store_initialized:
        return _store
    _store_initialized = True

    if not PGVECTOR_CONNECTION:
        logger.warning(
            "PGVECTOR_CONNECTION / DATABASE_URL not set; memory cache disabled."
        )
        return None

    try:
        from langchain_ollama import OllamaEmbeddings

        embeddings = OllamaEmbeddings(model=EMBED_MODEL, base_url=OLLAMA_BASE_URL)
        _ensure_extension(PGVECTOR_CONNECTION)
        _store = MemoryStore(PGVECTOR_CONNECTION, PGVECTOR_COLLECTION, embeddings)
        logger.info(
            "Memory store ready (collection=%s, embed_model=%s).",
            PGVECTOR_COLLECTION,
            EMBED_MODEL,
        )
        return _store
    except Exception as exc:  # noqa: BLE001 - fail-open by design
        logger.warning(
            "Could not initialize memory store (%s); cache disabled (fail-open).",
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def memory_node(state: SpectreState) -> dict[str, Any]:
    """Query the FP cache for each Semgrep finding.

    Emits ``memory_matches`` (the cached hits) and records the signatures of
    cached false positives into ``false_positives`` so downstream nodes can
    skip LLM triage for them.
    """
    findings = state.get("semgrep_findings", [])
    if not findings:
        return {"memory_matches": [], "stage": AnalysisStage.MEMORY}

    store = get_store()
    if store is None:
        return {"memory_matches": [], "stage": AnalysisStage.MEMORY}

    matches: list[MemoryMatch] = []
    cached_fps: list[str] = []

    for finding in findings:
        try:
            hits = store.search(finding)
        except Exception as exc:  # noqa: BLE001 - per-finding isolation
            logger.warning("Memory search failed for %s: %s", finding.rule_id, exc)
            continue

        for hit in hits:
            if hit.distance > DISTANCE_THRESHOLD:
                continue
            # Re-tag the match with the *current* finding's signature so
            # downstream nodes know which finding to skip.
            matches.append(
                MemoryMatch(
                    signature=finding.signature,
                    verdict=hit.verdict,
                    confidence=hit.confidence,
                    distance=hit.distance,
                    cached_report=hit.cached_report,
                )
            )
            if hit.verdict == Verdict.FALSE_POSITIVE:
                cached_fps.append(finding.signature)

    if cached_fps:
        logger.info("Cached false positives short-circuited: %s", cached_fps)

    return {
        "memory_matches": matches,
        "false_positives": cached_fps,
        "stage": AnalysisStage.MEMORY,
    }


def cache_false_positive(finding: SemgrepFinding, report_text: str = "") -> None:
    """Write-back helper for the report node: store a confirmed FP."""
    store = get_store()
    if store is None:
        return
    try:
        store.add(finding, Verdict.FALSE_POSITIVE, report_text)
    except Exception as exc:  # noqa: BLE001 - caching is best-effort
        logger.warning("Failed to cache false positive %s: %s", finding.signature, exc)


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.memory_node)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Query the SPECTRE FP cache.")
    parser.add_argument("query", help="Free-text query to search the cache.")
    parser.add_argument("--k", type=int, default=MAX_K)
    args = parser.parse_args()

    store = get_store()
    if store is None:
        raise SystemExit("Memory store unavailable.")

    embedding = store._embeddings.embed_query(args.query)
    for doc, score in store.vectorstore.similarity_search_with_score_by_vector(
        embedding, k=args.k
    ):
        print(f"[distance={score:.4f}] {doc.metadata}")
