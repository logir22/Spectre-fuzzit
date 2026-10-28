"""Async pgvector client for continuous recon (code/endpoint signatures).

Monitors target deployments in real time: fingerprint code, endpoints and HTTP
responses into a vector DB, then run semantic similarity on new content to
alert on changes before human researchers notice.

Uses ``asyncpg`` (fast async driver) and pgvector's ``<=>`` cosine operator.
Fail-open: connection/import errors return empty results rather than raising.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

ASYNC_DB_URL = os.environ.get("ASYNC_DB_URL", "") or os.environ.get("PGVECTOR_CONNECTION", "")

_EMBED_SQL = """
INSERT INTO signatures (kind, key, fingerprint, embedding)
VALUES ($1, $2, $3, $4::vector)
ON CONFLICT (kind, key) DO UPDATE SET embedding = EXCLUDED.embedding
"""

_SEARCH_SQL = """
SELECT kind, key, fingerprint, 1 - (embedding <=> $1::vector) AS similarity
FROM signatures
ORDER BY embedding <=> $1::vector
LIMIT $2
"""


def fingerprint(content: str) -> str:
    """Stable content hash (sha256, 32 hex chars)."""
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()[:32]


def fingerprint_code(path: str, source: str) -> str:
    """Namespace a code fingerprint by its file path."""
    return f"{path}@{fingerprint(source)}"


def _vec_literal(embedding: list[float]) -> str:
    """Render a float list as a pgvector literal (``[1.0,0.0,...]``).

    asyncpg cannot infer the ``vector`` type from a Python list, so we pass the
    canonical text form and let the SQL ``::vector`` cast parse it.
    """
    return "[" + ",".join(str(x) for x in embedding) + "]"


class AsyncVectorStore:
    """Thin async wrapper over a pgvector table ``signatures``."""

    def __init__(self, dsn: str = ASYNC_DB_URL) -> None:
        self.dsn = dsn
        self._pool = None

    async def _connect(self):
        if self._pool is None:
            import asyncpg

            self._pool = await asyncpg.create_pool(dsn=self.dsn, min_size=1, max_size=5)
        return self._pool

    async def ensure_schema(self) -> None:
        pool = await self._connect()
        async with pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signatures (
                    id serial PRIMARY KEY,
                    kind text NOT NULL,
                    key text NOT NULL,
                    fingerprint text,
                    embedding vector(768),
                    updated_at timestamptz DEFAULT now(),
                    UNIQUE (kind, key)
                )
                """
            )

    async def upsert(self, kind: str, key: str, fingerprint: str, embedding: list[float]) -> None:
        try:
            pool = await self._connect()
            async with pool.acquire() as conn:
                await conn.execute(_EMBED_SQL, kind, key, fingerprint, _vec_literal(embedding))
        except Exception as exc:  # noqa: BLE001 - fail-open
            logger.warning("async vector upsert failed: %s", exc)

    async def search(self, embedding: list[float], k: int = 5) -> list[dict]:
        try:
            pool = await self._connect()
            async with pool.acquire() as conn:
                rows = await conn.fetch(_SEARCH_SQL, _vec_literal(embedding), k)
            return [
                {
                    "kind": r["kind"],
                    "key": r["key"],
                    "fingerprint": r["fingerprint"],
                    "similarity": float(r["similarity"]),
                }
                for r in rows
            ]
        except Exception as exc:  # noqa: BLE001 - fail-open
            logger.warning("async vector search failed: %s", exc)
            return []
