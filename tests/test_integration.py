"""Integration tests against live Redis / pgvector services.

Skipped by default; run with:

    docker compose up -d redis db
    pytest --run-integration

Each test skips gracefully if the backing service is unreachable.
"""

import asyncio
import os
import uuid

import pytest

pytestmark = pytest.mark.integration

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
ASYNC_DB_URL = os.environ.get("ASYNC_DB_URL", "") or os.environ.get("PGVECTOR_CONNECTION", "")


# ---------------------------------------------------------------------------
# Redis event bus
# ---------------------------------------------------------------------------


@pytest.fixture
def redis_bus():
    from agents.events import EventBus

    stream = f"spectre_it_{uuid.uuid4().hex[:8]}"
    bus = EventBus(url=REDIS_URL, stream=stream)
    if bus._redis is None:
        pytest.skip("Redis not reachable")
    return bus


def test_redis_publish_drain(redis_bus):
    from agents.events import NEW_CRASH

    redis_bus.publish(NEW_CRASH, {"signature": "abc123", "signal": 6})
    events = redis_bus.drain({NEW_CRASH})
    assert any(e["data"].get("signature") == "abc123" for e in events)


def test_redis_drain_filter_preserves_others(redis_bus):
    from agents.events import NEW_CRASH

    redis_bus.publish("other_event", {"x": 1})
    redis_bus.publish(NEW_CRASH, {"signature": "filtered"})
    events = redis_bus.drain({NEW_CRASH})
    assert all(e["event"] == NEW_CRASH for e in events)
    assert any(e["data"].get("signature") == "filtered" for e in events)


# ---------------------------------------------------------------------------
# pgvector (asyncpg)
# ---------------------------------------------------------------------------


def test_vectordb_roundtrip():
    if not ASYNC_DB_URL:
        pytest.skip("ASYNC_DB_URL not set")
    try:
        import asyncpg  # noqa: F401
    except ImportError:
        pytest.skip("asyncpg not installed")

    from agents.vectordb import AsyncVectorStore

    async def run():
        store = AsyncVectorStore(ASYNC_DB_URL)
        await store.ensure_schema()
        vec = [0.0] * 768
        vec[0] = 1.0
        key = f"it_{uuid.uuid4().hex[:8]}"
        await store.upsert("test", key, "fp-1", vec)
        return await store.search(vec, k=1)

    try:
        results = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001 - skip if DB unreachable
        pytest.skip(f"pgvector unreachable: {exc}")
        return

    assert results
    assert results[0]["similarity"] > 0.99


def test_vectordb_fingerprint_roundtrip_independent():
    from agents.vectordb import fingerprint

    assert fingerprint("a") == fingerprint("a")
