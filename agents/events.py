"""Event bus for event-driven decoupling between producers and consumers.

Producers (e.g. the fuzzer on finding a crash) publish events like
``new_crash``; consumers (e.g. the AI triage/report worker) drain them at
their own pace. A broker (Redis Streams) buffers bursts so 1,000 crashes in a
minute do not saturate the LLM endpoint.

The bus degrades gracefully to an in-memory queue when Redis is unavailable,
so the rest of SPECTRE never hard-depends on a running broker.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
EVENTS_STREAM = os.environ.get("SPECTRE_EVENTS_STREAM", "spectre_events")
CONSUMER_GROUP = os.environ.get("SPECTRE_EVENTS_GROUP", "spectre")

NEW_CRASH = "new_crash"
FINDING_READY = "finding_ready"
REPORT_GENERATED = "report_generated"


class EventBus:
    """Publish/consume events via Redis Streams with an in-memory fallback."""

    def __init__(self, url: Optional[str] = REDIS_URL, stream: str = EVENTS_STREAM) -> None:
        self.stream = stream
        self._redis = None
        self._local: list[dict] = []
        if url:
            try:
                import redis

                self._redis = redis.Redis.from_url(url, decode_responses=True)
                self._redis.ping()
                logger.info("Event bus connected to Redis (%s).", url)
            except Exception as exc:  # noqa: BLE001 - fail-open
                logger.warning("Redis unavailable (%s); using in-memory event bus.", exc)
                self._redis = None

    def publish(self, event_type: str, payload: Optional[dict] = None) -> str:
        """Publish an event and return its id."""
        event_id = uuid.uuid4().hex
        event = {"event": event_type, "id": event_id, "ts": time.time(), "data": payload or {}}
        if self._redis is not None:
            try:
                self._redis.xadd(self.stream, {"json": json.dumps(event)})
                return event_id
            except Exception as exc:  # noqa: BLE001
                logger.warning("Redis publish failed (%s); buffering locally.", exc)
        self._local.append(event)
        return event_id

    def drain(self, event_types: Optional[set[str]] = None) -> list[dict]:
        """Return (and remove) pending events, optionally filtered by type."""
        events: list[dict] = []

        if self._redis is not None:
            try:
                try:
                    self._redis.xgroup_create(
                        self.stream, CONSUMER_GROUP, id="0", mkstream=True
                    )
                except Exception:  # noqa: BLE001 - group already exists
                    pass
                results = self._redis.xreadgroup(
                    CONSUMER_GROUP,
                    CONSUMER_GROUP,
                    {self.stream: ">"},
                    count=100,
                    block=None,
                )
                for _, msgs in results:
                    for msg_id, fields in msgs:
                        try:
                            event = json.loads(fields.get("json", "{}"))
                        except json.JSONDecodeError:
                            continue
                        if event_types is None or event.get("event") in event_types:
                            events.append(event)
                        self._redis.xack(self.stream, CONSUMER_GROUP, msg_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Redis drain failed: %s", exc)

        remaining = []
        for event in self._local:
            if event_types is None or event.get("event") in event_types:
                events.append(event)
            else:
                remaining.append(event)
        self._local = remaining

        return events

    def run_worker(
        self,
        handler,
        event_types: Optional[set[str]] = None,
        poll_interval: float = 1.0,
        max_iterations: Optional[int] = None,
    ) -> int:
        """Drain events in a loop, dispatching each to ``handler(event)``."""
        processed = 0
        while max_iterations is None or processed < max_iterations:
            events = self.drain(event_types)
            if not events:
                if max_iterations is not None:
                    break
                time.sleep(poll_interval)
                continue
            for event in events:
                handler(event)
                processed += 1
        return processed
