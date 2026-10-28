"""Crash deduplication via normalized stack-trace hashing.

A fuzzer re-discovers the same root-cause bug thousands of times through
different inputs and code paths. Hashing the *normalized* stack trace lets us
collapse those into a single first-seen event and pay AI inference cost only
once per bug within a sliding time window.

Normalization strips ASLR addresses, build IDs and line offsets so the same
crash at different addresses hashes to the same signature.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional

from .state import CrashReport

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_SECONDS = int(os.environ.get("DEDUP_WINDOW_SECONDS", "86400"))


def normalize_frame(frame: str) -> str:
    """Reduce a stack frame to its stable function name (no addresses/offsets)."""
    f = frame.strip()
    f = re.sub(r"^#\d+\s+0x[0-9a-fA-F]+\s+in\s+", "", f)
    f = re.sub(r"\s*\(BuildId:.*$", "", f)
    f = re.sub(r"\s*\([^)]*\+?\s*0x[0-9a-fA-F]+\)$", "", f)
    f = re.sub(r":\d+$", "", f)
    return f.strip()


def crash_signature(crash: CrashReport, top_n: int = 5) -> str:
    """Return a stable, dedup-friendly hash for a crash (top-N frames)."""
    frames = [normalize_frame(f) for f in (crash.stack_trace or [])[:top_n]]
    frames = [f for f in frames if f]
    if not frames:
        head = (crash.asan_output or "").strip().splitlines()
        frames = [normalize_frame(head[0]) if head else "asan:unknown"]
    key = "\n".join(frames)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


class CrashDeduplicator:
    """Sliding-window dedup store with optional JSON persistence."""

    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        state_file: Optional[str | Path] = None,
    ) -> None:
        self.window = window_seconds
        self.state_file = Path(state_file) if state_file else None
        self._seen: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.state_file and self.state_file.exists():
            try:
                self._seen = json.loads(self.state_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._seen = {}

    def _save(self) -> None:
        if self.state_file:
            try:
                self.state_file.write_text(json.dumps(self._seen), encoding="utf-8")
            except OSError as exc:
                logger.warning("Could not persist dedup state: %s", exc)

    def register(self, crash: CrashReport) -> tuple[bool, int]:
        """Record a crash.

        Returns ``(is_new, count)``: ``is_new=True`` on first sighting within
        the window, otherwise ``False`` with the running duplicate count.
        """
        sig = crash_signature(crash)
        now = time.time()
        entry = self._seen.get(sig)
        if entry and (now - entry.get("last", 0.0) < self.window):
            entry["count"] = int(entry.get("count", 1)) + 1
            entry["last"] = now
            self._save()
            return False, entry["count"]

        self._seen[sig] = {"count": 1, "first": now, "last": now}
        self._save()
        return True, 1

    def unique_count(self) -> int:
        return len(self._seen)
