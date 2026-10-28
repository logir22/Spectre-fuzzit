"""WAF detection and SOCKS5 proxy rotation (evasion loop).

When a network sensor / HTTP probe reports a WAF block, the orchestration graph
routes back to an evasion step that rotates the egress SOCKS5 proxy and retries,
keeping the recon→SAST→fuzz loop alive without a human in the loop.
"""

from __future__ import annotations

import itertools
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

SOCKS5_PROXIES = [p for p in os.environ.get("SOCKS5_PROXIES", "").split(",") if p.strip()]

WAF_SIGNALS = [
    "403 forbidden",
    "406 not acceptable",
    "429 too many requests",
    "blocked by",
    "cloudflare",
    "mod_security",
    "akamai",
    "imperva",
    "incapsula",
    "challenge required",
]


def detect_waf(response_text: str) -> bool:
    """Heuristically detect a WAF / rate-limit block in an HTTP response."""
    text = (response_text or "").lower()
    return any(signal in text for signal in WAF_SIGNALS)


class ProxyRotator:
    """Round-robin over a list of SOCKS5 proxies."""

    def __init__(self, proxies: Optional[list[str]] = None) -> None:
        self._proxies = list(proxies if proxies is not None else SOCKS5_PROXIES)
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None

    @property
    def available(self) -> int:
        return len(self._proxies)

    @property
    def current(self) -> Optional[str]:
        return next(self._cycle) if self._cycle else None

    def rotate(self) -> Optional[str]:
        """Advance to (and return) the next proxy."""
        return self.current
