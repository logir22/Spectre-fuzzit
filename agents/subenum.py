"""Passive subdomain enumeration (recon step).

Closes the loop from wildcard scope to concrete hostnames:

    *.example.com  ->  [api.example.com, dev.example.com, ...]

Sources (all fail-open):

  * `crt.sh` certificate-transparency logs (passive, no auth) — the primary
    source and the "community database" of choice.
  * `subfinder` / `amass` CLIs, if installed (shell-out, best-effort).
  * Built-in common-subdomain wordlist + DNS resolution as a last resort.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import urllib.request
from typing import Any, Optional

from .state import SpectreState

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = int(os.environ.get("SUBENUM_HTTP_TIMEOUT", "30"))
SUBFINDER_BIN = os.environ.get("SUBFINDER_BIN", "subfinder")
AMASS_BIN = os.environ.get("AMASS_BIN", "amass")

_COMMON_SUBDOMAINS = [
    "www", "api", "admin", "dev", "staging", "mail", "app", "docs",
    "portal", "internal", "test", "ci", "git", "jenkins", "vpn",
    "status", "support", "blog", "shop", "login",
]


def normalize_domain(domain: str) -> str:
    """Strip a leading wildcard / trailing dot and lowercase."""
    d = (domain or "").strip().lower()
    if d.startswith("*."):
        d = d[2:]
    return d.rstrip(".")


def is_wildcard(identifier: str) -> bool:
    return (identifier or "").strip().startswith("*.")


def is_resolvable(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def crt_sh_subdomains(domain: str) -> list[str]:
    """Query crt.sh certificate-transparency logs for subdomains of ``domain``."""
    base = normalize_domain(domain)
    if not base:
        return []
    url = f"https://crt.sh/?q=%25.{base}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SPECTRE/0.1"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("crt.sh query failed for %s: %s", base, exc)
        return []

    subs: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for name in entry.get("name_value", "").split("\n"):
            name = normalize_domain(name)
            if name.endswith("." + base) and name != base:
                subs.add(name)
    return sorted(subs)


def _run_enum_tool(binary: str, domain: str) -> list[str]:
    if shutil.which(binary) is None:
        return []
    try:
        proc = subprocess.run(
            [binary, "-silent", "-d", domain],
            capture_output=True,
            text=True,
            timeout=180,
        )
        return [ln.strip().lower() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("%s failed: %s", binary, exc)
        return []


def brute_subdomains(domain: str, wordlist: Optional[list[str]] = None) -> list[str]:
    """Fallback: probe common subdomain names via DNS."""
    base = normalize_domain(domain)
    found = []
    for name in (wordlist or _COMMON_SUBDOMAINS):
        candidate = f"{name}.{base}"
        if is_resolvable(candidate):
            found.append(candidate)
    return found


def enumerate_subdomains(domain: str, resolve: bool = False) -> list[str]:
    """Return concrete subdomains for a (possibly wildcard) scope entry."""
    base = normalize_domain(domain)
    if not base:
        return []

    subs: set[str] = set(crt_sh_subdomains(base))
    subs |= set(_run_enum_tool(SUBFINDER_BIN, base))
    subs |= set(_run_enum_tool(AMASS_BIN, base))

    if not subs:
        subs |= set(brute_subdomains(base))

    result = sorted(subs)
    if resolve:
        result = [s for s in result if is_resolvable(s)]
    return result


def subenum_node(state: SpectreState) -> dict[str, Any]:
    """LangGraph node: expand discovered wildcard scope into subdomains."""
    targets = state.get("discovered_targets", [])
    wildcards = [t for t in targets if is_wildcard(t)]
    if not wildcards:
        return {}

    subs: list[str] = []
    for wc in wildcards:
        subs.extend(enumerate_subdomains(wc))
    subs = sorted(set(subs))
    logger.info("subenum: %d wildcard(s) -> %d subdomain(s)", len(wildcards), len(subs))
    return {"subdomains": subs}
