"""Target discovery module.

Pulls *authorized* scope from public bug-bounty data sources so SPECTRE can
be aimed at in-scope assets only:

  * ``arkadiyt/bounty-targets-data`` — daily JSON dumps of HackerOne,
    Bugcrowd, Intigriti, YesWeHack, Hackenproof and Federacy (updated via
    GitHub Actions), including per-program in/out-of-scope entries.
  * `ProjectDiscovery Chaos <https://chaos.projectdiscovery.io>`_ — a public
    dataset of resolved subdomains per bounty program.
  * `BBRF <https://github.com/honoki/bbrf-client>`_ — optional local scope
    manager (CouchDB) queried through the ``bbrf`` CLI.

Everything is fail-open: network or tooling failures log a warning and return
empty results rather than raising.
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import subprocess
import urllib.request
import zipfile
from typing import Any, Optional

from .state import ChaosProgram, ProgramScope, ScopeEntry

logger = logging.getLogger(__name__)

BOUNTY_TARGETS_BASE = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
)
CHAOS_INDEX_URL = "https://chaos-data.projectdiscovery.io/index.json"
BBRF_BIN = os.environ.get("BBRF_BIN", "bbrf")
HTTP_TIMEOUT = int(os.environ.get("TARGETS_HTTP_TIMEOUT", "30"))

PLATFORM_FILES: dict[str, str] = {
    "hackerone": "hackerone_data.json",
    "bugcrowd": "bugcrowd_data.json",
    "intigriti": "intigriti_data.json",
    "yeswehack": "yeswehack_data.json",
}

ALL_DOMAINS_URL = f"{BOUNTY_TARGETS_BASE}/domains.txt"
ALL_WILDCARDS_URL = f"{BOUNTY_TARGETS_BASE}/wildcards.txt"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http_get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "SPECTRE/0.1"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "SPECTRE/0.1"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# Normalization / matching
# ---------------------------------------------------------------------------


def _entry(raw: Any) -> ScopeEntry:
    if not isinstance(raw, dict):
        return ScopeEntry(identifier=str(raw))
    identifier = (
        raw.get("asset_identifier")
        or raw.get("identifier")
        or raw.get("asset")
        or raw.get("target")
        or ""
    )
    asset_type = raw.get("asset_type") or raw.get("type") or ""
    severity = raw.get("max_severity") or raw.get("severity") or ""
    return ScopeEntry(asset_type=asset_type, identifier=identifier, max_severity=severity)


def _normalize_program(item: dict[str, Any], platform: str) -> ProgramScope:
    targets = item.get("targets") if isinstance(item.get("targets"), dict) else {}
    in_scope = targets.get("in_scope") or item.get("in_scope") or []
    out_of_scope = targets.get("out_of_scope") or item.get("out_of_scope") or []
    return ProgramScope(
        handle=item.get("handle", ""),
        name=item.get("name", ""),
        platform=platform,
        url=item.get("url", ""),
        offers_bounties=bool(item.get("offers_bounties", False)),
        in_scope=[_entry(e) for e in in_scope],
        out_of_scope=[_entry(e) for e in out_of_scope],
    )


def matches_scope(domain: str, entries: list[ScopeEntry]) -> bool:
    """Return True if ``domain`` falls within any of ``entries`` (wildcard aware)."""
    domain = domain.rstrip(".").lower()
    for entry in entries:
        ident = entry.identifier.rstrip(".").lower()
        if not ident:
            continue
        if ident == domain:
            return True
        if ident.startswith("*."):
            suffix = ident[2:]
            if domain == suffix or domain.endswith("." + suffix):
                return True
    return False


# ---------------------------------------------------------------------------
# Bounty targets data (arkadiyt/bounty-targets-data)
# ---------------------------------------------------------------------------


def fetch_bounty_targets(platform: Optional[str] = None) -> list[ProgramScope]:
    """Download program scope from the bounty-targets-data repository."""
    platforms = [platform] if platform else list(PLATFORM_FILES)
    results: list[ProgramScope] = []
    for name in platforms:
        fname = PLATFORM_FILES.get(name)
        if not fname:
            logger.warning("Unknown platform: %s", name)
            continue
        try:
            data = _http_get_json(f"{BOUNTY_TARGETS_BASE}/{fname}")
        except Exception as exc:  # noqa: BLE001 - fail-open
            logger.warning("Could not fetch %s scope: %s", name, exc)
            continue
        for item in data:
            if isinstance(item, dict):
                results.append(_normalize_program(item, name))
    return results


def search_programs(programs: list[ProgramScope], query: str) -> list[ProgramScope]:
    """Filter programs by a case-insensitive substring over name/handle/platform."""
    q = query.lower()
    return [
        p
        for p in programs
        if q in p.name.lower() or q in p.handle.lower() or q in p.platform.lower()
    ]


def _fetch_scope_list(url: str, label: str) -> list[str]:
    try:
        text = _http_get_bytes(url).decode("utf-8", "ignore")
        return [ln.strip() for ln in text.splitlines() if ln.strip()]
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("Could not fetch %s: %s", label, exc)
        return []


def fetch_all_domains() -> list[str]:
    """Return the aggregate list of every in-scope domain across all programs."""
    return _fetch_scope_list(ALL_DOMAINS_URL, "domains.txt")


def fetch_all_wildcards() -> list[str]:
    """Return the aggregate list of in-scope wildcard domains across all programs."""
    return _fetch_scope_list(ALL_WILDCARDS_URL, "wildcards.txt")


# ---------------------------------------------------------------------------
# ProjectDiscovery Chaos
# ---------------------------------------------------------------------------


def fetch_chaos_index() -> list[ChaosProgram]:
    try:
        data = _http_get_json(CHAOS_INDEX_URL)
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("Could not fetch Chaos index: %s", exc)
        return []
    out: list[ChaosProgram] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        out.append(
            ChaosProgram(
                name=item.get("name", ""),
                url=item.get("URL", ""),
                platform=item.get("platform", ""),
                bounty=bool(item.get("bounty", False)),
                domains=int(item.get("count", 0)),
            )
        )
    return out


def fetch_chaos_domains(program_name: str) -> list[str]:
    """Download and unzip the subdomain list for a Chaos program."""
    program = next((p for p in fetch_chaos_index() if p.name == program_name), None)
    if program is None or not program.url:
        logger.warning("Chaos program not found: %s", program_name)
        return []
    try:
        data = _http_get_bytes(program.url)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if member.endswith(".txt"):
                    return zf.read(member).decode("utf-8", "ignore").splitlines()
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("Could not fetch Chaos domains for %s: %s", program_name, exc)
        return []
    return []


# ---------------------------------------------------------------------------
# BBRF (optional local scope manager)
# ---------------------------------------------------------------------------


def bbrf_run(*args: str, timeout: int = 60) -> str:
    """Invoke the ``bbrf`` CLI, returning combined stdout/stderr ('' if absent)."""
    if shutil.which(BBRF_BIN) is None:
        logger.warning("BBRF not installed (%s); skipping.", BBRF_BIN)
        return ""
    try:
        proc = subprocess.run(
            [BBRF_BIN, *args], capture_output=True, text=True, timeout=timeout
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("bbrf failed: %s", exc)
        return ""


def bbrf_programs() -> list[str]:
    return [ln.strip() for ln in bbrf_run("programs").splitlines() if ln.strip()]


def bbrf_domains(program: Optional[str] = None) -> list[str]:
    args = ["domains"] if program is None else ["domains", "--program", program]
    return [ln.strip() for ln in bbrf_run(*args).splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.targets)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Discover authorized bounty targets.")
    parser.add_argument("--platform", default=None, help="Filter by platform.")
    parser.add_argument("--query", default=None, help="Filter programs by substring.")
    parser.add_argument("--chaos", default=None, help="Fetch Chaos subdomains for a program.")
    args = parser.parse_args()

    if args.chaos:
        print("\n".join(fetch_chaos_domains(args.chaos)))
    else:
        programs = fetch_bounty_targets(args.platform)
        if args.query:
            programs = search_programs(programs, args.query)
        for p in programs:
            print(f"[{p.platform}] {p.name} ({p.handle}) — {len(p.in_scope)} in-scope")
