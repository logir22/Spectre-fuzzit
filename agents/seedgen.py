"""Directed fuzz-seed generation from SAST findings (CPG/taint directed).

Instead of blind mutation, extract the risky sinks surfaced by Semgrep/Joern
and turn them into AFL dictionaries + targeted seeds, so the fuzzer spends its
CPU budget on the vulnerable paths rather than exploring blindly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from .state import JoernFinding, SemgrepFinding

_MAGIC_RE = re.compile(r"0x[0-9a-fA-F]+|\b\d{4,}\b")
_STRING_RE = re.compile(r'"([^"]{1,64})"')
_FORMAT_RE = re.compile(r"%[0-9.\-+ #]*[diuxXfFeEgGcspn%]")


def extract_tokens(source_text: str) -> set[str]:
    """Extract interesting constants, strings and format specifiers from source."""
    text = source_text or ""
    tokens: set[str] = set()
    for match in _MAGIC_RE.finditer(text):
        tokens.add(match.group(0))
    for match in _STRING_RE.finditer(text):
        tokens.add(match.group(1))
    for match in _FORMAT_RE.finditer(text):
        tokens.add(match.group(0))
    return {t for t in tokens if t and len(t) <= 64}


def build_afl_dictionary(tokens: set[str] | list[str]) -> str:
    """Render an AFL ``.dict`` file body from a set of tokens."""
    lines = []
    for i, token in enumerate(sorted(tokens)):
        escaped = token.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'token_{i}="{escaped}"')
    return "\n".join(lines)


def write_afl_dictionary(tokens: set[str] | list[str], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(build_afl_dictionary(tokens), encoding="utf-8")
    return path


def findings_to_tokens(
    semgrep: list[SemgrepFinding],
    joern: list[JoernFinding],
) -> set[str]:
    """Collect fuzzing tokens from every SAST finding (sources, sinks, code)."""
    tokens: set[str] = set()
    for f in semgrep:
        tokens |= extract_tokens(f.code_snippet or "")
        tokens |= extract_tokens(f.message or "")
        if f.source and f.source.content:
            tokens |= extract_tokens(f.source.content)
        if f.sink and f.sink.content:
            tokens |= extract_tokens(f.sink.content)
    for j in joern:
        tokens |= extract_tokens(j.code or "")
        tokens |= extract_tokens(j.description or "")
    return tokens


def build_seed_plan(
    semgrep: list[SemgrepFinding],
    joern: list[JoernFinding],
) -> dict[str, Any]:
    """Produce a seed plan: AFL dictionary tokens + per-finding target hints."""
    tokens = findings_to_tokens(semgrep, joern)
    targets = [
        {
            "file": f.path,
            "line": f.start_line,
            "rule": f.rule_id,
            "sink": f.sink.content if f.sink else "",
        }
        for f in semgrep
    ]
    return {"tokens": sorted(tokens), "targets": targets}
