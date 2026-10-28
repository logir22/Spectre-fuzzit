"""Semgrep analysis node.

Executes the Semgrep binary against the target repository, parses the JSON
output, and extracts the taint source and sink for every finding so the
downstream nodes (memory, report) can reason about dataflow without
re-running the tool.

Subprocess handling is deliberately defensive: we distinguish between a
missing binary, a timeout, a non-zero/error exit code and malformed JSON so
the graph can route failures instead of crashing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from .state import (
    AnalysisStage,
    SemgrepFinding,
    Severity,
    SpectreState,
    TaintLocation,
)

logger = logging.getLogger(__name__)

# Configuration surfaced through environment variables so the Docker image
# can override defaults without code changes.
SEMGREP_BIN = os.environ.get("SEMGREP_BIN", "semgrep")
DEFAULT_CONFIG = os.environ.get("SEMGREP_CONFIG", "p/cpp")
DEFAULT_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", "300"))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SemgrepError(RuntimeError):
    """Base error for Semgrep execution failures."""


class SemgrepNotFoundError(SemgrepError):
    """Raised when the Semgrep binary is not available on PATH."""


class SemgrepTimeoutError(SemgrepError):
    """Raised when Semgrep exceeds the allowed execution time."""


class SemgrepExecutionError(SemgrepError):
    """Raised when Semgrep returns an error exit code (>= 2)."""

    def __init__(self, message: str, returncode: int, stderr: str) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class SemgrepParseError(SemgrepError):
    """Raised when Semgrep output cannot be decoded as JSON."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_binary() -> str:
    """Resolve and validate the Semgrep binary, raising early if absent."""
    if shutil.which(SEMGREP_BIN) is None:
        raise SemgrepNotFoundError(
            f"Semgrep binary '{SEMGREP_BIN}' not found on PATH. "
            "Install Semgrep or set SEMGREP_BIN to its full path."
        )
    return SEMGREP_BIN


def _to_location(entry: Optional[dict[str, Any]]) -> Optional[TaintLocation]:
    """Normalize a Semgrep dataflow-trace entry into a TaintLocation."""
    if not entry:
        return None
    loc = entry.get("location") or {}
    start = loc.get("start") or {}
    return TaintLocation(
        content=entry.get("content"),
        path=loc.get("path") or entry.get("path"),
        line=start.get("line"),
        col=start.get("col"),
    )


def _parse_finding(result: dict[str, Any]) -> SemgrepFinding:
    """Map a single Semgrep JSON result into a validated SemgrepFinding."""
    extra = result.get("extra") or {}
    start = result.get("start") or {}
    end = result.get("end") or {}

    severity_raw = str(extra.get("severity") or "INFO").upper()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        severity = Severity.INFO

    # Taint-mode rules emit a dataflow_trace describing the source -> sink
    # path; pattern rules leave it empty, in which case source/sink is None.
    trace = extra.get("dataflow_trace") or {}
    source = _to_location(trace.get("taint_source"))
    sink = _to_location(trace.get("taint_sink"))
    intermediates = [
        t for t in (_to_location(v) for v in (trace.get("intermediate_vars") or []))
        if t is not None
    ]

    return SemgrepFinding(
        rule_id=result.get("check_id", "unknown"),
        severity=severity,
        message=extra.get("message", ""),
        path=result.get("path", ""),
        start_line=start.get("line", 0),
        end_line=end.get("line", 0),
        source=source,
        sink=sink,
        intermediate_vars=intermediates,
        code_snippet=extra.get("lines", ""),
        metadata=extra.get("metadata") or {},
    )


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


def run_semgrep(
    repo_path: str | Path,
    config: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    extra_args: Optional[list[str]] = None,
) -> list[SemgrepFinding]:
    """Run Semgrep against ``repo_path`` and return parsed findings.

    Raises:
        SemgrepNotFoundError: binary missing.
        SemgrepTimeoutError: scan exceeded ``timeout``.
        SemgrepExecutionError: Semgrep exited with code >= 2.
        SemgrepParseError: output could not be parsed as JSON.
        SemgrepError: target path invalid.
    """
    repo_path = Path(repo_path).resolve()
    if not repo_path.exists():
        raise SemgrepError(f"Target path does not exist: {repo_path}")

    binary = _require_binary()
    config = config or DEFAULT_CONFIG

    cmd = [
        binary,
        "scan",
        "--json",
        "--metrics", "off",
        "--config", config,
        "--",
        str(repo_path),
    ]
    if extra_args:
        cmd.extend(extra_args)

    logger.info("Running semgrep: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or b"") if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or "")
        raise SemgrepTimeoutError(
            f"Semgrep exceeded {timeout}s. Partial stdout: {partial}"
        ) from exc
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            # Race between which() and exec, or a relative binary name.
            raise SemgrepNotFoundError(
                f"Semgrep binary '{SEMGREP_BIN}' could not be executed."
            ) from exc
        # e.g. Windows AppLocker / Application Control blocking the binary.
        raise SemgrepError(f"Semgrep could not be executed: {exc}") from exc

    stdout = proc.stdout or ""

    # Semgrep exit codes: 0 = no findings, 1 = findings present, >= 2 = error.
    if proc.returncode >= 2:
        raise SemgrepExecutionError(
            f"Semgrep failed with exit code {proc.returncode}",
            returncode=proc.returncode,
            stderr=proc.stderr or "",
        )

    if not stdout.strip():
        logger.info("Semgrep returned empty output (no findings).")
        return []

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepParseError(
            f"Failed to parse Semgrep JSON output: {exc}. "
            f"stdout preview: {stdout[:500]}"
        ) from exc

    results = payload.get("results", []) if isinstance(payload, dict) else []
    findings = [_parse_finding(r) for r in results]
    logger.info("Semgrep produced %d finding(s).", len(findings))
    return findings


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def semgrep_node(state: SpectreState) -> dict[str, Any]:
    """LangGraph node: run Semgrep and emit findings (or a structured error)."""
    repo_path = state.get("repo_path", "")
    config = state.get("semgrep_config") or None

    if not repo_path:
        return {
            "semgrep_findings": [],
            "error": "semgrep_node: 'repo_path' not provided in state.",
            "stage": AnalysisStage.SEMGREP,
        }

    try:
        findings = run_semgrep(repo_path, config=config)
    except SemgrepError as exc:
        logger.error("Semgrep node failed: %s", exc)
        return {
            "semgrep_findings": [],
            "error": str(exc),
            "stage": AnalysisStage.SEMGREP,
        }
    except Exception as exc:  # noqa: BLE001 - safety net, never crash the graph
        logger.exception("Semgrep node raised an unexpected error")
        return {
            "semgrep_findings": [],
            "error": f"semgrep_node unexpected error: {exc}",
            "stage": AnalysisStage.SEMGREP,
        }

    return {"semgrep_findings": findings, "stage": AnalysisStage.SEMGREP}


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.semgrep_node)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Run Semgrep and dump parsed findings.")
    parser.add_argument("repo_path", help="Directory to scan.")
    parser.add_argument("--config", default=None, help="Semgrep config (default: p/cpp).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout in seconds.")
    args = parser.parse_args()

    for finding in run_semgrep(args.repo_path, config=args.config, timeout=args.timeout):
        print(finding.model_dump_json(indent=2))
