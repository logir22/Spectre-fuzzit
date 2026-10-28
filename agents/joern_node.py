"""Joern analysis node.

Wraps the Joern CLI in two subprocess stages:

  1. ``joern-parse``  -> produce a Code Property Graph (``cpg.bin``) from the
     target repository.
  2. ``joern --script pointer_taint.sc`` -> run the taint traversal and emit
     findings as JSON (captured from stdout, or the ``outFile`` fallback).

Subprocess handling mirrors ``semgrep_node``: distinct exceptions for a
missing binary, a timeout, a non-zero exit and unparseable output, so the
graph can route failures instead of crashing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from .state import AnalysisStage, JoernFinding, SpectreState

logger = logging.getLogger(__name__)

JOERN_PARSE_BIN = os.environ.get("JOERN_PARSE_BIN", "joern-parse")
JOERN_BIN = os.environ.get("JOERN_BIN", "joern")
JOERN_TIMEOUT = int(os.environ.get("JOERN_TIMEOUT", "600"))
DEFAULT_SCRIPT = str(Path(__file__).resolve().parent.parent / "scripts" / "pointer_taint.sc")
JOERN_SCRIPT = os.environ.get("JOERN_SCRIPT", DEFAULT_SCRIPT)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class JoernError(RuntimeError):
    """Base error for Joern execution failures."""


class JoernNotFoundError(JoernError):
    """Raised when a Joern binary is not available on PATH."""


class JoernTimeoutError(JoernError):
    """Raised when a Joern stage exceeds the allowed execution time."""


class JoernExecutionError(JoernError):
    """Raised when a Joern command exits non-zero."""

    def __init__(self, message: str, returncode: int, stderr: str) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class JoernParseError(JoernError):
    """Raised when Joern output cannot be decoded as a JSON array."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_binary(binary: str) -> str:
    if shutil.which(binary) is None:
        raise JoernNotFoundError(
            f"Joern binary '{binary}' not found on PATH. "
            "Install Joern or set the corresponding *_BIN environment variable."
        )
    return binary


def _extract_json_array(text: str) -> list[dict[str, Any]]:
    """Recover a JSON array from Joern's (possibly noisy) stdout."""
    text = (text or "").strip()
    if not text:
        return []

    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            try:
                data = json.loads(line)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                continue

    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

    raise JoernParseError(f"Could not extract JSON from Joern output: {text[:500]}")


def _parse_results(data: list[dict[str, Any]]) -> list[JoernFinding]:
    findings: list[JoernFinding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        source = item.get("source") or ""
        sink = item.get("sink") or ""
        findings.append(
            JoernFinding(
                node_id=str(item.get("id") or ""),
                label=item.get("label") or "taint",
                code=sink,
                method=item.get("method") or "",
                file=item.get("file") or "",
                line=item.get("line"),
                description=f"{source} -> {sink}",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def run_joern_parse(
    src: str | Path,
    cpg_out: str | Path,
    timeout: int = JOERN_TIMEOUT,
) -> Path:
    """Run ``joern-parse`` and return the path to the generated CPG."""
    src = Path(src).resolve()
    cpg_out = Path(cpg_out).resolve()
    if not src.exists():
        raise JoernError(f"Source path does not exist: {src}")

    binary = _require_binary(JOERN_PARSE_BIN)
    cmd = [binary, "-o", str(cpg_out), str(src)]
    logger.info("Running joern-parse: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise JoernTimeoutError(f"joern-parse exceeded {timeout}s.") from exc
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise JoernNotFoundError(f"Could not execute '{binary}'.") from exc
        raise JoernError(f"joern-parse could not be executed: {exc}") from exc

    if proc.returncode != 0:
        raise JoernExecutionError(
            f"joern-parse failed with exit code {proc.returncode}",
            proc.returncode,
            proc.stderr or proc.stdout or "",
        )

    if not cpg_out.exists():
        raise JoernError(f"joern-parse completed but CPG not found at {cpg_out}")

    return cpg_out


def run_joern_script(
    cpg_file: str | Path,
    script: str | Path = JOERN_SCRIPT,
    out_file: Optional[str | Path] = None,
    timeout: int = JOERN_TIMEOUT,
) -> list[JoernFinding]:
    """Run the Scala taint script against a CPG and parse its JSON output."""
    script = Path(script)
    if not script.exists():
        raise JoernError(f"Joern script not found: {script}")

    cpg = str(Path(cpg_file).resolve())
    binary = _require_binary(JOERN_BIN)
    params = [f"cpgFile={cpg}", f"outFile={out_file or ''}"]
    cmd = [binary, "--script", str(script), "--params", ",".join(params)]
    logger.info("Running joern script: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise JoernTimeoutError(f"joern script exceeded {timeout}s.") from exc
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise JoernNotFoundError(f"Could not execute '{binary}'.") from exc
        raise JoernError(f"joern script could not be executed: {exc}") from exc

    if proc.returncode != 0:
        raise JoernExecutionError(
            f"joern script failed with exit code {proc.returncode}",
            proc.returncode,
            proc.stderr or proc.stdout or "",
        )

    try:
        data = _extract_json_array(proc.stdout or "")
    except JoernParseError:
        data = []

    if not data and out_file and Path(out_file).exists():
        try:
            data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise JoernParseError(f"Could not read Joern output file: {exc}") from exc

    return _parse_results(data)


def run_joern(
    repo_path: str | Path,
    script: str | Path = JOERN_SCRIPT,
    timeout: int = JOERN_TIMEOUT,
    workdir: Optional[str | Path] = None,
) -> list[JoernFinding]:
    """Full pipeline: parse the repo into a CPG, then run the taint script.

    The CPG and intermediate JSON are written into a temporary directory that
    is cleaned up automatically unless ``workdir`` is provided for debugging.
    """
    repo_path = Path(repo_path).resolve()
    if not repo_path.exists():
        raise JoernError(f"Target path does not exist: {repo_path}")

    if workdir:
        tmpdir = Path(workdir)
        tmpdir.mkdir(parents=True, exist_ok=True)
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix="spectre_joern_"))

    cpg_file = tmpdir / "cpg.bin"
    out_file = tmpdir / "taint_results.json"

    try:
        run_joern_parse(repo_path, cpg_file, timeout=timeout)
        return run_joern_script(cpg_file, script=script, out_file=out_file, timeout=timeout)
    finally:
        if not workdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def joern_node(state: SpectreState) -> dict[str, Any]:
    """LangGraph node: build the CPG and surface taint findings."""
    repo_path = state.get("repo_path", "")
    if not repo_path:
        return {
            "joern_findings": [],
            "error": "joern_node: 'repo_path' not provided in state.",
            "stage": AnalysisStage.JOERN,
        }

    try:
        findings = run_joern(repo_path)
    except JoernError as exc:
        logger.error("Joern node failed: %s", exc)
        return {
            "joern_findings": [],
            "error": str(exc),
            "stage": AnalysisStage.JOERN,
        }
    except Exception as exc:  # noqa: BLE001 - safety net, never crash the graph
        logger.exception("Joern node raised an unexpected error")
        return {
            "joern_findings": [],
            "error": f"joern_node unexpected error: {exc}",
            "stage": AnalysisStage.JOERN,
        }

    return {"joern_findings": findings, "stage": AnalysisStage.JOERN}


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.joern_node)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Run Joern taint analysis and dump findings.")
    parser.add_argument("repo_path", help="Directory (C/C++) to parse.")
    parser.add_argument("--script", default=JOERN_SCRIPT, help="Joern .sc script path.")
    parser.add_argument("--timeout", type=int, default=JOERN_TIMEOUT)
    parser.add_argument("--keep-workdir", action="store_true", help="Keep CPG artifacts.")
    args = parser.parse_args()

    workdir = None
    if args.keep_workdir:
        workdir = Path(tempfile.mkdtemp(prefix="spectre_joern_"))
        print(f"Workdir: {workdir}")

    for finding in run_joern(args.repo_path, script=args.script, timeout=args.timeout, workdir=workdir):
        print(finding.model_dump_json(indent=2))
