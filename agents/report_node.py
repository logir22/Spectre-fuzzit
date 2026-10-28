"""Report node: LLM-generated Markdown vulnerability report.

Aggregates the output of every upstream node (Semgrep, Joern, fuzzing, and
the false-positive cache) and asks a local Ollama model (``ChatOllama``) to
draft a professional, HackerOne-ready report.

Design principles:
  * Fail-open: if Ollama is unreachable or the model errors, we fall back to
    a deterministic template report so the run still produces output.
  * Cached false positives are excluded before the LLM is invoked.
  * The LLM is given a compact JSON context and instructed to never invent
    findings.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .state import (
    AnalysisStage,
    CrashReport,
    FuzzResult,
    JoernFinding,
    SemgrepFinding,
    SpectreState,
)
from .events import REPORT_GENERATED, EventBus
from . import telemetry

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder")
OLLAMA_TEMPERATURE = float(os.environ.get("OLLAMA_TEMPERATURE", "0.2"))
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "600"))
REPORTS_DIR = os.environ.get("REPORTS_DIR", str(Path(__file__).resolve().parent.parent / "reports"))

SYSTEM_PROMPT = """\
You are SPECTRE, an expert application security engineer writing bug bounty reports.

Given the JSON analysis results below for target "{target}", produce a professional,
HackerOne-ready vulnerability report in Markdown.

Required structure (use exactly these top-level sections, in this order):
1. ## Summary — one paragraph describing what was found and the overall risk.
2. ## Reproduction Steps — exact numbered commands to reproduce each issue.
3. ## Proof of Concept — minimized PoC code/input that triggers the issue.
4. ## Impact — theoretical business/security impact of exploitation.

Rules:
- Deduplicate findings that describe the same underlying bug.
- For each finding include: Severity, CWE (if inferable), vulnerable location
  (file:line), and remediation.
- Order findings from most to least severe (CRITICAL > HIGH > MEDIUM > LOW > INFO).
- Clearly separate "Static Analysis" findings (Semgrep/Joern) from "Dynamic
  Analysis" findings (fuzzing/AFL++ crashes).
- For fuzzing crashes, describe the sanitizer report, the crashing signal, and
  provide a reproduction command using the crash input file.
- If there are no findings, state that clearly and do NOT invent vulnerabilities.
- Use CVSS 3.1 style severity rationale when possible.
- Respond ONLY with the Markdown report, no preamble.

Analysis results:
{context}
"""

REPORT_SECTIONS = ["Summary", "Reproduction Steps", "Proof of Concept", "Impact"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _select_findings(state: SpectreState) -> tuple[
    list[SemgrepFinding],
    list[JoernFinding],
    list[CrashReport],
    Optional[FuzzResult],
]:
    fp_signatures = set(state.get("false_positives", []))
    semgrep = [f for f in state.get("semgrep_findings", []) if f.signature not in fp_signatures]
    joern = state.get("joern_findings", [])
    crashes = state.get("crash_reports", [])
    fuzz = state.get("fuzz_result")
    return semgrep, joern, crashes, fuzz


def _build_context(
    repo_path: str,
    semgrep: list[SemgrepFinding],
    joern: list[JoernFinding],
    crashes: list[CrashReport],
    fuzz: Optional[FuzzResult],
) -> str:
    static = [
        {
            "tool": "semgrep",
            "rule": f.rule_id,
            "severity": f.severity.value,
            "file": f.path,
            "line": f.start_line,
            "message": f.message,
            "source": str(f.source) if f.source else None,
            "sink": str(f.sink) if f.sink else None,
            "code": f.code_snippet,
        }
        for f in semgrep
    ] + [
        {
            "tool": "joern",
            "method": j.method,
            "file": j.file,
            "line": j.line,
            "source_to_sink": j.description,
        }
        for j in joern
    ]

    dynamic = {
        "total_execs": fuzz.total_execs if fuzz else 0,
        "execs_per_sec": fuzz.execs_per_sec if fuzz else 0.0,
        "unique_crashes": fuzz.unique_crashes if fuzz else 0,
        "hangs": fuzz.hangs if fuzz else 0,
        "crashes": [
            {
                "id": c.crash_id,
                "binary": c.binary_path,
                "input": c.input_file,
                "signal": c.signal,
                "asan_output": c.asan_output[:2000],
                "stack_trace": c.stack_trace[:20],
            }
            for c in crashes
        ],
    }

    payload = {
        "target": repo_path,
        "static_analysis": static,
        "dynamic_analysis": dynamic,
    }
    return json.dumps(payload, indent=2, default=str)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(
    repo_path: str,
    context: str,
    model: str = OLLAMA_MODEL,
    base_url: str = OLLAMA_BASE_URL,
) -> str:
    """Ask the local Ollama model to draft the Markdown report."""
    from langchain_ollama import ChatOllama

    llm = ChatOllama(
        model=model,
        base_url=base_url,
        temperature=OLLAMA_TEMPERATURE,
        client_kwargs={"timeout": OLLAMA_TIMEOUT},
    )
    prompt = SYSTEM_PROMPT.format(target=repo_path, context=context)
    response = llm.invoke(prompt)
    content = getattr(response, "content", None) or str(response)
    if isinstance(content, list):  # some models return content blocks
        content = "".join(str(block) for block in content)
    return str(content).strip()


def build_poc(crash: CrashReport) -> str:
    """Render a minimized PoC block for a crash (repro command + signal + ASAN)."""
    lines = [
        "```",
        f"# Reproduce with the crashing input (signal {crash.signal}):",
        f"#   {crash.binary_path} < {crash.input_file}",
    ]
    if crash.asan_output:
        summary = next(
            (ln for ln in crash.asan_output.splitlines() if "ERROR: AddressSanitizer" in ln),
            "",
        )
        if summary:
            lines.append(f"# {summary.strip()}")
    lines.append("```")
    return "\n".join(lines)


def fallback_report(
    repo_path: str,
    semgrep: list[SemgrepFinding],
    joern: list[JoernFinding],
    crashes: list[CrashReport],
    fuzz: Optional[FuzzResult],
    llm_fallback: bool = False,
) -> str:
    """Deterministic template report used when the LLM is unavailable."""
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        "# SPECTRE Vulnerability Report",
        "",
        f"- **Target:** `{repo_path}`",
        f"- **Generated:** {now}",
        f"- **Engine:** SPECTRE (deterministic template)",
        "",
        "## Summary",
        "",
        f"- Static findings (Semgrep): {len(semgrep)}",
        f"- Taint flows (Joern): {len(joern)}",
        f"- Fuzzing crashes: {len(crashes)}",
        f"- Fuzz executions: {fuzz.total_execs if fuzz else 0}",
        "",
    ]

    if not (semgrep or joern or crashes):
        lines += ["No vulnerabilities were detected by any analysis stage.", ""]
        return "\n".join(lines)

    if semgrep:
        lines += ["## Static Analysis — Semgrep", ""]
        for f in semgrep:
            lines += [
                f"### {f.rule_id} — {f.severity.value}",
                "",
                f"- **Location:** `{f.path}:{f.start_line}`",
                f"- **Message:** {f.message}",
            ]
            if f.source:
                lines.append(f"- **Source:** {f.source}")
            if f.sink:
                lines.append(f"- **Sink:** {f.sink}")
            if f.code_snippet:
                lines += ["", "```", f.code_snippet.strip(), "```"]
            lines += [""]

    if joern:
        lines += ["## Static Analysis — Joern (Taint Flows)", ""]
        for j in joern:
            lines += [
                f"- `{j.method}` at `{j.file}:{j.line}` — `{j.description}`",
            ]
        lines += [""]

    if crashes:
        lines += ["## Dynamic Analysis — AFL++ Crashes", ""]
        for c in crashes:
            lines += [
                f"### Crash {c.crash_id} (signal {c.signal})",
                "",
                f"- **Binary:** `{c.binary_path}`",
                f"- **Input:** `{c.input_file}`",
            ]
            if c.stack_trace:
                lines += ["", "```"]
                lines += c.stack_trace[:15]
                lines += ["```"]
            lines += ["", build_poc(c), ""]

    if semgrep or joern or crashes:
        lines += ["## Proof of Concept", ""]
        for f in semgrep:
            if f.code_snippet:
                lines += ["```", f.code_snippet.strip(), "```"]
        for c in crashes:
            lines += [build_poc(c)]
        lines += [""]

        lines += ["## Impact", ""]
        lines += [
            "These issues may allow memory corruption (out-of-bounds write/read), "
            "potentially leading to remote code execution or denial of service "
            "depending on the attack surface and process privileges.",
            "",
        ]

    if llm_fallback:
        lines += [
            "## Note",
            "",
            "This report was generated by the deterministic fallback because the LLM "
            "was unavailable. Re-run with Ollama reachable for a fully-authored report.",
            "",
        ]
    return "\n".join(lines)

def save_report(markdown: str, repo_path: str, output_dir: str = REPORTS_DIR) -> Path:
    """Persist the report into the configured reports directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    repo_name = Path(repo_path).name or "target"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = out / f"spectre_{repo_name}_{stamp}.md"
    path.write_text(markdown, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def report_node(state: SpectreState) -> dict[str, Any]:
    """LangGraph node: assemble context and produce the final Markdown report."""
    repo_path = state.get("repo_path", "")
    semgrep, joern, crashes, fuzz = _select_findings(state)

    with telemetry.span("report_node", repo=repo_path):
        if not (semgrep or joern or crashes):
            markdown = fallback_report(repo_path, semgrep, joern, crashes, fuzz)
            return {"report_markdown": markdown, "stage": AnalysisStage.REPORT}

        context = _build_context(repo_path, semgrep, joern, crashes, fuzz)
        total = len(semgrep) + len(joern) + len(crashes)
        telemetry.counter("spectre.report.findings", total)

        try:
            markdown = generate_report(repo_path, context)
            if not markdown:
                raise ValueError("LLM returned an empty report.")
        except Exception as exc:  # noqa: BLE001 - fail-open
            logger.warning(
                "LLM report generation failed (%s); falling back to template.", exc
            )
            markdown = fallback_report(repo_path, semgrep, joern, crashes, fuzz, llm_fallback=True)

    EventBus().publish(REPORT_GENERATED, {"target": repo_path, "findings": total})
    return {"report_markdown": markdown, "stage": AnalysisStage.REPORT}


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.report_node)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Generate a SPECTRE report from a context JSON file.")
    parser.add_argument("context", help="Path to a JSON file produced by _build_context.")
    parser.add_argument("--repo", default="unknown", help="Target repo path/name.")
    parser.add_argument("--model", default=OLLAMA_MODEL)
    args = parser.parse_args()

    ctx = Path(args.context).read_text(encoding="utf-8")
    report = generate_report(args.repo, ctx, model=args.model)
    print(report)
