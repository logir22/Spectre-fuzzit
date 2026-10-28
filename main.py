"""SPECTRE command-line entry point.

Usage:
    python main.py <target> [--no-joern] [--no-fuzzer] ...

Runs the full LangGraph pipeline and prints/saves the Markdown report.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import typer
from pydantic import BaseModel

from agents.graph import run_pipeline
from agents.report_node import REPORTS_DIR, save_report
from agents.targets import (
    fetch_bounty_targets,
    fetch_chaos_domains,
    fetch_chaos_index,
    matches_scope,
    search_programs,
)
from agents.subenum import enumerate_subdomains

app = typer.Typer(
    name="spectre",
    help="SPECTRE - automated C/C++ vulnerability detection (SAST + fuzzing).",
    add_completion=False,
)
targets_app = typer.Typer(
    name="targets",
    help="Discover authorized bounty targets from public scope data.",
    add_completion=False,
)
app.add_typer(targets_app)


def _json_safe(obj: Any) -> Any:
    """Recursively convert state values into JSON-serializable primitives."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to the C/C++ repository to analyze."),
    semgrep_config: Optional[str] = typer.Option(
        None, "--semgrep-config", help="Semgrep config (rule pack like p/cpp or a local dir)."
    ),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Ollama model for report generation."),
    fuzz_timeout: Optional[int] = typer.Option(None, "--fuzz-timeout", help="AFL++ fuzzing time in seconds."),
    no_joern: bool = typer.Option(False, "--no-joern", help="Skip the Joern CPG analysis stage."),
    no_fuzzer: bool = typer.Option(False, "--no-fuzzer", help="Skip the AFL++ fuzzing stage."),
    output_dir: str = typer.Option(REPORTS_DIR, "--output-dir", help="Directory for the Markdown report."),
    json_out: bool = typer.Option(False, "--json", help="Also write the final state as JSON."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Analyze a C/C++ repository and emit a HackerOne-ready report."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    final = run_pipeline(
        target,
        semgrep_config=semgrep_config,
        llm_model=llm_model,
        fuzz_timeout=fuzz_timeout,
        run_joern=not no_joern,
        run_fuzzer=not no_fuzzer,
    )

    markdown = final.get("report_markdown") or ""

    try:
        path = save_report(markdown, target, output_dir=output_dir)
    except OSError as exc:
        logging.getLogger("spectre").warning("Could not save report: %s", exc)
        path = None

    typer.echo(markdown)
    if path:
        typer.echo(f"\nReport saved to: {path}")

    if json_out:
        out = Path(output_dir) / "state.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(_json_safe(final), indent=2), encoding="utf-8")
        typer.echo(f"State dumped to: {out}")


@targets_app.command("list")
def targets_list(
    platform: Optional[str] = typer.Option(
        None, "--platform", help="Filter by platform (hackerone, bugcrowd, ...)."
    ),
    query: Optional[str] = typer.Option(None, "--query", help="Filter by name/handle substring."),
) -> None:
    """List public bounty programs and their in-scope asset counts."""
    programs = fetch_bounty_targets(platform)
    if query:
        programs = search_programs(programs, query)
    for p in programs:
        typer.echo(f"[{p.platform}] {p.name} ({p.handle}) — {len(p.in_scope)} in-scope | {p.url}")


@targets_app.command("search")
def targets_search(
    domain: str = typer.Argument(..., help="Domain to check for authorized scope."),
) -> None:
    """Check which public programs list a domain as in-scope."""
    programs = fetch_bounty_targets()
    hits = [p for p in programs if matches_scope(domain, p.in_scope)]
    if not hits:
        typer.echo(f"No public program lists {domain} in scope.")
        raise typer.Exit(1)
    for p in hits:
        out = matches_scope(domain, p.out_of_scope)
        flag = "OUT-OF-SCOPE too" if out else "in-scope"
        typer.echo(f"[{p.platform}] {p.name} ({p.handle}) — {flag}")


@targets_app.command("chaos")
def targets_chaos(
    program: Optional[str] = typer.Option(None, "--program", help="Fetch subdomains for a program."),
    list_programs: bool = typer.Option(False, "--list", help="List all Chaos programs."),
) -> None:
    """Query the ProjectDiscovery Chaos dataset."""
    if program:
        for d in fetch_chaos_domains(program):
            typer.echo(d)
        return
    for p in fetch_chaos_index():
        typer.echo(f"[{p.platform}] {p.name} — {p.domains} domains{' (bounty)' if p.bounty else ''}")


@targets_app.command("subdomains")
def targets_subdomains(
    domain: str = typer.Argument(..., help="Domain or wildcard (e.g. *.shopify.com)."),
) -> None:
    """Enumerate subdomains (crt.sh + subfinder/amass) for a domain."""
    for sub in enumerate_subdomains(domain):
        typer.echo(sub)


if __name__ == "__main__":
    app()
