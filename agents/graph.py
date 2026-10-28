"""LangGraph assembly: nodes, edges, conditional routing and cycles.

The graph is now a *cyclic* orchestration rather than a linear pipeline:

    START -> recon -> semgrep -> memory -> joern -> fuzzer -> report -> END
                                                    ^         |
                                                    +--evasion+   (on WAF)

Conditional routing (data-availability driven, so a skipped stage never breaks
the join into ``report``):

  * ``route_after_semgrep``: query the FP cache only if Semgrep produced findings.
  * ``route_after_memory``: skip Joern if ``run_joern`` is false.
  * ``route_after_joern``: skip fuzzing if ``run_fuzzer`` is false.
  * ``route_after_fuzzer``: loop back through ``evasion`` (SOCKS5 rotation) when
    a WAF is detected, bounded by ``max_evasions``.

The ``fuzzer -> evasion -> fuzzer`` cycle is why ``invoke`` uses a recursion
limit: the loop terminates autonomously once the WAF flag is cleared or the
evasion budget is exhausted.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from langgraph.graph import END, START, StateGraph

from .state import AnalysisStage, SpectreState
from .semgrep_node import semgrep_node
from .memory_node import memory_node
from .joern_node import joern_node
from .fuzzer_node import fuzzer_node
from .report_node import report_node
from .targets import fetch_bounty_targets, search_programs
from .evasion import ProxyRotator

logger = logging.getLogger(__name__)

RECURSION_LIMIT = int(os.environ.get("SPECTRE_RECURSION_LIMIT", "25"))


# ---------------------------------------------------------------------------
# Nodes (lightweight orchestration glue)
# ---------------------------------------------------------------------------


def recon_node(state: SpectreState) -> dict[str, Any]:
    """Discover in-scope targets matching ``recon_query`` (no-op if unset)."""
    query = state.get("recon_query", "")
    if not query:
        return {"stage": AnalysisStage.INIT}
    programs = search_programs(fetch_bounty_targets(), query)
    targets = [e.identifier for p in programs for e in p.in_scope]
    logger.info("recon: %d program(s) matched, %d in-scope entries", len(programs), len(targets))
    return {"discovered_targets": targets, "stage": AnalysisStage.INIT}


def evasion_node(state: SpectreState) -> dict[str, Any]:
    """Rotate the SOCKS5 egress and consume the WAF flag (bounded loop)."""
    proxy = ProxyRotator().rotate()
    count = state.get("evasion_count", 0) + 1
    logger.info("evasion: rotated egress proxy=%s (attempt %d)", proxy, count)
    return {"evasion_count": count, "waf_detected": False, "stage": AnalysisStage.FUZZING}


# ---------------------------------------------------------------------------
# Routing functions
# ---------------------------------------------------------------------------


def route_after_semgrep(state: SpectreState) -> str:
    """Advance from Semgrep: query memory only when there are findings."""
    if state.get("semgrep_findings"):
        return "memory"
    if state.get("run_joern", True):
        return "joern"
    if state.get("run_fuzzer", True):
        return "fuzzer"
    return "report"


def route_after_memory(state: SpectreState) -> str:
    """Advance from the memory node to the next enabled analysis stage."""
    if state.get("run_joern", True):
        return "joern"
    if state.get("run_fuzzer", True):
        return "fuzzer"
    return "report"


def route_after_joern(state: SpectreState) -> str:
    """Advance from Joern: fuzz only if enabled, otherwise report."""
    return "fuzzer" if state.get("run_fuzzer", True) else "report"


def route_after_fuzzer(state: SpectreState) -> str:
    """After fuzzing: loop through evasion on WAF detection, else report."""
    if state.get("waf_detected") and state.get("evasion_count", 0) < state.get("max_evasions", 3):
        return "evasion"
    return "report"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph() -> StateGraph:
    """Assemble and compile the SPECTRE state graph."""
    graph = StateGraph(SpectreState)

    graph.add_node("recon", recon_node)
    graph.add_node("semgrep", semgrep_node)
    graph.add_node("memory", memory_node)
    graph.add_node("joern", joern_node)
    graph.add_node("fuzzer", fuzzer_node)
    graph.add_node("evasion", evasion_node)
    graph.add_node("report", report_node)

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "semgrep")

    graph.add_conditional_edges(
        "semgrep",
        route_after_semgrep,
        {"memory": "memory", "joern": "joern", "fuzzer": "fuzzer", "report": "report"},
    )

    graph.add_conditional_edges(
        "memory",
        route_after_memory,
        {"joern": "joern", "fuzzer": "fuzzer", "report": "report"},
    )

    graph.add_conditional_edges(
        "joern",
        route_after_joern,
        {"fuzzer": "fuzzer", "report": "report"},
    )

    graph.add_conditional_edges(
        "fuzzer",
        route_after_fuzzer,
        {"evasion": "evasion", "report": "report"},
    )

    graph.add_edge("evasion", "fuzzer")  # cycle: retry after rotating proxy
    graph.add_edge("report", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------


def run_pipeline(
    repo_path: str,
    *,
    semgrep_config: Optional[str] = None,
    llm_model: Optional[str] = None,
    fuzz_timeout: Optional[int] = None,
    run_joern: bool = True,
    run_fuzzer: bool = True,
    recon_query: Optional[str] = None,
    max_evasions: int = 3,
) -> dict[str, Any]:
    """Execute the full SPECTRE pipeline and return the final state."""
    initial: SpectreState = {
        "repo_path": repo_path,
        "stage": AnalysisStage.INIT,
        "run_joern": run_joern,
        "run_fuzzer": run_fuzzer,
        "max_evasions": max_evasions,
    }
    if semgrep_config:
        initial["semgrep_config"] = semgrep_config
    if llm_model:
        initial["llm_model"] = llm_model
    if fuzz_timeout is not None:
        initial["fuzz_timeout"] = fuzz_timeout
    if recon_query:
        initial["recon_query"] = recon_query

    app = build_graph()
    logger.info("Starting SPECTRE pipeline for %s", repo_path)
    return app.invoke(initial, config={"recursion_limit": RECURSION_LIMIT})


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.graph)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Run the SPECTRE graph.")
    parser.add_argument("repo_path")
    parser.add_argument("--semgrep-config", default=None)
    parser.add_argument("--llm-model", default=None)
    parser.add_argument("--fuzz-timeout", type=int, default=None)
    parser.add_argument("--no-joern", action="store_true")
    parser.add_argument("--no-fuzzer", action="store_true")
    parser.add_argument("--recon-query", default=None)
    args = parser.parse_args()

    result = run_pipeline(
        args.repo_path,
        semgrep_config=args.semgrep_config,
        llm_model=args.llm_model,
        fuzz_timeout=args.fuzz_timeout,
        run_joern=not args.no_joern,
        run_fuzzer=not args.no_fuzzer,
        recon_query=args.recon_query,
    )

    print(result.get("report_markdown", ""))
