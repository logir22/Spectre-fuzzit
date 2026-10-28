import pytest

from agents.graph import (
    build_graph,
    evasion_node,
    recon_node,
    route_after_fuzzer,
    route_after_joern,
    route_after_memory,
    route_after_semgrep,
)


def test_route_semgrep_with_findings():
    assert route_after_semgrep({"semgrep_findings": [1]}) == "memory"


def test_route_semgrep_no_findings_goes_joern():
    assert route_after_semgrep({}) == "joern"


def test_route_semgrep_no_joern_goes_fuzzer():
    assert route_after_semgrep({"run_joern": False}) == "fuzzer"


def test_route_semgrep_all_disabled_goes_report():
    assert route_after_semgrep({"run_joern": False, "run_fuzzer": False}) == "report"


def test_route_after_memory():
    assert route_after_memory({}) == "joern"
    assert route_after_memory({"run_joern": False}) == "fuzzer"
    assert route_after_memory({"run_joern": False, "run_fuzzer": False}) == "report"


def test_route_after_joern():
    assert route_after_joern({}) == "fuzzer"
    assert route_after_joern({"run_fuzzer": False}) == "report"


def test_graph_compiles():
    graph = build_graph()
    assert graph is not None


def test_route_after_fuzzer_evasion():
    state = {"waf_detected": True, "evasion_count": 0, "max_evasions": 3}
    assert route_after_fuzzer(state) == "evasion"


def test_route_after_fuzzer_budget_exhausted():
    state = {"waf_detected": True, "evasion_count": 3, "max_evasions": 3}
    assert route_after_fuzzer(state) == "report"


def test_route_after_fuzzer_no_waf():
    assert route_after_fuzzer({}) == "report"


def test_recon_node_noop_without_query():
    out = recon_node({})
    assert "discovered_targets" not in out or out.get("discovered_targets") == []


def test_evasion_node_rotates_and_counts():
    out = evasion_node({"evasion_count": 0})
    assert out["evasion_count"] == 1
    assert out["waf_detected"] is False
