from agents.report_node import _build_context, _select_findings, build_poc, fallback_report
from agents.state import CrashReport, SemgrepFinding, Severity, SpectreState


def test_select_filters_cached_false_positive():
    f = SemgrepFinding(rule_id="r", severity=Severity.HIGH, path="a.c", start_line=1)
    state = SpectreState(
        repo_path="/x",
        semgrep_findings=[f],
        false_positives=[f.signature],
    )
    semgrep, _, _, _ = _select_findings(state)
    assert semgrep == []


def test_select_keeps_non_fp():
    f = SemgrepFinding(rule_id="r", severity=Severity.HIGH, path="a.c", start_line=1)
    state = SpectreState(repo_path="/x", semgrep_findings=[f])
    semgrep, _, _, _ = _select_findings(state)
    assert len(semgrep) == 1


def test_build_context_contains_target():
    ctx = _build_context("/tmp/x", [], [], [], None)
    assert '"target": "/tmp/x"' in ctx


def test_build_context_serializes_findings():
    f = SemgrepFinding(
        rule_id="r", severity=Severity.HIGH, path="a.c", start_line=1, message="boom"
    )
    ctx = _build_context("/x", [f], [], [], None)
    assert '"rule": "r"' in ctx
    assert '"message": "boom"' in ctx


def test_fallback_report_no_findings():
    out = fallback_report("/x", [], [], [], None)
    assert "No vulnerabilities" in out


def test_fallback_report_with_findings_includes_sections():
    f = SemgrepFinding(rule_id="r", severity=Severity.HIGH, path="a.c", start_line=1)
    out = fallback_report("/x", [f], [], [], None)
    assert "Static Analysis — Semgrep" in out
    assert "r — HIGH" in out


def test_build_poc():
    c = CrashReport(
        crash_id="id:1",
        signal=6,
        binary_path="./target",
        input_file="/tmp/in",
        asan_output="ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1\n...",
    )
    poc = build_poc(c)
    assert "signal 6" in poc
    assert "stack-buffer-overflow" in poc
    assert "./target < /tmp/in" in poc


def test_fallback_report_has_standard_sections():
    c = CrashReport(
        crash_id="id:1",
        signal=6,
        binary_path="./target",
        input_file="/tmp/in",
        asan_output="ERROR: AddressSanitizer: stack-buffer-overflow",
        stack_trace=["#0 0x1 in foo"],
    )
    out = fallback_report("/x", [], [], [c], None)
    assert "## Summary" in out
    assert "## Proof of Concept" in out
    assert "## Impact" in out
