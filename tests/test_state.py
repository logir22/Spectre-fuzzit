from agents.state import (
    SemgrepFinding,
    Severity,
    TaintLocation,
    Verdict,
)


def test_signature_full():
    f = SemgrepFinding(
        rule_id="r1",
        path="a.c",
        start_line=10,
        source=TaintLocation(path="a.c", line=3),
        sink=TaintLocation(path="a.c", line=10),
    )
    assert f.signature == "r1|a.c:10|a.c:3->a.c:10"


def test_signature_no_source_sink():
    f = SemgrepFinding(rule_id="r1", path="a.c", start_line=10)
    assert f.signature == "r1|a.c:10|?->?"


def test_severity_parsing():
    assert Severity("HIGH") == Severity.HIGH
    assert Severity.CRITICAL.value == "CRITICAL"


def test_verdict_values():
    assert Verdict.TRUE_POSITIVE.value == "true_positive"
    assert Verdict.FALSE_POSITIVE.value == "false_positive"
