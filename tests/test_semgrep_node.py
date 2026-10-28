from agents.semgrep_node import _parse_finding
from agents.state import Severity

TAINT_RESULT = {
    "check_id": "cpp.lang.security.buffer-overflow",
    "path": "src/vuln.c",
    "start": {"line": 42, "col": 5},
    "end": {"line": 42, "col": 20},
    "extra": {
        "severity": "HIGH",
        "message": "Buffer overflow via memcpy",
        "lines": "memcpy(buf, src, len);",
        "metadata": {"cwe": "CWE-787"},
        "dataflow_trace": {
            "taint_source": {
                "content": 'getenv("HOME")',
                "location": {"path": "src/vuln.c", "start": {"line": 10, "col": 9}},
            },
            "taint_sink": {
                "content": "memcpy(buf, src, len)",
                "location": {"path": "src/vuln.c", "start": {"line": 42, "col": 5}},
            },
            "intermediate_vars": [
                {
                    "content": "src = env",
                    "location": {"path": "src/vuln.c", "start": {"line": 11, "col": 3}},
                }
            ],
        },
    },
}


def test_parse_taint_finding():
    f = _parse_finding(TAINT_RESULT)
    assert f.rule_id == "cpp.lang.security.buffer-overflow"
    assert f.severity == Severity.HIGH
    assert f.source.path == "src/vuln.c" and f.source.line == 10
    assert f.sink.path == "src/vuln.c" and f.sink.line == 42
    assert len(f.intermediate_vars) == 1
    assert f.code_snippet == "memcpy(buf, src, len);"


def test_parse_finding_without_trace():
    result = {
        "check_id": "r",
        "path": "a.c",
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {"message": "m", "severity": "low"},
    }
    f = _parse_finding(result)
    assert f.source is None
    assert f.sink is None
    assert f.intermediate_vars == []
    assert f.severity == Severity.LOW


def test_parse_unknown_severity_defaults_to_info():
    result = {
        "check_id": "r",
        "path": "a.c",
        "start": {},
        "end": {},
        "extra": {"severity": "bogus"},
    }
    assert _parse_finding(result).severity == Severity.INFO
