import pytest

from agents.joern_node import JoernParseError, _extract_json_array, _parse_results


def test_extract_clean_array():
    assert _extract_json_array('[{"a": 1}]') == [{"a": 1}]


def test_extract_noisy_stdout():
    text = 'WARN: loading cpg\n[{"id": "1"}]\ntrailing log\n'
    assert _extract_json_array(text) == [{"id": "1"}]


def test_extract_empty_string():
    assert _extract_json_array("") == []


def test_extract_invalid_raises():
    with pytest.raises(JoernParseError):
        _extract_json_array("no json here at all")


def test_parse_results():
    data = [
        {
            "id": "abc",
            "label": "taint",
            "method": "main",
            "file": "vuln.c",
            "line": 42,
            "source": "getenv()",
            "sink": "memcpy()",
        }
    ]
    findings = _parse_results(data)
    assert len(findings) == 1
    assert findings[0].line == 42
    assert findings[0].description == "getenv() -> memcpy()"


def test_parse_results_skips_non_dicts():
    findings = _parse_results([{"sink": "x"}, "junk", 42])
    assert len(findings) == 1
    assert findings[0].code == "x"
