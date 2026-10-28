from agents.seedgen import (
    build_afl_dictionary,
    build_seed_plan,
    extract_tokens,
    findings_to_tokens,
)
from agents.state import SemgrepFinding, TaintLocation


def test_extract_tokens():
    src = 'if (n == 0x7f454c46 || magic == 123456) printf("%s-%d", "ELFMAG", n);'
    tokens = extract_tokens(src)
    assert "0x7f454c46" in tokens
    assert "123456" in tokens
    assert "ELFMAG" in tokens
    assert "%s" in tokens
    assert "%d" in tokens


def test_build_afl_dictionary():
    tokens = {"0xdeadbeef", "FLAG"}
    text = build_afl_dictionary(tokens)
    assert '="FLAG"' in text
    assert '="0xdeadbeef"' in text


def test_findings_to_tokens():
    f = SemgrepFinding(
        rule_id="r",
        path="a.c",
        start_line=1,
        source=TaintLocation(content='getenv("HOME")'),
        sink=TaintLocation(content="memcpy(buf, 0x1234)"),
        code_snippet="memcpy(dst, src, 0x400);",
    )
    tokens = findings_to_tokens([f], [])
    assert "HOME" in tokens
    assert "0x1234" in tokens
    assert "0x400" in tokens


def test_build_seed_plan():
    f = SemgrepFinding(rule_id="r", path="a.c", start_line=3)
    plan = build_seed_plan([f], [])
    assert "tokens" in plan
    assert plan["targets"][0]["line"] == 3
