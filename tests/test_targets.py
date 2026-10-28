from agents.state import ProgramScope, ScopeEntry
from agents.targets import _entry, _normalize_program, matches_scope, search_programs


def test_entry_extracts_fields():
    raw = {"asset_type": "URL", "asset_identifier": "*.example.com", "max_severity": "critical"}
    e = _entry(raw)
    assert e.asset_type == "URL"
    assert e.identifier == "*.example.com"
    assert e.max_severity == "critical"
    assert e.is_wildcard is True


def test_entry_string_fallback():
    assert _entry("example.com").identifier == "example.com"


def test_matches_scope_exact():
    entries = [ScopeEntry(identifier="example.com")]
    assert matches_scope("example.com", entries) is True
    assert matches_scope("example.com.", entries) is True  # trailing dot
    assert matches_scope("sub.example.com", entries) is False


def test_matches_scope_wildcard():
    entries = [ScopeEntry(identifier="*.example.com")]
    assert matches_scope("foo.example.com", entries) is True
    assert matches_scope("a.b.example.com", entries) is True
    assert matches_scope("example.com", entries) is True  # apex
    assert matches_scope("evil-example.com", entries) is False


def test_matches_scope_case_insensitive():
    entries = [ScopeEntry(identifier="*.Example.COM")]
    assert matches_scope("Foo.Example.Com", entries) is True


def test_normalize_program():
    item = {
        "handle": "acme",
        "name": "Acme",
        "url": "https://hackerone.com/acme",
        "offers_bounties": True,
        "targets": {
            "in_scope": [{"asset_type": "URL", "asset_identifier": "*.acme.com"}],
            "out_of_scope": [{"asset_type": "URL", "asset_identifier": "dev.acme.com"}],
        },
    }
    p = _normalize_program(item, "hackerone")
    assert p.handle == "acme"
    assert p.platform == "hackerone"
    assert p.offers_bounties is True
    assert len(p.in_scope) == 1
    assert p.in_scope[0].identifier == "*.acme.com"
    assert len(p.out_of_scope) == 1


def test_normalize_program_top_level_fallback():
    item = {
        "handle": "acme",
        "in_scope": [{"asset_type": "URL", "asset_identifier": "example.com"}],
        "out_of_scope": [],
    }
    p = _normalize_program(item, "bugcrowd")
    assert len(p.in_scope) == 1
    assert p.in_scope[0].identifier == "example.com"


def test_search_programs():
    a = ProgramScope(name="Acme Corp", handle="acme", platform="hackerone")
    b = ProgramScope(name="Beta", handle="beta", platform="bugcrowd")
    assert len(search_programs([a, b], "acme")) == 1
    assert search_programs([a, b], "acme")[0].name == "Acme Corp"
    assert len(search_programs([a, b], "bugcrowd")) == 1
    assert len(search_programs([a, b], "zzz")) == 0
