from agents.subenum import (
    brute_subdomains,
    enumerate_subdomains,
    is_wildcard,
    normalize_domain,
)


def test_normalize_domain():
    assert normalize_domain("*.shopify.com") == "shopify.com"
    assert normalize_domain("SHOPIFY.COM.") == "shopify.com"
    assert normalize_domain("  api.example.com  ") == "api.example.com"
    assert normalize_domain("") == ""


def test_is_wildcard():
    assert is_wildcard("*.example.com") is True
    assert is_wildcard("example.com") is False
    assert is_wildcard("") is False


def test_brute_subdomains_uses_wordlist():
    # force a wordlist to avoid network DNS lookups
    subs = brute_subdomains("example.com", wordlist=["www", "api"])
    # result depends on DNS; just verify it returns a list (possibly empty)
    assert isinstance(subs, list)


def test_enumerate_empty_domain():
    assert enumerate_subdomains("") == []
