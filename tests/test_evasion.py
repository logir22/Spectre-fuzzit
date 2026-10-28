from agents.evasion import ProxyRotator, detect_waf


def test_detect_waf():
    assert detect_waf("HTTP/1.1 403 Forbidden") is True
    assert detect_waf("<html>protected by Cloudflare</html>") is True
    assert detect_waf("HTTP/1.1 200 OK") is False


def test_proxy_rotator_round_robin():
    r = ProxyRotator(proxies=["socks5://a:1", "socks5://b:2"])
    assert r.available == 2
    assert r.rotate() == "socks5://a:1"
    assert r.rotate() == "socks5://b:2"
    assert r.rotate() == "socks5://a:1"


def test_proxy_rotator_empty():
    r = ProxyRotator(proxies=[])
    assert r.available == 0
    assert r.current is None
