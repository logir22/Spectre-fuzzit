from agents.vectordb import fingerprint, fingerprint_code


def test_fingerprint_stable():
    assert fingerprint("abc") == fingerprint("abc")
    assert fingerprint("abc") != fingerprint("abd")
    assert len(fingerprint("x")) == 32


def test_fingerprint_code_namespaces():
    assert fingerprint_code("a.c", "int x;") == "a.c@" + fingerprint("int x;")
