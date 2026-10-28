from agents.dedup import CrashDeduplicator, crash_signature, normalize_frame
from agents.state import CrashReport


def _crash(frames, asan=""):
    return CrashReport(crash_id="id:1", stack_trace=frames, asan_output=asan)


def test_normalize_frame_strips_addresses():
    f = "#0 0x7f1234 in __asan_memcpy (BuildId: abc) /lib/x.so+0x1234"
    n = normalize_frame(f)
    assert "0x7f1234" not in n
    assert "BuildId" not in n


def test_signature_stable_across_addresses():
    a = _crash(["#0 0x1000 in memcpy", "#1 0x2000 in LLVMFuzzerTestOneInput"])
    b = _crash(["#0 0xAAAA in memcpy", "#1 0xBBBB in LLVMFuzzerTestOneInput"])
    assert crash_signature(a) == crash_signature(b)


def test_signature_differs_for_different_root_cause():
    a = _crash(["#0 0x1000 in memcpy", "#1 0x2000 in foo"])
    b = _crash(["#0 0x1000 in free", "#1 0x2000 in bar"])
    assert crash_signature(a) != crash_signature(b)


def test_signature_falls_back_to_asan_first_line():
    a = _crash([], asan="ERROR: AddressSanitizer: heap-buffer-overflow\nmore")
    b = _crash([], asan="ERROR: AddressSanitizer: heap-buffer-overflow\nmore2")
    assert crash_signature(a) == crash_signature(b)


def test_dedup_registers_first_as_new():
    d = CrashDeduplicator(window_seconds=100)
    crash = _crash(["#0 0x1 in foo"])
    assert d.register(crash) == (True, 1)
    assert d.register(crash) == (False, 2)
    assert d.register(crash) == (False, 3)
    assert d.unique_count() == 1


def test_dedup_window_expiry(tmp_path):
    state = tmp_path / "dedup.json"
    d = CrashDeduplicator(window_seconds=0, state_file=state)
    crash = _crash(["#0 0x1 in foo"])
    assert d.register(crash) == (True, 1)
    # window=0 => previous entry is always expired => seen as new again
    assert d.register(crash) == (True, 1)
