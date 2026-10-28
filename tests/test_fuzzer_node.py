from pathlib import Path

import pytest

from agents.fuzzer_node import _parse_signal, _parse_stats, find_sources


def test_parse_signal():
    assert _parse_signal("id:000000,sig:06,src:000000,time:123") == 6
    assert _parse_signal("id:000000,src:000000") is None


def test_parse_stats(tmp_path):
    stats_file = tmp_path / "fuzzer_stats"
    stats_file.write_text(
        "execs_done : 12345\n"
        "execs_per_sec : 205.75\n"
        "unique_crashes : 2\n"
        "unique_hangs : 0\n"
        "corpus_count : 87\n"
        "start_time : 0\n"
    )
    stats = _parse_stats(stats_file)
    assert stats["execs_done"] == 12345
    assert stats["execs_per_sec"] == 205.75
    assert stats["unique_crashes"] == 2
    assert stats["corpus_count"] == 87


def test_parse_stats_missing_file(tmp_path):
    assert _parse_stats(tmp_path / "does_not_exist") == {}


def test_find_sources(tmp_path):
    (tmp_path / "a.c").write_text("")
    (tmp_path / "b.cpp").write_text("")
    (tmp_path / "c.h").write_text("")
    (tmp_path / "d.txt").write_text("")
    found = {Path(p).name for p in find_sources(tmp_path)}
    assert found == {"a.c", "b.cpp"}


def test_default_driver_exists():
    from agents.fuzzer_node import DEFAULT_FUZZ_DRIVER

    assert Path(DEFAULT_FUZZ_DRIVER).exists()


def test_harness_not_found_raises(tmp_path):
    from agents.fuzzer_node import FuzzerError, run_fuzzer

    with pytest.raises(FuzzerError, match="Harness not found"):
        run_fuzzer(str(tmp_path), harness=str(tmp_path / "missing.cc"))
