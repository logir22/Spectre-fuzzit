"""Make the ``agents`` package importable and register integration markers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def pytest_addoption(parser):
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests against live Redis/pgvector services.",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: requires live Redis/pgvector services (use --run-integration)"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-integration"):
        return
    skip = pytest.mark.skip(reason="needs --run-integration to run")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
