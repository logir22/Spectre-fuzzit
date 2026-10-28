"""Execution isolation abstraction for untrusted / generated code.

Running fuzzers against memory-unsafe targets (or code emitted by a model) is
dangerous for the host. This module lets SPECTRE run such work inside a
stronger boundary than a plain process:

  * ``none``        — bare ``subprocess`` (default, fastest).
  * ``docker``      — throwaway container (``docker run --rm --network none``).
  * ``gvisor``      — Docker with the gVisor ``runsc`` runtime (kernel-level
                      syscall sandbox; ~millisecond boot).
  * ``firecracker`` — AWS Firecracker MicroVM (jailer/firectl), not wired here.

Selection is via the ``ISOLATION_RUNTIME`` environment variable.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any, Optional

logger = logging.getLogger(__name__)

ISOLATION_RUNTIME = os.environ.get("ISOLATION_RUNTIME", "none")
GVISOR_RUNTIME = os.environ.get("GVISOR_RUNTIME", "runsc")

SUPPORTED_RUNTIMES = ("none", "docker", "gvisor", "firecracker")


def isolation_runtime() -> str:
    return ISOLATION_RUNTIME


def _docker_run(
    cmd: list[str],
    *,
    image: Optional[str],
    runtime_name: Optional[str],
    network: str,
    timeout: Optional[int],
) -> subprocess.CompletedProcess:
    if not image:
        raise ValueError("`image` is required for docker/gvisor isolation")
    if shutil.which("docker") is None:
        raise RuntimeError("docker binary not found; cannot use container isolation")

    argv = ["docker", "run", "--rm", "--network", network]
    if runtime_name:
        argv += ["--runtime", runtime_name]
    argv += [image, *cmd]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def run_sandboxed(
    cmd: list[str],
    *,
    runtime: Optional[str] = None,
    image: Optional[str] = None,
    timeout: Optional[int] = None,
    network: str = "none",
) -> subprocess.CompletedProcess:
    """Run ``cmd`` under the configured isolation runtime."""
    runtime = runtime or ISOLATION_RUNTIME
    if runtime not in SUPPORTED_RUNTIMES:
        raise ValueError(f"Unknown isolation runtime: {runtime!r}")

    if runtime in ("none", "", None):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if runtime == "docker":
        return _docker_run(cmd, image=image, runtime_name=None, network=network, timeout=timeout)
    if runtime == "gvisor":
        return _docker_run(
            cmd, image=image, runtime_name=GVISOR_RUNTIME, network=network, timeout=timeout
        )
    # firecracker
    raise NotImplementedError(
        "Firecracker MicroVM isolation is not implemented; use docker/gvisor "
        "or invoke `jailer`/`firectl` directly."
    )


def describe_isolation() -> dict[str, Any]:
    return {"runtime": ISOLATION_RUNTIME, "supported": list(SUPPORTED_RUNTIMES)}
