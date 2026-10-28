"""Fuzzing node: AFL++ + AddressSanitizer.

Compiles C/C++ sources with ``afl-clang-fast++`` instrumented with ASAN, then
runs ``afl-fuzz`` for a short time-boxed session (default 60s) and collects
the resulting crash inputs along with their ASAN reports.

Subprocess handling follows the same defensive pattern as the other nodes:
distinct exceptions for missing binaries, compile failures, timeouts and
unparseable statistics, so the graph can route a fuzzing failure without
crashing the whole run.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from .state import AnalysisStage, CrashReport, FuzzResult, SpectreState
from .dedup import CrashDeduplicator, crash_signature
from .events import NEW_CRASH, EventBus
from .seedgen import build_afl_dictionary, findings_to_tokens
from . import telemetry

logger = logging.getLogger(__name__)

AFL_FUZZ_BIN = os.environ.get("AFL_FUZZ_BIN", "afl-fuzz")
AFL_CXX = os.environ.get("AFL_CXX", "afl-clang-fast++")
AFL_CC = os.environ.get("AFL_CC", "afl-clang-fast")

FUZZ_TIME_LIMIT = int(os.environ.get("FUZZ_TIME_LIMIT", "60"))
FUZZ_MEM_LIMIT = os.environ.get("FUZZ_MEM_LIMIT", "none")
FUZZ_ARGS = os.environ.get("FUZZ_ARGS", "")
FUZZ_EXTRA_FLAGS = os.environ.get("FUZZ_EXTRA_FLAGS", "")

DEFAULT_FUZZ_DRIVER = os.environ.get(
    "FUZZ_DRIVER",
    str(Path(__file__).resolve().parent.parent / "scripts" / "standalone_fuzz_driver.cc"),
)

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".C"}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FuzzerError(RuntimeError):
    """Base error for fuzzing failures."""


class FuzzerNotFoundError(FuzzerError):
    """Raised when a required AFL binary is missing."""


class FuzzerCompileError(FuzzerError):
    """Raised when compiling the target with afl-clang-fast++ fails."""

    def __init__(self, message: str, returncode: int, stderr: str) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class FuzzerTimeoutError(FuzzerError):
    """Raised when afl-fuzz exceeds the safety timeout."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_binary(binary: str) -> str:
    if shutil.which(binary) is None:
        raise FuzzerNotFoundError(
            f"AFL binary '{binary}' not found on PATH. "
            "Install AFL++ or set the corresponding *_BIN environment variable."
        )
    return binary


def find_sources(repo_path: str | Path) -> list[str]:
    """Discover C/C++ source files in the repository."""
    return sorted(
        str(p)
        for p in Path(repo_path).rglob("*")
        if p.suffix in SOURCE_EXTS and p.is_file()
    )


def create_seed_corpus(corpus_dir: str | Path, content: Optional[bytes] = None) -> Path:
    """Create a seed corpus directory with a single minimal input file."""
    corpus_dir = Path(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    seed = corpus_dir / "seed"
    seed.write_bytes(content if content is not None else b"A" * 64 + b"\n")
    return corpus_dir


def _parse_signal(name: str) -> Optional[int]:
    match = re.search(r"sig:(\d+)", name)
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def compile_target(
    sources: list[str | Path],
    output: str | Path,
    cpp: bool = True,
    timeout: int = 180,
) -> Path:
    """Compile the given sources into an ASAN-instrumented AFL binary."""
    compiler = AFL_CXX if cpp else AFL_CC
    _require_binary(compiler)

    flags = ["-fsanitize=address", "-g", "-O1", "-fno-omit-frame-pointer"]
    flags += FUZZ_EXTRA_FLAGS.split()

    output = Path(output)
    cmd = [compiler, *flags, *[str(s) for s in sources], "-o", str(output)]
    logger.info("Compiling fuzz target: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise FuzzerTimeoutError(f"Compilation exceeded {timeout}s.") from exc
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise FuzzerNotFoundError(f"Could not execute '{compiler}'.") from exc
        raise FuzzerError(f"Compilation could not be executed: {exc}") from exc

    if proc.returncode != 0:
        raise FuzzerCompileError(
            f"Compilation failed with exit code {proc.returncode}",
            proc.returncode,
            proc.stderr or proc.stdout or "",
        )

    if not output.exists():
        raise FuzzerError(f"Compilation produced no binary at {output}")

    return output


def compile_harness_target(
    harness: str | Path,
    output: str | Path,
    driver: str | Path = DEFAULT_FUZZ_DRIVER,
    extra_sources: Optional[list[str]] = None,
    extra_flags: Optional[list[str]] = None,
    timeout: int = 300,
) -> Path:
    """Compile an OSS-Fuzz harness (LLVMFuzzerTestOneInput) with an AFL driver.

    Links ``harness.cc`` + ``standalone_fuzz_driver.cc`` (which provides
    ``main``) plus any ``extra_sources`` (pre-compiled objects / static libs).
    Use ``extra_flags`` for include paths and link flags.
    """
    compiler = AFL_CXX

    harness = Path(harness)
    driver = Path(driver)
    if not harness.exists():
        raise FuzzerError(f"Harness not found: {harness}")
    if not driver.exists():
        raise FuzzerError(f"AFL driver not found: {driver}")

    _require_binary(compiler)

    flags = ["-fsanitize=address", "-g", "-O1", "-fno-omit-frame-pointer"]
    flags += FUZZ_EXTRA_FLAGS.split()
    if extra_flags:
        flags += extra_flags

    sources = [str(harness), str(driver)] + [str(s) for s in (extra_sources or [])]
    output = Path(output)
    cmd = [compiler, *flags, *sources, "-o", str(output)]
    logger.info("Compiling harness target: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise FuzzerTimeoutError(f"Harness compilation exceeded {timeout}s.") from exc
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise FuzzerNotFoundError(f"Could not execute '{compiler}'.") from exc
        raise FuzzerError(f"Harness compilation could not be executed: {exc}") from exc

    if proc.returncode != 0:
        raise FuzzerCompileError(
            f"Harness compilation failed with exit code {proc.returncode}",
            proc.returncode,
            proc.stderr or proc.stdout or "",
        )

    if not output.exists():
        raise FuzzerError(f"Harness compilation produced no binary at {output}")

    return output


def _fuzz_and_collect(
    binary: str | Path,
    corpus: str | Path,
    outdir: str | Path,
    time_limit: int,
    fuzz_args: Optional[str],
    dictionary: Optional[str | Path] = None,
) -> FuzzResult:
    """Run afl-fuzz and build the aggregate FuzzResult."""
    stats = run_afl_fuzz(
        binary, corpus, outdir, time_limit=time_limit, fuzz_args=fuzz_args, dictionary=dictionary
    )
    crashes = collect_crashes(outdir, binary, fuzz_args=fuzz_args)
    return FuzzResult(
        total_execs=stats.get("execs_done", 0),
        execs_per_sec=float(stats.get("execs_per_sec", 0.0) or 0.0),
        unique_crashes=max(int(stats.get("unique_crashes", 0)), len(crashes)),
        hangs=stats.get("unique_hangs", 0),
        corpus_count=stats.get("corpus_count", 0),
        crashes=crashes,
        output_dir=str(outdir),
    )


def run_afl_fuzz(
    binary: str | Path,
    corpus_dir: str | Path,
    outdir: str | Path,
    time_limit: int = FUZZ_TIME_LIMIT,
    fuzz_args: Optional[str] = None,
    dictionary: Optional[str | Path] = None,
) -> dict[str, Any]:
    """Run afl-fuzz for ``time_limit`` seconds and return parsed stats."""
    _require_binary(AFL_FUZZ_BIN)

    outdir = Path(outdir)
    args = fuzz_args if fuzz_args is not None else FUZZ_ARGS

    cmd = [
        AFL_FUZZ_BIN,
        "-i", str(corpus_dir),
        "-o", str(outdir),
        "-V", str(time_limit),
        "-m", FUZZ_MEM_LIMIT,
    ]
    if dictionary:
        cmd += ["-x", str(dictionary)]
    cmd += ["--", str(binary)]
    if args:
        cmd.extend(args.split())

    env = {
        **os.environ,
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_UI": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_leaks=0",
    }

    logger.info("Running afl-fuzz: %s", " ".join(cmd))
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=time_limit + 60,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise FuzzerTimeoutError(f"afl-fuzz exceeded {time_limit + 60}s.") from exc
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise FuzzerNotFoundError(f"Could not execute '{AFL_FUZZ_BIN}'.") from exc
        raise FuzzerError(f"afl-fuzz could not be executed: {exc}") from exc

    return _parse_stats(outdir / "default" / "fuzzer_stats")


def _parse_stats(stats_file: Path) -> dict[str, Any]:
    if not stats_file.exists():
        return {}

    stats: dict[str, Any] = {}
    for line in stats_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        try:
            stats[key] = int(value)
        except ValueError:
            try:
                stats[key] = float(value)
            except ValueError:
                stats[key] = value
    return stats


def _reproduce(
    binary: str | Path,
    crash_file: Path,
    use_file_arg: bool,
    fuzz_args: str,
) -> tuple[str, list[str]]:
    """Re-run the crashing input to capture the ASAN report."""
    env = {
        **os.environ,
        "ASAN_OPTIONS": "abort_on_error=1:symbolize=1:detect_leaks=0",
    }

    try:
        if use_file_arg:
            argv = [str(binary)] + [a.replace("@@", str(crash_file)) for a in fuzz_args.split()]
            proc = subprocess.run(argv, capture_output=True, timeout=15, env=env)
        else:
            data = crash_file.read_bytes()
            proc = subprocess.run([str(binary)], input=data, capture_output=True, timeout=15, env=env)
    except (subprocess.TimeoutExpired, OSError):
        return "", []

    raw = (proc.stderr or b"") + b"\n" + (proc.stdout or b"")
    text = raw.decode("utf-8", errors="replace").strip()
    trace = [ln for ln in text.splitlines() if re.search(r"#\d+\s+0x", ln)]
    return text, trace


def collect_crashes(
    outdir: str | Path,
    binary: str | Path,
    fuzz_args: Optional[str] = None,
) -> list[CrashReport]:
    """Enumerate crash inputs produced by afl-fuzz and their ASAN reports."""
    crash_dir = Path(outdir) / "default" / "crashes"
    if not crash_dir.exists():
        return []

    args = fuzz_args if fuzz_args is not None else FUZZ_ARGS
    use_file_arg = "@@" in args

    crashes: list[CrashReport] = []
    for crash_file in sorted(crash_dir.iterdir()):
        if not crash_file.name.startswith("id:"):
            continue
        asan_output, stack_trace = _reproduce(binary, crash_file, use_file_arg, args)
        crashes.append(
            CrashReport(
                crash_id=crash_file.name,
                binary_path=str(binary),
                input_file=str(crash_file),
                signal=_parse_signal(crash_file.name),
                asan_output=asan_output,
                stack_trace=stack_trace,
            )
        )
    return crashes


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_fuzzer(
    repo_path: str | Path,
    time_limit: int = FUZZ_TIME_LIMIT,
    workdir: Optional[str | Path] = None,
    sources: Optional[list[str]] = None,
    seed_dir: Optional[str | Path] = None,
    fuzz_args: Optional[str] = None,
    harness: Optional[str | Path] = None,
    driver: Optional[str | Path] = None,
    extra_sources: Optional[list[str]] = None,
    extra_flags: Optional[list[str]] = None,
    dictionary: Optional[str | Path] = None,
) -> FuzzResult:
    """Full fuzzing pipeline.

    Two modes:

    1. Single-file target (default): discover C/C++ sources under
       ``repo_path`` and compile them together as one executable.
    2. OSS-Fuzz harness: when ``harness`` is provided, compile
       ``harness`` + the AFL driver (``main``) plus ``extra_sources``
       (pre-built objects / static libs), with ``extra_flags`` for
       include/link options.
    """
    repo_path = Path(repo_path).resolve()
    if not repo_path.exists():
        raise FuzzerError(f"Target path does not exist: {repo_path}")

    if workdir:
        tmpdir = Path(workdir)
        tmpdir.mkdir(parents=True, exist_ok=True)
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix="spectre_fuzz_"))

    try:
        if harness:
            binary = compile_harness_target(
                harness,
                tmpdir / "target",
                driver=driver or DEFAULT_FUZZ_DRIVER,
                extra_sources=extra_sources,
                extra_flags=extra_flags,
            )
        else:
            resolved_sources = [Path(s) for s in (sources or find_sources(repo_path))]
            if not resolved_sources:
                logger.info("No C/C++ sources found; skipping fuzzing.")
                return FuzzResult()
            cpp = any(s.suffix in {".cc", ".cpp", ".cxx"} for s in resolved_sources)
            binary = compile_target(resolved_sources, tmpdir / "target", cpp=cpp)

        corpus = Path(seed_dir) if seed_dir else create_seed_corpus(tmpdir / "corpus")
        outdir = tmpdir / "afl_out"
        return _fuzz_and_collect(binary, corpus, outdir, time_limit, fuzz_args, dictionary)
    finally:
        if not workdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def fuzzer_node(state: SpectreState) -> dict[str, Any]:
    """LangGraph node: fuzz the target and emit the crash report set."""
    repo_path = state.get("repo_path", "")
    time_limit = state.get("fuzz_timeout", FUZZ_TIME_LIMIT)
    target_files = state.get("target_files", [])
    harness = state.get("fuzzer_harness") or None
    driver = state.get("fuzzer_driver") or None

    if not repo_path:
        return {
            "fuzz_result": FuzzResult(),
            "crash_reports": [],
            "error": "fuzzer_node: 'repo_path' not provided in state.",
            "stage": AnalysisStage.FUZZING,
        }

    # Directed fuzzing: build an AFL dictionary from upstream SAST findings.
    dict_path: Optional[str] = None
    tokens = findings_to_tokens(state.get("semgrep_findings", []), state.get("joern_findings", []))
    if tokens:
        fd, dict_path = tempfile.mkstemp(prefix="spectre_", suffix=".dict")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(build_afl_dictionary(tokens))

    try:
        with telemetry.span("fuzzer_node", repo=repo_path, time_limit=time_limit):
            result = run_fuzzer(
                repo_path,
                time_limit=time_limit,
                sources=target_files or None,
                harness=harness,
                driver=driver,
                dictionary=dict_path,
            )
    except FuzzerError as exc:
        logger.error("Fuzzer node failed: %s", exc)
        return {
            "fuzz_result": FuzzResult(),
            "crash_reports": [],
            "error": str(exc),
            "stage": AnalysisStage.FUZZING,
        }
    except Exception as exc:  # noqa: BLE001 - safety net, never crash the graph
        logger.exception("Fuzzer node raised an unexpected error")
        return {
            "fuzz_result": FuzzResult(),
            "crash_reports": [],
            "error": f"fuzzer_node unexpected error: {exc}",
            "stage": AnalysisStage.FUZZING,
        }
    finally:
        if dict_path:
            try:
                os.unlink(dict_path)
            except OSError:
                pass

    # Deduplicate crashes by normalized stack trace and publish new ones to
    # the event bus so the AI triage worker can consume them at its own pace.
    dedup = CrashDeduplicator()
    new_crashes: list[CrashReport] = []
    for crash in result.crashes:
        telemetry.counter("spectre.crashes.total")
        is_new, _count = dedup.register(crash)
        if is_new:
            new_crashes.append(crash)
            telemetry.counter("spectre.crashes.unique")
        else:
            telemetry.counter("spectre.crashes.duplicate")
    telemetry.histogram("spectre.fuzz.execs", float(result.total_execs))

    bus = EventBus()
    for crash in new_crashes:
        bus.publish(
            NEW_CRASH,
            {
                "crash_id": crash.crash_id,
                "signal": crash.signal,
                "signature": crash_signature(crash),
                "input": crash.input_file,
            },
        )

    return {
        "fuzz_result": result,
        "crash_reports": new_crashes,
        "stage": AnalysisStage.FUZZING,
    }


# ---------------------------------------------------------------------------
# Standalone invocation (python -m agents.fuzzer_node)
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Fuzz a C/C++ target with AFL++.")
    parser.add_argument("repo_path", help="Directory containing C/C++ sources.")
    parser.add_argument("--time-limit", type=int, default=FUZZ_TIME_LIMIT)
    parser.add_argument("--seed-dir", default=None)
    parser.add_argument("--fuzz-args", default=None, help='AFL args, e.g. "@@" for file-input targets.')
    parser.add_argument("--harness", default=None, help="OSS-Fuzz harness (.cc) with LLVMFuzzerTestOneInput.")
    parser.add_argument("--driver", default=None, help="AFL driver .cc providing main (default: scripts/standalone_fuzz_driver.cc).")
    parser.add_argument("--extra-source", action="append", default=[], help="Additional object/lib to link (repeatable).")
    parser.add_argument("--extra-flag", action="append", default=[], help="Extra compile/link flag (repeatable).")
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    workdir = None
    if args.keep_workdir:
        workdir = Path(tempfile.mkdtemp(prefix="spectre_fuzz_"))
        print(f"Workdir: {workdir}")

    result = run_fuzzer(
        args.repo_path,
        time_limit=args.time_limit,
        workdir=workdir,
        seed_dir=args.seed_dir,
        fuzz_args=args.fuzz_args,
        harness=args.harness,
        driver=args.driver,
        extra_sources=args.extra_source or None,
        extra_flags=args.extra_flag or None,
    )
    print(result.model_dump_json(indent=2))
