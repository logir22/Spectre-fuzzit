"""Pydantic schemas and LangGraph state for SPECTRE.

This module defines the canonical data structures shared by every agent
node. Individual findings are modeled as Pydantic models so they can be
validated, serialized, and (for the memory node) embedded into pgvector.
The LangGraph state itself is a ``TypedDict`` whose list fields use
reducer annotations so multiple nodes can safely append to the same list.
"""

from __future__ import annotations

import operator
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import TypedDict


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Normalized severity scale shared across Semgrep, Joern and the LLM."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AnalysisStage(str, Enum):
    """Progression markers written into the graph state for observability."""

    INIT = "init"
    SEMGREP = "semgrep"
    MEMORY = "memory"
    JOERN = "joern"
    FUZZING = "fuzzing"
    REPORT = "report"
    DONE = "done"


class Verdict(str, Enum):
    """Final disposition of a candidate finding."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"
    NEEDS_REVIEW = "needs_review"


# ---------------------------------------------------------------------------
# Finding models
# ---------------------------------------------------------------------------


class TaintLocation(BaseModel):
    """A single hop in a dataflow trace (source, sink or intermediate var)."""

    model_config = ConfigDict(extra="allow")

    content: Optional[str] = None
    path: Optional[str] = None
    line: Optional[int] = None
    col: Optional[int] = None

    def __str__(self) -> str:  # pragma: no cover - display helper
        where = f"{self.path}:{self.line}" if self.path else "?"
        return f"{self.content or ''}  [{where}]"


class SemgrepFinding(BaseModel):
    """A finding produced by a Semgrep scan (taint-mode aware)."""

    model_config = ConfigDict(extra="allow")

    rule_id: str
    severity: Severity = Severity.INFO
    message: str = ""
    path: str = ""
    start_line: int = 0
    end_line: int = 0
    source: Optional[TaintLocation] = None
    sink: Optional[TaintLocation] = None
    intermediate_vars: list[TaintLocation] = Field(default_factory=list)
    code_snippet: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def signature(self) -> str:
        """Stable fingerprint for false-positive caching and de-duplication."""
        src = f"{self.source.path}:{self.source.line}" if self.source else "?"
        sink = f"{self.sink.path}:{self.sink.line}" if self.sink else "?"
        return f"{self.rule_id}|{self.path}:{self.start_line}|{src}->{sink}"


class JoernFinding(BaseModel):
    """A finding surfaced from the Joern Code Property Graph traversal."""

    model_config = ConfigDict(extra="allow")

    node_id: str = ""
    label: str = ""
    code: str = ""
    method: str = ""
    file: str = ""
    line: Optional[int] = None
    description: str = ""


class CrashReport(BaseModel):
    """A single crash discovered by the fuzzing node."""

    model_config = ConfigDict(extra="allow")

    crash_id: str
    binary_path: str = ""
    input_file: str = ""
    signal: Optional[int] = None
    asan_output: str = ""
    stack_trace: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FuzzResult(BaseModel):
    """Aggregate summary of an AFL++ fuzzing session."""

    model_config = ConfigDict(extra="allow")

    total_execs: int = 0
    execs_per_sec: float = 0.0
    unique_crashes: int = 0
    hangs: int = 0
    corpus_count: int = 0
    crashes: list[CrashReport] = Field(default_factory=list)
    output_dir: str = ""


class MemoryMatch(BaseModel):
    """A similarity hit returned by the pgvector false-positive cache."""

    model_config = ConfigDict(extra="allow")

    signature: str = ""
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = 0.0
    distance: float = 0.0
    cached_report: str = ""


# ---------------------------------------------------------------------------
# Target discovery models
# ---------------------------------------------------------------------------


class ScopeEntry(BaseModel):
    """A single in/out-of-scope asset from a bounty program."""

    model_config = ConfigDict(extra="allow")

    asset_type: str = ""
    identifier: str = ""
    max_severity: str = ""

    @property
    def is_wildcard(self) -> bool:
        return self.identifier.startswith("*.")


class ProgramScope(BaseModel):
    """A bounty program with its normalized in/out-of-scope assets."""

    model_config = ConfigDict(extra="allow")

    handle: str = ""
    name: str = ""
    platform: str = ""
    url: str = ""
    offers_bounties: bool = False
    in_scope: list[ScopeEntry] = Field(default_factory=list)
    out_of_scope: list[ScopeEntry] = Field(default_factory=list)


class ChaosProgram(BaseModel):
    """A program entry from the ProjectDiscovery Chaos dataset."""

    model_config = ConfigDict(extra="allow")

    name: str = ""
    url: str = ""
    platform: str = ""
    bounty: bool = False
    domains: int = 0


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------


class SpectreState(TypedDict, total=False):
    """Canonical state threaded through every node in the graph.

    List fields are ``Annotated`` with ``operator.add`` so LangGraph merges
    (rather than overwrites) the values returned by parallel nodes.
    """

    # --- inputs ---
    repo_path: str
    config_dir: str
    semgrep_config: str
    llm_model: str
    fuzz_timeout: int
    run_joern: bool
    run_fuzzer: bool
    fuzzer_harness: str
    fuzzer_driver: str
    recon_query: str
    max_evasions: int
    waf_detected: bool
    evasion_count: int

    # --- accumulated outputs (reducer: concatenate) ---
    target_files: Annotated[list[str], operator.add]
    semgrep_findings: Annotated[list[SemgrepFinding], operator.add]
    joern_findings: Annotated[list[JoernFinding], operator.add]
    crash_reports: Annotated[list[CrashReport], operator.add]
    memory_matches: Annotated[list[MemoryMatch], operator.add]
    confirmed: Annotated[list[SemgrepFinding], operator.add]
    false_positives: Annotated[list[str], operator.add]
    discovered_targets: Annotated[list[str], operator.add]

    # --- single-value fields (overwritten) ---
    fuzz_result: Optional[FuzzResult]
    report_markdown: str
    error: Optional[str]
    stage: AnalysisStage
