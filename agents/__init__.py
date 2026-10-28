"""SPECTRE agent package.

Exports the canonical state schema and finding models shared by every
agent node in the LangGraph workflow.
"""

from .state import (
    AnalysisStage,
    CrashReport,
    FuzzResult,
    JoernFinding,
    MemoryMatch,
    SemgrepFinding,
    Severity,
    SpectreState,
    TaintLocation,
    Verdict,
)

__all__ = [
    "AnalysisStage",
    "CrashReport",
    "FuzzResult",
    "JoernFinding",
    "MemoryMatch",
    "SemgrepFinding",
    "Severity",
    "SpectreState",
    "TaintLocation",
    "Verdict",
]
