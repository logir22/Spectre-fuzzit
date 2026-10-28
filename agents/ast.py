"""Tree-sitter AST extraction (lazy, fail-open).

Parsing source into a real AST and injecting the relevant subtree into the LLM
context (instead of raw text) reduces hallucination when the model writes PoCs:
it reasons over rigid structure, not prose.

When tree-sitter (and a C++ grammar) is unavailable, we fall back to a
line-numbered window around the target location, which is still useful for PoC
generation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_treesitter: Optional[dict] = None


def _load() -> dict:
    global _treesitter
    if _treesitter is not None:
        return _treesitter
    _treesitter = {"parser": None, "lang": None}
    try:
        from tree_sitter import Language, Parser

        parser = Parser()
        try:
            import tree_sitter_cpp

            parser.language = Language(tree_sitter_cpp.language())
        except Exception as exc:  # noqa: BLE001 - grammar optional
            logger.warning("tree-sitter C++ grammar unavailable: %s", exc)
        _treesitter = {"parser": parser, "lang": None}
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("tree-sitter unavailable (%s); AST context disabled.", exc)
        _treesitter = {"parser": None, "lang": None}
    return _treesitter


def ast_available() -> bool:
    return _load()["parser"] is not None


def window_context(source: str, line: int, n: int = 15) -> str:
    """Return a line-numbered window of ``source`` around ``line`` (1-indexed)."""
    lines = source.splitlines()
    if not lines or line < 1 or line > len(lines):
        return ""
    start = max(1, line - n)
    end = min(len(lines), line + n)
    out = []
    for i in range(start, end + 1):
        marker = ">" if i == line else " "
        out.append(f"{marker}{i:4d}: {lines[i - 1]}")
    return "\n".join(out)


def _enclosing_function(node, line: int) -> Optional[object]:
    """Find the smallest ``function_definition`` node containing ``line``."""
    if node.type in ("function_definition", "function_definition_declarator"):
        start_row = node.start_point[0] + 1
        end_row = node.end_point[0] + 1
        if start_row <= line <= end_row:
            return node
    for child in node.children:
        found = _enclosing_function(child, line)
        if found is not None:
            return found
    return None


def ast_context(file_path: str | Path, line: int, n: int = 15) -> str:
    """Return AST/context for the code at ``file_path:line``.

    Prefers the enclosing function extracted via tree-sitter; falls back to a
    line-numbered window when tree-sitter is unavailable or the file is absent.
    """
    path = Path(file_path)
    if not path.exists():
        return ""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not source:
        return ""

    ts = _load()
    if ts["parser"] is not None:
        try:
            tree = ts["parser"].parse(source.encode("utf-8"))
            func = _enclosing_function(tree.root_node, line)
            if func is not None:
                return func.text.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            logger.warning("tree-sitter parse failed: %s", exc)

    return window_context(source, line, n)
