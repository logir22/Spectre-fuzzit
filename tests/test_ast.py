from agents.ast import ast_context, window_context

SAMPLE = """\
int foo(int x) {
  int y = x * 2;
  return y + 1;
}
"""


def test_window_context_marks_target():
    out = window_context("line1\nline2\nline3\n", 2, n=1)
    assert ">   2: line2" in out
    assert "    1: line1" in out


def test_window_context_empty():
    assert window_context("", 1) == ""


def test_window_context_out_of_range():
    assert window_context("a\nb\n", 99) == ""


def test_ast_context_falls_back_to_window(tmp_path):
    p = tmp_path / "a.c"
    p.write_text(SAMPLE)
    # tree-sitter may or may not be installed; ast_context always returns text
    out = ast_context(str(p), 2)
    assert out != ""
    assert "int y = x * 2;" in out


def test_ast_context_missing_file(tmp_path):
    assert ast_context(str(tmp_path / "nope.c"), 1) == ""
