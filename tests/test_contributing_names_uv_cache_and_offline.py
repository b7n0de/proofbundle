"""CONTRIBUTING.md names every uv variable the plugin tests take from their caller, and says what it does.

Finding B20, the documentation part (2026-11-09). The plugin tests withhold the caller's environment from every process
they start, apart from the names in FIXED of tests/_plugin_env.py. Two of them are uv's, UV_CACHE_DIR and UV_OFFLINE,
and CI sets both (.github/workflows/ci.yml). A contributor who runs the suite offline or with a cache of their own had
no place in CONTRIBUTING.md that named them. FIXED is read from the syntax tree, not imported, so this test is not a
plugin test and keeps its own caller's environment.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _fixed_uv_names() -> list:
    tree = ast.parse((REPO / "tests" / "_plugin_env.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "FIXED" for t in node.targets):
            return [n for n in ast.literal_eval(node.value) if n.startswith("UV_")]
    raise AssertionError("tests/_plugin_env.py has no FIXED")


def test_the_reader_finds_the_uv_names():
    assert _fixed_uv_names(), "FIXED names no uv variable; this test would pass by finding nothing"


def test_contributing_names_each_uv_name_with_one_sentence_of_its_effect():
    text = " ".join((REPO / "CONTRIBUTING.md").read_text(encoding="utf-8").split())
    for name in _fixed_uv_names():
        saetze = [s for s in re.split(r"(?<=\.)\s", text) if f"`{name}`" in s]
        assert saetze, f"CONTRIBUTING.md does not name `{name}`"
        assert any(len(s.split()) >= 8 for s in saetze), (name, saetze)
