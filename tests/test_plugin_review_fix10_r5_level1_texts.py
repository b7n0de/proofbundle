"""Review round 10 of 2026-10-11, R10-5: the documents describe Level 1 as it is since R9-1, not the withdrawn capability.

Measured by the reviewer at 1698db61: DECISIONS.md lines 123 to 125, 241 to 244 and 271 to 277, and the docstrings of
evaluate_push (3913 to 3916) and _evaluate_targets (3967 to 3973) named pass and inactive for a Level 1 push, the two
fetch rules as the next step, and a Level 1 comparison against the recorded state. The same sentence on pass and
inactive stood in three more places of DECISIONS.md, in the README and in two places of the gate's source.

Property: the documents say what Level 1 does: it denies an evidenced failure at the commits a push sends and leaves the
resolution of its destination NOT MEASURED; fetch rules do not change that; the comparison with the destination's state
is made by Level 2 on git's ref lines. Red against a91e9627, whose documents are those of 1698db61.
"""
from __future__ import annotations

import ast
import pathlib
import re

PLUGIN = pathlib.Path(__file__).resolve().parents[1] / "plugins" / "proofbundle"
DECISIONS = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
README = (PLUGIN / "README.md").read_text(encoding="utf-8")
GATE_SOURCE = (PLUGIN / "hooks" / "proofbundle_gate.py").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """The text with every run of whitespace and comment markers as one space, so a sentence across lines matches."""
    return re.sub(r"(\s|#:|#)+", " ", text)


def _docstring(name: str) -> str:
    for node in ast.walk(ast.parse(GATE_SOURCE)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return _flat(ast.get_docstring(node) or "")
    raise AssertionError(name)


WITHDRAWN = ["it may return `pass` or `inactive`", "may return `pass` or `inactive` after its checks",
             "whose next step names the two fetch rules", "the push is still resolved and compared",
             "stays possible (POSSIBLE) on Level 1"]


def test_no_document_names_the_withdrawn_level_1_capability():
    for name, text in (("DECISIONS.md", DECISIONS), ("README.md", README), ("proofbundle_gate.py", GATE_SOURCE)):
        flat = _flat(text)
        for sentence in WITHDRAWN:
            assert sentence not in flat, (name, sentence)


def test_d3_says_what_level_1_does_with_a_push():
    flat = _flat(DECISIONS)
    assert ("Under Claude Code it denies an evidenced failure at the commits a push sends and otherwise asks" in flat)
    assert "the comparison with the destination's state is Level 2's, on git's own ref lines" in flat


def test_the_docstrings_say_that_level_1_resolves_no_target():
    push = _docstring("evaluate_push")
    assert "locally known state" not in push, push
    assert "NOT MEASURED at the destination check" in push, push
    targets = _docstring("_evaluate_targets")
    assert "Level 1 resolves no target since R9-1" in targets, targets
