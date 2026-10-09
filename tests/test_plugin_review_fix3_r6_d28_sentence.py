"""Review round 3 of 2026-10-09, R3-6: D28 names what the gate frees since K-NW-2 B.

The limits of D28 said that the PreToolUse gate asks before or denies `git add` and `git commit`, so an unattended run
could not commit and the done check could pass only on an uncommitted state. Since K-NW-2 B the gate frees the narrow
forms after a repository state check (D3). The reviewer gave the replacement word for word; this test holds it.
Red against ab0773e5.
"""
from __future__ import annotations

import pathlib
import re

import test_plugin_gate_n24 as n24

DECISIONS = pathlib.Path(n24.gate.__file__).resolve().parents[1] / "DECISIONS.md"
NEW = ("The PreToolUse gate frees the narrow git add and git commit -m forms after a repository state check (D3), so an "
       "unattended run can commit when that check passes. Other forms still ask under Claude Code or deny under Codex.")


def _flat() -> str:
    return re.sub(r"\s+", " ", DECISIONS.read_text(encoding="utf-8"))


def test_d28_carries_the_reviewers_sentences_word_for_word():
    assert _flat().count(NEW) == 1


def test_d28_no_longer_says_an_unattended_run_cannot_commit():
    text = _flat()
    assert "the agent cannot commit and the done check can only pass on an uncommitted state" not in text
    assert "The `PreToolUse` gate asks before (Claude Code) or denies (Codex) `git add` and `git commit`" not in text
