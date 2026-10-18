"""Nachtrag 37: a case for the mutant of Nachtrag 35 that survived (n35/mutation_1 of the delivery, at d2314682).

M85g took back the host check inside the autonomous answer: main() starts it only under Claude Code, so every test
through the hook stayed green, while a call of autonomous_outcome() under Codex would have answered as under Claude Code.
The answer under Codex is the outcome of decide(), whatever the call (D12, D37, D85).

M87b (sources_clean) is not given a case: where the repository is one of D71, HEAD declares, and _local_inactivity then
returns no note, so sources_clean is true wherever D87 reads it; the mutant is equivalent under D71 (read, not measured).
"""
from __future__ import annotations

import time

import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean


@pytest.mark.parametrize("form", ["cd {R} && git status", "git reset --hard HEAD~1", "git tag v1",
                                  "git merge -F {T}/msg.txt topic"])
def test_M85g_under_codex_the_autonomous_answer_is_the_outcome_of_decide(tmp_path, form):
    repo = d71._repo(tmp_path)
    (tmp_path / "msg.txt").write_text("Merge\n")
    command = d71._command(form, repo, tmp_path)
    deadline = time.monotonic() + 60
    out = gate.decide(command, str(repo), deadline, "codex")
    assert gate.autonomous_outcome(out, command, str(repo), deadline, host="codex") is out
