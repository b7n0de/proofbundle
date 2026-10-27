"""Follow-up note 37: a case for each mutant that survived: M85g of follow-up note 35 (n35/mutation_1 of the delivery, at d2314682),
and M91a, M91i and M92b of follow-up note 37 (n37/mutation_1, at 35ae2249), each killed in n37/mutation_2.

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


# --- follow-up note 37: a case each for the mutants of D91 and D92 that survived the first run (n37/mutation_1) -------------

def test_M91a_an_ask_with_a_reason_d71_does_not_replace_is_not_the_local_class(tmp_path):
    """The local class answers only an ask whose every reason D71 replaces; any other reason keeps D85's answer."""
    repo = d71._repo(tmp_path, url="https://github.com/someone/x.git")
    (tmp_path / "msg.txt").write_text("Merge\n")
    command = f"git merge -F {tmp_path}/msg.txt topic"
    deadline = time.monotonic() + 60
    asked = gate.Verdict("ask", "a reason D71 does not replace", "push_not_measured")
    out = gate.Outcome("ask", asked.text(), [asked])
    assert gate._autonomy_local(out, command, str(repo), deadline, {}) is None
    free = gate.Verdict("ask", "a reason D71 replaces", "possible_unmodeled_push")
    assert gate._autonomy_local(gate.Outcome("ask", free.text(), [free]), command, str(repo), deadline,
                                {}).decision == "pass"


def test_M91i_a_repository_that_holds_the_gate_directory_is_not_the_local_class(tmp_path, monkeypatch):
    repo = d71._repo(tmp_path, url="https://github.com/someone/x.git")
    (tmp_path / "msg.txt").write_text("Merge\n")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(repo / "gatedir"))
    command = f"git merge -F {tmp_path}/msg.txt topic"
    deadline = time.monotonic() + 60
    free = gate.Verdict("ask", "a reason D71 replaces", "possible_unmodeled_push")
    import os
    environ = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                          "PROOFBUNDLE_GATE_DIR")}
    assert gate._autonomy_local(gate.Outcome("ask", free.text(), [free]), command, str(repo), deadline,
                                environ) is None


def test_M92b_without_a_record_of_the_remote_head_the_default_branch_is_unknown_even_with_a_destination_record(tmp_path):
    """The destination has a local record, so the rules compare; the default branch is still not measured."""
    import test_plugin_n37_machine_check_d92 as d92
    repo = d92._fixture(tmp_path, record_head=False)
    d71._git(repo, "update-ref", f"refs/remotes/origin/{d92.OWN}", "main")
    answer, entry = d92._hook(repo, tmp_path, f"git push origin {d92.OWN}")
    assert "free_work_branch_go" not in entry["reason_ids"], (answer, entry)
