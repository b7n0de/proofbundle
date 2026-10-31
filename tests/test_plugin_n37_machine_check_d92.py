"""D92, follow-up note 37, addendum 2: a machine check in place of a click, with a receipt in the gate log.

The owner's screens of account A (gate 89d2e8b7, 2026-10-18 23:11 Berlin): `git push` to the own work branch
`chore/empty-evidence-declaration` asked (D3), and so did `gh pr edit 388 -R b7n0de/proofbundle --body-file <file>` at
the own pull request (D27). At the head of D91 the push still asked (D87 knew only claude/…) and so did the edit (an
external effect of the closed list).

The rule (D92, in the autonomous answer of D85, under Claude Code):
- a push passes under the standing GO of D87 where its one destination is the local branch of the same name, neither
  the default branch the remote's HEAD names here (which must be recorded) nor a protected one, with every condition of
  D87; the log carries a receipt (quittung: the destination, the remote, the commit, the checks);
- `gh pr edit <number> [-R b7n0de/<repo>] --body-file <file> [--title <title>]` in a repository of D71 passes where
  the house's form checker (scripts/b7_pr_form_gate.py at refs/remotes/<remote>/HEAD) passes the text, with a receipt;
  it is blocked (pr_form_red) where the checker finds it red; where the checker is missing or cannot measure, or the
  file lies outside the work tree and the temp folder or below a name with a dot, the answer of the last class stands.

RED at faeec220 (the head of D91): the free pushes to branches outside claude/, the receipt, the pass and the block of
the edit. The counter cases are controls, green at both.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85).
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []
OWN = "chore/empty-evidence-declaration"
FOOTER = "Written by an AI session of b7n0de under owner review.\n\nMeasurement, not certification.\n"
#: A stand-in with the interface of the house's checker (judge(payload) -> (reasons, title)) and rules (b) and (c) in
#: small: the footer at the end, no "generated with"; NOT MEASURABLE where the text says UNREADABLE.
STAND_IN = '''FOOTER = "Written by an AI session of b7n0de under owner review.\\n\\nMeasurement, not certification."


def judge(payload):
    body = payload["pull_request"]["body"]
    reasons = []
    if "milestone" not in payload["pull_request"]:
        reasons.append("(a) NOT MEASURABLE: the payload's pull request has no milestone field")
    if not body.replace("\\r\\n", "\\n").rstrip("\\n").endswith(FOOTER):
        reasons.append("(b) the description does not end with exactly the two lines of the house footer")
    if "generated with" in body.lower():
        reasons.append("(c) the description carries a tool attribution")
    if "UNREADABLE" in body:
        reasons.append("(c) NOT MEASURABLE: no parser, so what renders as a link cannot be read")
    return reasons, None
'''


def _fixture(tmp_path, checker=STAND_IN, record_head=True):
    """The repository of D87 (claude/x checked out, origin/main and origin/HEAD recorded) with the branch OWN, and the
    house's checker at the remote's default branch."""
    repo = d71._repo(tmp_path)
    d71._git(repo, "checkout", "-q", "-b", "house", "main")
    if checker is not None:
        (repo / "scripts").mkdir()
        (repo / "scripts" / "b7_pr_form_gate.py").write_text(checker)
    (repo / "h.txt").write_text("house\n")
    d71._git(repo, "add", "-A")
    d71._git(repo, "commit", "-q", "-m", "H")
    d71._git(repo, "update-ref", "refs/remotes/origin/main", "house")
    if record_head:
        d71._git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    d71._git(repo, "checkout", "-q", "-b", "claude/x", "main")
    (repo / "w.txt").write_text("work\n")
    d71._git(repo, "add", "-A")
    d71._git(repo, "commit", "-q", "-m", "W")
    d71._git(repo, "branch", OWN, "HEAD")
    return repo


def _hook(repo, tmp_path, command, host="claude", env_extra=None):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d92",
             "tool_input": {"command": command.replace("{R}", str(repo)).replace("{T}", str(tmp_path))}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    env.update(env_extra or {})
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *AUTONOMOUS], json.dumps(event), env,
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return (json.loads(proc.stdout) if proc.stdout.strip() else None), entry


def _decision(answer):
    return None if answer is None else answer["hookSpecificOutput"].get("permissionDecision")


FREE_PUSHES = [f"git push origin {OWN}", f"git -C {{R}} push -u origin {OWN}", "git push origin topic",
               f"git push origin {OWN}:{OWN}", f"git push origin {OWN}:refs/heads/{OWN}", "git push -u origin HEAD",
               "git push origin claude/x"]


@pytest.mark.parametrize("form", FREE_PUSHES)
def test_D92_a_push_to_the_local_branch_of_the_same_name_passes_with_a_receipt(tmp_path, form):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert _decision(answer) is None and "free_work_branch_go" in entry["reason_ids"], (form, answer, entry)
    receipt = entry["quittung"]
    branch = receipt["ziel"].removeprefix("refs/heads/")
    assert receipt["art"] == "push" and receipt["remote"] == "origin" and \
        receipt["commit"] == d71._git(repo, "rev-parse", branch), receipt
    assert "(D92)." in ga.short_text(answer)


#: Each keeps its answer: another name, the default branch, a protected one, a forced push.
KEEP_PUSHES = [(f"git push origin claude/x:{OWN}", "ask"), ("git push origin HEAD:topic", "ask"),
               ("git push origin claude/x:claude/y", "ask"), ("git push origin main", "deny"),
               ("git push origin house:main", "deny"), (f"git push -f origin {OWN}", "deny"),
               (f"git push origin {OWN} topic", "ask")]


@pytest.mark.parametrize("form, decision", KEEP_PUSHES)
def test_D92_control_every_other_push_keeps_its_answer(tmp_path, form, decision):
    repo = _fixture(tmp_path)
    answer, entry = _hook(repo, tmp_path, form)
    assert _decision(answer) in ((decision, "deny") if decision == "ask" else (decision,)), (form, answer)
    assert "free_work_branch_go" not in entry["reason_ids"] and "quittung" not in entry


def test_D92_control_without_a_record_of_the_remote_head_the_default_branch_is_not_measured(tmp_path):
    repo = _fixture(tmp_path, record_head=False)
    answer, entry = _hook(repo, tmp_path, f"git push origin {OWN}")
    assert _decision(answer) in ("ask", "deny") and "free_work_branch_go" not in entry["reason_ids"]


def _body(tmp_path, text, name="body.md"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_D92_gh_pr_edit_with_a_body_the_checker_passes_is_free_with_a_receipt(tmp_path):
    repo = _fixture(tmp_path)
    body = _body(tmp_path, "## The change\n\nText.\n\n## Marking\n\n" + FOOTER)
    answer, entry = _hook(repo, tmp_path, f"gh pr edit 388 -R b7n0de/proofbundle --body-file {body}")
    assert _decision(answer) is None and "free_pr_edit_form" in entry["reason_ids"], (answer, entry)
    assert entry["autonomy"]["klasse"] == "maschine" and "(D92)." in ga.short_text(answer)
    receipt = entry["quittung"]
    assert receipt["art"] == "pr_edit" and receipt["pr"] == "388" and receipt["regeln"] == ["b", "c"]
    assert receipt["text_sha256"] == hashlib.sha256(body.read_bytes()).hexdigest()
    assert receipt["pruefer_blob"] == d71._git(repo, "rev-parse", "refs/remotes/origin/HEAD:scripts/b7_pr_form_gate.py")


@pytest.mark.parametrize("form", ["gh pr edit 388 --body-file {B}", "gh pr edit 388 -F {B} -t 'fix: x'",
                                  "gh pr edit 388 --repo=b7n0de/proofbundle --body-file={B}"])
def test_D92_the_other_spellings_of_the_edit(tmp_path, form):
    repo = _fixture(tmp_path)
    body = _body(tmp_path, "Text.\n\n" + FOOTER)
    answer, entry = _hook(repo, tmp_path, form.replace("{B}", str(body)))
    assert _decision(answer) is None and "free_pr_edit_form" in entry["reason_ids"], (form, answer)


@pytest.mark.parametrize("text, rule", [("Text without the footer.\n", "(b)"),
                                        ("Generated with a tool.\n\n" + FOOTER, "(c)")])
def test_D92_a_body_the_checker_finds_red_is_blocked_with_its_reason(tmp_path, text, rule):
    repo = _fixture(tmp_path)
    body = _body(tmp_path, text)
    answer, entry = _hook(repo, tmp_path, f"gh pr edit 388 --body-file {body}")
    # changed in follow-up note 33 (D109): the same checker judges the same file in decide() under both hosts, so a red body
    # is denied there with the checker's rule, before the autonomous answer of D92 and its receipt
    assert _decision(answer) == "deny" and "text_form_red" in entry["reason_ids"], answer
    assert rule in answer["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("case", ["not_measurable", "no_checker", "dot_folder", "link_out", "other_repo", "extra_option",
                                  "gh_repo_env", "too_big", "not_utf8"])
def test_D92_control_where_the_checker_does_not_carry_it_the_last_class_answers(tmp_path, case):
    repo = _fixture(tmp_path, checker=None if case == "no_checker" else STAND_IN)
    text = "UNREADABLE\n\n" + FOOTER if case == "not_measurable" else "Text.\n\n" + FOOTER
    body = _body(tmp_path, text, ".private/body.md" if case == "dot_folder" else "body.md")
    if case == "link_out":
        secret = _body(tmp_path, "Text.\n\n" + FOOTER, ".private/other.md")
        (repo / "link.md").symlink_to(secret)
        body = repo / "link.md"
    if case == "too_big":
        body.write_text("x" * (getattr(gate, "MAX_PR_BODY_BYTES", 256 * 1024) + 1) + FOOTER)
    if case == "not_utf8":
        body.write_bytes(b"\xff\xfe" + FOOTER.encode())
    command = {"other_repo": f"gh pr edit 388 -R someone/proofbundle --body-file {body}",
               "extra_option": f"gh pr edit 388 --body-file {body} --add-label x"}.get(
        case, f"gh pr edit 388 --body-file {body}")
    extra = {"GH_REPO": "someone/else"} if case == "gh_repo_env" else None
    answer, entry = _hook(repo, tmp_path, command, env_extra=extra)
    assert _decision(answer) in ("ask", "deny"), (case, answer)
    assert not {"free_pr_edit_form", "pr_form_red"} & set(entry["reason_ids"]), (case, entry["reason_ids"])


def test_D92_control_outside_a_repository_of_d71_the_edit_keeps_its_answer(tmp_path):
    repo = d71._repo(tmp_path, url="https://github.com/someone/x.git")
    body = _body(tmp_path, "Text.\n\n" + FOOTER)
    answer, entry = _hook(repo, tmp_path, f"gh pr edit 388 --body-file {body}")
    assert _decision(answer) in ("ask", "deny") and "free_pr_edit_form" not in entry["reason_ids"]


def test_D92_control_codex_keeps_its_answer(tmp_path):
    repo = _fixture(tmp_path)
    body = _body(tmp_path, "Text.\n\n" + FOOTER)
    for command in (f"gh pr edit 388 --body-file {body}", f"git push origin {OWN}"):
        answer, entry = _hook(repo, tmp_path, command, host="codex")
        assert answer is not None and not {"free_pr_edit_form", "free_work_branch_go"} & set(entry["reason_ids"])


def test_D92_the_checker_runs_on_a_copy_and_never_in_the_work_tree(tmp_path):
    """A checker the session writes into the work tree is not the house's: the gate reads the remote's default branch."""
    repo = _fixture(tmp_path, checker=None)
    (repo / "scripts").mkdir()
    (repo / "scripts" / "b7_pr_form_gate.py").write_text(STAND_IN.replace("reasons = []", "return [], None"))
    body = _body(tmp_path, "no footer\n")
    answer, entry = _hook(repo, tmp_path, f"gh pr edit 388 --body-file {body}")
    assert "free_pr_edit_form" not in entry["reason_ids"], answer


def test_D92_the_judge_drops_rule_a_and_reports_a_checker_that_fails_as_not_measured(tmp_path):
    deadline = time.monotonic() + 60
    assert gate._house_form_judge(STAND_IN.encode(), ("Text.\n\n" + FOOTER).encode(), deadline) == []
    assert gate._house_form_judge(STAND_IN.encode(), b"UNREADABLE\n", deadline) == [
        "(b) the description does not end with exactly the two lines of the house footer"]   # a measured red stands
    assert gate._house_form_judge(STAND_IN.encode(), ("UNREADABLE\n\n" + FOOTER).encode(), deadline) is None
    assert gate._house_form_judge(b"raise SystemExit(3)\n", b"x", deadline) is None
    assert gate._house_form_judge(b"def judge(p):\n    return 'no list', None\n", b"x", deadline) is None
