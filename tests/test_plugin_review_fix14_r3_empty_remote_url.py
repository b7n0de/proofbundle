"""Review round 14 of 2026-10-13, R14-3: an empty remote URL does not hide the push source of git's older remote files.

Measured by the reviewer at f3b898bc with git 2.51.1: a clean commit A and a branch other on it; on main a valid
declaration with an empty evidence list and a done task whose policy is missing; push.default current; remote.legacy.url
an empty value; .git/remotes/legacy with the URL of a local bare repository and `Push: refs/heads/other:refs/heads/other`.
The real Level 1 hook for `git push legacy` answered deny/missing_file and named main as the pushed commit; the control
`git push legacy other:refs/heads/other` asked with the right source commit. Under git 2.51.1 the empty URL starts the URL
list anew and git takes the remote file, while _legacy_remote saw the key and passed over the file. git 2.43.0 refuses the
empty URL. Measured here at 745b5b07 with git 2.43.0: the same deny naming main (git itself ends that push with "no path
specified").

Property (contract D5; owner choice 2 A: no unresolved source is replaced by HEAD): whether the configuration gives the
remote a URL is read from the list git uses, with its reset at an empty value; with no URL left, the older remote files
decide, the source of a push with no refspec is not resolved, and no commit is named as pushed. Red against 745b5b07.
"""
from __future__ import annotations

import json

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

DONE_WITHOUT_POLICY = json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": [], "done": {
    "receipt": ".proofbundle/test.done.json", "policy": ".proofbundle/missing-policy.json"}})


def _case(tmp_path, urls):
    work, remote, a = w1._undeclared(tmp_path)
    w1._git(work, "branch", "other", a)
    main = w1._commit(work, gate.DECLARATION, DONE_WITHOUT_POLICY)
    w1._git(work, "config", "push.default", "current")
    for url in urls:
        w1._git(work, "config", "--add", "remote.legacy.url", url if url != "bare" else str(remote))
    (work / ".git" / "remotes").mkdir(exist_ok=True)
    (work / ".git" / "remotes" / "legacy").write_text(f"URL: {remote}\nPush: refs/heads/other:refs/heads/other\n",
                                                       encoding="utf-8")
    return work, a, main


@pytest.mark.parametrize("urls", [[""], ["https://example.invalid/o/r.git", ""]], ids=["empty", "reset_at_the_end"])
def test_the_reviewers_case_no_url_left_the_source_is_not_resolved(env, tmp_path, urls):
    work, _a, main = _case(tmp_path, urls)
    answer, entry, text = w1._l1(env, work, "git push legacy")
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert entry["verdict"] == "ask" and entry["reason_ids"] == ["push_not_measured"], entry
    assert f"the pushed commit {main[:12]}" not in text and main[:12] not in text, text
    assert "the gate cannot tell which commits the push sends, so it checked no evidence" in text, text


def test_control_a_url_after_the_empty_value_is_gits_and_the_source_stays_main(env, tmp_path):
    work, _a, main = _case(tmp_path, ["", "bare"])
    answer, entry, text = w1._l1(env, work, "git push legacy")
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    assert entry["verdict"] == "deny" and entry["reason_ids"] == ["missing_file"], entry
    assert f"the pushed commit {main[:12]}" in text, text


def test_control_a_refspec_names_the_source(env, tmp_path):
    work, a, main = _case(tmp_path, [""])
    answer, entry, text = w1._l1(env, work, "git push legacy other:refs/heads/other")
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert f"the evidence at the sent source commit(s) {a[:12]} showed no failure" in text, text
    assert main[:12] not in text, text
