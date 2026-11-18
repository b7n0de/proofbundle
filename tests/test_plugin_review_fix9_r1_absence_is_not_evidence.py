"""Review round 9 of 2026-10-11, R9-1: a ref missing from this repository's record is no evidence that the remote lacks it.

Measured by the reviewer at b288ee66: the done fixture with full history, the remote's main at A, local main at B, the
rules +refs/heads/*:refs/remotes/origin/*, +refs/tags/*:refs/recorded/origin/tags/* and
+refs/refs/*:refs/recorded/origin/refs/* set before the fetch. On the test remote `git update-ref refs/tags/refs/heads/main
A` and `git config uploadpack.hideRefs refs/tags/refs/heads/main`, then `git fetch origin`. Level 1 for `git push origin
main`: pass with done. `git push --porcelain --no-verify origin main`: exit 1, "dst refspec refs/heads/main matches more
than one", both refs unchanged. A second probe without hideRefs: fetch with the standard rule only and --no-tags, then set
the two recording rules without a new fetch: the same false pass. Under git 2.43.0 and 2.51.1.

Property: without evidence of where an observation came from and that it was complete, the destination's resolution
stays NOT MEASURED. A configured rule proves no fetch that ran under it, and a fetch and a push see different sets of the
remote's refs (uploadpack.hideRefs hides a ref from the one, not from the other). So no ref this repository lacks counts
as a ref the remote lacks, and the two recording rules are no repair (the claim is withdrawn from the answer, the report
and DECISIONS.md D3). Level 2 is not concerned: git hands the pre-push hook the ref it resolved against what the remote
advertised to the push. Red against b288ee66.
"""
from __future__ import annotations

import json
import subprocess

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_git = n2c._git

NOT_MEASURED = ("ask", ["push_not_measured"])
#: Remote refs git push also matches for the value refs/heads/main as strong matches (remote.c, count_refspec_match).
STRONG = ("refs/tags/refs/heads/main", "refs/refs/heads/main", "refs/heads/refs/heads/main")
#: The forms whose destination value is refs/heads/main.
FULL_FORMS = ("git push origin main", "git push origin HEAD:refs/heads/main", "git push origin main:refs/heads/main",
              "git push")


def _remote(tmp_path) -> str:
    return str(tmp_path / "remote.git")


def _on_remote(tmp_path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "--git-dir", _remote(tmp_path), *args], capture_output=True, text=True, timeout=60,
                          check=False)


def _remote_refs(tmp_path) -> str:
    return _on_remote(tmp_path, "for-each-ref", "--format=%(refname) %(objectname)").stdout


def _push(repo, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "push", "--porcelain", "--no-verify", *args], capture_output=True,
                          text=True, timeout=60, check=False)


def _verdict(env, repo, command: str) -> tuple[str, list]:
    _answer, entry = n2c._level1(env, repo, command=command)
    return entry["verdict"], entry["reason_ids"]


def _hidden_beside(tmp_path, r, name: str) -> None:
    """The review's case: `name` on the remote at the remote's main, hidden from upload-pack, then a fetch with the
    recording rules the fixture set before it."""
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert _on_remote(tmp_path, "update-ref", name, a).returncode == 0
    assert _on_remote(tmp_path, "config", "uploadpack.hideRefs", name).returncode == 0
    _git(r.path, "fetch", "-q", "origin")


def _unfetched_beside(tmp_path, name: str) -> n2c.Repo:
    """The review's second probe: the standard rule only and a fetch without tags, then the recording rules set
    without a new fetch, and `name` on the remote, not hidden."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    _git(r.path, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert _on_remote(tmp_path, "update-ref", name, a).returncode == 0
    _git(r.path, "fetch", "-q", "--no-tags", "origin")
    n2c.record_remote_refs(r.path)
    return r


def _valid(tmp_path) -> n2c.Repo:
    r = n2c.Repo(tmp_path)
    r.make("valid")
    return r


@pytest.mark.parametrize("name", STRONG)
def test_git_refuses_the_push_beside_a_hidden_ref_and_leaves_both_refs(tmp_path, name):
    """Non-vacuous: the hidden ref is not in the record, and git still refuses the push."""
    r = _valid(tmp_path)
    _hidden_beside(tmp_path, r, name)
    local = name.replace("refs/tags/", "refs/recorded/origin/tags/", 1).replace("refs/refs/", "refs/recorded/origin/refs/", 1)
    assert _git(r.path, "show-ref", "--verify", "--quiet", local, check=False).returncode == 1
    before = _remote_refs(tmp_path)
    push = _push(r.path, "origin", "main")
    assert push.returncode == 1 and "dst refspec refs/heads/main matches more than one" in push.stderr, push.stderr
    assert _remote_refs(tmp_path) == before


@pytest.mark.parametrize("command", FULL_FORMS)
@pytest.mark.parametrize("name", STRONG)
def test_a_ref_hidden_from_the_fetch_is_not_evidenced_absent(env, tmp_path, name, command):
    r = _valid(tmp_path)
    _hidden_beside(tmp_path, r, name)
    assert _verdict(env, r.path, command) == NOT_MEASURED, (name, command)


@pytest.mark.parametrize("name", ["refs/tags/refs/heads/main", "refs/refs/heads/main"])
def test_git_refuses_the_push_beside_a_ref_no_fetch_under_the_rules_saw(tmp_path, name):
    r = _unfetched_beside(tmp_path, name)
    push = _push(r.path, "origin", "main")
    assert push.returncode == 1 and "matches more than one" in push.stderr, push.stderr


@pytest.mark.parametrize("command", FULL_FORMS)
@pytest.mark.parametrize("name", ["refs/tags/refs/heads/main", "refs/refs/heads/main"])
def test_a_rule_set_after_the_fetch_is_no_record(env, tmp_path, name, command):
    r = _unfetched_beside(tmp_path, name)
    assert _verdict(env, r.path, command) == NOT_MEASURED, (name, command)


def test_git_accepts_the_push_where_the_remote_holds_no_ref_beside_main(tmp_path):
    """Non-vacuous for the cost below: git pushes, so the NOT MEASURED there is the gate's missing evidence."""
    r = _valid(tmp_path)
    assert _push(r.path, "--dry-run", "origin", "main").returncode == 0


@pytest.mark.parametrize("command", FULL_FORMS)
def test_the_cost_a_complete_looking_record_is_not_evidence_either(env, tmp_path, command):
    """The recording rules, run before the fetch, and no ref beside main on the remote: this repository cannot tell
    this case from the hidden one, so it is NOT MEASURED too, where the gate had passed (owner choice C: A)."""
    r = _valid(tmp_path)
    assert _verdict(env, r.path, command) == NOT_MEASURED, command


def test_a_rule_for_refs_main_does_not_make_a_short_destination_measurable(env, tmp_path):
    r = _valid(tmp_path)
    _git(r.path, "config", "--add", "remote.origin.fetch", "+refs/m*:refs/recorded/origin/m*")
    _git(r.path, "fetch", "-q", "origin")
    assert _verdict(env, r.path, "git push origin HEAD:main") == NOT_MEASURED


def _answer(env, repo, command: str) -> str:
    answer, _entry = n2c._level1(env, repo, command=command)
    return json.dumps(answer, ensure_ascii=False)


@pytest.mark.parametrize("command", ["git push origin main", "git push"])
def test_the_answer_offers_no_fetch_rule_as_a_repair(env, tmp_path, command):
    """The two recording rules are withdrawn as a next step: they record what one fetch saw, not what the remote shows
    the push. The answer says why the resolution is not evidenced and that a person reviews the push."""
    r = _valid(tmp_path)
    text = _answer(env, r.path, command)
    assert "refs/recorded" not in text and "git fetch" not in text, text
    assert "not known here" in text and "have a person review the push" in text, text


@pytest.mark.parametrize("name", STRONG)
def test_the_answer_names_a_recorded_ref_only_as_this_repositorys_record(env, tmp_path, name):
    """A recorded candidate is still named, as what this repository records, not as what the remote held."""
    r = _valid(tmp_path)
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert _on_remote(tmp_path, "update-ref", name, a).returncode == 0
    _git(r.path, "fetch", "-q", "origin")
    text = _answer(env, r.path, "git push origin main")
    assert "this repository records" in text and "the remote held" not in text, text


def test_level_2_judges_the_ref_git_resolved(env, tmp_path):
    """Level 2 is not concerned: git hands the pre-push hook the remote ref it resolved, with its state on the remote."""
    r = _valid(tmp_path)
    proc = n2c._level2(env, r.path)
    assert proc.returncode == 0 and "The done check passed at the pushed commit" in proc.stderr, proc.stderr
