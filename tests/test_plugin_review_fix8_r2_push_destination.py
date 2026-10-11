"""Review round 8 of 2026-10-10, R8-2: a push destination counts as resolved only where git's resolution is evidenced.

Measured by the reviewer at 1fc58527: the done fixture with full history, local main=B, the remote's refs/heads/main=A
and the standard rule +refs/heads/*:refs/remotes/origin/*. On the test remote `git update-ref refs/heads/refs/heads/main
A`, then `git fetch origin`. Claude Level 1 for `git push origin main`: pass with done. `git push --porcelain
--no-verify origin main`: exit 1, "dst refspec refs/heads/main matches more than one", both remote refs unchanged.
Under 2.43.0 and 2.51.1, under 2.51.1 also HEAD:refs/heads/main falsely green. No stale tracking ref is needed.

Property: a spelling and a unique fetch mapping do not show that git resolves the destination uniquely. git looks the
destination value up among every ref the remote advertises, by the rules of ref_rev_parse_rules (remote.c,
count_refspec_match): for refs/heads/main it also matches refs/heads/refs/heads/main, refs/tags/refs/heads/main and
refs/refs/heads/main, for a short main also refs/tags/main and refs/main; two strong matches make git refuse the push,
and a weak match (under refs/remotes/) counts only without a strong one (measured with git 2.43.0 and 2.51.1). The
remote is not read (D3): what the gate knows of its refs is what the remote's fetch rules recorded. An evidenced
ambiguity, and a resolution the recorded refs cannot show, are NOT MEASURED; the full spelling alone is not enough.
The fixture of test_plugin_gate_n2c_push_done records refs/tags/ and refs/refs/ (RECORDING_RULES); a repository with
the standard rule alone leaves every Level 1 push NOT MEASURED, which the cost tests below state. Red against 2aaeb6bc.

Review round 9 of 2026-10-11, R9-1, withdrew the other half: a candidate this repository does not record is no
candidate the remote lacks, whatever the fetch rules (a rule proves no fetch that ran under it, and a fetch does not
see every ref a push sees). So every Level 1 push is NOT MEASURED at this check, the round-8 controls that passed with
the recording rules are NOT MEASURED too, and the answer offers no fetch rule as a repair. git's facts below stand;
test_plugin_review_fix9_r1_absence_is_not_evidence.py holds the cases of R9-1.
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


def _repo(tmp_path, record: bool = True) -> n2c.Repo:
    """main tracks origin/main at A, one commit of work (B) with a valid receipt. With record False the remote keeps
    only the standard rule +refs/heads/*:refs/remotes/origin/*, as `git clone` writes it."""
    r = n2c.Repo(tmp_path)
    r.make("valid")
    if not record:
        _git(r.path, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    return r


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


def _beside(tmp_path, r, name: str) -> None:
    """A ref `name` on the remote at the remote's main (A), then a fetch that records what the rules record."""
    a = _on_remote(tmp_path, "rev-parse", "refs/heads/main").stdout.strip()
    assert _on_remote(tmp_path, "update-ref", name, a).returncode == 0
    _git(r.path, "fetch", "-q", "origin")


#: Remote refs git push also matches for the value refs/heads/main as strong matches.
STRONG = ("refs/heads/refs/heads/main", "refs/tags/refs/heads/main", "refs/refs/heads/main")
#: The forms whose destination value is refs/heads/main.
FULL_FORMS = ("git push origin main", "git push origin HEAD:refs/heads/main", "git push origin main:refs/heads/main",
              "git push")


@pytest.mark.parametrize("name", STRONG)
def test_git_refuses_the_push_and_leaves_both_refs(tmp_path, name):
    """Non-vacuous, the review's case and its two siblings: a strong match beside refs/heads/main."""
    r = _repo(tmp_path)
    _beside(tmp_path, r, name)
    before = _remote_refs(tmp_path)
    push = _push(r.path, "origin", "main")
    assert push.returncode == 1 and "dst refspec refs/heads/main matches more than one" in push.stderr, push.stderr
    assert _remote_refs(tmp_path) == before


@pytest.mark.parametrize("command", FULL_FORMS)
@pytest.mark.parametrize("name", STRONG)
def test_an_evidenced_ambiguity_is_not_measured(env, tmp_path, name, command):
    r = _repo(tmp_path)
    _beside(tmp_path, r, name)
    assert _verdict(env, r.path, command) == NOT_MEASURED, (name, command)


def test_git_accepts_the_push_of_a_plain_clone(tmp_path):
    """Non-vacuous for the cost below: without a ref beside main git pushes, so a NOT MEASURED there is the gate's
    missing evidence, not git's refusal."""
    r = _repo(tmp_path, record=False)
    assert _push(r.path, "--dry-run", "origin", "main").returncode == 0


@pytest.mark.parametrize("command", FULL_FORMS)
def test_the_cost_a_remote_whose_rules_record_refs_heads_only_is_not_measured(env, tmp_path, command):
    """The standard rule records refs/heads/ only: whether the remote holds refs/tags/refs/heads/main or
    refs/refs/heads/main is not known here, and either makes git refuse the push. That is a resolution the recorded
    refs cannot show, so it is NOT MEASURED, where the gate had passed."""
    r = _repo(tmp_path, record=False)
    assert _verdict(env, r.path, command) == NOT_MEASURED, command


@pytest.mark.parametrize("command", FULL_FORMS)
def test_control_recorded_namespaces_without_a_ref_beside_main_keep_the_pass(env, tmp_path, command):
    """Round 8 passed here; since R9-1 the recorded namespaces are no evidence that the remote lacks a ref beside
    main, so the push asks at the destination check, after the done check at the sent commit showed no failure."""
    r = _repo(tmp_path)
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path, command=command))


@pytest.mark.parametrize("name", ["refs/remotes/refs/heads/main", "refs/remotes/refs/heads/main/HEAD",
                                  "refs/heads/heads/main"])
def test_control_a_weak_or_no_match_beside_main_keeps_the_pass(env, tmp_path, name):
    """refs/remotes/... is a weak match, which counts only without a strong one; refs/heads/heads/main is no match.
    git pushes main in both cases. Since R9-1 the gate cannot show that no strong match stands beside main, so the
    push asks at the destination check."""
    r = _repo(tmp_path)
    _beside(tmp_path, r, name)
    assert _push(r.path, "--dry-run", "origin", "main").returncode == 0
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path, command="git push origin main"))


@pytest.mark.parametrize("name", ["refs/tags/main", "refs/main"])
def test_git_refuses_a_short_destination_beside_another_match(tmp_path, name):
    r = _repo(tmp_path)
    _beside(tmp_path, r, name)
    push = _push(r.path, "--dry-run", "origin", "HEAD:main")
    assert push.returncode == 1 and "dst refspec main matches more than one" in push.stderr, push.stderr


@pytest.mark.parametrize("command", ["git push origin HEAD:main", "git push origin main:main"])
def test_a_short_destination_is_not_measured(env, tmp_path, command):
    """For a short value git also matches refs/main and refs/tags/main; whether the remote holds them is not known
    here, so a short destination is NOT MEASURED (R8-2, R9-1)."""
    r = _repo(tmp_path)
    assert _verdict(env, r.path, command) == NOT_MEASURED, command


#: A rule that records refs/main and does not map refs/heads/main: a `*` may stand anywhere in a side (R6-3).
SHORT_RULE = "+refs/m*:refs/recorded/origin/m*"


def test_a_rule_that_records_refs_main_makes_a_short_destination_measurable(env, tmp_path):
    """Withdrawn by R9-1: round 8 took a rule that records refs/main, with no such local ref, as evidence that the
    remote lacks it. git pushes here, and the gate cannot show it, so the push stays NOT MEASURED."""
    r = _repo(tmp_path)
    _git(r.path, "config", "--add", "remote.origin.fetch", SHORT_RULE)
    _git(r.path, "fetch", "-q", "origin")
    assert _push(r.path, "--dry-run", "origin", "HEAD:main").returncode == 0
    n2c.assert_destination_not_measured(*n2c._level1(env, r.path, command="git push origin HEAD:main"))


@pytest.mark.parametrize("name", ["refs/tags/main", "refs/main"])
def test_with_that_rule_a_short_destination_beside_another_match_is_not_measured(env, tmp_path, name):
    r = _repo(tmp_path)
    _git(r.path, "config", "--add", "remote.origin.fetch", SHORT_RULE)
    _beside(tmp_path, r, name)
    assert _verdict(env, r.path, "git push origin HEAD:main") == NOT_MEASURED, name


def test_a_negative_rule_that_excludes_a_candidate_leaves_it_unrecorded(env, tmp_path):
    r = _repo(tmp_path)
    _git(r.path, "config", "--add", "remote.origin.fetch", "^refs/tags/refs/heads/main")
    assert _verdict(env, r.path, "git push origin main") == NOT_MEASURED


def test_git_pushes_a_tag_source_to_the_tag_not_to_the_branch(tmp_path):
    """The sibling in the source: a refspec without `:` names on the remote the source's own full name. With a tag rel
    and no branch rel here, `git push origin rel` writes refs/tags/rel, while a branch rel on the remote has a
    tracking ref the gate could compare with."""
    r = _repo(tmp_path)
    _git(r.path, "push", "-q", "--no-verify", "origin", "HEAD~1:refs/heads/rel")
    _git(r.path, "fetch", "-q", "origin")
    _git(r.path, "tag", "rel", "HEAD")
    push = _push(r.path, "--dry-run", "origin", "rel")
    assert push.returncode == 0 and "\trefs/tags/rel:refs/tags/rel\t" in push.stdout, push.stdout


def test_a_source_whose_full_name_is_not_the_branch_is_not_measured(env, tmp_path):
    """The gate had qualified rel to refs/heads/rel, compared it with origin/rel and passed a push that writes a tag."""
    r = _repo(tmp_path)
    _git(r.path, "push", "-q", "--no-verify", "origin", "HEAD~1:refs/heads/rel")
    _git(r.path, "fetch", "-q", "origin")
    _git(r.path, "tag", "rel", "HEAD")
    assert _verdict(env, r.path, "git push origin rel") == NOT_MEASURED


def test_a_plain_fetch_rule_without_a_destination_is_not_measured(env, tmp_path):
    """R7-4 counts any plain source of the pushing remote as not evidenced. A plain rule without a destination writes
    FETCH_HEAD only and maps no tracking ref; git fetches with it. Since R9-1 the destination check leaves every push
    NOT MEASURED whatever the rules, so this case no longer depends on a check of plain rules there (round 8's M82h)."""
    r = _repo(tmp_path)
    _git(r.path, "config", "--add", "remote.origin.fetch", "refs/heads/main")
    assert subprocess.run(["git", "-C", str(r.path), "fetch", "-q", "origin"], capture_output=True, timeout=60,
                          check=False).returncode == 0
    assert _verdict(env, r.path, "git push origin main") == NOT_MEASURED


def _answer(env, repo, command: str, host: str = "claude") -> str:
    answer, _entry = n2c._level1(env, repo, host=host, command=command)
    return json.dumps(answer, ensure_ascii=False)


@pytest.mark.parametrize("command", ["git push origin main", "git push"])
def test_the_answer_names_the_unrecorded_ref_and_the_rules_that_record_it(env, tmp_path, command):
    """The answer names the remote refs git push also matches and says that whether the remote holds one is not known
    here. Round 8 also named two fetch rules as the repair; R9-1 withdrew that, so no rule is offered. Under Codex
    every push is NOT MEASURED before its target is read (D12), so this is Claude Code's answer."""
    r = _repo(tmp_path, record=False)
    text = _answer(env, r.path, command)
    assert "git push also matches refs/refs/heads/main, refs/tags/refs/heads/main" in text, text
    assert "not known here" in text and "have a person review the push" in text, text
    assert "refs/recorded" not in text and "git fetch" not in text and "a wildcard refspec" not in text, text


@pytest.mark.parametrize("name", STRONG)
def test_the_answer_names_the_ambiguity_git_refuses(env, tmp_path, name):
    """A recorded candidate is named as what this repository records, with git's refusal, never as what the remote
    held (R9-1)."""
    r = _repo(tmp_path)
    _beside(tmp_path, r, name)
    text = _answer(env, r.path, "git push origin main")
    assert f"this repository records {name}" in text and "refuses the push" in text, text
    assert "the remote held" not in text, text
