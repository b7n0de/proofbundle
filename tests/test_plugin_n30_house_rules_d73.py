"""D73, Nachtrag 30: house rules before every freedom, D71 included, under both hosts.

Owner choice of 2026-10-18 ("Hausregeln ins Tor, die Zeile nennt die Gefahr"). H1: `--admin` on `gh pr merge`, and a
`gh api` call that bypasses or changes a protection rule, deny. H2: a tag that goes out asks, its line naming the tag
and the owner GO a release needs. H3: `gh pr create` asks, its line naming the limit of 8 open pull requests (owner
question O30-1). H4: `pkill -f` and `killall` ask in a chain with further work or where their pattern can match their
own command line, with the measured siblings that end the command's own shell.

RED at ffa7d39a (the head of Nachtrag 29): the forms of H1 to H4 and their lines. The counter cases keep their answer and
are controls, green at both. The repository, the environment and the stand-in gh are those of
test_plugin_n30_short_line_d72.py; no case reaches a network, and no kill runs.
"""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import _gate_answer as ga
from test_plugin_n30_short_line_d72 import HOSTS, _answer, _clean, _line, _outcome, _repo, gate, pytestmark  # noqa: F401


# --- H1: --admin on gh pr merge, and a gh api call on a protection rule, deny under both hosts ------------------------

H1_ADMIN = [
    "gh pr checks 12 -R b7n0de/proofbundle && gh pr merge 12 -R b7n0de/proofbundle --admin --merge",   # S1
    "gh pr merge 12 --admin",
    "gh pr merge 12 -R b7n0de/proofbundle --auto --merge --admin",
    "gh pr merge --admin 12 --squash",
    "gh pr merge 12 --admin=true",
    "gh pr merge 12 --admin=false",
    'gh pr merge 12 "--admin"',
    "gh pr merge 12 --ad''min",
    "gh pr merge 12 \\--admin",
    "/usr/local/bin/gh pr merge 12 --admin",
    "gh pr merge 12 -R b7n0de/proofbundle -sd --admin",
    "gh pr merge 12 -t subject --admin",
    "gh pr merge 12 --repo=b7n0de/proofbundle --admin",
    "gh -R b7n0de/proofbundle pr merge 12 --admin",
    "sudo -u root gh pr merge 12 --admin",
    "timeout 30 gh pr merge 12 --admin",
    "bash -c 'gh pr merge 12 --admin'",
    "bash -lc 'gh pr merge 12 --admin --auto'",
    "for n in 12 13; do gh pr merge $n --admin; done",
    "G=gh; $G pr merge 12 --admin",
    "echo done; gh pr merge 12 --merge --delete-branch --admin",
    "x=$(gh pr merge 12 --admin)",
    "gh pr merge 12 --admin &",
]
H1_API = [
    "gh api -X DELETE repos/b7n0de/proofbundle/branches/main/protection",
    "gh api --method PUT repos/{owner}/{repo}/branches/main/protection --input rules.json",
    "gh api repos/b7n0de/proofbundle/branches/main/protection/enforce_admins -X DELETE",
    "gh api -XPATCH /repos/b7n0de/proofbundle/rulesets/7 -f enforcement=disabled",
    "gh api orgs/b7n0de/rulesets -f name=x",
    "gh api -X PUT repos/b7n0de/proofbundle/pulls/12/merge",
    "gh api https://api.github.com/repos/b7n0de/proofbundle/branches/main/protection -X DELETE",
    "gh api -X PUT repos/b7n0de/proofbundle/environments/production -F wait_timer=0",
    "gh api -X POST repos/b7n0de/proofbundle/secret-scanning/push-protection-bypasses -f reason=used_in_tests",
    "gh api graphql -f query='mutation { deleteBranchProtectionRule(input: {branchProtectionRuleId: \"x\"}) "
    "{ clientMutationId } }'",
    "gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: \"x\"}) { clientMutationId } }'",
    "gh api graphql -F query='mutation { updateRepositoryRuleset(input: {}) { clientMutationId } }'",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", H1_ADMIN)
def test_D73_H1_admin_on_gh_pr_merge_denies_under_both_hosts(tmp_path, form, host):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, host)
    assert out is not None and out.decision == "deny", (form, host, out and out.decision)
    assert "house_admin_merge" in [v.reason_id for v in out.verdicts]
    assert out.step == "gh pr merge --admin"
    line = _line(out, host)
    assert "--admin" in line and line.endswith("(D73).") and line.startswith("Gate blocks gh pr merge --admin"), line


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", H1_API)
def test_D73_H1_a_gh_api_call_on_a_protection_rule_denies_under_both_hosts(tmp_path, form, host):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, host)
    assert out is not None and out.decision == "deny", (form, host, out and out.decision)
    assert "house_protection_api" in [v.reason_id for v in out.verdicts]
    assert out.step.startswith("gh api") and _line(out, host).endswith("(D73)."), (out.step, _line(out, host))


def test_D73_H1_the_S1_line_names_admin_not_the_first_step(tmp_path):
    repo = _repo(tmp_path)
    out = _outcome(repo, H1_ADMIN[0])
    assert _line(out) == ("Gate blocks gh pr merge --admin because --admin merges past the branch protection, which a "
                          "house rule forbids (D73).")
    assert _line(out, language="de") == ("Tor sperrt gh pr merge --admin, weil --admin am Schutz des Zweigs vorbei "
                                         "merget, was eine Hausregel verbietet (D73).")


# --- H2: a tag that goes out asks; under Codex it denies ---------------------------------------------------------------

H2 = [
    ("cd {R} && git tag -s v6.2.0 -m text && git push origin v6.2.0", "v6.2.0"),     # S2
    ("git push origin v6.2.0", "v6.2.0"),
    ("git push origin v0", "v0"),
    ("git push origin release-candidate", "release-candidate"),
    ("git -C {R} push origin release-candidate", "release-candidate"),
    ("git push origin refs/tags/v0", "v0"),
    ("git push origin HEAD:refs/tags/v7", "v7"),
    ("git push origin +v0:v0", "v0"),
    ("git push origin tag v0", "v0"),
    ("git push origin tag twin", "twin"),       # `tag` names refs/tags/twin, which a branch twin leaves ambiguous else
    ("git push -d origin v0", "v0"),
    ("git push origin :refs/tags/v0", "v0"),
    ("git tag rc-x && git push origin rc-x", "rc-x"),
    ("git push --tags origin", None),
    ("git push --tag origin", None),
    ("git push --follow-tags origin main", None),
    ("git push --mirror origin", None),
    ("git -c push.followTags=true push origin main", None),
    ("gh release create v6.2.0 --notes x", "v6.2.0"),
    ("gh release create -t title v6.2.0", "v6.2.0"),
    ("gh release new v6.2.0", "v6.2.0"),
    ("gh api -X POST repos/b7n0de/proofbundle/git/refs -f ref=refs/tags/v6.2.0 -f sha=abc", "v6.2.0"),
    ("gh api repos/b7n0de/proofbundle/releases -f tag_name=v6.2.0", "v6.2.0"),
]


@pytest.mark.parametrize("form, tag", H2)
def test_D73_H2_a_tag_that_goes_out_asks_and_the_line_names_the_tag(tmp_path, form, tag):
    repo = _repo(tmp_path)
    out = _outcome(repo, form)
    assert out is not None and out.decision == "ask", (form, out and out.decision)
    assert "house_tag_out" in [v.reason_id for v in out.verdicts]
    line = _line(out)
    assert "owner GO" in line and line.endswith("(D73)."), line
    assert tag is None or tag in out.step, (out.step, tag)


@pytest.mark.parametrize("form, tag", H2)
def test_D73_H2_under_codex_a_tag_that_goes_out_denies(tmp_path, form, tag):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, "codex")
    assert out is not None and out.decision in ("ask", "deny"), (form, out and out.decision)
    assert "house_tag_out" in [v.reason_id for v in out.verdicts]
    assert gate.answer(out.decision, out.text, host="codex")["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_D73_H2_the_S2_line_names_the_tag_and_the_release(tmp_path):
    repo = _repo(tmp_path)
    out = _outcome(repo, H2[0][0])
    assert _line(out) == ("Gate asks at git push v6.2.0 because a tag goes out, and a v-tag can start a release that "
                          "needs an owner GO (D73).")
    assert _line(out, language="de") == ("Tor fragt bei git push v6.2.0, weil ein Tag nach außen geht und ein v-Tag "
                                         "eine Veröffentlichung mit Owner-GO auslösen kann (D73).")


# --- H3: gh pr create asks, the line names the limit of 8 --------------------------------------------------------------

H3 = [
    "gh pr create -R b7n0de/proofbundle --base main --head topic --title t --body-file notes.md",     # C2
    "gh pr create --fill",
    "gh pr new --title t --body b",
    "gh -R b7n0de/proofbundle pr create --title t --body b",
    "gh api repos/b7n0de/proofbundle/pulls -f title=t -f head=topic -f base=main",
    "gh api graphql -f query='mutation { createPullRequest(input: {}) { clientMutationId } }'",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", H3)
def test_D73_H3_gh_pr_create_asks_and_the_line_names_the_limit(tmp_path, form, host):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, host)
    assert out is not None and out.decision == "ask", (form, host, out and out.decision)
    assert "house_pr_limit" in [v.reason_id for v in out.verdicts]
    line = _line(out, host)
    assert f"at most {gate.HOUSE_PR_LIMIT} open PRs" in line and gate.HOUSE_PR_LIMIT == 8, line
    assert f"höchstens {gate.HOUSE_PR_LIMIT} offene PRs" in _line(out, host, "de")


# --- H4: a kill by pattern that can end its own command line asks -----------------------------------------------------

H4 = [
    ("pkill -f sleep; echo weiter", "pkill -f"),                          # S7
    ("pkill -f 'node server' && npm start", "pkill -f"),
    ("pkill -f sleep || true", "pkill -f"),
    ("pkill -f '[s]leep'; echo weiter", "pkill -f"),       # alone this pattern matches no line of its own; the chain asks
    ("pkill -f sleep", "pkill -f"),
    ("pkill --full sleep", "pkill -f"),
    ("pkill -fx sleep", "pkill -f"),
    ("pkill -9 -f sleep", "pkill -f"),
    ("sudo pkill -f sleep", "pkill -f"),
    ("killall sleep; echo weiter", "killall"),
    ("killall -9 sleep && echo weiter", "killall"),
    ("sleep 30 & killall sleep", "killall"),
    ("killall bash", "killall"),
    ("killall -r '^cla'", "killall"),
    ("pkill bash", "pkill"),
    ("pkill node", "pkill"),
    ("kill $$", "kill $$"),
    ("kill 0", "kill 0"),
    ("kill -9 -1", "kill -1"),
    ("kill $PPID", "kill $PPID"),
    ("kill $(pgrep -f sleep)", "pgrep -f"),
    ("pgrep -f sleep | xargs kill", "pgrep -f"),
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form, step", H4)
def test_D73_H4_a_kill_that_can_end_its_own_line_asks(tmp_path, form, step, host):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, host)
    assert out is not None and out.decision == "ask", (form, host, out and out.decision)
    reasons = [v.reason_id for v in out.verdicts]
    assert {"house_kill_pattern", "house_kill_own"} & set(reasons), reasons
    assert out.step == step, (out.step, step)
    assert _line(out, host).endswith(("(D73).", "(D73). Codex cannot ask, so the gate blocks the call."))


def test_D73_H4_the_S7_line_names_pkill_f_and_says_run_it_alone(tmp_path):
    repo = _repo(tmp_path)
    out = _outcome(repo, H4[0][0])
    assert _line(out) == "Gate asks at pkill -f because the pattern can also match its own command line; run it alone (D73)."
    assert _line(out, language="de") == ("Tor fragt bei pkill -f, weil das Muster auch die eigene Befehlszeile treffen "
                                         "kann; führe ihn einzeln aus (D73).")


# --- counter cases: they keep their answer, no house rule -------------------------------------------------------------

#: The answer at ffa7d39a and at the head, per host, measured with this file's repository: (decision, reason ids).
COUNTER = {
    "gh pr merge 12 -R b7n0de/proofbundle --auto --merge": (("pass", ["free_work_profile"]),
                                                            ("ask", ["net_unmodeled_git"])),
    "git tag -l": (("pass", ["free_work_profile"]), ("ask", ["git_form_not_free"])),
    "git push origin topic": (("ask", ["push_not_measured"]), ("warn", ["codex_context_unbound"])),
    "git push origin main": (("ask", ["push_not_measured"]), ("warn", ["codex_context_unbound"])),
    "git push origin candidate-branch": (("ask", ["push_not_measured"]), ("warn", ["codex_context_unbound"])),
    "git tag v6.2.0": (("ask", ["git_form_not_free"]), ("ask", ["git_form_not_free"])),
    "pkill sleep": ((None, []), (None, [])),
    "kill 12345": ((None, []), (None, [])),
    "kill -9 12345": ((None, []), (None, [])),
    "pkill -f '[s]leep'": ((None, []), (None, [])),
    "gh pr merge 12 --auto --merge --subject --admin": (("ask", ["net_unmodeled_git"]), ("ask", ["net_unmodeled_git"])),
    'gh pr merge 12 --auto --merge --body "never use --admin"': (("ask", ["net_unmodeled_git"]),
                                                                 ("ask", ["net_unmodeled_git"])),
    "gh pr merge 12 -- --admin": (("ask", ["net_unmodeled_git"]), ("ask", ["net_unmodeled_git"])),
    # changed in Nachtrag 48 (D117): under Claude Code a word in the message is no call, the net counts it no more
    'git commit -m "gh pr merge 12 --admin is a house rule"': (("pass", ["free_after_state_check"]),
                                                               ("ask", ["free_after_state_check", "net_unmodeled_git"])),
    "echo 'gh pr merge 12 --admin'": ((None, []), (None, [])),
    "cat > notes2.md <<'EOF'\ngh pr merge 12 --admin\npkill -f x; killall y\nEOF": ((None, []), (None, [])),
    "gh api repos/b7n0de/proofbundle/branches/main/protection": (("pass", ["free_after_gh_profile"]),
                                                                 ("pass", ["free_after_gh_profile"])),
    "gh api -X GET repos/b7n0de/proofbundle/rulesets": (("pass", ["free_after_gh_profile"]),
                                                        ("pass", ["free_after_gh_profile"])),
    "grep -rn pkill notes.md": ((None, []), (None, [])),
    # a name that is a branch and a tag: git refuses the push as ambiguous and sends nothing; a full destination of
    # refs/heads/ and a short destination are no tag the repository sends
    "git push origin twin": (("ask", ["push_not_measured"]), ("warn", ["codex_context_unbound"])),
    "git push origin main:refs/heads/release-candidate": (("ask", ["push_not_measured"]),
                                                          ("warn", ["codex_context_unbound"])),
    "git push origin main:release-candidate": (("ask", ["push_not_measured"]), ("warn", ["codex_context_unbound"])),
}


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", sorted(COUNTER))
def test_D73_control_a_counter_case_keeps_its_answer(tmp_path, form, host):
    repo = _repo(tmp_path)
    assert _answer(repo, form, host) == COUNTER[form][HOSTS.index(host)], (form, host)


# --- the house rules weigh against the gate's own answer --------------------------------------------------------------

def test_D73_a_house_rule_goes_before_every_answer_that_lets_a_call_run(tmp_path):
    deadline = time.monotonic() + 60
    for decision, reason in (("pass", "free_work_profile"), ("handover", "handed_over"), ("warn", "codex_context_unbound"),
                             ("inactive", "nothing_declared"), ("ask", "push_not_measured")):
        own = gate.Verdict(decision, "detail (DECISIONS.md D3).", reason)
        out = gate._with_house_rules(gate.Outcome(decision, own.detail, [own]), "pkill -f x; true", str(tmp_path),
                                     deadline)
        assert out.decision == "ask" and [v.reason_id for v in out.verdicts] == [reason, "house_kill_pattern"]
        assert out.step == "pkill -f" and out.cause.reason_id == "house_kill_pattern"
    denied = gate.Verdict("deny", "detail (DECISIONS.md D6).", "verification_failed")
    out = gate._with_house_rules(gate.Outcome("deny", denied.detail, [denied], step="git push"), "pkill -f x; true",
                                 str(tmp_path), deadline)
    assert out.decision == "deny" and out.step == "git push" and out.cause is None   # a deny of the gate stays first
    asked = gate.Verdict("ask", "detail (DECISIONS.md D27).", "net_unmodeled_git")
    out = gate._with_house_rules(gate.Outcome("ask", asked.detail, [asked]), "gh pr merge 1 --admin", str(tmp_path),
                                 deadline)
    assert out.decision == "deny" and out.cause.reason_id == "house_admin_merge"
    assert gate._with_house_rules(None, "ls -la", str(tmp_path), deadline) is None


def test_D73_a_house_rule_goes_before_D71(tmp_path):
    """`gh pr merge --auto` is free under D71 in this repository; with --admin H1 denies it, with a tag H2 asks."""
    repo = _repo(tmp_path)
    assert _answer(repo, "gh pr merge 12 -R b7n0de/proofbundle --auto --merge") == ("pass", ["free_work_profile"])
    out = _outcome(repo, "gh pr merge 12 -R b7n0de/proofbundle --auto --merge --admin")
    assert out.decision == "deny" and "house_admin_merge" in [v.reason_id for v in out.verdicts]


# --- the hook as the host runs it -------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("command, decision, word", [
    (H1_ADMIN[0], "deny", "--admin"), ("pkill -f sleep; echo weiter", "ask", "pkill -f"),
    ("git push origin v6.2.0", "ask", "v6.2.0")])
def test_D73_the_hook_as_the_host_runs_it(tmp_path, host, command, decision, word):
    repo = _repo(tmp_path)
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}, "session_id": "n30"})
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert proc.returncode == 0, proc.stderr
    expected = "deny" if host == "codex" else decision
    assert answer["hookSpecificOutput"]["permissionDecision"] == expected, answer
    assert word in answer["systemMessage"] and "(D73)." in answer["systemMessage"], answer["systemMessage"]
    assert not (tmp_path / "gh_started.log").exists() or "--version" not in (tmp_path / "gh_started.log").read_text()


# --- the grammar of the house rules -----------------------------------------------------------------------------------

@pytest.mark.parametrize("args, admin", [
    (["--admin"], True), (["12", "--admin=1"], True), (["-sd", "--admin"], True), (["-t", "x", "--admin"], True),
    (["--subject", "--admin"], False), (["--body", "--admin"], False), (["-t", "--admin"], False),
    (["-dt", "--admin"], False), (["--subject=x", "--admin"], True), (["--", "--admin"], False),
    (["--ADMIN"], False), (["--adm"], False)])
def test_D73_H1_admin_is_read_as_gh_reads_it(args, admin):
    assert gate._house_admin(args) is admin


@pytest.mark.parametrize("args, endpoint, method", [
    (["repos/a/b"], "repos/a/b", "GET"), (["repos/a/b", "-f", "x=1"], "repos/a/b", "POST"),
    (["-X", "GET", "repos/a/b", "-f", "x=1"], "repos/a/b", "GET"), (["-XDELETE", "repos/a/b"], "repos/a/b", "DELETE"),
    (["--method=put", "repos/a/b"], "repos/a/b", "PUT"), (["repos/a/b", "--input", "f.json"], "repos/a/b", "POST"),
    (["-X", "$M", "repos/a/b"], "repos/a/b", "?"), (["-H", "Accept: x", "repos/a/b"], "repos/a/b", "GET")])
def test_D73_a_gh_api_call_is_read_as_gh_reads_it(args, endpoint, method):
    assert gate._house_api_call(args)[:2] == (endpoint, method)


def test_D73_a_here_document_body_is_no_call():
    text = "cat > f <<'EOF'\ngh pr merge 1 --admin\nEOF\ngit status\ncat <<-X\n\tpkill -f y\n\tX\necho <<<z"
    assert gate._house_strip_heredocs(text) == "cat > f <<'EOF'\ngit status\ncat <<-X\necho <<<z"


@pytest.mark.parametrize("args, full, pattern", [
    (["-f", "x"], True, 1), (["--full", "x"], True, 1), (["-fx", "x"], True, 1), (["-9", "-f", "x"], True, 2),
    (["-u", "root", "x"], False, 2), (["-uroot", "-f", "x"], True, 2), (["x"], False, 0), (["--", "-f"], False, 1)])
def test_D73_H4_pkill_is_read_as_procps_reads_it(args, full, pattern):
    assert gate._house_pgrep_args(args)[:2] == (full, pattern)


@pytest.mark.parametrize("args, targets", [
    (["123"], ["123"]), (["-9", "123"], ["123"]), (["-9", "-1"], ["-1"]), (["-s", "KILL", "0"], ["0"]),
    (["-1"], []), (["--", "-1"], ["-1"]), (["-l"], [])])
def test_D73_H4_kill_is_read_as_bash_reads_it(args, targets):
    assert gate._house_kill_targets(args) == targets
