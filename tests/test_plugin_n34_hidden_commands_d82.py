"""D82, follow-up note 34: a substitution bash runs, which the gate did not see, in a command it let through.

Found by the review session in the gate of follow-up note 31 (C31-1 to C31-3) and measured here with bash 5.2.21 and a marker program in
place of a real command (messung/truth_n34.jsonl): bash runs a substitution in the index of a name it reads (`[ -v
'a[$(…)]' ]`, `test -v`, `read 'a[$(…)]'`), single quotes or not; in an arithmetic expansion (`$(( $(…) ))`, `$[ … ]`),
quoted or not; in the index of a parameter expansion (`${a['$(…)']}`); after an apostrophe inside double quotes
(`"it's $(…)"`) and after an escaped quote (`it\\'s $(…)`), which the scanner of substitutions took for the start of a
single-quoted string; and in `$((…) )`, a command substitution of a subshell. The gate of 89d2e8b7 answered each with
nothing when the hidden command was `git push origin main`: the read forms of D66 and D77, the data steps of D72 and the
scanner shared by D3, D38, D67, D69 and D73 did not see it.

The rule (D82): the scanner of substitutions reads quotes as bash does and counts every substitution inside an
arithmetic or a parameter expansion; the net (D27) takes the same bodies; `read` is a read form only where each name is a
plain name; `[` and `test` count `-v` only before a plain name, in the read forms of D77 and in the steps of D72; the step
parser refuses `$[ ]`. Nothing gets freer: a command that was held stays held.

RED at 89d2e8b7 (the head of follow-up note 31): every hidden push. The controls (what bash does not run, and the read forms
that name git only as data) are green at both.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import time

import pytest

import test_plugin_n26_read_only_d66 as d66

gate = d66.gate
pytestmark = d66.pytestmark
_clean_git_environment = d66._clean_git_environment
repo = d66.repo
PUSH = "git push origin main"

#: Each form with {g} where the hidden command stands, and the hosts under which the gate of 89d2e8b7 let it through.
HIDDEN = [
    ("C31-1", "[ -v 'a[$({g})]' ]", "claude"),
    ("C31-1", "[ -v 'a[$({g})]' ] && ls", "claude"),
    ("C31-1", "[ ! -v 'a[$({g})]' ]", "claude"),
    ("C31-1", "test -v 'a[$({g})]'", "claude codex"),
    ("C31-2", "echo 1 | read 'a[$({g})]'", "claude codex"),
    ("C31-2", "echo 1 | read -r x 'a[$({g})]'", "claude codex"),
    ("C31-3", "echo $(( $({g}) + 1 ))", "claude codex"),
    ("C31-3", "echo \"$(( $({g}) + 1 ))\"", "claude codex"),
    ("C31-3", "echo $(( `{g}` + 1 ))", "claude codex"),
    ("C31-3", "echo $(( 'a[$({g})]' ))", "claude codex"),
    ("C31-3", "grep -c x README.md $(( $({g}) ))", "claude codex"),
    ("C31-3", "echo $(( ( $({g}) ) ))", "claude codex"),
    ("C34-1", "echo ${{PATH['$({g})']}}", "claude codex"),
    ("C34-1", "echo \"${{UNSET_X:-'$({g})'}}\"", "claude codex"),
    ("C34-2", "echo $[ 'a[$({g})]' ]", "claude codex"),
    ("C34-3", "echo $(({g}) )", "claude codex"),
    ("C34-4", "echo \"it's $({g})\"", "claude codex"),
    ("C34-4", "grep -c \"it's\" README.md $({g})", "claude codex"),
    ("C34-4", "echo it\\'s $({g})", "claude codex"),
]
#: What bash does not run, and read forms that name git only as data: free at both commits.
FREE = [
    ("claude codex", "echo 'a[$(git push origin main)]'"),
    ("claude", "[ 'a[$(git push origin main)]' -eq 0 ]"),
    ("claude", "[ -v PATH ]"),
    ("claude", "[ -n \"x\" ] && ls"),
    ("claude codex", "echo 1 | read -r line"),
    ("claude codex", "echo a b | read -r -a words"),
    ("claude codex", "echo 1 | while read -r a b; do echo \"$a\"; done"),
    ("claude codex", "echo $(( 1 + 2 ))"),
    ("claude codex", "grep -c \"it's\" README.md"),
    ("claude codex", "grep -c \"git push\" README.md"),
    ("claude codex", "echo \"it's git push\""),
    ("claude codex", "echo ${PATH:-x}"),
]


def decided(repo: pathlib.Path, command: str, host: str):
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("finding, form, _free_at_base", HIDDEN)
def test_D82_a_hidden_push_is_held(repo, finding, form, _free_at_base, host):
    out = decided(repo, form.format(g=PUSH), host)
    assert out is not None and out.decision in ("ask", "deny"), (finding, form, out and out.decision)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D82_a_house_rule_in_an_arithmetic_expansion_denies(repo, host):
    out = decided(repo, "echo $(( $(gh pr merge 1 --admin) ))", host)
    assert out is not None and out.decision == "deny", out and out.decision
    assert "house_admin_merge" in [v.reason_id for v in out.verdicts]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", ["echo ${a['$(gi? push origin main)']}", "echo $(( $(gi? push origin main) + 1 ))"])
def test_D82_the_net_reads_a_program_position_inside_an_expansion(repo, command, host):
    """A glob at the program position of a substitution inside a parameter or an arithmetic expansion may name git: the
    net (D27) takes the bodies the scanner finds, so the command is NOT MEASURED, never free."""
    out = decided(repo, command, host)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.decision)


@pytest.mark.parametrize("hosts, command", FREE)
def test_D82_control_what_bash_does_not_run_stays_free(repo, hosts, command):
    for host in hosts.split():
        out = decided(repo, command, host)
        assert out is None or out.decision == "pass", (host, command, out and [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("raw, bodies", [
    ("echo \"it's $(git push)\"", ["git push"]),
    ("echo it\\'s $(git push)", ["git push"]),
    ("echo $(( $(git push) + 1 ))", ["git push"]),
    ("echo $(( 'a[$(git push)]' ))", ["git push"]),
    ("echo $(( `git push` ))", ["git push"]),
    ("echo $((git push) )", ["(git push) "]),
    ("echo ${a['$(git push)']}", ["git push"]),
    ("echo $[ 'a[$(git push)]' ]", ["git push"]),
    ("cat <(git push)", ["git push"]),
    ("echo 'a[$(git push)]'", []),
    ("echo ${UNSET:-x} $(( 1 + 2 ))", []),
    ("echo \\$(git push)", []),
    ("echo \"$(git status)\" '$(git push)'", ["git status"]),
])
def test_D82_the_scanner_finds_what_bash_runs(raw, bodies):
    assert gate._subst_bodies(raw) == bodies, raw


@pytest.mark.parametrize("args, plain", [
    ("x", True), ("-r x y", True), ("-r -a words", True), ("-rp prompt x", True), ("-p 'a[$(m)]' x", True),
    ("-t 5 -n 1 -u 3 x", True), ("-d '' x", True), ("-- x", True), ("-ra words", True),
    ("'a[0]'", False), ("-a 'a[0]'", False), ("-aa[0]", False), ("x 'a[$(m)]'", False), ("-x y", False),
    ("$NAME", False), ("-p", False),
])
def test_D82_read_is_a_read_form_only_with_plain_names(args, plain):
    assert gate._read_only_form(f"echo 1 | read {args}") is plain, args


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("finding, form, _free_at_base", HIDDEN)
def test_D82_truth_bash_runs_the_hidden_command(tmp_path, finding, form, _free_at_base):
    """The truth each row stands on, measured with a marker program in place of the command; no git, no network."""
    marker = tmp_path / "pbmark"
    log = tmp_path / "mark.log"
    marker.write_text(f"#!/bin/sh\necho ran >> {log}\necho 0\n")
    marker.chmod(0o755)
    (tmp_path / "README.md").write_text("x\n")
    subprocess.run(["bash", "-c", form.format(g="pbmark")], cwd=tmp_path, capture_output=True, timeout=30,
                   env={"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path), "LC_ALL": "C"})
    assert log.exists(), (finding, form)
    assert os.path.getsize(log) > 0
