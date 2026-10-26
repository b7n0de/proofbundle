"""Class b of the ask load (FIX-18 part B, DESIGN_ask_load.md 3.2, D36): a gh read form is free after a gh profile.

The owner's answers of 2026-10-14 (equal to the reviewer's recommendations): no `gh attestation verify` (answer 4); the
rules bound to checked gh versions (answer 5); class b applies under Codex too (answer 10); and, as for class a, a pager
counts because no host adapter is bound (answer 3). The allow-list is gh 2.89.0's, measured against a local stand-in
for github.com in a network namespace of its own; the measurements live in the archive of this build, not here.

FREE: asked at ac0e8a72, the parent of this build, free here. KEEP: not free at the parent and here; each names the
rule of the build it guards, and the mutant of that rule frees it. The gh the gate checks is a script in tmp_path that
answers `--version` as gh 2.89.0 does and records any other start, so no case depends on the gh of the machine and no
case starts a real gh; one case at the end checks the real gh where it is 2.89.0. Every repository lives under tmp_path
and has no remote that is reached.
"""
from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
gate = n2c.gate
FREE = ("pass", "inactive", "allow")
VERSION_LINE = "gh version 2.89.0 (2026-03-26)"


def _fake_gh(folder: pathlib.Path, version_line: str = VERSION_LINE) -> None:
    """A gh that answers `--version` with version_line and records every other start."""
    (folder / "gh").write_text(f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "{version_line}"; '
                               'echo "https://github.com/cli/cli/releases/tag/v2.89.0"; exit 0; fi\n'
                               f'echo "$*" >> {folder.parent / "gh_started.log"}\nexit 0\n')
    (folder / "gh").chmod(0o755)


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment: no GH_* name, no PAGER, a home and a gh configuration folder of its own, and a bin folder
    with the stand-in gh first on PATH (only absolute entries)."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    _fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60)
    for key, value in (("user.name", "t"), ("user.email", "t@example.org"), ("commit.gpgsign", "false"),
                       ("remote.origin.url", "https://github.com/o/r.git")):
        subprocess.run(["git", "-C", str(repo), "config", key, value], check=True, timeout=60)
    (repo / "a.txt").write_text("a\n")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True, timeout=60)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "one"], check=True, timeout=60)
    return repo


def _decide(repo: pathlib.Path, command: str, host: str = "claude") -> tuple[str | None, list[str]]:
    # The gate reads this process's environment: the caller's names are withheld (tests/_plugin_env.py), so it holds
    # what _clean and the case set, the GH_* names among them.
    out = gate.decide(command, str(repo), time.monotonic() + 120, host)
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


def _asked(decision: str | None, reasons: list[str]) -> bool:
    """Asked, and not by the gh profile's pass: at the parent the safety net asks (net_unmodeled_git), here the gh
    profile names what it found (gh_form_not_free, held by test_the_gh_profile_names_what_it_found)."""
    return decision == "ask" and "free_after_gh_profile" not in reasons and \
        bool({"gh_form_not_free", "net_unmodeled_git", "step_after_state_change"} & set(reasons))


def _config(tmp_path: pathlib.Path, name: str, text: str) -> pathlib.Path:
    path = tmp_path / "home" / ".config" / "gh" / name
    path.write_text(text)
    return path


# --- FREE: the read forms of the allow-list -------------------------------------------------------------------------

READ_FORMS = [
    "gh pr view 41", "gh pr view", "gh pr view 41 --comments", "gh pr view 41 --json title,state --jq .state",
    "gh pr view 41 -R o/r", "gh pr view 41 --repo=o/r", "gh pr checks 41", "gh pr checks 41 --watch --interval 5",
    "gh pr checks --required", "gh pr diff 41 --name-only", "gh pr diff 41 --color never",
    "gh pr list --limit 10 --state all", "gh pr list -L5 -s merged", "gh pr status", "gh run view 1 --log",
    "gh run view 1 --log-failed", "gh run list -w ci -L 5", "gh run list --branch main --json status",
    "gh issue view 7 --comments", "gh issue list -S 'is:open label:bug'", "gh release view v1.0.0",
    "gh release list -L 3", "gh repo view o/r --json name", "gh repo view", "gh workflow list --all",
    "gh workflow view ci.yml --yaml", "gh auth status", "gh auth status --active", "gh --version",
    "gh pr view 41 --template '{{.title}}'", "gh pr view --help",
    # a quoted or escaped command word runs the same gh (and no alias), as class a reads `"git" status` (D34)
    '"gh" pr list', "\\gh pr list", "g'h' pr list",
    "gh api repos/o/r", "gh api /repos/o/r", "gh api repos/o/r --jq .full_name", "gh api 'repos/{owner}/{repo}'",
    "gh api repos/o/r/pulls --paginate --jq '.[].number'", "gh api -i repos/o/r", "gh api --verbose repos/o/r",
    "gh api -X GET search/issues -f q=repo:o/r", "gh api --method GET search/issues -F q=repo:o/r",
    "gh api 'repos/o/r/actions/runs?per_page=5'", "gh api repos/o/r -H 'Accept: application/vnd.github+json'",
    "gh api repos/o/r --cache 1h",
    "gh api graphql -f query='query{viewer{login}}'", "gh api graphql -f query='{viewer{login}}'",
    "gh api graphql -f query='query Q($n:Int){viewer{repositories(first:$n){nodes{name}}}}' -F n=3",
    "gh api graphql -f query='fragment F on User{login} query{viewer{...F}}'",
    "gh api graphql -f query='query{repository(owner:\"o\",name:\"r\"){description}}'",
    "gh api graphql -f 'query=query { viewer { login } } # a comment'",
]
#: Read forms inside a longer command, judged by class c step by step (D33).
IN_CHAINS = [
    "gh pr checks 41 | head -20", "gh run list --limit 5 && gh run view 1 | head -30",
    "echo \"PR: $(gh pr view 41 --json state --jq .state)\"", "gh pr view 41 && git log -1",
    "gh pr view 41 --comments | tail -40", "gh api graphql -f query='{viewer{login}}' | jq .",
]


@pytest.mark.parametrize("command", READ_FORMS + IN_CHAINS)
def test_FREE_a_gh_read_form_is_free_after_the_gh_profile(tmp_path, command):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision in FREE, (command, decision, reasons)
    assert "free_after_gh_profile" in reasons, (command, reasons)
    assert not (tmp_path / "gh_started.log").exists(), "the gate started gh for more than --version"


@pytest.mark.parametrize("command", ["gh pr view 41", "gh api repos/o/r --jq .full_name", "gh pr checks 41 | head -20",
                                     "gh auth status", "gh api graphql -f query='{viewer{login}}'"])
def test_FREE_class_b_applies_under_codex(tmp_path, command):
    """Owner answer 10: a, d and e are off under Codex, b is not; the gh profile reads no repository, so the directory
    the Codex hook cannot bind plays no part."""
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command, "codex")
    assert decision in FREE and "free_after_gh_profile" in reasons, (command, decision, reasons)


@pytest.mark.parametrize("environ", [{"GH_TOKEN": "x"}, {"GITHUB_TOKEN": "x"}, {"GH_REPO": "o/r"},
                                     {"GH_NO_UPDATE_NOTIFIER": "1"}, {"GH_DEBUG": "api"}, {"GH_EDITOR": "vi"},
                                     {"GH_BROWSER": "firefox"}, {"NO_COLOR": "1"}, {"BROWSER": "x"}])
def test_FREE_an_inert_environment_name_keeps_the_form_free(tmp_path, monkeypatch, environ):
    for key, value in environ.items():
        monkeypatch.setenv(key, value)
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert decision in FREE, (environ, reasons)


@pytest.mark.parametrize("text", ["version: 1\ngit_protocol: https\npager:\nhttp_unix_socket:\nbrowser:\n",
                                  "pager: \"\"\n", "pager: ''\n",
                                  "# What protocol to use\ngit_protocol: https # inline\neditor:\nprompt: enabled\n"
                                  "aliases:\n    co: pr checkout\n    prv: pr view\n"])
def test_FREE_a_configuration_without_a_pager_or_socket_keeps_the_form_free(tmp_path, text):
    """An empty pager starts none (measured with gh 2.89.0 on a terminal: `pager:` and `pager: ""`); older gh wrote
    this template with every key empty."""
    _config(tmp_path, "config.yml", text)
    _config(tmp_path, "hosts.yml", "github.com:\n    users:\n        u:\n            oauth_token: x\n"
                                   "    git_protocol: https\n    oauth_token: x\n    user: u\n")
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert decision in FREE, (text, reasons)


def test_FREE_an_empty_GH_PAGER_overrides_the_configured_pager(tmp_path, monkeypatch):
    """Measured with gh 2.89.0 on a terminal: GH_PAGER set and empty, the configured pager did not start."""
    _config(tmp_path, "config.yml", "pager: less\n")
    monkeypatch.setenv("GH_PAGER", "")
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert decision in FREE, reasons


def test_FREE_a_write_outside_the_gh_configuration_before_a_gh_step(tmp_path):
    other = tmp_path / "notes.txt"
    # a write with `>`: an append outside the work folder is denied since D104 (Nachtrag 33)
    decision, reasons = _decide(_repo(tmp_path), f"echo x > {shlex.quote(str(other))}; gh pr view 41")
    assert decision in FREE, reasons


# --- KEEP: every rule of the build, each not free at the parent and here --------------------------------------------

KEEP = [
    # the forms that open a browser, name another host or print the token
    ("web", "gh pr view 41 --web"), ("web", "gh pr view 41 -w"), ("web", "gh repo view --web"),
    ("web", "gh run view 1 -w"), ("web", "gh browse"),
    ("hostname", "gh api --hostname evil.example repos/o/r"), ("hostname", "gh auth status --hostname x"),
    ("hostname", "gh auth status -h x"),
    ("token", "gh auth status -t"), ("token", "gh auth status --show-token"), ("token", "gh auth token"),
    # a repository in another spelling names its own host (measured)
    ("repo_form", "gh pr view 1 -R git@127.0.0.1:o/r"), ("repo_form", "gh pr view 1 -R https://127.0.0.1/o/r"),
    ("repo_form", "gh pr view 1 -R 127.0.0.1/o/r"), ("repo_form", "gh pr view 1 --repo=evil.example/o/r"),
    ("repo_form", "gh repo view 127.0.0.1/o/r"), ("repo_form", "gh repo view git@127.0.0.1:o/r"),
    ("repo_form", "gh repo view https://127.0.0.1/o/r"),
    # a URL as the argument names its own host (measured); one argument at most
    ("positional", "gh pr view https://127.0.0.1/o/r/pull/1"),
    ("positional", "gh pr diff https://127.0.0.1/o/r/pull/1"),
    ("positional", "gh pr checks https://127.0.0.1/o/r/pull/1"),
    ("positional", "gh issue view https://127.0.0.1/o/r/issues/1"), ("positional", "gh pr view 1 2"),
    ("positional", "gh pr list extra"), ("positional", "gh pr view feature-branch"),
    # jq reads the environment (measured: the token printed)
    ("jq_env", "gh api repos/o/r --jq '$ENV.GH_TOKEN'"), ("jq_env", "gh api repos/o/r --jq 'env.GH_TOKEN'"),
    ("jq_env", "gh pr view 41 --json title --jq '$ENV|keys'"), ("jq_env", "gh pr view 41 --json title -q env"),
    ("jq_env", "gh api repos/o/r -q '\"\\(env)\"'"),
    # gh api: a method other than GET, a field without -X GET, a local file, a header, a full URL
    ("api_method", "gh api -X POST repos/o/r/issues -f title=x"),
    ("api_method", "gh api --method=PUT repos/o/r/topics -f names[]=x"),
    ("api_method", "gh api -XDELETE repos/o/r/git/refs/heads/x"), ("api_method", "gh api -X get repos/o/r"),
    ("api_field", "gh api repos/o/r/issues -f title=x"), ("api_field", "gh api repos/o/r/issues -F title=x"),
    ("api_field", "gh api repos/o/r/issues --raw-field title=x"),
    ("api_file", "gh api -X GET repos/o/r -F x=@secret.txt"), ("api_file", "gh api -X GET repos/o/r -f x=@secret.txt"),
    ("api_file", "gh api -X GET repos/o/r --input body.json"), ("api_file", "gh api -X GET repos/o/r -F x=@-"),
    ("api_header", "gh api repos/o/r -H 'X-HTTP-Method-Override: DELETE'"),
    ("api_url", "gh api https://evil.example/x"), ("api_url", "gh api HTTPS://127.0.0.1/x"),
    ("api_url", "gh api //127.0.0.1/x"), ("api_url", "gh api 'repos/o/r?u=https://127.0.0.1/'"),
    ("api_url", "gh api graphql/x"),
    # GraphQL: one query and nothing else
    ("graphql", "gh api graphql -f query='mutation{addStar(input:{starrableId:\"R\"}){clientMutationId}}'"),
    ("graphql", "gh api graphql -f query='query{viewer{login}} mutation{addStar(input:{starrableId:\"R\"})"
                "{clientMutationId}}'"),
    ("graphql", "gh api graphql -f query='query A{viewer{login}}' -f operationName=A"),
    ("graphql", "gh api graphql -F query=@q.graphql"), ("graphql", "gh api graphql --input q.json"),
    ("graphql", "gh api graphql -F query='{viewer{login}}'"), ("graphql", "gh api graphql -f query='subscription{x}'"),
    ("graphql", "gh api graphql -f query='{viewer{login}'"), ("graphql", "gh api graphql -X GET -f query='{a}'"),
    ("graphql", "gh api graphql -f query='{a}' -f query='{b}'"), ("graphql", "gh api graphql -f query='{a} {b}'"),
    ("graphql", "gh api graphql -f query='type X{a:Int}'"), ("graphql", "gh api graphql"),
    # every other command and option as gh 2.89.0 lists them
    ("command", "gh pr merge 41 --merge"), ("command", "gh pr comment 41 --body x"),
    ("command", "gh attestation verify dist/x.whl --repo o/r"), ("command", "gh pr checkout 41"),
    ("command", "gh run download 1"), ("command", "gh foo"), ("command", "gh view x"),
    ("command", "gh config set pager cat"), ("command", "gh search prs foo"), ("command", "gh status"),
    ("command", "gh run watch 1"), ("command", "gh pr ls"), ("command", "gh -R o/r pr view 1"),
    ("option", "gh pr view 41 --unknown"), ("option", "gh pr view -cw 41"), ("option", "gh pr view 41 --comments=true"),
    ("option", "gh pr view -- 41"), ("option", "gh pr view 41 -R=o/r"), ("option", "gh pr view 41 --json"),
    # the command as a whole: a prefix assignment, a program path, a word the shell may rewrite, a redirection
    ("assignment", "LANG=C gh pr view 41"), ("assignment", "GH_HOST=evil gh api repos/o/r"),
    ("assignment", "GH_PAGER=cat gh pr view 41"),
    ("bare", "/usr/bin/gh pr view 41"), ("bare", "./gh pr view 41"),
    ("rewrite", "gh api repos/o/r/actions/runs?per_page=5"), ("rewrite", "gh pr view 4*"),
    ("rewrite", "gh api repos/{owner}/{repo}"),
    ("redirect", "gh pr view 41 > out.txt"), ("redirect", "gh api repos/o/r 2> err.txt"),
    # class c: a step before the gh step that changes what the gh profile read
    ("chain", "gh config set pager less; gh pr view 41"), ("chain", "export GH_HOST=evil; gh api repos/o/r"),
    ("chain", "GH_FORCE_TTY=1; gh pr view 41"), ("chain", "env gh pr view 41"), ("chain", "bash -c 'gh pr view 41'"),
]


@pytest.mark.parametrize("rule,command", KEEP)
def test_KEEP_a_form_outside_the_allow_list_keeps_todays_answer(tmp_path, rule, command):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (rule, command, reasons)
    assert "free_after_gh_profile" not in reasons, (rule, command, reasons)


@pytest.mark.parametrize("rule,command", [k for k in KEEP if k[0] in ("web", "token", "jq_env", "api_method",
                                                                       "graphql", "repo_form")])
def test_KEEP_under_codex_too(tmp_path, rule, command):
    decision, reasons = _decide(_repo(tmp_path), command, "codex")
    assert decision not in FREE, (rule, command, reasons)


def test_KEEP_a_write_into_the_gh_configuration_before_a_gh_step(tmp_path):
    """Class c (D33, D36): the gh profile read the configuration before the chain ran, so a step that writes into gh's
    configuration folder before the gh step changes what that answer read."""
    path = tmp_path / "home" / ".config" / "gh" / "config.yml"
    decision, reasons = _decide(_repo(tmp_path), f"echo 'pager: less' >> {shlex.quote(str(path))}; gh pr view 41")
    # the append lies outside the work folder and is denied since D104 (Nachtrag 33); the step keeps its reason
    assert decision in ("ask", "deny") and "step_after_state_change" in reasons, reasons


ENV_KEEP = [("PAGER", "less"), ("PAGER", ""), ("GH_PAGER", "less"), ("GH_FORCE_TTY", "1"), ("GH_HOST", "evil.example"),
            ("GH_ENTERPRISE_TOKEN", "x"), ("GITHUB_ENTERPRISE_TOKEN", "x"), ("GH_REPO", "127.0.0.1/o/r"),
            ("GH_REPO", "git@127.0.0.1:o/r"), ("GH_PATH", "/x/gh"), ("GH_SOMETHING_NEW", "1"),
            ("GH_CONFIG_DIR", "relative/gh")]


@pytest.mark.parametrize("name,value", ENV_KEEP)
def test_KEEP_the_hooks_environment_counts(tmp_path, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert _asked(decision, reasons), (name, reasons)


CONFIG_KEEP = [
    ("config.yml", "pager: less\n"), ("config.yml", "http_unix_socket: /tmp/gh.sock\n"),
    ("config.yml", "pager: 'less -R'\n"), ("config.yml", "something_new: x\n"),
    ("config.yml", "aliases: {co: pr checkout}\n"), ("config.yml", "pager: &p less\n"),
    ("config.yml", "pager: |\n  x\n"),
    ("config.yml", "- pager\n"), ("config.yml", "\tpager: x\n"), ("config.yml", "editor: vim's\n"),
    ("config.yml", "hosts:\n    github.com:\n        pager: less\n"),
    ("hosts.yml", "github.com:\n    pager: less\n"), ("hosts.yml", "github.com:\n    http_unix_socket: /s\n"),
    ("hosts.yml", "github.com:\n    something_new: x\n"), ("hosts.yml", "github.com:\n    users:\n        u:\n"
                                                                     "            pager: less\n"),
]


@pytest.mark.parametrize("name,text", CONFIG_KEEP)
def test_KEEP_gh_configuration_counts(tmp_path, name, text):
    _config(tmp_path, name, text)
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert _asked(decision, reasons), (name, text, reasons)


def test_KEEP_the_configuration_folder_follows_xdg(tmp_path, monkeypatch):
    folder = tmp_path / "xdg" / "gh"
    folder.mkdir(parents=True)
    (folder / "config.yml").write_text("pager: less\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert _asked(decision, reasons), reasons


def test_KEEP_no_home_and_no_configuration_folder(tmp_path, monkeypatch):
    monkeypatch.delenv("HOME")
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert _asked(decision, reasons), reasons


@pytest.mark.parametrize("line", ["gh version 2.88.0 (2026-02-01)", "gh version 2.90.0 (2026-05-01)", "not gh at all",
                                  ""])
def test_KEEP_a_gh_version_the_gate_has_not_measured(tmp_path, line):
    _fake_gh(tmp_path / "bin", line)
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert _asked(decision, reasons), (line, reasons)


def test_KEEP_no_gh_on_path(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "home"))
    decision, reasons = _decide(repo, "gh pr view 41")
    assert _asked(decision, reasons), reasons


@pytest.mark.parametrize("entry", ["", "bin", "/proc/self/cwd"])
def test_KEEP_a_path_entry_that_depends_on_the_process(tmp_path, monkeypatch, entry):
    monkeypatch.setenv("PATH", os.pathsep.join([entry, str(tmp_path / "bin"), "/usr/bin", "/bin"]))
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert _asked(decision, reasons), (entry, reasons)


def test_the_profile_starts_gh_only_for_its_version(tmp_path):
    """The gate starts the gh on PATH only with --version (once for the whole command and once for its step, D33)."""
    log = tmp_path / "versions.log"
    (tmp_path / "bin" / "gh").write_text(f'#!/bin/sh\necho "$*" >> {log}\nif [ "$1" = "--version" ]; then '
                                         f'echo "{VERSION_LINE}"; exit 0; fi\nexit 0\n')
    decision, _reasons = _decide(_repo(tmp_path), "gh pr view 41")
    assert decision in FREE
    assert set(log.read_text().splitlines()) == {"--version"}


@pytest.mark.skipif(not shutil.which("gh", path="/usr/local/bin:/usr/bin:/bin"), reason="no gh on the machine")
def test_the_real_gh_of_the_machine_where_it_is_2_89_0(tmp_path, monkeypatch):
    """The version line of the real gh: free where it is 2.89.0, asked for any other version."""
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    real = subprocess.run(["gh", "--version"], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path / "home"),
                               "GH_NO_UPDATE_NOTIFIER": "1"}).stdout
    decision, reasons = _decide(_repo(tmp_path), "gh pr view 41")
    if real.startswith("gh version 2.89.0 ("):
        assert decision in FREE, reasons
    else:
        assert _asked(decision, reasons), reasons


def test_the_graphql_reader_counts_operations_not_words():
    """Unit cases of the document reader: one query, fragments beside it, strings and comments that hold braces or
    the word mutation, and the forms it refuses."""
    assert gate._gh_graphql_query_only('query { a(x: "} mutation {") }')
    assert gate._gh_graphql_query_only('{ a } # mutation { b }')
    assert gate._gh_graphql_query_only('query Q($a: In = {x: 1}) @d(y: 2) { a }')
    assert gate._gh_graphql_query_only('query { a(x: """doc \\""" mutation { b }""") }')
    assert not gate._gh_graphql_query_only('"""a description""" query { a }')   # no description on an operation
    assert not gate._gh_graphql_query_only('mutation M { a }')
    assert not gate._gh_graphql_query_only('query { a } query { b }')
    assert not gate._gh_graphql_query_only('fragment F on X { a }')
    assert not gate._gh_graphql_query_only('query { a ')
    assert not gate._gh_graphql_query_only('query { a(x: "open) }')
    assert not gate._gh_graphql_query_only('extend type X { a: Int }')
    assert not gate._gh_graphql_query_only('')


@pytest.mark.parametrize("kind,value,named", [
    ("env", ("PAGER", "less"), "a pager: PAGER"), ("env", ("GH_HOST", "evil.example"), "GH_HOST"),
    ("env", ("GH_REPO", "127.0.0.1/o/r"), "GH_REPO"), ("config", "pager: less", "a pager: pager"),
    ("config", "http_unix_socket: /s", "a unix socket for HTTP"),
    ("version", "gh version 2.88.0 (2026-02-01)", "version 2.88.0"),
])
def test_the_gh_profile_names_what_it_found(tmp_path, monkeypatch, kind, value, named):
    """The build's own answer (D36): the gh profile names what it found, with the reason id gh_form_not_free (at the
    parent the safety net asked with net_unmodeled_git and named nothing)."""
    if kind == "env":
        monkeypatch.setenv(*value)
    elif kind == "config":
        _config(tmp_path, "config.yml", value + "\n")
    else:
        _fake_gh(tmp_path / "bin", value)
    out = gate.decide("gh pr view 41", str(_repo(tmp_path)), time.monotonic() + 120, "claude")
    assert out.decision == "ask" and [v.reason_id for v in out.verdicts] == ["gh_form_not_free"], out.verdicts
    assert named in out.text, out.text
