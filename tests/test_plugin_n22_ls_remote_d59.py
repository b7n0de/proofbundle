"""D59, follow-up note 22 part 3: `git -C <abs> ls-remote` from github.com is free after the fetch profile of D45.

Owner choice of 2026-10-17, 11:1x Berlin. Until now every ls-remote asked (_REMOTE_READS, D41), also where the fetch of
D45 is free; account A stopped at it on 2026-10-17 09:09Z. Free now, under Claude Code and never under Codex:
`git -C <literal absolute path> ls-remote [-q|--quiet] [--heads|--branches] [--tags] [--refs] <remote> [<pattern>…]`
as the whole command, when the fetch profile of D45 finds nothing for that remote. The grammar of _fetch_form: options
without a value before the remote, a remote name and not a URL or path, every word literal, no `$`, no word the shell
may rewrite, no `--`; a pattern may start with `refs/` but carries no `:`, `+`, `^`, `@{`, `..` and no glob. Every
other option (--upload-pack, -o, --server-option, --get-url, --symref, --sort) stays at D41.

Ground truth, measured with git 2.43.0 under strace with no network against a local stand-in for github.com
(truth_ls_remote_n22.py of the delivery, 58 cases): the form from https://github.com/<owner>/<repo> started
git-remote-https only, connected only to github.com and wrote nothing under .git; pager.ls-remote on a terminal, a
remote helper (remote.<name>.vcs), a URL rewrite, a proxy, a credential helper or askpass on a 401 and a remote word
that names a local repository started a program or reached another host, and the fetch profile finds each of them.

The repository is the clone of tests/test_plugin_fetch_github_profile.py: under an absolute path, origin
https://github.com/o/r with the one fetch rule of a clone; nothing is reached. RED at 9f578c2a: every free case, the
pass text, the asks that name what the profile found and the short line naming ls-remote; the other asks are controls,
green at both heads.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

import _worktree_layout as w
import test_plugin_ask_load_b_gh as b
import test_plugin_fetch_github_profile as f
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
gate = f.gate
FREE_ID = "free_after_ls_remote_profile"
FORMS = ["ls-remote origin", "ls-remote -q origin", "ls-remote --quiet origin", "ls-remote --heads origin",
         "ls-remote --branches origin", "ls-remote --tags origin", "ls-remote --refs origin",
         "ls-remote --heads --tags --refs origin main v1", "ls-remote origin refs/heads/main",
         "ls-remote -q --heads origin main release-2.1 feature/x", "ls-remote --tags origin refs/tags/v1.0"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_", "XDG_")) or k.lower().endswith("_proxy")
                or k in ("PAGER", "AI_AGENT", "CLAUDECODE", "DO_NOT_TRACK", "SSH_ASKPASS")]:
        monkeypatch.delenv(key, raising=False)
    w.clean(monkeypatch, tmp_path)
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    b._fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))
    for name, value in f.DELTA.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def repo(tmp_path):
    return f.repo.__wrapped__(tmp_path)


def _decide(repo, command: str, host: str = "claude"):
    return gate.decide(command.format(a=repo), str(repo), time.monotonic() + 180, host)


def _ls_free(out) -> bool:
    return out is not None and out.decision == "pass" and [v.reason_id for v in out.verdicts] == [FREE_ID]


def _d41(out) -> bool:
    """The ask of D41: remote_read_not_modeled, and never the free reason."""
    return out is not None and out.decision == "ask" and "remote_read_not_modeled" in [v.reason_id for v in
                                                                                        out.verdicts] \
        and FREE_ID not in [v.reason_id for v in out.verdicts]


def _hook(tmp_path, cwd, command: str, host: str = "claude", language: str | None = None, **extra: str):
    """The hook's decision and the short line (D53), with a gate directory of the case."""
    gate_dir = tmp_path / "gate-dir"
    gate_dir.mkdir(exist_ok=True)
    if language is not None:
        (gate_dir / "language").write_text(language + "\n", encoding="utf-8")
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    argv = [sys.executable, "-I", w.G] + (["--host", host] if host != "claude" else [])
    env = plugin_env(**f.DELTA, PATH=os.environ["PATH"], CLAUDE_PLUGIN_DATA=str(tmp_path / "plugin-data"),
                     PLUGIN_DATA=str(tmp_path / "plugin-data"), PROOFBUNDLE_GATE_DIR=str(gate_dir), **extra)
    proc = subprocess.run(argv, input=event, capture_output=True, text=True, env=env, timeout=180, check=False)
    answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return proc.returncode, answer.get("hookSpecificOutput", {}).get("permissionDecision"), answer.get("systemMessage")


# --- free ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("form", FORMS)
def test_D59_the_form_from_github_is_free(repo, form):
    out = _decide(repo, f"git -C {{a}} {form}")
    assert _ls_free(out), (form, out and out.text)


def test_D59_a_url_with_dot_git_and_another_remote_name_are_free(repo):
    w.git(repo, "remote", "set-url", "origin", "https://github.com/o/r.git")
    w.git(repo, "remote", "add", "upstream", "https://github.com/up-stream/r.e_po")
    assert _ls_free(_decide(repo, "git -C {a} ls-remote origin"))
    assert _ls_free(_decide(repo, "git -C {a} ls-remote --heads upstream main"))


def test_D59_free_through_the_hook_and_silent(tmp_path, repo):
    assert _hook(tmp_path, tmp_path, f"git -C {repo} ls-remote --heads origin main") == (0, None, None)


def test_D59_the_pass_names_the_profile_and_D59_and_no_value(repo):
    detail = _decide(repo, "git -C {a} ls-remote origin").verdicts[0].detail
    for named in ("git ls-remote origin is free", "The fetch profile of D45",
                  "at a URL of the form https://github.com/<owner>/<repo>", "writes nothing in the repository",
                  "D45, D59", "A pager is named (PAGER in the hook's environment)", "git ls-remote starts none"):
        assert named in detail, (named, detail)
    assert "github.com/o/r" not in detail      # the URL is named by its form, never its value (D49)


@pytest.mark.parametrize("setting", [("core.pager", "less"), ("@env", "GIT_PAGER"), ("pager.ls-remote", "true")])
def test_D59_a_pager_ls_remote_does_not_start_does_not_count(repo, monkeypatch, setting):
    """Measured: PAGER, GIT_PAGER and core.pager started nothing, on a terminal too; pager.ls-remote started its pager on
    a terminal and is bound under the host of D42 (AI_AGENT of account A)."""
    if setting[0] == "@env":
        monkeypatch.setenv(setting[1], "less")
    else:
        w.git(repo, "config", *setting)
    assert _ls_free(_decide(repo, "git -C {a} ls-remote origin")), setting


@pytest.mark.parametrize("hook", ["pre-push", "post-checkout", "pre-commit", "post-merge"])
def test_D59_a_hook_the_fetch_does_not_run_keeps_it_free(tmp_path, repo, hook):
    w.proxy(tmp_path, repo / ".git" / "hooks" / hook, "hook")
    assert _ls_free(_decide(repo, "git -C {a} ls-remote origin"))


# --- the options and words D59 leaves at D41: each asks -------------------------------------------------------------

EXCLUDED = {
    "--upload-pack=": "git -C {a} ls-remote --upload-pack=/bin/true origin",
    "--upload-pack": "git -C {a} ls-remote --upload-pack /bin/true origin",
    "-o": "git -C {a} ls-remote -o x origin",
    "-o attached": "git -C {a} ls-remote -ox origin",
    "--server-option=": "git -C {a} ls-remote --server-option=x origin",
    "--server-option": "git -C {a} ls-remote --server-option x origin",
    "--get-url": "git -C {a} ls-remote --get-url origin",
    "--symref": "git -C {a} ls-remote --symref origin",
    "--sort=": "git -C {a} ls-remote --sort=version:refname origin",
    "--sort": "git -C {a} ls-remote --sort version:refname origin",
    "--exit-code": "git -C {a} ls-remote --exit-code origin",
    "--": "git -C {a} ls-remote -- origin",
    "an option after the remote": "git -C {a} ls-remote origin --heads",
    "a URL": "git -C {a} ls-remote https://github.com/o/r",
    "a path": "git -C {a} ls-remote {a}",
    "a relative path": "git -C {a} ls-remote ./neighbour",
    "no remote": "git -C {a} ls-remote",
    "a pattern with a glob": "git -C {a} ls-remote origin 'refs/heads/*'",
    "a pattern with a colon": "git -C {a} ls-remote origin main:main",
    "a pattern with a plus": "git -C {a} ls-remote origin +main",
    "a pattern with a caret": "git -C {a} ls-remote origin ^main",
    "a pattern with @{": "git -C {a} ls-remote origin 'main@{{1}}'",
    "a pattern with ..": "git -C {a} ls-remote origin a..b",
    "a word the shell rewrites": "git -C {a} ls-remote origin ma*n",
    "a $ word": "git -C {a} ls-remote origin '$X'",
}


@pytest.mark.parametrize("case", list(EXCLUDED))
def test_D59_control_an_excluded_option_or_word_asks_with_D41(repo, case):
    out = _decide(repo, EXCLUDED[case])
    assert _d41(out), (case, out and out.text)
    assert "the fetch profile" not in out.text, case


GLOBAL_KEEPS = ["git ls-remote origin", "git -C ~/workrepo ls-remote origin", "git -C home/x ls-remote origin",
                "git -C {a} -C {a} ls-remote origin", "git -c http.proxy=x -C {a} ls-remote origin",
                "git --no-pager -C {a} ls-remote origin"]


@pytest.mark.parametrize("command", GLOBAL_KEEPS)
def test_D59_control_without_one_literal_absolute_c_keeps_D41(repo, command):
    out = _decide(repo, command)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.text)
    assert FREE_ID not in [v.reason_id for v in out.verdicts], command


# --- only as the whole command ---------------------------------------------------------------------------------------

WHOLE_ONLY = ["git -C {a} ls-remote origin | head -1", "git -C {a} ls-remote origin && git -C {a} log -1",
              "git -C {a} ls-remote origin; echo done", "git -C {a} status; git -C {a} ls-remote origin",
              "cd {a} && git -C {a} ls-remote origin", "git -C {a} ls-remote origin > {a}/../refs.txt",
              "git -C {a} ls-remote origin 2>&1", "GIT_TRACE=1 git -C {a} ls-remote origin",
              "HTTPS_PROXY=http://x:1 git -C {a} ls-remote origin", "PAGER=cat git -C {a} ls-remote origin",
              "sh -c 'git -C {a} ls-remote origin'"]


@pytest.mark.parametrize("command", WHOLE_ONLY)
def test_D59_control_not_the_whole_command_keeps_the_ask(repo, command):
    out = _decide(repo, command)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.text)
    assert FREE_ID not in [v.reason_id for v in out.verdicts], command


@pytest.mark.parametrize("command", ["git -C {a} ls-remote origin", "git -C {a} ls-remote --heads origin main"])
def test_D59_control_under_codex_the_answer_of_D41(repo, command):
    out = _decide(repo, command, host="codex")
    assert _d41(out), out and out.text
    assert "the fetch profile" not in out.text and "D59" not in out.text, out.text


def test_D59_under_codex_the_hook_blocks_with_the_D41_line(tmp_path, repo):
    rc, decision, line = _hook(tmp_path, tmp_path, f"git -C {repo} ls-remote origin", host="codex")
    assert (rc, decision) == (0, "deny"), line
    assert line.startswith("Gate blocks git ls-remote because this ls-remote can reach another host or start a program "
                           "nobody checked (D41)."), line   # D116: what can go wrong, before the D number


# --- a finding of the profile asks, with the short line of D53 --------------------------------------------------------

FINDINGS = {
    "a local path as URL": ("@url", "{tmp}/origin", "the URL of the remote origin is not https://github.com/<owner>/<repo>"),
    "http.proxy": ("http.proxy", "http://127.0.0.1:3128", "http.proxy"),
    "insteadOf": ("url.https://other.example/.insteadOf", "https://github.com/", "a URL rewrite"),
    "uploadpack of the remote": ("remote.origin.uploadpack", "{tmp}/up", "remote.origin.uploadpack"),
    "vcs of the remote": ("remote.origin.vcs", "probe", "remote.origin.vcs"),
    "credential cache": ("credential.helper", "cache", "a credential helper the fetch profile does not know"),
    "core.fsmonitor": ("core.fsmonitor", "{tmp}/fsm", "fsmonitor"),
    "core.sshCommand": ("core.sshCommand", "ssh -v", "core.sshcommand"),
    "a remapped rule": ("@fetch", "+refs/heads/side:refs/remotes/origin/main", "the fetch rules of the remote origin"),
    "reference-transaction hook": ("@hook", "reference-transaction", "a hook the fetch or its maintenance may start"),
    "HTTPS_PROXY": ("@env", "HTTPS_PROXY", "a proxy"),
    "GIT_ASKPASS": ("@env", "GIT_ASKPASS", "GIT_ASKPASS"),
    "a submodule": ("@gitmodules", "", "a submodule"),
    "pager.ls-remote on a host with a terminal": ("@unbind", "pager.ls-remote", "a pager: pager.ls-remote"),
    "a remote word with no remote": ("@remote", "neighbour", "the remote neighbour has no URL"),
}


def _finding(tmp_path, repo, monkeypatch, key, value):
    remote = "origin"
    if key == "@url":
        w.git(repo, "remote", "set-url", "origin", value.format(tmp=tmp_path))
    elif key == "@fetch":
        w.git(repo, "config", "--replace-all", "remote.origin.fetch", value)
    elif key == "@hook":
        w.proxy(tmp_path, repo / ".git" / "hooks" / value, "hook")
    elif key == "@env":
        monkeypatch.setenv(value, "http://127.0.0.1:3128" if value.endswith("PROXY") else "/bin/true")
    elif key == "@gitmodules":
        (repo / ".gitmodules").write_text('[submodule "m"]\n\tpath = m\n\turl = https://github.com/o/m\n')
    elif key == "@unbind":
        monkeypatch.delenv("AI_AGENT")
        w.git(repo, "config", value, "true")
    elif key == "@remote":
        remote = value
    else:
        w.git(repo, "config", key, value.format(tmp=tmp_path))
    return remote


@pytest.mark.parametrize("case", list(FINDINGS))
def test_D59_a_finding_of_the_profile_asks_and_names_it(tmp_path, repo, monkeypatch, case):
    key, value, named = FINDINGS[case]
    remote = _finding(tmp_path, repo, monkeypatch, key, value)
    out = _decide(repo, f"git -C {{a}} ls-remote {remote}")
    assert _d41(out), (case, out and out.text)
    assert "The fetch profile of D45 found" in out.text and "so this ls-remote is not the one D59 frees" in out.text
    assert named in out.text, (case, out.text)


@pytest.mark.parametrize("language, line", [
    (None, "Gate asks at git ls-remote because this ls-remote can reach another host or start a program nobody checked "
           "(D59)."),
    ("de", "Tor fragt bei git ls-remote, weil dieses ls-remote einen anderen Host erreichen oder ein ungeprüftes "
           "Programm starten kann (D59).")])   # D116
@pytest.mark.parametrize("case", ["http.proxy", "reference-transaction hook", "a local path as URL", "HTTPS_PROXY"])
def test_D59_a_finding_asks_with_the_short_line_of_D53(tmp_path, repo, monkeypatch, case, language, line):
    key, value, _named = FINDINGS[case]
    extra = {}
    if key == "@env":
        extra[value] = "http://127.0.0.1:3128"
    else:
        _finding(tmp_path, repo, monkeypatch, key, value)
    rc, decision, shown = _hook(tmp_path, tmp_path, f"git -C {repo} ls-remote origin", language=language, **extra)
    assert (rc, decision, shown) == (0, "ask", line), (case, shown)


def test_D59_an_excluded_option_asks_with_the_D41_line_naming_ls_remote(tmp_path, repo):
    """Before D59 the line of every ls-remote said `this fetch is not the form the gate frees`."""
    rc, decision, shown = _hook(tmp_path, tmp_path, f"git -C {repo} ls-remote --symref origin")
    assert (rc, decision, shown) == \
        (0, "ask", "Gate asks at git ls-remote because this ls-remote can reach another host or start a program nobody "
                   "checked (D41)."), shown   # D116


def test_D59_the_form_reads_no_word_the_shell_may_rewrite():
    """The contract of _ls_remote_form as of _fetch_form: a word flagged as rewritten by the shell, or one holding `$`,
    is never the form. Through decide() the character classes of the remote and the patterns already refuse every such
    word (the mutant run of the delivery: taking this check back changed no answer there); this holds the check
    itself."""
    assert gate._ls_remote_form(["--heads", "origin", "main"]) == "origin"
    assert gate._ls_remote_form(["--heads", "origin", "main"], [False, False, False]) == "origin"
    assert gate._ls_remote_form(["--heads", "origin", "main"], [False, False, True]) is None
    assert gate._ls_remote_form(["--heads", "origin", "main"], [False, True, False]) is None
    assert gate._ls_remote_form(["origin", "ma$in"]) is None
