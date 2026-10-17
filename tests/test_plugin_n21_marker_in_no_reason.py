"""D49 as a class, Nachtrag 21 part 2 (review Runde 24, R24-2): no reason of a profile names a value it read.

Found by the reviewer of round 24 at 6459ff53: the fetch profile named the hook directory core.hooksPath resolves to,
word for word. D49 kept values out of reasons, but not the paths resolved from them: the hook directory of
core.hooksPath, the file an include, GIT_CONFIG_GLOBAL, HOME or XDG_CONFIG_HOME selects, the gh on PATH, gh's
configuration folder from GH_CONFIG_DIR, XDG_CONFIG_HOME or HOME and its extension folder from XDG_DATA_HOME or HOME,
the main clone a linked worktree's .git file names, git's own error text quoting a value or a file, and the repository
and git directory a local done order records. Owner choice of 2026-10-16: the class, with one shared marker test.

The rule (D49, sharpened): no reason, long, short or in the log, names a value from the configuration, the environment
or a file, nor a path resolved from one; it names the key, the scope and the file by its role. Words of the command and
fixed built-in default paths stay, and the class list of the delivery names them.

The one test: each case puts MARK into the value of one key, one environment name or one file a profile reads, so that
the profile finds something there, and runs every command whose profile reads it, in-process under Claude Code and
under Codex and once through the hook with its log. No text holds MARK. MARK never stands in a word of the command, in
the repository's own path or in a key's name. RED at 6459ff53 where a reason named a resolved path or git's error text;
the rest are controls, green at both.
"""
from __future__ import annotations

import json
import os
import pathlib
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
MARK = "mrk21q7x"
READ, STATE, FETCH, GH = "git -C {a} status", "git -C {a} add a.txt", "git -C {a} fetch -q origin main", "gh pr view 41"
CHECKOUT = "git -C {a} worktree add {t}/wt-target"
GIT_FORMS = [READ, STATE, FETCH, CHECKOUT]
UNKNOWN = "[probe]\n\tkey = x\n"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    f._clean.__wrapped__(monkeypatch, tmp_path)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "plugin-data"))


@pytest.fixture
def repo(tmp_path):
    clone = f.repo.__wrapped__(tmp_path)
    assert MARK not in str(clone)
    return clone


def _write(path: pathlib.Path, text: str) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _gh_helper(t, repo, mp):
    """The fetch reaches the gh profile through the gh helper (D45, D54)."""
    w.git(repo, "config", "credential.helper", "!gh auth git-credential")


# --- the cases: (what the profile reads, the setting, the commands, a word the reason holds where the profile saw it) --

def hooks_path_folder(t, repo, mp):
    w.proxy(t, t / f"{MARK}-hooks" / "probe-hook", "hook")
    w.git(repo, "config", "core.hooksPath", str(t / f"{MARK}-hooks"))


def hooks_path_file(t, repo, mp):
    _write(t / f"{MARK}-hooks-file", "x\n")
    w.git(repo, "config", "core.hooksPath", str(t / f"{MARK}-hooks-file"))


def include_path(t, repo, mp):
    w.git(repo, "config", "include.path", str(_write(t / f"{MARK}-inc" / "inc.config", UNKNOWN)))


def include_if_path(t, repo, mp):
    w.git(repo, "config", "includeIf.gitdir:/.path", str(_write(t / f"{MARK}-incif" / "inc.config", UNKNOWN)))


def include_malformed(t, repo, mp):
    w.git(repo, "config", "include.path", str(_write(t / f"{MARK}-bad" / "bad.config", "[probe\n")))


def config_global(t, repo, mp):
    mp.setenv("GIT_CONFIG_GLOBAL", str(_write(t / f"{MARK}-global.config", UNKNOWN)))


def config_global_home(t, repo, mp):
    mp.delenv("GIT_CONFIG_GLOBAL")
    home = t / f"{MARK}-home"
    _write(home / ".gitconfig", UNKNOWN)
    (home / ".config" / "gh").mkdir(parents=True)
    mp.setenv("HOME", str(home))


def config_global_xdg(t, repo, mp):
    mp.delenv("GIT_CONFIG_GLOBAL")
    _write(t / f"{MARK}-xdg" / "git" / "config", UNKNOWN)
    (t / f"{MARK}-xdg" / "gh").mkdir(parents=True)
    mp.setenv("XDG_CONFIG_HOME", str(t / f"{MARK}-xdg"))


def config_system(t, repo, mp):
    mp.setenv("GIT_CONFIG_SYSTEM", str(_write(t / f"{MARK}-system.config", UNKNOWN)))


def bad_boolean(t, repo, mp):
    _write(repo / ".git" / "config", (repo / ".git" / "config").read_text() + f"[core]\n\tbare = {MARK}\n")


def linked_worktree_hook(t, repo, mp):
    """The command names the worktree; git takes the main clone, its hooks and its config from the .git file."""
    w.proxy(t, repo / ".git" / "hooks" / "probe-hook", "hook")


def linked_worktree_key(t, repo, mp):
    _write(repo / ".git" / "config", (repo / ".git" / "config").read_text() + UNKNOWN)


def linked_worktree_modules(t, repo, mp):
    (repo / ".git" / "worktrees" / "linked" / "modules" / "m").mkdir(parents=True)


def gh_config_dir_key(t, repo, mp):
    mp.setenv("GH_CONFIG_DIR", str(t / f"{MARK}-gh"))
    _write(t / f"{MARK}-gh" / "config.yml", "probe: x\n")
    _gh_helper(t, repo, mp)


def gh_config_xdg_socket(t, repo, mp):
    mp.setenv("XDG_CONFIG_HOME", str(t / f"{MARK}-xdg"))
    _write(t / f"{MARK}-xdg" / "gh" / "config.yml", "http_unix_socket: /run/probe.sock\n")
    _gh_helper(t, repo, mp)


def gh_config_home_form(t, repo, mp):
    home = t / f"{MARK}-home"
    _write(home / ".config" / "gh" / "config.yml", "- not a block\n")
    mp.setenv("HOME", str(home))
    _gh_helper(t, repo, mp)


def gh_config_unreadable(t, repo, mp):
    mp.setenv("GH_CONFIG_DIR", str(t / f"{MARK}-gh"))
    (t / f"{MARK}-gh" / "config.yml").mkdir(parents=True)
    _gh_helper(t, repo, mp)


def gh_on_path_version(t, repo, mp):
    (t / f"{MARK}-bin").mkdir()
    b._fake_gh(t / f"{MARK}-bin", "gh version 2.91.0 (2026-04-01)")
    mp.setenv("PATH", os.pathsep.join([str(t / f"{MARK}-bin"), "/usr/local/bin", "/usr/bin", "/bin"]))
    _gh_helper(t, repo, mp)


def gh_on_path_no_start(t, repo, mp):
    _write(t / f"{MARK}-bin" / "gh", f"#!{t / MARK}-nointerpreter\n").chmod(0o755)
    mp.setenv("PATH", os.pathsep.join([str(t / f"{MARK}-bin"), "/usr/local/bin", "/usr/bin", "/bin"]))
    _gh_helper(t, repo, mp)


def gh_on_path_no_version(t, repo, mp):
    _write(t / f"{MARK}-bin" / "gh", "#!/bin/sh\nexit 3\n").chmod(0o755)
    mp.setenv("PATH", os.pathsep.join([str(t / f"{MARK}-bin"), "/usr/local/bin", "/usr/bin", "/bin"]))
    _gh_helper(t, repo, mp)


def gh_extension_xdg(t, repo, mp):
    b._fake_gh(t / "bin", "gh version 2.92.0 (2026-04-28)")
    mp.setenv("GH_TELEMETRY", "0")
    mp.setenv("XDG_DATA_HOME", str(t / f"{MARK}-data"))
    (t / f"{MARK}-data" / "gh" / "extensions" / "gh-probe").mkdir(parents=True)
    _gh_helper(t, repo, mp)


def gh_extension_home(t, repo, mp):
    b._fake_gh(t / "bin", "gh version 2.92.0 (2026-04-28)")
    mp.setenv("GH_TELEMETRY", "0")
    home = t / f"{MARK}-home"
    (home / ".config" / "gh").mkdir(parents=True)
    (home / ".local" / "share" / "gh" / "extensions" / "gh-probe").mkdir(parents=True)
    mp.setenv("HOME", str(home))
    _gh_helper(t, repo, mp)


def remote_url(t, repo, mp):
    w.git(repo, "remote", "set-url", "origin", f"https://github.com/o/{MARK}x/y")


def credential_helper(t, repo, mp):
    w.git(repo, "config", "credential.helper", f"!/usr/bin/probe {MARK}")


def unknown_key_value(t, repo, mp):
    w.git(repo, "config", "probe.secret", MARK)


def environment_value(t, repo, mp):
    mp.setenv("GIT_TRACE", str(t / f"{MARK}-trace"))


CASES = {
    "core.hooksPath names a folder with a hook": (hooks_path_folder, GIT_FORMS, "hook"),
    "core.hooksPath names a file": (hooks_path_file, GIT_FORMS, "hook"),
    "include.path names a file with an unknown key": (include_path, GIT_FORMS, "probe.key"),
    "includeIf.<condition>.path names a file with an unknown key": (include_if_path, GIT_FORMS, "probe.key"),
    "include.path names a file git cannot parse": (include_malformed, GIT_FORMS, "cannot read"),
    "GIT_CONFIG_GLOBAL names a file with an unknown key": (config_global, GIT_FORMS, "probe.key"),
    "HOME holds .gitconfig with an unknown key": (config_global_home, GIT_FORMS, "probe.key"),
    "XDG_CONFIG_HOME holds git/config with an unknown key": (config_global_xdg, GIT_FORMS, "probe.key"),
    "GIT_CONFIG_SYSTEM names a file with an unknown key": (config_system, GIT_FORMS, "probe.key"),
    "a value git rejects: core.bare": (bad_boolean, GIT_FORMS, "gate cannot read"),
    "a linked worktree: the main clone's hook": (linked_worktree_hook, [READ, STATE, FETCH], "hook"),
    "a linked worktree: the main clone's config": (linked_worktree_key, [READ, STATE, FETCH], "probe.key"),
    "a linked worktree: a modules folder in its git directory": (linked_worktree_modules, [FETCH], "submodule"),
    "GH_CONFIG_DIR holds config.yml with an unknown key": (gh_config_dir_key, [GH, FETCH], "probe"),
    "XDG_CONFIG_HOME holds gh/config.yml with a unix socket": (gh_config_xdg_socket, [GH, FETCH], "unix socket"),
    "HOME holds gh's config.yml in a form the profile does not read": (gh_config_home_form, [GH, FETCH], "block form"),
    "gh's config.yml cannot be read": (gh_config_unreadable, [GH, FETCH], "cannot be read"),
    "PATH: a gh of an unchecked version": (gh_on_path_version, [GH, FETCH], "2.91.0"),
    "PATH: a gh that cannot start": (gh_on_path_no_start, [GH, FETCH], "could not be started"),
    "PATH: a gh that names no version": (gh_on_path_no_version, [GH, FETCH], "named no gh version"),
    "XDG_DATA_HOME holds a gh extension": (gh_extension_xdg, [GH, FETCH], "extension"),
    "HOME holds a gh extension": (gh_extension_home, [GH, FETCH], "extension"),
    "control: the remote's URL": (remote_url, [FETCH], "remote.origin.url"),
    "control: a credential helper": (credential_helper, [FETCH], "credential.helper"),
    "control: an unknown key's value": (unknown_key_value, [READ, STATE, FETCH, CHECKOUT], "probe.secret"),
    "control: an environment value": (environment_value, [READ, STATE, FETCH, CHECKOUT], "GIT_TRACE"),
}
LINKED = {"a linked worktree: the main clone's hook", "a linked worktree: the main clone's config",
          "a linked worktree: a modules folder in its git directory"}


def _linked(tmp_path: pathlib.Path, repo: pathlib.Path) -> pathlib.Path:
    """The main clone moved under a path that holds MARK, and a linked worktree of it outside: the command names the
    worktree, and only its .git file names the main clone."""
    main = tmp_path / f"{MARK}-main"
    repo.rename(main)
    worktree = tmp_path / "linked"
    w.git(main, "worktree", "add", "-q", str(worktree), "-b", "side")
    w.git(worktree, "update-ref", "refs/remotes/origin/main", "HEAD")
    return worktree


def _texts(out) -> list[str]:
    if out is None:
        return []
    texts = [out.text]
    for v in out.verdicts:
        texts += [v.text(), v.detail, v.evidence or "", v.failed or "", v.next_step or ""]
    return texts


def _hook_texts(tmp_path: pathlib.Path, cwd: pathlib.Path, command: str) -> list[str]:
    """The whole hook output and every log line it left, with the case's own environment."""
    names = ("GH_CONFIG_DIR", "GH_TELEMETRY", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "CLAUDE_PLUGIN_DATA")
    extra = {n: os.environ[n] for n in names if n in os.environ}
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", w.G], input=event, capture_output=True, text=True, timeout=180,
                          check=False, env=plugin_env(**f.DELTA, PATH=os.environ["PATH"], **extra))
    logs = [p.read_text(encoding="utf-8", errors="replace") for p in (tmp_path / "plugin-data").rglob("*")
            if p.is_file()]
    return [proc.stdout, proc.stderr, *logs]


@pytest.mark.parametrize("case", list(CASES))
def test_N21_no_reason_of_a_profile_names_a_value_it_read_or_a_path_resolved_from_one(tmp_path, repo, monkeypatch,
                                                                                         case):
    setup, commands, seen = CASES[case]
    directory = _linked(tmp_path, repo) if case in LINKED else repo
    setup(tmp_path, repo if case not in LINKED else tmp_path / f"{MARK}-main", monkeypatch)
    for template in commands:
        command = template.format(a=directory, t=tmp_path)
        assert MARK not in command
        for host in ("claude", "codex"):
            out = gate.decide(command, str(directory), time.monotonic() + 180, host)
            texts = _texts(out)
            assert out is not None and out.decision not in f.FREE, (case, command, host, texts)
            assert not [t for t in texts if MARK in t], (case, command, host, [t for t in texts if MARK in t])
            if host == "claude" and template != CHECKOUT:
                assert any(seen in t for t in texts), (case, command, "the profile did not see the setting", texts)
        hooked = _hook_texts(tmp_path, directory, command)
        assert not [t for t in hooked if MARK in t], (case, command, [t for t in hooked if MARK in t])


# --- the write protection the checkout check reads (_protected_write): a file tool's own path is a word of the call ----

WRITES = ["a hard link to a file an include names", "the file a hook entry links to", "a hook entry itself"]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("case", WRITES)
def test_N21_the_write_protection_names_the_guarded_file_by_its_role(tmp_path, repo, host, case):
    """The call names only the target; the configuration file, the hook directory and the hook entry it is guarded by
    stand under paths that hold MARK and come from an include or core.hooksPath."""
    hooks = tmp_path / f"{MARK}-hooks"
    hooks.mkdir()
    w.git(repo, "config", "core.hooksPath", str(hooks))
    included = _write(tmp_path / f"{MARK}-inc" / "inc.config", "[user]\n\tname = t\n")
    w.git(repo, "config", "include.path", str(included))
    target = tmp_path / "target.txt"
    if case.startswith("a hard link"):
        os.link(included, target)
    elif case.startswith("the file a hook entry"):
        target.write_text("#!/bin/sh\n")
        (hooks / "pre-commit").symlink_to(target)
    else:
        target = hooks / "pre-commit"
    out = gate.decide_write("Write", {"file_path": str(target)}, str(repo), time.monotonic() + 180, host)
    texts = _texts(out)
    assert out is not None and out.decision in ("ask", "deny"), (case, texts)
    assert not [t for t in texts if MARK in t.replace(str(target), "<the call's own path>")], (case, host, texts)

# --- the local done order (D38): the repository, the git directory and the base it records -----------------------------

import test_plugin_done_check as d  # noqa: E402
import test_plugin_done_local_order as lo  # noqa: E402

DONE = ["unbound: the clone moved away", "bound: a check is open"]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("case", DONE)
def test_N21_no_reason_of_a_local_done_order_names_the_repository_git_directory_or_base_it_records(tmp_path, host,
                                                                                                    case):
    """The order records the clone's path, its git directory and HEAD as its base; the Stop hook reads them from the
    order file. The clone's path holds MARK, the gate directory does not (its paths are outside this class, see the
    class list of the delivery). The log line keeps the repository it checked with its HEAD (D21): the field
    repos[].path of a bound order is the root git found there, no reason, and is left out of the search here (owner
    question O21-4 of the delivery)."""
    (tmp_path / "done").mkdir()
    env, keys = d.env.__wrapped__(tmp_path / "done"), d.Keys(tmp_path)
    clone = tmp_path / f"{MARK}-repo"
    clone.mkdir()
    d._git(clone, "init", "-q", "-b", "main")
    d._write(clone / "test_ok.py", "def test_ok():\n    assert True\n")
    d._commit(clone)
    order = lo._local_order(env, clone, keys.public)
    assert MARK not in str(order)
    base = json.loads(order.read_text(encoding="utf-8"))["base"]
    d._write(clone / "later.txt", "a commit after the order, so that HEAD is not its base\n")
    d._commit(clone, "later")
    if case.startswith("unbound"):
        clone.rename(tmp_path / "moved")
    data = tmp_path / "plugin-data-done"
    answer = lo._stop({**env, "CLAUDE_PLUGIN_DATA": str(data)}, lo._session_dir(tmp_path), host)
    logs = []
    for line in (line for p in data.rglob("*") if p.is_file() for line in p.read_text(encoding="utf-8").splitlines()):
        entry = json.loads(line)
        for repository in entry.get("repos") or []:
            repository.pop("path", None)
        logs.append(json.dumps(entry))
    text = json.dumps(answer) + "\n".join(logs)
    assert answer is not None and "block" in text, (case, text)
    assert MARK not in text and base[:12] not in text, (case, host, text)
