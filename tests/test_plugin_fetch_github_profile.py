"""D45, Ergänzung 1 to Nachtrag 19, part B: `git -C <abs> fetch` from github.com is free after a fetch profile.

Owner choice of 2026-10-16, 11:5x Berlin. Until now every fetch asked (D41). Free now, under Claude Code and never
under Codex: `git -C <absolute path> fetch` with at most -q/--quiet, --prune, --no-tags, a remote name and branch names
without a colon, as the whole command or as a step of class c, when the fetch profile of its repository finds nothing.

Ground truth, measured with git 2.43.0 under strace with no network against a local stand-in for github.com
(truth_fetch_e1.py of the delivery, 67 cases and delta's chain): such a fetch from https://github.com/<owner>/<repo>
started only git's own programs and connected only to github.com; a reference-transaction hook, pre-auto-gc with gc
due, fsmonitor, remote.<name>.vcs, every credential helper and askpass on a 401, url.*.insteadOf, http.proxy, the proxy
names and a submodule each started a program or reached another host; no other documented hook, no filter, pager,
ssh setting or uploadpack of the remote started for an https fetch.

The repository is a clone under an absolute path with origin https://github.com/o/r and the one fetch rule of a clone;
nothing is fetched (the gate judges the command, it does not run it). The gh the credential helper may name is the
stand-in of tests/test_plugin_ask_load_b_gh.py. RED at 1db350a1: every free case and the texts that name a finding; the
asks are controls, green at both heads.
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
import test_plugin_gate_n2c_push_done as n2c
from _plugin_env import plugin_env

pytestmark = w.d.pytestmark
gate = n2c.gate
FREE = ("pass", "inactive", "allow")
BOUND = "claude-code_2-1-301_harness"
#: delta's environment of 09:53Z as Cowork measured it.
DELTA = {"AI_AGENT": BOUND, "GIT_OPTIONAL_LOCKS": "0", "PAGER": "less", "LESS": "-R", "GIT_EDITOR": "true",
         "CLAUDECODE": "1"}
FORMS = ["fetch -q origin main", "fetch origin", "fetch --prune origin", "fetch --no-tags origin main",
         "fetch --quiet --prune --no-tags origin main feature/x", "fetch -q --prune origin main release-2.1"]


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
    for name, value in DELTA.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def repo(tmp_path):
    clone = tmp_path / "home" / "konrad" / "2bedone"
    clone.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(clone)], check=True, timeout=60, env=plugin_env())
    for key, value in (("user.name", "t"), ("user.email", "t@example.org"), ("commit.gpgsign", "false")):
        w.git(clone, "config", key, value)
    (clone / "a.txt").write_text("one\n")
    w.git(clone, "add", "a.txt")
    w.git(clone, "commit", "-q", "-m", "one")
    w.git(clone, "remote", "add", "origin", "https://github.com/o/r")
    w.git(clone, "update-ref", "refs/remotes/origin/main", "HEAD")
    return clone


def _decide(repo, command: str, host: str = "claude"):
    return gate.decide(command.format(a=repo), str(repo), time.monotonic() + 180, host)


def _free(out) -> bool:
    return out is None or (out.decision in FREE and all(v.decision in FREE for v in out.verdicts))


def _fetch_free(out) -> bool:
    return out is not None and out.decision == "pass" and [v.reason_id for v in out.verdicts] == \
        ["free_after_fetch_profile"]


def _asked(out) -> bool:
    return out is not None and out.decision == "ask" and "remote_read_not_modeled" in [v.reason_id for v in
                                                                                        out.verdicts]


def _hook(cwd, command: str, **extra: str) -> tuple[int, str | None, str]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", w.G], input=event, capture_output=True, text=True,
                          env=plugin_env(**DELTA, PATH=os.environ["PATH"], **extra), timeout=180, check=False)
    out = json.loads(proc.stdout).get("hookSpecificOutput", {}) if proc.stdout.strip() else {}
    return proc.returncode, out.get("permissionDecision"), out.get("permissionDecisionReason") or ""


# --- free ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("form", FORMS)
def test_E1B_the_fetch_form_from_github_is_free(tmp_path, repo, form):
    out = _decide(repo, f"git -C {{a}} {form}")
    assert _fetch_free(out), (form, out and out.text)


def test_E1B_a_url_with_dot_git_is_free(tmp_path, repo):
    w.git(repo, "remote", "set-url", "origin", "https://github.com/o/r.git")
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main"))


def test_E1B_another_remote_name_is_free(tmp_path, repo):
    w.git(repo, "remote", "add", "upstream", "https://github.com/up-stream/r.e_po")
    assert _fetch_free(_decide(repo, "git -C {a} fetch upstream main"))


def test_E1B_deltas_chain_is_free_through_the_hook(tmp_path, repo):
    """The case of Cowork's measurement with a clone whose origin is on github.com; the chain's ground truth is the run
    of the same chain under strace against the stand-in (truth_fetch_e1.py: git's own programs, tail, ls and grep, and
    github.com:443 only)."""
    sha = w.git(repo, "rev-parse", "HEAD").strip()
    a = repo
    chain = (f"git -C {a} status --porcelain --branch; git -C {a} rev-parse HEAD; "
             f"git -C {a} log -1 --format=%B {sha} | tail -3; git -C {a} fetch -q origin main; "
             f"git -C {a} rev-parse origin/main; git -C {a} merge-base --is-ancestor {sha} HEAD; "
             f'echo "basis_ist_vorfahr=$?"; ls {a}/.git/hooks/ | grep -v sample')
    assert _hook(tmp_path, chain) == (0, None, "")


def test_E1B_the_pass_names_the_url_the_rule_and_D45(tmp_path, repo):
    detail = _decide(repo, "git -C {a} fetch -q origin main").verdicts[0].detail
    for named in ("git fetch origin is free", "at https://github.com/o/r", "the one fetch rule of a clone",
                  "A pager is named (PAGER in the hook's environment)", BOUND, "D45"):
        assert named in detail, (named, detail)


@pytest.mark.parametrize("hook", ["pre-push", "post-checkout", "post-merge", "pre-commit", "post-index-change",
                                  "post-rewrite", "fsmonitor-watchman", "push-to-checkout"])
def test_E1B_a_hook_neither_the_fetch_nor_its_maintenance_runs_keeps_it_free(tmp_path, repo, hook):
    """Measured: all 26 such hooks present, with gc forced and with --prune, none started (the pre-push hook of Level 2
    among them, which delta's repositories carry)."""
    w.proxy(tmp_path, repo / ".git" / "hooks" / hook, "hook")
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main"))


@pytest.mark.parametrize("helper", [["store"], ["", "store"], ["!{gh} auth git-credential"],
                                    ["", "!{gh} auth git-credential"], ["!gh auth git-credential"]])
def test_E1B_a_measured_credential_helper_keeps_it_free(tmp_path, repo, helper):
    for value in helper:
        w.git(repo, "config", "--add", "credential.https://github.com.helper",
              value.format(gh=tmp_path / "bin" / "gh"))
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main"))


@pytest.mark.parametrize("setting", [("filter.lfs.clean", "git-lfs clean -- %f"),
                                     ("filter.lfs.process", "git-lfs filter-process"), ("filter.lfs.required", "true"),
                                     ("fetch.prune", "true"), ("gc.auto", "0"), ("maintenance.auto", "false"),
                                     ("core.fsmonitor", "false"), ("fetch.recurseSubmodules", "false"),
                                     ("remote.upstream.url", "/elsewhere"), ("branch.main.remote", "origin"),
                                     ("uploadpack.allowAnySHA1InWant", "true")])
def test_E1B_a_key_the_fetch_starts_nothing_for_keeps_it_free(tmp_path, repo, setting):
    w.git(repo, "config", *setting)
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main")), setting


def test_E1B_a_submodule_with_recursion_off_keeps_it_free(tmp_path, repo):
    (repo / ".gitmodules").write_text('[submodule "m"]\n\tpath = m\n\turl = https://github.com/o/m\n')
    w.git(repo, "config", "fetch.recurseSubmodules", "false")
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main"))


def test_E1B_optional_locks_zero_of_the_bash_tool_keeps_it_free(tmp_path, repo, monkeypatch):
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "0")
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main"))


# --- the profile asks, with what it found ----------------------------------------------------------------------------

def _config_case(repo, tmp_path, entries):
    for key, value in entries:
        w.git(repo, "config", "--add", key, value.format(tmp=tmp_path))


CONFIG_ASKS = {
    "a local path": [("@url", "{tmp}/origin")],
    "http": [("@url", "http://github.com/o/r")],
    "no repository": [("@url", "https://github.com/o")],
    "a further path": [("@url", "https://github.com/o/r/x")],
    "a user": [("@url", "https://u@github.com/o/r")],
    "a port": [("@url", "https://github.com:443/o/r")],
    "another case": [("@url", "https://GitHub.com/o/r")],
    "a dot repository": [("@url", "https://github.com/o/..")],
    "a trailing slash": [("@url", "https://github.com/o/r/")],
    "another host": [("@url", "https://gitlab.com/o/r")],
    "two URLs": [("remote.origin.url", "https://github.com/o/s")],
    "a remapped rule": [("@fetch", "+refs/heads/side:refs/remotes/origin/main")],
    "a second rule": [("remote.origin.fetch", "+refs/tags/*:refs/tags/*")],
    "no rule": [("@nofetch", "")],
    "uploadpack of the remote": [("remote.origin.uploadpack", "{tmp}/up")],
    "vcs of the remote": [("remote.origin.vcs", "probe")],
    "proxy of the remote": [("remote.origin.proxy", "http://127.0.0.1:3128")],
    "pushurl of the remote": [("remote.origin.pushurl", "https://github.com/o/r")],
    "insteadOf": [("url.https://other.example/.insteadOf", "https://github.com/")],
    "pushInsteadOf": [("url.https://other.example/.pushInsteadOf", "https://github.com/")],
    "http.proxy": [("http.proxy", "http://127.0.0.1:3128")],
    "http.sslVerify": [("http.sslVerify", "false")],
    "http.extraHeader": [("http.extraHeader", "X: y")],
    "core.sshCommand": [("core.sshCommand", "ssh -v")],
    "core.askPass": [("core.askPass", "{tmp}/ask")],
    "core.fsmonitor": [("core.fsmonitor", "{tmp}/fsm")],
    "a promisor": [("remote.origin.promisor", "true")],
    "credential cache": [("credential.helper", "cache --timeout=30")],
    "credential store with a file": [("credential.helper", "store --file {tmp}/c")],
    "credential shell helper": [("credential.helper", "!{tmp}/helper")],
    "credential helper on PATH": [("credential.helper", "probe")],
    "credential gh of another file": [("credential.helper", "!/usr/local/bin/gh-other/gh auth git-credential")],
    "credential gh with more words": [("credential.helper", "!gh auth git-credential --hostname x")],
    "credential useHttpPath": [("credential.useHttpPath", "true")],
    "fetch.recurseSubmodules=true": [("fetch.recurseSubmodules", "true")],
    "submodule.recurse": [("submodule.recurse", "true")],
    "maintenance task": [("maintenance.prefetch.enabled", "true")],
    "gc.recentObjectsHook": [("gc.recentObjectsHook", "{tmp}/h")],
    "transfer.bundleURI": [("transfer.bundleURI", "true")],
    "an unknown key": [("probe.unknown", "x")],
    "core.pager without the bound host": [("core.pager", "less"), ("@unbind", "")],
}


@pytest.mark.parametrize("case", list(CONFIG_ASKS))
def test_E1B_control_a_configuration_the_profile_does_not_know_asks(tmp_path, repo, monkeypatch, case):
    for key, value in CONFIG_ASKS[case]:
        if key == "@url":
            w.git(repo, "remote", "set-url", "origin", value.format(tmp=tmp_path))
        elif key == "@fetch":
            w.git(repo, "config", "--replace-all", "remote.origin.fetch", value)
        elif key == "@nofetch":
            w.git(repo, "config", "--unset-all", "remote.origin.fetch")
        elif key == "@unbind":
            monkeypatch.delenv("AI_AGENT")
        else:
            _config_case(repo, tmp_path, [(key, value)])
    out = _decide(repo, "git -C {a} fetch -q origin main")
    assert _asked(out), (case, out and out.text)


ENV_ASKS = {"HTTPS_PROXY": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128",
            "ALL_PROXY": "http://127.0.0.1:3128", "all_proxy": "socks5://127.0.0.1:1", "HTTP_PROXY": "http://x:1",
            "http_proxy": "http://x:1", "GIT_SSH": "/bin/true", "GIT_SSH_COMMAND": "ssh -v",
            "GIT_ASKPASS": "/bin/true", "SSH_ASKPASS": "/bin/true", "GIT_SSL_NO_VERIFY": "1",
            "GIT_SSL_CAINFO": "/tmp/x.pem", "GIT_HTTP_USER_AGENT": "x", "GIT_TRACE": "1", "GIT_EXEC_PATH": "/x",
            "GIT_OPTIONAL_LOCKS": "1", "GIT_PAGER@unbound": "less"}


@pytest.mark.parametrize("name", list(ENV_ASKS))
def test_E1B_control_an_environment_the_profile_does_not_know_asks(tmp_path, repo, monkeypatch, name):
    if name.endswith("@unbound"):
        monkeypatch.delenv("AI_AGENT")
        name = name.split("@")[0]
    monkeypatch.setenv(name, ENV_ASKS.get(name, ENV_ASKS.get(f"{name}@unbound")))
    out = _decide(repo, "git -C {a} fetch -q origin main")
    assert _asked(out), (name, out and out.text)


@pytest.mark.parametrize("hook", ["reference-transaction", "pre-auto-gc", "post-fetch", "probe"])
def test_E1B_control_a_hook_the_fetch_or_its_maintenance_may_start_asks(tmp_path, repo, hook):
    w.proxy(tmp_path, repo / ".git" / "hooks" / hook, "hook")
    assert _asked(_decide(repo, "git -C {a} fetch -q origin main"))


def test_E1B_control_a_hook_through_core_hookspath_asks(tmp_path, repo):
    w.proxy(tmp_path, tmp_path / "hooks" / "reference-transaction", "hook")
    w.git(repo, "config", "core.hooksPath", str(tmp_path / "hooks"))
    assert _asked(_decide(repo, "git -C {a} fetch -q origin main"))


@pytest.mark.parametrize("kind", ["gitmodules", "gitlink", "modules dir"])
def test_E1B_control_a_submodule_asks(tmp_path, repo, kind):
    if kind == "gitmodules":
        (repo / ".gitmodules").write_text('[submodule "m"]\n\tpath = m\n\turl = https://github.com/o/m\n')
    elif kind == "gitlink":
        head = w.git(repo, "rev-parse", "HEAD").strip()
        w.git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},m")
    else:
        (repo / ".git" / "modules" / "m").mkdir(parents=True)
    assert _asked(_decide(repo, "git -C {a} fetch -q origin main"))


@pytest.mark.parametrize("version", ["gh version 2.91.0 (2026-04-01)", "gh version 2.92.0 (2026-04-28)"])
def test_E1B_control_a_gh_helper_asks_where_the_gh_profile_is_not_free(tmp_path, repo, version):
    """2.91.0 is no checked version; 2.92.0 has its telemetry on unless turned off (D43)."""
    b._fake_gh(tmp_path / "bin", version)
    w.git(repo, "config", "credential.https://github.com.helper", f"!{tmp_path / 'bin' / 'gh'} auth git-credential")
    assert _asked(_decide(repo, "git -C {a} fetch -q origin main"))


def test_E1B_a_gh_helper_under_2_92_0_with_telemetry_off_is_free(tmp_path, repo, monkeypatch):
    b._fake_gh(tmp_path / "bin", "gh version 2.92.0 (2026-04-28)")
    monkeypatch.setenv("GH_TELEMETRY", "0")
    w.git(repo, "config", "credential.https://github.com.helper", f"!{tmp_path / 'bin' / 'gh'} auth git-credential")
    assert _fetch_free(_decide(repo, "git -C {a} fetch -q origin main"))


NAMED = [("@url", "{tmp}/origin", "the URL of the remote origin is not https://github.com/<owner>/<repo>"),
         ("http.proxy", "http://127.0.0.1:3128", "http.proxy"),
         ("url.https://other.example/.insteadOf", "https://github.com/", "insteadof"),
         ("remote.origin.vcs", "probe", "remote.origin.vcs"),
         ("credential.helper", "cache", "a credential helper the fetch profile does not know: 'cache'"),
         ("core.fsmonitor", "{tmp}/fsm", "fsmonitor, which the fetch starts"),
         ("@hook", "reference-transaction", "a hook the fetch or its maintenance may start"),
         ("@env", "HTTPS_PROXY", "a proxy, which takes the fetch to another host first: HTTPS_PROXY"),
         ("@gitmodules", "", "a submodule"), ("@fetch", "+refs/heads/side:refs/remotes/origin/main",
                                              "the fetch rules of the remote origin are not the one rule")]


@pytest.mark.parametrize("key, value, named", NAMED)
def test_E1B_the_ask_names_what_the_profile_found(tmp_path, repo, monkeypatch, key, value, named):
    if key == "@url":
        w.git(repo, "remote", "set-url", "origin", value.format(tmp=tmp_path))
    elif key == "@hook":
        w.proxy(tmp_path, repo / ".git" / "hooks" / value, "hook")
    elif key == "@env":
        monkeypatch.setenv(value, "http://127.0.0.1:3128")
    elif key == "@gitmodules":
        (repo / ".gitmodules").write_text("")
    elif key == "@fetch":
        w.git(repo, "config", "--replace-all", "remote.origin.fetch", value)
    else:
        w.git(repo, "config", key, value.format(tmp=tmp_path))
    out = _decide(repo, "git -C {a} fetch -q origin main")
    assert _asked(out) and "the fetch profile found" in out.text and named in out.text, (key, out.text)


# --- the form: anything else keeps today's answer --------------------------------------------------------------------

FORM_KEEPS = ["git fetch -q origin main", "git -C {a}/../2bedone/.. fetch origin", "git -C home/x fetch origin",
              "git -C {a} -C {a} fetch origin", "git -c http.proxy=x -C {a} fetch origin", "git -C {a} fetch",
              "git -C {a} fetch --all", "git -C {a} fetch --tags origin", "git -C {a} fetch --depth=1 origin",
              "git -C {a} fetch -v origin", "git -C {a} fetch --force origin", "git -C {a} fetch --dry-run origin",
              "git -C {a} fetch --unshallow origin", "git -C {a} fetch --recurse-submodules origin",
              "git -C {a} fetch --multiple origin upstream", "git -C {a} fetch origin main:main",
              "git -C {a} fetch origin +main", "git -C {a} fetch origin ^main",
              "git -C {a} fetch origin 'refs/heads/*'",
              "git -C {a} fetch origin tag v1", "git -C {a} fetch origin refs/heads/main",
              "git -C {a} fetch https://github.com/o/r main", "git -C {a} fetch origin --prune",
              "git -C {a} fetch -- origin", "git -C {a} fetch origin ma*n", "git -C {a} fetch origin $BRANCH",
              "GIT_TRACE=1 git -C {a} fetch origin", "PAGER=cat git -C {a} fetch origin",
              "HTTPS_PROXY=http://x:1 git -C {a} fetch origin", "git -C {a} fetch origin > {a}/../out.txt",
              "git -C {a} fetch origin .lock", "git -C {a} fetch origin a..b", "git -C {a} fetch origin @{{u}}"]


@pytest.mark.parametrize("command", FORM_KEEPS)
def test_E1B_control_another_form_keeps_todays_answer(tmp_path, repo, command):
    out = _decide(repo, command)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.text)
    assert "free_after_fetch_profile" not in [v.reason_id for v in out.verdicts], command


@pytest.mark.parametrize("command", ["git -C {a} fetch -q origin main", "git -C {a} fetch origin",
                                     "git -C {a} log -1; git -C {a} fetch -q origin main"])
def test_E1B_control_under_codex_the_fetch_is_never_free(tmp_path, repo, command):
    out = _decide(repo, command, host="codex")
    assert out is not None and out.decision != "pass" and "free_after_fetch_profile" not in \
        [v.reason_id for v in out.verdicts], out and out.text
    assert "the fetch profile" not in out.text


# --- class c: the fetch as a step ------------------------------------------------------------------------------------

@pytest.mark.parametrize("command", ["git -C {a} fetch -q origin main && git -C {a} rev-parse origin/main",
                                     "git -C {a} status; git -C {a} fetch --prune origin; git -C {a} log -1",
                                     "git -C {a} fetch -q origin main | tail -1",
                                     "git -C {a} fetch -q origin main; git -C {a} merge-base --is-ancestor HEAD "
                                     "origin/main"])
def test_E1B_the_fetch_as_a_step_is_free(tmp_path, repo, command):
    assert _free(_decide(repo, command)), command


@pytest.mark.parametrize("command", [
    "git -C {a} fetch -q origin main && git -C {a} push origin main",
    "git -C {a} config remote.origin.url https://github.com/evil/r && git -C {a} fetch -q origin main",
    "echo x > {a}/.gitmodules; git -C {a} fetch -q origin main",
    "git -C {a} add sub; git -C {a} fetch -q origin main",
    "cd {a} && git -C {a} fetch -q origin main",
    "git -C {a} fetch -q origin main > {a}/../out.txt; git -C {a} log -1"])
def test_E1B_control_a_step_before_or_a_push_after_keeps_the_ask(tmp_path, repo, command):
    """A push after the fetch is a gated step that is not the first and keeps the answer of the whole command (the push
    check reads the tracking refs the fetch writes, D45); a step before it that may change what the fetch profile read
    makes the fetch ask (step_after_state_change)."""
    out = _decide(repo, command)
    assert out is not None and out.decision in ("ask", "deny"), (command, out and out.text)


@pytest.mark.parametrize("key, value", [("extensions.partialClone", "origin"), ("remote.origin.promisor", "true")])
def test_E1B_a_promisor_is_named_as_such(tmp_path, repo, key, value):
    w.git(repo, "config", key, value)
    out = _decide(repo, "git -C {a} fetch -q origin main")
    assert _asked(out) and "a lazy fetch from a promisor remote" in out.text, out.text


def test_E1B_a_fetch_the_profile_does_not_free_stays_a_gated_step(tmp_path, repo):
    """Not the first step and not free on its own: class c keeps the whole command's answer, as for every fetch before
    (D33); its decision and reason ids are the whole command's."""
    w.git(repo, "remote", "set-url", "origin", str(tmp_path / "elsewhere"))
    command = "git -C {a} log -1; git -C {a} fetch -q origin main".format(a=repo)
    env = plugin_env(**DELTA, PATH=os.environ["PATH"])
    out = gate.decide(command, str(repo), time.monotonic() + 180, "claude", env)
    whole = gate._decide_outcome_whole(command, str(repo), time.monotonic() + 180, "claude", env)
    assert (out.decision, [v.reason_id for v in out.verdicts]) == \
        (whole.decision, [v.reason_id for v in whole.verdicts]), out.text
