"""D98, Nachtrag 40 (B40-1): the fetch of a local bundle into refs/remotes/beilage/ is free.

Found by delta at f9e5f18e (20261019T0819Z, card OA-f4a38d2ac0): under the switch of D85 the gate blocked, with no free
way and no card, `git -C <clone> fetch -q <local bundle> refs/heads/<branch>:refs/remotes/beilage/<name>`
(remote_read_not_modeled). Every order to delta brings its heads as a bundle.

Measured with git 2.43.0 under GIT_TRACE2_EVENT and strace -f, every hook of githooks(5) a marker, no network
(truth_b40.py of the delivery, 24 forms): the fetch of a regular bundle file (version 2 or 3) by its absolute path
started git's own programs and the hook reference-transaction only, connected nowhere and wrote the one tracking ref;
http.proxy, a credential helper, core.sshCommand, core.askPass, GIT_SSH, GIT_SSH_COMMAND, GIT_ASKPASS, SSH_ASKPASS,
HTTPS_PROXY and files named pre-push.local or pre-commit.local started nothing for it, --upload-pack was ignored. A
folder in its place started git-upload-pack through a shell, so did a url.<base>.insteadOf that rewrote the path to a
folder; core.fsmonitor set to a program started it; a symbolic link was followed.

The rule (D98): `git -C <absolute clone> fetch [-q|--quiet] [--no-tags] <absolute path> <ref>:refs/remotes/beilage/
<name>…` as the whole command is free under Claude Code where the path is a regular file (no link) outside a .ssh folder
that starts with the signature of a git bundle and the bundle check of the clone finds nothing.

RED at f9e5f18e (the head of PLUGIN_N35): the free forms and the settings that start nothing for a bundle. The catch
cases (a folder, every other transport form, a link, a file that is no bundle, a target outside refs/remotes/beilage/, a
`+`, a foreign refspec among several, --upload-pack, -c before fetch, a hook the fetch starts, fsmonitor, a URL rewrite of
the path, a submodule, an unknown key, a longer command, Codex) are green at both.
"""
from __future__ import annotations

import builtins
import os
import pathlib
import shutil
import subprocess
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: delta's environment as Cowork measured it (test_plugin_fetch_github_profile.py), the parts a bundle check reads.
DELTA = {"AI_AGENT": "claude-code_2-1-301_harness", "GIT_OPTIONAL_LOCKS": "0", "PAGER": "less", "LESS": "-R",
         "GIT_EDITOR": "true", "CLAUDECODE": "1"}
SPEC = "refs/heads/topic:refs/remotes/beilage/topic"


def _git(cwd: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True,
                          timeout=60).stdout.strip()


@pytest.fixture
def env(tmp_path, monkeypatch):
    return setup(tmp_path, monkeypatch)


def setup(tmp_path, monkeypatch) -> dict:
    """src with main (A) and topic (B), the clone of src, and in b/ the bundles of topic (v2, v3, two heads), a folder,
    a link, a file that is no bundle, and a bundle under a .ssh folder."""
    for name, value in DELTA.items():
        monkeypatch.setenv(name, value)
    src, b = tmp_path / "src", tmp_path / "b"
    subprocess.run(["git", "init", "-q", "-b", "main", str(src)], check=True, timeout=60)
    (src / "a.txt").write_text("a\n")
    _git(src, "add", "a.txt")
    _git(src, "commit", "-q", "-m", "A")
    _git(src, "checkout", "-q", "-b", "topic")
    (src / "b.txt").write_text("b\n")
    _git(src, "add", "b.txt")
    _git(src, "commit", "-q", "-m", "B")
    _git(src, "checkout", "-q", "main")
    clone = tmp_path / "home" / "klon"
    subprocess.run(["git", "clone", "-q", "--no-local", str(src), str(clone)], check=True, timeout=60,
                   capture_output=True)
    b.mkdir()
    _git(src, "bundle", "create", "-q", str(b / "topic.bundle"), "main..topic")
    _git(src, "bundle", "create", "-q", "--version=3", str(b / "topic_v3.bundle"), "main..topic")
    _git(src, "bundle", "create", "-q", str(b / "two.bundle"), "main", "topic")
    (b / "ordner.bundle").mkdir()
    os.symlink(b / "topic.bundle", b / "link.bundle")
    (b / "kein.bundle").write_text("# not a git bundle\n")
    ssh = tmp_path / "home" / ".ssh"
    ssh.mkdir(parents=True)
    shutil.copy(b / "topic.bundle", ssh / "x.bundle")
    os.symlink(ssh, b / "sshlink")
    return {"C": clone, "B": b / "topic.bundle", "T": tmp_path, "src": src}


def _cmd(form: str, e: dict) -> str:
    b = e["B"].parent
    return (form.replace("{C}", str(e["C"])).replace("{B}", str(e["B"])).replace("{B3}", str(b / "topic_v3.bundle"))
            .replace("{B2}", str(b / "two.bundle")).replace("{DIR}", str(b / "ordner.bundle"))
            .replace("{LINK}", str(b / "link.bundle")).replace("{NOB}", str(b / "kein.bundle"))
            .replace("{SRC}", str(e["src"])).replace("{SSHB}", str(e["T"] / "home" / ".ssh" / "x.bundle"))
            .replace("{SSHL}", str(b / "sshlink" / "x.bundle"))
            .replace("{T}", str(e["T"])))


def answered(e, command, host="claude"):
    deadline = time.monotonic() + 60
    out = gate.decide(command, str(e["C"]), deadline, host)
    if host == "claude" and out is not None and out.decision == "ask":
        out = gate.autonomous_outcome(out, command, str(e["C"]), deadline, host)
    if out is None:
        return None, []
    return out.decision, [v.reason_id for v in out.verdicts]


#: B40-1, free at the head under Claude Code; at f9e5f18e each asked (remote_read_not_modeled), blocked under the switch.
FREE = [
    f"git -C {{C}} fetch -q {{B}} {SPEC}", f"git -C {{C}} fetch {{B}} {SPEC}", f"git -C {{C}} fetch -q {{B3}} {SPEC}",
    "git -C {C} fetch --quiet --no-tags {B} refs/heads/topic:refs/remotes/beilage/n40/topic",
    "git -C {C} fetch -q {B} topic:refs/remotes/beilage/topic",
    "git -C {C} fetch -q {B2} refs/heads/topic:refs/remotes/beilage/topic refs/heads/main:refs/remotes/beilage/main",
]


@pytest.mark.parametrize("form", FREE)
def test_B40_1_the_fetch_of_a_local_bundle_into_beilage_is_free(env, form):
    decision, reasons = answered(env, _cmd(form, env))
    assert decision == "pass" and "free_bundle_fetch" in reasons, (form, decision, reasons)


#: Settings and names that start nothing for the fetch of a bundle (measured), each with the first free form.
INERT = {
    "http.proxy": ("config", "http.proxy", "http://127.0.0.1:9"),
    "credential.helper": ("config", "credential.helper", "store"),
    "core.sshCommand": ("config", "core.sshCommand", "/bin/false"),
    "core.askPass": ("config", "core.askPass", "/bin/false"),
    "HTTPS_PROXY": ("env", "HTTPS_PROXY", "http://127.0.0.1:9"),
    "GIT_SSH_COMMAND": ("env", "GIT_SSH_COMMAND", "/bin/false"),
    "GIT_ASKPASS": ("env", "GIT_ASKPASS", "/bin/false"),
    "SSH_ASKPASS": ("env", "SSH_ASKPASS", "/bin/false"),
    "pre-push.local": ("hook", "pre-push.local", ""),
    "pre-commit": ("hook", "pre-commit", ""),
    "remote.origin.proxy": ("config", "remote.origin.proxy", "http://127.0.0.1:9"),
}


@pytest.mark.parametrize("name", sorted(INERT))
def test_B40_1_settings_that_start_nothing_for_a_bundle_keep_it_free(env, monkeypatch, name):
    kind, key, value = INERT[name]
    if kind == "config":
        _git(env["C"], "config", key, value)
    elif kind == "env":
        monkeypatch.setenv(key, value)
    else:
        hook = env["C"] / ".git" / "hooks" / key
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o755)
    decision, reasons = answered(env, _cmd(FREE[0], env))
    assert decision == "pass" and "free_bundle_fetch" in reasons, (name, decision, reasons)


#: B40-1 catch cases by form: not free at the head, as at f9e5f18e.
CATCH = [
    f"git -C {{C}} fetch -q {{DIR}} {SPEC}", f"git -C {{C}} fetch -q {{SRC}} {SPEC}",
    f"git -C {{C}} fetch -q 'ext::sh -c touch% {{T}}/x' {SPEC}", f"git -C {{C}} fetch -q file://{{B}} {SPEC}",
    f"git -C {{C}} fetch -q ssh://example.invalid/x.git {SPEC}", f"git -C {{C}} fetch -q example.invalid:x.git {SPEC}",
    f"git -C {{C}} fetch -q https://example.invalid/x.git {SPEC}", f"git -C {{C}} fetch -q ../b/topic.bundle {SPEC}",
    f"git -C {{C}} fetch -q {{LINK}} {SPEC}", f"git -C {{C}} fetch -q {{NOB}} {SPEC}",
    f"git -C {{C}} fetch -q {{T}}/fehlt.bundle {SPEC}", f"git -C {{C}} fetch -q {{SSHB}} {SPEC}",
    f"git -C {{C}} fetch -q {{SSHL}} {SPEC}",
    "git -C {C} fetch -q {B} refs/heads/topic:refs/heads/topic",
    "git -C {C} fetch -q {B} refs/heads/topic:refs/remotes/origin/topic",
    "git -C {C} fetch -q {B} refs/heads/topic:refs/tags/t", "git -C {C} fetch -q {B} refs/heads/topic:refs/remotes/beilagex/t",
    "git -C {C} fetch -q {B} refs/heads/topic:refs/remotes/beilage", "git -C {C} fetch -q {B} refs/heads/topic:refs/remotes/beilage/",
    "git -C {C} fetch -q {B} refs/heads/topic:refs/remotes/beilage/../../heads/x",
    "git -C {C} fetch -q {B} +refs/heads/topic:refs/remotes/beilage/topic",
    f"git -C {{C}} fetch -q {{B}} {SPEC} refs/heads/main:refs/heads/main",
    "git -C {C} fetch -q {B} refs/heads/*:refs/remotes/beilage/*", "git -C {C} fetch -q {B}",
    "git -C {C} fetch -q {B} refs/heads/topic", f"git -C {{C}} fetch -q --upload-pack=/bin/true {{B}} {SPEC}",
    f"git -C {{C}} fetch -q --upload-pack /bin/true {{B}} {SPEC}", f"git -C {{C}} -c protocol.allow=always fetch -q {{B}} {SPEC}",
    f"git -c core.fsmonitor=/bin/true -C {{C}} fetch -q {{B}} {SPEC}", f"git -C {{C}} fetch -q --prune {{B}} {SPEC}",
    f"git -C {{C}} fetch -q -- {{B}} {SPEC}", f"git fetch -q {{B}} {SPEC}", f"GIT_TRACE=1 git -C {{C}} fetch -q {{B}} {SPEC}",
    f"git -C {{C}} fetch -q {{B}} {SPEC} && git -C {{C}} log -1", f"git -C {{C}} fetch -q {{B}} {SPEC} > {{T}}/out.txt",
    f"git -C {{C}} fetch -q {{B}} {SPEC}:x",
]


@pytest.mark.parametrize("form", CATCH)
def test_B40_1_catch_every_other_form_is_not_free(env, form):
    decision, reasons = answered(env, _cmd(form, env))
    assert decision != "pass" and "free_bundle_fetch" not in reasons, (form, decision, reasons)


def _hook(env, name):
    hook = env["C"] / ".git" / "hooks" / name
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(0o755)


#: B40-1 catch cases by the clone: what the bundle check finds keeps the first free form from being free.
SETUPS = {
    "reference-transaction hook": lambda e, m: _hook(e, "reference-transaction"),
    "pre-auto-gc hook": lambda e, m: _hook(e, "pre-auto-gc"),
    "Reference-Transaction hook (case)": lambda e, m: _hook(e, "Reference-Transaction"),
    "core.hooksPath with the hook": lambda e, m: (
        (e["T"] / "h").mkdir(), (e["T"] / "h" / "reference-transaction").write_text("#!/bin/sh\n"),
        (e["T"] / "h" / "reference-transaction").chmod(0o755), _git(e["C"], "config", "core.hooksPath", str(e["T"] / "h"))),
    "core.fsmonitor": lambda e, m: _git(e["C"], "config", "core.fsmonitor", "/bin/true"),
    "url.insteadOf on the path": lambda e, m: _git(e["C"], "config", f"url.{e['src']}.insteadOf", str(e["B"])),
    "url.insteadOf on its folder": lambda e, m: _git(e["C"], "config", "url.file:///x/.insteadOf", str(e["B"].parent) + "/"),
    "a remote named as the path": lambda e, m: _git(e["C"], "config", f"remote.{e['B']}.url", str(e["src"])),
    "a submodule": lambda e, m: (e["C"] / ".gitmodules").write_text('[submodule "s"]\n\tpath = s\n\turl = ../s\n'),
    "a promisor remote": lambda e, m: _git(e["C"], "config", "remote.origin.promisor", "true"),
    "an unknown key": lambda e, m: _git(e["C"], "config", "fetch.unknownkey", "1"),
    "fetch.recurseSubmodules on": lambda e, m: _git(e["C"], "config", "fetch.recurseSubmodules", "true"),
    "GIT_TRACE in the environment": lambda e, m: m.setenv("GIT_TRACE", "1"),
    "GIT_EXEC_PATH in the environment": lambda e, m: m.setenv("GIT_EXEC_PATH", str(e["T"])),
}


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_B40_1_catch_what_the_bundle_check_finds_keeps_the_ask(env, monkeypatch, name):
    SETUPS[name](env, monkeypatch)
    out = gate.decide(_cmd(FREE[0], env), str(env["C"]), time.monotonic() + 60, "claude")
    assert out is not None and out.decision == "ask" and "remote_read_not_modeled" in [v.reason_id for v in out.verdicts], \
        (name, out and [v.reason_id for v in out.verdicts])


@pytest.mark.parametrize("form", FREE[:2])
def test_B40_1_control_under_codex_the_fetch_keeps_its_ask(env, form):
    decision, reasons = answered(env, _cmd(form, env), "codex")
    assert decision in ("ask", "deny") and "free_bundle_fetch" not in reasons, (form, decision, reasons)


def test_B40_1_the_gate_reads_no_file_under_a_ssh_folder(env, monkeypatch):
    """The gate opens a bundle file to read its first line; a path with a folder named .ssh it never opens."""
    opened = []
    real_os_open, real_open = os.open, builtins.open
    monkeypatch.setattr(os, "open", lambda path, *a, **k: (opened.append(str(path)), real_os_open(path, *a, **k))[1])
    monkeypatch.setattr(builtins, "open", lambda path, *a, **k: (opened.append(str(path)), real_open(path, *a, **k))[1])
    try:
        answered(env, _cmd(f"git -C {{C}} fetch -q {{SSHB}} {SPEC}", env))
    finally:
        monkeypatch.undo()
    assert not any(".ssh" in p.split(os.sep) for p in opened), opened
