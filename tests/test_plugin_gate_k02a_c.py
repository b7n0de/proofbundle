"""Owner choice K02-A C (2026-10-08): Level 2 names a sandbox that keeps the verifier from starting.

Measured in KARTEN-02 under Codex 0.161.0 (`--sandbox workspace-write`, network off): git starts the installed
pre-push hook and the gate runs, but the verifier does not start, because uv cannot write its cache (`Read-only file
system (os error 30)`) or, with a writable empty cache, cannot resolve its package index (`failed to lookup address
information: Temporary failure in name resolution`). The push was denied with the generic "the verifier did not
initialise" text. Now Level 2 says NOT MEASURED with a text and a reason of its own (`sandbox_verifier_unavailable`):
the push belongs to a person outside the sandbox, the boundary is CI. The exit code and the outcome stay as they were
(exit 1, the remote ref unchanged).

The sign comes from what is measured, never from an environment name alone: uv's own answer must name the failed
write or the failed resolution, and a probe of the gate's own must confirm it (a write in uv's cache folder; a name
resolution, or a connection to an address-literal proxy). The two sandboxes are rebuilt with bubblewrap: a read-only
root (the cache cannot be written) and a network namespace of its own (nothing resolves). `uv` here is a stand-in
that behaves like uv at the two measured points and otherwise starts the plugin's server with this interpreter.
Red against 12068a47, where both sandboxes got the generic text.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import urllib.parse

import pytest

import proofbundle
import test_plugin_gate_n2c_push_done as base
from _plugin_env import plugin_env

gate = base.gate
GATE = base.GATE
REASON = getattr(gate, "SANDBOX_REASON", "sandbox_verifier_unavailable")

BWRAP = shutil.which("bwrap")


def _bwrap_works() -> bool:
    if BWRAP is None:
        return False
    proc = subprocess.run([BWRAP, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net",
                           "true"], capture_output=True, timeout=30, check=False)
    return proc.returncode == 0


pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
needs_bwrap = pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap cannot build a sandbox here")

#: A stand-in for uv: `cache dir` prints UV_CACHE_DIR; `run` first writes a lock into that cache, as uv does, and fails
#: with uv's words when it cannot; then, with FAKE_UV_NEEDS_INDEX=1, resolves the package index and fails with uv's
#: words when it cannot; FAKE_UV_SAYS forces one of the two answers whatever the state is ("readonly", "dns") or a
#: failure of another kind ("other"). Otherwise it starts the script it is given with this interpreter.
FAKE_UV = f'''#!{sys.executable}
import os, socket, sys
args = sys.argv[1:]
cache = os.environ.get("UV_CACHE_DIR", "/nonexistent-cache")
if args[:2] == ["cache", "dir"]:
    print(cache)
    sys.exit(0)
says = os.environ.get("FAKE_UV_SAYS", "")
if says == "other":
    print("error: No solution found when resolving script dependencies", file=sys.stderr)
    sys.exit(1)
lock = os.path.join(cache, ".lock")
try:
    os.makedirs(cache, exist_ok=True)
    open(lock, "w").close()
    wrote = says != "readonly"
except OSError:
    wrote = False
if not wrote:
    print(f"error: failed to open file `{{lock}}`: Read-only file system (os error 30)", file=sys.stderr)
    sys.exit(2)
if os.environ.get("FAKE_UV_NEEDS_INDEX") == "1" or says == "dns":
    try:
        if says == "dns":
            raise OSError("forced")
        socket.getaddrinfo("pypi.org", 443)
    except OSError:
        print("error: Request failed after 3 retries", file=sys.stderr)
        print("  Caused by: failed to lookup address information: Temporary failure in name resolution",
              file=sys.stderr)
        sys.exit(2)
script = args[args.index("--script") + 1]
os.execv(sys.executable, [sys.executable, script, *args[args.index("--script") + 2:]])
'''


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(FAKE_UV, encoding="utf-8")
    (bin_dir / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for name in ("uv", "python3"):
        (bin_dir / name).chmod(0o755)
    (tmp_path / "tmp").mkdir()
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = plugin_env(PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean["CLAUDE_PLUGIN_DATA"] = clean["PLUGIN_DATA"] = str(tmp_path / "logs")
    clean["TMPDIR"] = str(tmp_path / "tmp")
    clean["UV_CACHE_DIR"] = str(tmp_path / "uv-cache")
    for key in ("FAKE_UV_NEEDS_INDEX", "FAKE_UV_SAYS"):
        clean.pop(key, None)
    return clean


def _sandbox(tmp_path: pathlib.Path, *, cache_writable: bool, network: bool) -> list[str]:
    """A bubblewrap prefix: the root read-only, the test's own folder writable (the workspace and its /tmp, as in
    Codex's workspace-write), uv's cache read-only where asked, and no network where asked."""
    cmd = [BWRAP, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--bind", str(tmp_path), str(tmp_path)]
    if not cache_writable:
        (tmp_path / "uv-cache").mkdir(exist_ok=True)
        cmd += ["--ro-bind", str(tmp_path / "uv-cache"), str(tmp_path / "uv-cache")]
    if not network:
        cmd += ["--unshare-net"]
    return cmd + ["--"]


def _level2(prefix: list[str], env: dict, repo: pathlib.Path) -> subprocess.CompletedProcess:
    line = f"refs/heads/main {base._rev(repo, 'HEAD')} refs/heads/main {base._rev(repo, 'origin/main')}\n"
    return subprocess.run([*prefix, sys.executable, "-I", str(GATE), "pre-push", "origin", "remote.git"], input=line,
                          capture_output=True, text=True, cwd=str(repo), env=env, timeout=180, check=False)


def _says_sandbox(proc: subprocess.CompletedProcess) -> bool:
    return REASON in proc.stderr and "The push belongs to a person outside the sandbox" in proc.stderr


# --- the two measured sandboxes ---------------------------------------------------------------------------------

@needs_bwrap
def test_without_a_writable_cache_level_2_names_the_sandbox_and_still_denies(env, tmp_path):
    repo = base.Repo(tmp_path)
    repo.make("valid")
    proc = _level2(_sandbox(tmp_path, cache_writable=False, network=True), env, repo.path)
    assert proc.returncode == 1, proc.stderr
    assert _says_sandbox(proc), proc.stderr
    assert proc.stderr.startswith("NOT MEASURED: ") and "uv could not write its cache" in proc.stderr
    assert "a write the gate tried there failed too (EROFS" in proc.stderr
    assert "the boundary is the required CI check" in proc.stderr


@needs_bwrap
def test_with_a_cache_but_no_network_level_2_names_the_sandbox_and_still_denies(env, tmp_path):
    repo = base.Repo(tmp_path)
    repo.make("valid")
    env["FAKE_UV_NEEDS_INDEX"] = "1"
    proc = _level2(_sandbox(tmp_path, cache_writable=True, network=False), env, repo.path)
    assert proc.returncode == 1, proc.stderr
    assert _says_sandbox(proc), proc.stderr
    assert "uv could not resolve its package index, and the gate reached none of the places uv would go" in proc.stderr


@needs_bwrap
def test_through_git_the_sandboxed_push_keeps_the_remote_ref(env, tmp_path):
    plugin = tmp_path / "cache-plugins" / "proofbundle" / "proofbundle" / "0.3.0"
    shutil.copytree(GATE.parent.parent, plugin, ignore=shutil.ignore_patterns("__pycache__"))
    repo = base.Repo(tmp_path)
    repo.make("valid")
    install = subprocess.run([sys.executable, "-I", str(plugin / "hooks" / "proofbundle_gate.py"), "install-pre-push",
                              "--repo", str(repo.path)], capture_output=True, text=True, env=env, timeout=120)
    assert install.returncode == 0, install.stderr
    before = base._git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip()
    proc = subprocess.run([*_sandbox(tmp_path, cache_writable=False, network=True), "git", "-C", str(repo.path),
                           "push", "origin", "main"], capture_output=True, text=True, env=env, timeout=180, check=False)
    after = base._git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip()
    assert proc.returncode != 0 and after == before, proc.stderr
    assert _says_sandbox(proc), proc.stderr


# --- the controls: network and cache there, and a sign that is only a word -------------------------------------

def test_with_network_and_a_writable_cache_the_push_gets_its_own_verdict(env, tmp_path):
    repo = base.Repo(tmp_path)
    repo.make("valid")
    proc = _level2([], env, repo.path)
    assert proc.returncode == 0, proc.stderr
    assert REASON not in proc.stderr
    (tmp_path / "second").mkdir()
    missing = base.Repo(tmp_path / "second")
    assert _level2([], env, missing.path).returncode == 1          # no receipt: denied as before, no sandbox text
    assert REASON not in _level2([], env, missing.path).stderr


def test_uvs_words_alone_are_not_a_sandbox_when_the_cache_is_writable(env, tmp_path):
    repo = base.Repo(tmp_path)
    repo.make("valid")
    env["FAKE_UV_SAYS"] = "readonly"
    proc = _level2([], env, repo.path)
    assert proc.returncode == 1, proc.stderr
    assert REASON not in proc.stderr
    assert "the verifier did not initialise (exit 2: error: failed to open file" in proc.stderr


def _network_reachable() -> bool:
    """Measured by the test itself, not by the code under test: pypi.org resolves, or an address-literal proxy the
    environment names accepts a connection."""
    try:
        socket.getaddrinfo("pypi.org", 443)
        return True
    except OSError:
        pass
    for key in ("HTTPS_PROXY", "https_proxy"):
        value = os.environ.get(key)
        if value:
            parts = urllib.parse.urlsplit(value if "//" in value else "//" + value)
            try:
                socket.create_connection((parts.hostname, parts.port or 443), timeout=3).close()
                return True
            except (OSError, ValueError, TypeError):
                continue
    return False


@pytest.mark.skipif(not _network_reachable(), reason="no place uv would go is reachable from here")
def test_uvs_words_alone_are_not_a_sandbox_when_the_network_answers(env, tmp_path):
    repo = base.Repo(tmp_path)
    repo.make("valid")
    env["FAKE_UV_SAYS"] = "dns"
    proc = _level2([], env, repo.path)
    assert proc.returncode == 1, proc.stderr
    assert REASON not in proc.stderr
    assert "failed to lookup address information" in proc.stderr


def test_an_environment_name_alone_is_not_a_sandbox(env, tmp_path):
    repo = base.Repo(tmp_path)
    repo.make("valid")
    env.update(CODEX_SANDBOX="seatbelt", CODEX_SANDBOX_NETWORK_DISABLED="1")
    proc = _level2([], env, repo.path)
    assert proc.returncode == 0 and REASON not in proc.stderr, proc.stderr
    env["FAKE_UV_SAYS"] = "other"                                  # uv fails for another reason, the names still set
    proc = _level2([], env, repo.path)
    assert proc.returncode == 1 and REASON not in proc.stderr, proc.stderr
    assert "the verifier did not initialise (exit 1: error: No solution found" in proc.stderr


def test_the_sign_needs_both_uvs_answer_and_the_gates_probe(monkeypatch, tmp_path):
    deadline = gate.time.monotonic() + 30
    monkeypatch.setattr(gate, "_uv_cache_dir", lambda uv, deadline: str(tmp_path))
    monkeypatch.setattr(gate, "_write_probe", lambda folder: "EROFS, Read-only file system, in " + folder)
    assert gate._verifier_start_sign("uv", "error: some other failure", deadline) is None
    kind, sign = gate._verifier_start_sign("uv", "error: Read-only file system (os error 30)", deadline)
    assert kind == "no_writable_cache" and str(tmp_path) in sign
    monkeypatch.setattr(gate, "_write_probe", lambda folder: None)
    assert gate._verifier_start_sign("uv", "error: Read-only file system (os error 30)", deadline) is None
    monkeypatch.setattr(gate, "_reach", lambda host, port: f"resolving {host} failed")
    kind, _ = gate._verifier_start_sign("uv", "Caused by: failed to lookup address information", deadline)
    assert kind == "no_network"
    monkeypatch.setattr(gate, "_reach", lambda host, port: None if host == "pypi.org" else "failed")
    assert gate._verifier_start_sign("uv", "Caused by: failed to lookup address information", deadline) is None


def test_the_write_probe_leaves_nothing_behind_and_creates_no_folder(tmp_path):
    assert gate._write_probe(str(tmp_path / "not" / "there")) is None
    assert sorted(p.name for p in tmp_path.iterdir()) == []


def test_other_paths_keep_the_generic_text():
    error = gate.VerifierCannotStart("the verifier did not initialise (exit 2: x), which refuses the whole verifier "
                                     "run", "no_network", "a sign")
    assert isinstance(error, gate.GateError) and str(error).startswith("the verifier did not initialise")
    assert (error.kind, error.sign) == ("no_network", "a sign")
