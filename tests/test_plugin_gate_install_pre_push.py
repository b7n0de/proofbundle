"""Owner choice K5-D C (2026-10-08, also the decision of owner card D24B): `install-pre-push`.

A command of its own writes Level 2, git's pre-push hook (D24), into the repository where the user calls it, and
only there: the repository's own hook folder (`.git/hooks`, or a local `core.hooksPath` inside the repository). The
hook is a fixed wrapper that finds the plugin's gate at each push, so a plugin update needs no new install, and that
denies the push when it finds none. The command sets no configuration, never acts globally, never replaces a
pre-push hook it did not write (it names that hook's path), and runs only when it is called.

Counter-probes: a plugin version change, a foreign hook, no plugin to find; a global, command-scope or outside hook
folder; an environment that moves the repository. Through git itself: a push without a receipt keeps the remote ref,
a valid receipt moves it.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import proofbundle
import test_plugin_gate_n2c_push_done as base

gate = base.gate
GATE = base.GATE
PLUGIN = GATE.parent.parent
pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("sh") is None,
                                reason="git or sh is not installed")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server and a `python3` that is this interpreter, so the hook git starts
    runs the gate with it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for name in ("uv", "python3"):
        (bin_dir / name).chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean["CLAUDE_PLUGIN_DATA"] = clean["PLUGIN_DATA"] = str(tmp_path / "logs")
    return clean


def _installed_plugin(tmp_path: pathlib.Path, version: str = "0.3.0") -> pathlib.Path:
    """A copy of the plugin as a host installs it: <cache>/<marketplace>/proofbundle/<version>/."""
    root = tmp_path / "cache" / "proofbundle" / "proofbundle" / version
    shutil.copytree(PLUGIN, root, ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _install(repo: pathlib.Path, gate_path: pathlib.Path = GATE, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(gate_path), "install-pre-push", "--repo", str(repo)],
                          capture_output=True, text=True, env=env, timeout=120, check=False)


def _plain_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    repo = tmp_path / "plain"
    repo.mkdir()
    base._git(repo, "init", "-q", "-b", "main")
    return repo


def _config_snapshot(repo: pathlib.Path) -> tuple:
    local = base._git(repo, "config", "--local", "--list", check=False).stdout
    return local, pathlib.Path(os.environ["GIT_CONFIG_GLOBAL"]).read_bytes() \
        if os.environ["GIT_CONFIG_GLOBAL"] != os.devnull else b""


# --- what the command writes, and what it leaves ---------------------------------------------------------------

def test_it_writes_the_fixed_wrapper_into_the_repositorys_own_hook_folder_and_nothing_else(tmp_path, monkeypatch):
    global_config = tmp_path / "global.gitconfig"
    global_config.write_text("[user]\n\tname = someone\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    repo = _plain_repo(tmp_path)
    before = _config_snapshot(repo)
    proc = _install(repo)
    assert proc.returncode == 0, proc.stderr
    hook = repo / ".git" / "hooks" / "pre-push"
    text = hook.read_text(encoding="utf-8")
    assert text == gate.pre_push_wrapper(str(PLUGIN.resolve()))
    assert text.splitlines()[1].startswith(gate.PRE_PUSH_MARK)
    assert os.access(hook, os.X_OK)
    assert _config_snapshot(repo) == before, "no configuration, local or global, changes"
    assert "Nothing else was changed" in proc.stdout and str(hook) in proc.stdout
    assert sorted(p.name for p in hook.parent.iterdir() if p.name.startswith(".pre-push.")) == []


def test_running_it_again_replaces_its_own_hook(tmp_path):
    repo = _plain_repo(tmp_path)
    assert _install(repo).returncode == 0
    again = _install(repo)
    assert again.returncode == 0 and "replaced the pre-push hook" in again.stdout, again.stderr


@pytest.mark.parametrize("kind", ["script", "link", "folder", "script with the mark elsewhere"])
def test_a_pre_push_hook_it_did_not_write_is_left_as_it_is_and_named(tmp_path, kind):
    repo = _plain_repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    if kind == "script":
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    elif kind == "link":
        target = tmp_path / "elsewhere"
        target.write_text(gate.pre_push_wrapper(str(PLUGIN)), encoding="utf-8")
        hook.symlink_to(target)
    elif kind == "folder":
        hook.mkdir()
    else:
        hook.write_text(f"#!/bin/sh\nexit 0\n{gate.PRE_PUSH_MARK}\n", encoding="utf-8")
    before = os.readlink(hook) if hook.is_symlink() else (None if hook.is_dir() else hook.read_bytes())
    proc = _install(repo)
    assert proc.returncode == 1, proc.stdout
    assert f"did not write exists at {hook}" in proc.stderr and "left as it is" in proc.stderr
    after = os.readlink(hook) if hook.is_symlink() else (None if hook.is_dir() else hook.read_bytes())
    assert after == before


def test_a_hook_folder_set_in_the_global_configuration_is_refused(tmp_path, monkeypatch):
    global_config = tmp_path / "global.gitconfig"
    shared = tmp_path / "shared-hooks"
    global_config.write_text(f"[core]\n\thooksPath = {shared}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    repo = _plain_repo(tmp_path)
    proc = _install(repo)
    assert proc.returncode == 1 and "set in the global configuration" in proc.stderr, proc.stderr
    assert not shared.exists() and not (repo / ".git" / "hooks" / "pre-push").exists()
    assert global_config.read_text(encoding="utf-8") == f"[core]\n\thooksPath = {shared}\n"


def test_a_hook_folder_given_in_the_environment_is_refused(tmp_path):
    repo = _plain_repo(tmp_path)
    shared = tmp_path / "env-hooks"
    env = dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath", GIT_CONFIG_VALUE_0=str(shared))
    proc = _install(repo, env=env)
    assert proc.returncode == 1 and "set in the command configuration" in proc.stderr, proc.stderr
    assert not shared.exists()


def test_a_local_hook_folder_inside_the_repository_is_used(tmp_path):
    repo = _plain_repo(tmp_path)
    base._git(repo, "config", "core.hooksPath", ".githooks")
    proc = _install(repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / ".githooks" / "pre-push").read_text(encoding="utf-8").splitlines()[1].startswith(gate.PRE_PUSH_MARK)
    assert not (repo / ".git" / "hooks" / "pre-push").exists()


def test_a_local_hook_folder_outside_the_repository_is_refused(tmp_path):
    repo = _plain_repo(tmp_path)
    shared = tmp_path / "shared-hooks"
    base._git(repo, "config", "core.hooksPath", str(shared))
    proc = _install(repo)
    assert proc.returncode == 1 and "points outside it" in proc.stderr, proc.stderr
    assert not shared.exists()


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
def test_an_environment_that_moves_the_repository_is_refused(tmp_path, name):
    repo = _plain_repo(tmp_path)
    proc = _install(repo, env=dict(os.environ, **{name: str(tmp_path / "other")}))
    assert proc.returncode == 1 and f"{name} is set" in proc.stderr, proc.stderr
    assert not (repo / ".git" / "hooks" / "pre-push").exists()


def test_a_folder_that_is_no_repository_is_refused(tmp_path):
    folder = tmp_path / "nothing-here"
    folder.mkdir()
    proc = _install(folder)
    assert proc.returncode == 1 and "is not the working tree of a git repository" in proc.stderr, proc.stderr
    assert list(folder.iterdir()) == []


def test_the_plugin_never_runs_it_by_itself():
    """Only the user's call installs: no hook configuration of either host and no other gate path names it."""
    for config in PLUGIN.rglob("*.json"):
        assert "install-pre-push" not in config.read_text(encoding="utf-8"), config
    source = GATE.read_text(encoding="utf-8")
    assert source.count("install_pre_push(") == 2, "defined once and called once, from its own command"
    assert gate.main.__code__.co_consts.count("install-pre-push") == 1


# --- the wrapper at push time ----------------------------------------------------------------------------------

def _resolve(root: pathlib.Path) -> str:
    return subprocess.run([sys.executable, "-I", "-c", gate._PRE_PUSH_RESOLVER, str(root)], capture_output=True,
                          text=True, timeout=60, check=True).stdout.strip()


def test_the_wrapper_finds_the_newest_installed_version_by_number(tmp_path):
    old = _installed_plugin(tmp_path, "0.3.0")
    newer = _installed_plugin(tmp_path, "0.10.0")
    (old.parent / "0.9.9-rc1").mkdir()          # not a version folder the wrapper reads
    assert _resolve(old) == str(newer / "hooks" / "proofbundle_gate.py")
    shutil.rmtree(newer)
    assert _resolve(old) == str(old / "hooks" / "proofbundle_gate.py")


def test_the_wrapper_reads_a_development_folder_as_it_is(tmp_path):
    assert _resolve(PLUGIN) == str(PLUGIN / "hooks" / "proofbundle_gate.py")
    assert _resolve(tmp_path) == ""


def _remote_head(tmp_path: pathlib.Path) -> str:
    return base._git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip()


@pytest.mark.parametrize("case", ["valid", "missing"])
def test_through_git_the_installed_hook_carries_the_done_check(env, tmp_path, case):
    plugin = _installed_plugin(tmp_path)
    r = base.Repo(tmp_path)
    r.make(case)
    assert _install(r.path, plugin / "hooks" / "proofbundle_gate.py", env=env).returncode == 0
    before = _remote_head(tmp_path)
    proc = base._git(r.path, "push", "origin", "main", env=env, check=False)
    if case == "valid":
        assert proc.returncode == 0 and _remote_head(tmp_path) == base._rev(r.path, "HEAD"), proc.stderr
    else:
        assert proc.returncode != 0 and _remote_head(tmp_path) == before, proc.stderr
        assert "no_receipt" in proc.stderr or "the push needs the done check" in proc.stderr, proc.stderr


def test_after_a_plugin_version_change_the_hook_runs_the_new_version(env, tmp_path):
    plugin = _installed_plugin(tmp_path, "0.3.0")
    r = base.Repo(tmp_path)
    r.make("valid")
    assert _install(r.path, plugin / "hooks" / "proofbundle_gate.py", env=env).returncode == 0
    newer = plugin.parent / "0.3.1"
    plugin.rename(newer)                          # the host replaced 0.3.0 by 0.3.1
    marker = tmp_path / "ran-0.3.1"
    gate_file = newer / "hooks" / "proofbundle_gate.py"
    gate_file.write_text(gate_file.read_text(encoding="utf-8").replace(
        "def pre_push_command(argv: list[str]) -> int:\n",
        f"def pre_push_command(argv: list[str]) -> int:\n    open({str(marker)!r}, 'w').close()\n", 1),
        encoding="utf-8")
    proc = base._git(r.path, "push", "origin", "main", env=env, check=False)
    assert marker.exists(), proc.stderr
    assert proc.returncode == 0 and _remote_head(tmp_path) == base._rev(r.path, "HEAD"), proc.stderr


def test_with_no_plugin_to_find_the_push_is_denied(env, tmp_path):
    plugin = _installed_plugin(tmp_path)
    r = base.Repo(tmp_path)
    r.make("valid")
    assert _install(r.path, plugin / "hooks" / "proofbundle_gate.py", env=env).returncode == 0
    shutil.rmtree(plugin.parent)                  # the plugin was removed
    before = _remote_head(tmp_path)
    proc = base._git(r.path, "push", "origin", "main", env=env, check=False)
    assert proc.returncode != 0 and _remote_head(tmp_path) == before, proc.stderr
    assert "no proofbundle plugin gate found" in proc.stderr and "the push is denied" in proc.stderr


def test_with_no_python3_the_push_is_denied(env, tmp_path):
    plugin = _installed_plugin(tmp_path)
    r = base.Repo(tmp_path)
    r.make("valid")
    assert _install(r.path, plugin / "hooks" / "proofbundle_gate.py", env=env).returncode == 0
    git = shutil.which("git")
    only_git = tmp_path / "only-git"
    only_git.mkdir()
    (only_git / "git").symlink_to(git)
    before = _remote_head(tmp_path)
    no_python = dict(env, PATH=f"{only_git}:/nonexistent")
    proc = subprocess.run([str(only_git / "git"), "-C", str(r.path), "push", "origin", "main"], capture_output=True,
                          text=True, env=no_python, timeout=120, check=False)
    assert proc.returncode != 0 and _remote_head(tmp_path) == before, proc.stderr
    assert "no proofbundle plugin gate found" in proc.stderr, proc.stderr  # python3 is not found, the gate stays empty
