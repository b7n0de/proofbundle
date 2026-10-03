"""Review Runde 7 (stand 36d991f3): one regression test per finding, each exactly the review's case.

These tests judge the gate's verdict. The only programs they start are marker scripts inside the test folder,
and only where a test first shows that plain git starts the marker, so the case is not vacuous. Red against
36d991f3, green after.
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

#: The program-selecting variables the gate reads from the hook's environment (as tests/test_plugin_gate_runde6b.py).
_PROGRAM_ENV = ["EDITOR", "GIT_ASKPASS", "GIT_EDITOR", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_PAGER",
                "GIT_PROXY_COMMAND", "GIT_SSH", "GIT_SSH_COMMAND", "PAGER", "SSH_ASKPASS", "VISUAL"]


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")] + _PROGRAM_ENV + ["GIT_NO_LAZY_FETCH"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """A plain repository with one commit and a bare remote `origin`, no hook and no helper."""
    repo, bare = tmp_path / name, tmp_path / f"{name}.git"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "init", "-q", "--bare", str(bare))
    _git(repo, "remote", "add", "origin", str(bare))
    return repo


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _decision(command: str, repo: pathlib.Path, host: str = "claude") -> tuple[str | None, str]:
    outcome = gate.decide(command, str(repo), _deadline(), host=host)
    if outcome is None:
        return None, ""
    return outcome.decision, outcome.text


def _marker_program(tmp_path: pathlib.Path, marker: pathlib.Path, name: str) -> pathlib.Path:
    """A script inside the test folder that leaves marker when something starts it."""
    program = tmp_path / name
    program.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n", encoding="utf-8")
    program.chmod(0o700)
    return program


# --- R7-7: lazy fetch in a partial clone, during the gate's own check ------------------------------------------

def _partial_clone(repo: pathlib.Path, tmp_path: pathlib.Path, marker: pathlib.Path) -> None:
    """repo turned into a partial clone whose promisor remote's uploadpack leaves marker (the review's setup)."""
    program = _marker_program(tmp_path, marker, "uploadpack-marker.sh")
    for key, value in (("remote.origin.url", str(tmp_path / "promisor-nowhere")), ("remote.origin.promisor", "true"),
                       ("extensions.partialClone", "origin"), ("remote.origin.uploadpack", str(program))):
        _git(repo, "config", "--local", key, value)


def _drop_loose(repo: pathlib.Path, oid: str) -> None:
    loose = repo / ".git" / "objects" / oid[:2] / oid[2:]
    assert loose.is_file(), "precondition: the object is a loose object that can be taken out"
    loose.unlink()


def test_r7_7_a_free_object_read_in_a_partial_clone_is_not_measured(tmp_path):
    """R7-7, first case: in a partial clone with a missing object, `git cat-file -p <OID>` got no answer from the
    gate and started the uploadpack the promisor remote names. The anti-vacuity half: plain git starts it."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-lazy-fetch"
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    _git(repo, "add", "b.txt")
    _git(repo, "commit", "-q", "-m", "b")
    oid = _git(repo, "rev-parse", "HEAD:b.txt")
    _partial_clone(repo, tmp_path, marker)
    _drop_loose(repo, oid)
    subprocess.run(["git", "-C", str(repo), "cat-file", "-p", oid], capture_output=True, check=False)
    assert marker.exists(), "the promisor transport is not live for a plain git; the case would be vacuous"
    marker.unlink()
    decision, text = _decision(f"git cat-file -p {oid}", repo)
    assert decision == "ask", text
    assert "promisor" in text, text
    assert not marker.exists(), "the gate's check started the promisor transport"


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_r7_7_the_mcp_diagnosis_reads_no_object_of_a_partial_clone(tmp_path, host, expected):
    """R7-7, second case: the committed declaration .proofbundle/evidence.json is missing locally; decide_mcp for
    create_pull_request started the promisor's uploadpack in its local diagnosis before it answered."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-lazy-fetch"
    (repo / ".proofbundle").mkdir()
    (repo / ".proofbundle" / "evidence.json").write_text('{"schema": "x"}\n', encoding="utf-8")
    _git(repo, "add", ".proofbundle/evidence.json")
    _git(repo, "commit", "-q", "-m", "declaration")
    oid = _git(repo, "rev-parse", "HEAD:.proofbundle/evidence.json")
    _partial_clone(repo, tmp_path, marker)
    _drop_loose(repo, oid)
    outcome = gate.decide_mcp("mcp__github__create_pull_request", str(repo), _deadline(), host=host)
    assert not marker.exists(), "the gate's diagnosis started the promisor transport"
    assert outcome is not None and outcome.decision == expected, outcome
    assert "partial clone" in outcome.text, outcome.text
    subprocess.run(["git", "-C", str(repo), "cat-file", "-t", "HEAD:.proofbundle/evidence.json"],
                   capture_output=True, check=False)
    assert marker.exists(), "the promisor transport is not live for a plain git; the case would be vacuous"


# --- R7-4: an unknown or changed context is not free ------------------------------------------------------------

def _fsmonitor_marker(tmp_path: pathlib.Path, marker: pathlib.Path) -> pathlib.Path:
    return _marker_program(tmp_path, marker, "fsmonitor-marker.sh")


def test_r7_4_a_wrapper_that_changes_the_directory_is_not_bound(tmp_path):
    """R7-4, first case: `env --chdir=<other repository> git status --short` started the other repository's
    core.fsmonitor, judged by the configuration of the event's directory. The anti-vacuity half: plain git in the
    other repository starts it."""
    repo, other, marker = _repo(tmp_path, "r"), _repo(tmp_path, "other"), tmp_path / "marker-fsmonitor"
    _git(other, "config", "core.fsmonitor", str(_fsmonitor_marker(tmp_path, marker)))
    subprocess.run(["git", "-C", str(other), "status", "--short"], capture_output=True, check=False)
    assert marker.exists(), "the other repository's fsmonitor is not live; the case would be vacuous"
    decision, text = _decision(f"env --chdir={shlex.quote(str(other))} git status --short", repo)
    assert decision == "ask", text
    assert "cannot bind git status" in text, text


def test_r7_4_a_program_path_named_git_is_not_free(tmp_path):
    """R7-4, second case: `<own path>/git status --short` ran the program at that path with no gate answer."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-path"
    (tmp_path / "bin").mkdir()
    program = _marker_program(tmp_path / "bin", marker, "git")
    decision, text = _decision(f"{shlex.quote(str(program))} status --short", repo)
    assert decision == "ask", text
    assert "cannot bind git status" in text, text


def test_r7_4_a_free_form_after_a_command_that_writes_the_configuration_is_not_free(tmp_path):
    """R7-4, third case: a command that appends core.fsmonitor to .git/config and then `; git status --short`
    started the marker, because the gate read the configuration before the whole chain. The anti-vacuity half:
    the same two steps, the append and then plain git, start it."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-fsmonitor"
    program = _fsmonitor_marker(tmp_path, marker)
    command = f"printf '[core]\\n\\tfsmonitor = {program}\\n' >> .git/config; git status --short"
    decision, text = _decision(command, repo)
    assert decision == "ask", text
    assert "cannot bind git status" in text, text
    with open(repo / ".git" / "config", "a", encoding="utf-8") as config:
        config.write(f"[core]\n\tfsmonitor = {program}\n")
    subprocess.run(["git", "-C", str(repo), "status", "--short"], capture_output=True, check=False)
    assert marker.exists(), "the appended fsmonitor is not live; the case would be vacuous"


# --- R7-2: the transport is chosen by argument, remote URL and protocol environment together ---------------------

def test_r7_2_an_inherited_protocol_allowance_does_not_free_an_ext_transport(tmp_path, monkeypatch):
    """R7-2, first case: with GIT_ALLOW_PROTOCOL=ext inherited by gate and git alike, `git ls-remote
    ext::<absolute path>/marker.sh` got no gate answer and started the marker. The anti-vacuity half: plain git
    with the same environment starts it."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-ext"
    program = _marker_program(tmp_path, marker, "ext-marker.sh")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "ext")
    decision, text = _decision(f"git ls-remote ext::{program}", repo)
    assert decision == "ask", text
    assert not marker.exists(), "the gate's check started the transport"
    subprocess.run(["git", "-C", str(repo), "ls-remote", f"ext::{program}"], capture_output=True, check=False,
                   timeout=60)
    assert marker.exists(), "the ext transport is not live for a plain git; the case would be vacuous"


@pytest.mark.parametrize("form", ["argument", "configured remote URL"])
def test_r7_2_a_scheme_url_that_selects_a_remote_helper_on_path_is_not_free(tmp_path, monkeypatch, form):
    """R7-2, second case: `markerprobe://…` as an argument or as the configured remote URL started a
    git-remote-markerprobe on the inherited PATH; _helper_url recognised only `::`. The anti-vacuity half: plain
    git starts the helper."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-helper"
    (tmp_path / "bin").mkdir()
    _marker_program(tmp_path / "bin", marker, "git-remote-markerprobe")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    if form == "argument":
        command, plain = "git ls-remote markerprobe://example/repo", ["ls-remote", "markerprobe://example/repo"]
    else:
        _git(repo, "config", "remote.origin.url", "markerprobe://example/repo")
        command, plain = "git fetch origin", ["fetch", "origin"]
    decision, text = _decision(command, repo)
    assert decision == "ask", text
    assert not marker.exists(), "the gate's check started the helper"
    subprocess.run(["git", "-C", str(repo), *plain], capture_output=True, check=False, timeout=60)
    assert marker.exists(), "the helper is not live for a plain git; the case would be vacuous"


# --- R7-3: a hook that depends on the git version --------------------------------------------------------------

def test_r7_3_a_reference_transaction_hook_makes_symbolic_ref_not_measured(tmp_path):
    """R7-3: the profile of symbolic-ref excluded reference-transaction; under git 2.51.1 `git symbolic-ref
    refs/test-symbolic refs/heads/main` started that hook with no gate answer (the reviewer's measurement). No
    anti-vacuity half here: git 2.43.0 does not start the hook for a symbolic reference (measured in Nachtrag 20),
    so the hook is never run by this test."""
    repo, marker = _repo(tmp_path), tmp_path / "marker-reference-transaction"
    hooks = repo / ".git" / "hooks"
    _marker_program(hooks, marker, "reference-transaction")
    decision, text = _decision("git symbolic-ref refs/test-symbolic refs/heads/main", repo)
    assert decision == "ask", text
    assert "reference-transaction" in text, text
    assert not marker.exists()


# --- R7-5: protected write targets -------------------------------------------------------------------------------

def _write_decision(tool: str, path: pathlib.Path, cwd: pathlib.Path, host: str = "claude") -> str | None:
    tool_input = {"file_path": str(path)}
    tool_input.update({"content": "x\n"} if tool == "Write" else {"old_string": "a", "new_string": "b"})
    outcome = gate.decide_write(tool, tool_input, str(cwd), _deadline(), host=host)
    return None if outcome is None else outcome.decision


def _outside_script(tmp_path: pathlib.Path) -> pathlib.Path:
    """A file outside the repository that a hook entry points to. It is never executed."""
    outside = tmp_path / "outside" / "script.sh"
    outside.parent.mkdir()
    outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    outside.chmod(0o700)
    return outside


def test_r7_5_an_edit_of_a_hook_path_that_links_outside_asks(tmp_path):
    """R7-5, first case: an Edit on .git/hooks/pre-push, a symlink to a file outside the repository, got no
    answer, because only the resolved path was compared with the hook directory."""
    repo = _repo(tmp_path)
    (repo / ".git" / "hooks" / "pre-push").symlink_to(_outside_script(tmp_path))
    assert _write_decision("Edit", repo / ".git" / "hooks" / "pre-push", repo) == "ask"


def test_r7_5_an_edit_of_the_file_a_hook_entry_resolves_to_asks(tmp_path):
    """R7-5, second case: the external target of a hook symlink, edited under its own path, got no answer."""
    repo = _repo(tmp_path)
    outside = _outside_script(tmp_path)
    (repo / ".git" / "hooks" / "pre-push").symlink_to(outside)
    assert _write_decision("Edit", outside, repo) == "ask"


def test_r7_5_an_edit_of_a_hard_link_to_a_hook_asks(tmp_path):
    """R7-5, third case: a hard link to a hook, edited under its own path outside the repository, got no answer."""
    repo = _repo(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o700)
    alias = tmp_path / "alias-of-the-hook"
    os.link(hook, alias)
    assert _write_decision("Edit", alias, repo) == "ask"


@pytest.mark.parametrize("state", ["empty", "missing"])
def test_r7_5_a_write_to_an_include_from_the_command_scope_asks(tmp_path, monkeypatch, state):
    """R7-5, fourth case: include.path injected through GIT_CONFIG_COUNT has the origin `command line:`, and the
    include capture read only `file:` origins, so a write to the empty or still missing included file got no
    answer."""
    repo = _repo(tmp_path)
    included = tmp_path / "injected.gitconfig"
    if state == "empty":
        included.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "include.path")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(included))
    assert _write_decision("Write", included, repo) == "ask"


# --- R7-6: the Codex write path without a proven binding ---------------------------------------------------------

def test_r7_6_a_codex_patch_without_a_proven_binding_is_denied(tmp_path):
    """R7-6: without `*** Environment ID:` apply_patch writes into the primary environment while the hook's cwd
    can be local; a synthetic patch on .git/config with a local hook cwd outside any repository got no answer.
    A missing environment line is no proof of binding, so the write is NOT MEASURED and denied."""
    cwd = tmp_path / "local-not-a-repository"
    cwd.mkdir()
    patch = "*** Begin Patch\n*** Update File: .git/config\n@@\n-a\n+b\n*** End Patch"
    outcome = gate.decide_write("apply_patch", {"command": patch}, str(cwd), _deadline(), host="codex")
    assert outcome is not None and outcome.decision == "deny", outcome
    assert outcome.text.startswith("NOT MEASURED:") and "Environment ID" in outcome.text, outcome.text


# --- R7-8: the eval trace reader and events of no known type ----------------------------------------------------

def _evals_reader():
    """The trace reader of tests/test_plugin_evals.py, loaded by path, so this test judges the reader of the tree
    it runs in."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_r7_8_plugin_evals", ROOT / "tests" / "test_plugin_evals.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("kind, expected", [(None, "not-measured"), ("", "not-measured"),
                                            ("assistant_v2", "not-measured"), ("assistant", "order-violation")])
def test_r7_8_an_inspect_event_without_a_known_type_makes_the_trace_not_measured(tmp_path, kind, expected):
    """R7-8: an inspect event with only its top-level `type` removed, followed by a valid verify event, read as
    'ok'; an empty or unknown type did the same. With type "assistant" the same trace is 'order-violation' (the
    control)."""
    reader = _evals_reader()
    inspect = {"type": kind, "message": {"content": [{"type": "tool_use", "name": reader.I, "input": {}}]}}
    if kind is None:
        del inspect["type"]
    verify = {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": reader.V, "input": {}}]}}
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(e) for e in (inspect, verify)), encoding="utf-8")
    assert reader.run_order_verdict(trace) == expected
