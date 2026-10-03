"""The pre-tool gate of the proofbundle plugin (plugins/proofbundle/hooks).

The gate runs before every shell call. For git push, gh pr create and gh release create it verifies
the evidence the repository declares at HEAD, through the plugin's MCP server, and answers deny, ask or
no permission decision. These tests run the gate as the host runs it, a separate process fed one event on stdin, and
replace only `uv` by a shim that starts the same server with this interpreter and this checkout.

Properties checked:
- a gated call is found in the forms a shell accepts (chains, nesting, wrappers, directory changes),
  and a call the gate does not know is left alone;
- an MCP tool that opens a pull request, a merge request or a release, pushes files, writes a file or
  merges a pull request is gated by name, through a second matcher, and an MCP tool the gate does not
  know gets no answer;
- a gated MCP tool's answer says what the gate could not see: the branch it publishes, the pull request
  it merges, or the bytes it writes, which come from its own arguments;
- every declared item names the proofbundle-tree-sha256/v1 digest of the tree at HEAD, both in the
  declaration and inside the signed evidence; a missing, stale or unsigned subject is denied;
- the gate never answers allow: a pass carries no permission decision;
- a repository the gate measured to declare nothing, neither at HEAD nor in the working tree, gets no
  permission decision, and the answer says NOT MEASURED and that the gate is not active there (D5, C);
  it is never reported as verified;
- every other case where nothing was verified (a declaration only in the working tree, an empty list,
  no repository or no commit, a repository the gate cannot resolve or cannot measure) is answered ask
  and NOT MEASURED;
- deleting the declaration in a commit switches the gate off, and the deletion stays in the diff of
  the pushed range (the price of D5, C);
- tampered, missing, unpinned or unverifiable evidence, a malformed declaration, a verifier that cannot
  start and unreadable hook input are answered deny;
- the gate reads HEAD, not the working tree;
- the hook entry blocks the call when the gate itself cannot run, and its timeout exceeds the gate's
  own deadline, so a host that lets a timed-out hook pass never gets the chance;
- every deny and every ask names the evidence it concerns, what failed and the next step, and carries the
  rule never to weaken the declaration, a policy or a key to get past the gate (D19);
- a push is resolved to its targets and the commits it newly sends to each (D3, D20): a change of the
  evidence rules at any sent commit against the target's tracked state is asked, a change of an evidence
  file or of the per-release subject is not, an intermediate commit that removes the declaration or whose
  evidence does not verify is caught even behind a valid tip, and a push the gate cannot resolve (no
  tracking ref, --all, a URL remote, an untracked branch) is NOT MEASURED, never inactive (N1, N2, N3).
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import proofbundle
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
HOOKS = PLUGIN / "hooks" / "hooks.json"

# Import the gate without leaving a __pycache__ in the plugin folder, which a host copies on install.
_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _b64(key) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def _git(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


def _commit(repo: pathlib.Path, message: str = "c") -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)


def _write(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _pinned_policy(key) -> dict:
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "gate-test",
            "allowed_issuers": [{"public_key_b64": _b64(key)}], "signature": {"require_expected_signer": True}}


def _declare(repo: pathlib.Path, *items: dict) -> None:
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": list(items)})


def _subject(digest: str) -> dict:
    return {"algorithm": gate.TREE_ALGORITHM, "digest": digest}


def _statement(digest: str) -> bytes:
    """The payload a bundle signs to name its tree subject."""
    return json.dumps({"subject": _subject(digest)}).encode()


def _head_digest(repo: pathlib.Path) -> str:
    return gate.tree_digest(str(repo), "HEAD")


def _tamper_bundle(path: pathlib.Path) -> None:
    bundle = json.loads(path.read_text())
    raw = bytearray(base64.b64decode(bundle["payload_b64"]))
    raw[0] ^= 1
    bundle["payload_b64"] = base64.b64encode(bytes(raw)).decode()
    path.write_text(json.dumps(bundle))


BUNDLE = ".proofbundle/build.bundle.json"
POLICY = ".proofbundle/policy.json"


def _publish(repo: pathlib.Path) -> None:
    """Push HEAD to the repository's local bare remote, so the remote-tracking ref records it as the
    reviewed state the next push is measured against (DECISIONS.md, D20)."""
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")


def _plain(tmp_path: pathlib.Path, name: str = "plain", *, remote: bool = False) -> pathlib.Path:
    """A repository with one commit that never declared anything. With remote=True it has a bare remote and
    a remote-tracking ref for main, so a bare push resolves to a target this repository already tracks."""
    path = tmp_path / name
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "README.md", "never declared\n")
    _commit(path)
    if remote:
        _git(tmp_path, "init", "-q", "--bare", str(tmp_path / f"{name}.git"))
        _git(path, "remote", "add", "origin", str(tmp_path / f"{name}.git"))
        _git(path, "push", "-q", "origin", "HEAD:refs/heads/main")
    return path


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository whose HEAD declares one bundle over its own tree, signed by the key its policy pins.

    The code is committed first, its tree digest computed, and the evidence committed on top under
    .proofbundle/, which the digest leaves out, so the second commit has the digest the evidence names.
    That state is then pushed to a local bare remote, as the reviewed state of the evidence rules.
    """
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "README.md", "release\n")
    _write(path / "src" / "app.py", "print('hi')\n")
    _commit(path)
    digest = _head_digest(path)
    signer = generate_signer()
    _write(path / BUNDLE, emit_bundle(_statement(digest), signer))
    _write(path / POLICY, _pinned_policy(signer))
    _declare(path, {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": _subject(digest)})
    _commit(path)
    assert _head_digest(path) == digest
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "remote.git"))
    _git(path, "remote", "add", "origin", str(tmp_path / "remote.git"))
    _publish(path)
    return path


@pytest.fixture
def shim(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    # The gate calls `uv run --quiet --script <server>`; the shim drops the three options.
    uv.write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    uv.chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    env = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    return env


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    """Isolate git configuration for the whole test, so the gate reads the clean configuration the owner
    measured in throwaway repositories (Runde 5). A CI/agent proxy may inject a global
    `url.https://github.com/.insteadOf` through GIT_CONFIG_COUNT/KEY_*/VALUE_* or a global config file, and
    Ebene 1 now reports NOT MEASURED whenever ANY insteadOf/pushInsteadOf rule is configured (Punkt 9).
    Without this isolation every resolve-path test — in-process gate calls and the gate subprocess alike,
    which both read the host configuration — would read NOT MEASURED from an unrelated environment rule.
    The explicit R4-7 tests set a LOCAL rewrite in the repository and still see it."""
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def run_gate(env: dict, cwd: pathlib.Path | str, command: str, *, raw: str | None = None) -> dict | None:
    event = raw if raw is not None else json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd), "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, str(GATE)], input=event, capture_output=True, text=True,
                          env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


INACTIVE = "The gate is not active in this repository, because nothing is declared."
WEAKEN_RULE = ("Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; "
               "obtain the missing evidence instead or ask the user.")


def decision(answer: dict | None) -> str:
    """deny, ask, pass (verified, no decision) or inactive (nothing declared, no decision)."""
    assert answer is not None, "a gated call must be answered"
    specific = answer["hookSpecificOutput"]
    assert specific["hookEventName"] == "PreToolUse"
    assert answer["systemMessage"] == specific["additionalContext"]
    got = specific.get("permissionDecision", "pass")
    assert got in ("deny", "ask", "pass"), "the gate must never answer allow"
    if got != "pass":
        assert specific["permissionDecisionReason"] == answer["systemMessage"]
        for part in ("Evidence: ", ". Failed: ", ". Next step: ", WEAKEN_RULE, " Details: "):
            assert part in answer["systemMessage"], (part, answer["systemMessage"])
        return got
    assert "permissionDecisionReason" not in specific
    message = answer["systemMessage"]
    if "NOT MEASURED" in message:
        # No decision on NOT MEASURED only where the gate measured that nothing is declared.
        assert message.count("NOT MEASURED:") == message.count(INACTIVE), message
        return "inactive"
    return "pass"


def reason(answer: dict) -> str:
    return answer["systemMessage"]


# --- which calls are gated ---------------------------------------------------------------------------

@pytest.mark.parametrize("command, expected", [
    # Nachtrag 15, Ebene 1: the gate resolves ONLY one strict simple command headed by a bare git/gh. These
    # are the counter-cases the reviewer named (Punkt 6); each must still resolve.
    ("git push", [("git push", ".", [])]),
    ("git push origin main", [("git push", ".", ["origin", "main"])]),
    ("git push origin HEAD:main", [("git push", ".", ["origin", "HEAD:main"])]),
    ("git push origin main --tags", [("git push", ".", ["origin", "main", "--tags"])]),
    ("GIT_TERMINAL_PROMPT=0 git push", [("git push", ".", [])]),           # a neutral prefix still resolves
    ("git push origin main 2>&1", [("git push", ".", ["origin", "main"])]),  # a trailing redirection is dropped
    ("git push origin main >/dev/null", [("git push", ".", ["origin", "main"])]),
    ("git -C ../other push", [("git push", "./../other", [])]),  # one literal -C, joined not normalised (R4-2)
    ("git-push origin", [("git push", ".", ["origin"])]),
    ("gh pr create --fill", [("gh pr create", ".", None)]),
    ("gh pr new", [("gh pr new", ".", None)]),
    ("gh -R owner/repo pr create", [("gh pr create", ".", None)]),
    ("gh release create v1.0.0", [("gh release create", ".", None)]),
    ("gh release new v1", [("gh release new", ".", None)]),
    # Everything outside that one strict form is NOT MEASURED: a git global option the strict form does not
    # model, a path-form git, a wrapper, a chain, a pipeline, a nesting, an expansion, a cd.
    ("git -c push.default=simple push", [("git push", gate.UNKNOWN, None)]),
    ("git -c http.proxy=http://p push origin main", [("git push", gate.UNKNOWN, None)]),
    ("git --no-pager push", [("git push", gate.UNKNOWN, None)]),
    ("git --git-dir=x push", [("git push", gate.UNKNOWN, None)]),
    ("/usr/bin/git push", [("git push", gate.UNKNOWN, None)]),  # a path git is NOT MEASURED, not the host's
    ("FOO=1 sudo command git push", [("git push", gate.UNKNOWN, None)]),  # sudo, command, a PATH-class prefix
    ("make && git push", [("git push", gate.UNKNOWN, None)]),
    ("cd a && cd b && git push", [("git push", gate.UNKNOWN, None)]),   # Nachtrag 15: a cd chain is NOT MEASURED
    ("cd sub && git push", [("git push", gate.UNKNOWN, None)]),         # Punkt 6: cd sub is now NOT MEASURED
    ("cd $HOME && git push", [("git push", gate.UNKNOWN, None)]),
    ("git status\ngit push", [("git status", gate.UNKNOWN, [gate._NOT_FREE]), ("git push", gate.UNKNOWN, None)]),
    ("popd; git push", [("git push", gate.UNKNOWN, None)]),
    ("x=$(git push)", [("git push", gate.UNKNOWN, None)]),
    ("`git push`", [("git push", gate.UNKNOWN, None)]),
    ("bash -c 'git push'", [("git push", gate.UNKNOWN, None)]),
    ("sh -c 'cd sub; git push'", [("git push", gate.UNKNOWN, None)]),
    # Punkt 5: a form that would turn off the gate's check of the real push is denied, not resolved.
    ("git push --no-verify", [("git push", ".", [gate._HOOKS_DISABLE])]),
    ("git -c core.hooksPath=/x push", [("git push", ".", [gate._HOOKS_DISABLE])]),
    ("git config core.hooksPath /x", [("git config core.hooksPath", ".", [gate._HOOKS_DISABLE])]),
    # An unparsable command (an unbalanced quote) still names its gated call through the fallback.
    ("git commit -m 'no closing quote; git push", [("unparsed command", gate.UNKNOWN, None)]),
    # Review Runde 10, R10-1: every git form is gated, so the fallback names an unparsable git commit too (until
    # then it was left alone below).
    ("git commit -m 'no closing quote", [("unparsed command", gate.UNKNOWN, None)]),
    # Runde 9 (owner choice B): a repository form is never free; a per-command -c changes nothing about that.
    ("git -c a=b status push", [("git status", gate.UNKNOWN, [gate._NOT_FREE])]),
])
def test_a_gated_call_is_found_in_every_shell_form(command, expected):
    assert gate.gated_calls(command) == expected


@pytest.mark.parametrize("command, label", [
    ("git status", "git status"), ("git stash push", "git stash"), ("git log --grep push", "git log"),
    ("git config push.default simple", "git config"),
])
def test_a_git_form_that_acts_on_a_repository_is_never_free(command, label):
    """Review Runde 9, owner choice B: these four forms were left alone as local subcommands; every git form that
    acts on a repository is NOT MEASURED now, whatever its words."""
    assert gate.gated_calls(command) == [(label, gate.UNKNOWN, [gate._NOT_FREE])]


@pytest.mark.parametrize("command", [
    "git --version",
    "gh pr view 3", "gh pr list", "gh release list", "npm publish", "ls -la",
    "echo 'git push'",   # Nachtrag 15: echo does not execute its argument, so it is not a gated call
])
def test_a_call_the_gate_does_not_know_is_left_alone(command):
    assert gate.gated_calls(command) == []


# --- the declaration ---------------------------------------------------------------------------------

KEY = base64.b64encode(bytes(range(32))).decode()
SUBJ = {"algorithm": "proofbundle-tree-sha256/v1", "digest": "ab" * 32}
GOOD_BUNDLE = {"kind": "bundle", "path": ".proofbundle/b.json", "policy": ".proofbundle/p.json", "subject": SUBJ}
GOOD_DECISION = {"kind": "decision", "path": ".proofbundle/d.json", "public_key": KEY, "subject": SUBJ}


def _declaration(evidence, **extra) -> bytes:
    return json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": evidence, **extra}).encode()


def test_a_well_formed_declaration_is_read_exactly():
    items = gate.parse_declaration(_declaration([GOOD_BUNDLE, GOOD_DECISION]))
    assert items == [GOOD_BUNDLE, GOOD_DECISION]
    assert gate.parse_declaration(_declaration([])) == []
    assert gate.DECLARATION_SCHEMA == "proofbundle-plugin/evidence/v0.2"


@pytest.mark.parametrize("raw", [
    b"not json", b"[]", b'{"schema": "x", "evidence": []}',
    _declaration([], extra=1),
    b'{"schema": "proofbundle-plugin/evidence/v0.2", "schema": "proofbundle-plugin/evidence/v0.2", "evidence": []}',
    b'{"schema": "proofbundle-plugin/evidence/v0.1", "evidence": []}',
    _declaration({}), _declaration([GOOD_BUNDLE] * (gate.MAX_ITEMS + 1)),
    _declaration([dict(GOOD_BUNDLE, note="x")]), _declaration([dict(GOOD_BUNDLE, kind="statement")]),
    _declaration([dict(GOOD_BUNDLE, path="/etc/passwd")]), _declaration([dict(GOOD_BUNDLE, path="../x.json")]),
    _declaration([dict(GOOD_BUNDLE, path="./.proofbundle/b.json")]),
    _declaration([dict(GOOD_BUNDLE, path=".proofbundle//b.json")]),
    _declaration([dict(GOOD_BUNDLE, path=".proofbundle\\b.json")]), _declaration([dict(GOOD_BUNDLE, path="")]),
    _declaration([dict(GOOD_BUNDLE, path=5)]),
    _declaration([{"kind": "bundle", "path": ".proofbundle/b.json", "subject": SUBJ}]),
    _declaration([dict(GOOD_BUNDLE, public_key=KEY)]),
    _declaration([{"kind": "decision", "path": ".proofbundle/d.json", "subject": SUBJ}]),
    _declaration([dict(GOOD_DECISION, public_key=base64.b64encode(b"short").decode())]),
    _declaration([dict(GOOD_DECISION, public_key="not base64!")]),
    _declaration([dict(GOOD_DECISION, policy="../p")]),
    # the evidence and its policy live under .proofbundle/, which the tree digest leaves out
    _declaration([dict(GOOD_BUNDLE, path="evidence/b.json")]),
    _declaration([dict(GOOD_BUNDLE, policy="policy.json")]),
    _declaration([dict(GOOD_BUNDLE, path=".proofbundle")]),
    # every item names its tree subject, exactly
    _declaration([{k: v for k, v in GOOD_BUNDLE.items() if k != "subject"}]),
    _declaration([dict(GOOD_BUNDLE, subject=None)]),
    _declaration([dict(GOOD_BUNDLE, subject="ab" * 32)]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, algorithm="sha256"))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, algorithm="git-tree"))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, digest="AB" * 32))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, digest="ab" * 20))]),
    _declaration([dict(GOOD_BUNDLE, subject=dict(SUBJ, note="x"))]),
    # an outcome receipt has no field that can carry a tree subject
    _declaration([dict(GOOD_DECISION, kind="outcome")]),
])
def test_a_malformed_declaration_is_refused(raw):
    with pytest.raises(gate.GateError):
        gate.parse_declaration(raw)


# --- the answers -------------------------------------------------------------------------------------

def test_a_call_the_gate_does_not_know_gets_no_answer(shim, repo):
    assert run_gate(shim, repo, "ls -la && echo done") is None
    assert run_gate(shim, repo, "git --version") is None
    assert decision(run_gate(shim, repo, "git status && ls")) == "ask"   # review Runde 9: no free git form


def test_declared_evidence_that_verifies_gets_no_permission_decision(shim, repo):
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "pass"
    assert "1 of 1 declared items verified" in reason(answer)
    assert "not that the recorded values are true" in reason(answer)


def _decision(shim: dict, signer, *snapshot: dict) -> dict:
    template = json.loads(subprocess.run([sys.executable, "-m", "proofbundle.cli", "decision", "init"],
                                         capture_output=True, text=True, check=True, env=shim).stdout)
    template["inputSnapshot"] = list(template["inputSnapshot"]) + list(snapshot)
    return emit_decision_receipt(template, signer)


def _tree_input(digest: str) -> dict:
    return {"name": "tree", "uri": gate.TREE_SUBJECT_URI, "digest": {"sha256": digest}}


def test_a_decision_receipt_under_its_pinned_key_passes_and_under_another_key_is_denied(shim, repo, tmp_path):
    signer = generate_signer()
    digest = _head_digest(repo)
    _write(repo / ".proofbundle" / "release.decision.json", _decision(shim, signer, _tree_input(digest)))
    item = {"kind": "decision", "path": ".proofbundle/release.decision.json", "public_key": _b64(signer),
            "subject": _subject(digest)}
    _declare(repo, item)
    _commit(repo)
    assert "evidence rules" in reason(run_gate(shim, repo, "gh release create v1"))
    _publish(repo)
    assert decision(run_gate(shim, repo, "gh release create v1")) == "pass"
    _declare(repo, dict(item, public_key=_b64(generate_signer())))
    _commit(repo)
    answer = run_gate(shim, repo, "gh release create v1")
    assert decision(answer) == "deny"
    assert "verification failed" in reason(answer)


def test_a_decision_receipt_that_does_not_name_the_tree_in_its_signed_inputs_is_denied(shim, repo):
    signer = generate_signer()
    digest = _head_digest(repo)
    item = {"kind": "decision", "path": ".proofbundle/release.decision.json", "public_key": _b64(signer),
            "subject": _subject(digest)}
    _write(repo / ".proofbundle" / "release.decision.json", _decision(shim, signer))
    _declare(repo, item)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "names no tree subject" in reason(answer)
    _write(repo / ".proofbundle" / "release.decision.json", _decision(shim, signer, _tree_input("cd" * 32)))
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "signed evidence names" in reason(answer)


# --- the tree subject --------------------------------------------------------------------------------

def test_evidence_signed_for_an_older_tree_is_denied(shim, repo):
    _write(repo / "src" / "app.py", "print('changed after signing')\n")
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "does not match the tree at HEAD" in reason(answer)
    assert _head_digest(repo) in reason(answer)


def test_a_declared_subject_the_signature_does_not_cover_is_denied(shim, repo):
    """Updating the declaration to the new digest does not help: the signed payload still names the old one."""
    _write(repo / "src" / "app.py", "print('changed after signing')\n")
    _commit(repo)
    declaration = json.loads((repo / gate.DECLARATION).read_text())
    declaration["evidence"][0]["subject"] = _subject(_head_digest(repo))
    _write(repo / gate.DECLARATION, declaration)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "signed evidence names" in reason(answer)


@pytest.mark.parametrize("payload", [b"release bytes", b"{}", b'{"subject": "x"}',
                                     b'{"subject": {"algorithm": "proofbundle-tree-sha256/v1"}}'])
def test_a_bundle_whose_payload_is_not_a_subject_statement_is_denied(shim, repo, payload):
    signer = generate_signer()
    _write(repo / BUNDLE, emit_bundle(payload, signer))
    _write(repo / POLICY, _pinned_policy(signer))
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "names no tree subject" in reason(answer)


def test_a_change_inside_the_evidence_folder_keeps_the_pass(shim, repo):
    _write(repo / ".proofbundle" / "notes.md", "an added note\n")
    _commit(repo)
    assert decision(run_gate(shim, repo, "git push")) == "pass"


def test_the_pass_names_the_tree_it_verified(shim, repo):
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "pass"
    assert f"{gate.TREE_ALGORITHM} {_head_digest(repo)}" in reason(answer)


def test_a_tampered_bundle_at_head_is_denied(shim, repo):
    _tamper_bundle(repo / BUNDLE)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "exit 1" in reason(answer)


def test_the_gate_reads_head_not_the_working_tree(shim, repo):
    _tamper_bundle(repo / BUNDLE)
    _write(repo / "src" / "app.py", "print('uncommitted')\n")
    assert decision(run_gate(shim, repo, "git push")) == "pass"
    (repo / gate.DECLARATION).unlink()
    assert decision(run_gate(shim, repo, "git push")) == "pass"


def test_a_declared_bundle_missing_at_head_is_denied(shim, repo):
    _git(repo, "rm", "-q", BUNDLE)
    _commit(repo)
    answer = run_gate(shim, repo, "gh pr create --fill")
    assert decision(answer) == "deny"
    assert "missing at HEAD" in reason(answer)


def test_a_bundle_signed_by_a_key_the_policy_does_not_pin_is_denied(shim, repo):
    _write(repo / POLICY, _pinned_policy(generate_signer()))
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "exit 3" in reason(answer) or "exit 1" in reason(answer)


@pytest.mark.parametrize("policy", [
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p"},
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [],
     "signature": {"require_expected_signer": True}},
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": KEY}]},
    {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", "allowed_issuers": [{"public_key_b64": KEY}],
     "signature": {"require_expected_signer": "true"}},
    "not json",
])
def test_a_bundle_policy_that_pins_no_signer_is_denied(shim, repo, policy):
    _write(repo / POLICY, policy)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny"
    assert "pin a signer" in reason(answer) or "is not JSON" in reason(answer)


def test_a_malformed_declaration_is_denied(shim, repo):
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [{"kind": "bundle"}]})
    _commit(repo)
    assert decision(run_gate(shim, repo, "git push")) == "deny"


def test_a_repository_that_declares_nothing_but_whose_push_resolves_is_inactive(shim, tmp_path):
    """D5 still holds where the push resolves: a repository that declares nothing, pushing a tracked
    branch whose base also declares nothing, is inactive (no permission decision)."""
    repo = _plain(tmp_path, remote=True)
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "inactive"
    assert reason(answer).startswith("NOT MEASURED:")
    assert "not active in this repository" in reason(answer)


@pytest.mark.parametrize("command", ["git push", "git push --all", "git push https://example/x main",
                                      "git push origin HEAD:release"])
def test_an_unresolved_push_is_not_measured_even_when_nothing_is_declared(shim, tmp_path, command):
    """N1, N2: with no tracking ref for the target, with --all, with a URL remote, or with a destination
    this repository does not track, the gate cannot see everything the push sends. It does not switch off
    because HEAD declares nothing; it asks (deny under Codex). There is no default-branch fallback."""
    repo = _plain(tmp_path, remote=(command != "git push"))  # a remote exists, but the target is untracked
    answer = run_gate(shim, repo, command)
    assert decision(answer) == "ask"
    assert "cannot resolve what this push sends" in reason(answer)


def test_a_declaration_only_in_the_working_tree_is_not_measured_and_asks(shim, tmp_path):
    """The gate reads the pushed commit, not the working tree: an uncommitted declaration over a base that
    also declares nothing is NOT MEASURED, and the ask says it is not committed (D5)."""
    repo = _plain(tmp_path, remote=True)
    _declare(repo, GOOD_BUNDLE)  # written to the working tree only, never committed
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")
    assert "not committed" in reason(answer)
    _git(repo, "add", "-A")
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "ask", "staged is not committed; the gate reads the commit"


@pytest.mark.parametrize("plant", ["file", "dangling-link", "folder"])
def test_anything_at_the_declaration_path_of_the_working_tree_keeps_the_ask(shim, tmp_path, plant):
    """Only "no such file" measures absence; a file where the folder should be, a dangling link or a
    folder at the declaration's path is something, and the gate does not switch itself off for it."""
    repo = _plain(tmp_path, remote=True)
    target = repo / gate.DECLARATION
    if plant == "file":
        (repo / ".proofbundle").write_text("not a folder\n", encoding="utf-8")
    elif plant == "dangling-link":
        target.parent.mkdir()
        target.symlink_to(repo / "nowhere.json")
    else:
        target.mkdir(parents=True)
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")


def test_a_head_the_gate_cannot_list_keeps_the_ask(tmp_path, monkeypatch):
    """If git does not confirm with exit 0 that HEAD has nothing at the declaration's path, the gate
    has not measured absence and keeps its NOT MEASURED ask."""
    repo = _plain(tmp_path)
    real = gate._git

    def failing_ls_tree(repo_dir, *args, deadline):
        if args[:1] == ("ls-tree",) and gate.DECLARATION in args:
            return subprocess.CompletedProcess(args, 128, b"", b"fatal: simulated")
        return real(repo_dir, *args, deadline=deadline)

    monkeypatch.setattr(gate, "_git", failing_ls_tree)
    verdict, why = gate.evaluate_repository(str(repo), gate.time.monotonic() + 30)
    assert verdict == "ask"
    assert why.startswith("NOT MEASURED:")
    monkeypatch.setattr(gate, "_git", real)
    assert gate.evaluate_repository(str(repo), gate.time.monotonic() + 30)[0] == "inactive"


def test_deleting_the_declaration_is_a_rules_change_while_the_remote_is_known(shim, repo):
    """D20 narrows the price of D5, C: a push that removes the declaration the remote holds is a change of
    the evidence rules, asked under Claude Code, and the deletion stays in the pushed diff."""
    assert decision(run_gate(shim, repo, "git push origin main")) == "pass"
    _git(repo, "rm", "-q", gate.DECLARATION)
    _commit(repo, "drop the declaration")
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "ask"
    assert "the push removes the declaration" in reason(answer)
    changed = subprocess.run(["git", "-C", str(repo), "diff", "--name-status", "origin/main..HEAD"],
                             capture_output=True, text=True, check=True).stdout
    assert changed.splitlines() == [f"D\t{gate.DECLARATION}"]


def test_without_a_known_remote_a_push_is_not_measured(shim, repo):
    """N1, N2: with no remote at all, the gate cannot resolve the target, so it does not switch off even
    though the push removes the committed declaration; it asks."""
    _git(repo, "remote", "remove", "origin")
    _git(repo, "rm", "-q", gate.DECLARATION)
    _commit(repo, "drop the declaration")
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert "cannot resolve what this push sends" in reason(answer)


def test_an_empty_declaration_is_not_measured_and_asks(shim, repo):
    _declare(repo)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")


def test_a_directory_without_a_repository_or_a_commit_is_not_measured(shim, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert decision(run_gate(shim, plain, "git push")) == "ask"
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    _git(fresh, "init", "-q")
    answer = run_gate(shim, fresh, "git push")
    assert decision(answer) == "ask"
    assert "no commit at HEAD" in reason(answer)


def test_a_call_whose_repository_cannot_be_resolved_is_not_measured(shim, repo):
    answer = run_gate(shim, repo, "cd $SOMEWHERE && git push")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:")


def test_the_repository_a_directory_change_names_is_the_one_checked(shim, repo, tmp_path):
    other = _plain(tmp_path, "other", remote=True)
    assert decision(run_gate(shim, repo, "git push")) == "pass"
    # Nachtrag 15: a cd no longer resolves the repository; the whole command is NOT MEASURED.
    assert decision(run_gate(shim, repo, f"cd {other} && git push")) == "ask"
    # but a single `git -C <repo>` still names the repository, resolved physically through symlinks (R4-2).
    assert decision(run_gate(shim, other, f"git -C {repo} push")) == "pass"


def test_a_chain_across_repositories_is_not_measured_while_a_single_push_resolves(shim, repo, tmp_path):
    other = _plain(tmp_path, "other", remote=True)
    # Nachtrag 15: a chained command is NOT MEASURED as a whole, whatever the repositories hold — the gate
    # no longer resolves one repository per link of a chain. Red against aed5ed74, which resolved each and
    # answered inactive here.
    both = run_gate(shim, repo, f"git push && git -C {other} push")
    assert decision(both) == "ask"
    assert both["systemMessage"].startswith("NOT MEASURED: ")
    # each repository still resolves on its own, as a single `git -C`; the declared, verified repo passes
    assert decision(run_gate(shim, other, f"git -C {repo} push")) == "pass"
    plain = _plain(tmp_path, "plain")  # no remote: a single push to it is NOT MEASURED
    assert decision(run_gate(shim, plain, "git push")) == "ask"


def test_one_failing_repository_denies_the_whole_call(shim, repo, tmp_path):
    other = tmp_path / "other"
    shutil.copytree(repo, other)
    _tamper_bundle(other / BUNDLE)
    _commit(other)
    # Nachtrag 15: reached as a single `git -C` (a chain would be NOT MEASURED); invalid evidence at head
    # denies regardless of the push range.
    assert decision(run_gate(shim, repo, f"git -C {other} push")) == "deny"


def test_a_verifier_that_cannot_start_denies(shim, repo, tmp_path):
    no_uv = dict(shim, PATH=os.pathsep.join(p for p in shim["PATH"].split(os.pathsep) if not (pathlib.Path(p) / "uv").exists()))
    answer = run_gate(no_uv, repo, "git push")
    assert decision(answer) == "deny"
    assert "uv is not on PATH" in reason(answer)
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "uv").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (broken / "uv").chmod(0o755)
    answer = run_gate(dict(shim, PATH=os.pathsep.join([str(broken), no_uv["PATH"]])), repo, "git push")
    assert decision(answer) == "deny"
    assert "no answer" in reason(answer)


@pytest.mark.parametrize("raw", ["not json", "[]", '{"tool_input": {}}', '{"tool_input": {"command": 5}}'])
def test_unreadable_hook_input_is_denied(shim, repo, raw):
    assert decision(run_gate(shim, repo, "", raw=raw)) == "deny"


def test_a_codex_style_argument_vector_is_read_as_a_command(shim, repo):
    direct = json.dumps({"cwd": str(repo), "tool_input": {"command": ["git", "push"]}})
    assert decision(run_gate(shim, repo, "", raw=direct)) == "pass"
    # A vector that wraps the push in a nested shell is read as a command too, and the push is seen: under
    # the closed grammar a nested shell is NOT MEASURED. At aed5ed74 `bash -lc 'git push'` resolved to the
    # cwd and passed a verified cwd; N15 makes it NOT MEASURED (ask). This only exercises the gate's reading
    # of a list-form command; it is not a claim about what Codex sends. Measured at the Codex pins 14a477ea
    # and c248f6d4, Codex hands the PreToolUse hook `{"command": args.cmd}` — the raw command, with no outer
    # `bash -lc` wrapper (exec_command.rs, pre_tool_use_payload; test exec_command_pre_tool_use_payload_uses_
    # raw_command). So a real Codex event would carry the command itself, nothing to unpack. The separate
    # R5-2 context defect (the hook's cwd is the session dir, not the execution workdir) is why every Codex
    # push is NOT MEASURED (Nachtrag 18, Punkt 10; D12).
    wrapped = json.dumps({"cwd": str(repo), "tool_input": {"command": ["bash", "-lc", "git push"]}})
    assert decision(run_gate(shim, repo, "", raw=wrapped)) == "ask"


# --- MCP tools ---------------------------------------------------------------------------------------

def _mcp_event(repo: pathlib.Path | str, tool: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo),
                       "tool_input": {"owner": "o", "repo": "r", "title": "t", "head": "main", "base": "main"}})


GATED_MCP = ["mcp__github__create_pull_request", "mcp__plugin_x_github__create_pull_request",
             "mcp__gitlab__create_merge_request", "mcp__gitea__create_release", "mcp__a__b__create_release",
             "mcp__github__push_files", "mcp__github__create_or_update_file", "mcp__github__merge_pull_request",
             "mcp__plugin_x_github__merge_pull_request"]
#: Owner decision of 2026-09-29 (DECISIONS.md, D8): these five write to a remote and stay ungated, open.
OPEN_MCP = ["mcp__github__delete_file", "mcp__github__create_branch", "mcp__github__update_pull_request",
            "mcp__github__update_pull_request_branch", "mcp__github__enable_pr_auto_merge"]
UNGATED_MCP = OPEN_MCP + [
    "mcp__github__create_issue", "mcp__github__create_pull_request_review", "mcp__github__create_pull_request_x",
    "mcp__github__push_files_x", "mcp__github__merge_pull_request_review", "mcp__github__xpush_files",
    "Bash_create_pull_request", "create_pull_request", "mcp__create_pull_request", "mcp__push_files"]


def test_a_proofbundle_folder_in_the_repository_cannot_replace_the_verifier(shim, repo):
    """Review Z1/N4: a top-level proofbundle/ package in the checked repository, with evidence signed by a
    key the policy does not pin, must not pass. The gate and server start the verifier isolated (empty cwd,
    python -I), so the repository's own proofbundle/cli.py never shadows the pinned package."""
    _write(repo / "proofbundle" / "__init__.py", "__version__ = 'fake'\n")
    _write(repo / "proofbundle" / "cli.py", "import json, sys\nprint(json.dumps({'ok': True}))\nsys.exit(0)\n")
    _commit(repo, "a proofbundle/ folder in the repository")
    digest = _head_digest(repo)  # the declared subject matches this tree, so the gate reaches verification
    _write(repo / BUNDLE, emit_bundle(_statement(digest), generate_signer()))  # a key the policy does not pin
    declaration = json.loads((repo / gate.DECLARATION).read_text())
    declaration["evidence"][0]["subject"] = _subject(digest)
    _write(repo / gate.DECLARATION, declaration)
    _commit(repo, "evidence for the new tree, signed by the wrong key")
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "deny", "the real verifier denies; a fake proofbundle/cli.py would pass"
    assert "exit 3" in reason(answer) or "exit 1" in reason(answer)
    assert "verification failed" in reason(answer)


def test_the_mcp_matcher_names_exactly_the_gated_tools():
    import re  # noqa: PLC0415
    assert gate.MCP_GATED_TOOLS == ("create_pull_request", "create_merge_request", "create_release",
                                    "push_files", "create_or_update_file", "merge_pull_request")
    for tool in GATED_MCP:
        assert re.search(gate.MCP_MATCHER, tool), tool
        assert gate.mcp_gated(tool)
    for tool in UNGATED_MCP:
        assert not re.search(gate.MCP_MATCHER, tool), tool
        assert not gate.mcp_gated(tool)


@pytest.mark.parametrize("tool", GATED_MCP)
def test_a_gated_mcp_tool_is_not_measured_whatever_the_local_repository(shim, repo, tool):
    """Runde 6, R6-1: a gated MCP write is NOT MEASURED and asks under Claude, because the hook binds neither
    its actual target nor the bytes it writes. The local repository is checked as a diagnosis only: a valid
    one and a changed one give the same decision."""
    answer = run_gate(shim, repo, "", raw=_mcp_event(repo, tool))
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED:") and "Diagnosis only" in reason(answer)
    assert "the local repository" in reason(answer)
    _write(repo / "src" / "app.py", "print('changed after signing')\n")
    _commit(repo)
    assert decision(run_gate(shim, repo, "", raw=_mcp_event(repo, tool))) == "ask"


def test_an_mcp_pull_request_without_declared_evidence_is_not_measured(shim, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    _git(plain, "init", "-q", "-b", "main")
    _commit(plain)
    answer = run_gate(shim, plain, "", raw=_mcp_event(plain, "mcp__github__create_pull_request"))
    assert decision(answer) == "ask"  # R6-1: never inactive for the foreign target
    assert reason(answer).startswith("NOT MEASURED:")
    _declare(plain, GOOD_BUNDLE)
    answer = run_gate(shim, plain, "", raw=_mcp_event(plain, "mcp__github__create_pull_request"))
    assert decision(answer) == "ask"


@pytest.mark.parametrize("tool, unseen", [
    ("mcp__github__create_pull_request", "it cannot see the branch the tool publishes"),
    ("mcp__gitea__create_release", "it cannot see the branch the tool publishes"),
    ("mcp__github__merge_pull_request", "it cannot see the pull request the tool merges"),
    ("mcp__github__push_files", "the bytes the tool writes come from its own arguments"),
    ("mcp__github__create_or_update_file", "the bytes the tool writes come from its own arguments"),
])
def test_a_gated_mcp_tool_says_what_the_gate_could_not_see(shim, repo, tool, unseen):
    answer = run_gate(shim, repo, "", raw=_mcp_event(repo, tool))
    assert decision(answer) == "ask"
    assert unseen in reason(answer)


def test_an_mcp_write_without_declared_evidence_is_not_measured(shim, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    _git(plain, "init", "-q", "-b", "main")
    _commit(plain)
    for tool in ("mcp__github__push_files", "mcp__github__create_or_update_file", "mcp__github__merge_pull_request"):
        answer = run_gate(shim, plain, "", raw=_mcp_event(plain, tool))
        assert decision(answer) == "ask", tool  # R6-1: never inactive for the foreign target
        assert reason(answer).startswith("NOT MEASURED:"), tool


@pytest.mark.parametrize("tool", [t for t in UNGATED_MCP if t.startswith("mcp__")])
def test_an_mcp_tool_the_gate_does_not_know_gets_no_answer(shim, repo, tool):
    assert run_gate(shim, repo, "", raw=_mcp_event(repo, tool)) is None


# --- the hook entry ----------------------------------------------------------------------------------

def _hook_entries() -> list[dict]:
    config = json.loads(HOOKS.read_text(encoding="utf-8"))
    assert set(config) <= {"description", "hooks"}
    groups = config["hooks"]["PreToolUse"]
    # Nachtrag 19b, Punkt 8: the file tools join, so a write to a repository's configuration or hooks is judged
    assert [g["matcher"] for g in groups] == ["Bash", gate.MCP_MATCHER, "^(Write|Edit|MultiEdit|NotebookEdit)$"]
    assert groups[0]["hooks"] == groups[1]["hooks"] == groups[2]["hooks"], "every matcher runs the same gate"
    return groups[0]["hooks"]


def test_the_hook_file_matcher_and_d8_name_the_same_tools():
    import re  # noqa: PLC0415
    matcher = json.loads(HOOKS.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][1]["matcher"]
    for tool in GATED_MCP:
        assert re.search(matcher, tool), tool
    for tool in UNGATED_MCP:
        assert not re.search(matcher, tool), tool
    decisions = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
    d8 = decisions.split("## D8.", 1)[1].split("\n## ", 1)[0]
    assert f"`{gate.MCP_MATCHER}`" in d8
    gated, _, rest = d8.partition("Ungated")
    for name in gate.MCP_GATED_TOOLS:
        assert f"`{name}`" in gated, name
    for tool in OPEN_MCP:
        assert f"`{tool.rsplit('__', 1)[1]}`" in rest, tool


def test_the_hook_runs_the_gate_on_every_shell_call_with_room_for_its_deadline():
    (entry,) = _hook_entries()
    assert entry["type"] == "command"
    assert "if" not in entry, "an if filter would let compound and nested forms of a gated call pass"
    assert '"${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"' in entry["command"]
    assert entry["timeout"] > gate.DEADLINE_SECONDS


def test_the_hook_blocks_the_call_when_the_gate_cannot_run(tmp_path, repo):
    (entry,) = _hook_entries()
    event = json.dumps({"cwd": str(repo), "tool_input": {"command": "git --version"}})
    ok = subprocess.run(["sh", "-c", entry["command"]], input=event, capture_output=True, text=True,
                        env=dict(os.environ, CLAUDE_PLUGIN_ROOT=str(PLUGIN)), check=False)
    assert (ok.returncode, ok.stdout) == (0, "")
    missing = subprocess.run(["sh", "-c", entry["command"]], input=event, capture_output=True, text=True,
                             env=dict(os.environ, CLAUDE_PLUGIN_ROOT=str(tmp_path / "gone")), check=False)
    assert missing.returncode == 2
    assert "blocked" in missing.stderr


# --- actionable rejections and the evidence rules (D19, D20) ----------------------------------------

def test_a_rejection_names_the_evidence_what_failed_and_the_next_step(shim, repo):
    _tamper_bundle(repo / BUNDLE)
    _commit(repo)
    text = reason(run_gate(shim, repo, "git push"))
    assert text.startswith("proofbundle gate: Evidence: bundle .proofbundle/build.bundle.json (evidence[0]). Failed: exit 1")
    assert "Next step: obtain evidence that verifies under the declared key or policy." in text
    assert text.count(WEAKEN_RULE) == 1


def test_a_not_measured_ask_keeps_its_prefix_and_names_the_declaration(shim, repo):
    _declare(repo)
    _commit(repo)
    text = reason(run_gate(shim, repo, "git push"))
    assert text.startswith("NOT MEASURED: Evidence: the declaration .proofbundle/evidence.json. Failed: its evidence "
                           "list is empty.")


def test_a_weakened_policy_is_a_rules_change_and_is_asked(shim, repo):
    policy = json.loads((repo / POLICY).read_text())
    policy["allowed_issuers"].append({"public_key_b64": _b64(generate_signer())})
    _write(repo / POLICY, policy)
    _commit(repo, "allow a second issuer")
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert "the policy .proofbundle/policy.json changes" in reason(answer)
    assert "Changes to the evidence rules need a review" in reason(answer)
    _publish(repo)
    assert decision(run_gate(shim, repo, "git push")) == "pass", "once the remote holds it, the push is plain"


def test_a_changed_key_or_item_is_a_rules_change(shim, repo):
    declaration = json.loads((repo / gate.DECLARATION).read_text())
    declaration["evidence"][0]["path"] = ".proofbundle/other.bundle.json"
    (repo / ".proofbundle" / "other.bundle.json").write_text((repo / BUNDLE).read_text())
    _write(repo / gate.DECLARATION, declaration)
    _commit(repo)
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert "the declared items change" in reason(answer)


def test_an_intermediate_commit_that_changes_the_rules_is_caught(shim, tmp_path):
    """D3 B, N3: a valid tip does not heal a bad middle commit. origin/main = A (declared), B removes the
    declaration, C restores the identical rules (same pinned key) for a new tree; the tip's rules match the
    base, yet the push still reports B's rules change, because every sent commit is compared."""
    path = tmp_path / "chain"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "src" / "app.py", "print('A')\n")
    _commit(path)
    signer = generate_signer()  # held here, so C can restore A's exact policy and key

    def sign(message: str) -> None:
        digest = _head_digest(path)
        _write(path / BUNDLE, emit_bundle(_statement(digest), signer))
        _write(path / POLICY, _pinned_policy(signer))
        _declare(path, {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": _subject(digest)})
        _commit(path, message)

    sign("A: declare")  # A
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "chain.git"))
    _git(path, "remote", "add", "origin", str(tmp_path / "chain.git"))
    _git(path, "push", "-q", "origin", "main")
    _git(path, "rm", "-q", "-r", ".proofbundle")
    _commit(path, "B: remove the declaration")  # B
    _write(path / "src" / "app.py", "print('C')\n")
    _commit(path, "C code")
    sign("C: restore the identical rules for a new tree")  # C, same key and policy as A
    answer = run_gate(shim, path, "git push origin main")
    assert decision(answer) == "ask"
    assert "the push removes the declaration" in reason(answer)


def test_an_intermediate_commit_with_invalid_evidence_is_caught(shim, repo):
    """D3 B, N3: an intermediate commit whose evidence does not verify denies the push, even though the
    tip verifies. origin/main = A; B tampers the bundle for B's tree; C restores a valid tip."""
    _write(repo / "src" / "app.py", "print('B and C')\n")
    _commit(repo, "B: change code, keep A's evidence (now stale for B's tree)")  # B: stale subject -> deny
    b_commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    digest_c = _head_digest(repo)  # C changes only .proofbundle, so C's tree digest equals B's
    fresh = generate_signer()
    _write(repo / BUNDLE, emit_bundle(_statement(digest_c), fresh))
    _write(repo / POLICY, _pinned_policy(fresh))
    declaration = json.loads((repo / gate.DECLARATION).read_text())
    declaration["evidence"][0]["subject"] = _subject(digest_c)
    _write(repo / gate.DECLARATION, declaration)
    _commit(repo, "C: valid evidence for the tip")  # C verifies and is bound; B in the range does not
    answer = run_gate(shim, repo, "git push origin main")
    assert decision(answer) == "deny"
    assert b_commit[:12] in reason(answer) and "does not match the tree" in reason(answer)


def test_a_git_replacement_does_not_change_the_evidence_the_gate_reads(shim, tmp_path):
    """R3-8: git reads replacement objects but transfers the originals, so a replacement must not change
    the gate's view. origin/main and HEAD are A (no declaration); branch `bad` is B with a malformed
    declaration. `git push --force origin bad:main` sends B; the gate must judge B, not a replacement of
    it. Measured red against 3026924e: `git replace B A` turned the deny into inactive."""
    path = _plain(tmp_path, "rep", remote=True)  # A: README only, origin/main = A
    _git(path, "checkout", "-q", "-b", "bad")
    _write(path / gate.DECLARATION, "{ not valid json\n")  # a malformed declaration at B
    _commit(path, "B: malformed declaration")
    b = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                       check=True).stdout.strip()
    a = subprocess.run(["git", "-C", str(path), "rev-parse", "refs/remotes/origin/main"], capture_output=True,
                       text=True, check=True).stdout.strip()
    _git(path, "checkout", "-q", "main")
    assert decision(run_gate(shim, path, "git push --force origin bad:main")) == "deny", "no replacement yet"
    _git(path, "replace", b, a)  # a replace-aware read of B now returns A, which declares nothing
    answer = run_gate(shim, path, "git push --force origin bad:main")
    assert decision(answer) == "deny", "the gate must read the transferred object B, not its replacement A"
    assert "malformed" in reason(answer) or "could not be read" in reason(answer) or "declaration" in reason(answer)


def test_a_graft_does_not_hide_a_commit_the_push_sends(shim, tmp_path):
    """R3-8 (grafts): .git/info/grafts rewrites the parent chain git reads, but the push sends the real
    ancestors. A graft that reparents the tip past a malformed middle commit must not hide it. Measured red
    against 3026924e, where --no-replace-objects left grafts in force; GIT_GRAFT_FILE emptied fixes it."""
    path = _plain(tmp_path, "graft", remote=True)  # A: no declaration, origin/main = A
    _write(path / gate.DECLARATION, "{ not valid json\n")
    _commit(path, "X: malformed declaration")  # X, a child of A
    _git(path, "rm", "-q", "-r", ".proofbundle")
    _commit(path, "C: clean tip")  # C, a child of X; its tree declares nothing
    a = subprocess.run(["git", "-C", str(path), "rev-parse", "refs/remotes/origin/main"], capture_output=True,
                       text=True, check=True).stdout.strip()
    c = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                       check=True).stdout.strip()
    assert decision(run_gate(shim, path, "git push origin main")) == "deny", "X is in the range, no graft yet"
    (path / ".git" / "info" / "grafts").write_text(f"{c} {a}\n", encoding="utf-8")  # reparent C past X
    answer = run_gate(shim, path, "git push origin main")
    assert decision(answer) == "deny", "the gate must evaluate X, which the push still sends"


def _resolve(repo, *args):
    return gate.resolve_push_targets(str(repo), list(args), gate.time.monotonic() + 30)


def _repo_with_remote(tmp_path, name, *, stale):
    """A repository with a bare remote and a tracking ref for main, one commit ahead of the remote. With
    stale=True its declaration names a subject no tree matches, so a push to it denies; otherwise it
    declares nothing and a push is inactive."""
    path = tmp_path / name
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "f.txt", name + "\n")
    if stale:
        _write(path / BUNDLE, "{}")
        _write(path / POLICY, "{}")
        _declare(path, {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": _subject("0" * 64)})
    _commit(path)
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / f"{name}.git"))
    _git(path, "remote", "add", "origin", str(tmp_path / f"{name}.git"))
    _git(path, "push", "-q", "origin", "HEAD:refs/heads/main")
    _write(path / "f.txt", name + " more\n")
    _commit(path, "more")  # one commit ahead, so there is something to push
    return path


def _remote_head(tmp_path, name):
    out = subprocess.run(["git", "--git-dir", str(tmp_path / f"{name}.git"), "rev-parse", "--verify",
                          "--quiet", "refs/heads/main"], capture_output=True, text=True, check=False)
    return out.stdout.strip()


@pytest.mark.parametrize("command, cwd, expect", [
    ("(cd ../good && true) ; git push origin main", "bad", "ask"),   # Nachtrag 15: a subshell -> NOT MEASURED
    ("GIT_DIR=../bad/.git git push origin main", "good", "ask"),      # prefix GIT_DIR -> NOT MEASURED
    ("env -C ../bad git push origin main", "good", "ask"),            # env -C -> NOT MEASURED
    ("export GIT_DIR=../bad/.git ; git push origin main", "good", "ask"),  # exported GIT_DIR -> NOT MEASURED
])
def test_a_command_that_moves_the_repository_is_resolved_or_not_measured(shim, tmp_path, command, cwd, expect):
    """Befund 1 with Nachtrag 15, Ebene 1: a cd in a subshell, a GIT_DIR prefix, env -C and an exported
    GIT_DIR each make the push act on `bad` while the gate, at 78132534, judged `good` or the cwd as
    inactive. Under the closed grammar none of these is the one strict simple command, so every form is now
    NOT MEASURED (the subshell too, which Nachtrag 12 still resolved to bad). Executing the command shows the
    push really reaches bad's remote, so NOT MEASURED is the honest verdict. Red against aed5ed74, where the
    subshell form resolved to bad and denied."""
    bad = _repo_with_remote(tmp_path, "bad", stale=True)
    _repo_with_remote(tmp_path, "good", stale=False)
    answer = run_gate(shim, tmp_path / cwd, command)
    assert decision(answer) == expect, (command, reason(answer))
    if expect == "ask":
        assert reason(answer).startswith("NOT MEASURED: ") and "cannot tell which repository" in reason(answer)
    subprocess.run(command, shell=True, cwd=str(tmp_path / cwd), check=True, capture_output=True,
                   env=dict(os.environ, **{k: "t" for k in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME")},
                            **{k: "t@e" for k in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")}))
    bad_head = subprocess.run(["git", "-C", str(bad), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    assert _remote_head(tmp_path, "bad") == bad_head, "the push really acted on bad, not on what the gate judged"


def test_an_unmodelled_git_env_var_is_not_measured_but_a_neutral_one_resolves(shim, tmp_path):
    """Befund 1: only a narrow list of GIT_* names is target-neutral; every other is unresolved, like a
    push option. GIT_TERMINAL_PROMPT=0 still resolves; GIT_OBJECT_DIRECTORY does not."""
    _repo_with_remote(tmp_path, "r", stale=False)
    assert decision(run_gate(shim, tmp_path / "r", "GIT_TERMINAL_PROMPT=0 git push origin main")) == "inactive"
    answer = run_gate(shim, tmp_path / "r", "GIT_OBJECT_DIRECTORY=/tmp/x git push origin main")
    assert decision(answer) == "ask" and "cannot tell which repository" in reason(answer)


@pytest.mark.parametrize("command", [
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=url.https://e.invalid/.pushInsteadOf GIT_CONFIG_VALUE_0=x git push origin main",
    "HOME=/tmp/elsewhere git push origin main",
    "GIT_CONFIG_GLOBAL=/tmp/x.gitconfig git push origin main",
    "env HOME=/tmp/elsewhere git push origin main",
])
def test_config_assigned_in_the_command_is_not_measured(shim, tmp_path, command):
    """Befund 2 with Nachtrag 15, Ebene 1: a configuration assigned in the command (GIT_CONFIG_*, HOME,
    XDG_CONFIG_HOME, through a prefix or env) is a non-neutral prefix or a wrapper, so the directory is NOT
    MEASURED. Red against 78132534, which inherited only the host environment and resolved these to main.
    Under the closed grammar the reason is the generic unresolved-directory one, not the config-sentinel
    wording the earlier resolver produced."""
    _repo_with_remote(tmp_path, "r", stale=False)
    answer = run_gate(shim, tmp_path / "r", command)
    assert decision(answer) == "ask"
    assert "cannot tell which repository" in reason(answer)


# --- Nachtrag 12: the closed grammar for the directory --------------------------------------------------

def _exec_env() -> dict:
    """An environment that lets `git push` run in a test without a configured identity or a prompt."""
    return dict(os.environ, GIT_TERMINAL_PROMPT="0",
                **{k: "t" for k in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME")},
                **{k: "t@e" for k in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")})


#: The eleven forms the reviewer measured on 2026-10-01 (Nachtrag 12). At 90c4208b each was judged
#: inactive while the push really reached `bad`; the closed grammar now leaves the directory NOT MEASURED.
#: Each entry is (command, the working directory it runs in). `{script}` is filled with a path in tmp_path.
_CLOSED_FORMS = [
    ("false && cd ../good ; git push origin main", "bad"),
    ("true || cd ../good ; git push origin main", "bad"),
    ("[ -d /nowhere ] && cd ../good ; git push origin main", "bad"),
    ("set -a ; GIT_DIR=../bad/.git ; git push origin main", "good"),
    ("eval 'export GIT_DIR=../bad/.git' ; git push origin main", "good"),
    ("declare -gx GIT_DIR=../bad/.git ; git push origin main", "good"),
    ("{ cd ../bad ; } ; git push origin main", "good"),
    ("if true ; then cd ../bad ; fi ; git push origin main", "good"),
    ("for d in ../bad ; do cd $d ; done ; git push origin main", "good"),
    ("f() { cd ../bad ; } ; f ; git push origin main", "good"),
    ("printf 'cd ../bad\\n' > {script} ; . {script} ; git push origin main", "good"),
]


@pytest.mark.parametrize("command, cwd", _CLOSED_FORMS)
def test_a_closed_grammar_form_is_not_measured_and_the_push_still_reaches_bad(shim, tmp_path, command, cwd):
    """Nachtrag 12: a conditional `cd`, an environment set through `set -a`/`eval`/`declare`, and a `cd`
    inside a brace group, an `if`, a `for`, a function or a sourced file all leave the command outside the
    modeled grammar, so the gate says NOT MEASURED instead of the wrong inactive. Executing the command
    shows the push really reaches `bad`. Red against 90c4208b, where every form resolved to the cwd or to
    `good` and was inactive."""
    bad = _repo_with_remote(tmp_path, "bad", stale=True)
    _repo_with_remote(tmp_path, "good", stale=False)
    command = command.replace("{script}", str(tmp_path / "s.sh"))
    answer = run_gate(shim, tmp_path / cwd, command)
    assert decision(answer) == "ask", (command, reason(answer))
    assert reason(answer).startswith("NOT MEASURED: ") and "cannot tell which repository" in reason(answer)
    subprocess.run(["bash", "-c", command], cwd=str(tmp_path / cwd), check=True, capture_output=True,
                   env=_exec_env())  # bash, as the reviewer measured: `declare`, `set -a`, `function` are bash
    bad_head = subprocess.run(["git", "-C", str(bad), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    assert _remote_head(tmp_path, "bad") == bad_head, "the push really acted on bad, not on what the gate judged"


#: The differential set of Nachtrag 15, Ebene 1: short commands built from the grammar's pieces and the
#: reviewer's dimensions (CDPATH, a symlinked -C, a failing redirection, conditional chains, subshells, a
#: start-file-style function, a nested shell), each with the repository the gate must resolve it to
#: ('a', 'b') or None when the closed grammar leaves it NOT MEASURED. `{bad}` is a redirection target whose
#: directory does not exist, so the redirection fails and the push never runs; `blink` is a symlink to the
#: sibling repository `b`.
_DIFFERENTIAL = [
    # the strict single commands: resolved, and the push really comes from the resolved repository
    ("git push origin main", "a"),
    ("git push --force origin main", "a"),
    ("GIT_TERMINAL_PROMPT=0 git push origin main", "a"),
    ("git push origin main 2>/dev/null", "a"),
    ("git -C ../b push origin main", "b"),
    ("git -C blink push origin main", "b"),                     # a symlinked -C, resolved physically (R4-2)
    ("git push origin main >{bad}", "a"),                       # the redirection fails, so no push runs
    # everything else is NOT MEASURED
    ("true && git push origin main", None),
    ("cd ../b && git push origin main", None),
    ("cd ../b ; git push origin main", None),
    ("cd ../b && cd ../a && git push origin main", None),
    ("cd ../b && git push origin main 2>&1", None),
    ("(cd ../b) ; git push origin main", None),                 # subshell
    ("(cd ../b && true) ; git push origin main", None),         # subshell
    ("false && cd ../b ; git push origin main", None),          # conditional chain
    ("true || cd ../b ; git push origin main", None),           # conditional chain
    ("{ cd ../b ; } ; git push origin main", None),             # brace group
    ("f() { cd ../b ; } ; f ; git push origin main", None),     # start-file-style function
    ("CDPATH=.. cd b && git push origin main", None),           # CDPATH redirects `cd b` to the sibling b
    ("CDPATH=.. git push origin main", None),                   # a non-neutral prefix
    ("HOME=/nowhere git push origin main", None),               # config-class prefix: now NOT MEASURED
    ("GIT_DIR=../b/.git git push origin main", None),
    ("eval 'cd ../b' ; git push origin main", None),
    ("bash -lc 'cd ../b && git push origin main'", None),       # a nested shell (the bypass probe)
    ("command git push origin main", None),
]


def test_the_differential_property_holds_the_push_comes_from_the_resolved_repository(tmp_path, capsys):
    """Nachtrag 15, Ebene 1: two properties over the differential set. P1 (soundness, no false pass): for
    every command, when the gate resolves a directory and the executed command advances exactly one remote,
    that remote is the resolved one. P2 (the closed grammar): the gate resolves exactly the strict single
    commands and leaves every other form NOT MEASURED, resolving to the listed repository where it resolves.
    Each command is judged by the gate, then run in bash in `a`; the repository whose bare remote advances
    is the real source. Prints the set size, the number resolved, and the violations for the report. Red
    against aed5ed74, where the cd, subshell and config-prefix forms resolved rather than NOT MEASURED."""
    a = _repo_with_remote(tmp_path, "a", stale=False)
    b = _repo_with_remote(tmp_path, "b", stale=False)
    os.symlink(str(b), str(a / "blink"))  # a symlink in a's working tree pointing at the sibling repo b
    bad = str(tmp_path / "no-such-dir" / "x")  # a redirection target whose parent directory does not exist
    heads = {name: subprocess.run(["git", "-C", str(tmp_path / name), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()
             for name in ("a", "b")}
    base = {name: _remote_head(tmp_path, name) for name in ("a", "b")}  # one commit behind each HEAD
    assert all(base[n] and base[n] != heads[n] for n in ("a", "b"))
    violations, measured = [], 0
    for raw, expect in _DIFFERENTIAL:
        command = raw.replace("{bad}", bad)
        for name in ("a", "b"):  # reset each bare remote to one commit behind its HEAD
            subprocess.run(["git", "--git-dir", str(tmp_path / f"{name}.git"), "update-ref",
                            "refs/heads/main", base[name]], check=True, capture_output=True)
        calls = gate.gated_calls(command)
        assert len(calls) == 1, (command, calls)
        _, gdir, _ = calls[0]
        subprocess.run(["bash", "-c", command], cwd=str(a), capture_output=True, env=_exec_env())
        pushed = [n for n in ("a", "b") if _remote_head(tmp_path, n) == heads[n]]
        source = pushed[0] if len(pushed) == 1 else None
        if gdir is gate.UNKNOWN:
            resolved = None
        else:
            resolved = "a" if os.path.realpath(os.path.join(str(a), gdir)) == os.path.realpath(str(a)) else \
                       ("b" if os.path.realpath(os.path.join(str(a), gdir)) == os.path.realpath(str(b)) else "?")
            measured += 1
            if source is not None and source != resolved:  # P1: a resolved push never acts on another repo
                violations.append((command, "resolved", resolved, "but pushed", source))
        # P2: the gate resolves exactly the forms the closed grammar resolves, to exactly the named repo
        if expect is None:
            if gdir is not gate.UNKNOWN:
                violations.append((command, "expected NOT MEASURED, resolved", resolved))
        elif resolved != expect:
            violations.append((command, f"expected resolved {expect}, got", resolved))
    with capsys.disabled():
        print(f"\n[N15 differential] commands={len(_DIFFERENTIAL)} resolved={measured} "
              f"violations={len(violations)}")
        for v in violations:
            print("  VIOLATION", v)
    assert violations == []


# --- Nachtrag 15, Ebene 1: deny on a hook-disabling form, the bypass probes, R4-7 ----------------------

@pytest.mark.parametrize("command", [
    "git push --no-verify",
    "git push --no-verify origin main",
    "git -c core.hooksPath=/x push origin main",
    "git -c core.hooksPath= push",
    "git config core.hooksPath /x",
    "git config core.hooksPath .husky",
])
def test_a_form_that_turns_off_the_real_push_check_is_denied(shim, repo, command):
    """Nachtrag 15, Ebene 1, Punkt 5: --no-verify would skip the pre-push hook, and setting core.hooksPath
    (through a -c option or git config) would redirect or disable it, so the gate denies rather than let an
    unchecked push through. Red against aed5ed74, where --no-verify was a neutral push flag that resolved
    and passed, and core.hooksPath was never recognised."""
    answer = run_gate(shim, repo, command)
    assert decision(answer) == "deny"
    assert "turn off the gate's check of the real push" in reason(answer)


def test_a_hook_disabling_form_denies_in_a_chain_where_the_directory_is_not_measured(shim, repo):
    """The deny holds inside a chain, where the directory is NOT MEASURED: the hook-disabling marker denies
    regardless of the directory, and a deny outranks the NOT MEASURED ask of the rest of the chain. Without
    this the bypass `git push --no-verify && anything` would only ask, not deny."""
    assert decision(run_gate(shim, repo, "git push --no-verify && git push")) == "deny"
    assert decision(run_gate(shim, repo, "cd elsewhere && git push --no-verify")) == "deny"


@pytest.mark.parametrize("command", [
    "bash -lc 'git push'",
    "bash -cl 'git push origin main'",
    "sh -lc 'git push'",
    "env bash -lc 'git push'",
    "bash -ilc 'git push'",
    "/bin/bash -lc 'git push'",
])
def test_a_push_nested_in_a_shell_bundle_is_not_measured(shim, repo, command):
    """A push run through `bash -lc`/`sh -lc` (the Codex host's own form) and its flag-bundle variants is a
    nested shell, which the closed grammar leaves NOT MEASURED — never silently passed. Red against
    aed5ed74, which resolved these to the cwd and would pass a verified cwd. The scan still has to SEE the
    push through any `-c` bundle (`-lc`, `-cl`, `-ilc`) and through a wrapper, or the push would slip past
    unseen; that it is seen, as NOT MEASURED, is what this asserts."""
    answer = run_gate(shim, repo, command)
    assert decision(answer) == "ask"
    assert answer["systemMessage"].startswith("NOT MEASURED: ")


def test_a_push_insteadof_rewrite_is_not_measured(repo):
    """R4-7: `git remote get-url` shows the rewritten push URL, but the equality of the displayed push and
    fetch URLs is not a proof the push reaches the comparison-state origin. A url.*.pushInsteadOf rule that
    applies to this remote makes the push NOT MEASURED. Runde 6, Punkt 2: a rule that provably does not
    match this remote's URL is excluded and no longer forces NOT MEASURED. Red against aed5ed74, which
    compared only the displayed URLs."""
    assert _resolve(repo, "origin", "main") is not None  # no push rewrite: the target resolves
    _git(repo, "config", "url.https://mirror.invalid/.pushInsteadOf", "https://origin.invalid/")
    assert _resolve(repo, "origin", "main") is not None  # the rule does not match the remote's path URL
    url = str(repo.parent / "remote.git")  # the fixture's remote URL (a local bare repository path)
    _git(repo, "config", "url.https://mirror.invalid/x/.pushInsteadOf", url)
    assert _resolve(repo, "origin", "main") is None      # a push-only rewrite of this remote: NOT MEASURED


def test_a_symlinked_minus_c_is_resolved_physically(repo, tmp_path):
    """R4-2: `git -C` walks the filesystem physically, so the gate resolves it with realpath, not a string
    normalisation. A `git -C link/..` where `link` is a symlink names the symlink target's parent, not the
    cwd. The gate must judge the same repository git does."""
    link = tmp_path / "link"
    link.symlink_to(repo)
    # git -C link/.. acts in the parent of the symlink target (repo's parent), not in the cwd
    calls = gate.gated_calls(f"git -C {link}/.. push")
    assert len(calls) == 1 and calls[0][0] == "git push"
    _, gdir, _ = calls[0]
    assert gdir is not gate.UNKNOWN
    assert os.path.realpath(os.path.join(os.getcwd(), gdir)) == os.path.realpath(str(repo.parent))


# --- Nachtrag 15, Ebene 2: the prototype pre-push hook (DECISIONS.md, D24) -----------------------------

def _push_env(shim: dict) -> dict:
    return dict(shim, GIT_TERMINAL_PROMPT="0",
                **{k: "t" for k in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME")},
                **{k: "t@e" for k in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL")})


def _install_pre_push(repo_path: pathlib.Path) -> None:
    """Install the prototype pre-push hook in THIS repository only, through its local core.hooksPath. The
    hook forwards git's argv and stdin to the gate's `pre-push` entry. Nothing global is touched."""
    hooks = repo_path / ".pb-prototype-hooks"
    hooks.mkdir()
    hook = hooks / "pre-push"
    hook.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{GATE}" pre-push "$@"\n', encoding="utf-8")
    hook.chmod(0o755)
    _git(repo_path, "config", "core.hooksPath", str(hooks))


#: Forms that push to `bad` from within it. Level 1 leaves most NOT MEASURED; the prototype Level-2 hook
#: sees git's real refs and denies the push regardless of the form. `git push --no-verify` is the exception
#: the levels are built around: --no-verify skips the hook, so only Level 1's deny stops it.
_LEVEL2_FORMS = [
    "git push origin main",
    "cd . && git push origin main",
    "(git push origin main)",
    "{ git push origin main ; }",
    "true && git push origin main",
    "env git push origin main",
    "bash -lc 'git push origin main'",
    "bash -cl 'git push origin main'",
    "sh -lc 'git push origin main'",
    "eval 'git push origin main'",
]


def test_the_prototype_pre_push_hook_catches_what_level_1_leaves_not_measured(shim, tmp_path, capsys):
    """Nachtrag 15, Ebene 2 (D24): the prototype pre-push hook reaches a verdict from git's own ref lines,
    independent of the shell form, so it denies a push of invalid evidence that Level 1 could only mark NOT
    MEASURED. Each form is run for real against `bad` (whose declaration names a subject no tree matches);
    the hook must block every one and the remote must not advance. `git push --no-verify` is measured too:
    it skips the hook (Level 2 cannot see it), which is why Level 1 denies it. A clean repository's push is
    allowed. Prints the Level 1 / Level 2 table for the report."""
    bad = _repo_with_remote(tmp_path, "bad", stale=True)
    good = _repo_with_remote(tmp_path, "good", stale=False)
    _install_pre_push(bad)
    _install_pre_push(good)
    base = _remote_head(tmp_path, "bad")
    env = _push_env(shim)
    rows = []
    for form in _LEVEL2_FORMS:
        subprocess.run(["git", "--git-dir", str(tmp_path / "bad.git"), "update-ref", "refs/heads/main", base],
                       check=True, capture_output=True)
        level1 = decision(run_gate(shim, bad, form))
        proc = subprocess.run(["bash", "-c", form], cwd=str(bad), capture_output=True, env=env)
        blocked = proc.returncode != 0 and _remote_head(tmp_path, "bad") == base
        rows.append((form, level1, "blocked" if blocked else "PUSHED"))
        assert blocked, (form, "level2 did not block", proc.stderr.decode()[-400:])
    # --no-verify skips the hook entirely: Level 2 cannot stop it, only Level 1's deny does.
    subprocess.run(["git", "--git-dir", str(tmp_path / "bad.git"), "update-ref", "refs/heads/main", base],
                   check=True, capture_output=True)
    nv_level1 = decision(run_gate(shim, bad, "git push --no-verify origin main"))
    nv = subprocess.run(["bash", "-c", "git push --no-verify origin main"], cwd=str(bad), capture_output=True, env=env)
    nv_blocked = nv.returncode != 0 and _remote_head(tmp_path, "bad") == base
    rows.append(("git push --no-verify origin main", nv_level1, "blocked" if nv_blocked else "PUSHED"))
    assert nv_level1 == "deny"               # Level 1 denies --no-verify
    assert not nv_blocked                    # Level 2 is skipped by --no-verify, so the real push went through
    # a clean repository (nothing invalid): the hook allows the push and the remote advances
    good_base = _remote_head(tmp_path, "good")
    ok = subprocess.run(["bash", "-c", "git push origin main"], cwd=str(good), capture_output=True, env=env)
    assert ok.returncode == 0 and _remote_head(tmp_path, "good") != good_base
    rows.append(("git push origin main (clean repo)", decision(run_gate(shim, good, "git push origin main")), "allowed"))
    with capsys.disabled():
        print("\n[N15 Ebene-2 pre-push prototype]  form | Level 1 | Level 2 (real push)")
        for form, l1, l2 in rows:
            print(f"  {form:45} | {l1:9} | {l2}")


def test_a_fetch_refspec_that_does_not_map_the_target_is_not_measured(shim, repo):
    """R3-2: the remote-tracking ref name is not proof of what it tracks. A fetch refspec that maps another
    remote branch onto refs/remotes/origin/main means that ref records 'other', not 'main', so a push to
    main is judged against the wrong state. NOT MEASURED. Red against 3026924e, which checked only the
    name. The reviewer's reproduction: a force push to main stayed inactive and removed the declaration."""
    assert _resolve(repo, "origin", "main") is not None  # the standard refspec maps main cleanly
    _git(repo, "config", "remote.origin.fetch", "+refs/heads/other:refs/remotes/origin/main")
    assert _resolve(repo, "origin", "main") is None, "main no longer maps to origin/main"
    answer = run_gate(shim, repo, "git push --force origin main")
    assert decision(answer) == "ask" and reason(answer).startswith("NOT MEASURED: ")


def test_a_fetch_refspec_collision_on_the_tracking_ref_is_not_measured(repo):
    """R3-2: if two remote branches both map onto refs/remotes/origin/main, the ref's state is whichever
    fetched last. NOT MEASURED even though the expected name exists and main still maps."""
    _git(repo, "config", "--add", "remote.origin.fetch", "+refs/heads/other:refs/remotes/origin/main")
    assert _resolve(repo, "origin", "main") is None


def test_options_after_a_double_dash_are_the_remote_and_refspec(repo):
    """R3-1: `--` ends options; what follows is <remote> <refspec>, not more refspecs for a default push.
    Measured red against 3026924e, where `-- origin zzz` fell through to the default push target."""
    assert _resolve(repo, "--", "origin", "zzz") is None  # zzz has no tracking ref: NOT MEASURED
    assert _resolve(repo, "--", "origin", "main") == _resolve(repo, "origin", "main")


def test_an_option_the_gate_does_not_model_is_not_measured(repo):
    """R3-1: --repo and -c change the endpoint; an abbreviation like --mir is --mirror; an unknown option
    may do anything. Only a narrow list of target-neutral options is allowed literally. Red against
    3026924e, where these fell through to a resolved default target."""
    for args in (["--repo=other", "--force"], ["--repo", "other"], ["--mir", "origin"],
                 ["--yet-unknown", "origin", "main"], ["origin", "main", "--exec=/x", "--unknown"]):
        assert _resolve(repo, *args) is None, args
    # the narrow allowlist still resolves a plain force push and a push option
    assert _resolve(repo, "--force", "origin", "main") is not None
    assert _resolve(repo, "-o", "ci.skip", "origin", "main") is not None
    assert _resolve(repo, "origin", "main", "--force-with-lease") is not None


def test_a_git_true_bool_in_the_push_config_is_not_measured(repo):
    """R3-3: git reads 1, yes, on as true. A mirror remote or push.followTags set to such a value adds
    refs the command does not name. Red against 3026924e, where only the literal 'true' was caught."""
    for key, value in (("remote.origin.mirror", "1"), ("push.followTags", "on"),
                       ("remote.origin.mirror", "yes")):
        _git(repo, "config", key, value)
        assert _resolve(repo, "origin", "main") is None, (key, value)
        _git(repo, "config", "--unset-all", key)


def test_a_malformed_git_bool_in_the_push_config_is_not_measured(repo):
    """R3-3: a value git cannot read as a boolean is NOT MEASURED, not silently false."""
    _git(repo, "config", "remote.origin.mirror", "notabool")
    assert _resolve(repo, "origin", "main") is None


def test_a_rewritten_or_multiple_push_endpoint_is_not_measured(repo, tmp_path):
    """Befund 1: pushInsteadOf and a second remote URL send the push to a different or further endpoint
    than the remote-tracking ref records. Red against 3026924e, which checked only remote.<name>.pushurl."""
    url = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True,
                         text=True, check=True).stdout.strip()
    _git(repo, "config", f"url.https://example.invalid/.pushInsteadOf", url)
    assert _resolve(repo, "origin", "main") is None, "pushInsteadOf rewrites the push endpoint"
    _git(repo, "config", "--unset-all", "url.https://example.invalid/.pushInsteadOf")
    assert _resolve(repo, "origin", "main") is not None, "without a rewrite it resolves again"
    _git(repo, "config", "--add", "remote.origin.url", str(tmp_path / "second.git"))
    assert _resolve(repo, "origin", "main") is None, "a second remote URL sends the push to both"


def test_config_injected_through_the_environment_is_not_measured(repo, monkeypatch):
    """R3-1: the gate reads git configuration in the push's own environment, so a GIT_CONFIG_* injection
    reaches its endpoint read as it reaches the push. An injected pushurl makes the push endpoint differ
    from the fetch endpoint the tracking ref records, so the push is NOT MEASURED. Red against 3026924e,
    where remote.<name>.pushurl was read only from the committed configuration."""
    assert _resolve(repo, "origin", "main") is not None
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "remote.origin.pushurl")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://example.invalid/x.git")
    assert _resolve(repo, "origin", "main") is None


def test_config_injected_on_the_command_line_is_not_measured(shim, repo):
    """R3-1 with Nachtrag 15, Ebene 1: `git -c <key>=<value> push` carries a git global option the strict
    single-command grammar does not model, so the directory is NOT MEASURED before any target is resolved.
    Red against 3026924e, where -c was consumed and ignored; the reason is now the generic unresolved-
    directory one, not the earlier config-sentinel wording."""
    answer = run_gate(shim, repo, "git -c remote.origin.pushurl=/tmp/elsewhere.git push origin main")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED: ") and "cannot tell which repository" in reason(answer)


def test_a_force_push_that_drops_a_declaration_on_another_branch_is_resolved_or_not_measured(shim, repo, tmp_path):
    """N1: a push to a branch this repository tracks is judged against that branch's state, not the default
    branch. Pushing a declaration-free HEAD onto a tracked `release` that declared is a rules change."""
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/release")  # release = A (declared), now tracked
    _git(repo, "rm", "-q", "-r", ".proofbundle")
    _commit(repo, "drop the declaration")
    answer = run_gate(shim, repo, "git push --force origin HEAD:release")
    assert decision(answer) == "ask"
    assert "the push removes the declaration" in reason(answer)


def test_new_evidence_for_a_new_tree_is_no_rules_change(shim, repo):
    """A release changes the code, the evidence file and the declared subject; the rules stay."""
    _write(repo / "src" / "app.py", "print('release 2')\n")
    _commit(repo, "release 2")
    digest = _head_digest(repo)
    signer_key = json.loads((repo / POLICY).read_text())["allowed_issuers"][0]["public_key_b64"]
    signer = generate_signer()
    _write(repo / BUNDLE, emit_bundle(_statement(digest), signer))
    policy = json.loads((repo / POLICY).read_text())
    assert policy["allowed_issuers"][0]["public_key_b64"] == signer_key
    declaration = json.loads((repo / gate.DECLARATION).read_text())
    declaration["evidence"][0]["subject"] = _subject(digest)
    _write(repo / gate.DECLARATION, declaration)
    _commit(repo, "evidence for release 2")
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "deny", "signed by a key the unchanged policy does not pin"
    assert "evidence rules" not in reason(answer)
    # the rules themselves did not change: the base the remote holds and the pushed commit agree.
    targets = gate.resolve_push_targets(str(repo), ["origin", "main"], gate.time.monotonic() + 30)
    assert targets is not None and len(targets) == 1
    base = gate._rules_at(str(repo), targets[0].tracking, gate.time.monotonic() + 30)
    head = gate._rules_at(str(repo), targets[0].source, gate.time.monotonic() + 30)
    assert base == head and base[0] == "declared"


def test_a_push_the_remote_already_holds_adds_no_commits(shim, repo):
    targets = gate.resolve_push_targets(str(repo), ["origin", "main"], gate.time.monotonic() + 30)
    assert targets is not None and len(targets) == 1
    assert gate._newly_reachable(str(repo), targets[0].source, targets[0].tracking,
                                 gate.time.monotonic() + 30) == []
    assert decision(run_gate(shim, repo, "git push origin main")) == "pass"


def test_without_a_remote_tracking_ref_the_range_is_not_measured(shim, repo):
    _git(repo, "remote", "remove", "origin")
    answer = run_gate(shim, repo, "git push")
    assert decision(answer) == "ask"
    assert reason(answer).startswith("NOT MEASURED: ")
    assert "cannot resolve what this push sends" in reason(answer)


def test_adding_a_declaration_to_a_repository_the_remote_knows_is_a_rules_change(shim, tmp_path):
    plain = _plain(tmp_path)
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "plain.git"))
    _git(plain, "remote", "add", "origin", str(tmp_path / "plain.git"))
    _publish(plain)
    digest = _head_digest(plain)
    signer = generate_signer()
    _write(plain / BUNDLE, emit_bundle(_statement(digest), signer))
    _write(plain / POLICY, _pinned_policy(signer))
    _declare(plain, {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": _subject(digest)})
    _commit(plain, "declare evidence")
    answer = run_gate(shim, plain, "git push")
    assert decision(answer) == "ask"
    assert "the push adds the declaration" in reason(answer)


def test_every_skill_and_the_server_carry_the_rule_never_to_weaken(shim):
    for skill in ("verify", "review-receipt", "emit"):
        text = (PLUGIN / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
        assert text.split("\n---\n", 1)[1].count(WEAKEN_RULE) == 1, skill
    lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
    proc = subprocess.run([sys.executable, str(PLUGIN / "server" / "proofbundle_mcp.py")],
                          input="".join(json.dumps(m) + "\n" for m in lines), capture_output=True, text=True,
                          env=shim, timeout=60, check=True)
    assert json.loads(proc.stdout.splitlines()[0])["result"]["instructions"].count(WEAKEN_RULE) == 1
    assert gate.WEAKEN_RULE == WEAKEN_RULE
