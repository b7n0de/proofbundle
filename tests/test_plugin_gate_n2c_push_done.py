"""Owner choice N2 C (2026-10-08): a push requires the done check at the pushed commit, at Level 1 and Level 2.

The done check of D26 and D28 runs at the end of a session for the working state. A push now runs the same check
at every commit it sends as a tip, for the tree the push sends: the declaration, the done policy and the order come
from that commit, its tree read from git stands in for the working state, and the receipts are read from the
working tree, where the tests left them. Level 1 is the PreToolUse gate under Claude Code (`git push`, `gh pr
create`); Level 2 is git's pre-push hook (D24), which carries the push check under Codex too (Karte 5 D), where
Level 1 only warns (Karte 5 A).

Counter-probes at both levels: no receipt, a foreign key, a receipt for another commit, a manipulated receipt, red
tests, and a valid receipt. Each receipt is signed with a key made in the test; the verifier is the plugin's own
server, started through a `uv` shim with this interpreter. Red against 336500ba, where such a push was NOT MEASURED
without a decision (`done_only`) and the pre-push hook let it through.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

import proofbundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

RECEIPT = gate.DONE_RECEIPT
POLICY = gate.DONE_POLICY
CASES = ("valid", "missing", "foreign", "stale", "manipulated", "red")
#: The reason each counter-probe denies with; the valid receipt passes.
REASONS = {"missing": "no_receipt", "foreign": "verification_failed", "stale": "stale_receipt",
           "manipulated": "verification_failed", "red": "not_done"}


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean["CLAUDE_PLUGIN_DATA"] = clean["PLUGIN_DATA"] = str(tmp_path / "logs")
    return clean


def _git(repo: pathlib.Path, *args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=check, capture_output=True, text=True,
                          env=env, timeout=120)


#: Fetch rules that record the remote's refs under refs/tags/ and refs/refs/ in local namespaces of their own. With
#: the pattern rule for refs/heads/ they record every ref git push can also match for a full branch destination
#: (refs/heads/refs/heads/<x>, refs/tags/refs/heads/<x>, refs/refs/heads/<x>), which the gate needs to evidence that
#: the destination resolves to the branch alone (review round 8 of 2026-10-10, R8-2). A repository without them leaves
#: every Level 1 push NOT MEASURED; the tests of that are in test_plugin_review_fix8_r2_push_destination.py.
RECORDING_RULES = ("+refs/tags/*:refs/recorded/{remote}/tags/*", "+refs/refs/*:refs/recorded/{remote}/refs/*")


def record_remote_refs(repo: pathlib.Path, remote: str = "origin") -> None:
    """Give `remote` the fetch rules of RECORDING_RULES beside its own."""
    for rule in RECORDING_RULES:
        _git(repo, "config", "--add", f"remote.{remote}.fetch", rule.format(remote=remote))


def _rev(repo: pathlib.Path, rev: str) -> str:
    return _git(repo, "rev-parse", rev).stdout.strip()


def _write(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _policy(signer) -> dict:
    public = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
    return {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "done-test",
            "allowed_issuers": [{"public_key_b64": public}], "signature": {"require_expected_signer": True}}


def _commit(repo: pathlib.Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)


def _receipt(repo: pathlib.Path, signer, *, failed: int = 0) -> pathlib.Path:
    """A pytest receipt as the package's plugin writes it, for the working state now."""
    state = gate.working_state(str(repo), time.monotonic() + 60)
    clean = state["worktree"] == state["tree"]
    git = {"git_hash": state["commit"], "git_tree": state["tree"], "git_clean": clean}
    if not clean:
        git["git_worktree_tree"] = state["worktree"]
    passed = 3
    provenance = {"harness": "pytest", "exit_status": 1 if failed else 0, "tests_ran": passed + failed,
                  "tests_passed": passed, "n_passed": passed, "n_failed": failed, "n_error": 0, "n_skipped": 0,
                  "n_xfailed": 0, "n_xpassed": 0, **git}
    score = format(passed / (passed + failed), ".6f").rstrip("0").rstrip(".")
    claim, _ = build_eval_claim(suite="pytest", suite_version="9", metric="pass_rate", comparator=">=",
                                threshold="1", score=score, n=passed + failed, model_id=f"gitCommit:{state['commit']}",
                                dataset_id="pytest-suite", issuer="", timestamp="2026-10-08T12:00:00+00:00",
                                provenance=provenance)
    _write(repo / RECEIPT, emit_eval_receipt(claim, signer))
    return repo / RECEIPT


class Repo:
    """A repository whose main tracks origin/main at the commit that declares the done check, then one commit of
    work that the push sends."""

    def __init__(self, tmp_path: pathlib.Path, evidence: bool = False):
        self.signer = generate_signer()
        self.path = path = tmp_path / "r"
        path.mkdir()
        _git(path, "init", "-q", "-b", "main")
        _write(path / "src" / "module.py", "VALUE = 1\n")
        _write(path / ".proofbundle" / ".gitignore", "proofbundle_pytest_receipt.json\n")
        _write(path / POLICY, _policy(self.signer))
        self.evidence_signer = generate_signer() if evidence else None
        self._declare([])
        _commit(path, "declare the done check")
        if evidence:
            self.sign_evidence()
            _commit(path, "evidence for the declaring commit")
        subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "remote.git")], check=True, timeout=60)
        _git(path, "remote", "add", "origin", str(tmp_path / "remote.git"))
        record_remote_refs(path)
        _git(path, "push", "-q", "-u", "origin", "main")
        _write(path / "src" / "module.py", "VALUE = 2\n")
        _commit(path, "work")
        if evidence:  # the evidence names the tree of the work commit itself (the digest leaves .proofbundle/ out)
            self.sign_evidence()
            _git(path, "add", "-A")
            _git(path, "commit", "-q", "--amend", "--no-edit")

    def _declare(self, items: list) -> None:
        _write(self.path / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": items,
                                              "done": {"receipt": RECEIPT, "policy": POLICY}})

    def sign_evidence(self) -> None:
        subject = {"algorithm": gate.TREE_ALGORITHM, "digest": gate.tree_digest(str(self.path), "HEAD")}
        _write(self.path / ".proofbundle" / "b.json", emit_bundle(json.dumps({"subject": subject}).encode(),
                                                                  self.evidence_signer))
        _write(self.path / ".proofbundle" / "policy.json", _policy(self.evidence_signer))
        self._declare([{"kind": "bundle", "path": ".proofbundle/b.json", "policy": ".proofbundle/policy.json",
                        "subject": subject}])

    def make(self, case: str) -> None:
        """The receipt of one counter-probe, for the commit the push sends."""
        if case == "missing":
            return
        if case == "foreign":
            _receipt(self.path, generate_signer())
        elif case == "red":
            _receipt(self.path, self.signer, failed=1)
        else:
            _receipt(self.path, self.signer)
        if case == "stale":   # the receipt names this commit; one more commit is what the push sends
            _write(self.path / "src" / "module.py", "VALUE = 3\n")
            _commit(self.path, "more work after the tests")
        if case == "manipulated":
            bundle = json.loads((self.path / RECEIPT).read_text(encoding="utf-8"))
            claim = json.loads(base64.b64decode(bundle["payload_b64"]))
            claim["provenance"]["tests_passed"] += 1
            bundle["payload_b64"] = base64.b64encode(json.dumps(claim).encode()).decode()
            _write(self.path / RECEIPT, bundle)


def _level1(env: dict, repo: pathlib.Path, host: str = "claude",
            command: str = "git push origin main") -> tuple[dict, dict]:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}})
    proc = subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    entry = json.loads((pathlib.Path(env["PLUGIN_DATA"]) / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
    return json.loads(proc.stdout), entry


def _level2(env: dict, repo: pathlib.Path) -> subprocess.CompletedProcess:
    """The pre-push hook as git starts it: in the repository, with git's ref line on stdin."""
    line = f"refs/heads/main {_rev(repo, 'HEAD')} refs/heads/main {_rev(repo, 'origin/main')}\n"
    return subprocess.run([sys.executable, "-I", str(GATE), "pre-push", "origin", "remote.git"], input=line,
                          capture_output=True, text=True, cwd=str(repo), env=env, timeout=180, check=False)


@pytest.mark.parametrize("case", CASES)
def test_level_1_a_push_needs_the_done_check_at_the_pushed_commit(env, tmp_path, case):
    r = Repo(tmp_path)
    r.make(case)
    answer, entry = _level1(env, r.path)
    decision = answer["hookSpecificOutput"].get("permissionDecision")
    if case == "valid":
        assert decision is None, answer
        assert (entry["verdict"], entry["reason_ids"]) == ("pass", ["done"]), entry
        assert f"The done check passed at the pushed commit {_rev(r.path, 'HEAD')[:12]}" in answer["systemMessage"]
    else:
        assert decision == "deny", (case, answer)
        assert entry["reason_ids"] == [REASONS[case]], (case, entry)
        assert "the push needs the done check at the pushed commit" in answer["systemMessage"]


@pytest.mark.parametrize("case", CASES)
def test_level_2_the_pre_push_hook_needs_the_done_check_at_the_pushed_commit(env, tmp_path, case):
    r = Repo(tmp_path)
    r.make(case)
    proc = _level2(env, r.path)
    if case == "valid":
        assert proc.returncode == 0, proc.stderr
        assert "The done check passed at the pushed commit" in proc.stderr
    else:
        assert proc.returncode == 1, (case, proc.stderr)
        assert "the push needs the done check at the pushed commit" in proc.stderr, proc.stderr


@pytest.mark.parametrize("case", ["valid", "missing", "stale"])
def test_level_2_through_git_itself_with_the_hook_in_a_local_hooks_path(env, tmp_path, case):
    """Karte 5 D: git starts the pre-push hook in the push's own repository. The hook is installed for this test only,
    through a local core.hooksPath (how it is installed outside tests is the open owner card D24B)."""
    r = Repo(tmp_path)
    r.make(case)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "pre-push").write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{GATE}" pre-push "$@"\n',
                                    encoding="utf-8")
    (hooks / "pre-push").chmod(0o755)
    _git(r.path, "config", "core.hooksPath", str(hooks))
    before = _git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip()
    proc = _git(r.path, "push", "origin", "main", env=env, check=False)
    after = _git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip()
    if case == "valid":
        assert proc.returncode == 0 and after == _rev(r.path, "HEAD"), proc.stderr
    else:
        assert proc.returncode != 0 and after == before, (case, proc.stderr)
        assert REASONS[case] in proc.stderr or "the push needs the done check" in proc.stderr


def test_the_pushed_tree_counts_not_the_working_tree(env, tmp_path):
    """A receipt for the clean commit, then an uncommitted change: the end of the session is not done (the working
    state differs), and the push of the commit is, because the push sends the commit's tree."""
    r = Repo(tmp_path)
    r.make("valid")
    _write(r.path / "src" / "module.py", "VALUE = 99\n")   # not committed
    assert gate.done_evaluation(str(r.path), time.monotonic() + 60)["verdict"].reason_id == "stale_receipt"
    answer, entry = _level1(env, r.path)
    assert "permissionDecision" not in answer["hookSpecificOutput"], answer
    assert entry["reason_ids"] == ["done"]


def test_a_receipt_of_an_uncommitted_state_does_not_pass_the_push(env, tmp_path):
    """The tests ran on a working state with a change that was never committed: the receipt names HEAD's commit and
    tree, but the tree it ran on is not the tree the push sends."""
    r = Repo(tmp_path)
    _write(r.path / "src" / "module.py", "VALUE = 99\n")
    _receipt(r.path, r.signer)
    answer, entry = _level1(env, r.path)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert entry["reason_ids"] == ["stale_receipt"]
    assert "the tree the push sends is tree" in answer["systemMessage"]


def test_gh_pr_create_needs_the_done_check_at_the_branch_it_publishes(env, tmp_path):
    r = Repo(tmp_path)
    answer, entry = _level1(env, r.path, command="gh pr create --fill")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert entry["reason_ids"] == ["no_receipt"]


def test_evidence_and_done_both_have_to_pass(env, tmp_path):
    r = Repo(tmp_path, evidence=True)
    answer, entry = _level1(env, r.path)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert entry["reason_ids"] == ["no_receipt"]
    r.make("valid")
    answer, entry = _level1(env, r.path)
    assert "permissionDecision" not in answer["hookSpecificOutput"], answer
    assert entry["reason_ids"] == ["verified"]
    assert "declared items verified" in answer["systemMessage"]
    assert "The done check passed at the pushed commit" in answer["systemMessage"]


def test_under_codex_level_1_warns_and_level_2_carries_the_done_check(env, tmp_path):
    """Karte 5 A with D: the Codex PreToolUse answer is the unbound-context warning, whatever the receipts; the
    pre-push hook git starts in the push's repository denies the same push without a receipt."""
    r = Repo(tmp_path)
    answer, entry = _level1(env, r.path, host="codex")
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    assert (entry["verdict"], entry["reason_ids"]) == ("warn", ["codex_context_unbound"])
    proc = _level2(env, r.path)
    assert proc.returncode == 1 and "no test run left a receipt" in proc.stderr, proc.stderr


def test_a_pushed_commit_without_a_done_check_gets_none(env, tmp_path):
    """The done check applies where the pushed commit declares one: a repository whose declaration has no done
    section keeps its push answer (nothing declared, inactive)."""
    path = tmp_path / "plain"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": []})
    _commit(path, "a declaration without a done check")
    subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "remote.git")], check=True, timeout=60)
    _git(path, "remote", "add", "origin", str(tmp_path / "remote.git"))
    _git(path, "push", "-q", "-u", "origin", "main")
    verdict = gate.done_evaluation(str(path), time.monotonic() + 60, at_commit=_rev(path, "HEAD"))["verdict"]
    assert (verdict.decision, verdict.reason_id) == ("inactive", "no_done_check")
    assert "at the pushed commit" in verdict.detail


def test_an_unresolved_push_with_a_failed_done_check_is_a_deny(env, tmp_path):
    """Befund 1 of review Runde 6 holds for the done check too: where the target comparison is NOT MEASURED (a branch
    this repository does not track), the commit the push sends is still known, and a failed done check there is a
    proven failure, so the push is denied rather than asked."""
    r = Repo(tmp_path)
    answer, entry = _level1(env, r.path, command="git push origin main:refs/heads/other")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert entry["reason_ids"] == ["no_receipt"]
    assert "Separately, the comparison with the target was NOT MEASURED" in answer["systemMessage"]
    r.make("valid")
    answer, entry = _level1(env, r.path, command="git push origin main:refs/heads/other")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer   # a pass cannot heal the comparison
    assert entry["reason_ids"] == ["push_not_measured"]


def test_level_2_a_new_remote_ref_with_a_failed_done_check_is_a_deny(env, tmp_path):
    r = Repo(tmp_path)
    line = f"refs/heads/main {_rev(r.path, 'HEAD')} refs/heads/other {'0' * 40}\n"
    proc = subprocess.run([sys.executable, "-I", str(GATE), "pre-push", "origin", "remote.git"], input=line,
                          capture_output=True, text=True, cwd=str(r.path), env=env, timeout=180, check=False)
    assert proc.returncode == 1 and "no test run left a receipt" in proc.stderr, proc.stderr
    assert "Separately, the comparison with the target was NOT MEASURED" in proc.stderr


def test_the_check_is_at_the_pushed_commit_not_at_head(env, tmp_path):
    """A push of another branch (`other:main`): a receipt for HEAD does not pass it, and the next step names the
    commit to check out; a receipt for the pushed commit does, while HEAD is elsewhere."""
    r = Repo(tmp_path)
    _git(r.path, "switch", "-q", "-c", "other")
    _write(r.path / "src" / "module.py", "VALUE = 5\n")
    _commit(r.path, "other work")
    pushed = _rev(r.path, "HEAD")
    _git(r.path, "switch", "-q", "main")
    _receipt(r.path, r.signer)                       # a valid receipt for HEAD, which is main
    answer, entry = _level1(env, r.path, command="git push origin other:refs/heads/main")   # in full (R8-2)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert entry["reason_ids"] == ["stale_receipt"]
    assert f"the pushed commit {pushed[:12]}" in answer["systemMessage"]
    assert f"git checkout {pushed[:12]} &&" in answer["systemMessage"]
    _git(r.path, "switch", "-q", "other")
    _receipt(r.path, r.signer)                       # now a receipt for the pushed commit
    _git(r.path, "switch", "-q", "main")
    answer, entry = _level1(env, r.path, command="git push origin other:refs/heads/main")
    assert "permissionDecision" not in answer["hookSpecificOutput"], answer
    assert entry["reason_ids"] == ["done"]
