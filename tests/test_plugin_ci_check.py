"""The CI mode of the plugin gate and its templates (plugins/proofbundle/ci, DECISIONS.md D22).

`proofbundle_gate.py ci-check --repo DIR --require-declaration true|false` runs the gate's own
evaluation of HEAD. These tests run it as a workflow runs it, a separate process, and replace only `uv`
by a shim that starts the same server with this interpreter and this checkout.

Properties checked:
- exit 0 only when every declared item verified and names the tree of HEAD, or when nothing is declared
  and the workflow input says the repository need not declare;
- a missing declaration where the input requires one fails, also when the declaration was deleted in a
  commit, so deleting it cannot switch the check off;
- every other NOT MEASURED fails, whatever the input says;
- every deny of the gate fails, including a verifier that cannot start and a malformed declaration;
- the check does not read the push range of D20 and needs no remote, and its pass does not claim that
  the evidence rules were compared;
- a wrong call exits 2 and prints no report; a report carries the gate's form on every failure;
- the workflow template takes the requirement as a required boolean input without a default, pins the
  gate to a full commit SHA, checks out the head of a pull request, and calls the CI mode; the
  CODEOWNERS template covers .proofbundle/, the workflows and itself.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

import proofbundle
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
CI = PLUGIN / "ci"
WORKFLOW = CI / "proofbundle-evidence.yml"
CODEOWNERS = CI / "CODEOWNERS.template"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

BUNDLE = ".proofbundle/build.bundle.json"
POLICY = ".proofbundle/policy.json"
REPORT_KEYS = {"outcome", "exit_code", "require_declaration", "repo", "head", "verdict", "reason_id", "digests",
               "message", "gate_version"}
WEAKEN_RULE = ("Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; "
               "obtain the missing evidence instead or ask the user.")


def _git(repo: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


def _commit(repo: pathlib.Path) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "c")


def _write(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")


def _subject(digest: str) -> dict:
    return {"algorithm": gate.TREE_ALGORITHM, "digest": digest}


def _declare(repo: pathlib.Path, *items: dict) -> None:
    _write(repo / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": list(items)})


def _init(path: pathlib.Path) -> pathlib.Path:
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "README.md", "release\n")
    _commit(path)
    return path


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository without a remote whose HEAD declares one bundle over its own tree, signed by the key
    its policy pins."""
    path = _init(tmp_path / "repo")
    digest = gate.tree_digest(str(path), "HEAD")
    signer = generate_signer()
    key = base64.b64encode(signer.public_key().public_bytes_raw()).decode()
    _write(path / BUNDLE, emit_bundle(json.dumps({"subject": _subject(digest)}).encode(), signer))
    _write(path / POLICY, {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "ci-test",
                           "allowed_issuers": [{"public_key_b64": key}], "signature": {"require_expected_signer": True}})
    _declare(path, {"kind": "bundle", "path": BUNDLE, "policy": POLICY, "subject": _subject(digest)})
    _commit(path)
    return path


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server with this interpreter and this checkout's package."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nshift 3\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    return clean


def ci_check(env: dict, cwd: pathlib.Path, *args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run([sys.executable, str(GATE), "ci-check", *args], capture_output=True, text=True,
                          env=env, cwd=cwd, timeout=120, check=False)
    return proc.returncode, (json.loads(proc.stdout) if proc.stdout.strip() else None), proc.stderr


def check(env: dict, repo: pathlib.Path, required: bool) -> tuple[int, dict]:
    code, report, stderr = ci_check(env, repo.parent, "--repo", str(repo),
                                    "--require-declaration", "true" if required else "false")
    assert report is not None, stderr
    assert set(report) == REPORT_KEYS
    assert report["exit_code"] == code
    assert report["require_declaration"] is required
    assert report["gate_version"] == gate.GATE_VERSION
    assert report["message"] in stderr
    if code != 0:
        assert stderr.startswith("proofbundle evidence check FAILED: ")
        for part in ("Evidence: ", ". Failed: ", ". Next step: ", WEAKEN_RULE, " Details: "):
            assert part in report["message"], (part, report["message"])
    else:
        assert stderr.startswith("proofbundle evidence check passed: ")
    return code, report


# --- exit 0 --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("required", [True, False])
def test_evidence_that_verifies_passes(env, repo, required):
    code, report = check(env, repo, required)
    assert (code, report["outcome"], report["verdict"], report["reason_id"]) == (0, "verified", "pass", "verified")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    assert report["head"] == head
    assert report["digests"] and all(d.startswith(".proofbundle/") for d in report["digests"])
    assert "not that the recorded values are true" in report["message"]


def test_nothing_declared_passes_only_where_no_declaration_is_required(env, tmp_path):
    plain = _init(tmp_path / "plain")
    code, report = check(env, plain, False)
    assert (code, report["outcome"], report["reason_id"]) == (0, "not_required", "nothing_declared")
    assert report["message"].startswith("NOT MEASURED: ")
    assert "Nothing was verified." in report["message"]
    code, report = check(env, plain, True)
    assert (code, report["outcome"], report["verdict"], report["reason_id"]) == (
        1, "declaration_required", "deny", "declaration_required")


# --- exit 1 --------------------------------------------------------------------------------------------

def test_deleting_the_declaration_fails_where_one_is_required(env, repo):
    _git(repo, "rm", "-q", "-r", ".proofbundle")
    _commit(repo)
    code, report = check(env, repo, True)
    assert (code, report["outcome"]) == (1, "declaration_required")
    assert gate.DECLARATION in report["message"]


@pytest.mark.parametrize("required", [True, False])
def test_every_other_not_measured_fails_whatever_the_input_says(env, repo, tmp_path, required):
    _declare(repo)
    _commit(repo)
    code, report = check(env, repo, required)
    assert (code, report["outcome"], report["reason_id"]) == (1, "not_measured", "empty_declaration")

    uncommitted = _init(tmp_path / f"uncommitted-{required}")
    _declare(uncommitted, {"kind": "bundle", "path": BUNDLE})
    code, report = check(env, uncommitted, required)
    assert (code, report["outcome"], report["reason_id"]) == (1, "not_measured", "declaration_uncommitted")

    nothing = tmp_path / f"not-a-repository-{required}"
    nothing.mkdir()
    code, report = check(env, nothing, required)
    assert (code, report["outcome"], report["reason_id"]) == (1, "not_measured", "not_a_work_tree")


def test_tampered_evidence_fails(env, repo):
    bundle = json.loads((repo / BUNDLE).read_text())
    raw = bytearray(base64.b64decode(bundle["payload_b64"]))
    raw[0] ^= 1
    bundle["payload_b64"] = base64.b64encode(bytes(raw)).decode()
    _write(repo / BUNDLE, bundle)
    _commit(repo)
    code, report = check(env, repo, False)
    assert (code, report["outcome"], report["verdict"], report["reason_id"]) == (
        1, "failed", "deny", "verification_failed")


def test_evidence_for_another_tree_fails(env, repo):
    _write(repo / "src" / "app.py", "print('changed')\n")
    _commit(repo)
    code, report = check(env, repo, False)
    assert (code, report["outcome"], report["reason_id"]) == (1, "failed", "stale_subject")


def test_a_malformed_declaration_and_a_verifier_that_cannot_start_fail(env, repo, tmp_path):
    no_uv = tmp_path / "no-uv"
    no_uv.mkdir()
    (no_uv / "git").symlink_to(shutil.which("git"))
    code, report = check(dict(env, PATH=str(no_uv)), repo, False)
    assert (code, report["outcome"], report["reason_id"]) == (1, "failed", "gate_error")
    assert "uv is not on PATH" in report["message"]

    _write(repo / gate.DECLARATION, "{not json")
    _commit(repo)
    code, report = check(env, repo, False)
    assert (code, report["outcome"], report["reason_id"]) == (1, "failed", "gate_error")


# --- the push range is not read ------------------------------------------------------------------------

def test_the_check_does_not_read_the_push_range(env, repo, tmp_path):
    """Before a push the gate would ask here: the remote holds a state without the declaration, so the
    push adds it (D20). In CI that review is the code owners' part, and the check passes on evidence."""
    _git(tmp_path, "init", "-q", "--bare", str(tmp_path / "remote.git"))
    _git(repo, "remote", "add", "origin", str(tmp_path / "remote.git"))
    _git(repo, "push", "-q", "origin", "HEAD~1:refs/heads/main")
    _git(repo, "fetch", "-q", "origin")
    verdict = gate.evaluate_repository(str(repo), gate.time.monotonic() + gate.DEADLINE_SECONDS)
    assert (verdict.decision, verdict.reason_id) == ("ask", "rules_changed")
    code, report = check(env, repo, True)
    assert (code, report["outcome"]) == (0, "verified")
    assert "not compared with any earlier state" in report["message"]
    assert "leaves the evidence rules as the remote holds them" not in report["message"]


# --- a wrong call --------------------------------------------------------------------------------------

@pytest.mark.parametrize("args", [
    (),
    ("--repo", "."),
    ("--require-declaration", "true"),
    ("--repo", ".", "--require-declaration", "yes"),
    ("--repo", ".", "--require-declaration", "True"),
    ("--repo", ".", "--require-declaration", ""),
    ("--repo", ".", "--require-declaration", "true", "--rev", "HEAD"),
    ("--repo", ".", "--require-declaration"),
])
def test_a_wrong_call_exits_2_without_a_report(env, repo, args):
    code, report, stderr = ci_check(env, repo, *args)
    assert (code, report) == (2, None)
    assert gate.CI_USAGE in stderr


# --- the templates -------------------------------------------------------------------------------------

def test_the_workflow_template_takes_the_requirement_from_its_caller():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    on = workflow.get("on", workflow.get(True))
    assert set(on) == {"workflow_call"}
    inputs = on["workflow_call"]["inputs"]
    assert set(inputs) == {"require-declaration", "proofbundle-ref"}
    assert inputs["require-declaration"]["type"] == "boolean"
    assert inputs["require-declaration"]["required"] is True
    assert "default" not in inputs["require-declaration"]
    assert inputs["proofbundle-ref"]["required"] is True and "default" not in inputs["proofbundle-ref"]
    assert workflow["permissions"] == {"contents": "read"}
    (job,) = workflow["jobs"].values()
    assert job["permissions"] == {"contents": "read"}
    steps = job["steps"]
    uses = [s["uses"] for s in steps if "uses" in s]
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses
    checkouts = [s["with"] for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert all(c["persist-credentials"] is False for c in checkouts)
    (checked,) = [c for c in checkouts if c.get("path") == "checked"]
    assert checked["ref"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    (gate_checkout,) = [c for c in checkouts if c.get("repository") == "b7n0de/proofbundle"]
    assert gate_checkout["ref"] == "${{ inputs.proofbundle-ref }}"
    runs = [s for s in steps if "run" in s]
    pin = runs[0]
    assert pin["env"] == {"GATE_REF": "${{ inputs.proofbundle-ref }}"}
    assert "^[0-9a-f]{40}$" in pin["run"] and "exit 1" in pin["run"]
    last = runs[-1]
    assert last["env"] == {"REQUIRE_DECLARATION": "${{ inputs.require-declaration }}"}
    assert "gate/plugins/proofbundle/hooks/proofbundle_gate.py ci-check" in last["run"]
    assert '--repo checked --require-declaration "$REQUIRE_DECLARATION"' in last["run"]
    assert "${{" not in "".join(s["run"] for s in runs), "inputs reach the shell through env only"


def test_the_workflow_template_calls_the_ci_mode_with_both_options():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_call:" in text
    assert text.count("ci-check") == 1
    assert "--require-declaration" in text and "--repo checked" in text


def test_the_codeowners_template_covers_the_rules_the_workflows_and_itself():
    lines = [line.split() for line in CODEOWNERS.read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    paths = {parts[0] for parts in lines}
    assert all(len(parts) >= 2 for parts in lines)
    assert {"/.proofbundle/", "/.github/workflows/proofbundle-evidence.yml", "/.github/CODEOWNERS"} <= paths


def test_the_ci_readme_names_every_outcome_and_exit_code():
    text = (CI / "README.md").read_text(encoding="utf-8")
    for outcome in ("verified", "not_required", "declaration_required", "not_measured", "failed"):
        assert f"`{outcome}`" in text, outcome
    assert "D22" in (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
