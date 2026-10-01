"""Evidence from a test run, bound to the tree it ran on (plugins/proofbundle, DECISIONS.md D23).

`proofbundle_gate.py run-evidence --repo DIR --out FILE [--timeout S] -- COMMAND...` runs a pytest command
on the clean working tree of HEAD and writes the unsigned statement of a green run. These tests run it as
a user runs it, a separate process, with a real inner pytest, and sign the statement with the package's
own `emit` command, as the README says.

Properties checked:
- a green run on a clean tree that leaves the tree as it was writes a statement whose subject is the
  tree digest of HEAD, and whose run record holds the command as run, the program and its sha256, the
  exit code and the counts from the JUnit report, the digests before and after, and no environment value;
- there is no statement when the working tree differs from HEAD before the run (a changed or an
  untracked file; an ignored file is not compared), when the run changes the tree or moves HEAD, when it
  fails, finds no test, times out or writes no report, or when the file already exists;
- signed with `proofbundle emit` and declared, the statement passes the gate and the CI mode; a signed
  run record that does not show a green run on the subject's tree is denied, whoever made it, as is a
  run record signed for another tree;
- a wrong call exits 2 and prints no report.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import proofbundle
from proofbundle.emit import emit_bundle, generate_signer

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

BUNDLE = ".proofbundle/tests.bundle.json"
POLICY = ".proofbundle/policy.json"
PYTEST = [sys.executable, "-m", "pytest", "-q", "tests/"]
REPORT_KEYS = {"outcome", "reason_id", "message", "statement", "run", "gate_version"}
GREEN = """import pytest


def test_one():
    assert 1 + 1 == 2


def test_two():
    assert "a" in "abc"


@pytest.mark.skip(reason="not here")
def test_skipped():
    pass
"""


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def _commit(repo: pathlib.Path) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "c")


def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """A repository whose HEAD holds a small green pytest suite and ignores build/."""
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _write(path / "tests" / "test_green.py", GREEN)
    _write(path / ".gitignore", "build/\n")
    _commit(path)
    return path


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """The environment of the tool and of the inner pytest: this checkout's package, no opt-in to the
    package's own pytest receipt, a planted secret, and a `uv` shim for the gate's verifier."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    package_root = str(pathlib.Path(proofbundle.__file__).resolve().parent.parent)
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("PROOFBUNDLE_", "PYTEST_"))}
    clean["PATH"] = os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["RUN_EVIDENCE_SECRET"] = "s3cr3t-value-7f"
    return clean


def run_evidence(env: dict, repo: pathlib.Path, out: pathlib.Path, *command: str,
                 options: tuple = ()) -> tuple[int, dict | None, str]:
    argv = [sys.executable, str(GATE), "run-evidence", "--repo", str(repo), "--out", str(out), *options, "--",
            *(command or PYTEST)]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=repo.parent, timeout=300, check=False)
    report = json.loads(proc.stdout) if proc.stdout.strip() else None
    if report is not None:
        assert set(report) == REPORT_KEYS
        assert report["message"] in proc.stderr
    return proc.returncode, report, proc.stderr


def refused(env: dict, repo: pathlib.Path, out: pathlib.Path, *command: str, options: tuple = ()) -> dict:
    code, report, stderr = run_evidence(env, repo, out, *command, options=options)
    assert report is not None, stderr
    assert (code, report["outcome"], report["statement"]) == (1, "no_evidence", None), report
    assert report["message"].startswith("NO EVIDENCE: ")
    assert not out.exists(), "no statement may be written without a green run on an unchanged tree"
    return report


# --- a green run ---------------------------------------------------------------------------------------

def test_a_green_run_on_a_clean_tree_writes_a_statement_bound_to_that_tree(env, repo, tmp_path):
    out = tmp_path / "statement.json"
    code, report, stderr = run_evidence(env, repo, out)
    assert code == 0, stderr
    assert (report["outcome"], report["reason_id"], report["statement"]) == ("evidence", "green_run", str(out))
    raw = out.read_bytes()
    statement = json.loads(raw)
    assert set(statement) == {"subject", "run"}
    digest = gate.tree_digest(str(repo), "HEAD")
    assert statement["subject"] == {"algorithm": gate.TREE_ALGORITHM, "digest": digest}
    run = statement["run"]
    assert run == report["run"]
    assert set(run) == gate.RUN_KEYS and run["schema"] == gate.RUN_SCHEMA
    assert run["commit"] == _git(repo, "rev-parse", "HEAD")
    assert run["tree_before"] == run["tree_after"] == digest
    assert run["exit_code"] == 0
    assert run["counts"] == {"tests": 3, "passed": 2, "failed": 0, "errors": 0, "skipped": 1}
    program = shutil.which(sys.executable)
    assert run["program"] == {"path": os.path.abspath(program),
                              "sha256": hashlib.sha256(pathlib.Path(program).read_bytes()).hexdigest()}
    assert run["command"][:len(PYTEST)] == [os.path.abspath(program), *PYTEST[1:]]
    assert run["command"][len(PYTEST):-1] == ["-p", "no:cacheprovider"]
    assert run["command"][-1].startswith("--junitxml=")
    assert gate.run_record_problem(run, digest) is None
    assert b"s3cr3t-value-7f" not in raw and "s3cr3t-value-7f" not in json.dumps(report)
    assert _git(repo, "status", "--porcelain", "--untracked-files=all") == ""


def test_the_selection_of_tests_is_part_of_the_record(env, repo, tmp_path):
    out = tmp_path / "statement.json"
    code, report, _ = run_evidence(env, repo, out, *PYTEST, "-k", "test_one")
    assert code == 0
    assert report["run"]["counts"]["passed"] == 1
    assert ["-k", "test_one"] == report["run"]["command"][len(PYTEST):len(PYTEST) + 2]


def test_an_ignored_file_is_not_compared(env, repo, tmp_path):
    _write(repo / "build" / "artifact.txt", "left over\n")
    code, _, stderr = run_evidence(env, repo, tmp_path / "statement.json")
    assert code == 0, stderr


# --- no evidence ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("change", ["modified", "untracked", "staged"])
def test_a_working_tree_that_differs_from_head_gives_no_evidence(env, repo, tmp_path, change):
    if change == "modified":
        _write(repo / "tests" / "test_green.py", GREEN + "\n# edited\n")
    elif change == "untracked":
        _write(repo / "tests" / "test_new.py", "def test_new():\n    assert True\n")
    else:
        _write(repo / "notes.md", "staged only\n")
        _git(repo, "add", "notes.md")
    report = refused(env, repo, tmp_path / "statement.json")
    assert report["reason_id"] == "tree_not_clean"
    assert report["run"] is None


@pytest.mark.parametrize("body, reason_id", [
    ("import pathlib\n\ndef test_writes():\n    pathlib.Path('written.txt').write_text('x')\n", "tree_changed"),
    ("import pathlib\n\ndef test_edits():\n    p = pathlib.Path('tests/test_green.py')\n"
     "    p.write_text(p.read_text() + '# edited by a test\\n')\n", "tree_changed"),
    ("import subprocess\n\ndef test_commits():\n    subprocess.run(['git', '-c', 'user.name=t', '-c', "
     "'user.email=t@example.org', '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'x'], "
     "check=True)\n", "head_moved"),
], ids=["writes-a-file", "edits-a-tracked-file", "commits"])
def test_a_run_that_changes_the_tree_or_moves_head_gives_no_evidence(env, repo, tmp_path, body, reason_id):
    _write(repo / "tests" / "test_side_effect.py", body)
    _commit(repo)
    report = refused(env, repo, tmp_path / "statement.json")
    assert report["reason_id"] == reason_id


@pytest.mark.parametrize("body, command, reason_id", [
    ("def test_red():\n    assert False\n", (), "run_failed"),
    ("import pytest\n\n@pytest.fixture\ndef broken():\n    raise RuntimeError('x')\n\n"
     "def test_error(broken):\n    pass\n", (), "run_failed"),
    (None, (sys.executable, "-m", "pytest", "-q", "tests/", "-k", "no_such_test"), "run_failed"),
    (None, ("true",), "no_report"),
    (None, ("no-such-program-for-run-evidence",), "no_program"),
], ids=["red-test", "fixture-error", "nothing-selected", "not-pytest", "no-program"])
def test_a_run_that_is_not_green_gives_no_evidence(env, repo, tmp_path, body, command, reason_id):
    if body is not None:
        _write(repo / "tests" / "test_more.py", body)
        _commit(repo)
    report = refused(env, repo, tmp_path / "statement.json", *command)
    assert report["reason_id"] == reason_id
    if reason_id == "run_failed":
        assert gate.run_record_problem(report["run"], report["run"]["tree_before"]) is not None


def test_a_run_that_does_not_finish_in_time_gives_no_evidence(env, repo, tmp_path):
    _write(repo / "tests" / "test_slow.py", "import time\n\ndef test_slow():\n    time.sleep(30)\n")
    _commit(repo)
    report = refused(env, repo, tmp_path / "statement.json", options=("--timeout", "2"))
    assert report["reason_id"] == "timeout"


def test_an_existing_file_is_never_overwritten(env, repo, tmp_path):
    out = tmp_path / "statement.json"
    out.write_text("kept\n", encoding="utf-8")
    code, report, _ = run_evidence(env, repo, out)
    assert (code, report["reason_id"]) == (1, "not_written")
    assert out.read_text(encoding="utf-8") == "kept\n"


def test_outside_a_repository_there_is_no_evidence(env, tmp_path):
    folder = tmp_path / "plain"
    folder.mkdir()
    report = refused(env, folder, tmp_path / "statement.json")
    assert report["reason_id"] == "not_a_work_tree"


FAKE_RUNNER = """import sys
report = next(a for a in sys.argv if a.startswith("--junitxml=")).split("=", 1)[1]
open(report, "w", encoding="utf-8").write(sys.argv[1])
"""


@pytest.mark.parametrize("xml, reason_id", [
    ('<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0"/></testsuites>', "green_run"),
    ('<testsuite tests="2" failures="0" errors="0" skipped="1"/>', "green_run"),
    ('<testsuites><testsuite tests="2" failures="0" errors="1" skipped="0"/></testsuites>', "run_failed"),
    ('<testsuites><testsuite tests="2" failures="1" errors="0" skipped="0"/></testsuites>', "run_failed"),
    ('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="1"/></testsuites>', "run_failed"),
    ('<testsuites><testsuite tests="0" failures="0" errors="0" skipped="0"/></testsuites>', "run_failed"),
    ('<testsuites><testsuite tests="1" failures="0" errors="2" skipped="0"/></testsuites>', "no_report"),
    ('<testsuites><testsuite tests="two" failures="0" errors="0" skipped="0"/></testsuites>', "no_report"),
    ('<testsuites><testsuite tests="-2" failures="0" errors="0" skipped="0"/></testsuites>', "no_report"),
    ('<!DOCTYPE t [<!ENTITY x "2">]><testsuite tests="2" failures="0" errors="0" skipped="0"/>', "no_report"),
    ('<!DOCTYPE testsuite><testsuite tests="2" failures="0" errors="0" skipped="0"/>', "no_report"),
    ('<testsuites/>', "no_report"),
    ('<other tests="2"/>', "no_report"),
    ('not xml', "no_report"),
], ids=["green-testsuites", "green-testsuite", "report-error", "report-failure", "only-skipped", "no-tests", "counts-do-not-add-up", "count-not-a-number", "negative-count", "entity", "doctype", "no-testsuite", "other-root", "not-xml"])
def test_the_counts_come_from_the_report_and_not_from_the_exit_code(env, repo, tmp_path, xml, reason_id):
    """A runner that exits 0 and writes the given report: the record takes the counts from the report."""
    runner = tmp_path / "fake_runner.py"
    runner.write_text(FAKE_RUNNER, encoding="utf-8")
    out = tmp_path / "statement.json"
    code, report, stderr = run_evidence(env, repo, out, sys.executable, str(runner), xml)
    assert report["reason_id"] == reason_id, (report, stderr)
    assert code == (0 if reason_id == "green_run" else 1)
    assert out.exists() is (reason_id == "green_run")


# --- signed and declared -------------------------------------------------------------------------------

def _sign_and_declare(env: dict, repo: pathlib.Path, statement: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """Sign with the package's emit command, as the README says, pin the key and declare the bundle."""
    (repo / ".proofbundle").mkdir(exist_ok=True)
    subprocess.run([sys.executable, "-c", "import sys; from proofbundle.cli import main; sys.exit(main())", "emit",
                    "--payload-file", str(statement), "--out", str(repo / BUNDLE),
                    "--new-key", str(tmp_path / "signing.key")], env=env, check=True, capture_output=True)
    key = json.loads((repo / BUNDLE).read_text())["signature"]["public_key_b64"]
    digest = json.loads(statement.read_text())["subject"]["digest"]
    _write(repo / POLICY, json.dumps({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "run-test",
                                      "allowed_issuers": [{"public_key_b64": key}],
                                      "signature": {"require_expected_signer": True}}))
    _write(repo / gate.DECLARATION, json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": [
        {"kind": "bundle", "path": BUNDLE, "policy": POLICY,
         "subject": {"algorithm": gate.TREE_ALGORITHM, "digest": digest}}]}))
    _commit(repo)


def _evaluate(repo: pathlib.Path, env: dict):
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        return gate.evaluate_repository(str(repo), gate.time.monotonic() + gate.DEADLINE_SECONDS, check_range=False)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_a_signed_green_run_passes_the_gate_and_the_ci_mode(env, repo, tmp_path):
    out = tmp_path / "statement.json"
    assert run_evidence(env, repo, out)[0] == 0
    _sign_and_declare(env, repo, out, tmp_path)
    verdict = _evaluate(repo, env)
    assert (verdict.decision, verdict.reason_id) == ("pass", "verified"), verdict.text()
    proc = subprocess.run([sys.executable, str(GATE), "ci-check", "--repo", str(repo), "--require-declaration", "true"],
                          capture_output=True, text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["outcome"] == "verified"


def test_a_signed_run_for_an_older_tree_is_denied(env, repo, tmp_path):
    out = tmp_path / "statement.json"
    assert run_evidence(env, repo, out)[0] == 0
    _write(repo / "tests" / "test_green.py", GREEN + "\n# changed after the run\n")
    _commit(repo)
    _sign_and_declare(env, repo, out, tmp_path)
    verdict = _evaluate(repo, env)
    assert (verdict.decision, verdict.reason_id) == ("deny", "stale_subject")


def _green_record(repo: pathlib.Path, env: dict, tmp_path: pathlib.Path) -> dict:
    out = tmp_path / "green.json"
    assert run_evidence(env, repo, out)[0] == 0
    return json.loads(out.read_text())


@pytest.mark.parametrize("mutate, why", [
    (lambda r: r.update(exit_code=1), "exit code 1"),
    (lambda r: r.update(exit_code=True), "exit code True"),
    (lambda r: r.update(exit_code=False), "exit code False"),
    (lambda r: r["counts"].update(failed=1, tests=4), "1 failed"),
    (lambda r: r["counts"].update(errors=1, tests=4), "1 errors"),
    (lambda r: r["counts"].update(passed=0, skipped=3), "0 passed"),
    (lambda r: r["counts"].update(tests=9), "of 9 tests"),
    (lambda r: r["counts"].update(passed="2"), "no readable counts"),
    (lambda r: r["counts"].pop("skipped"), "no readable counts"),
    (lambda r: r.update(tree_after="0" * 64), "another tree"),
    (lambda r: r.update(tree_before="0" * 64), "another tree"),
    (lambda r: r.update(schema="proofbundle-plugin/test-run/v0"), "is not a"),
    (lambda r: r.update(note="an extra key"), "is not a"),
    (lambda r: r.pop("report_sha256"), "is not a"),
    (lambda r: r.update(command=[]), "names no command"),
], ids=["exit-code-1", "exit-code-true", "exit-code-false", "a-failure", "an-error", "none-passed", "sum-off", "count-a-string", "count-missing", "tree-after", "tree-before", "old-schema", "extra-key", "missing-key", "no-command"])
def test_a_signed_run_record_that_is_not_green_is_denied(env, repo, tmp_path, mutate, why):
    statement = _green_record(repo, env, tmp_path)
    forged = copy.deepcopy(statement)
    mutate(forged["run"])
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(forged), encoding="utf-8")
    _sign_and_declare(env, repo, path, tmp_path)
    verdict = _evaluate(repo, env)
    assert (verdict.decision, verdict.reason_id) == ("deny", "not_bound"), verdict.text()
    assert why in verdict.text()
    content = (repo / BUNDLE).read_bytes()
    assert gate.signed_subjects("bundle", content) == []


def test_a_run_record_beside_another_subject_binds_nothing(env, repo, tmp_path):
    statement = _green_record(repo, env, tmp_path)
    signer = generate_signer()
    for payload in ({"subject": statement["subject"], "run": statement["run"], "extra": 1},
                    {"run": statement["run"]},
                    {"subject": {"algorithm": gate.TREE_ALGORITHM, "digest": "0" * 64}, "run": statement["run"]}):
        content = json.dumps(emit_bundle(json.dumps(payload).encode(), signer)).encode()
        assert gate.signed_subjects("bundle", content) == [], payload.keys()
    green = json.dumps(emit_bundle(json.dumps(statement).encode(), signer)).encode()
    assert gate.signed_subjects("bundle", green) == [statement["subject"]["digest"]]
    assert gate.signed_run_problem("bundle", green) is None
    plain = json.dumps(emit_bundle(gate.subject_statement(statement["subject"]["digest"]), signer)).encode()
    assert gate.signed_run_problem("bundle", plain) is None
    assert base64.b64decode(json.loads(plain)["payload_b64"]) == gate.subject_statement(statement["subject"]["digest"])


# --- a wrong call --------------------------------------------------------------------------------------

@pytest.mark.parametrize("args", [
    (),
    ("--repo", ".", "--out", "x.json"),
    ("--repo", ".", "--out", "x.json", "--"),
    ("--out", "x.json", "--", "pytest"),
    ("--repo", ".", "--", "pytest"),
    ("--repo", ".", "--out", "x.json", "--timeout", "0", "--", "pytest"),
    ("--repo", ".", "--out", "x.json", "--timeout", "1.5", "--", "pytest"),
    ("--repo", ".", "--out", "x.json", "--shell", "--", "pytest"),
])
def test_a_wrong_call_exits_2_without_a_report(env, repo, args):
    proc = subprocess.run([sys.executable, str(GATE), "run-evidence", *args], capture_output=True, text=True,
                          env=env, cwd=repo, timeout=60, check=False)
    assert (proc.returncode, proc.stdout) == (2, "")
    assert gate.RUN_USAGE in proc.stderr
    assert not (repo / "x.json").exists()


def test_the_readme_and_the_decisions_describe_the_route():
    readme = (PLUGIN / "README.md").read_text(encoding="utf-8")
    assert "run-evidence --repo . --out" in readme
    assert "proofbundle emit --payload-file" in readme
    decisions = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
    assert "## D23. Evidence from the test run itself" in decisions
    assert "Signing stays experimental and runs only on the user's explicit request" in decisions
