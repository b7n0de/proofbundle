"""Release-ceremony INTEGRATION test (makellose-500 round-14 gate fix, option C).

The pre-tag receipt binds ``subject_tree_digest``. It once bound the FULL ``HEAD^{tree}``, which
INCLUDES the receipt once committed -- committing the attestation changed the tree it bound, so the gate
rejected every committed receipt (circular, proven 2026-08-27). Round 13 (option B) bound
``HEAD:src/proofbundle`` and fixed the circularity, but the deep-gate refuted it: binding only the
package subtree unbinds ``pyproject.toml``, so a dependency injected AFTER signing shipped past the gate.
Round 14 (option C, owner-GO) binds the ``HEAD`` top-level tree MINUS ``audit_artifacts/`` -- src +
pyproject (deps) + scripts (the verifier) + every release surface, with the receipt's own directory
outside so the binding stays committable. This test proves the REAL produce -> commit -> verify flow
end-to-end (subprocess, real scripts, real git): a committed receipt verifies, a post-signing dependency
injection is REJECTED (the refuted-option-B exploit), and a src change is REJECTED -- the exact
integration the harness's fixed-constant unit tests never exercised.
"""
import base64
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
SRC = REPO / "src"


def _run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=env)


def _git(args, cwd):
    r = _run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd)
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r


def test_committed_receipt_verifies_and_src_change_is_rejected(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    (repo / "src" / "proofbundle").mkdir(parents=True)
    (repo / "audit_artifacts" / "500").mkdir(parents=True)
    for s in ("pre_tag_receipt.py", "pre_tag_audit_gate.py", "pre_tag_receipt_lib.py"):
        (repo / "scripts" / s).write_bytes((SCRIPTS / s).read_bytes())
    (repo / "src" / "proofbundle" / "__init__.py").write_text("__version__ = '5.0.0'\n")
    (repo / "src" / "proofbundle" / "signature.py").write_bytes(
        (SRC / "proofbundle" / "signature.py").read_bytes())
    (repo / "pyproject.toml").write_text('[project]\nname = "proofbundle"\nversion = "5.0.0"\n')
    (repo / "CHANGELOG.md").write_text(
        "## [5.0.0] - 2026-08-25\naudit passed, pre-tag adversarial audit ran\n")
    (repo / "audit_artifacts" / "500" / "PRE_REGISTRATION.md").write_text(
        "pre-tag adversarial audit RUN, PASS\n")

    priv = Ed25519PrivateKey.generate()
    (repo / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
        base64.b64encode(priv.public_key().public_bytes_raw()).decode() + "\n")
    (repo / "_privkey.b64").write_text(base64.b64encode(priv.private_bytes_raw()).decode())
    (repo / "_audit.txt").write_text("audit ran\n")

    _git(["init", "-q"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "candidate"], repo)

    env = {"PYTHONPATH": f"{repo}/src:{repo}/scripts", "PATH": "/usr/bin:/bin"}

    r = _run([sys.executable, "scripts/pre_tag_receipt.py", "--repo", ".", "--version", "5.0.0",
              "--audit-command", "c", "--audit-exit", "0", "--audit-output-file", "_audit.txt",
              "--runner-identity", "test", "--produced-at", "2026-08-27T06:00:00Z",
              "--privkey-file", "_privkey.b64"], repo, env)
    assert r.returncode == 0, f"receipt production failed: {r.stderr}"
    _git(["add", "audit_artifacts/500/"], repo)
    _git(["commit", "-q", "-m", "receipt"], repo)

    # THE FIX: a committed receipt must now VERIFY (before the fix this was REJECT, tree mismatch).
    g = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
              "--strict"], repo, env)
    assert g.returncode == 0, f"committed receipt must verify after option-B fix: {g.stdout}\n{g.stderr}"
    assert "receipt-verified=True" in g.stdout

    # OPTION C regression (the deep-gate refuted src-only option B here): a dependency injection into
    # pyproject.toml AFTER signing must be REJECTED -- src/proofbundle is unchanged, but pyproject is
    # now inside the bound subject, so the backdoored dep can no longer ship past the gate.
    pj = repo / "pyproject.toml"
    pj.write_text(pj.read_text().replace('version = "5.0.0"',
                  'version = "5.0.0"\ndependencies = ["evil-backdoor-pkg==6.6.6"]', 1))
    _git(["add", "pyproject.toml"], repo)
    _git(["commit", "-q", "-m", "inject dep"], repo)
    gdep = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
                 "--strict"], repo, env)
    assert gdep.returncode == 1, f"a pyproject dep injection after signing must be REJECTED (option C), got {gdep.returncode}: {gdep.stdout}"
    assert "does not bind THIS tree" in gdep.stdout or "receipt-verified=False" in gdep.stdout

    # NOT WEAKENED: a src/proofbundle change after signing must be REJECTED.
    (repo / "src" / "proofbundle" / "__init__.py").write_text("__version__ = '5.0.0'\n# tampered\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "tamper src"], repo)
    g2 = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
               "--strict"], repo, env)
    assert g2.returncode == 1, f"a src change after signing must be REJECTED, got exit {g2.returncode}: {g2.stdout}"
    assert "does not bind THIS tree" in g2.stdout or "receipt-verified=False" in g2.stdout
