"""The third-party verifier of the pre-tag receipt, driven end to end through real git and the real scripts.

WHY THIS FILE EXISTS (P19, F2 -- owner decision 2026-09-15, option A). F1 measured that a reader who
installs from PyPI never receives the audit receipt, and that the only command RELEASE.md offers a
third party (`gh attestation verify`) covers the build provenance, not the audit verdict. The
verifier under test is the path for a reader who holds a clone: read receipt, anchor and gate from
the COMMIT, take the tree digest over the checked-out HEAD, verify against the pinned key.

THREE CONTRACTS FROM THE ORDER, each planted as a defect that must be refused, plus the positive
control without which the three would also pass against a verifier that refuses everything, plus
two properties that fall out of reading from the commit rather than the working tree.

Every case runs the real ``scripts/verify_pre_tag_receipt.py`` as a subprocess against a real git
repository built in a temporary directory, the way ``tests/test_pre_tag_receipt_commit_flow.py``
does for the gate. A test that reconstructed the verifier's logic would measure the reconstruction.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
SRC = REPO / "src"
VERIFIER = "verify_pre_tag_receipt.py"
_SCRIPTS_NEEDED = ("pre_tag_receipt.py", "pre_tag_audit_gate.py", "pre_tag_receipt_lib.py",
                   "sign_readiness_artifact.py", VERIFIER)


def _run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=env)


def _git(args, cwd):
    r = _run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd)
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r.stdout.strip()


def _head(repo) -> str:
    return _git(["rev-parse", "HEAD"], repo)


@pytest.fixture
def welt(tmp_path):
    """A candidate repository with a committed trust anchor and a committed receipt for 5.0.0.

    Returns (repo, env, priv, candidate_commit, receipt_commit). The receipt commit is the commit a
    third party would be pointed at by the attestation.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    for s in _SCRIPTS_NEEDED:
        if not (SCRIPTS / s).is_file():
            pytest.skip(f"scripts/{s} is not here (sdist without repo context)")
    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    (repo / "audit_artifacts" / "500").mkdir(parents=True)
    for s in _SCRIPTS_NEEDED:
        (repo / "scripts" / s).write_bytes((SCRIPTS / s).read_bytes())
    # The whole package is copied, not a typed list of two files -- the commit-flow test learned
    # that lesson when a stricter decoder import made a typed minimal tree fall over.
    shutil.copytree(SRC / "proofbundle", repo / "src" / "proofbundle",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (repo / "src" / "proofbundle" / "__init__.py").write_text("__version__ = '5.0.0'\n")
    (repo / "pyproject.toml").write_text('[project]\nname = "proofbundle"\nversion = "5.0.0"\n')
    (repo / "CHANGELOG.md").write_text("## [5.0.0] - 2026-08-25\naudit passed\n")
    (repo / "_audit.txt").write_text("audit ran\n")
    priv = Ed25519PrivateKey.generate()
    (repo / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
        base64.b64encode(priv.public_key().public_bytes_raw()).decode() + "\n")
    (repo / "_privkey.b64").write_text(base64.b64encode(priv.private_bytes_raw()).decode())
    # The real repository ignores bytecode; without this line the producer's own __pycache__
    # would show up as an untracked file under scripts/ and the verifier would refuse its own
    # positive control -- which is exactly the refusal it is built for, so the fixture must be
    # faithful to the real tree here rather than the verifier being lenient.
    (repo / ".gitignore").write_text("__pycache__/\n")
    _git(["init", "-q"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "candidate"], repo)
    kandidat = _head(repo)
    env = {"PYTHONPATH": f"{repo}/src:{repo}/scripts", "PATH": "/usr/bin:/bin",
           "PB_INLINE_SIGNING": "1"}
    # THE AUDIT OUTPUT IS TOUCHED LAST, immediately before the run that consumes it.
    #
    # It used to be written near the top of this fixture, before `.gitignore` and before the
    # commit. Since 2026-09-20 the receipt tool refuses when a tracked path is NEWER than the audit
    # output, because an audit cannot have read bytes that did not exist yet — and `.gitignore` was
    # exactly that. The failure was not stable: two files written in the same instant can compare
    # either way depending on timestamp resolution, so the error moved between cases from run to
    # run. Writing it here makes the fixture describe the ceremony it is standing in for, and it
    # fixes the ORDER for every case in this file rather than for the one that happened to fail.
    #
    # ITS TIME IS TOUCHED, NOT ITS CONTENT, and the first attempt got that wrong: moving the write
    # down here took the file out of `git add -A` above, so it became UNTRACKED and every case in
    # the file errored with `?? _audit.txt`. The original position was deliberate — this file is
    # TRACKED. `os.utime` leaves the bytes alone, so the tree stays clean, and only the ordering
    # the receipt tool reads is corrected.
    os.utime(repo / "_audit.txt", None)
    r = _run([sys.executable, "scripts/pre_tag_receipt.py", "--repo", ".", "--version", "5.0.0",
              "--audit-command", "c", "--audit-exit", "0", "--audit-output-file", "_audit.txt",
              "--runner-identity", "test", "--produced-at", "2026-08-27T06:00:00Z",
              "--privkey-file", "_privkey.b64"], repo, env)
    assert r.returncode == 0, f"receipt production failed: {r.stderr}"
    _git(["add", "audit_artifacts/500/"], repo)
    _git(["commit", "-q", "-m", "receipt"], repo)
    return repo, env, priv, kandidat, _head(repo)


def _verify(repo, env, commit, version="5.0.0"):
    r = _run([sys.executable, "scripts/" + VERIFIER, "--repo", ".", "--commit", commit,
              "--version", version, "--json"], repo, env)
    try:
        res = json.loads(r.stdout)
    except ValueError:
        res = None
    return r.returncode, res, r.stdout + r.stderr


def _receipt_path(repo):
    """The receipt the producer wrote. Its NAME is not fixed (the producer's default and the
    owner-assembled receipts differ), which is why gate and verifier read the whole folder."""
    ordner = repo / "audit_artifacts" / "500"
    dateien = sorted(ordner.glob("*.json")) if ordner.is_dir() else []
    return dateien[0] if dateien else ordner / "pre_tag_receipt_5.0.0.json"


def _resign(receipt: dict, priv) -> dict:
    """Sign the receipt's canonical bytes with ``priv`` -- the exact bytes the verifier reconstructs."""
    sys.path.insert(0, str(SCRIPTS))
    from pre_tag_receipt_lib import canonical_bytes  # noqa: PLC0415
    r = dict(receipt)
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    r["signer_pubkey"] = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return r


class TestPositiveControl:
    def test_a_committed_receipt_verifies_at_its_commit(self, welt):
        """Without this, every refusal below would also hold for a verifier that refuses everything."""
        repo, env, _priv, _kand, commit = welt
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0, roh
        assert res["verdict"] == "VERIFIED", res
        assert res["receipt_read_from"].startswith("git ls-tree/show "), "read from the commit, not the disk"
        assert res["receipt_path"] == "audit_artifacts/500/" + _receipt_path(repo).name
        assert res["trusted_pubkey_count"] == 1
        assert res["verified"] and not res["rejected"]
        assert "LIMIT" in res["limit"] and "same repository" in res["limit"], (
            "the limit travels with every verdict, the passing one included")

    def test_the_limit_is_printed_in_the_human_form_too(self, welt):
        repo, env, _priv, _kand, commit = welt
        r = _run([sys.executable, "scripts/" + VERIFIER, "--repo", ".", "--commit", commit,
                  "--version", "5.0.0"], repo, env)
        assert r.returncode == 0
        assert "verdict=VERIFIED" in r.stdout
        assert "LIMIT:" in r.stdout


class TestContract1_NoValidReceiptFails:
    def test_a_commit_without_a_receipt_is_not_verified(self, welt):
        repo, env, _priv, kandidat, _commit = welt
        _git(["checkout", "-q", "--detach", kandidat], repo)
        rc, res, roh = _verify(repo, env, kandidat)
        assert rc == 1, roh
        assert res["verdict"] == "NOT_VERIFIED"
        assert "no receipt" in res["reason"]

    def test_a_receipt_signed_by_an_untrusted_key_is_not_verified(self, welt):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        repo, env, _priv, _kand, _commit = welt
        fremd = Ed25519PrivateKey.generate()
        p = _receipt_path(repo)
        p.write_text(json.dumps(_resign(json.loads(p.read_text()), fremd), indent=2))
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "foreign signer"], repo)
        rc, res, roh = _verify(repo, env, _head(repo))
        assert rc == 1, roh
        assert res["verdict"] == "NOT_VERIFIED"
        assert "trusted set" in res["reason"]

    def test_a_tampered_receipt_is_not_verified(self, welt):
        repo, env, _priv, _kand, _commit = welt
        p = _receipt_path(repo)
        r = json.loads(p.read_text())
        r["audit_command"] = "tampered after signing"
        p.write_text(json.dumps(r, indent=2))
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "tamper"], repo)
        rc, res, roh = _verify(repo, env, _head(repo))
        assert rc == 1, roh
        assert "signature" in res["reason"]

    def test_an_unreadable_receipt_is_not_verified_and_not_absent(self, welt):
        repo, env, _priv, _kand, _commit = welt
        _receipt_path(repo).write_text("{ this is not json")
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "broken"], repo)
        rc, res, roh = _verify(repo, env, _head(repo))
        assert rc == 1, roh
        assert "not readable" in res["reason"] and "no receipt" not in res["reason"], (
            "present-but-broken is a finding about the artefact, never the leniency of absence")

    def test_a_foreign_artefact_beside_the_receipt_neither_verifies_nor_poisons(self, welt):
        """The findings register of this house lives in the version folder. It is not a receipt:
        it must not be judged as a broken one, and it must not stand in for a missing one.

        ORDER MATTERS, and the first draft of this case got it wrong: a neighbour committed AFTER
        the receipt moves the tree digest (only the receipt itself and the mutable evidence are
        outside the binding), so the receipt was rightly rejected. The ceremony rule says every
        neighbour in the version folder is committed BEFORE the receipt; the case follows it."""
        repo, env, _priv, kandidat, _commit = welt
        fremd = {"schema": "proofbundle.findings_register.v2", "entries": []}
        _git(["checkout", "-q", "--detach", kandidat], repo)
        (repo / "audit_artifacts" / "500").mkdir(parents=True, exist_ok=True)
        (repo / "audit_artifacts" / "500" / "findings_register_v2.json").write_text(json.dumps(fremd))
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "register, before any receipt"], repo)
        nur_register = _head(repo)
        # ALONE it is absence, not a rejection -- and the foreign file is named as such.
        rc, res, roh = _verify(repo, env, nur_register)
        assert rc == 1 and res["verdict"] == "NOT_VERIFIED", roh
        assert "no receipt" in res["reason"] and "foreign" in res["reason"] and not res["rejected"]
        assert res["foreign_files"] == ["audit_artifacts/500/findings_register_v2.json"]
        # THE AUDIT RUNS ON THE TREE AS IT NOW STANDS, and this line is the second half of the
        # ORDER rule the docstring above states. The fixture writes `_audit.txt` once, before this
        # case commits the register; since 2026-09-20 the receipt tool also refuses when a tracked
        # path was written AFTER the audit output, because an audit cannot have read bytes that did
        # not exist yet. Re-running the audit here is what the ceremony does anyway — the case
        # measured the verifier, and it had been relying on an ordering the tool no longer allows.
        (repo / "_audit.txt").write_text("audit ran\n")
        # BESIDE a receipt produced over this tree it neither verifies nor poisons.
        r = _run([sys.executable, "scripts/pre_tag_receipt.py", "--repo", ".", "--version", "5.0.0",
                  "--audit-command", "c", "--audit-exit", "0", "--audit-output-file", "_audit.txt",
                  "--runner-identity", "test", "--produced-at", "2026-08-27T06:00:00Z",
                  "--privkey-file", "_privkey.b64"], repo, env)
        assert r.returncode == 0, r.stderr
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "receipt beside the register"], repo)
        rc2, res2, roh2 = _verify(repo, env, _head(repo))
        assert rc2 == 0 and res2["verdict"] == "VERIFIED", roh2
        assert res2["foreign_files"] == ["audit_artifacts/500/findings_register_v2.json"]
        assert res2["receipt_path"].endswith("pre_tag_receipt_5.0.0.json") and not res2["rejected"]


class TestContract2_ReceiptForAnotherCommitFails:
    def test_the_receipt_of_the_previous_commit_does_not_cover_a_later_one(self, welt):
        """The receipt binds the tree of the commit it was made for. A later commit that changes
        src/ carries the same receipt file -- and must NOT verify, because the tree moved."""
        repo, env, _priv, _kand, commit = welt
        (repo / "src" / "proofbundle" / "__init__.py").write_text("__version__ = '5.0.0'\n# later\n")
        _git(["add", "src/proofbundle/__init__.py"], repo)
        _git(["commit", "-q", "-m", "a later commit, same receipt file"], repo)
        spaeter = _head(repo)
        assert spaeter != commit
        rc, res, roh = _verify(repo, env, spaeter)
        assert rc == 1, roh
        assert res["verdict"] == "NOT_VERIFIED"
        assert "does not bind THIS tree" in res["reason"], res["reason"]
        # ANTI-PARITY: the same receipt still verifies at the commit it was made for.
        _git(["checkout", "-q", "--detach", commit], repo)
        rc2, res2, roh2 = _verify(repo, env, commit)
        assert rc2 == 0 and res2["verdict"] == "VERIFIED", roh2


class TestContract3_CorrectSignatureWrongSubjectFails:
    def test_a_trusted_signature_over_the_wrong_subject_is_not_verified(self, welt):
        """The trusted key signs a receipt whose subject is the digest of something else (here: the
        sha256 of a blob standing in for a wheel). The signature is genuine and verifies over the
        signed bytes; the subject is not this tree. That is not a receipt for this commit."""
        repo, env, priv, _kand, _commit = welt
        p = _receipt_path(repo)
        r = json.loads(p.read_text())
        r["subject_tree_digest"] = hashlib.sha256(b"proofbundle-5.0.0-py3-none-any.whl").hexdigest()
        falsch = _resign(r, priv)
        p.write_text(json.dumps(falsch, indent=2))
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "right key, wrong subject"], repo)
        rc, res, roh = _verify(repo, env, _head(repo))
        assert rc == 1, roh
        assert res["verdict"] == "NOT_VERIFIED"
        assert "does not bind THIS tree" in res["reason"], res["reason"]
        # THE SIGNATURE REALLY IS CORRECT -- shown with the library the verifier uses, against the
        # receipt's own digests as the expectation. Without this line the case could pass because
        # of a broken signature, which is contract 1, not contract 3.
        sys.path.insert(0, str(SCRIPTS))
        sys.path.insert(0, str(repo / "src"))
        from pre_tag_receipt_lib import load_trusted_pubkeys, verify_receipt  # noqa: PLC0415
        ok, grund = verify_receipt(falsch, trusted_pubkeys=load_trusted_pubkeys(repo),
                                   expected_version="5.0.0",
                                   subject_tree_digest=falsch["subject_tree_digest"],
                                   gate_source_digest=falsch["gate_source_digest"])
        assert ok, f"the planted receipt must carry a genuine signature, got: {grund}"


class TestReadFromTheCommitNotTheWorkingTree:
    def test_a_receipt_placed_in_the_working_tree_does_not_count(self, welt):
        """A dirty checkout can hold any file. Only what the commit carries is read."""
        repo, env, _priv, kandidat, commit = welt
        gut = _receipt_path(repo).read_text()
        _git(["checkout", "-q", "--detach", kandidat], repo)
        assert not _receipt_path(repo).exists()
        _receipt_path(repo).parent.mkdir(parents=True, exist_ok=True)
        _receipt_path(repo).write_text(gut)                    # the genuine receipt, uncommitted
        rc, res, roh = _verify(repo, env, kandidat)
        assert rc == 1, roh
        assert "no receipt" in res["reason"] and "working tree does not count" in res["reason"]

    def test_a_modified_verifier_library_on_disk_refuses_the_measurement(self, welt):
        """LENS A, 2026-09-18, P0 -- the executed exploit, kept as the contract. The receipt was read
        from the commit, the CODE that judged it was read from disk: one uncommitted edit to
        `verify_receipt`, HEAD untouched, and a garbage receipt came back VERIFIED. Now a modified
        or untracked file under scripts/ or src/ refuses the measurement with exit 2."""
        repo, env, _priv, _kand, commit = welt
        lib = repo / "scripts" / "pre_tag_receipt_lib.py"
        original = lib.read_text(encoding="utf-8")
        lib.write_text(original.replace(
            "def verify_receipt(receipt: dict, *, trusted_pubkeys: list[str], expected_version: str,",
            "def verify_receipt(receipt: dict, *, trusted_pubkeys: list[str], expected_version: str,  # edited", 1),
            encoding="utf-8")
        assert lib.read_text(encoding="utf-8") != original
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2, roh
        assert res["verdict"] == "NOT_MEASURABLE" and "local modification" in res["reason"], res["reason"]
        # the same for an UNTRACKED file that could shadow an import
        lib.write_text(original, encoding="utf-8")
        (repo / "src" / "proofbundle" / "signature_shadow.py").write_text("x = 1\n")
        rc2, res2, _ = _verify(repo, env, commit)
        assert rc2 == 2 and "untracked" in res2["reason"]
        (repo / "src" / "proofbundle" / "signature_shadow.py").unlink()
        # ANTI-PARITY: the clean checkout verifies again -- the refusal is about the dirt, not the commit.
        rc3, res3, roh3 = _verify(repo, env, commit)
        assert rc3 == 0 and res3["verdict"] == "VERIFIED", roh3

    def test_an_uppercase_commit_id_is_accepted_as_the_same_commit(self, welt):
        repo, env, _priv, _kand, commit = welt
        rc, res, roh = _verify(repo, env, commit.upper())
        assert rc == 0 and res["commit"] == commit, roh

    def test_a_checkout_at_another_head_is_refused_not_measured(self, welt):
        repo, env, _priv, kandidat, commit = welt
        _git(["checkout", "-q", "--detach", kandidat], repo)
        rc, res, roh = _verify(repo, env, commit)          # asks about the receipt commit ...
        assert rc == 2, roh                                 # ... while checked out elsewhere
        assert res["verdict"] == "NOT_MEASURABLE"
        assert "not at the named commit" in res["reason"]

    def test_an_abbreviated_commit_id_is_refused(self, welt):
        repo, env, _priv, _kand, commit = welt
        rc, res, roh = _verify(repo, env, commit[:12])
        assert rc == 2, roh
        assert "40-hex" in res["reason"]

    def test_a_commit_that_is_not_in_the_clone_is_refused(self, welt):
        repo, env, _priv, _kand, _commit = welt
        rc, res, roh = _verify(repo, env, "f" * 40)
        assert rc == 2, roh
        assert "not an object of this clone" in res["reason"]


class TestBytecodeNextToTheSourceIsNotCode:
    """Lens C, 2026-09-18, P0 with an executed counter-example: a poisoned `.pyc` under the judged
    tree's `__pycache__` was executed in place of the committed `signature.py`, `git status` showed
    nothing (ignored paths are never listed), and a tampered receipt came back VERIFIED. The
    verifier now keeps this run's bytecode cache in a fresh directory, so the planted file is
    never read. The test first proves the poison is LIVE for a plain interpreter (anti-vacuity),
    then that the verifier is unmoved by it."""

    @staticmethod
    def _craft_pyc(quelle, ziel, malicious_source):
        import importlib.util as ilu  # noqa: PLC0415
        import marshal  # noqa: PLC0415
        import struct  # noqa: PLC0415
        st = quelle.stat()
        code = compile(malicious_source, str(quelle), "exec")
        daten = (ilu.MAGIC_NUMBER + struct.pack("<I", 0)
                 + struct.pack("<I", int(st.st_mtime) & 0xFFFFFFFF)
                 + struct.pack("<I", st.st_size & 0xFFFFFFFF) + marshal.dumps(code))
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_bytes(daten)

    def test_a_poisoned_pyc_under_pycache_does_not_verify_a_tampered_receipt(self, welt):
        repo, env, _priv, _kand, _commit = welt
        # the receipt is tampered after signing and committed: the real verifier must refuse it
        pfad = _receipt_path(repo)
        r = json.loads(pfad.read_text())
        r["audit_command"] = "tampered after signing, no re-sign"
        pfad.write_text(json.dumps(r, indent=2))
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "tamper"], repo)
        commit = _head(repo)
        rc0, res0, _ = _verify(repo, env, commit)
        assert rc0 == 1 and res0["verdict"] == "NOT_VERIFIED", (rc0, res0)
        # the poison: verify_ed25519 -> True, header copied from the untouched source
        sig_py = repo / "src" / "proofbundle" / "signature.py"
        pyc = sig_py.parent / "__pycache__" / f"signature.{sys.implementation.cache_tag}.pyc"
        self._craft_pyc(sig_py, pyc, "def verify_ed25519(public_key, signature, message):\n    return True\n")
        # anti-vacuity: a plain interpreter DOES run the poison (otherwise this test proves nothing)
        probe = _run([sys.executable, "-c",
                      "import proofbundle.signature as s; print(s.verify_ed25519(b'', b'', b''))"],
                     repo, {"PYTHONPATH": f"{repo}/src", "PATH": env["PATH"]})
        assert probe.stdout.strip() == "True", ("the planted bytecode is not live; the test would be "
                                                "vacuous", probe.stdout, probe.stderr)
        # and git sees nothing: the checkout guard alone could never catch this
        st = _run(["git", "status", "--porcelain", "--untracked-files=all", "--", "scripts", "src"], repo)
        assert st.stdout.strip() == ""
        # the verifier is unmoved
        rc, res, raw = _verify(repo, env, commit)
        assert rc == 1 and res["verdict"] == "NOT_VERIFIED", (rc, res, raw[-300:])
        assert "signature" in res["reason"].lower()
