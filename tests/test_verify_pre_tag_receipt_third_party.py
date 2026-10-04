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
import shlex
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
#: The audit the producer runs in these fixtures: a program that prints one line and exits 0.
_AUDIT = shlex.join([sys.executable, "-c", "print('audit ran')"])


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
    # THE AUDIT RUNS INSIDE THE TOOL (2026-09-21): started by the receipt script between two
    # measurements of the tree; the record is written by the script, outside the tree.
    r = _run([sys.executable, "scripts/pre_tag_receipt.py", "--repo", ".", "--version", "5.0.0",
              "--audit-command", _AUDIT, "--audit-output-file", str(tmp_path / "_audit_record.txt"),
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
        # BESIDE a receipt produced over this tree it neither verifies nor poisons.
        r = _run([sys.executable, "scripts/pre_tag_receipt.py", "--repo", ".", "--version", "5.0.0",
                  "--audit-command", _AUDIT,
                  "--audit-output-file", str(repo.parent / "_audit_record_beside_register.txt"),
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
        assert res["verdict"] == "NOT_MEASURABLE" and "is not the commit" in res["reason"], res["reason"]
        # the same for an UNTRACKED file that could shadow an import
        lib.write_text(original, encoding="utf-8")
        (repo / "src" / "proofbundle" / "signature_shadow.py").write_text("x = 1\n")
        rc2, res2, _ = _verify(repo, env, commit)
        assert rc2 == 2 and "is not the commit" in res2["reason"]
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


class TestNoUncommittedCodeJudges:
    """Deep gate run 7 at 1a3cd672, L6-620v7-T6-VERIFIER-SELF-HIDDEN-SHADOW-01 (three of three jurors P1): an untracked
    package that hides itself with its own `.gitignore` (`*`) was invisible to the verifier's `git status`, and a
    package directory is imported ahead of a module of the same name, so `src/proofbundle/signature/` judged in place of
    the committed `signature.py`; from `scripts/`, the script's own directory on `sys.path`, `scripts/contextlib/` ran at
    the first import, before any check. Both gave `0 VERIFIED` for a tampered receipt.

    THE PROPERTY, as the generator below states it: for every position at which Python would take a planted package
    for a module the verifier imports, a self-hidden plant refuses the measurement (exit 2), and a plant in `scripts/`
    is never imported at all. The positions are read from a real run (`python -X importtime`), not typed: every
    `proofbundle` submodule and every top-level module the verifier process imports. The controls: unplanted, the
    tampered receipt is NOT_VERIFIED (exit 1); planted without the hiding `.gitignore`, `git status` already refuses."""

    @staticmethod
    def _tamper(repo):
        pfad = _receipt_path(repo)
        r = json.loads(pfad.read_text())
        r["audit_command"] = "tampered after signing, no re-sign"
        pfad.write_text(json.dumps(r, indent=2))
        _git(["add", "audit_artifacts/500/"], repo)
        _git(["commit", "-q", "-m", "tamper"], repo)
        return _head(repo)

    @staticmethod
    def _imported_modules(repo, env, commit):
        """Every module name the verifier process imports, read from `-X importtime` of a real run."""
        r = _run([sys.executable, "-X", "importtime", "scripts/" + VERIFIER, "--repo", ".", "--commit", commit,
                  "--version", "5.0.0", "--json"], repo, env)
        namen = set()
        for zeile in r.stderr.splitlines():
            if zeile.startswith("import time:") and zeile.count("|") == 2:
                name = zeile.rsplit("|", 1)[1].strip()
                if name and name != "package":
                    namen.add(name)
        return namen

    @staticmethod
    def _plant(ort, marker):
        """A package at `ort` that writes `marker` when imported, hidden by its own `.gitignore`."""
        ort.mkdir(parents=True)
        (ort / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('imported')\n")
        (ort / ".gitignore").write_text("*\n")

    def _positions(self, repo, env, commit):
        namen = self._imported_modules(repo, env, commit)
        unter = sorted({n.split(".")[1] for n in namen if n.startswith("proofbundle.") and n.count(".") == 1})
        oben = sorted({n.split(".")[0] for n in namen} - set(sys.builtin_module_names) - {"proofbundle"})
        return ([("src", repo / "src" / "proofbundle" / u) for u in unter]
                + [("scripts", repo / "scripts" / o) for o in oben])

    def test_control_the_tampered_receipt_is_not_verified_without_a_plant(self, welt):
        repo, env, _priv, _kand, _commit = welt
        commit = self._tamper(repo)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 1 and res["verdict"] == "NOT_VERIFIED", roh

    def test_the_positions_are_read_from_a_real_run_and_are_many(self, welt):
        """Anti-vacuity of the generator: the run names the signature module and the standard modules the script
        imports at its top, so the positions below are the ones a planted package would take."""
        repo, env, _priv, _kand, commit = welt
        orte = {(teil, p.name) for teil, p in self._positions(repo, env, commit)}
        assert ("src", "signature") in orte
        for name in ("argparse", "hashlib", "json"):
            assert ("scripts", name) in orte, sorted(orte)
        assert len(orte) >= 20, len(orte)

    def test_every_self_hidden_plant_refuses_the_measurement(self, welt):
        """In process, through `measure`, one plant at a time: the refusal is the verifier's comparison of the checkout
        with the commit, which runs before any judged code is imported."""
        repo, env, _priv, _kand, _commit = welt
        commit = self._tamper(repo)
        sys.path.insert(0, str(SCRIPTS))
        import importlib  # noqa: PLC0415
        verifier = importlib.import_module("verify_pre_tag_receipt")
        befunde = []
        positionen = self._positions(repo, env, commit)
        for teil, ort in positionen:
            marker = repo.parent / f"_marker_{teil}_{ort.name}"
            self._plant(ort, marker)
            try:
                st = _run(["git", "status", "--porcelain", "--untracked-files=all", "--", "scripts", "src"], repo)
                res = verifier.measure(repo, commit, "5.0.0")
                if st.stdout.strip() != "":
                    befunde.append(f"{teil}/{ort.name}: the plant is not hidden from git status, the case proves nothing")
                if res["verdict"] != "NOT_MEASURABLE" or "is not the commit" not in (res["reason"] or ""):
                    befunde.append(f"{teil}/{ort.name}: {res['verdict']} {str(res['reason'])[:120]}")
            finally:
                shutil.rmtree(ort)
        assert befunde == [], "\n".join(befunde)
        assert positionen

    def test_a_plant_in_scripts_is_never_imported_by_the_script(self, welt):
        """As a reader runs it (`python scripts/verify_pre_tag_receipt.py`): every standard module the script imports at
        its top, planted under `scripts/` and hidden, writes a marker when imported. No marker may appear, and the
        verdict is exit 2. The anti-vacuity half: without the path cleaning, a plain script run from `scripts/` would
        take the plant for each module the interpreter has not loaded at its start."""
        repo, env, _priv, _kand, _commit = welt
        commit = self._tamper(repo)
        namen = [o.name for teil, o in self._positions(repo, env, commit)
                 if teil == "scripts" and o.name in ("argparse", "hashlib", "json", "re", "pathlib", "tempfile",
                                                       "subprocess", "contextlib", "__future__")]
        assert namen
        befunde, lebendig = [], []
        for name in namen:
            ort, marker = repo / "scripts" / name, repo.parent / f"_marker_scripts_{name}"
            self._plant(ort, marker)
            try:
                rc, res, roh = _verify(repo, env, commit)
                if marker.exists():
                    befunde.append(f"scripts/{name} was imported")
                    marker.unlink()
                if rc != 2:
                    befunde.append(f"scripts/{name}: exit {rc}")
                probe = repo / "scripts" / "_probe_plain.py"
                probe.write_text(f"import {name}\n")
                _run([sys.executable, "scripts/_probe_plain.py"], repo, {"PATH": env["PATH"]})
                probe.unlink()
                if marker.exists():
                    lebendig.append(name)
                    marker.unlink()
            finally:
                shutil.rmtree(ort)
        assert befunde == [], "\n".join(befunde)
        assert lebendig, "no plant was live for a plain script run; the case would prove nothing"

    def test_a_modified_file_hidden_by_an_index_bit_refuses_the_measurement(self, welt):
        """The neighbour of the same class: `git status` reads the index, and a modified committed file whose
        `skip-worktree` or `assume-unchanged` bit is set is not listed. The verifier compares the bytes."""
        repo, env, _priv, _kand, _commit = welt
        commit = self._tamper(repo)
        ziel = repo / "src" / "proofbundle" / "signature.py"
        original = ziel.read_bytes()
        for bit in ("--skip-worktree", "--assume-unchanged"):
            ziel.write_bytes(original + b"\n# modified\n")
            _git(["update-index", bit, "src/proofbundle/signature.py"], repo)
            try:
                st = _run(["git", "status", "--porcelain", "--untracked-files=all", "--", "scripts", "src"], repo)
                assert st.stdout.strip() == "", f"{bit}: git status lists the change, the case proves nothing"
                rc, res, roh = _verify(repo, env, commit)
                assert rc == 2 and "is not the commit" in res["reason"], (bit, roh)
            finally:
                _git(["update-index", bit.replace("--", "--no-"), "src/proofbundle/signature.py"], repo)
                ziel.write_bytes(original)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 1 and res["verdict"] == "NOT_VERIFIED", roh

    def test_an_uncommitted_symbolic_link_refuses_the_measurement(self, welt):
        """A symbolic link Python follows is code from outside the commit, wherever it points."""
        repo, env, _priv, _kand, _commit = welt
        commit = self._tamper(repo)
        fremd = repo.parent / "_outside_pkg"
        fremd.mkdir()
        (fremd / "__init__.py").write_text("x = 1\n")
        link = repo / "src" / "proofbundle" / "signature_link"
        link.symlink_to(fremd, target_is_directory=True)
        (repo / "src" / "proofbundle" / ".gitignore").write_text("signature_link\n.gitignore\n")
        try:
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 2 and "is not the commit" in res["reason"], roh
        finally:
            link.unlink()
            (repo / "src" / "proofbundle" / ".gitignore").unlink()

    def test_an_editable_install_record_does_not_refuse(self, welt):
        """The counter-direction: a file Python cannot import (the `*.egg-info` an editable install writes under
        `src/`) is no code, and a reader with such a record must still be able to verify."""
        repo, env, _priv, _kand, commit = welt
        info = repo / "src" / "proofbundle.egg-info"
        info.mkdir()
        (info / "PKG-INFO").write_text("Name: proofbundle\n")
        (info / "SOURCES.txt").write_text("src/proofbundle/__init__.py\n")
        (repo / ".git" / "info" / "exclude").write_text("*.egg-info/\n")
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh


class TestNoFileOfTheCheckoutRunsBeforeTheCheck:
    """Codex on pull request 311 at 3f598b5b (P1), reproduced at 1e189f89: the fix above took only `scripts/` and `src/`
    off the path. With the top level on `sys.path` (`PYTHONPATH=.`), an untracked `contextlib.py` there ran before any
    check, and so did `argparse.py` and `json.py`, `tests/contextlib.py` through `PYTHONPATH=tests`, a top-level module
    under `python -m scripts.verify_pre_tag_receipt`, and a top-level `sitecustomize.py`, which Python loads at start.

    THE PROPERTY, per entry through which Python finds modules in the checkout. The positions are read, not typed: every
    top-level module a real run imports, every module loaded when a script started the same way runs its first line,
    and the two startup hooks. Each is planted, and a probe started the same way shows which of them Python takes
    before the first line (repeated until no new one runs, as a plant that breaks the start hides the ones after it).
    A position after the first line is never taken from the checkout. A position before it is code the script cannot
    keep from running: its plant does not run, or the run is refused with exit 2, or it gives no verdict at all. In
    isolated mode (`-I`, the documented command) no plant runs.

    Codex at e61dc740 (P1, reproduced): the fix of 653b5d67 kept the entries of an interpreter installed in the clone. A
    `.pth` in such a `.venv/` runs before the first line, `-I` included, and one that patched
    `importlib.util.spec_from_file_location` gave exit 0 VERIFIED for a receipt that does not bind the tree. An
    interpreter installed in the checkout now refuses the measurement, and no entry in the checkout stays on the path."""

    #: How a reader may put a directory of the checkout on the path: (label, PYTHONPATH below the top level or None,
    #: started with `-m`, directory the plants go to, relative to the top level).
    _EINTRAEGE = (("the top level through PYTHONPATH", ".", False, "."),
                  ("a subdirectory through PYTHONPATH", "tests", False, "tests"),
                  ("the working directory under python -m", None, True, "."))

    @staticmethod
    def _plant_module(ordner, name, marker_dir):
        """`<ordner>/<name>.py` that leaves a marker when imported. It writes through `posix`, which is built in, so
        no plant stands in for it, and which works before the interpreter has set up `open` at start."""
        ordner.mkdir(parents=True, exist_ok=True)
        marker = marker_dir / f"{ordner.name}__{name}"
        (ordner / f"{name}.py").write_text(
            f"import posix\nposix.close(posix.open({str(marker)!r}, posix.O_WRONLY | posix.O_CREAT, 0o644))\n")

    @staticmethod
    def _ausreissen(ordner, namen, marker_dir):
        for name in namen:
            (ordner / f"{name}.py").unlink(missing_ok=True)
        shutil.rmtree(ordner / "__pycache__", ignore_errors=True)
        for p in marker_dir.iterdir():
            p.unlink()

    @staticmethod
    def _umgebung(repo, eintrag):
        env = {"PATH": "/usr/bin:/bin"}
        if eintrag[1] is not None:
            env["PYTHONPATH"] = str((repo / eintrag[1]).resolve())
        return env

    def _aufruf(self, repo, eintrag, commit):
        start = [sys.executable] + (["-m", "scripts.verify_pre_tag_receipt"] if eintrag[2] else ["scripts/" + VERIFIER])
        return (start + ["--repo", ".", "--commit", commit, "--version", "5.0.0", "--json"],
                self._umgebung(repo, eintrag))

    def _probe(self, repo, eintrag, inhalt):
        """Runs `inhalt` as a script started the way `eintrag` starts the verifier. -> CompletedProcess"""
        probe = repo / "scripts" / "_probe_first_line.py"
        probe.write_text(inhalt)
        start = [sys.executable] + (["-m", "scripts._probe_first_line"] if eintrag[2] else ["scripts/_probe_first_line.py"])
        try:
            return _run(start, repo, self._umgebung(repo, eintrag))
        finally:
            probe.unlink()

    def _kandidaten(self, repo, env, commit, eintrag):
        namen = {n.split(".")[0] for n in TestNoUncommittedCodeJudges._imported_modules(repo, env, commit)}
        r = self._probe(repo, eintrag, "import sys\nprint('\\n'.join(sorted(sys.modules)))\n")
        assert r.returncode == 0, r.stderr
        namen |= {z.split(".")[0] for z in r.stdout.split()}
        return sorted((namen | {"sitecustomize", "usercustomize"}) - set(sys.builtin_module_names)
                      - {"proofbundle", "__main__"})

    def _vor_der_ersten_zeile(self, repo, eintrag, kandidaten, marker_dir):
        """The candidates Python takes from the entry before a script's first line, by planting all and probing."""
        ordner = (repo / eintrag[3]).resolve()
        rest, vorher = set(kandidaten), set()
        while True:
            for name in rest:
                self._plant_module(ordner, name, marker_dir)
            self._probe(repo, eintrag, "pass\n")
            neu = {p.name.split("__", 1)[1] for p in marker_dir.iterdir()}
            self._ausreissen(ordner, rest, marker_dir)
            if not neu:
                return vorher
            vorher |= neu
            rest -= neu

    def test_no_module_after_the_first_line_is_taken_from_an_entry_into_the_checkout(self, welt):
        repo, env, _priv, _kand, _commit = welt
        commit = TestNoUncommittedCodeJudges._tamper(repo)
        marker_dir = repo.parent / "_marker_eintrag"
        marker_dir.mkdir()
        befunde, gemessen = [], 0
        for eintrag in self._EINTRAEGE:
            label, pp, mit_m, ordner_rel = eintrag
            kandidaten = self._kandidaten(repo, env, commit, eintrag)
            nach = sorted(set(kandidaten) - self._vor_der_ersten_zeile(repo, eintrag, kandidaten, marker_dir))
            # `python -m` loads `contextlib` before the first line (runpy imports it): a position of the next test.
            for name in ("argparse", "hashlib", "json", "re", "pathlib") + (() if mit_m else ("contextlib",)):
                assert name in nach, (label, name, nach)
            ordner = (repo / ordner_rel).resolve()
            for name in nach:
                self._plant_module(ordner, name, marker_dir)
            try:
                # ANTI-VACUITY: through this entry a plain import takes the plant (the case of the first fix). The
                # import runs in a script started the way the verifier starts, the start whose positions before the
                # first line were measured above. `python -c` is a different start: from 3.13 on it imports
                # `linecache` and calls `linecache._register_code` before the command runs, a real run loads
                # `linecache`, so it is planted, and the command never reached its import on 3.13 and 3.14.
                self._probe(repo, eintrag, "import argparse\n")
                lebendig = marker_dir / f"{ordner.name}__argparse"
                assert lebendig.exists(), f"{label}: the plant is not live for a plain import, the case proves nothing"
                lebendig.unlink()
                cmd, run_env = self._aufruf(repo, eintrag, commit)
                r = _run(cmd, repo, run_env)
                gelaufen = sorted(p.name for p in marker_dir.iterdir())
                if gelaufen:
                    befunde.append(f"{label}: imported from the checkout {gelaufen[:6]}")
                if r.returncode != 1 or '"NOT_VERIFIED"' not in r.stdout:
                    befunde.append(f"{label}: exit {r.returncode} {(r.stdout + r.stderr)[-200:]}")
                gemessen += len(nach)
            finally:
                self._ausreissen(ordner, nach, marker_dir)
        assert befunde == [], "\n".join(befunde)
        assert gemessen >= 3 * 20, gemessen

    def test_a_module_of_the_checkout_loaded_before_the_first_line_never_yields_an_unrefused_verdict(self, welt):
        repo, env, _priv, _kand, _commit = welt
        commit = TestNoUncommittedCodeJudges._tamper(repo)
        marker_dir = repo.parent / "_marker_start"
        marker_dir.mkdir()
        positionen = []
        for eintrag in (self._EINTRAEGE[0], self._EINTRAEGE[2]):
            kandidaten = self._kandidaten(repo, env, commit, eintrag)
            positionen += [(eintrag, n) for n in sorted(self._vor_der_ersten_zeile(repo, eintrag, kandidaten,
                                                                                     marker_dir))]
        befunde, verweigert, ohne_urteil = [], [], []
        for eintrag, name in positionen:
            ordner = (repo / eintrag[3]).resolve()
            self._plant_module(ordner, name, marker_dir)
            try:
                cmd, run_env = self._aufruf(repo, eintrag, commit)
                r = _run(cmd, repo, run_env)
                lief = (marker_dir / f"{ordner.name}__{name}").exists()
                try:
                    res = json.loads(r.stdout)
                except ValueError:
                    res = None
                if not lief:
                    if r.returncode != 1 or not res or res.get("verdict") != "NOT_VERIFIED":
                        befunde.append(f"{eintrag[0]}, {name}: did not run, yet exit {r.returncode}")
                elif res is None:
                    ohne_urteil.append(name)
                elif r.returncode == 2 and "before the verifier's first line" in str(res.get("reason")):
                    verweigert.append(name)
                else:
                    befunde.append(f"{eintrag[0]}, {name}: ran before the first line and the verdict stands: "
                                   f"exit {r.returncode} {res.get('verdict')}")
            finally:
                self._ausreissen(ordner, [name], marker_dir)
        assert befunde == [], "\n".join(befunde)
        assert "sitecustomize" in verweigert, ("no startup plant was refused, the case would prove nothing",
                                              verweigert, ohne_urteil)
        # From 3.11 on most start modules are frozen and no plant stands in for them, so the count depends on the
        # version (24 on 3.10.12, 16 on 3.11.15); `sitecustomize` through PYTHONPATH and `scripts` under `-m` are
        # not frozen on any version, so they stay positions.
        assert len(positionen) >= 2, positionen

    def test_in_isolated_mode_no_planted_module_runs_and_a_good_receipt_verifies(self, welt):
        """The documented command, `python -I`: every position of the two tests above, planted at the top level and in
        `tests/`, both on PYTHONPATH, and not one of them runs; a good receipt verifies with it."""
        repo, env, _priv, _kand, good = welt
        cmd, run_env = self._aufruf(repo, self._EINTRAEGE[0], good)
        r = _run([sys.executable, "-I", *cmd[1:]], repo, run_env)
        assert r.returncode == 0 and '"VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]
        commit = TestNoUncommittedCodeJudges._tamper(repo)
        namen = set()
        for eintrag in self._EINTRAEGE:
            namen |= set(self._kandidaten(repo, env, commit, eintrag))
        marker_dir = repo.parent / "_marker_isoliert"
        marker_dir.mkdir()
        orte = (repo, repo / "tests")
        for ordner in orte:
            for name in namen:
                self._plant_module(ordner, name, marker_dir)
        try:
            run_env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": f"{repo}:{repo / 'tests'}"}
            r = _run([sys.executable, "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", commit,
                      "--version", "5.0.0", "--json"], repo, run_env)
            gelaufen = sorted(p.name for p in marker_dir.iterdir())
            assert gelaufen == [], gelaufen[:10]
            assert r.returncode == 1 and '"NOT_VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]
            # ANTI-VACUITY: without -I the same plants run.
            _run([sys.executable, "scripts/" + VERIFIER, "--repo", ".", "--commit", commit, "--version", "5.0.0",
                  "--json"], repo, run_env)
            assert any(marker_dir.iterdir()), "no plant ran without -I either, the case proves nothing"
        finally:
            for ordner in orte:
                self._ausreissen(ordner, namen, marker_dir)
        assert len(namen) >= 30, len(namen)

    def test_no_entry_in_the_checkout_stays_on_the_path(self, welt, monkeypatch, tmp_path):
        """At the function: every entry in the checkout goes, the top level, the working directory and the site
        directory of an interpreter installed in the clone included; an entry outside stays. Since the fix for Codex at
        6d081424 (thread 4173974268) an entry that CONTAINS the checkout goes too, so the working directory used as the
        outside control here lies beside the clone, and a third step measures the parent as working directory."""
        repo, _env, _priv, _kand, _commit = welt
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_t6_root_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        aussen = tmp_path / "outside_stdlib"
        aussen.mkdir()
        venv_sp = repo / ".venv" / "lib" / "python3" / "site-packages"
        venv_sp.mkdir(parents=True)
        (repo / "tests").mkdir(exist_ok=True)
        monkeypatch.chdir(aussen)
        monkeypatch.setattr(sys, "path", [str(repo), str(repo / "tests"), str(repo / "scripts"), str(venv_sp),
                                          str(repo / "src"), str(aussen), ""])
        monkeypatch.setattr(sys, "prefix", str(repo / ".venv"))
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(aussen), ""], sys.path
        monkeypatch.chdir(repo)
        monkeypatch.setattr(sys, "path", ["", str(aussen)])
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(aussen)], "the empty entry is the working directory, here the checkout"
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "path", ["", str(aussen)])
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(aussen)], "the empty entry is the working directory, here the parent of the checkout"

    def test_the_overlap_check_covers_the_whole_installation_both_directions(self, welt, monkeypatch):
        """At the function: any prefix or site directory that contains the checkout, equals it, or lies in it is an
        overlap; a directory fully beside it is not. A prefix ABOVE the checkout counts now (Codex found a clone rooted
        at `lib-dynload`, which is under a prefix), so the test over the whole installation is bidirectional."""
        repo, _env, _priv, _kand, _commit = welt
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_t6_overlap_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # a directory fully beside the checkout -> no overlap
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("sys.prefix", str(repo.parent / "elsewhere"))])
        assert mod._interpreter_overlaps_the_checkout() == []
        # a prefix ABOVE the checkout is an overlap now (lib-dynload lies under such a prefix)
        oben = str(repo.resolve().parent)
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("sys.prefix", oben)])
        assert mod._interpreter_overlaps_the_checkout() == [f"sys.prefix ({oben})"], \
            "a prefix containing the checkout is an overlap"
        # a prefix IN the checkout (a .venv in the clone)
        innen = str((repo / ".venv").resolve())
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("sys.base_prefix", innen)])
        assert mod._interpreter_overlaps_the_checkout() == [f"sys.base_prefix ({innen})"]
        # a site directory the checkout lies in (a clone at the venv's purelib)
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("site", oben)])
        assert mod._interpreter_overlaps_the_checkout() == [f"site ({oben})"]
        # equal paths are an overlap
        gleich = str(repo.resolve())
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("site", gleich)])
        assert mod._interpreter_overlaps_the_checkout() == [f"site ({gleich})"]

    def test_the_startup_eyes_enumerate_prefixes_and_site_dirs(self, welt):
        """Anti-vacuity of the enumeration: a real run names the four prefixes and at least one site directory, so the
        containment test above is applied to the directories that actually hold startup code."""
        repo, _env, _priv, _kand, _commit = welt
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_t6_eyes_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        augen = mod._interpreter_startaugen()
        namen = {n for n, _ in augen}
        assert {"sys.prefix", "sys.exec_prefix", "sys.base_prefix", "sys.base_exec_prefix"} <= namen, namen
        assert "site" in namen, namen

    def test_the_config_refusal_names_each_program_family(self, welt, monkeypatch):
        """At the function: a program-selecting key of each family is reported, an empty one and a non-program key are
        not. `filter.<n>.`, `diff.<n>.`, `merge.<n>.` carry a free middle name; the exact keys name a program directly."""
        repo, _env, _priv, _kand, _commit = welt
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_t6_config_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        familien = {
            "filter.secret.clean": "sh -c evil", "filter.x.process": "git-lfs", "diff.j.command": "jq",
            "diff.word.textconv": "pandoc", "merge.ours.driver": "touch win", "core.fsmonitor": "/hook",
            "core.sshcommand": "ssh -i k", "diff.external": "run", "credential.helper": "store",
            "core.hooksPath": "/hooks",
            # the P2 families Codex named at d0e47397: a URL-scoped credential helper, a per-command pager,
            # an interactive diff filter, an ssh signing command.
            "credential.https://example.com.helper": "!touch m", "pager.status": "less -X",
            "interactive.diffFilter": "diff-highlight", "gpg.ssh.defaultKeyCommand": "ssh-add -L",
        }
        for key, value in familien.items():
            _git(["config", "--local", key, value], repo)
        _git(["config", "--local", "filter.empty.clean", ""], repo)       # empty: no program
        _git(["config", "--local", "core.ignoreCase", "false"], repo)     # not a program key
        _git(["config", "--local", "pager.diff", "false"], repo)          # a pager switched off, not a program
        gefunden = {z.split("=", 1)[0].lower() for z in mod._git_configuration_selects_a_program(repo)}
        for key in familien:
            assert key.lower() in gefunden, (key, sorted(gefunden))
        assert "filter.empty.clean" not in gefunden and "core.ignorecase" not in gefunden, sorted(gefunden)
        assert "pager.diff" not in gefunden, ("a pager switched off names no program", sorted(gefunden))

    def test_a_virtual_environment_inside_the_checkout_refuses_the_measurement(self, welt):
        """Codex's case, executed: `python -m venv .venv` in the clone, a `.pth` there that imports a module patching
        `importlib.util.spec_from_file_location` so that the loaded library's `verify_receipt` says yes. With and
        without `-I` the planted module runs (the anti-vacuity half) and the run is refused with exit 2, for the good
        receipt as for the tampered one; the same interpreter outside the clone verifies the good receipt."""
        repo, _env, _priv, _kand, good = welt
        r = _run([sys.executable, "-m", "venv", "--without-pip", str(repo / ".venv")], repo.parent)
        assert r.returncode == 0, r.stderr
        innen = repo / ".venv" / "bin" / "python"
        r = _run([str(innen), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], repo.parent)
        assert r.returncode == 0, r.stderr
        sp = Path(r.stdout.strip())
        aussen = sorted({p for p in sys.path if p.endswith(("site-packages", "dist-packages")) and Path(p).is_dir()})
        marker = repo.parent / "_marker_installation"
        (sp / "pb_planted_at_start.py").write_text(
            f"open({str(marker)!r}, 'w').write('ran')\n"
            "import importlib.util as _u\n"
            "_orig = _u.spec_from_file_location\n"
            "def _spec(name, *a, **k):\n"
            "    s = _orig(name, *a, **k)\n"
            "    if name == '_verify_pre_tag_receipt_lib' and s is not None:\n"
            "        _ex = s.loader.exec_module\n"
            "        def exec_module(m, _ex=_ex):\n"
            "            _ex(m)\n"
            "            m.verify_receipt = lambda *aa, **kk: (True, 'planted')\n"
            "        s.loader.exec_module = exec_module\n"
            "    return s\n"
            "_u.spec_from_file_location = _spec\n")
        (sp / "pb_planted_at_start.pth").write_text("".join(p + "\n" for p in aussen) + "import pb_planted_at_start\n")
        tampered = TestNoUncommittedCodeJudges._tamper(repo)
        for commit in (good, tampered):
            _git(["checkout", "-q", "--detach", commit], repo)
            for modus in ([], ["-I"]):
                marker.unlink(missing_ok=True)
                r = _run([str(innen), *modus, "scripts/" + VERIFIER, "--repo", ".", "--commit", commit,
                          "--version", "5.0.0", "--json"], repo, {"PATH": "/usr/bin:/bin"})
                assert marker.exists(), (modus, "the planted start module did not run, the case proves nothing")
                res = json.loads(r.stdout)
                assert r.returncode == 2 and "shares a directory with the checkout" in res["reason"], (
                    modus, r.stdout[-400:])
        _git(["checkout", "-q", "--detach", good], repo)
        r = _run([sys.executable, "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        assert r.returncode == 0 and '"VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]

    def test_a_script_from_another_checkout_refuses_the_measurement(self, welt):
        """The neighbour of the same class, measured at 653b5d67: the code that judges lies in the checkout the script
        runs from, and only the checkout `--repo` names is compared. A second clone whose library says yes to every
        receipt, run against the clean checkout of a tampered receipt, is refused with exit 2; the script of the judged
        checkout itself gives NOT_VERIFIED, and the forged clone judging itself is refused as not the commit."""
        repo, _env, _priv, _kand, _commit = welt
        tampered = TestNoUncommittedCodeJudges._tamper(repo)
        fremd = repo.parent / "other_clone"
        _git(["clone", "-q", str(repo), str(fremd)], repo.parent)
        _git(["checkout", "-q", "--detach", tampered], fremd)
        lib = fremd / "scripts" / "pre_tag_receipt_lib.py"
        lib.write_text(lib.read_text(encoding="utf-8")
                       + "\n\ndef verify_receipt(receipt, **kw):\n    return True, 'FORGED in the other clone'\n",
                       encoding="utf-8")
        env = {"PATH": "/usr/bin:/bin"}
        r = _run([sys.executable, "-I", str(fremd / "scripts" / VERIFIER), "--repo", str(repo), "--commit", tampered,
                  "--version", "5.0.0", "--json"], repo, env)
        res = json.loads(r.stdout)
        assert r.returncode == 2 and "only the checkout --repo names is compared" in res["reason"], r.stdout[-400:]
        r = _run([sys.executable, "-I", str(repo / "scripts" / VERIFIER), "--repo", str(repo), "--commit", tampered,
                  "--version", "5.0.0", "--json"], repo, env)
        assert r.returncode == 1 and '"NOT_VERIFIED"' in r.stdout, r.stdout[-400:]
        r = _run([sys.executable, "-I", str(fremd / "scripts" / VERIFIER), "--repo", str(fremd), "--commit", tampered,
                  "--version", "5.0.0", "--json"], fremd, env)
        assert r.returncode == 2 and "is not the commit" in json.loads(r.stdout)["reason"], r.stdout[-400:]

    def test_a_clone_inside_the_interpreter_site_directory_refuses(self, welt):
        """Codex on PR 311 at 252ba3c6 (P1), executed: an external venv, the tree cloned at its `purelib`, and a `.pth`
        in `purelib` (above the clone, so the earlier prefix-in-checkout check missed it) that replaces the loaded
        verifier library. The documented `python -I` ran the `.pth` before the first line; now the run is refused with
        exit 2 because the checkout lies in a site directory of the interpreter. The planted module runs (anti-vacuity),
        the same interpreter against a clone OUTSIDE its site directories verifies the good receipt."""
        repo, _env, _priv, good = welt[0], welt[1], welt[2], welt[4]
        venv = repo.parent / "outer_venv"
        r = _run([sys.executable, "-m", "venv", "--system-site-packages", "--without-pip", str(venv)], repo.parent)
        assert r.returncode == 0, r.stderr
        innen = venv / "bin" / "python"
        sp = Path(_run([str(innen), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                       repo.parent).stdout.strip())
        aussen = sorted({p for p in sys.path if p.endswith(("site-packages", "dist-packages")) and Path(p).is_dir()})
        marker = repo.parent / "_marker_site"
        (sp / "pb_site_plant.py").write_text(
            f"open({str(marker)!r}, 'w').write('ran')\n"
            "import importlib.util as _u\n_orig = _u.spec_from_file_location\n"
            "def _spec(name, *a, **k):\n    s = _orig(name, *a, **k)\n"
            "    if name == '_verify_pre_tag_receipt_lib' and s is not None:\n"
            "        _ex = s.loader.exec_module\n"
            "        def exec_module(m, _ex=_ex):\n            _ex(m)\n"
            "            m.verify_receipt = lambda *aa, **kk: (True, 'planted via site .pth')\n"
            "        s.loader.exec_module = exec_module\n    return s\n_u.spec_from_file_location = _spec\n")
        (sp / "pb_site_plant.pth").write_text("".join(p + "\n" for p in aussen) + "import pb_site_plant\n")
        klon = sp / "proofbundle_clone"
        _git(["clone", "-q", str(repo), str(klon)], repo.parent)
        _git(["checkout", "-q", "--detach", good], klon)
        for modus in ([], ["-I"]):
            marker.unlink(missing_ok=True)
            r = _run([str(innen), *modus, str(klon / "scripts" / VERIFIER), "--repo", str(klon), "--commit", good,
                      "--version", "5.0.0", "--json"], klon, {"PATH": "/usr/bin:/bin"})
            assert marker.exists(), (modus, "the site .pth did not run, the case proves nothing")
            res = json.loads(r.stdout)
            assert r.returncode == 2 and "shares a directory with the checkout" in res["reason"], (modus, r.stdout[-400:])
        # ANTI-PARITY, with the plant removed (the interpreter is trusted; the plant is the environment, not the
        # clone): the same interpreter against a clone OUTSIDE its site directories verifies the good receipt. This
        # shows the refusal above is the checkout lying in the site directory, not the clone id or the receipt.
        (sp / "pb_site_plant.pth").unlink()
        (sp / "pb_site_plant.py").unlink()
        aussenklon = repo.parent / "clone_outside"
        _git(["clone", "-q", str(repo), str(aussenklon)], repo.parent)
        _git(["checkout", "-q", "--detach", good], aussenklon)
        r = _run([str(innen), "-I", str(aussenklon / "scripts" / VERIFIER), "--repo", str(aussenklon), "--commit", good,
                  "--version", "5.0.0", "--json"], aussenklon, {"PATH": "/usr/bin:/bin"})
        assert r.returncode == 0 and '"VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]

    def test_a_clone_configuring_a_clean_filter_refuses_and_never_runs_it(self, welt):
        """Owner OA-4496f29e70, executed per family: a clean filter chosen by `.git/config` and `.git/info/attributes`
        runs during `git status`. The verifier refuses the clone with exit 2 before the status, and the filter marker
        never appears. The counter-check: a plain `git status` in the same clone DOES run it (anti-vacuity). One case
        stands for the clean filter; `test_the_config_refusal_names_each_program_family` covers every family at the
        function, which is where the families differ."""
        repo, env, _priv, _kand, commit = welt
        marker = repo.parent / "_marker_filter_e2e"
        _git(["config", "--local", "filter.boese.clean", f"sh -c 'touch {marker}; cat'"], repo)
        (repo / ".git" / "info").mkdir(parents=True, exist_ok=True)
        (repo / ".git" / "info" / "attributes").write_text("* filter=boese\n")
        for p in repo.rglob("*.py"):
            p.touch()                                           # make the files racy so git re-runs the filter
        marker.unlink(missing_ok=True)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and "select a program" in (res["reason"] or ""), roh
        assert not marker.exists(), "the clean filter ran although the clone was refused"
        # ANTI-VACUITY: a plain git status in the same clone does run the filter.
        marker.unlink(missing_ok=True)
        _run(["git", "status", "--porcelain"], repo)
        assert marker.exists(), "the planted clean filter is not live; the case would be vacuous"


def _load_by_path(datei, name):
    import importlib.util as ilu  # noqa: PLC0415
    spec = ilu.spec_from_file_location(name, datei)
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _outside_venv(tmp, name, extra_lines=()):
    """A virtual environment OUTSIDE the clone whose `.pth` makes the suite's site directories importable (the verifier
    needs `cryptography`) and adds `extra_lines`. -> (python, purelib)"""
    venv = tmp / name
    r = _run([sys.executable, "-m", "venv", "--without-pip", str(venv)], tmp)
    assert r.returncode == 0, r.stderr
    python = venv / "bin" / "python"
    sp = Path(_run([str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], tmp).stdout.strip())
    aussen = sorted({p for p in sys.path if p.endswith(("site-packages", "dist-packages")) and Path(p).is_dir()})
    (sp / "pb_outside.pth").write_text("".join(p + "\n" for p in (*aussen, *extra_lines)))
    return python, sp


class TestExternalReviewOf65d8f8cd:
    """The external review of 65d8f8cd and 40f52da4 (FIX_FIRST, 2026-10-02), one case per finding, each the case the
    review measured. Owner decision OA-afcb198da0 B: a regression test per finding with its catch proof, no further
    attack probes of our own. Every case below was run red against 40f52da4 with the fix removed and green with it; the
    numbers stand in the report of the round."""

    def test_F1_a_boolean_value_exempts_no_command_and_no_directory(self, welt):
        """F1, at the function as the review measured it: `filter.demo.clean=true`, `core.sshCommand=false` and
        `core.hooksPath=off` each came back `[]` at 40f52da4, because a boolean value was exempted for every key. The
        value of these keys IS the command or the directory. The control: `pager.status=false` switches paging off and
        names no program, so it stays free; an empty value names nothing."""
        repo, env, _priv, _kand, commit = welt
        mod = _load_by_path(repo / "scripts" / VERIFIER, "_f1_verifier")
        faelle = {"filter.demo.clean": "true", "core.sshCommand": "false", "core.hooksPath": "off"}
        for key, value in faelle.items():
            _git(["config", "--local", key, value], repo)
        _git(["config", "--local", "pager.status", "false"], repo)
        _git(["config", "--local", "filter.leer.clean", ""], repo)
        gefunden = {z.split("=", 1)[0].lower() for z in mod._git_configuration_selects_a_program(repo)}
        for key in faelle:
            assert key.lower() in gefunden, (key, sorted(gefunden))
        assert "pager.status" not in gefunden, ("a pager switched off names no program", sorted(gefunden))
        assert "filter.leer.clean" not in gefunden, sorted(gefunden)
        # END TO END: the same configuration refuses the run with exit 2; without it the good receipt verifies.
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and "select a program" in (res["reason"] or ""), roh
        for key in faelle:
            _git(["config", "--local", "--unset", key], repo)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    @staticmethod
    def _partial_clone(repo, marker):
        """`repo` turned into a partial clone whose promisor remote's transport program leaves `marker`."""
        programm = repo.parent / "_uploadpack_marker.sh"
        programm.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n")
        programm.chmod(0o700)
        for key, value in (("remote.origin.url", str(repo.parent / "_promisor_nowhere")),
                           ("remote.origin.promisor", "true"), ("extensions.partialClone", "origin"),
                           ("remote.origin.uploadpack", str(programm))):
            _git(["config", "--local", key, value], repo)

    def test_F3_no_object_is_read_from_a_partial_clone(self, welt):
        """F3, as the review measured it at d0e47397: in a partial clone, a missing object asked through the library's
        `git_objects` or the verifier's `_objekte` started the configured `remote.origin.uploadpack` (lazy fetch), and
        the whole verifier run left the marker before it answered NOT_MEASURABLE. Now both funnels refuse a partial
        clone before any object is read: no marker, and the verifier names the reason. The anti-vacuity half: a plain
        `git cat-file` in the same clone does start the program."""
        repo, env, _priv, _kand, commit = welt
        marker = repo.parent / "_marker_lazy_fetch"
        self._partial_clone(repo, marker)
        fehlt = "1" * 40
        _run(["git", "cat-file", "-p", fehlt], repo)
        assert marker.exists(), "the promisor transport is not live for a plain git; the case would be vacuous"
        marker.unlink()
        lib = _load_by_path(repo / "scripts" / "pre_tag_receipt_lib.py", "_f3_lib")
        with pytest.raises(lib.BaumNichtLesbar, match="partial clone"):
            lib.git_objects(repo, [(fehlt, "blob")])
        assert not marker.exists(), "the library's object read started the promisor transport"
        verifier = _load_by_path(repo / "scripts" / VERIFIER, "_f3_verifier")
        with pytest.raises(verifier._NichtDasObjekt, match="partial clone"):
            verifier._objekte(repo, [(fehlt, "blob")])
        assert not marker.exists(), "the verifier's object read started the promisor transport"
        # END TO END, with an object of the commit missing from the store, so a read of it would fetch.
        gate = _git(["rev-parse", f"{commit}:scripts/pre_tag_audit_gate.py"], repo)
        lose = repo / ".git" / "objects" / gate[:2] / gate[2:]
        assert lose.is_file(), "precondition: the gate blob is a loose object that can be taken out"
        lose.unlink()
        rc, res, roh = _verify(repo, env, commit)
        assert not marker.exists(), "a verifier run started the promisor transport"
        assert rc == 2 and res["reason"].startswith("the clone is a partial clone"), roh

    def test_F4_a_tracked_directory_replaced_by_a_link_refuses(self, welt):
        """F4, as the review measured it: the tracked directory `src/proofbundle` replaced by a symbolic link to an
        outside copy whose tracked files are byte-identical, with an extra `extra.py` behind the link. At 40f52da4 the
        byte comparison came back `[]` like the clean control and the run said VERIFIED; `git status` saw the exchange.
        The type of every committed path is compared first now. The control: the directory put back verifies."""
        repo, env, _priv, _kand, commit = welt
        paket = repo / "src" / "proofbundle"
        aussen = repo.parent / "_outside_proofbundle"
        shutil.copytree(paket, aussen, ignore=shutil.ignore_patterns("__pycache__"))
        (aussen / "extra.py").write_text("EXTRA = True\n")
        shutil.rmtree(paket)
        paket.symlink_to(aussen, target_is_directory=True)
        try:
            st = _run(["git", "status", "--porcelain", "--", "src"], repo)
            assert st.stdout.strip(), "precondition: git sees the exchanged directory"
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 2 and res["verdict"] == "NOT_MEASURABLE", roh
            assert "is not the commit" in res["reason"] and "symbolic link" in res["reason"], res["reason"]
        finally:
            paket.unlink()
            shutil.copytree(aussen, paket, ignore=shutil.ignore_patterns("__pycache__", "extra.py"))
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    def test_F5_under_isolation_a_startup_path_into_the_clone_refuses(self, welt, tmp_path):
        """F5: a `.pth` path line in an OUTSIDE virtual environment puts the clone on the search path at start, where
        the review saw a `sitecustomize.py` of the clone run under `python -I` although every prefix and site directory
        lay outside it. A check inside the started process cannot undo that; what it can see is the entry, which under
        `-I` no `PYTHONPATH` and no script directory put there. At 40f52da4 the run with that line verified (exit 0);
        now it is refused with exit 2. The control: the same environment without the line verifies."""
        repo, _env, _priv, _kand, good = welt
        mit, _sp = _outside_venv(tmp_path, "venv_with_clone_line", extra_lines=(str(repo),))
        r = _run([str(mit), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        res = json.loads(r.stdout)
        assert r.returncode == 2 and "search path at start" in res["reason"], r.stdout[-400:]
        ohne, _sp2 = _outside_venv(tmp_path, "venv_without_clone_line")
        r = _run([str(ohne), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        assert r.returncode == 0 and '"VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]

    def test_F5_GUARD_the_reviewed_sitecustomize_never_yields_a_verdict(self, welt, tmp_path):
        """F5, the review's own case: a `sitecustomize.py` at the top of the clone, reached through the `.pth` path line.
        It runs before the first line (the review measured it on CPython 3.12.14); the verifier cannot prevent that and
        must not give a verdict after it. GUARD: at 40f52da4 the tripwire for a loaded module of the checkout already
        refused it with exit 2, as the review saw. Where the start of the interpreter under test loads a `sitecustomize`
        from outside the clone first (measured on the Debian build of Python 3.10.12 here: its standard library's own),
        the clone's never runs; the case is measured to be absent on that interpreter and skips, naming the module that
        was loaded. The review ran it on CPython 3.12.14 (external review of d97f6e7b, R2-4: one measured build says
        nothing about every build of a distribution)."""
        repo, _env, _priv, _kand, good = welt
        marker = tmp_path / "_marker_sitecustomize"
        (repo / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').write('ran')\n")
        python, _sp = _outside_venv(tmp_path, "venv_reviewed_case", extra_lines=(str(repo),))
        probe = _run([str(python), "-I", "-c",
                      "import sys; m = sys.modules.get('sitecustomize'); print(getattr(m, '__file__', '') or '')"],
                     tmp_path, {"PATH": "/usr/bin:/bin"})
        geladen = probe.stdout.strip()
        if Path(geladen).resolve() != (repo / "sitecustomize.py").resolve():
            marker.unlink(missing_ok=True)
            pytest.skip(f"the case does not exist on this interpreter ({sys.version.split()[0]}): its start loaded the "
                        f"sitecustomize at {geladen or '(none)'}, so the clone's is never reached")
        marker.unlink(missing_ok=True)
        r = _run([str(python), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        assert marker.exists(), "the clone's sitecustomize did not run; the case would be vacuous"
        res = json.loads(r.stdout)
        assert r.returncode == 2 and res["verdict"] == "NOT_MEASURABLE", r.stdout[-400:]

    def test_F2_F5_the_texts_claim_no_more_than_is_checked(self):
        """F2 and F5, the texts: the review named sentences that described more than the code checks. The verifier's
        own description and RELEASE.md must state the startup search path as the reader's precondition, and must not
        say that an outside interpreter plus `-I` keeps every file of the checkout from running, that the clone's
        attributes are refused, or that the remaining git calls run no program."""
        texte = {"verifier": (SCRIPTS / VERIFIER).read_text(encoding="utf-8"),
                 "RELEASE.md": (REPO / "RELEASE.md").read_text(encoding="utf-8")}
        for name, text in texte.items():
            flach = " ".join(text.split())
            assert "no startup file of that interpreter names a directory of the clone" in flach, name
            for satz in ("plus ``-I``, no file of the checkout runs before the first line",
                         "plus `-I`, no file of the checkout runs before the first line",
                         "configuration or ``.git/info/attributes`` names a program",
                         "configuration or `.git/info/attributes` names a program",
                         "the remaining git calls read objects (`cat-file --batch`, `ls-tree`, `rev-parse`) and run no"):
                assert satz not in flach, (name, satz)


class TestExternalReviewRound2OfD97f6e7b:
    """The second external review, of 6e05e186, 48d58901 and d97f6e7b (FIX_FIRST, families NOT CONFIRMED, 2026-10-03), one
    case per finding, each the case the review named. Owner B on OA-4954d09148 and the rule of OA-0a507fd998 ("if he does
    not confirm them, A applies, with a fix of our own and a regression test before the tag"). Each case was run red with
    its fix removed and against the scripts of d97f6e7b, and green with the fix; the numbers stand in the round's report."""

    def test_R2_5_a_directory_that_cannot_be_listed_refuses(self, welt):
        """R2-5: `os.walk` without `onerror` dropped the error of a directory it could not list, so an uncommitted
        directory under `src/` that cannot be listed left no finding and the run went on to the library. Now that is an
        incomplete measurement: exit 2, before the library is loaded. The readable positive control: the same directory,
        listable, is refused for the module in it; without the directory the good receipt verifies."""
        import os  # noqa: PLC0415
        import stat  # noqa: PLC0415
        repo, env, _priv, _kand, commit = welt
        ordner = repo / "src" / "proofbundle" / "_nicht_gelistet"
        ordner.mkdir()
        (ordner / "modul.py").write_text("X = 1\n")
        ordner.chmod(stat.S_IWUSR | stat.S_IXUSR)                 # searchable, not listable
        try:
            try:
                os.listdir(ordner)
            except PermissionError:
                pass
            else:
                pytest.skip("this user can list a directory without its read bit (root?): the case does not exist here")
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 2 and res["verdict"] == "NOT_MEASURABLE", roh
            assert "cannot be listed" in res["reason"], res["reason"]
        finally:
            ordner.chmod(stat.S_IRWXU)
        rc, res, roh = _verify(repo, env, commit)                  # listable: the module itself is the finding
        assert rc == 2 and "not in the commit" in res["reason"], roh
        shutil.rmtree(ordner)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    def test_R2_1_a_hooks_path_of_white_space_or_empty_is_refused(self, welt):
        """R2-1: the value was stripped, so `core.hooksPath` of one space looked empty and came back `[]`; it names a real
        relative directory. A directory key is refused whenever it is set, even empty. The control: the funnel's own
        empty `core.fsmonitor`, which git reads as off, stays free."""
        repo, env, _priv, _kand, commit = welt
        mod = _load_by_path(repo / "scripts" / VERIFIER, "_r2_1_verifier")
        for wert in (" ", ""):
            _git(["config", "--local", "core.hooksPath", wert], repo)
            gefunden = mod._git_configuration_selects_a_program(repo)
            assert [z for z in gefunden if z.lower().startswith("core.hookspath=")], (repr(wert), gefunden)
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 2 and "select a program" in (res["reason"] or ""), (repr(wert), roh)
        _git(["config", "--local", "--unset", "core.hooksPath"], repo)
        # White space is not empty for a key whose EMPTY value git reads as off: `core.fsmonitor` of one space is a hook
        # path, not the switch. This is the half that catches a stripped comparison; `core.hooksPath` above is refused
        # with or without it.
        _git(["config", "--local", "core.fsmonitor", " "], repo)
        assert [z for z in mod._git_configuration_selects_a_program(repo) if z.lower().startswith("core.fsmonitor")]
        _git(["config", "--local", "core.fsmonitor", ""], repo)
        assert not [z for z in mod._git_configuration_selects_a_program(repo) if z.lower().startswith("core.fsmonitor")]
        _git(["config", "--local", "--unset", "core.fsmonitor"], repo)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    def test_R2_2_an_empty_remote_subsection_is_a_partial_clone(self, welt):
        """R2-2: `remote..promisor`, a remote with an EMPTY name, was not matched by `remote\\..+`; both funnels refuse it
        now before any object is read. Written into `.git/config` as git stores it (`[remote ""]`)."""
        repo, env, _priv, _kand, commit = welt
        with open(repo / ".git" / "config", "a", encoding="utf-8") as f:
            f.write('[remote ""]\n\tpromisor = true\n')
        assert "promisor" in _git(["config", "--local", "--get-regexp", "promisor"], repo), \
            "precondition: git reads the empty subsection"
        lib = _load_by_path(repo / "scripts" / "pre_tag_receipt_lib.py", "_r2_2_lib")
        with pytest.raises(lib.BaumNichtLesbar, match="partial clone"):
            lib.git_run(repo, "rev-parse", "HEAD")
        verifier = _load_by_path(repo / "scripts" / VERIFIER, "_r2_2_verifier")
        rc, _out, err = verifier._git(repo, "rev-parse", "HEAD")
        assert rc == 128 and "partial clone" in err, (rc, err)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and res["reason"].startswith("the clone is a partial clone"), roh

    def test_R2_families_named_by_the_review_are_refused(self, welt):
        """Question 2 of the review: `core.gitProxy`, `remote.origin.uploadpack`, `remote.origin.receivepack`,
        `remote.origin.vcs`, `difftool.demo.cmd` and a shell alias each came back `[]` at d97f6e7b. Each is refused now,
        at the function and, for one, end to end. Controls: a plain alias and the remote's URL name no program."""
        repo, env, _priv, _kand, commit = welt
        mod = _load_by_path(repo / "scripts" / VERIFIER, "_r2_families_verifier")
        faelle = {"core.gitProxy": "proxy-programm", "remote.origin.uploadpack": "upload-programm",
                  "remote.origin.receivepack": "receive-programm", "remote.origin.vcs": "fremd",
                  "difftool.demo.cmd": "diff-programm", "alias.lauf": "!touch marker"}
        for key, value in faelle.items():
            _git(["config", "--local", key, value], repo)
        _git(["config", "--local", "alias.st", "status"], repo)
        _git(["config", "--local", "remote.origin.url", str(repo.parent / "nirgends")], repo)
        gefunden = {z.split("=", 1)[0].lower() for z in mod._git_configuration_selects_a_program(repo)}
        for key in faelle:
            assert key.lower() in gefunden, (key, sorted(gefunden))
        assert "alias.st" not in gefunden and "remote.origin.url" not in gefunden, sorted(gefunden)
        for key in faelle:
            if key != "core.gitProxy":
                _git(["config", "--local", "--unset", key], repo)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and "core.gitproxy" in (res["reason"] or "").lower(), roh

    def test_R2_attributes_that_name_a_driver_are_refused_as_git_resolves_them(self, welt):
        """Owner OA-0a507fd998 A, as the review describes it: the EFFECTIVE attributes per path, including
        `.git/info/attributes`, a rule in a subdirectory's `.gitattributes` and a macro. At d97f6e7b a clone with
        unconfigured driver names verified (the review's own control); each of the three forms is refused now. Controls:
        built-in patterns and drivers (`diff=python`, `merge=union`), `-text` and a harmless macro still verify."""
        repo, env, _priv, _kand, commit = welt
        info = repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        unter = repo / "src" / "proofbundle" / ".gitattributes"
        faelle = {
            "info/attributes": lambda: (info / "attributes").write_text("*.py filter=boese\n"),
            "subdirectory rule": lambda: unter.write_text("signature.py diff=boese\n"),
            "macro": lambda: (info / "attributes").write_text("[attr]tarnung merge=boese\nscripts/*.py tarnung\n"),
        }
        for name, pflanze in faelle.items():
            pflanze()
            try:
                rc, res, roh = _verify(repo, env, commit)
                assert rc == 2 and "names a driver" in (res["reason"] or ""), (name, roh)
            finally:
                (info / "attributes").unlink(missing_ok=True)
                unter.unlink(missing_ok=True)
        (info / "attributes").write_text("[attr]harmlos -diff\n*.py diff=python merge=union\n*.md -text\n* harmlos\n")
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    def test_R2_3_R2_4_the_texts_claim_only_what_was_measured(self):
        """R2-3 and R2-4: the CHANGELOG names the refusal of the LISTED families, not of every program-selecting
        configuration; RESTRISIKO_620 no longer generalises one measured Debian build to every Debian and Ubuntu build."""
        changelog = " ".join((REPO / "CHANGELOG.md").read_text(encoding="utf-8").split())
        restrisiko = " ".join((REPO / "RESTRISIKO_620.md").read_text(encoding="utf-8").split())
        assert "selects a program from the listed families" in changelog
        assert "On Debian and Ubuntu builds" not in restrisiko
        assert "On the measured Debian build of Python 3.10.12" in restrisiko


class TestExternalReviewRound3Of12d5a7cb:
    """The third external review, of 813691c3, 0bfee205, f371ca79 and 12d5a7cb (FIX_FIRST, NOT CONFIRMED, 2026-10-03), one
    case per finding, each the case the review measured. Owner B on OA-a77da552f6. Each case was run red with its fix
    removed and against the scripts of 12d5a7cb, and green with the fix; the numbers stand in the round's report."""

    _NEUN = [(a, w) for a in ("filter", "diff", "merge") for w in ("set", "unset", "unspecified")]

    @staticmethod
    def _info(repo, text):
        info = repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text(text)

    def test_R3_1_a_driver_named_like_a_state_is_refused(self, welt):
        """R3-1: check-attr prints `set`, `unset` and `unspecified` both for the states and for a driver ASSIGNED that
        name, and at 12d5a7cb all nine assignments, and a macro `[attr]hidden filter=set`, came back VERIFIED. Each is
        refused now, also under the documented `python -I`. The controls, the real states `filter`, `-filter`,
        `!filter` and the built-ins `diff=python merge=union`, still verify."""
        repo, env, _priv, _kand, commit = welt
        for attribut, wert in self._NEUN:
            self._info(repo, f"*.py {attribut}={wert}\n")
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 2 and "a driver of that name, not the state" in (res["reason"] or ""), (attribut, wert, roh)
        self._info(repo, "[attr]hidden filter=set\n*.py hidden\n")
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and "a driver of that name, not the state" in (res["reason"] or ""), ("macro", roh)
        self._info(repo, "*.py filter=set\n")
        r = _run([sys.executable, "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", commit, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        assert r.returncode == 2 and '"NOT_MEASURABLE"' in r.stdout, ("-I", r.stdout[-300:])
        for zustand in ("*.py filter\n", "*.py -filter\n", "*.py !filter\n", "*.py diff=python merge=union\n"):
            self._info(repo, zustand)
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 0 and res["verdict"] == "VERIFIED", (zustand, roh)

    def test_R3_1_the_selection_is_not_left_to_a_changed_index(self, welt):
        """R3-1, the review's condition on the second question: it must cover every committed path and must not leave
        their choice to a changeable index. The pathspec query lists the INDEX; a committed file taken out of it (`git rm
        --cached`, the file still on disk and byte-identical) would escape it. Such an index refuses before anything is
        told apart; with the file back in the index the same attribute is refused as a driver."""
        repo, env, _priv, _kand, commit = welt
        self._info(repo, "signature.py filter=set\n")
        _git(["rm", "-q", "--cached", "src/proofbundle/signature.py"], repo)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and "the index does not list exactly the files of the commit" in (res["reason"] or ""), roh
        _git(["add", "src/proofbundle/signature.py"], repo)
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 2 and "a driver of that name, not the state" in (res["reason"] or ""), roh
        (repo / ".git" / "info" / "attributes").unlink()
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    def test_R3_5_a_warning_while_reading_the_attributes_refuses(self, welt):
        """R3-5: a `.git/info/attributes` over git's size limit is ignored with a warning and exit 0; at 12d5a7cb the empty
        answer passed and the run said VERIFIED. Any warning now refuses with git's diagnostic. The file is written
        sparse (git reads its size first), so it takes no space. Skipped, after measuring, where this git has no
        limit and prints no warning."""
        repo, env, _priv, _kand, commit = welt
        info = repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        with open(info / "attributes", "wb") as f:
            f.truncate(110 * 1024 * 1024)
        probe = _run(["git", "check-attr", "filter", "--", "scripts/" + VERIFIER], repo)
        if "overly large" not in probe.stderr:
            (info / "attributes").unlink()
            pytest.skip(f"this git prints no warning for a 110 MiB attributes file: {probe.stderr.strip()[:120]!r}")
        try:
            rc, res, roh = _verify(repo, env, commit)
            assert rc == 2 and "git warned while reading the attributes" in (res["reason"] or ""), roh
        finally:
            (info / "attributes").unlink()
        rc, res, roh = _verify(repo, env, commit)
        assert rc == 0 and res["verdict"] == "VERIFIED", roh

    def test_R3_3_R3_4_the_texts_say_what_the_code_does(self):
        """R3-3: CHANGELOG and RESTRISIKO_620 no longer say in the present tense that `.git/info/attributes` is not read,
        and R620-REV-OPEN-1 stays open. R3-4: neither RELEASE.md nor the refusal says that a fresh clone carries no
        such driver."""
        changelog = " ".join((REPO / "CHANGELOG.md").read_text(encoding="utf-8").split())
        restrisiko = " ".join((REPO / "RESTRISIKO_620.md").read_text(encoding="utf-8").split())
        release = " ".join((REPO / "RELEASE.md").read_text(encoding="utf-8").split())
        verifier = " ".join((SCRIPTS / VERIFIER).read_text(encoding="utf-8").split())
        # count, not `not in`: a failing `not in` over a whole file makes pytest diff the file, minutes per run
        assert changelog.count("`.git/info/attributes` is not read") == 0
        assert "The verifier now queries Git for the effective `filter`, `diff` and `merge` attributes" in changelog
        assert "At 65d8f8cd, `.git/info/attributes` was not read" in restrisiko
        assert "R620-REV-OPEN-1, OPEN until the review re-checks R3-1" in restrisiko
        assert release.count("straight from the forge carries no such setting") == 0
        assert "A fresh clone does not remove a driver selected by committed attributes." in verifier

    def test_R3_2_the_red_time_run_stays_reported_and_its_threshold_is_unchanged(self):
        """R3-2: the first full suite at 0bfee205 failed the time exponent of `renewal_ats_chain`; the review asked that
        the red run stay reported with its cause not established, and that the threshold not be loosened. The bound and
        the number of runs per curve point are the ones at d0e47397, and RESTRISIKO_620 carries the red run."""
        quelle = (REPO / "tests" / "test_budget_kostenkurve.py").read_text(encoding="utf-8")
        assert "\nEXPONENT_MAX = 1.2\n" in quelle
        assert "\nWIEDERHOLUNGEN = 3\n" in quelle
        restrisiko = " ".join((REPO / "RESTRISIKO_620.md").read_text(encoding="utf-8").split())
        assert ("The time exponent exceeded the limit in the first run under foreign load; isolated repeats at both "
                "heads and the full rerun passed, so the cause of the deviation is not conclusively established."
                ) in restrisiko


class TestCodexAt6d081424:
    """Codex on PR 311 at 6d081424 (review 5401710426, 2026-10-03), owner A on OA-a4cbf870f1: the P1 fixed as a class
    with a regression test for the case Codex measured, the P2 narrowed in the texts and recorded for 6.2.1. Each case
    was run red with its fix taken back and against the verifier of 6d081424; the numbers stand in the report."""

    def test_P1_a_startup_path_that_contains_the_clone_refuses(self, welt, tmp_path):
        """Thread 4173974268, the condition Codex named: a `.pth` line in an OUTSIDE virtual environment names the PARENT
        of the clone, not a directory of it. Under `python -I` that entry is on the search path at start, and a package
        lookup descends from it into the clone. At 6d081424 the check compared in one direction only and the run
        verified (exit 0); now it is refused with exit 2. The control: the same environment without the line verifies."""
        repo, _env, _priv, _kand, good = welt
        mit, _sp = _outside_venv(tmp_path, "venv_with_parent_line", extra_lines=(str(repo.parent),))
        r = _run([str(mit), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        res = json.loads(r.stdout)
        assert r.returncode == 2 and "search path at start" in res["reason"], r.stdout[-400:]
        assert "or one that contains it" in res["reason"], res["reason"][:300]
        ohne, _sp2 = _outside_venv(tmp_path, "venv_without_parent_line")
        r = _run([str(ohne), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        assert r.returncode == 0 and '"VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]

    def test_P1_the_path_cleaning_drops_an_entry_that_contains_the_clone(self, welt, monkeypatch):
        """Thread 4173974268, the second place Codex named: `_remove_the_judged_tree_from_sys_path` kept the parent of the
        clone, from which a module of the clone's name is importable. Now an entry that contains the checkout goes as
        well as one inside it; an entry beside the checkout stays (the control)."""
        repo, _env, _priv, _kand, _commit = welt
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_codex_6d08_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        daneben = repo.parent / "daneben"
        daneben.mkdir()
        monkeypatch.setattr(sys, "path", [str(repo.parent), str(repo / "src"), str(daneben), *sys.path])
        mod._remove_the_judged_tree_from_sys_path()
        aufgeloest = {str(Path(p).resolve()) for p in sys.path if p}
        assert str(repo.parent.resolve()) not in aufgeloest, "the parent of the clone stayed on the path"
        assert str((repo / "src").resolve()) not in aufgeloest, "a directory of the clone stayed on the path"
        assert str(daneben.resolve()) in aufgeloest, "an entry beside the clone was dropped"

    def test_P1_GUARD_codex_case_a_clone_named_sitecustomize_never_yields_a_verdict(self, welt, tmp_path):
        """Thread 4173974268, Codex's own case: the clone is called `sitecustomize`, the outside `.pth` names its parent,
        and an untracked `__init__.py` at the top of the clone runs at start and hides its origin. Where the interpreter
        under test finds a `sitecustomize` of its own first (measured on the Debian build of Python 3.10.12 here: its
        standard library's), the clone is never imported; the case is measured to be absent there and skips, naming the
        module that was loaded. Where it runs, the verifier must refuse with exit 2 and give no verdict."""
        repo, _env, _priv, _kand, good = welt
        eltern = tmp_path / "eltern"
        eltern.mkdir()
        klon = eltern / "sitecustomize"
        _git(["clone", "-q", str(repo), str(klon)], tmp_path)
        _git(["checkout", "-q", "--detach", good], klon)
        marker = tmp_path / "_marker_codex_6d08"
        (klon / "__init__.py").write_text(
            "import sys\n"
            f"open({str(marker)!r}, 'w').write('ran')\n"
            "sys.modules.pop('sitecustomize', None)\n")
        python, _sp = _outside_venv(tmp_path, "venv_codex_case", extra_lines=(str(eltern),))
        probe = _run([str(python), "-I", "-c", "print('probe')"], tmp_path, {"PATH": "/usr/bin:/bin"})
        if not marker.exists():
            stdlib = _run([str(python), "-I", "-c",
                           "import importlib.util as u; s = u.find_spec('sitecustomize'); print(getattr(s, 'origin', ''))"],
                          tmp_path, {"PATH": "/usr/bin:/bin"}).stdout.strip()
            pytest.skip(f"the case does not exist on this interpreter ({sys.version.split()[0]}): its start found the "
                        f"sitecustomize at {stdlib or '(none)'} first, so the clone is never imported ({probe.returncode})")
        marker.unlink()
        r = _run([str(python), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], klon, {"PATH": "/usr/bin:/bin"})
        assert marker.exists(), "the clone did not run as sitecustomize; the case would be vacuous"
        res = json.loads(r.stdout)
        assert r.returncode == 2 and res["verdict"] == "NOT_MEASURABLE", r.stdout[-400:]

    def test_P1_P2_the_texts_say_what_is_checked(self):
        """The reader's precondition names a directory that contains the clone (P1), and the attribute check is described
        for committed FILES with the gitlink named, with the open line for 6.2.1 in RESTRISIKO_620.md (P2)."""
        verifier = " ".join((SCRIPTS / VERIFIER).read_text(encoding="utf-8").split())
        release = " ".join((REPO / "RELEASE.md").read_text(encoding="utf-8").split())
        restrisiko = " ".join((REPO / "RESTRISIKO_620.md").read_text(encoding="utf-8").split())
        for name, text in (("verifier", verifier), ("RELEASE.md", release)):
            assert "names a directory of the clone or a directory that contains it" in text, name
        assert verifier.count("Every committed path whose EFFECTIVE") == 0
        assert "Every committed FILE (a blob, a symbolic link included)" in verifier
        assert "A gitlink is not asked." in verifier
        assert "(a gitlink is not asked)" in release
        assert "R620-CODEX-6D08-1, serious, fixed after 6d081424" in restrisiko
        assert "R620-CODEX-6D08-2, P2, open for 6.2.1" in restrisiko


class TestCodexAt553989ae:
    """Codex on PR 311 at 553989ae (review 5403492349, thread 4175430079, 2026-10-03): the containment helper made the
    filesystem root `/` into the prefix `//`, so a search path entry `/` was never found to contain the checkout. The
    fix is in the one helper every caller asks; the cases measure the helper against an independent containment and
    the two functions Codex named. A clone directly under the root is not built here; the condition is measured at
    the helper and at the functions, and end to end with the root on the search path."""

    @staticmethod
    def _pruefer(repo):
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_codex_5539_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX roots: drive and UNC roots are not generated here, "
                        "R620-CODEX-6CAB-2 for 6.2.1 (Codex on PR 311 at 6cab813e, thread 4175660289)")
    def test_P1_the_helper_agrees_with_an_independent_containment_over_generated_paths(self, welt):
        """Every pair of generated resolved paths, the root included, against `os.path.commonpath` as the oracle: `ort`
        is judged inside `wurzel` exactly when their common path is `wurzel`."""
        import os  # noqa: PLC0415
        repo, _env, _priv, _kand, _commit = welt
        mod = self._pruefer(repo)
        teile = ("", "a", "ab", "a/b", "a/bc", "ab/c", "a/b/c")
        orte = sorted({"/" + t for t in teile})
        geprueft = 0
        for wurzel in orte:
            for ort in orte:
                erwartet = os.path.commonpath([ort, wurzel]) == wurzel
                assert mod._judged_location(ort, wurzel) is erwartet, (ort, wurzel)
                geprueft += 1
        assert geprueft == len(orte) ** 2 == 49
        # ANTI-VACUITY: the generated set holds the case of the finding, the root containing every other path.
        assert all(mod._judged_location(o, "/") for o in orte)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX roots: drive and UNC roots are not generated here, "
                        "R620-CODEX-6CAB-2 for 6.2.1 (Codex on PR 311 at 6cab813e, thread 4175660289)")
    def test_P1_the_root_on_the_path_is_reported_at_start_and_dropped_by_the_cleaning(self, welt, monkeypatch):
        """Both functions Codex named, with `/` on the path: the startup path check under `-I` reports it, and the path
        cleaning drops it. The control: an entry beside the clone is neither reported nor dropped."""
        import types  # noqa: PLC0415
        repo, _env, _priv, _kand, _commit = welt
        mod = self._pruefer(repo)
        daneben = repo.parent / "daneben_5539"
        daneben.mkdir()
        monkeypatch.setattr(sys, "flags", types.SimpleNamespace(isolated=1))
        monkeypatch.setattr(sys, "path", ["/", str(daneben)])
        assert mod._startup_search_paths_into_the_checkout() == ["/"]
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(daneben)], sys.path

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX roots: drive and UNC roots are not generated here, "
                        "R620-CODEX-6CAB-2 for 6.2.1 (Codex on PR 311 at 6cab813e, thread 4175660289)")
    def test_P1_the_root_on_the_search_path_at_start_refuses(self, welt, tmp_path):
        """End to end: a `.pth` line in an outside virtual environment adds `/`, and under `python -I` the run is refused
        with exit 2. The control without the line verifies the good receipt."""
        repo, _env, _priv, _kand, good = welt
        mit, _sp = _outside_venv(tmp_path, "venv_with_root_line", extra_lines=("/",))
        r = _run([str(mit), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        res = json.loads(r.stdout)
        assert r.returncode == 2 and "search path at start" in res["reason"], r.stdout[-400:]
        ohne, _sp2 = _outside_venv(tmp_path, "venv_without_root_line")
        r = _run([str(ohne), "-I", "scripts/" + VERIFIER, "--repo", ".", "--commit", good, "--version", "5.0.0",
                  "--json"], repo, {"PATH": "/usr/bin:/bin"})
        assert r.returncode == 0 and '"VERIFIED"' in r.stdout, (r.stdout + r.stderr)[-400:]

    def test_P1_the_risk_sheet_records_the_root_case(self):
        """RESTRISIKO_620.md carries the finding with its state, and the verifier's helper names it."""
        verifier = " ".join((SCRIPTS / VERIFIER).read_text(encoding="utf-8").split())
        restrisiko = " ".join((REPO / "RESTRISIKO_620.md").read_text(encoding="utf-8").split())
        assert "R620-CODEX-5539-1, serious, fixed after 553989ae" in restrisiko
        assert "thread 4175430079" in verifier


class TestCodexAt6cab813e:
    """Codex on PR 311 at 6cab813e (review 5403733452, 2026-10-04): thread 4175660286 (P1), a second spelling of the same
    directory, as on a volume that does not tell upper from lower case, was no container, because the helper compared
    spellings only; thread 4175660289 (P2), the root cases above are POSIX roots. The helper now compares the identity
    of the directory when the spelling does not match. A volume without case distinction is not available here; two
    spellings of one directory are made with an alias, and a resolution that keeps the spelling is simulated."""

    @staticmethod
    def _pruefer(repo):
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_codex_6cab_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_P1_two_spellings_of_one_directory_are_one_container(self, welt, tmp_path):
        """The helper with two spellings of one directory, in both directions; the controls are a sibling directory
        and a directory whose name only starts like the container's."""
        repo, _env, _priv, _kand, _commit = welt
        mod = self._pruefer(repo)
        echt = tmp_path / "Echt"
        (echt / "child").mkdir(parents=True)
        alias = tmp_path / "alias"
        alias.symlink_to(echt, target_is_directory=True)
        (tmp_path / "Andere" / "child").mkdir(parents=True)
        (tmp_path / "EchtX" / "child").mkdir(parents=True)
        assert mod._judged_location(str(alias / "child"), str(echt))
        assert mod._judged_location(str(echt / "child"), str(alias))
        assert mod._judged_location(str(alias), str(echt))
        assert not mod._judged_location(str(tmp_path / "Andere" / "child"), str(echt))
        assert not mod._judged_location(str(tmp_path / "EchtX" / "child"), str(echt))
        assert not mod._judged_location(str(tmp_path), str(echt))

    def test_P1_a_second_spelling_on_the_path_is_reported_and_dropped(self, welt, tmp_path, monkeypatch):
        """Codex's condition at the two functions: the resolution keeps the spelling it was given (simulated), and a
        second spelling of the clone's parent is on the path. It is reported at start under -I and dropped by the path
        cleaning; an entry beside the clone stays."""
        import types  # noqa: PLC0415
        repo, _env, _priv, _kand, _commit = welt
        mod = self._pruefer(repo)
        zweite = tmp_path / "zweite_schreibweise"
        zweite.symlink_to(repo.parent, target_is_directory=True)
        daneben = tmp_path / "daneben_6cab"
        daneben.mkdir()
        wurzel = mod._checkout_root()
        monkeypatch.setattr(mod.os.path, "realpath", lambda p, *a, **k: mod.os.path.abspath(p))
        assert mod._checkout_root() == wurzel
        monkeypatch.setattr(sys, "flags", types.SimpleNamespace(isolated=1))
        monkeypatch.setattr(sys, "path", [str(zweite), str(daneben)])
        assert mod._startup_search_paths_into_the_checkout() == [str(zweite)]
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(daneben)], sys.path

    def test_P1_P2_the_risk_sheet_records_both_threads(self):
        """RESTRISIKO_620.md carries the P1 as fixed and the P2 as open for 6.2.1, and the helper names the P1."""
        verifier = " ".join((SCRIPTS / VERIFIER).read_text(encoding="utf-8").split())
        restrisiko = " ".join((REPO / "RESTRISIKO_620.md").read_text(encoding="utf-8").split())
        assert "R620-CODEX-6CAB-1, serious, fixed after 6cab813e" in restrisiko
        assert "R620-CODEX-6CAB-2, P3 on the tests, open for 6.2.1" in restrisiko
        assert "thread 4175660286" in verifier
