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
                # ANTI-VACUITY: through this entry a plain import takes the plant (the case of the first fix).
                _run([sys.executable, "-c", "import argparse"], repo if pp is None else repo.parent,
                     self._umgebung(repo, eintrag))
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
        directory of an interpreter installed in the clone included; an entry outside stays."""
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
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "path", [str(repo), str(repo / "tests"), str(repo / "scripts"), str(venv_sp),
                                          str(repo / "src"), str(aussen), ""])
        monkeypatch.setattr(sys, "prefix", str(repo / ".venv"))
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(aussen), ""], sys.path
        monkeypatch.chdir(repo)
        monkeypatch.setattr(sys, "path", ["", str(aussen)])
        mod._remove_the_judged_tree_from_sys_path()
        assert sys.path == [str(aussen)], "the empty entry is the working directory, here the checkout"

    def test_the_overlap_check_covers_both_directions(self, welt, monkeypatch):
        """At the function: a prefix or site directory IN the checkout counts, a checkout IN a site directory counts,
        a directory beside or above the checkout does not. Codex found both directions (prefix in the checkout, and
        the checkout in the interpreter's `purelib`)."""
        repo, _env, _priv, _kand, _commit = welt
        import importlib.util as ilu  # noqa: PLC0415
        spec = ilu.spec_from_file_location("_t6_overlap_verifier", repo / "scripts" / VERIFIER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        draussen = str(repo.parent / "elsewhere")
        # all prefixes outside, site dirs outside -> no overlap
        for name in ("prefix", "exec_prefix", "base_prefix", "base_exec_prefix"):
            monkeypatch.setattr(sys, name, draussen)
        monkeypatch.setattr(mod, "_interpreter_startaugen",
                            lambda: [("site", str(repo.parent / "venv" / "site-packages"))])
        assert mod._interpreter_overlaps_the_checkout() == []
        # a prefix above the checkout is not an overlap
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("sys.prefix", str(repo.parent))])
        assert mod._interpreter_overlaps_the_checkout() == [], "a directory above the checkout is not an overlap"
        # a prefix IN the checkout (a .venv in the clone)
        innen = str((repo / ".venv").resolve())
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("sys.prefix", innen)])
        assert mod._interpreter_overlaps_the_checkout() == [f"sys.prefix ({innen})"]
        # the checkout IN a site directory (a clone at the venv's purelib)
        obendrueber = str(repo.resolve().parent)
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("site", obendrueber)])
        assert mod._interpreter_overlaps_the_checkout() == [f"site ({obendrueber})"], \
            "the checkout inside a site directory is an overlap"
        # equal paths are an overlap
        gleich = str(repo.resolve())
        monkeypatch.setattr(mod, "_interpreter_startaugen", lambda: [("site", gleich)])
        assert mod._interpreter_overlaps_the_checkout() == [f"site ({gleich})"]

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
        }
        for key, value in familien.items():
            _git(["config", "--local", key, value], repo)
        _git(["config", "--local", "filter.empty.clean", ""], repo)       # empty: no program
        _git(["config", "--local", "core.ignoreCase", "false"], repo)     # not a program key
        gefunden = {z.split("=", 1)[0].lower() for z in mod._git_configuration_selects_a_program(repo)}
        for key in familien:
            assert key.lower() in gefunden, (key, sorted(gefunden))
        assert "filter.empty.clean" not in gefunden and "core.ignorecase" not in gefunden, sorted(gefunden)

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
        assert r.returncode == 2 and "local modification" in json.loads(r.stdout)["reason"], r.stdout[-400:]

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
