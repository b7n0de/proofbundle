"""The verifier block (P19, 6.1.0): which build produced a receipt, against which vector set.

THE QUESTION, measured on 2026-09-12 against v6.0.0: no receipt and no verify result carried the
version, wheel digest or build digest of the verifier that produced it; two wheels of the same
version were indistinguishable from the receipt. These tests hold the block that closes that,
and each closing has its counter-proof -- a block that cannot be refused is a field, not a bind.

Generator-hardened where a list would age: the validator is exercised by mutating ONE field of a
valid block at a time, from a table that names the mutation, and a positive control guards
against the validator degrading into a constant refusal.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from proofbundle import agent_review as AR
from proofbundle import dsse
from proofbundle import verifier_block as VB

REPO = Path(__file__).resolve().parents[1]
CONFORMANCE = REPO / "conformance"


def _key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return sk, sk.public_key().public_bytes_raw()


def _valid_block() -> dict:
    return {
        "implementation": "proofbundle", "version": "6.1.0",
        "build": {"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 77},
        "vectorSet": {"name": "proofbundle.conformance.manifest.v1",
                      "digest": {"sha256": "2" * 64}, "cases": 110},
        "testResult": {"predicateType": VB.TEST_RESULT_PREDICATE_TYPE, "result": "PASSED",
                       "statementDigest": {"sha256": "3" * 64}},
        "assurance": "selfDeclared",
    }


def _v02_predicate() -> dict:
    p = json.loads((CONFORMANCE / "agent_review"
                    / "agent-review-v02-positive-control-emitter-default-is-v02"
                    / "predicate.json").read_text(encoding="utf-8"))
    return p


# ── measuring the build ───────────────────────────────────────────────────────────────────────
class TestMeasureBuild:
    def test_the_running_package_has_a_measurable_identity(self):
        b = VB.measure_build()
        assert set(b) == {"digest", "source", "files"}
        assert VB._is_digest(b["digest"])
        assert b["source"] in VB.BUILD_SOURCES
        assert b["files"] >= 10

    def test_measuring_twice_gives_the_same_digest(self):
        assert VB.measure_build() == VB.measure_build()

    def test_a_source_tree_digest_moves_when_a_package_file_changes(self, tmp_path):
        """The digest is over the files, not over their names: one byte in one file moves it."""
        pkg = tmp_path / "proofbundle"
        shutil.copytree(REPO / "src" / "proofbundle", pkg,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        vorher = VB.measure_build(pkg)
        assert vorher["source"] == "source-tree", "a copied tree is not an installed distribution"
        (pkg / "__init__.py").write_text((pkg / "__init__.py").read_text() + "\n# one more byte\n")
        nachher = VB.measure_build(pkg)
        assert nachher["digest"] != vorher["digest"]
        assert nachher["files"] == vorher["files"]

    def test_bytecode_is_not_part_of_the_build_identity(self, tmp_path):
        pkg = tmp_path / "proofbundle"
        shutil.copytree(REPO / "src" / "proofbundle", pkg,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        vorher = VB.measure_build(pkg)
        (pkg / "__pycache__").mkdir()
        (pkg / "__pycache__" / "x.cpython-312.pyc").write_bytes(b"\0\1\2")
        assert VB.measure_build(pkg) == vorher

    def test_an_empty_package_directory_has_no_identity(self, tmp_path):
        leer = tmp_path / "proofbundle"
        leer.mkdir()
        with pytest.raises(VB.VerifierBlockError, match="no package files"):
            VB.measure_build(leer)

    def test_installed_record_rows_are_the_package_rows_only(self, tmp_path, monkeypatch):
        """The RECORD of a wheel install also lists console scripts whose bytes carry the venv's
        interpreter path. Only the `proofbundle/` rows identify the wheel, so only they count."""
        import importlib.metadata as im

        pkg = tmp_path / "site" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("__version__ = 'x'\n")
        echt = VB._record_digest_of(pkg / "__init__.py")
        record = ("../../../bin/proofbundle,sha256=AAAA,188\n"
                  f"proofbundle/__init__.py,sha256={echt},20\n"
                  "proofbundle-6.1.0.dist-info/RECORD,,\n")

        class Dist:
            def read_text(self, name):
                return record if name == "RECORD" else None

            def locate_file(self, rel):
                return tmp_path / "site" / rel

        monkeypatch.setattr(im, "distribution", lambda name: Dist())
        b = VB.measure_build(pkg)
        assert b["source"] == "installed-record"
        assert b["files"] == 1
        assert b["digest"]["sha256"] == hashlib.sha256(
            f"proofbundle/__init__.py\0{echt}".encode()).hexdigest()

    def test_bytecode_rows_in_record_do_not_hide_an_installed_build(self, tmp_path, monkeypatch):
        """LENS C, 2026-09-18, P0 -- executed against a real wheel: `pip install` compiles by default
        and writes `proofbundle/__pycache__/x.pyc,,` rows without a hash. The first draft read one
        such row as a package file without a hash and gave up on the whole listing, so every default
        install measured as `source-tree` and the block's one distinguishing property was dead."""
        import importlib.metadata as im

        pkg = tmp_path / "site" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("__version__ = 'x'\n")
        record = (f"proofbundle/__init__.py,sha256={VB._record_digest_of(pkg / '__init__.py')},20\n"
                  "proofbundle/__pycache__/__init__.cpython-310.pyc,,\n"
                  "proofbundle/policies/__pycache__/x.cpython-312.pyc,,\n"
                  "proofbundle-6.1.0.dist-info/RECORD,,\n")

        class Dist:
            def read_text(self, name):
                return record if name == "RECORD" else None

            def locate_file(self, rel):
                return tmp_path / "site" / rel

        monkeypatch.setattr(im, "distribution", lambda name: Dist())
        b = VB.measure_build(pkg)
        assert b["source"] == "installed-record", b
        assert b["files"] == 1
        # ANTI-PARITY: a package file (not bytecode) without a hash still refuses the RECORD path.
        record = "proofbundle/__init__.py,,\n"
        assert VB.measure_build(pkg)["source"] == "source-tree"

    def test_a_link_leaving_the_package_tree_is_refused_not_hashed(self, tmp_path):
        """LENS C, P1: a symlink out of the tree made the digest move with bytes outside the tree."""
        pkg = tmp_path / "proofbundle"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("__version__ = 'x'\n")
        aussen = tmp_path / "aussen.py"
        aussen.write_text("x = 1\n")
        (pkg / "link.py").symlink_to(aussen)
        with pytest.raises(VB.VerifierBlockError, match="outside the package"):
            VB.measure_build(pkg)

    def test_a_modified_installed_file_is_not_the_installed_build(self, tmp_path, monkeypatch):
        """Codex round one on PR 224, P1: an installed file edited in place while RECORD stayed
        untouched measured the identical installed-record digest, and `report` called it a MATCH.
        RECORD is what the installer wrote; the identity of the running build is the bytes."""
        import importlib.metadata as im

        pkg = tmp_path / "site" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("__version__ = 'x'\n")
        (pkg / "a.py").write_text("def f():\n    return 1\n")
        record = (f"proofbundle/__init__.py,sha256={VB._record_digest_of(pkg / '__init__.py')},20\n"
                  f"proofbundle/a.py,sha256={VB._record_digest_of(pkg / 'a.py')},22\n"
                  "proofbundle-6.1.0.dist-info/RECORD,,\n")

        class Dist:
            def read_text(self, name):
                return record if name == "RECORD" else None

            def locate_file(self, rel):
                return tmp_path / "site" / rel

        monkeypatch.setattr(im, "distribution", lambda name: Dist())
        vorher = VB.measure_build(pkg)
        assert vorher["source"] == "installed-record" and vorher["files"] == 2
        (pkg / "a.py").write_text("def f():\n    return 2  # modified in place\n")
        nachher = VB.measure_build(pkg)
        assert nachher["source"] == "source-tree", "a modified install is another build"
        assert nachher["digest"] != vorher["digest"]
        # a RECORD row whose file is gone is the same finding
        (pkg / "a.py").unlink()
        assert VB.measure_build(pkg)["source"] == "source-tree"

    def test_a_record_row_that_leaves_the_package_is_not_an_installed_file(self, tmp_path, monkeypatch):
        """Second reviewer, round 3, P2: `proofbundle/../elsewhere.py` passes the prefix filter and
        would be hashed outside the install. A row must name a file of the package."""
        import importlib.metadata as im

        pkg = tmp_path / "site" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("__version__ = 'x'\n")
        aussen = tmp_path / "site" / "elsewhere.py"
        aussen.write_text("def verify_ed25519(*a):\n    return True\n")
        record = (f"proofbundle/__init__.py,sha256={VB._record_digest_of(pkg / '__init__.py')},20\n"
                  f"proofbundle/../elsewhere.py,sha256={VB._record_digest_of(aussen)},40\n"
                  "proofbundle-6.1.0.dist-info/RECORD,,\n")

        class Dist:
            def read_text(self, name):
                return record if name == "RECORD" else None

            def locate_file(self, rel):
                return tmp_path / "site" / rel

        monkeypatch.setattr(im, "distribution", lambda name: Dist())
        b = VB.measure_build(pkg)
        assert b["source"] == "source-tree", "a RECORD that vouches for bytes outside the package is not the package"
        assert b["files"] == 1

    def test_an_editable_install_is_measured_as_a_source_tree(self, tmp_path, monkeypatch):
        """The distribution says the package is installed at A; the module on disk lives at B.
        That is an editable install or a checkout on PYTHONPATH -- the RECORD describes files
        that are not the ones running, so the tree is measured instead."""
        import importlib.metadata as im

        pkg = tmp_path / "checkout" / "proofbundle"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("__version__ = 'x'\n")

        class Dist:
            def read_text(self, name):
                return "proofbundle/__init__.py,sha256=BBBB,20\n"

            def locate_file(self, rel):
                return tmp_path / "elsewhere" / rel

        monkeypatch.setattr(im, "distribution", lambda name: Dist())
        assert VB.measure_build(pkg)["source"] == "source-tree"


# ── measuring the vector set ──────────────────────────────────────────────────────────────────
def _mini_corpus(root: Path, cases=("a", "b")) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(
        {"schema": "proofbundle.conformance.manifest.v1", "cases": list(cases)}))
    for c in cases:
        (root / c).mkdir(exist_ok=True)
        (root / c / "case.json").write_text(json.dumps({"caseId": c}))
    return root


class TestMeasureVectorSet:
    def test_the_real_corpus_is_measurable(self):
        vs = VB.measure_vector_set(CONFORMANCE)
        assert vs["name"] == "proofbundle.conformance.manifest.v1"
        assert VB._is_digest(vs["digest"])
        manifest = json.loads((CONFORMANCE / "manifest.json").read_text())
        assert vs["cases"] == len(manifest["cases"])

    def test_the_digest_covers_case_files_not_only_the_manifest(self, tmp_path):
        root = _mini_corpus(tmp_path / "c")
        vorher = VB.measure_vector_set(root)
        (root / "a" / "case.json").write_text(json.dumps({"caseId": "a", "changed": True}))
        assert VB.measure_vector_set(root)["digest"] != vorher["digest"], (
            "a case file changed and the manifest did not -- the digest must still move")

    def test_a_named_but_absent_case_is_refused(self, tmp_path):
        root = _mini_corpus(tmp_path / "c")
        shutil.rmtree(root / "b")
        with pytest.raises(VB.VerifierBlockError, match="absent"):
            VB.measure_vector_set(root)

    def test_an_empty_case_directory_is_refused(self, tmp_path):
        root = _mini_corpus(tmp_path / "c")
        (root / "b" / "case.json").unlink()
        with pytest.raises(VB.VerifierBlockError, match="no file"):
            VB.measure_vector_set(root)

    def test_two_spellings_of_one_case_directory_are_refused(self, tmp_path):
        """Codex round one on PR 224, P2: `['a', './a']` was accepted, hashed twice and counted as
        two cases. A case is a directory; uniqueness is judged on the resolved path."""
        root = tmp_path / "conformance"
        (root / "a").mkdir(parents=True)
        (root / "a" / "case.json").write_text("{}")
        for alias in ("./a", "a/../a"):
            (root / "manifest.json").write_text(json.dumps({"cases": ["a", alias]}))
            with pytest.raises(VB.VerifierBlockError, match="two spellings"):
                VB.measure_vector_set(root)
        (root / "b").symlink_to(root / "a")
        (root / "manifest.json").write_text(json.dumps({"cases": ["a", "b"]}))
        with pytest.raises(VB.VerifierBlockError, match="two spellings"):
            VB.measure_vector_set(root)
        # anti-parity: the single spelling measures one case
        (root / "manifest.json").write_text(json.dumps({"cases": ["a"]}))
        assert VB.measure_vector_set(root)["cases"] == 1

    def test_a_case_listed_twice_is_refused(self, tmp_path):
        """LENS C, P2: `cases` counted the listing, not the corpus."""
        root = _mini_corpus(tmp_path / "c", cases=("a", "b"))
        (root / "manifest.json").write_text(json.dumps(
            {"schema": "proofbundle.conformance.manifest.v1", "cases": ["a", "b", "a"]}))
        with pytest.raises(VB.VerifierBlockError, match="more than once"):
            VB.measure_vector_set(root)

    def test_a_link_leaving_the_corpus_is_refused_not_hashed(self, tmp_path):
        """LENS C, P1: the digest moved with bytes outside the corpus while every corpus byte stood."""
        root = _mini_corpus(tmp_path / "c")
        aussen = tmp_path / "aussen.json"
        aussen.write_text("{}")
        (root / "a" / "vector.json").symlink_to(aussen)
        with pytest.raises(VB.VerifierBlockError, match="outside the corpus"):
            VB.measure_vector_set(root)
        # a case DIRECTORY that is a link out of the corpus is refused as well
        (root / "a" / "vector.json").unlink()
        (root / "manifest.json").write_text(json.dumps(
            {"schema": "proofbundle.conformance.manifest.v1", "cases": ["a", "b", "weg"]}))
        (tmp_path / "anderswo").mkdir()
        (tmp_path / "anderswo" / "case.json").write_text("{}")
        (root / "weg").symlink_to(tmp_path / "anderswo")
        with pytest.raises(VB.VerifierBlockError, match="outside the corpus"):
            VB.measure_vector_set(root)

    def test_a_manifest_without_cases_is_refused(self, tmp_path):
        root = tmp_path / "c"
        root.mkdir()
        (root / "manifest.json").write_text(json.dumps({"schema": "x", "cases": []}))
        with pytest.raises(VB.VerifierBlockError, match="names no cases"):
            VB.measure_vector_set(root)


# ── the block's form ──────────────────────────────────────────────────────────────────────────
#: ONE mutation each, named. A refusal that depends on two defects at once proves neither.
_MUTATIONEN = {
    "unknown top-level field": lambda b: b.update({"wheelUrl": "https://x"}),
    "missing implementation": lambda b: b.pop("implementation"),
    "empty implementation": lambda b: b.update({"implementation": ""}),
    "missing version": lambda b: b.pop("version"),
    "version not a release": lambda b: b.update({"version": "latest"}),
    "missing build": lambda b: b.pop("build"),
    "build not an object": lambda b: b.update({"build": "1" * 64}),
    "build digest not sha256": lambda b: b["build"].update({"digest": {"sha256": "abc"}}),
    "build digest uppercase": lambda b: b["build"].update({"digest": {"sha256": "A" * 64}}),
    "build digest extra algorithm": lambda b: b["build"].update(
        {"digest": {"sha256": "1" * 64, "sha512": "2" * 128}}),
    "build source unknown": lambda b: b["build"].update({"source": "wheel"}),
    "build files zero": lambda b: b["build"].update({"files": 0}),
    "build files boolean": lambda b: b["build"].update({"files": True}),
    "build unknown field": lambda b: b["build"].update({"wheel": "x.whl"}),
    "vectorSet not an object": lambda b: b.update({"vectorSet": "corpus"}),
    "vectorSet missing digest": lambda b: b["vectorSet"].pop("digest"),
    "vectorSet digest not sha256": lambda b: b["vectorSet"].update({"digest": {"sha256": "z" * 64}}),
    "vectorSet cases zero": lambda b: b["vectorSet"].update({"cases": 0}),
    "vectorSet unknown field": lambda b: b["vectorSet"].update({"url": "x"}),
    "testResult wrong predicate type": lambda b: b["testResult"].update(
        {"predicateType": "https://slsa.dev/verification_summary/v1"}),
    "testResult result outside the three values": lambda b: b["testResult"].update({"result": "PARTIAL"}),
    "testResult digest not sha256": lambda b: b["testResult"].update({"statementDigest": {"sha256": ""}}),
    "testResult unknown field": lambda b: b["testResult"].update({"url": "x"}),
    "assurance raised": lambda b: b.update({"assurance": "runnerObserved"}),
    "assurance missing": lambda b: b.pop("assurance"),
}


class TestValidateVerifierBlock:
    def test_positive_control_a_valid_block_validates(self):
        assert VB.validate_verifier_block(_valid_block()) == []

    def test_a_block_without_the_optional_parts_validates(self):
        b = _valid_block()
        del b["vectorSet"]
        del b["testResult"]
        del b["build"]["files"]
        assert VB.validate_verifier_block(b) == []

    @pytest.mark.parametrize("name", sorted(_MUTATIONEN))
    def test_each_single_defect_is_refused(self, name):
        b = _valid_block()
        _MUTATIONEN[name](b)
        errs = VB.validate_verifier_block(b)
        assert errs, f"{name}: the block was accepted with the defect in place"

    def test_a_non_object_is_refused(self):
        assert VB.validate_verifier_block("proofbundle 6.1.0")
        assert VB.validate_verifier_block(None)

    def test_build_verifier_block_refuses_to_assemble_an_invalid_one(self):
        with pytest.raises(VB.VerifierBlockError):
            VB.build_verifier_block(build={"digest": {"sha256": "nope"}, "source": "source-tree"},
                                    version="6.1.0")

    def test_measure_verifier_block_assembles_what_this_process_can_measure(self):
        b = VB.measure_verifier_block(conformance_dir=CONFORMANCE)
        assert VB.validate_verifier_block(b) == []
        assert b["build"] == VB.measure_build()
        assert b["vectorSet"] == VB.measure_vector_set(CONFORMANCE)
        assert "testResult" not in b, "no statement was given, so no reference is invented"
        assert VB.measure_verifier_block().get("vectorSet") is None, (
            "without a corpus the block names the build and says nothing about a vector set")


# ── the test-result statement and the join ────────────────────────────────────────────────────
def _results(*triples):
    return [{"caseId": c, "ok": ok, "scope": scope} for c, ok, scope in triples]


class TestTestResultStatement:
    def _stmt(self, results=None):
        # `is None`, not `or`: an EMPTY list is a case of its own and must reach the function.
        if results is None:
            results = _results(("a", True, "full"), ("b", True, "full"))
        return VB.build_test_result_statement(
            build=_valid_block()["build"], vector_set=_valid_block()["vectorSet"],
            results=results, version="6.1.0")

    def test_the_statement_has_the_in_toto_shape_and_the_build_as_subject(self):
        s = self._stmt()
        assert s["_type"] == VB.STATEMENT_TYPE
        assert s["predicateType"] == VB.TEST_RESULT_PREDICATE_TYPE
        assert s["subject"] == [{"name": "proofbundle-6.1.0", "digest": {"sha256": "1" * 64}}]
        assert s["predicate"]["configuration"][0]["digest"] == {"sha256": "2" * 64}
        assert s["predicate"]["configuration"][0]["annotations"]["cases"] == 110
        assert VB.validate_test_result_statement(s) == []

    def test_result_mapping_follows_the_corpus_rule_a_skipped_check_is_never_a_pass(self):
        assert self._stmt()["predicate"]["result"] == "PASSED"
        w = self._stmt(_results(("a", True, "full"), ("b", True, "partial")))
        assert w["predicate"]["result"] == "WARNED" and w["predicate"]["warnedTests"] == ["b"]
        n = self._stmt(_results(("a", True, "none")))
        assert n["predicate"]["result"] == "WARNED"
        f = self._stmt(_results(("a", True, "full"), ("b", False, "full"), ("c", True, "partial")))
        assert f["predicate"]["result"] == "FAILED"
        assert f["predicate"]["failedTests"] == ["b"] and f["predicate"]["warnedTests"] == ["c"]

    def test_no_results_is_refused(self):
        with pytest.raises(VB.VerifierBlockError, match="at least one"):
            self._stmt([])

    def test_a_result_without_a_case_id_is_refused(self):
        with pytest.raises(VB.VerifierBlockError, match="caseId"):
            self._stmt([{"ok": True, "scope": "full"}])

    def test_the_reference_and_the_join_close(self):
        s = self._stmt()
        ref = VB.test_result_ref(s)
        assert ref["result"] == "PASSED" and ref["statementDigest"]["sha256"] == VB.statement_digest(s)
        b = VB.build_verifier_block(build=_valid_block()["build"], version="6.1.0",
                                    vector_set=_valid_block()["vectorSet"], test_result=ref)
        j = VB.join_test_result(b, s)
        assert j["ok"] and not j["errors"], j

    def test_the_join_fails_on_another_build_and_on_a_tampered_statement_and_on_another_result(self):
        s = self._stmt()
        b = VB.build_verifier_block(build=_valid_block()["build"], version="6.1.0",
                                    vector_set=_valid_block()["vectorSet"],
                                    test_result=VB.test_result_ref(s))
        andere = copy.deepcopy(s)
        andere["subject"][0]["digest"] = {"sha256": "9" * 64}
        j1 = VB.join_test_result(b, andere)
        assert not j1["ok"] and not j1["subject_matches_build"]
        manipuliert = copy.deepcopy(s)
        manipuliert["predicate"]["passedTests"].append("c")
        j2 = VB.join_test_result(b, manipuliert)
        assert not j2["ok"] and not j2["digest_matches"] and j2["subject_matches_build"]
        b3 = copy.deepcopy(b)
        b3["testResult"]["result"] = "FAILED"
        j3 = VB.join_test_result(b3, s)
        assert not j3["ok"] and not j3["result_matches"]

    def test_the_join_fails_when_the_statement_ran_another_vector_set(self):
        """un-review 2026-09-18, P1: subject, digest and result agreed, and the statement was
        about corpus A while the block declared corpus B. The fourth equality closes that."""
        s = self._stmt()
        b = VB.build_verifier_block(build=_valid_block()["build"], version="6.1.0",
                                    vector_set=_valid_block()["vectorSet"],
                                    test_result=VB.test_result_ref(s))
        # the block declares another corpus; the reference (digest, result) still matches
        b["vectorSet"] = {"name": "another-corpus", "digest": {"sha256": "8" * 64}, "cases": 3}
        j = VB.join_test_result(b, s)
        assert not j["ok"] and not j["vector_set_matches"], j
        assert j["subject_matches_build"] and j["digest_matches"] and j["result_matches"]
        assert any("vector set" in e for e in j["errors"])
        # same case count, different digest -- still another corpus
        b["vectorSet"] = {"name": "another-corpus", "digest": {"sha256": "8" * 64}, "cases": 110}
        assert not VB.join_test_result(b, s)["ok"]

    def test_a_result_that_its_own_lists_contradict_is_refused(self):
        """Codex round one on PR 224, P1: `result: PASSED` beside `failedTests: [...]` validated
        clean. The headline is derived from the lists; a case in two lists is the same defect."""
        s = self._stmt()
        assert VB.validate_test_result_statement(s) == []
        p = s["predicate"]
        p["failedTests"] = ["definitely-failed"]
        errs = VB.validate_test_result_statement(s)
        assert any("contradicts its own case lists" in e and "'FAILED'" in e for e in errs), errs
        p["failedTests"] = []
        p["warnedTests"] = ["ran-partially"]
        assert any("derive 'WARNED'" in e for e in VB.validate_test_result_statement(s))
        p["result"] = "WARNED"
        assert VB.validate_test_result_statement(s) == []
        p["passedTests"] = ["ran-partially"]
        assert any("more than one outcome" in e for e in VB.validate_test_result_statement(s))

    def test_a_statement_that_names_no_case_is_not_a_test_result(self):
        """Second reviewer, round 3, P1: three empty lists derived PASSED. Evidence of nothing is
        not evidence of success; the builder already refuses empty results, the validator now too."""
        s = self._stmt()
        p = s["predicate"]
        p["passedTests"], p["warnedTests"], p["failedTests"] = [], [], []
        errs = VB.validate_test_result_statement(s)
        assert any("names no case" in e for e in errs), errs
        for result in ("WARNED", "FAILED"):
            p["result"] = result
            assert any("names no case" in e for e in VB.validate_test_result_statement(s))
        # anti-parity: one named case makes it a result again
        p["result"], p["passedTests"] = "PASSED", ["one-case"]
        assert VB.validate_test_result_statement(s) == []

    def test_a_configuration_entry_without_the_case_count_does_not_join(self):
        """un round 2 (2026-09-18, P1): the case count was read with the block's own count as the
        default, so a configuration entry without `annotations` matched by construction. Both
        halves of the vector-set equality are required now."""
        s = self._stmt()
        b = VB.build_verifier_block(build=_valid_block()["build"], version="6.1.0",
                                    vector_set=_valid_block()["vectorSet"],
                                    test_result=VB.test_result_ref(s))
        assert VB.join_test_result(b, s)["ok"], "positive control: the untouched statement joins"
        s["predicate"]["configuration"][0].pop("annotations")
        b["testResult"] = VB.test_result_ref(s)          # the reference follows the new bytes
        j = VB.join_test_result(b, s)
        assert j["digest_matches"] and not j["vector_set_matches"] and not j["ok"], j
        assert any("vector set" in e for e in j["errors"])
        # a wrong count under the right digest is refused just the same
        s["predicate"]["configuration"][0]["annotations"] = {"cases": 3}
        b["testResult"] = VB.test_result_ref(s)
        assert not VB.join_test_result(b, s)["vector_set_matches"]

    def test_a_block_that_cites_a_run_must_declare_its_vector_set(self):
        b = _valid_block()
        del b["vectorSet"]
        errs = VB.validate_verifier_block(b)
        assert errs and any("testResult without vectorSet" in e for e in errs)

    def test_a_block_without_a_reference_cannot_be_joined(self):
        b = _valid_block()
        del b["testResult"]
        j = VB.join_test_result(b, self._stmt())
        assert not j["ok"] and "cites no test result" in j["errors"][0]

    def test_the_statement_digest_is_over_the_object_not_the_file(self):
        s = self._stmt()
        assert VB.statement_digest(s) == VB.statement_digest(json.loads(json.dumps(s, indent=4)))

    def test_signing_produces_a_dsse_envelope_that_verifies(self):
        sk, pk = _key()
        s = self._stmt()
        env = VB.sign_test_result_statement(s, sk)
        assert dsse.verify_envelope(env, pk, payload_type=VB.INTOTO_STATEMENT_PAYLOAD_TYPE)
        assert json.loads(dsse.load_payload(env)) == s
        assert not dsse.verify_envelope(env, bytes(32), payload_type=VB.INTOTO_STATEMENT_PAYLOAD_TYPE)

    def test_an_invalid_statement_is_not_signed(self):
        sk, _pk = _key()
        s = self._stmt()
        s["predicate"]["result"] = "MAYBE"
        with pytest.raises(VB.VerifierBlockError):
            VB.sign_test_result_statement(s, sk)


# ── in the receipt: emit, verify, report ──────────────────────────────────────────────────────
class TestInTheReceipt:
    def _roundtrip(self, predicate):
        """Emit, then read through the dispatcher: the version follows the object (v0.3 with a
        block, v0.2 without), and the dispatcher routes by the predicateType the emitter chose."""
        sk, pk = _key()
        env = AR.emit_agent_review(predicate, sk)
        return AR.verify_agent_review_any(env, pk, expected_subject_digest=AR._subject_digest(predicate),
                                          policy=AR.load_policy())

    @staticmethod
    def _predicate_type_of(env):
        return json.loads(base64.b64decode(env["payload"]))["predicateType"]

    def test_the_emitter_picks_v03_exactly_when_the_block_is_present(self):
        sk, _pk = _key()
        mit = AR.emit_agent_review(VB.attach(_v02_predicate(), _valid_block()), sk)
        ohne = AR.emit_agent_review(_v02_predicate(), sk)
        assert self._predicate_type_of(mit) == AR.AGENT_REVIEW_PREDICATE_TYPE_V03
        assert self._predicate_type_of(ohne) == AR.AGENT_REVIEW_PREDICATE_TYPE_V02
        assert AR.AGENT_REVIEW_PREDICATE_TYPE_V03.endswith("/agent-review/v0.3")

    def test_a_v02_typed_receipt_carrying_the_block_is_refused_by_every_verifier(self):
        """THE MEASUREMENT THAT MADE THE BLOCK A VERSION. Hand-built past the emitter: v0.2 type,
        block inside. 6.0.0 refuses it (unknown producer field); so must 6.1.0, under the same
        type, or the same bytes would carry two verdicts."""
        p = VB.attach(_v02_predicate(), _valid_block())
        sk, pk = _key()
        stmt = {"_type": AR.STATEMENT_TYPE,
                "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
                "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V02, "predicate": p}
        env = dsse.sign_envelope(AR._rfc8785_bytes(stmt), sk, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
        kw = {"expected_subject_digest": AR._subject_digest(p), "policy": AR.load_policy()}
        r02 = AR.verify_agent_review_v02(env, pk, **kw)
        assert r02["ok"] is False and r02["structure_ok"] is False
        assert any("producer.verifier is not an allowed field" in e for e in r02["errors"])
        assert r02["verifier_block"] is None, "a refused block is not reported as if it were read"
        r03 = AR.verify_agent_review_v03(env, pk, **kw)
        assert r03["ok"] is False and r03["predicate_type_ok"] is False
        assert "UNKNOWN_PREDICATE_VERSION" in r03["reason_codes"]
        assert any("use verify_agent_review_v02" in e for e in r03["errors"])
        rany = AR.verify_agent_review_any(env, pk, **kw)
        assert rany["ok"] is False and rany["predicateVersionStatus"] == "current"
        # ANTI-PARITY: the same predicate under the type the emitter would choose is valid.
        stmt["predicateType"] = AR.AGENT_REVIEW_PREDICATE_TYPE_V03
        env3 = dsse.sign_envelope(AR._rfc8785_bytes(stmt), sk, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
        assert AR.verify_agent_review_v03(env3, pk, **kw)["ok"] is True

    def test_the_v03_verifier_refuses_a_v02_receipt_with_a_pointer_and_v01_too(self):
        sk, pk = _key()
        p = _v02_predicate()
        env = AR.emit_agent_review(p, sk)
        r = AR.verify_agent_review_v03(env, pk, expected_subject_digest=AR._subject_digest(p),
                                       policy=AR.load_policy())
        assert r["ok"] is False and r["predicate_type_ok"] is False
        assert "UNKNOWN_PREDICATE_VERSION" in r["reason_codes"]
        assert any("use verify_agent_review_v03" not in e and "use verify_agent_review_v02" in e
                   for e in r["errors"])
        v01 = json.loads((CONFORMANCE / "agent_review"
                          / "agent-review-counter-proof-verifier-block-is-not-a-v01-field"
                          / "predicate.json").read_text(encoding="utf-8"))
        del v01["producer"]["verifier"]
        env1 = AR.emit_agent_review(v01, sk, legacy_v01=True)
        r1 = AR.verify_agent_review_v03(env1, pk, expected_subject_digest=AR._subject_digest(v01))
        assert r1["ok"] is False and "UNKNOWN_PREDICATE_VERSION" in r1["reason_codes"]
        assert any("this is the v0.3 verifier" in e for e in r1["errors"])

    def test_the_predicate_validator_gives_the_block_errors_one_reason_code(self):
        p = VB.attach(_v02_predicate(), _valid_block())
        p["producer"]["verifier"]["assurance"] = "independentlyWitnessed"
        errs = AR.validate_agent_review_v03_predicate(p, strict=True)
        assert errs and all(str(e).startswith("producer.verifier: ") for e in errs)
        assert {getattr(e, "code", None) for e in errs} == {"PRODUCER_VERIFIER_BLOCK_INVALID"}
        # v0.2 never reaches the block's validator: the field itself is unknown there.
        errs02 = AR.validate_agent_review_v02_predicate(p, strict=True)
        assert errs02 == ["producer.verifier is not an allowed field"]

    def test_the_render_switch_reads_a_block_as_v03(self):
        p = VB.attach(_v02_predicate(), _valid_block())
        AR.require_valid_agent_review_predicate_any(p)          # v0.3 rules, passes
        p["producer"]["verifier"]["build"]["digest"]["sha256"] = "nope"
        with pytest.raises(AR.AgentReviewError, match="agent-review/v0.3"):
            AR.require_valid_agent_review_predicate_any(p)

    def test_an_internal_error_result_carries_the_same_keys_as_every_other_result(self, monkeypatch):
        """Lens B, 2026-09-18: the except path built from the bare v0.1 skeleton and lost the v0.2
        keys -- a consumer reading `event_time_status` on an internal_error result got KeyError."""
        def _boom(*_a, **_k):
            raise RuntimeError("planted")
        monkeypatch.setattr(AR, "_verify_v02_inner", _boom)
        sk, pk = _key()
        env = AR.emit_agent_review(_v02_predicate(), sk)
        for verifier in (AR.verify_agent_review_v02, AR.verify_agent_review_v03):
            r = verifier(env, pk)
            assert r["ok"] is False and r["reason_code"] == "internal_error"
            assert r["event_time_status"] == "NOT_EVALUATED" and r["verifier_block"] is None
            assert getattr(r["errors"][0], "code", None) == "internal_error"

    def test_a_measured_block_travels_through_emit_and_verify_and_names_this_build(self):
        p = VB.attach(_v02_predicate(), VB.measure_verifier_block(conformance_dir=CONFORMANCE))
        r = self._roundtrip(p)
        assert r["ok"] is True, r["errors"]
        vb = r["verifier_block"]
        assert vb["present"] and vb["valid"]
        assert vb["build_digest"] == VB.measure_build()["digest"]["sha256"]
        assert vb["vector_set_cases"] == VB.measure_vector_set(CONFORMANCE)["cases"]
        assert vb["matches_this_verifier"] == "MATCH"

    def test_a_block_naming_another_build_is_reported_as_mismatch_and_stays_valid(self):
        p = VB.attach(_v02_predicate(), _valid_block())
        r = self._roundtrip(p)
        assert r["ok"] is True, "a receipt from another build is not thereby invalid"
        assert r["verifier_block"]["matches_this_verifier"] == "MISMATCH"
        assert r["verifier_block"]["test_result"] == "PASSED"

    def test_without_a_block_nothing_is_evaluated_and_ok_is_unaffected(self):
        """Two shapes of absence, kept apart. A v0.2 receipt has no block axis at all -- the
        version does not know the field -- so `verifier_block` is None there. A v0.3 receipt
        without a block (valid: the field is optional) reports absence, and NOT_EVALUATED is
        not a pass."""
        r = self._roundtrip(_v02_predicate())
        assert r["ok"] is True and r["verifier_block"] is None
        p = _v02_predicate()
        sk, pk = _key()
        stmt = {"_type": AR.STATEMENT_TYPE,
                "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
                "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V03, "predicate": p}
        env = dsse.sign_envelope(AR._rfc8785_bytes(stmt), sk, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
        r3 = AR.verify_agent_review_v03(env, pk, expected_subject_digest=AR._subject_digest(p),
                                        policy=AR.load_policy())
        assert r3["ok"] is True
        assert r3["verifier_block"] == {
            "present": False, "valid": None, "implementation": None, "version": None,
            "build_digest": None, "build_source": None, "vector_set_digest": None,
            "vector_set_cases": None, "test_result": None,
            "matches_this_verifier": "NOT_EVALUATED", "errors": []}

    def test_a_malformed_block_is_a_structural_error_at_emit_and_at_verify(self):
        p = VB.attach(_v02_predicate(), _valid_block())
        p["producer"]["verifier"]["assurance"] = "independentlyWitnessed"
        sk, pk = _key()
        with pytest.raises(AR.AgentReviewError, match="producer.verifier"):
            AR.emit_agent_review(p, sk)
        # hand-built past the emitter: the v0.3 verifier still refuses it, with the code
        stmt = {"_type": AR.STATEMENT_TYPE,
                "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
                "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V03, "predicate": p}
        env = dsse.sign_envelope(AR._rfc8785_bytes(stmt), sk, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = AR.verify_agent_review_v03(env, pk, expected_subject_digest=AR._subject_digest(p),
                                       policy=AR.load_policy())
        assert r["ok"] is False and r["structure_ok"] is False
        assert any("producer.verifier" in e for e in r["errors"])
        assert "PRODUCER_VERIFIER_BLOCK_INVALID" in r["reason_codes"]

    def test_v01_does_not_know_the_block_and_refuses_it(self):
        sk, _pk = _key()
        v01 = json.loads((CONFORMANCE / "agent_review"
                          / "agent-review-counter-proof-verifier-block-is-not-a-v01-field"
                          / "predicate.json").read_text(encoding="utf-8"))
        assert "verifier" in v01["producer"]
        with pytest.raises(AR.AgentReviewError, match="producer.verifier is not an allowed field"):
            AR.emit_agent_review(v01, sk, legacy_v01=True)
        # ANTI-PARITY: the same predicate without the block is a valid v0.1 predicate.
        del v01["producer"]["verifier"]
        AR.emit_agent_review(v01, sk, legacy_v01=True)

    def test_attach_refuses_an_invalid_block_and_a_non_object_producer(self):
        with pytest.raises(VB.VerifierBlockError):
            VB.attach(_v02_predicate(), {"implementation": "x"})
        p = _v02_predicate()
        p["producer"] = "someone"
        with pytest.raises(VB.VerifierBlockError, match="producer must be an object"):
            VB.attach(p, _valid_block())

    def test_a_valid_block_is_reported_even_when_the_statement_is_refused_for_another_reason(self):
        """Lens A (2026-09-18, P1): the report is a report. A v0.3 receipt whose statement is
        refused for a reason unrelated to the block (a wrong subject name) still names the
        build that produced it; before the fix `verifier_block` was None there."""
        p = VB.attach(_v02_predicate(), _valid_block())
        sk, pk = _key()
        stmt = {"_type": AR.STATEMENT_TYPE,
                "subject": [{"name": "not-the-subject-name", "digest": {"sha256": AR._subject_digest(p)}}],
                "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V03, "predicate": p}
        env = dsse.sign_envelope(AR._rfc8785_bytes(stmt), sk, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = AR.verify_agent_review_v03(env, pk, expected_subject_digest=AR._subject_digest(p),
                                       policy=AR.load_policy())
        assert r["ok"] is False and r["statement_shape_ok"] is False
        vb = r["verifier_block"]
        assert vb is not None and vb["present"] and vb["valid"]
        assert vb["build_digest"] == _valid_block()["build"]["digest"]["sha256"]
        assert vb["matches_this_verifier"] == "MISMATCH"
        # and under v0.2 the same defect leaves the field None: the version does not know the block
        stmt["predicateType"] = AR.AGENT_REVIEW_PREDICATE_TYPE_V02
        env2 = dsse.sign_envelope(AR._rfc8785_bytes(stmt), sk, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
        assert AR.verify_agent_review_v02(env2, pk)["verifier_block"] is None

    def test_the_v01_result_skeleton_is_untouched(self):
        """`_empty_result` is byte-pinned to 5.1.0; the block's field lives on the v0.2/v0.3 path only."""
        assert "verifier_block" not in AR._empty_result()


# ── the runner writes the separate object ─────────────────────────────────────────────────────
class TestRunnerWritesTheStatement:
    def test_run_conformance_writes_a_statement_that_joins_a_measured_block(self, tmp_path):
        """The real corpus, the real runner, the real switch. The statement's subject is the build
        that ran it, and a block measured by that build joins it -- the whole chain, once."""
        import subprocess
        import sys

        runner = REPO / "conformance" / "run_conformance.py"
        if not runner.is_file():
            pytest.skip("conformance/run_conformance.py is not here")
        ziel = tmp_path / "statement.json"
        r = subprocess.run([sys.executable, str(runner), "--test-result-out", str(ziel)],
                           cwd=str(REPO), capture_output=True, text=True, timeout=900)
        assert ziel.is_file(), f"no statement written (rc={r.returncode}):\n{r.stdout[-800:]}\n{r.stderr[-800:]}"
        s = json.loads(ziel.read_text(encoding="utf-8"))
        assert VB.validate_test_result_statement(s) == []
        assert "test-result statement ->" in r.stdout
        block = VB.measure_verifier_block(conformance_dir=CONFORMANCE, test_result_statement=s)
        j = VB.join_test_result(block, s)
        assert j["ok"], j
        assert s["subject"][0]["digest"] == VB.measure_build()["digest"]
        gezaehlt = (len(s["predicate"]["passedTests"]) + len(s["predicate"]["warnedTests"])
                    + len(s["predicate"]["failedTests"]))
        manifest = json.loads((CONFORMANCE / "manifest.json").read_text())
        assert gezaehlt == len(manifest["cases"]), "every case of the manifest is accounted for"
        # THE RESULT AND THE EXIT CODE AGREE: a failed run is a FAILED statement, never a PASSED
        # one beside a red exit -- and a green exit never sits beside FAILED.
        assert (r.returncode == 0) == (s["predicate"]["result"] != "FAILED"), (r.returncode, s["predicate"]["result"])

    @staticmethod
    def _runner_module():
        import importlib.util
        pfad = REPO / "conformance" / "run_conformance.py"
        if not pfad.is_file():
            pytest.skip("conformance/run_conformance.py is not here")
        spec = importlib.util.spec_from_file_location("rc_vb_test", pfad)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_a_run_on_the_reduced_schema_floor_is_warned_not_passed(self, tmp_path, capsys):
        """Codex round one on PR 224, P1: with the full validator absent and no switch, every case
        kept scope full and the statement said PASSED for a run whose schema validation never
        happened. The reduced floor is a partial check, in the headline and in the statement."""
        m = self._runner_module()
        echt = m.cross_format.has_full_schema_check
        ziel = tmp_path / "statement.json"
        try:
            m.cross_format.has_full_schema_check = lambda: False
            rc = m.run(test_result_out=ziel)
        finally:
            m.cross_format.has_full_schema_check = echt
        out = capsys.readouterr().out
        assert rc == 0, out[-600:]
        s = json.loads(ziel.read_text())
        assert s["predicate"]["result"] == "WARNED"
        assert s["predicate"]["passedTests"] == []
        assert len(s["predicate"]["warnedTests"]) >= 1
        assert "0 fully checked" in out and "structural floor only" in out

    def test_a_required_validator_that_is_unavailable_still_leaves_a_statement(self, tmp_path, capsys):
        """Codex round one on PR 224, P2: rc 1 and no file. Every early exit writes a FAILED
        statement, so 'the validator was missing' and 'no evidence' stay two observations."""
        m = self._runner_module()
        echt = m.cross_format.has_full_schema_check
        ziel = tmp_path / "statement.json"
        try:
            m.cross_format.has_full_schema_check = lambda: False
            rc = m.run(require_full_schema=True, test_result_out=ziel)
        finally:
            m.cross_format.has_full_schema_check = echt
        assert rc == 1
        assert ziel.is_file(), capsys.readouterr().out[-600:]
        s = json.loads(ziel.read_text())
        assert s["predicate"]["result"] == "FAILED"
        assert any("validator unavailable" in c for c in s["predicate"]["failedTests"])

    def test_a_broken_corpus_still_writes_a_failed_statement(self, tmp_path):
        """LENS C, P1: the corpus-integrity precondition returned before the statement was written,
        so the most severe failure class was the one without a statement. Executed on a scratch copy
        of the corpus with one caseId emptied."""
        import shutil
        import subprocess
        import sys

        runner = REPO / "conformance" / "run_conformance.py"
        if not runner.is_file():
            pytest.skip("conformance/run_conformance.py is not here")
        kopie = tmp_path / "conformance"
        shutil.copytree(CONFORMANCE, kopie, ignore=shutil.ignore_patterns("__pycache__"))
        fall = kopie / "agent_review" / "agent-review-v02-positive-control-emitter-default-is-v02" / "case.json"
        d = json.loads(fall.read_text(encoding="utf-8"))
        d["caseId"] = ""
        fall.write_text(json.dumps(d), encoding="utf-8")
        ziel = tmp_path / "statement.json"
        r = subprocess.run([sys.executable, str(kopie / "run_conformance.py"), "--test-result-out", str(ziel)],
                           cwd=str(REPO), capture_output=True, text=True, timeout=900,
                           env={**__import__("os").environ, "PYTHONPATH": str(REPO / "src")})
        assert r.returncode == 1, r.stdout[-600:]
        assert "corpus integrity FAIL" in r.stdout
        assert ziel.is_file(), "a broken corpus left no statement -- 'no statement' and 'broken' were one observation"
        s = json.loads(ziel.read_text(encoding="utf-8"))
        assert VB.validate_test_result_statement(s) == []
        assert s["predicate"]["result"] == "FAILED" and not s["predicate"]["passedTests"]
        assert any(t.startswith("corpus-integrity") for t in s["predicate"]["failedTests"])
