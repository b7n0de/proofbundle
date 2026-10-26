"""The Sigstore bundle reader (``adapters.sigstore_bundle``), held to its vectors.

VECTORS. tests/fixtures/sigstore_bundle holds two manifests. ``synthetic_cases.json``: bundles of a test
instance of Sigstore that ``generate_vectors.py`` writes from fixed test keys, each intact but for the one
departure the case names, so a negative fails at exactly its step. ``public_cases.json``: bundles as the npm
registry and the cli/cli test data publish them (sources in the fixture README), and byte edits of them.
Each case names its contract step, the exit code and the first check that fails; every input is pinned by
its sha256; every case is verified twice and the two verdicts must be equal.

INDEPENDENCE. Neither this file nor the generator imports a Sigstore client library; the last test reads
both and the module.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from proofbundle.adapters import sigstore_bundle as sb
from proofbundle.adapters.sigstore_bundle import NOT_CHECKED, PROFILES, exit_code, verify_sigstore_bundle

FIX = Path(__file__).resolve().parent / "fixtures" / "sigstore_bundle"
MANIFESTS = ("synthetic_cases.json", "public_cases.json")


def _cases(name: str) -> list:
    return json.loads((FIX / name).read_text(encoding="utf-8"))["cases"]


CASES = [case for name in MANIFESTS for case in _cases(name)]


def _arguments(case: dict) -> dict:
    kwargs = {"trusted_root": (FIX / case["trustedRoot"]).read_bytes(), "artifact_digest": case["artifactDigest"],
              "profile": case["profile"]}
    if "identity" in case:
        kwargs["identity"] = case["identity"]
    if "registryKeys" in case:
        kwargs["registry_keys"] = (FIX / case["registryKeys"]).read_bytes()
    if "expectedSubjectName" in case:
        kwargs["expected_subject_name"] = case["expectedSubjectName"]
    if "tlogThreshold" in case:
        kwargs["tlog_threshold"] = case["tlogThreshold"]
    return kwargs


@pytest.mark.parametrize("case", CASES, ids=[c["caseId"] for c in CASES])
def test_vector(case: dict) -> None:
    data = (FIX / case["input"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == case["sha256"], "a vendored vector changed (CONFORMANCE.md rule 1)"
    kwargs = _arguments(case)
    first = verify_sigstore_bundle(data, **kwargs).as_dict()
    second = verify_sigstore_bundle(data, **kwargs).as_dict()
    assert first == second, "two runs of one case gave two verdicts"
    failed = [c for c in first["checks"] if c["ok"] is not True]
    assert first["exit_code"] == case["expected"]["exitCode"], first["checks"]
    assert (failed[0]["name"] if failed else None) == case["expected"]["failedCheck"], first["checks"]
    assert len(failed) <= 1 or failed[0]["name"] in sb._REQUIREMENT, "a run continued past an integrity failure"
    assert first["automation"]["safeForAutomation"] is False, "no revocation and no log consistency is judged"
    for note in case.get("expectedNotes", ()):
        assert any(note in line for line in first["notes"]), (note, first["notes"])
    if case["expected"]["exitCode"] == 0:
        assert first["ok"] is True and first["policy"] == "OK"
        assert first["signing_times"], "a pass names the verified time it judged the chain at"


def test_every_check_that_can_fail_has_a_failing_vector() -> None:
    """A check without a failing vector could be dead code reading green. timestamp-authority is the one
    exception, and it is named in the fixture README: no RFC 3161 vector exists offline."""
    failing = {c["expected"]["failedCheck"] for c in CASES}
    every = sb._UNREADABLE | sb._INTEGRITY | sb._REQUIREMENT
    assert every - failing == {"timestamp-authority"}


def test_every_profile_has_a_positive_control_from_the_test_instance_and_from_public_data() -> None:
    for profile in PROFILES:
        sources = {c["input"].split("/")[0] for c in CASES if c["profile"] == profile
                   and c["expected"]["exitCode"] == 0}
        assert sources == {"synthetic", "public"}, profile


DOC = Path(__file__).resolve().parents[1] / "docs" / "SIGSTORE_BUNDLE_VERIFIER.md"


def _doc_section(title: str) -> str:
    parts = DOC.read_text(encoding="utf-8").split(f"\n## {title}\n", 1)
    assert len(parts) == 2, f"docs/SIGSTORE_BUNDLE_VERIFIER.md has no section {title!r}"
    return parts[1].split("\n## ", 1)[0]


def test_the_refusal_of_unknown_dsse_members_is_a_documented_deviation() -> None:
    """Owner decision of 2026-10-26: a member of the DSSE envelope or of its signature that the reader does
    not define is refused, although DSSE says a consumer MUST ignore it (contract DS-03). The documentation
    names the deviation and its vectors, and each vector of the step fails where it says."""
    text = " ".join(_doc_section("Deviations from the specifications").split())
    assert "DS-03" in text and "Consumers MUST ignore unrecognized fields." in text
    ds03 = [c for c in CASES if "DS-03" in c["steps"]]
    assert {c["caseId"] for c in ds03} == {"neg-dsse-envelope-unknown-member", "neg-dsse-signature-unknown-member"}
    for case in ds03:
        assert case["caseId"] in text
        assert case["expected"] == {"exitCode": 1, "failedCheck": "bundle-structure"}


def test_predicate_binding_is_a_note_and_decides_no_verdict() -> None:
    """Owner decision of 2026-10-26: the comparison of the predicate with the certificate follows the
    producers' code, not a specification, so it is a note in the verdict and never a check. Every verdict
    that read an SLSA predicate carries exactly one such note, every other verdict none."""
    assert "predicate-binding" not in sb._UNREADABLE | sb._INTEGRITY | sb._REQUIREMENT
    for case in CASES:
        out = verify_sigstore_bundle((FIX / case["input"]).read_bytes(), **_arguments(case)).as_dict()
        assert all(c["name"] != "predicate-binding" for c in out["checks"]), case["caseId"]
        read = PROFILES[case["profile"]]["predicate_type"] == sb.SLSA_PROVENANCE_V1 and any(
            c["name"] == "predicate" and c["ok"] is True for c in out["checks"])
        notes = [n for n in out["notes"] if n.startswith("predicate-binding: ")]
        assert len(notes) == (1 if read else 0), (case["caseId"], out["notes"])
        if read and "expectedNotes" not in case:
            assert notes[0].startswith("predicate-binding: agrees"), (case["caseId"], notes)


def test_the_three_classes_are_disjoint_and_an_unclassified_failure_is_structural() -> None:
    assert not (sb._UNREADABLE & sb._INTEGRITY or sb._UNREADABLE & sb._REQUIREMENT or sb._INTEGRITY & sb._REQUIREMENT)
    res = sb.VerificationResult()
    res.add("signature", True)
    res.add("a-check-nobody-classified", False)
    assert exit_code(sb.SigstoreVerdict(result=res)) == 1
    res = sb.VerificationResult()
    res.add("identity", False)
    assert exit_code(sb.SigstoreVerdict(result=res)) == 3


def _positive() -> tuple:
    case = next(c for c in CASES if c["caseId"] == "pos-github-v03-dsse")
    return (FIX / case["input"]).read_bytes(), _arguments(case)


def test_a_parsed_object_is_refused_as_unreadable() -> None:
    data, kwargs = _positive()
    verdict = verify_sigstore_bundle(json.loads(data), **kwargs)
    assert exit_code(verdict) == 2 and verdict.result.checks[-1].name == "readable"


def test_text_and_bytes_read_alike() -> None:
    data, kwargs = _positive()
    assert verify_sigstore_bundle(data.decode("utf-8"), **kwargs).as_dict() == \
        verify_sigstore_bundle(data, **kwargs).as_dict()


@pytest.mark.parametrize("change, why", [
    ({"profile": "github"}, "profile must be one of"),
    ({"artifact_digest": None}, "artifact_digest is required"),
    ({"artifact_digest": "sha256:ABCD"}, "neither"),
    ({"artifact_digest": "sha256:" + "ab" * 31}, "is not a sha256 digest"),
    ({"identity": None}, "identity is required"),
    ({"identity": {"source_repository_uri": ""}}, "non-empty string"),
    ({"identity": {"workflow": "x"}}, "which is not one of"),
    ({"registry_keys": b"{}"}, "registry_keys does not apply"),
    ({"trusted_root": b'{"mediaType": "x"}'}, "is not one this module reads"),
    ({"trusted_root": b'{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", '
                      b'"mediaType": "x"}'}, "duplicate"),
    ({"tlog_threshold": True}, "tlog_threshold"),
    ({"tlog_threshold": 2}, "exceeds the trusted logs"),
])
def test_unusable_trust_material_is_exit_2(change: dict, why: str) -> None:
    data, kwargs = _positive()
    kwargs.update(change)
    verdict = verify_sigstore_bundle(data, **kwargs)
    assert exit_code(verdict) == 2
    assert verdict.result.checks[-1].name == "verifier-config" and why in verdict.result.checks[-1].detail


def test_the_verdict_names_what_it_never_checks() -> None:
    data, kwargs = _positive()
    out = verify_sigstore_bundle(data, **kwargs).as_dict()
    assert out["not_checked"] == list(NOT_CHECKED)
    assert any("revocation" in line for line in out["not_checked"])
    assert out["specification"] == sb.SPEC_PIN


def _generator():
    spec = importlib.util.spec_from_file_location("sigstore_vector_generator", FIX / "generate_vectors.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except TypeError as exc:  # a cryptography release without deterministic ECDSA (before 44)
        pytest.skip(f"the generator needs deterministic ECDSA from cryptography: {exc}")
    return module


def test_the_synthetic_vectors_are_what_the_generator_writes() -> None:
    gen = _generator()
    by_id = {c["caseId"]: c for c in _cases("synthetic_cases.json")}
    built = gen.cases()
    assert [c["caseId"] for c in built] == list(by_id)
    for case in built:
        data = gen.bundle(**case.get("build", {}))
        if "raw" in case:
            data = gen._raw_edit(data, case["raw"])
        assert hashlib.sha256(data).hexdigest() == by_id[case["caseId"]]["sha256"], case["caseId"]
    assert gen.trusted_root() == (FIX / "trust" / "test_trusted_root.json").read_bytes()
    assert gen.trusted_root(log_id_of=gen.FOREIGN_REKOR_KEY) == \
        (FIX / "trust" / "test_trusted_root_bad_log_id.json").read_bytes()
    assert gen.trusted_root_unknown_curve() == (FIX / "trust" / "test_trusted_root_unknown_curve.json").read_bytes()
    assert gen.registry_keys() == (FIX / "trust" / "test_registry_keys.json").read_bytes()


def test_no_sigstore_client_is_imported() -> None:
    forbidden = ("sigstore", "sigstore_protobuf_specs", "sigstore_rekor_types", "in_toto_attestation", "tuf")
    for path in (Path(sb.__file__), Path(__file__), FIX / "generate_vectors.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{path.name} imports {name}"
