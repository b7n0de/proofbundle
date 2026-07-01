"""in-toto Statement v1 view of an eval receipt (self-hosted predicate type).

A self-hosted `predicateType` URI is fully in-toto-spec-conform and the right choice for a solo v0.x
(no official in-toto/attestation PR needed). See PREDICATE.md.

HONESTY (important): the `subject.digest` here is a SALTED COMMITMENT to the model identifier, NOT the
content hash of an artifact. Placing it under the standard `sha256` key would suggest an artifact hash
and mislead generic in-toto verifiers. in-toto permits arbitrary digest keys, so we use a unique custom
key `proofbundleModelCommitV1`; the `subject.name` is the descriptive `model-id-commitment`; and the
predicate mirrors the note in `subject_digest_note`. Full artifact digests come only once a model artifact
exists (deferred, see the roadmap).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://b7n0de.com/proofbundle/eval-receipt/v0.1"
VERIFIER_ID = "https://b7n0de.com/proofbundle"
MODEL_COMMIT_DIGEST_KEY = "proofbundleModelCommitV1"
DATASET_COMMIT_DIGEST_KEY = "proofbundleDatasetCommitV1"

# in-toto test-result predicate v0.1 (verified 2026-07 against in-toto/attestation spec/predicates/
# test-result.md). result ∈ {PASSED, WARNED, FAILED} (uppercase); configuration is a required list of
# ResourceDescriptor, each of which MUST carry one of uri/digest/content (a bare name is invalid). The
# predicate has NO native metric fields and NO top-level annotations, so metric details go into a
# ResourceDescriptor.annotations map. The DSSE payloadType is pinned so sign and verify agree.
TEST_RESULT_PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"
TEST_RESULT_PAYLOAD_TYPE = "application/vnd.in-toto.test-result+json"
_RESULT_ENUM = {True: "PASSED", False: "FAILED"}   # WARNED is unused (proofbundle asserts a pass/fail threshold)

_SUBJECT_DIGEST_NOTE = (
    "subject.digest is a salted commitment to the model identifier (key "
    f"{MODEL_COMMIT_DIGEST_KEY}), NOT an artifact content hash — do not treat it as sha256.")


def _commit_hex(commit: str) -> str:
    """Extract the hex of a `sha256:<hex>` salted commitment (the value that goes into the digest)."""
    return commit.split(":", 1)[1] if ":" in commit else commit


def to_intoto_statement(claim: dict, *, root_b64: Optional[str] = None,
                        harness: Optional[dict] = None) -> dict:
    """Build an in-toto Statement v1 whose predicate is the eval receipt.

    `root_b64` (from the signed bundle's merkle root) binds the statement to the receipt. `harness`
    (e.g. {"name": "inspect_ai", "version": "0.3.217"}) is optional. The subject digest is the model
    commitment under a custom key (never `sha256`).
    """
    predicate: dict[str, Any] = {
        "verifier": {"id": VERIFIER_ID},
        "evaluatedAt": claim["timestamp"],
        "suite": claim["suite"],
        "claims": [{
            "metric": claim["metric"], "comparator": claim["comparator"],
            "threshold": claim["threshold"], "passed": claim["passed"],
        }],
        "datasetCommit": claim.get("dataset_id_commit"),
        "subject_digest_note": _SUBJECT_DIGEST_NOTE,
    }
    if harness:
        predicate["harness"] = harness
    if root_b64:
        predicate["receipt"] = {"schema": "proofbundle/v0.1", "root_b64": root_b64}
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": "model-id-commitment",
            "digest": {MODEL_COMMIT_DIGEST_KEY: _commit_hex(claim["model_id_commit"])},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    return statement


def _canonical_body(statement: dict) -> bytes:
    """Deterministic byte serialization of the Statement for the DSSE payload. DSSE signs/verifies over
    exactly these bytes (verify decodes envelope.payload, never re-serializes), so a stable sorted dump
    is sufficient and keeps the core dependency-free (no rfc8785 needed for the in-toto export path)."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def to_test_result_statement(claim: dict, *, subject_digest: dict, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, url: Optional[str] = None) -> dict:
    """Build a STANDARD in-toto Statement v1 with the generic `test-result/v0.1` predicate (v0.9).

    Unlike ``to_intoto_statement`` (self-hosted predicate), this maps the receipt onto the community
    test-result predicate so a generic in-toto verifier understands it: ``result`` is PASSED/FAILED from
    the threshold; ``configuration`` lists ResourceDescriptors for the model and dataset commitments (each
    carries a real ``digest`` — a salted commitment hex under a proofbundle-specific algorithm key, never
    ``sha256`` — so ``name``-only descriptors, which are invalid, are avoided). Metric details (metric,
    comparator, threshold, passed, stderr) have no native field in test-result, so they live in the model
    descriptor's ``annotations``. ``subject_digest`` is a real DigestSet ({alg: hex}) for the receipt.
    """
    model_desc: dict[str, Any] = {
        "name": "model-id-commitment",
        "digest": {MODEL_COMMIT_DIGEST_KEY: _commit_hex(claim["model_id_commit"])},
        "annotations": {
            "suite": claim["suite"],
            "metric": claim["metric"],
            "comparator": claim["comparator"],
            "threshold": claim["threshold"],
            "passed": claim["passed"],
            "evaluatedAt": claim["timestamp"],
            "note": ("digest is a SALTED COMMITMENT to the model id, not an artifact content hash; "
                     "proofbundle attests authenticity+integrity of the claimed result, not the correctness "
                     "of the computation"),
        },
    }
    if claim.get("provenance"):
        model_desc["annotations"]["provenance"] = claim["provenance"]
    if harness:
        model_desc["annotations"]["harness"] = harness
    if root_b64:
        model_desc["annotations"]["receipt"] = {"schema": "proofbundle/v0.1", "root_b64": root_b64}
    configuration = [model_desc]
    dataset_commit = claim.get("dataset_id_commit")
    if dataset_commit:
        configuration.append({
            "name": "dataset-id-commitment",
            "digest": {DATASET_COMMIT_DIGEST_KEY: _commit_hex(dataset_commit)},
        })
    predicate: dict[str, Any] = {
        "result": _RESULT_ENUM[bool(claim["passed"])],
        "configuration": configuration,
    }
    suite = claim.get("suite")
    if suite:
        key = "passedTests" if claim["passed"] else "failedTests"
        predicate[key] = [str(suite)]
    if url:
        predicate["url"] = url
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "eval-receipt", "digest": dict(subject_digest)}],
        "predicateType": TEST_RESULT_PREDICATE_TYPE,
        "predicate": predicate,
    }


def export_intoto_dsse(claim: dict, signer, *, root_b64: Optional[str] = None,
                       harness: Optional[dict] = None, url: Optional[str] = None,
                       keyid: Optional[str] = None) -> dict:
    """Export a receipt as a DSSE-signed in-toto test-result attestation (v0.9). The native bundle stays
    the source of truth; this is an interop export. Returns a DSSE envelope. The subject digest is the
    sha256 of a stable *binder* over the receipt's model + dataset commitments, root, and timestamp — a
    real hex digest that binds the attestation to the receipt without revealing the model (not a hash of
    the statement body, and never the model's own sha256)."""
    from . import dsse  # noqa: PLC0415 — lazy: keeps the verify core free of the DSSE module

    # subject_digest binds to the receipt: sha256 of the model+dataset commitments + root (stable, hex).
    binder = json.dumps({
        "model_id_commit": claim["model_id_commit"],
        "dataset_id_commit": claim.get("dataset_id_commit"),
        "root_b64": root_b64,
        "timestamp": claim["timestamp"],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    subject_digest = {"sha256": hashlib.sha256(binder).hexdigest()}
    statement = to_test_result_statement(claim, subject_digest=subject_digest, root_b64=root_b64,
                                         harness=harness, url=url)
    body = _canonical_body(statement)
    return dsse.sign_envelope(body, signer, payload_type=TEST_RESULT_PAYLOAD_TYPE, keyid=keyid)


def verify_intoto_dsse(envelope: dict, public_key: bytes) -> dict:
    """Verify a DSSE-signed in-toto test-result attestation from ``export_intoto_dsse``. Returns
    {ok, statement, predicate_type}. ``ok`` is True iff the Ed25519 signature over the DSSE PAE verifies
    AND the payloadType is the pinned test-result media type."""
    from . import dsse  # noqa: PLC0415
    from .errors import BundleFormatError  # noqa: PLC0415

    ok = dsse.verify_envelope(envelope, public_key, payload_type=TEST_RESULT_PAYLOAD_TYPE)
    body = dsse.load_payload(envelope)
    try:
        statement = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:   # valid base64 but not a JSON Statement → malformed
        raise BundleFormatError("DSSE payload is not a JSON in-toto Statement") from exc
    return {"ok": bool(ok), "statement": statement,
            "predicate_type": statement.get("predicateType") if isinstance(statement, dict) else None}
