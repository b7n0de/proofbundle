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

from typing import Optional

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://b7n0de.com/proofbundle/eval-receipt/v0.1"
VERIFIER_ID = "https://b7n0de.com/proofbundle"
MODEL_COMMIT_DIGEST_KEY = "proofbundleModelCommitV1"

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
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": "model-id-commitment",
            "digest": {MODEL_COMMIT_DIGEST_KEY: _commit_hex(claim["model_id_commit"])},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "verifier": {"id": VERIFIER_ID},
            "evaluatedAt": claim["timestamp"],
            "suite": claim["suite"],
            "claims": [{
                "metric": claim["metric"], "comparator": claim["comparator"],
                "threshold": claim["threshold"], "passed": claim["passed"],
            }],
            "datasetCommit": claim.get("dataset_id_commit"),
            "subject_digest_note": _SUBJECT_DIGEST_NOTE,
        },
    }
    if harness:
        statement["predicate"]["harness"] = harness
    if root_b64:
        statement["predicate"]["receipt"] = {"schema": "proofbundle/v0.1", "root_b64": root_b64}
    return statement
