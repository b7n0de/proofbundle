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

from .canonical import CONTENT_ROOT_ALG, CanonicalizerUnavailable, canonicalize_statement
from .errors import BundleFormatError

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://b7n0de.com/proofbundle/eval-receipt/v0.1"
VERIFIER_ID = "https://b7n0de.com/proofbundle"
MODEL_COMMIT_DIGEST_KEY = "proofbundleModelCommitV1"
DATASET_COMMIT_DIGEST_KEY = "proofbundleDatasetCommitV1"

# The dedicated eval-result predicate (the shape proposed upstream in in-toto/attestation#565). Distinct
# from the self-hosted eval-receipt view above and from the community test-result mapping below: it
# extends the test-result shape with a threshold-based `claims[]`, privacy-preserving salted-commitment
# subjects, and an optional binding to the external signed receipt. predicateType is a VENDOR namespace
# for now (common practice, cf. cosign.sigstore.dev/…, apko.dev/…); the migration path to an in-toto.io
# namespace is documented in docs/IN_TOTO_PROFILE.md and needs a redirect PR only there. Status: PROPOSED
# — under discussion at in-toto/attestation#565, NOT standardized.
EVAL_RESULT_PREDICATE_TYPE = "https://b7n0de.com/attestation/eval-result/v0.1"
# DSSE payloadType for an in-toto Statement is the canonical Statement media type (in-toto spec v1
# envelope.md), NOT a predicate-specific subtype. Pinned so sign and verify agree.
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Content-root algorithm ids for these DSSE export paths (ADR 0002 / WP2 activation, 2.1.0). The DEFAULT is
# CONTENT_ROOT_ALG ("jcs-sha256-v1"): SHA-256 over the RFC-8785 (JCS) canonical Statement bytes, unifying
# these paths with the decision-receipt content root so cross-predicate composition matches byte-for-byte.
# The historic serializer (json.dumps(sort_keys=True) via `_canonical_body`, the released 2.0.0 wire) is
# retained as a NAMED legacy algorithm — an explicit declared mode, never an unlabeled fallback. A Statement
# DECLARES its algorithm in a top-level `contentRootAlg` field (in-toto Statement v1 allows additional
# top-level properties, additionalProperties:true), so the declaration is inside the signed payload and
# cannot be flipped after signing. ABSENT `contentRootAlg` ⇒ legacy (this is how already-signed 2.0.0
# receipts, which carry no field, keep verifying); absence is NEVER silently treated as jcs.
LEGACY_CONTENT_ROOT_ALG = "legacy-sortkeys-json-v0"

# Subject profiles (what the Statement's `subject` IS). Documented per profile in docs/IN_TOTO_PROFILE.md.
#   receipt      — the eval receipt itself (a binder digest; reveals nothing about the model). DEFAULT.
#   public-model — a disclosed public model artifact (caller supplies its real sha256).
#   release-gate — a release artifact gated on a passed eval ("deploy only if the eval passed"; SLSA hook).
SUBJECT_PROFILES = ("receipt", "public-model", "release-gate")

# An export is commitment-only. If a caller hands us an enriched claim that still carries a plaintext
# identifier or a raw salt, we REFUSE to export rather than risk leaking it into a portable attestation.
_FORBIDDEN_PLAINTEXT_KEYS = (
    "model_id", "dataset_id", "model_name", "dataset_name", "model_salt", "dataset_salt", "salt", "salts")
# The minimal claim fields the eval-result predicate needs; export refuses a claim missing any of them.
_EXPORT_REQUIRED = ("suite", "metric", "comparator", "threshold", "passed", "n", "model_id_commit",
                    "dataset_id_commit", "timestamp")

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
    """LEGACY (`legacy-sortkeys-json-v0`) Statement serialization: json.dumps(sort_keys=True). This is the
    released 2.0.0 wire; it is NOT full RFC-8785 (it does not normalize number formatting or string
    escaping), so it cannot carry a stable cross-implementation content root (ADR 0002). Retained as the
    NAMED legacy serializer so already-signed 2.0.0 receipts keep verifying byte-for-byte and legacy
    re-emission stays possible; new exports default to `jcs-sha256-v1` (see `_serialize_statement`)."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _declared_content_root_alg(statement: Any) -> str:
    """The content-root algorithm a Statement DECLARES via its top-level `contentRootAlg`. ABSENT ⇒ legacy
    (`legacy-sortkeys-json-v0`) — this is how released 2.0.0 receipts, which carry no field, keep verifying.
    Absence is NEVER silently treated as jcs (ADR 0002 §Migration 2, mirroring merkle.hash_alg)."""
    if isinstance(statement, dict):
        alg = statement.get("contentRootAlg")
        if isinstance(alg, str) and alg:
            return alg
    return LEGACY_CONTENT_ROOT_ALG


def _serialize_statement(statement: dict, content_root_alg: str) -> bytes:
    """Serialize a Statement under a NAMED content-root algorithm — no silent default between algorithms.

    * `jcs-sha256-v1` → RFC-8785 (JCS) canonical bytes via the shared `canonical.canonicalize_statement`
      (lazily needs the `[eval]` extra; a missing extra is a fail-closed `CanonicalizerUnavailable`);
    * `legacy-sortkeys-json-v0` → the historic `_canonical_body` (json.dumps(sort_keys=True), stdlib only).

    An unknown/unregistered id is a fail-closed error: a verifier MUST NOT default a missing/unknown
    algorithm (that is exactly where an algorithm-confusion attack would hide, ADR 0002 §1)."""
    if content_root_alg == CONTENT_ROOT_ALG:
        return canonicalize_statement(statement)
    if content_root_alg == LEGACY_CONTENT_ROOT_ALG:
        return _canonical_body(statement)
    raise BundleFormatError(
        f"unknown contentRootAlg {content_root_alg!r}: no silent default for a missing/unknown "
        "algorithm (algorithm-confusion guard, ADR 0002 §1)")


def _declare_content_root_alg(statement: dict, content_root_alg: str) -> dict:
    """Return the Statement with its content-root algorithm DECLARED. `jcs-sha256-v1` adds the top-level
    `contentRootAlg` field (part of the signed payload, so it cannot be flipped after signing); legacy adds
    NO field, so a legacy re-emission is byte-identical to the released 2.0.0 wire (absent ⇒ legacy on
    verify). An unknown id is a fail-closed error."""
    if content_root_alg == CONTENT_ROOT_ALG:
        return {**statement, "contentRootAlg": CONTENT_ROOT_ALG}
    if content_root_alg == LEGACY_CONTENT_ROOT_ALG:
        return {k: v for k, v in statement.items() if k != "contentRootAlg"}
    raise BundleFormatError(
        f"unknown contentRootAlg {content_root_alg!r} (ADR 0002 §1; no silent default)")


def _content_root_binding(statement: Any, body: bytes) -> tuple[bool, str, str]:
    """Verify the transmitted payload IS canonical for its OWN declared content-root algorithm. Fail-closed.

    Returns ``(ok, alg, detail)``. The verifier reads the DECLARED `contentRootAlg` (absent ⇒ legacy) and
    re-serializes the Statement with EXACTLY that algorithm, then checks byte-equality against the exact
    transmitted payload — it never re-canonicalizes to COMPUTE a root and never falls back between algorithms.
    A payload that deviates from its own declared canonical form is rejected (this is the P0 guard: a
    `json.dumps(sort_keys=True)` body offered AS `jcs-sha256-v1` is rejected — unless it also happens to be
    valid JCS — while the same body declared/absent as legacy verifies). Verifying `jcs-sha256-v1` canonicality
    needs the `[eval]` extra; without it this is fail-closed (never a silent pass over possibly non-canonical
    bytes). Legacy verification is stdlib-only, so released 2.0.0 receipts verify on a base install."""
    alg = _declared_content_root_alg(statement)
    if not isinstance(statement, dict):
        return False, alg, "payload is not a JSON in-toto Statement object"
    try:
        expected = _serialize_statement(statement, alg)
    except CanonicalizerUnavailable:
        return False, alg, ("cannot verify jcs-sha256-v1 canonicality — install proofbundle[eval] "
                            "(fail-closed; never a silent pass over non-canonical bytes)")
    except BundleFormatError as exc:
        return False, alg, str(exc)
    if expected != body:
        return False, alg, (f"payload is not canonical for its declared contentRootAlg={alg!r} "
                            "(algorithm-confusion / tamper, fail-closed)")
    return True, alg, ""


def to_test_result_statement(claim: dict, *, subject_digest: dict, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, url: Optional[str] = None,
                             content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
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
    return _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "eval-receipt", "digest": dict(subject_digest)}],
        "predicateType": TEST_RESULT_PREDICATE_TYPE,
        "predicate": predicate,
    }, content_root_alg)


def export_intoto_dsse(claim: dict, signer, *, root_b64: Optional[str] = None,
                       harness: Optional[dict] = None, url: Optional[str] = None,
                       keyid: Optional[str] = None,
                       content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Export a receipt as a DSSE-signed in-toto test-result attestation (v0.9). The native bundle stays
    the source of truth; this is an interop export. Returns a DSSE envelope. The subject digest is the
    sha256 of a stable *binder* over the receipt's model + dataset commitments, root, and timestamp — a
    real hex digest that binds the attestation to the receipt without revealing the model (not a hash of
    the statement body, and never the model's own sha256).

    The signed Statement declares its content-root algorithm (default `jcs-sha256-v1`, ADR 0002). Pass
    `content_root_alg=LEGACY_CONTENT_ROOT_ALG` for a byte-identical legacy re-emission (json.dumps root,
    no field)."""
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
                                         harness=harness, url=url, content_root_alg=content_root_alg)
    body = _serialize_statement(statement, content_root_alg)
    return dsse.sign_envelope(body, signer, payload_type=TEST_RESULT_PAYLOAD_TYPE, keyid=keyid)


def verify_intoto_dsse(envelope: dict, public_key: bytes) -> dict:
    """Verify a DSSE-signed in-toto test-result attestation from ``export_intoto_dsse``. Returns
    {ok, statement, predicate_type, content_root_alg, content_root_ok, content_root_detail}. ``ok`` is True
    iff the Ed25519 signature over the DSSE PAE verifies, the payloadType is the pinned test-result media
    type, AND the payload is canonical for its DECLARED contentRootAlg (absent ⇒ legacy; ADR 0002)."""
    from . import dsse  # noqa: PLC0415
    from .errors import BundleFormatError  # noqa: PLC0415

    ok = dsse.verify_envelope(envelope, public_key, payload_type=TEST_RESULT_PAYLOAD_TYPE)
    body = dsse.load_payload(envelope)
    try:
        statement = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:   # valid base64 but not a JSON Statement → malformed
        raise BundleFormatError("DSSE payload is not a JSON in-toto Statement") from exc
    binding_ok, alg, detail = _content_root_binding(statement, body)
    return {"ok": bool(ok) and binding_ok, "statement": statement,
            "predicate_type": statement.get("predicateType") if isinstance(statement, dict) else None,
            "content_root_alg": alg, "content_root_ok": binding_ok, "content_root_detail": detail}


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# eval-result predicate (in-toto/attestation#565 proposal) — subject profiles, salted commitments.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

def _is_sha256_hex(value: Any) -> bool:
    """True iff `value` is a 64-char lowercase hex string (a DigestSet sha256, per in-toto DigestSet rules)."""
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _commitment(commit: Optional[str], alg: Optional[str]) -> Optional[dict]:
    """A salted-commitment digest object `{alg, value, salted}` — never a plain artifact hash. `commit` is
    the receipt's `sha256:<hex>` form; the `salted:true` flag makes the privacy semantics explicit so a
    generic verifier never mistakes it for a content digest."""
    if not commit:
        return None
    return {"alg": alg or "sha256-salted-v1", "value": _commit_hex(commit), "salted": True}


def _forbid_plaintext_in_export(claim: dict) -> None:
    """Fail closed if the claim carries a plaintext identifier or a raw salt. An export must stay
    commitment-only — leaking a secret into a portable attestation is the one thing this path must never
    do (Paket 2 test 1). This guard is what the salt-leak mutation operator targets."""
    leaked = [k for k in _FORBIDDEN_PLAINTEXT_KEYS if k in claim]
    if leaked:
        raise BundleFormatError(
            f"refusing to export: claim carries plaintext/secret field(s) {leaked}; the in-toto export is "
            "commitment-only and must never carry a model/dataset name or a salt")


def _require_export_fields(claim: dict) -> None:
    """Refuse to export an invalid/incomplete receipt claim (Paket 2 test 3)."""
    if not isinstance(claim, dict):
        raise BundleFormatError("eval-result export needs a claim object")
    missing = [k for k in _EXPORT_REQUIRED if claim.get(k) in (None, "")]
    if missing:
        raise BundleFormatError(f"refusing to export: claim is missing required field(s) {missing}")


def resolve_subject(profile: str, claim: dict, *, root_b64: Optional[str] = None,
                    subject_name: Optional[str] = None, subject_sha256: Optional[str] = None) -> list:
    """Build the Statement `subject` for a subject profile. Every subject carries a real `digest` (in-toto
    matches on the digest alone). See SUBJECT_PROFILES for what each subject IS.

    * ``receipt`` (default): the subject is the receipt; the digest is the sha256 of a stable binder over
      the model+dataset commitments, the merkle root, and the timestamp — a real hex digest that binds the
      attestation to the receipt WITHOUT revealing the model.
    * ``public-model`` / ``release-gate``: the subject is a disclosed artifact; the caller supplies its real
      lowercase-hex sha256 (`subject_sha256`) and a name (`subject_name`).
    """
    if profile == "receipt":
        if not claim.get("model_id_commit") or not claim.get("timestamp"):
            raise BundleFormatError("receipt subject profile needs model_id_commit and timestamp")
        binder = json.dumps({
            "model_id_commit": claim["model_id_commit"],
            "dataset_id_commit": claim.get("dataset_id_commit"),
            "root_b64": root_b64,
            "timestamp": claim["timestamp"],
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return [{"name": "eval-receipt", "digest": {"sha256": hashlib.sha256(binder).hexdigest()}}]
    if profile in ("public-model", "release-gate"):
        sha = (subject_sha256 or "").lower()
        if not subject_name or not _is_sha256_hex(sha):
            raise BundleFormatError(
                f"subject profile '{profile}' requires --subject-name and a 64-char hex --subject-sha256")
        return [{"name": subject_name, "digest": {"sha256": sha}}]
    raise BundleFormatError(f"unknown subject profile '{profile}' (one of {', '.join(SUBJECT_PROFILES)})")


def to_eval_result_predicate(claim: dict, *, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, anchors: Optional[list] = None,
                             subject_profile: str = "receipt") -> dict:
    """Build the `eval-result/v0.1` predicate (lowerCamelCase, RFC-3339 speaking time fields, salted
    commitments, digests as {alg, value}). Validates the claim and refuses to leak secrets first. Only
    fields with real data are emitted (no fabricated `signedAt`/`preRegisteredAt`)."""
    _require_export_fields(claim)
    _forbid_plaintext_in_export(claim)
    predicate: dict[str, Any] = {
        "verifier": {"id": VERIFIER_ID},
        "evaluatedAt": claim["timestamp"],
        "suite": {"name": claim["suite"], "version": claim.get("suite_version")},
        "claims": [{
            "metric": claim["metric"], "comparator": claim["comparator"],
            "threshold": claim["threshold"], "passed": bool(claim["passed"]),
        }],
        "sampleSize": claim["n"],
        "commitments": {
            "model": _commitment(claim["model_id_commit"], claim.get("commit_alg")),
            "dataset": _commitment(claim.get("dataset_id_commit"), claim.get("commit_alg")),
        },
        "assuranceLevel": claim.get("assurance_level", "self_attested"),
        "subjectProfile": subject_profile,
    }
    if subject_profile == "receipt":
        predicate["subjectDigestNote"] = (
            "subject.digest is a binder over the receipt commitments+root, not an artifact hash")
    prereg = claim.get("prereg_sha256")
    if prereg:
        predicate["preRegistration"] = {"alg": "sha256", "value": prereg}
    if root_b64:
        predicate["receipt"] = {"schema": "proofbundle/v0.1", "merkleRootB64": root_b64}
    if harness:
        predicate["harness"] = harness
    if anchors:
        predicate["anchors"] = anchors
    return predicate


def to_eval_result_statement(claim: dict, *, subject: list, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, anchors: Optional[list] = None,
                             subject_profile: str = "receipt",
                             content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """A STANDARD in-toto Statement v1 carrying the eval-result predicate. Declares its content-root
    algorithm (default `jcs-sha256-v1`, ADR 0002); legacy adds no `contentRootAlg` field."""
    return _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": EVAL_RESULT_PREDICATE_TYPE,
        "predicate": to_eval_result_predicate(claim, root_b64=root_b64, harness=harness,
                                              anchors=anchors, subject_profile=subject_profile),
    }, content_root_alg)


def export_eval_result_dsse(claim: dict, signer, *, subject_profile: str = "receipt",
                            subject_name: Optional[str] = None, subject_sha256: Optional[str] = None,
                            root_b64: Optional[str] = None, harness: Optional[dict] = None,
                            anchors: Optional[list] = None, keyid: Optional[str] = None,
                            content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Export a receipt as a DSSE-signed in-toto Statement with the eval-result predicate. Deterministic:
    identical inputs produce byte-identical statement bytes. The signed Statement declares its content-root
    algorithm (default `jcs-sha256-v1`, ADR 0002 / WP2 activation). Pass
    `content_root_alg=LEGACY_CONTENT_ROOT_ALG` for a byte-identical legacy re-emission (released 2.0.0 wire:
    json.dumps root, no field)."""
    from . import dsse  # noqa: PLC0415 — lazy: keeps the verify core free of the DSSE module

    _require_export_fields(claim)          # fail-closed BEFORE building the (receipt-profile) subject binder
    _forbid_plaintext_in_export(claim)
    subject = resolve_subject(subject_profile, claim, root_b64=root_b64,
                              subject_name=subject_name, subject_sha256=subject_sha256)
    statement = to_eval_result_statement(claim, subject=subject, root_b64=root_b64, harness=harness,
                                         anchors=anchors, subject_profile=subject_profile,
                                         content_root_alg=content_root_alg)
    body = _serialize_statement(statement, content_root_alg)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def verify_eval_result_dsse(envelope: dict, public_key: bytes) -> dict:
    """Verify a DSSE-signed eval-result attestation. Returns {ok, statement, predicate_type,
    content_root_alg, content_root_ok, content_root_detail}. `ok` is True iff the Ed25519 signature over the
    DSSE PAE verifies, payloadType is the pinned in-toto Statement media type, AND the payload is canonical
    for its DECLARED contentRootAlg (absent ⇒ legacy; ADR 0002)."""
    from . import dsse  # noqa: PLC0415

    ok = dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
    body = dsse.load_payload(envelope)
    try:
        statement = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleFormatError("DSSE payload is not a JSON in-toto Statement") from exc
    binding_ok, alg, detail = _content_root_binding(statement, body)
    return {"ok": bool(ok) and binding_ok, "statement": statement,
            "predicate_type": statement.get("predicateType") if isinstance(statement, dict) else None,
            "content_root_alg": alg, "content_root_ok": binding_ok, "content_root_detail": detail}


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# SVR export — the in-toto Summary Verification Result (svr/v0.1). A verifier's summary; passing only.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

# predicateType is EXACT (in-toto/attestation SVR predicate, PR #470). Property strings are type-generic
# with a PROOFBUNDLE_ prefix (never a vendor/service name), per the SVR property-string convention.
SVR_PREDICATE_TYPE = "https://in-toto.io/attestation/svr/v0.1"

# WATCH: in-toto/attestation#551 proposes making `verifier.policies` a REQUIRED field for SVR v0.2. It is
# open and uncommented as of 2026-07-05. If it lands, this export must add a policies array — tracked in
# the report. `policy` here is the OPTIONAL v0.1 extension field ({uri, digest}), not the #551 change.


def _now_rfc3339z() -> str:
    from datetime import datetime, timezone  # noqa: PLC0415
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def svr_properties(result, claim: dict, *, prereg_verified: bool = False,
                   anchor_verified: bool = False) -> list:
    """Map a real VerificationResult + claim to the SVR property strings — ONLY the checks that genuinely
    passed. A missing optional check produces NO property (never a placeholder). PROOFBUNDLE_PREREG_BOUND
    and PROOFBUNDLE_ANCHOR_VALID are asserted ONLY when the caller confirms that verification actually
    ran offline (a present prereg hash or an anchors[] block alone is NOT a verified binding)."""
    checks = {c.name: c.ok for c in result.checks}
    props = []
    if checks.get("ed25519-signature"):
        props.append("PROOFBUNDLE_SIGNATURE_VALID")
    if checks.get("merkle-inclusion"):
        props.append("PROOFBUNDLE_RECEIPT_UNCHANGED")
    if claim.get("passed"):
        props.append("PROOFBUNDLE_THRESHOLD_MET")
    if claim.get("samples"):
        props.append("PROOFBUNDLE_SAMPLE_ROOT_VALID")
    if prereg_verified and claim.get("prereg_sha256"):
        props.append("PROOFBUNDLE_PREREG_BOUND")
    if anchor_verified:
        props.append("PROOFBUNDLE_ANCHOR_VALID")
    return props


def export_svr_dsse(bundle: dict, signer, *, time_created: Optional[str] = None,
                    policy: Optional[dict] = None, prereg_verified: bool = False,
                    anchor_verified: bool = False, keyid: Optional[str] = None,
                    content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Emit an in-toto SVR (svr/v0.1) for a receipt — ONLY after a real, passing verification.

    Refuses (fail-closed) if the receipt is not a valid eval receipt, does not cryptographically verify,
    OR did not pass its threshold. SVR carries only PASSING property strings; there is no FAILED form
    (that would be a VSA with a PASSED|FAILED verdict — deliberately NOT implemented here, see docs). The
    subject is the receipt digest; no secrets ever enter the statement."""
    from . import dsse  # noqa: PLC0415
    from .bundle import recompute_merkle_root_b64, verify_bundle  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415
    from .evalclaim import decode_eval_claim  # noqa: PLC0415

    try:
        claim = decode_eval_claim(bundle)
    except ProofBundleError as exc:   # a non-receipt / malformed bundle → clean fail-closed, not a raw error
        raise BundleFormatError(f"SVR export needs a valid eval receipt ({exc})") from exc
    if claim is None:
        raise BundleFormatError("SVR export needs a valid, issuer-bound eval receipt")
    result = verify_bundle(bundle)
    if not result.ok:
        raise BundleFormatError(
            "refusing to emit SVR: the receipt does not verify — an SVR carries only passing properties "
            "and has no FAILED form (a VSA would be the PASSED|FAILED format)")
    if not claim.get("passed"):
        raise BundleFormatError(
            "refusing to emit SVR: the eval did not pass its threshold — SVR summarizes a PASS, a failed "
            "eval has no positive summary")
    props = svr_properties(result, claim, prereg_verified=prereg_verified, anchor_verified=anchor_verified)
    subject = resolve_subject("receipt", claim, root_b64=recompute_merkle_root_b64(bundle).get("stated_b64"))
    verifier: dict[str, Any] = {"id": VERIFIER_ID}
    if policy:
        verifier["policy"] = policy
    statement = _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": SVR_PREDICATE_TYPE,
        "predicate": {
            "verifier": verifier,
            "timeCreated": time_created or _now_rfc3339z(),
            "properties": props,
        },
    }, content_root_alg)
    body = _serialize_statement(statement, content_root_alg)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def verify_svr_dsse(envelope: dict, public_key: bytes) -> dict:
    """Verify a DSSE-signed SVR attestation. Returns {ok, statement, predicate_type, content_root_alg,
    content_root_ok, content_root_detail}. `ok` requires the signature AND that the payload is canonical for
    its DECLARED contentRootAlg (absent ⇒ legacy; ADR 0002)."""
    from . import dsse  # noqa: PLC0415

    ok = dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
    body = dsse.load_payload(envelope)
    try:
        statement = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleFormatError("DSSE payload is not a JSON in-toto Statement") from exc
    binding_ok, alg, detail = _content_root_binding(statement, body)
    return {"ok": bool(ok) and binding_ok, "statement": statement,
            "predicate_type": statement.get("predicateType") if isinstance(statement, dict) else None,
            "content_root_alg": alg, "content_root_ok": binding_ok, "content_root_detail": detail}
