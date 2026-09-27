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

import copy
import hashlib
import json
import re
from typing import Any, Optional

from ._verdict import require_bool_verdict
from ._strict_json import loads_strict
from .canonical import CONTENT_ROOT_ALG, CanonicalizerUnavailable, canonicalize_statement
from .errors import BundleFormatError, ProofBundleError

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
# The revised #575 draft (2026-09-28: `evaluator` in place of `verifier`, one identification each for model
# and dataset, `evidence[]` in place of `receipt`) under ITS OWN type version. v0.1 above was emitted and
# signed by released versions; a consumer that keys on the type must never read those bytes under the
# revised rules, nor revised bytes under the old ones. So v0.1 keeps its contract unchanged (signature,
# content root, type) and v0.2 adds the shape of the revised draft to the verdict (gate G2).
EVAL_RESULT_V02_PREDICATE_TYPE = "https://b7n0de.com/attestation/eval-result/v0.2"
EVAL_RESULT_PREDICATE_TYPES = (EVAL_RESULT_PREDICATE_TYPE, EVAL_RESULT_V02_PREDICATE_TYPE)
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
    verdikt = require_bool_verdict(claim, wo="to_intoto_statement")
    predicate: dict[str, Any] = {
        "verifier": {"id": VERIFIER_ID},
        "evaluatedAt": claim["timestamp"],
        "suite": claim["suite"],
        "claims": [{
            "metric": claim["metric"], "comparator": claim["comparator"],
            "threshold": claim["threshold"], "passed": verdikt,
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


#: What a PRESENT but unusable `contentRootAlg` resolves to. It is deliberately not a registered id,
#: so `_serialize_statement` refuses it the same way it refuses any unknown one, and it names what was
#: found so the verdict says more than "unknown".
_PRESENT_BUT_UNUSABLE = "invalid-contentRootAlg"


def _declared_content_root_alg(statement: Any) -> str:
    """The content-root algorithm a Statement DECLARES via its top-level `contentRootAlg`. ABSENT ⇒ legacy
    (`legacy-sortkeys-json-v0`) — this is how released 2.0.0 receipts, which carry no field, keep verifying.
    Absence is NEVER silently treated as jcs (ADR 0002 §Migration 2, mirroring merkle.hash_alg).

    ABSENT AND PRESENT-BUT-UNUSABLE ARE NOT THE SAME THING, and until 2026-09-23 they were. S26, deep
    gate run 5, finding `L1-600-CRA-01`: the guard below was `isinstance(alg, str) and alg`, so a
    PRESENT value that is not a non-empty string fell through to the absence branch and resolved to
    LEGACY with `ok=true`. Measured before the fix, all six of `""`, `0`, `True`, `[]`, `{}` and
    `null` resolved to legacy, while an unknown STRING id correctly failed closed one line later in
    `_serialize_statement`. A document that declares something unusable was read as a document that
    declares nothing.

    THE HONEST BOUNDARY, because it belongs in the finding and not only in the fix: `contentRootAlg`
    sits INSIDE the signed payload, so this is not a signature bypass. The damage is that the verdict
    describes signed content wrongly, that a receipt which the contract says to reject is accepted,
    and that a stricter foreign verifier rules differently on identical bytes.

    THE CLASS: `(field ABSENT) == (resolved algorithm == LEGACY)` must hold strictly. Every algorithm
    or selector field read from parsed content has this shape, in both languages, which is why the
    guard here distinguishes the two states instead of widening the accepted type.
    """
    if not isinstance(statement, dict):
        return LEGACY_CONTENT_ROOT_ALG
    if "contentRootAlg" not in statement:
        return LEGACY_CONTENT_ROOT_ALG          # genuinely absent — the 2.0.0 receipts
    alg = statement["contentRootAlg"]
    if isinstance(alg, str) and alg:
        return alg                               # present and shaped like an id; registration is checked later
    return _PRESENT_BUT_UNUSABLE                 # present and unusable — fail-closed, never legacy


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


def _content_root_binding(statement: Any, body: bytes) -> tuple[bool, Optional[str], str]:
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
    # THE SENTINEL DRIVES THE DECISION, IT DOES NOT GET REPORTED AS SIGNED CONTENT. Codex, review of
    # 2026-09-23 on PR 254: for canonical bytes of `{"contentRootAlg":null}` the verdict correctly
    # said ok=False, and then named `content_root_alg="invalid-contentRootAlg"` and "unknown
    # contentRootAlg 'invalid-contentRootAlg'" — a string that appears NOWHERE in the signed
    # payload, and the same for every unusable type. The shared builder below feeds all three
    # verify_*_dsse surfaces, so one place fixed it for all three.
    #
    # The signature boundary and the fail-closed verdict were never in question; what was wrong is
    # that the verdict claimed the document declared something it did not. `gemeldet` is therefore
    # None (nothing usable was declared) and the detail names the type actually found.
    unbrauchbar = alg is _PRESENT_BUT_UNUSABLE or alg == _PRESENT_BUT_UNUSABLE
    gemeldet: Optional[str] = None if unbrauchbar else alg
    if unbrauchbar:
        roh = statement.get("contentRootAlg") if isinstance(statement, dict) else None
        return False, gemeldet, (
            f"contentRootAlg is present but unusable (found {type(roh).__name__} {roh!r}); a "
            "declaration that names no algorithm is refused rather than read as absent")
    if not isinstance(statement, dict):
        return False, gemeldet, "payload is not a JSON in-toto Statement object"
    try:
        expected = _serialize_statement(statement, alg)
    except CanonicalizerUnavailable:
        return False, alg, ("cannot verify jcs-sha256-v1 canonicality — install proofbundle[eval] "
                            "(fail-closed; never a silent pass over non-canonical bytes)")
    except (ProofBundleError, ValueError) as exc:
        # adversarial re-audit round 3: the BASE ProofBundleError (CanonicalizerUnavailable already handled
        # above) keeps any sibling — a BudgetExceeded/UnsupportedError from serialization — fail-closed here.
        # adversarial re-audit round 4: rfc8785.dumps raises FloatDomainError (NaN/Infinity) and IntegerDomainError
        # (an oversized JSON integer under loads_strict's digit cap) — BOTH ValueError subclasses, NOT
        # ProofBundleError. A hostile signed statement carrying such a value escaped verify_*_dsse raw
        # (_content_root_binding runs even when ok=False). Catching the ValueError family fails it closed.
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
    verdikt = require_bool_verdict(claim, wo="to_test_result_statement")
    model_desc: dict[str, Any] = {
        "name": "model-id-commitment",
        "digest": {MODEL_COMMIT_DIGEST_KEY: _commit_hex(claim["model_id_commit"])},
        "annotations": {
            "suite": claim["suite"],
            "metric": claim["metric"],
            "comparator": claim["comparator"],
            "threshold": claim["threshold"],
            "passed": verdikt,
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
        # `_RESULT_ENUM[verdikt]` and not `[bool(...)]`: the enum is keyed by True/False, so an indexing
        # KeyError would be the honest failure for anything else — but the refusal above says WHICH field
        # and WHICH type, which a KeyError never could.
        "result": _RESULT_ENUM[verdikt],
        "configuration": configuration,
    }
    suite = claim.get("suite")
    if suite:
        key = "passedTests" if verdikt else "failedTests"
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


def _intoto_verify_result(sig_ok, binding_ok, statement, alg, detail, expected_predicate_type) -> dict:
    """Shared verify-result builder for the three DSSE verify functions (WP-I1). ``ok`` conjuncts the
    signature, the content-root binding, AND — unless ``expected_predicate_type`` is None — that the
    statement's ``predicateType`` equals it (predicate-confusion defense). ``predicate_type_ok`` carries
    the granular verdict; ``predicate_type`` the value found."""
    got = statement.get("predicateType") if isinstance(statement, dict) else None
    if expected_predicate_type is None:
        type_ok = None
        merged_detail = detail
    else:
        type_ok = (got == expected_predicate_type)
        merged_detail = detail if type_ok else (
            (detail + "; " if detail else "")
            + f"predicateType {got!r} != expected {expected_predicate_type!r} (confusion attack?)")
    ok = bool(sig_ok) and binding_ok and (type_ok is not False)
    return {"ok": ok, "statement": statement, "predicate_type": got,
            "predicate_type_ok": type_ok, "content_root_alg": alg,
            "content_root_ok": binding_ok, "content_root_detail": merged_detail}


def verify_intoto_dsse(envelope: dict, public_key: bytes, *,
                       expected_predicate_type: str = TEST_RESULT_PREDICATE_TYPE) -> dict:
    """Verify a DSSE-signed in-toto test-result attestation from ``export_intoto_dsse``. Returns
    {ok, statement, predicate_type, predicate_type_ok, content_root_alg, content_root_ok,
    content_root_detail}. ``ok`` is True iff the Ed25519 signature over the DSSE PAE verifies, the
    payloadType is the pinned test-result media type, the payload is canonical for its DECLARED
    contentRootAlg (absent ⇒ legacy; ADR 0002), AND the statement's ``predicateType`` equals
    ``expected_predicate_type`` (WP-I1: the type was previously only RETURNED, so ``ok`` was True for a
    swapped-predicate confusion attack — an SVR or eval-result envelope accepted as a test-result).
    Pass ``expected_predicate_type=None`` to opt out of the type check (returns it as before)."""
    from . import dsse  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415

    try:
        # RE-GATE never-raise: crypto verify + body load + input_bytes budget + strict parse inside the
        # never-raise guard; a wide/oversized (BudgetExceeded) / dup-key (BundleFormatError) / malformed
        # untrusted envelope yields a fail-closed verdict, never a raw exception out of this dict-returning
        # verify surface (mirrors decision/outcome/run_ledger).
        ok = dsse.verify_envelope(envelope, public_key, payload_type=TEST_RESULT_PAYLOAD_TYPE)
        body = dsse.load_payload(envelope)
        statement = loads_strict(body.decode("utf-8"))   # WP-C1: duplicate keys rejected fail-closed
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        return _intoto_verify_result(False, False, None, None,
                                     f"DSSE payload rejected (fail-closed): {exc}",
                                     expected_predicate_type)
    binding_ok, alg, detail = _content_root_binding(statement, body)
    return _intoto_verify_result(ok, binding_ok, statement, alg, detail, expected_predicate_type)


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


def _require_export_fields(claim: dict) -> bool:
    """Refuse to export an invalid/incomplete receipt claim (Paket 2 test 3).

    RETURNS THE VALIDATED VERDICT, and that return type is the fix for a review finding rather than a
    convenience. See the comment at the emit site: a caller that re-reads the field instead of using
    this value can be handed a different value than the one that was checked.
    """
    if not isinstance(claim, dict):
        raise BundleFormatError("eval-result export needs a claim object")
    missing = [k for k in _EXPORT_REQUIRED if claim.get(k) in (None, "")]
    if missing:
        raise BundleFormatError(f"refusing to export: claim is missing required field(s) {missing}")
    # PRESENCE IS NOT TYPE, and `passed` is in _EXPORT_REQUIRED, which is exactly why this was missed:
    # the field was required and therefore looked checked. `"false"` is a non-empty string, so it passes
    # the loop above; R-B4. The type check belongs here rather than at each caller of this function.
    return require_bool_verdict(claim, wo="refusing to export")


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
    verdikt = _require_export_fields(claim)
    _forbid_plaintext_in_export(claim)
    predicate: dict[str, Any] = {
        "verifier": {"id": VERIFIER_ID},
        "evaluatedAt": claim["timestamp"],
        "suite": {"name": claim["suite"], "version": claim.get("suite_version")},
        "claims": [{
            "metric": claim["metric"], "comparator": claim["comparator"],
            # THE VALIDATED VALUE, NOT A SECOND READ -- and this comment replaces one that argued
            # for the wrong thing. It said: `claim["passed"]` raw rather than `bool(...)`, because
            # `_require_export_fields` above already refuses anything that is not a boolean. That
            # argument was about COERCION and passed over the ACCESSOR: what was validated is
            # `claim.get("passed")`, what was emitted is `claim["passed"]`. For a dict whose `get`
            # and `__getitem__` disagree those are two values. Measured 2026-09-24 with a dict
            # subclass whose `get("passed")` returns True while the stored item is `"false"`: the
            # validation passed, the predicate carried the string, and the DSSE path signed it.
            # THE CLASS: a check through one accessor and a use through another. The guard is not a
            # third accessor but PASSING THE VALIDATED VALUE ON.
            "threshold": claim["threshold"], "passed": verdikt,
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


def verify_eval_result_dsse(envelope: dict, public_key: bytes, *,
                            expected_predicate_type: Optional[str] = EVAL_RESULT_PREDICATE_TYPE) -> dict:
    """Verify a DSSE-signed eval-result attestation. Returns {ok, statement, predicate_type,
    predicate_type_ok, content_root_alg, content_root_ok, content_root_detail, predicate_shape_ok,
    predicate_shape_detail}. `ok` is True iff the Ed25519 signature over the DSSE PAE verifies, payloadType
    is the pinned in-toto Statement media type, the payload is canonical for its DECLARED contentRootAlg
    (absent ⇒ legacy; ADR 0002), the statement's `predicateType` equals `expected_predicate_type` (WP-I1:
    predicate-confusion defense — the type was previously only returned, so a swapped SVR/test-result
    envelope was accepted as an eval-result), AND, for a statement that declares
    `EVAL_RESULT_V02_PREDICATE_TYPE`, its predicate has the v0.2 shape (`classify_eval_result_v02_predicate`).

    The default still expects v0.1, and a v0.1 statement is judged exactly as before (no shape check,
    `predicate_shape_ok` None). To verify v0.2, pass `expected_predicate_type=EVAL_RESULT_V02_PREDICATE_TYPE`.
    Pass `expected_predicate_type=None` to opt out of the type check; the shape of a v0.2 statement is
    checked all the same."""
    from . import dsse  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415

    try:
        # RE-GATE never-raise (mirror verify_intoto_dsse): crypto + load + budget + parse inside the guard;
        # a wide/oversized/dup-key/malformed untrusted envelope yields a fail-closed verdict, never a raw
        # exception out of this dict-returning verify surface.
        ok = dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        body = dsse.load_payload(envelope)
        statement = loads_strict(body.decode("utf-8"))   # WP-C1: duplicate keys rejected fail-closed
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        res = _intoto_verify_result(False, False, None, None,
                                    f"DSSE payload rejected (fail-closed): {exc}",
                                    expected_predicate_type)
        res["predicate_shape_ok"], res["predicate_shape_detail"] = None, ""
        return res
    binding_ok, alg, detail = _content_root_binding(statement, body)
    res = _intoto_verify_result(ok, binding_ok, statement, alg, detail, expected_predicate_type)
    # THE CONTRACT FOLLOWS THE TYPE THE SIGNED STATEMENT DECLARES, not the type the caller expected: a
    # v0.2 statement is judged under v0.2 even when the caller opted out of the type check, and a v0.1
    # statement is never judged under v0.2. v0.1 has no shape contract and gets none now (G2: old
    # evidence stays verifiable under its old contract); `None` says that no shape was checked.
    if res["predicate_type"] == EVAL_RESULT_V02_PREDICATE_TYPE:
        shape_ok, shape_detail = classify_eval_result_v02_predicate(statement)
        res["predicate_shape_ok"], res["predicate_shape_detail"] = shape_ok, shape_detail
        if not shape_ok:
            res["ok"] = False
            res["content_root_detail"] = (
                (res["content_root_detail"] + "; " if res["content_root_detail"] else "") + shape_detail)
    else:
        res["predicate_shape_ok"], res["predicate_shape_detail"] = None, ""
    return res


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# eval-result v0.2 — the revised in-toto/attestation#575 draft (docs/upstream/eval-result.md).
# ─────────────────────────────────────────────────────────────────────────────────────────────────

# A URI with a scheme and no whitespace or control character (RFC 3986 shape, not a registry lookup).
_URI_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*:[^\s\x00-\x1f\x7f]+\Z")
_RFC3339_RE = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))\Z")
_LOWER_HEX_RE = re.compile(r"\A[0-9a-f]+\Z")
# The claim builder's grammar for a decimal string (evalclaim._DECIMAL_RE): the draft says "decimal
# string" and gives no grammar, so this is the reading implemented (ambiguity A3, docs/IN_TOTO_PROFILE.md).
_DECIMAL_STRING_RE = re.compile(r"\A-?[0-9]+(\.[0-9]+)?\Z")
# Fixed output lengths of the hash functions: a digest under one of these names that has another length,
# or is not lowercase hex, names no content. Every other algorithm name only needs a non-empty string.
_HEX_DIGEST_LENGTHS = (("md5", 32), ("sha1", 40), ("sha224", 56), ("sha256", 64), ("sha384", 96),
                       ("sha512", 128), ("sha512_224", 56), ("sha512_256", 64), ("sha3_224", 56),
                       ("sha3_256", 64), ("sha3_384", 96), ("sha3_512", 128))
_V02_COMPARATORS = (">=", ">", "<=", "<")
_V02_ASSURANCE_LEVELS = ("self_attested", "third_party", "reproduced", "enclave_attested")
_RD_STRING_FIELDS = ("name", "uri", "mediaType", "downloadLocation", "content")
_MAX_SAFE_INT = 2 ** 53 - 1


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_rfc3339(value: Any) -> bool:
    """An RFC 3339 date-time with an offset, and a real calendar date (no month 13, no 30 February)."""
    if not isinstance(value, str):
        return False
    m = _RFC3339_RE.match(value)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if not 1 <= month <= 12:
        return False
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    if not (1 <= day <= days and hour <= 23 and minute <= 59 and second <= 60):
        return False
    if m.group(8) is not None and (int(m.group(8)) > 23 or int(m.group(9)) > 59):
        return False
    return True


def _digest_set_problem(value: Any) -> str:
    """'' for a usable DigestSet, else what is wrong with it."""
    if not isinstance(value, dict):
        return f"digest must be a DigestSet object, got {type(value).__name__}"
    if not value:
        return "digest is empty"
    for alg, hexval in value.items():
        if not _nonempty_str(alg):
            return "digest has an empty algorithm name"
        if not _nonempty_str(hexval):
            return f"digest {alg[:40]!r} must be a non-empty string"
        for name, length in _HEX_DIGEST_LENGTHS:
            if alg == name and (len(hexval) != length or not _LOWER_HEX_RE.match(hexval)):
                return f"digest {alg!r} must be {length} lowercase hex characters"
    return ""


def _descriptor_problem(value: Any, where: str) -> str:
    """'' for a ResourceDescriptor that MUST carry `digest` (model, dataset, evidence entries)."""
    if not isinstance(value, dict):
        return f"{where} must be a ResourceDescriptor object, got {type(value).__name__}"
    if "digest" not in value:
        return f"{where} MUST carry digest"
    problem = _digest_set_problem(value["digest"])
    if problem:
        return f"{where}: {problem}"
    for field in _RD_STRING_FIELDS:
        if field in value and not isinstance(value[field], str):
            return f"{where}.{field} must be a string"
    if "annotations" in value and not isinstance(value["annotations"], dict):
        return f"{where}.annotations must be an object"
    return ""


def _commitment_problem(value: Any, where: str) -> str:
    """'' for a commitment entry `{alg, value, salted}`. A present entry that is not usable (null, a
    list, a missing field) is refused, never read as absent."""
    if not isinstance(value, dict):
        return f"{where} must be an object {{alg, value, salted}}, got {type(value).__name__}"
    if not _nonempty_str(value.get("alg")):
        return f"{where}.alg must be a non-empty string"
    hexval = value.get("value")
    if not (isinstance(hexval, str) and _LOWER_HEX_RE.match(hexval)):
        return f"{where}.value must be a non-empty lowercase hex string"
    if not isinstance(value.get("salted"), bool):
        return f"{where}.salted must be a boolean"
    return ""


def _claim_problems(claim: Any, where: str) -> list:
    if not isinstance(claim, dict):
        return [f"{where} must be an object {{metric, comparator, threshold, passed}}"]
    out = []
    if not _nonempty_str(claim.get("metric")):
        out.append(f"{where}.metric must be a non-empty string")
    comparator = claim.get("comparator")
    if not (isinstance(comparator, str) and comparator in _V02_COMPARATORS):
        out.append(f"{where}.comparator must be one of >=, >, <=, <")
    threshold = claim.get("threshold")
    if not (isinstance(threshold, str) and _DECIMAL_STRING_RE.match(threshold)):
        out.append(f"{where}.threshold must be a decimal string, never a JSON number")
    if not isinstance(claim.get("passed"), bool):
        out.append(f"{where}.passed must be a boolean")
    return out


def _eval_result_v02_predicate_problems(pred: Any) -> list:
    """Every way `pred` departs from the v0.2 predicate. Unknown fields are ignored at every level (in-toto
    parsing rules); a KNOWN field that is present must be usable, and a present-but-unusable value is
    refused rather than read as absent."""
    if not isinstance(pred, dict):
        return [f"predicate must be an object, got {type(pred).__name__}"]
    out = []
    evaluator = pred.get("evaluator")
    if not isinstance(evaluator, dict):
        hint = " (found `verifier`, the v0.1 role name)" if "verifier" in pred else ""
        out.append(f"evaluator is required: an object with id, the URI of the party that ran the evaluation{hint}")
    elif not (isinstance(evaluator.get("id"), str) and _URI_RE.match(evaluator["id"])):
        out.append("evaluator.id is required and must be a URI (TypeURI)")
    if not _is_rfc3339(pred.get("evaluatedAt")):
        out.append("evaluatedAt is required and must be an RFC 3339 date-time with an offset")
    suite = pred.get("suite")
    if not (isinstance(suite, dict) and _nonempty_str(suite.get("name")) and _nonempty_str(suite.get("version"))):
        out.append("suite is required: {name, version}, both non-empty strings")
    claims = pred.get("claims")
    if not isinstance(claims, list) or not claims:
        out.append("claims is required: one or more {metric, comparator, threshold, passed}")
    else:
        for i, claim in enumerate(claims):
            out.extend(_claim_problems(claim, f"claims[{i}]"))
    size = pred.get("sampleSize")
    if not (isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= _MAX_SAFE_INT):
        out.append("sampleSize is required: a non-negative integer")
    commitments: Any = pred.get("commitments", {})
    if not isinstance(commitments, dict):
        out.append(f"commitments must be an object, got {type(commitments).__name__}")
        commitments = {}
    for identity in ("model", "dataset"):
        forms = [form for form, present in ((f"commitments.{identity}", identity in commitments),
                                            (f"a top-level {identity} descriptor", identity in pred)) if present]
        if len(forms) != 1:
            found = " and ".join(forms) if forms else "neither"
            out.append(f"{identity} must be identified exactly once, by commitments.{identity} or by a "
                       f"top-level {identity} ResourceDescriptor; found {found}")
        elif identity in pred:
            problem = _descriptor_problem(pred[identity], identity)
            if problem:
                out.append(problem)
        else:
            problem = _commitment_problem(commitments[identity], f"commitments.{identity}")
            if problem:
                out.append(problem)
    level = pred.get("assuranceLevel")
    if not (isinstance(level, str) and level in _V02_ASSURANCE_LEVELS):
        out.append("assuranceLevel must be one of " + ", ".join(_V02_ASSURANCE_LEVELS))
    profile = pred.get("subjectProfile")
    if not (isinstance(profile, str) and profile in SUBJECT_PROFILES):
        out.append("subjectProfile must be one of " + ", ".join(SUBJECT_PROFILES))
    if "preRegistration" in pred:
        prereg = pred["preRegistration"]
        if not (isinstance(prereg, dict) and _nonempty_str(prereg.get("alg"))
                and isinstance(prereg.get("value"), str) and _LOWER_HEX_RE.match(prereg["value"])):
            out.append("preRegistration must be {alg, value} with a lowercase hex value")
    if "evidence" in pred:
        evidence = pred["evidence"]
        if not isinstance(evidence, list):
            out.append(f"evidence must be an array of ResourceDescriptors, got {type(evidence).__name__}")
        else:
            for i, entry in enumerate(evidence):
                problem = _descriptor_problem(entry, f"evidence[{i}]")
                if problem:
                    out.append(problem)
    if "harness" in pred:
        harness = pred["harness"]
        if not (isinstance(harness, dict) and _nonempty_str(harness.get("name"))
                and _nonempty_str(harness.get("version"))):
            out.append("harness must carry name and version as non-empty strings")
        elif "digest" in harness:
            problem = _digest_set_problem(harness["digest"])
            if problem:
                out.append(f"harness: {problem}")
    return out


def classify_eval_result_v02_predicate(statement: Any) -> tuple[bool, str]:
    """Judge a Statement against eval-result v0.2 (the revised #575 draft). Returns ``(ok, detail)``;
    ``detail`` names every violation, joined by "; ", and is empty when ok. Never raises: the input is
    the content of a signed envelope, which is untrusted however valid the signature is.

    Refused: an absent or non-URI ``evaluator.id``; a model or dataset identified twice or not at all
    (``commitments.<x>`` against a top-level ResourceDescriptor); a descriptor or an evidence entry without
    a usable ``digest``; a required field that is absent or of the wrong type; a Statement whose ``_type``
    is not Statement v1 or whose subject carries no digest. Ignored: every unknown field, at every level,
    including the v0.1 ``receipt`` block, ``anchors`` and ``subjectDigestNote``. Not refused: an evidence
    entry without ``mediaType``, ``uri`` or ``downloadLocation`` (the draft says SHOULD)."""
    if not isinstance(statement, dict):
        return False, f"statement must be a JSON object, got {type(statement).__name__}"
    out = []
    if statement.get("_type") != STATEMENT_TYPE:
        out.append(f"_type must be {STATEMENT_TYPE}")
    subject = statement.get("subject")
    if not isinstance(subject, list) or not subject:
        out.append("subject must be a non-empty array")
    else:
        for i, entry in enumerate(subject):
            problem = _descriptor_problem(entry, f"subject[{i}]")
            if problem:
                out.append(problem)
    out.extend(_eval_result_v02_predicate_problems(statement.get("predicate")))
    return (not out), "; ".join(out)


def receipt_evidence(receipt_bytes: bytes, *, root_b64: Optional[str] = None,
                     uri: Optional[str] = None) -> dict:
    """The `evidence[]` entry for an eval receipt: a ResourceDescriptor whose digest is the SHA-256 of the
    receipt file's exact bytes, so a generic consumer can fetch the file and compare. The Merkle root, which
    v0.1 carried in its `receipt` block, travels as an annotation for a consumer that verifies the receipt
    itself; the draft does not interpret it. `uri` is where the receipt can be fetched (the draft's SHOULD)."""
    if not isinstance(receipt_bytes, (bytes, bytearray)):
        raise BundleFormatError(
            f"receipt_evidence needs the receipt file's bytes, got {type(receipt_bytes).__name__}")
    descriptor: dict[str, Any] = {
        "name": "eval-receipt",
        "digest": {"sha256": hashlib.sha256(bytes(receipt_bytes)).hexdigest()},
        "mediaType": "application/json",
    }
    if uri is not None:
        if not (isinstance(uri, str) and _URI_RE.match(uri)):
            raise BundleFormatError("receipt_evidence: uri must be a URI")
        descriptor["uri"] = uri
    if root_b64:
        descriptor["annotations"] = {"merkleRootB64": root_b64}
    return descriptor


def to_eval_result_v02_predicate(claim: dict, *, evaluator_id: str, subject_profile: str = "receipt",
                                 model: Optional[dict] = None, dataset: Optional[dict] = None,
                                 evidence: Optional[list] = None, harness: Optional[dict] = None) -> dict:
    """Build the eval-result v0.2 predicate from a receipt claim.

    * ``evaluator_id``: the URI of the party that ran the evaluation. Required, no default: proofbundle
      records a result, it does not run the evaluation, so its own URI would name the wrong party.
    * ``model`` / ``dataset``: a ResourceDescriptor with a real ``digest`` for a PUBLIC identity. When given,
      it replaces the salted commitment for that identity; when not, the commitment is written. Each
      identity is therefore identified exactly once.
    * ``evidence``: ResourceDescriptors, each with a ``digest`` (see ``receipt_evidence``).

    ``subjectDigestNote`` stays for the receipt profile: its subject digest is a binder that names no file,
    and the note says so. ``anchors`` is not written: the draft scoped it out, and an external anchor is
    carried as an ``evidence`` entry with its own digest. Refuses a claim that carries a plaintext
    identifier or a salt, and a claim without ``suite_version`` (the draft requires ``suite.version``)."""
    verdikt = _require_export_fields(claim)
    _forbid_plaintext_in_export(claim)
    if not (isinstance(evaluator_id, str) and _URI_RE.match(evaluator_id)):
        raise BundleFormatError(
            "eval-result v0.2 needs evaluator_id, the URI of the party that ran the evaluation; there is no "
            "default, because the tool that records a result is not the party that produced it")
    suite_version = claim.get("suite_version")
    if not _nonempty_str(suite_version):
        raise BundleFormatError("eval-result v0.2 needs the claim's suite_version: suite is {name, version}")
    predicate: dict[str, Any] = {
        "evaluator": {"id": evaluator_id},
        "evaluatedAt": claim["timestamp"],
        "suite": {"name": claim["suite"], "version": suite_version},
        # `verdikt`, the validated value, never a second read of claim["passed"] (see to_eval_result_predicate).
        "claims": [{"metric": claim["metric"], "comparator": claim["comparator"],
                    "threshold": claim["threshold"], "passed": verdikt}],
        "sampleSize": claim["n"],
    }
    commitments: dict[str, Any] = {}
    if model is None:
        commitments["model"] = _commitment(claim["model_id_commit"], claim.get("commit_alg"))
    else:
        predicate["model"] = copy.deepcopy(model)
    if dataset is None:
        commitments["dataset"] = _commitment(claim["dataset_id_commit"], claim.get("commit_alg"))
    else:
        predicate["dataset"] = copy.deepcopy(dataset)
    if commitments:
        predicate["commitments"] = commitments
    predicate["assuranceLevel"] = claim.get("assurance_level", "self_attested")
    predicate["subjectProfile"] = subject_profile
    if subject_profile == "receipt":
        predicate["subjectDigestNote"] = (
            "subject.digest is a binder over the receipt commitments+root, not an artifact hash")
    prereg = claim.get("prereg_sha256")
    if prereg:
        predicate["preRegistration"] = {"alg": "sha256", "value": prereg}
    if evidence is not None:
        predicate["evidence"] = copy.deepcopy(evidence)
    if harness is not None:
        predicate["harness"] = copy.deepcopy(harness)
    problems = _eval_result_v02_predicate_problems(predicate)
    if problems:
        raise BundleFormatError(
            "refusing to emit an eval-result v0.2 predicate its own verifier refuses: " + "; ".join(problems))
    return predicate


def to_eval_result_v02_statement(claim: dict, *, subject: list, evaluator_id: str,
                                 subject_profile: str = "receipt", model: Optional[dict] = None,
                                 dataset: Optional[dict] = None, evidence: Optional[list] = None,
                                 harness: Optional[dict] = None,
                                 content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """A STANDARD in-toto Statement v1 carrying the eval-result v0.2 predicate, with its content-root
    algorithm declared (default `jcs-sha256-v1`). Refuses to return a Statement that
    `classify_eval_result_v02_predicate` would refuse."""
    statement = _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": EVAL_RESULT_V02_PREDICATE_TYPE,
        "predicate": to_eval_result_v02_predicate(
            claim, evaluator_id=evaluator_id, subject_profile=subject_profile, model=model, dataset=dataset,
            evidence=evidence, harness=harness),
    }, content_root_alg)
    ok, detail = classify_eval_result_v02_predicate(statement)
    if not ok:
        raise BundleFormatError(f"refusing to emit an eval-result v0.2 statement its own verifier refuses: {detail}")
    return statement


def export_eval_result_v02_dsse(claim: dict, signer, *, evaluator_id: str, subject_profile: str = "receipt",
                                subject_name: Optional[str] = None, subject_sha256: Optional[str] = None,
                                root_b64: Optional[str] = None, model: Optional[dict] = None,
                                dataset: Optional[dict] = None, evidence: Optional[list] = None,
                                harness: Optional[dict] = None, keyid: Optional[str] = None,
                                content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Export a receipt claim as a DSSE-signed eval-result v0.2 Statement. `root_b64` feeds the receipt
    profile's subject binder; the receipt itself is referenced through `evidence` (`receipt_evidence`).
    Deterministic: identical inputs give byte-identical statement bytes. Verify with
    `verify_eval_result_dsse(..., expected_predicate_type=EVAL_RESULT_V02_PREDICATE_TYPE)`."""
    from . import dsse  # noqa: PLC0415 — lazy: keeps the verify core free of the DSSE module

    _require_export_fields(claim)          # fail-closed BEFORE building the (receipt-profile) subject binder
    _forbid_plaintext_in_export(claim)
    subject = resolve_subject(subject_profile, claim, root_b64=root_b64,
                              subject_name=subject_name, subject_sha256=subject_sha256)
    statement = to_eval_result_v02_statement(
        claim, subject=subject, evaluator_id=evaluator_id, subject_profile=subject_profile, model=model,
        dataset=dataset, evidence=evidence, harness=harness, content_root_alg=content_root_alg)
    body = _serialize_statement(statement, content_root_alg)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


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
    passed. A missing optional check produces NO property (never a placeholder).

    **No-Overclaim scope (6-lens review):** `PROOFBUNDLE_SIGNATURE_VALID` / `PROOFBUNDLE_RECEIPT_UNCHANGED`
    / `PROOFBUNDLE_THRESHOLD_MET` / `PROOFBUNDLE_SAMPLE_ROOT_VALID` are derived from the passed
    `VerificationResult`/`claim` here. But `PROOFBUNDLE_PREREG_BOUND` and `PROOFBUNDLE_ANCHOR_VALID` are
    emitted PURELY from the caller's `prereg_verified` / `anchor_verified` flags — this function does NOT
    call `anchors.verify_anchors()` and does not check the anchor itself. They are CALLER-ATTESTED: the
    caller MUST have run a real offline anchor verification before passing the flag, or the signed SVR
    asserts a property it did not verify. A present prereg hash or an `anchors[]` block alone is NOT a
    verified binding."""
    # THE MOST LOAD-BEARING OF THE SIX SITES, because what it decides gets SIGNED. Measured 2026-09-24:
    # `passed="false"` put PROOFBUNDLE_THRESHOLD_MET into a signed SVR while the real `False` produced an
    # empty property list. This function is public, so the check belongs here and not only at
    # `export_svr_dsse`, whose `decode_eval_claim` now refuses a non-boolean one layer earlier. R-B4.
    verdikt = require_bool_verdict(claim, wo="svr_properties")
    checks = {c.name: c.ok for c in result.checks}
    props = []
    if checks.get("ed25519-signature"):
        props.append("PROOFBUNDLE_SIGNATURE_VALID")
    if checks.get("merkle-inclusion"):
        props.append("PROOFBUNDLE_RECEIPT_UNCHANGED")
    if verdikt:
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
    """Emit an in-toto SVR (svr/v0.1) for a receipt — after a real, passing signature/merkle/threshold
    verification (done here).

    Refuses (fail-closed) if the receipt is not a valid eval receipt, does not cryptographically verify,
    OR did not pass its threshold. SVR carries only PASSING property strings; there is no FAILED form
    (that would be a VSA with a PASSED|FAILED verdict — deliberately NOT implemented here, see docs). The
    subject is the receipt digest; no secrets ever enter the statement.

    **Caller-attested properties (No-Overclaim, 6-lens review):** `prereg_verified` / `anchor_verified`
    are NOT verified by this function — it does not call `anchors.verify_anchors()`. If you pass them, the
    signed SVR asserts `PROOFBUNDLE_PREREG_BOUND` / `PROOFBUNDLE_ANCHOR_VALID` on your word; run a real
    offline anchor verification first, or leave them False."""
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


def classify_svr_predicate_shape(statement: Any) -> tuple[bool, str]:
    """Structural check of an SVR Statement's predicate — the shape every consumer dereferences.

    RT-06 (deep gate 2026-09-05, L3-600-06): a VALIDLY SIGNED SVR whose ``predicate`` was a list, or whose
    ``properties`` was an int, made ``proofbundle svr --verify`` print ``[PASS] SVR attestation`` and then
    crash on the dereference. The signature proves who signed the bytes; it says nothing about whether
    the bytes have the shape the consumer is about to walk. So the shape is checked HERE, as part of the
    library verdict, and a consumer never has to guess. Returns ``(ok, detail)``; ``detail`` is empty
    when ok. Deliberately narrow: only what svr/v0.1 declares (predicate object, ``properties`` a list of
    strings, ``verifier`` an object when present, ``timeCreated`` a string when present).

    NAMED ``classify_`` ON PURPOSE (2026-09-05, after the never-raise family property reported it): this
    function takes UNTRUSTED input (a statement out of a signed envelope) and must JUDGE rather than crash,
    so it belongs in the never-raise denominator — and the ``classify_`` family is how that denominator is
    built. Widening the allowlist by one bespoke name would have put it beside the property instead of
    under it; the family test now fuzzes this function like every sibling."""
    if not isinstance(statement, dict):
        return False, "statement is not a JSON object"
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False, f"SVR predicate must be an object, got {type(predicate).__name__}"
    props = predicate.get("properties")
    if not isinstance(props, list):
        return False, f"SVR predicate.properties must be a list of strings, got {type(props).__name__}"
    if not all(isinstance(p, str) for p in props):
        return False, "SVR predicate.properties must contain strings only"
    if "verifier" in predicate and not isinstance(predicate["verifier"], dict):
        return False, "SVR predicate.verifier must be an object"
    if "timeCreated" in predicate and not isinstance(predicate["timeCreated"], str):
        return False, "SVR predicate.timeCreated must be a string"
    return True, ""


def verify_svr_dsse(envelope: dict, public_key: bytes, *,
                    expected_predicate_type: str = SVR_PREDICATE_TYPE) -> dict:
    """Verify a DSSE-signed SVR attestation. Returns {ok, statement, predicate_type, predicate_type_ok,
    content_root_alg, content_root_ok, content_root_detail}. `ok` requires the signature, the canonical
    contentRootAlg (absent ⇒ legacy; ADR 0002), AND the statement's `predicateType` == the SVR type
    (WP-I1: predicate-confusion defense — a swapped eval-result/test-result envelope was accepted as an
    SVR because the type was only returned). Pass `expected_predicate_type=None` to opt out."""
    from . import dsse  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415

    try:
        # RE-GATE never-raise (mirror verify_intoto_dsse): crypto + load + budget + parse inside the guard;
        # a wide/oversized/dup-key/malformed untrusted envelope yields a fail-closed verdict, never a raw
        # exception out of this dict-returning verify surface.
        ok = dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        body = dsse.load_payload(envelope)
        statement = loads_strict(body.decode("utf-8"))   # WP-C1: duplicate keys rejected fail-closed
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        return _intoto_verify_result(False, False, None, None,
                                     f"DSSE payload rejected (fail-closed): {exc}",
                                     expected_predicate_type)
    binding_ok, alg, detail = _content_root_binding(statement, body)
    res = _intoto_verify_result(ok, binding_ok, statement, alg, detail, expected_predicate_type)
    # RT-06 (L3-600-06): the predicate SHAPE is part of the verdict. A signed statement whose predicate
    # is not what svr/v0.1 declares is not an SVR that verified — ``ok`` stays False and the reason is
    # named, so no consumer prints PASS and then walks a list that is an int.
    shape_ok, shape_detail = classify_svr_predicate_shape(statement)
    res["predicate_shape_ok"] = shape_ok
    if not shape_ok:
        res["ok"] = False
        res["content_root_detail"] = (
            (res["content_root_detail"] + "; " if res["content_root_detail"] else "") + shape_detail)
    return res
