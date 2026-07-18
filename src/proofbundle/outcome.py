"""Action Outcome Receipt predicate `action-outcome/v0.1` — hand-rolled, fail-closed validation.

The core of proofbundle 3.2.0 (EXPERIMENTAL). Third link of the receipt chain
``eval-result → decision-receipt → action-outcome``: an EXECUTOR (a policy role distinct from the
decisionMaker) signs what was actually done, bound by digest to a Decision Receipt (``decisionRef``).

Like the rest of proofbundle it does NOT depend on a runtime jsonschema library;
``schemas/action-outcome-v0.1.schema.json`` is the external/docs schema, this module is the enforced one.
Fail-closed: unknown fields, missing required fields, bad enums, non-RFC3339-``Z`` timestamps and malformed
digests are errors, never silently accepted.

No-Overclaim (§1.4): ``status == executed`` attests only WHO signed WHAT happened, never that the effect was
good, correct or desired. Role separation (executor ≠ decisionMaker) is ENFORCED at verify time when the
bound decision's maker id is supplied, not merely recommended.

Field names are lowerCamelCase (ITE-9).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from ._strict_json import loads_strict
from .errors import BundleFormatError, ProofBundleError
from .subject_binding import nested_closure_violations

ACTION_OUTCOME_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/action-outcome/v0.1"
OUTCOME_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_0_1_X = re.compile(r"^0\.1\.\d+$")

_OUTCOME_STATUS = {"executed", "refused", "failed", "partial"}
_OUTCOME_POLICY_PURPOSE = "outcome"

_REQUIRED_ALWAYS = (
    "schemaVersion", "outcomeId", "decisionRef", "executor", "requestedActionDigest",
    "status", "performedAt",
)
_OPTIONAL = ("actualActionDigest", "responseDigest", "effectDigest", "recordedAt", "policyPurpose",
             "traceContext", "limitations", "validity",
             # Finding 16 (self-fixable part, additive): receiverRefs / sequence — see the module-level
             # note above `_OUTCOME_RECEIVER_ROLE` for what each closes and its honest, documented limit.
             "receiverRefs", "sequence",
             # relation/v0.1 (EXPERIMENTAL, 3.3.0): typed signed lineage edges — validated fail-closed
             # by relation.validate_relationships (incl. per-edge closure), not by the generic walker.
             "relationships")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

_DIGEST_FIELDS = ("requestedActionDigest", "actualActionDigest", "responseDigest", "effectDigest")
_TIME_PATHS = ("performedAt", "recordedAt")

# Nested schema closure (Finding 04 / subject_binding.nested_closure_violations): a top-level
# additionalProperties:false does NOT, by itself, close traceContext/validity — an undeclared key inside
# one of them previously rode along silently. Verified against `outcome init`'s CLI template
# (traceContext={"traceparent": ""}) and tests/test_outcome_verify.py's validity={"audience", "nonce"}.
_NESTED_ALLOWED: dict[str, tuple[str, ...]] = {
    "traceContext": ("traceparent",),
    "validity": ("audience", "nonce"),
    # Finding 16 (additive): receiverRefs[] mirrors decision.py's evidenceRefs[] shape exactly (digest-bound
    # third-party corroboration refs); sequence is the optional run/seq gap-detection pair.
    "receiverRefs[]": ("relation", "digest", "receiverId", "receiverKeyId", "artifactDigest"),
    "sequence": ("runId", "seq"),
}


class OutcomeReceiptError(ProofBundleError):
    """An Action Outcome Receipt predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def validate_outcome_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return a list of fail-closed errors for an ``action-outcome/v0.1`` predicate (empty = valid).

    strict currently adds no extra required fields beyond _REQUIRED_ALWAYS (the outcome predicate is small and
    fully required by default); the flag is kept for signature parity with decision.py and future §-gates."""
    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    # additionalProperties:false — any unknown top-level key is fail-closed.
    for k in predicate:
        if k not in _ALLOWED_TOP:
            errors.append(f"unknown field {k!r} (additionalProperties:false)")

    for req in _REQUIRED_ALWAYS:
        if req not in predicate:
            errors.append(f"missing required field {req!r}")

    sv = predicate.get("schemaVersion")
    if "schemaVersion" in predicate and not (isinstance(sv, str) and _SEMVER_0_1_X.match(sv)):
        errors.append("schemaVersion must match 0.1.x")

    oid = predicate.get("outcomeId")
    if "outcomeId" in predicate and not (isinstance(oid, str) and oid):
        errors.append("outcomeId must be a non-empty string")

    # decisionRef binds to the Decision Receipt content root (a sha256 digest object).
    if "decisionRef" in predicate and not _is_digest(predicate.get("decisionRef")):
        errors.append("decisionRef must be a sha256 digest object (content root of the bound decision)")

    ex = predicate.get("executor")
    if "executor" in predicate:
        if not isinstance(ex, dict) or not isinstance(ex.get("id"), str) or not ex.get("id"):
            errors.append("executor must be an object with a non-empty string 'id'")
        else:
            for k in ex:
                if k not in ("id", "keyId"):
                    errors.append(f"executor.{k} is not an allowed field")
            if "keyId" in ex and not isinstance(ex.get("keyId"), str):
                errors.append("executor.keyId, when present, must be a string")

    for df in _DIGEST_FIELDS:
        if df in predicate and not _is_digest(predicate.get(df)):
            errors.append(f"{df}, when present, must be a sha256 digest object")

    st = predicate.get("status")
    if "status" in predicate and st not in _OUTCOME_STATUS:
        errors.append(f"status must be one of {sorted(_OUTCOME_STATUS)}, got {st!r}")

    for tp in _TIME_PATHS:
        v = predicate.get(tp)
        if tp in predicate and not (isinstance(v, str) and _RFC3339_Z.match(v)):
            errors.append(f"{tp} must be an RFC3339 UTC 'Z' timestamp")

    # policyPurpose (optional): when present it MUST be exactly 'outcome' — a wrong purpose is a
    # confusion/misrouting signal, fail-closed (the CLI maps this to exit 3).
    if "policyPurpose" in predicate and predicate.get("policyPurpose") != _OUTCOME_POLICY_PURPOSE:
        errors.append(
            f"policyPurpose must be {_OUTCOME_POLICY_PURPOSE!r} for an outcome receipt, "
            f"got {predicate.get('policyPurpose')!r}")

    lim = predicate.get("limitations")
    if "limitations" in predicate and not (isinstance(lim, list) and all(isinstance(x, str) for x in lim)):
        errors.append("limitations must be a list of strings")

    tc = predicate.get("traceContext")
    if "traceContext" in predicate and not isinstance(tc, dict):
        errors.append("traceContext must be an object")

    # receiverRefs (Finding 16, additive, optional): third-party receiver/observer corroboration of this
    # outcome, digest-bound EXACTLY like decision.py's evidenceRefs[] (`relation` + a sha256 content-root
    # `digest`); `receiverId`/`receiverKeyId` optionally identify the corroborating party (`receiverKeyId`
    # is what `receiver_trusted_by_role` checks against a Trust Pack's `outcomeReceivers` role).
    recv = predicate.get("receiverRefs")
    if isinstance(recv, list):
        for i, ref in enumerate(recv):
            if (not isinstance(ref, dict) or not isinstance(ref.get("relation"), str)
                    or not ref.get("relation") or not _is_digest(ref.get("digest"))):
                errors.append(f"receiverRefs[{i}] needs a non-empty string 'relation' and a sha256 'digest'")
                continue
            if "receiverId" in ref and not isinstance(ref.get("receiverId"), str):
                errors.append(f"receiverRefs[{i}].receiverId, when present, must be a string")
            if "receiverKeyId" in ref and not isinstance(ref.get("receiverKeyId"), str):
                errors.append(f"receiverRefs[{i}].receiverKeyId, when present, must be a string")
            if "artifactDigest" in ref and not _is_digest(ref.get("artifactDigest")):
                errors.append(f"receiverRefs[{i}].artifactDigest, when present, must be a sha256 digest")
    elif "receiverRefs" in predicate:
        errors.append("receiverRefs must be a list")

    # sequence (Finding 16, additive, optional): a monotone (runId, seq) counter an executor MAY opt into so
    # `detect_outcome_sequence_gaps` can spot a SUPPRESSED outcome later in the same run (a missing seq
    # number). Honest limit: an executor that omits `sequence` entirely (unchanged default) stays invisible
    # to gap detection — this only helps when the executor opts in.
    seqobj = predicate.get("sequence")
    if "sequence" in predicate:
        if not isinstance(seqobj, dict):
            errors.append("sequence must be an object")
        else:
            rid = seqobj.get("runId")
            if not (isinstance(rid, str) and rid):
                errors.append("sequence.runId must be a non-empty string")
            sq = seqobj.get("seq")
            if not (isinstance(sq, int) and not isinstance(sq, bool) and sq >= 0):
                errors.append("sequence.seq must be a non-negative integer")

    # validity (Finding 04): previously had NO structural check at all — a scalar validity (e.g. the bare
    # string "n-1") silently reached verify_outcome_receipt, which only guards with
    # `_val if isinstance(_val, dict) else {}` and so treated it as an absent validity object without ever
    # flagging the malformed shape.
    val = predicate.get("validity")
    if "validity" in predicate and not isinstance(val, dict):
        errors.append("validity must be an object")

    # relationships (optional, relation/v0.1 EXPERIMENTAL): typed, SIGNED lineage edges — inside the
    # predicate so the DSSE signature covers them; closure/enums/digests enforced fail-closed by the
    # relation module itself.
    if "relationships" in predicate:
        from .relation import validate_relationships
        errors.extend(f"relationships: {e}" if not e.startswith("relationships") else e
                      for e in validate_relationships(predicate.get("relationships")))

    # Nested schema closure (Finding 04): additionalProperties:false at the TOP level does not, by itself,
    # close traceContext/validity — an undeclared key inside either previously rode along silently.
    errors.extend(nested_closure_violations(predicate, _NESTED_ALLOWED))

    return errors


def require_valid_outcome_predicate(predicate: Any, *, strict: bool = False) -> None:
    """Raise :class:`OutcomeReceiptError` if the predicate is invalid; return ``None`` if valid."""
    errs = validate_outcome_predicate(predicate, strict=strict)
    if errs:
        raise OutcomeReceiptError("invalid action-outcome predicate: " + "; ".join(errs))


def outcome_execution_proven(predicate: Any) -> bool | None:
    """Whether ``status == executed`` is backed by a digest of what was actually done/effected.

    Returns None when status is not 'executed' (not applicable), True when an executed outcome carries an
    ``effectDigest`` or ``actualActionDigest`` (a digest of the real effect/action), False when 'executed' is
    self-asserted with no such digest (the honesty limit — a signed claim, not proof of the effect)."""
    if not isinstance(predicate, dict) or predicate.get("status") != "executed":
        return None
    return _is_digest(predicate.get("effectDigest")) or _is_digest(predicate.get("actualActionDigest"))


# Finding 01 (2026-07 verify-layer hardening): trust_pack.py DECLARES an `outcomeExecutors` role (the
# identity an outcome's executor is meant to be checked against) but no verify_* path ever CONSUMED it —
# docs/predicates/action-outcome.md §7 lists this explicitly as open/future work. This closes that gap.
_OUTCOME_EXECUTOR_ROLE = "outcomeExecutors"


def executor_trusted_by_role(executor: Any, trust_pack: dict) -> bool:
    """True iff ``executor.keyId`` is a member of ``trust_pack``'s ``outcomeExecutors`` role and is NOT
    revoked. ``trust_pack`` MUST be the PREDICATE of an ALREADY-authenticated Trust Pack — the caller is
    responsible for having separately verified its own signature/threshold via
    ``trust_pack.verify_trust_pack`` (mirrors how ``policy`` elsewhere in this repo is caller-trusted local
    config that verify_* never re-verifies itself). This function checks ROLE MEMBERSHIP only; it never
    re-derives trust in the pack itself.

    Fail-closed: a missing/malformed role, a missing/malformed ``executor.keyId``, or a revoked key are all
    False — never a silent pass. Never raises on malformed input."""
    if not isinstance(executor, dict) or not isinstance(trust_pack, dict):
        return False
    key_id = executor.get("keyId")
    if not isinstance(key_id, str) or not key_id:
        return False
    roles = trust_pack.get("roles")
    role = roles.get(_OUTCOME_EXECUTOR_ROLE) if isinstance(roles, dict) else None
    key_ids = role.get("keyIds") if isinstance(role, dict) else None
    if not isinstance(key_ids, list) or key_id not in key_ids:
        return False
    revoked = trust_pack.get("revoked")
    if isinstance(revoked, list) and key_id in revoked:
        return False
    return True


# Finding 16 (self-fixable part of "outcome is overwhelmingly executor-self-attested"): the GENUINE gap a
# receipt cannot close from inside proofbundle alone is producing an independent receiver signature —
# whether a downstream/receiving system is willing to sign an acknowledgement is ecosystem adoption outside
# this repo's control (SOTA motivation: Notarized Agents arXiv:2606.04193, Proof of Execution
# arXiv:2607.05397). What IS self-fixable and built here: the CAPABILITY to carry + verify such a receiver's
# corroboration once it exists — a `receiverRefs[]` field (digest-bound exactly like decision.py's
# `evidenceRefs[]`), an `outcomeReceivers` Trust Pack role (mirrors `outcomeExecutors`) analogous to
# `executor_trusted_by_role`, and wiring into `assurance.classify_receiver_corroboration` so a genuinely
# independent, cryptographically verified corroboration reaches `EvidenceLevel.INDEPENDENTLY_ATTESTED` — see
# `verify_outcome_receipt`'s `receiver_attestation_resolver` parameter. `EvidenceLevel.EFFECT_OBSERVED`
# stays honestly unreachable (see `assurance.EFFECT_OBSERVED_NOT_IMPLEMENTED`) — even a signed receiver
# receipt is a RECEIPT about the effect, never a live observation of the real-world effect itself.
_OUTCOME_RECEIVER_ROLE = "outcomeReceivers"


def receiver_trusted_by_role(receiver_key_id: Any, trust_pack: dict) -> bool:
    """True iff ``receiver_key_id`` (a ``receiverRefs[]`` entry's ``receiverKeyId``) is a non-revoked member
    of ``trust_pack``'s ``outcomeReceivers`` role (Finding 16, mirrors :func:`executor_trusted_by_role`
    exactly). ``trust_pack`` MUST be the PREDICATE of an ALREADY-authenticated Trust Pack — same caller
    contract as ``executor_trusted_by_role``: this function checks ROLE MEMBERSHIP only, it never re-derives
    trust in the pack itself.

    Fail-closed: a missing/malformed role, a missing/malformed ``receiver_key_id``, or a revoked key are all
    False — never a silent pass. Never raises on malformed input."""
    if not isinstance(receiver_key_id, str) or not receiver_key_id or not isinstance(trust_pack, dict):
        return False
    roles = trust_pack.get("roles")
    role = roles.get(_OUTCOME_RECEIVER_ROLE) if isinstance(roles, dict) else None
    key_ids = role.get("keyIds") if isinstance(role, dict) else None
    if not isinstance(key_ids, list) or receiver_key_id not in key_ids:
        return False
    revoked = trust_pack.get("revoked")
    if isinstance(revoked, list) and receiver_key_id in revoked:
        return False
    return True


def resolve_receiver_ref(ref: dict, *, receiver_payload: bytes | None = None,
                         artifact_bytes: bytes | None = None) -> dict:
    """Offline check of one ``receiverRefs[]`` entry against resolved evidence (no network) — Finding 16,
    mirrors ``decision.resolve_evidence_ref`` exactly (same content-root/artifact-pin contract, applied to a
    receiver/observer's corroborating statement instead of a decision's evidence).

    ``receiver_payload`` is the EXACT DSSE payload bytes of the referenced receiver/observer Statement; its
    content root is ``sha256`` over exactly these bytes (invariant under counter-signing/key rotation of
    that statement, changes only when its CONTENT changes). ``artifact_bytes`` is a fetched blob checked
    against the optional ``artifactDigest``. Returns ``{content_root_ok, artifact_ok, detail}``; a check not
    requested is ``None``. WHO signed the receiver statement (and whether that differs from the executor) is
    the caller's job via a ``receiver_attestation_resolver`` passed to ``verify_outcome_receipt`` — this
    function only resolves CONTENT, mirroring the same layering ``resolve_evidence_ref`` uses."""
    from . import anchors as _anchors_mod  # noqa: PLC0415
    out: dict[str, Any] = {"content_root_ok": None, "artifact_ok": None, "detail": ""}
    want = (ref.get("digest") or {}).get("sha256") if isinstance(ref, dict) else None
    if receiver_payload is not None:
        got = _anchors_mod.statement_content_root(receiver_payload).hex()
        out["content_root_ok"] = (got == want)
        if out["content_root_ok"] is False:
            out["detail"] = "receiver content root != receiverRefs[].digest (receiver content changed?)"
    if artifact_bytes is not None and isinstance(ref, dict) and "artifactDigest" in ref:
        got_a = hashlib.sha256(artifact_bytes).hexdigest()
        out["artifact_ok"] = (got_a == (ref.get("artifactDigest") or {}).get("sha256"))
        if out["artifact_ok"] is False:
            out["detail"] = (out["detail"] + "; " if out["detail"] else "") + "artifactDigest != fetched blob"
    return out


def detect_outcome_sequence_gaps(predicates) -> dict:
    """Best-effort gap detection across a set of outcome predicates that share an executor + ``sequence.runId``
    (Finding 16, additive) — a way to spot a SUPPRESSED outcome: an executor who silently omits emitting a
    failed/refused receipt in the middle of a run leaves a hole in its own opted-in ``seq`` counter.

    Groups by ``(executor.id, sequence.runId)``, collects the distinct ``seq`` values, and reports any
    missing integer between the observed min and max as a gap. Returns
    ``{(executorId, runId): {"seqs": sorted_list, "gaps": missing_ints, "complete": bool}}``.

    HONEST LIMIT (No-Overclaim, this is the documented boundary of the self-fixable part of Finding 16): gap
    detection works ONLY when the executor OPTS IN to the ``sequence`` field. An executor that omits
    ``sequence`` entirely (the unchanged default) is INVISIBLE to this check — a suppressed receipt with no
    sequence numbering leaves no trace for the outcome layer alone to detect; this closes the "detectable
    IF instrumented" gap, not the "executor chooses not to instrument" gap (an adoption question, same class
    as the receiver-signature limit above).

    Caller contract: ``predicates`` SHOULD already be crypto-verified by the caller — this is a pure
    structural scan over already-trusted predicate dicts, it performs no signature checking itself. Never
    raises: a predicate with a missing/malformed ``executor.id`` or ``sequence`` is simply skipped (not
    counted in any group), not a crash of the whole scan."""
    groups: dict[tuple[str, str], list[int]] = {}
    for p in predicates:
        if not isinstance(p, dict):
            continue
        ex = p.get("executor")
        seq = p.get("sequence")
        if not (isinstance(ex, dict) and isinstance(ex.get("id"), str) and ex.get("id")):
            continue
        if not isinstance(seq, dict):
            continue
        run_id = seq.get("runId")
        seq_no = seq.get("seq")
        if not (isinstance(run_id, str) and run_id
                and isinstance(seq_no, int) and not isinstance(seq_no, bool) and seq_no >= 0):
            continue
        key = (ex["id"], run_id)
        groups.setdefault(key, []).append(seq_no)
    out: dict = {}
    for key, seqs in groups.items():
        seqs_sorted = sorted(set(seqs))
        gaps = [n for n in range(seqs_sorted[0], seqs_sorted[-1] + 1) if n not in seqs_sorted]
        out[key] = {"seqs": seqs_sorted, "gaps": gaps, "complete": not gaps}
    return out


# ── Emit / verify (DSSE in-toto Statement) ──────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    """RFC-8785 (JCS) canonical bytes — shared ``canonical.canonicalize_statement`` primitive (ADR 0002), so
    the content root is computed from ONE definition. A missing ``[eval]`` extra surfaces as the predicate-
    local :class:`OutcomeReceiptError` (never a raw ImportError)."""
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise OutcomeReceiptError(
            "outcome receipts need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_outcome_statement(predicate: dict, *, subject_name: str | None = None,
                            subject_sha256: str | None = None) -> dict:
    """Build a STANDARD in-toto Statement v1 whose predicate is the Outcome Receipt. The subject is by DEFAULT
    a commitment to the predicate: sha256 over its RFC-8785 canonical form. A caller-supplied override is
    self-attested and NOT cross-checked (No-Overclaim, same discipline as build_decision_statement)."""
    errs = validate_outcome_predicate(predicate, strict=False)
    if errs:
        raise OutcomeReceiptError("invalid action-outcome predicate: " + "; ".join(errs))
    name = subject_name or f"outcome:{predicate.get('outcomeId', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": ACTION_OUTCOME_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_outcome_receipt(predicate: dict, signer, *, subject_name: str | None = None,
                         subject_sha256: str | None = None, keyid: str | None = None,
                         strict: bool = True) -> dict:
    """Sign an Outcome Receipt as a DSSE-signed in-toto Statement. Emission is RFC-8785 canonical. Fail-closed:
    an invalid predicate raises before signing."""
    from . import dsse  # noqa: PLC0415
    errs = validate_outcome_predicate(predicate, strict=strict)
    if errs:
        raise OutcomeReceiptError("invalid action-outcome predicate: " + "; ".join(errs))
    statement = build_outcome_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _empty_result() -> dict:
    return {
        "ok": None, "structure_ok": None, "crypto_ok": None,
        "predicate_type_ok": None, "decision_bound": None, "role_separation_ok": None,
        "execution_proven": None, "audience_ok": None, "nonce_ok": None,
        "subject_binding": None, "subject_derived_ok": None,
        # Finding 01 / Finding 03 (2026-07 verify-layer hardening, additive): executor_role_trusted is None
        # unless a trust_pack is supplied (outcomeExecutors role membership); automation/evidence_levels are
        # computed at the end of verify — none of these three change the fields above.
        "executor_role_trusted": None, "automation": None, "evidence_levels": None,
        # Finding 16 (additive): receiver_bound mirrors decision.py's evidence_bound (digest-shape only,
        # None when receiverRefs is absent/empty); receiver_role_trusted is None unless BOTH trust_pack and
        # a non-empty receiverRefs are supplied. Neither is wired into the aggregate `ok` (receiverRefs is
        # OPTIONAL supplementary evidence, not core to the outcome's own validity — see verify docstring).
        "receiver_bound": None, "receiver_role_trusted": None,
        "lineage": None, "lineage_ok": None,
        # WP-B (3.4.0): the relations trust-policy verdict on the OUTCOME path — identical gate + codes
        # as the decision path; None until a relations policy is supplied. policy_ok is the relations
        # verdict here (distinct from executor_role_trusted, which stays the trust_pack role gate).
        "policy_ok": None, "lineage_requirement_failed": None,
        "relations_policy_failed": None, "relations_policy_codes": None,
        "warnings": [], "errors": [],
    }


def _finalize_failclosed(r: dict) -> dict:
    """Finalize a never-raise fail-closed verify result (parse/structure failure over untrusted input):
    ok=False plus a consistent automation verdict, mirroring the full-run shape. PB-2026-0717-07."""
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["ok"] = False
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": "executor_role_trusted",
        "references": ["decision_bound", "role_separation_ok", "audience_ok", "nonce_ok",
                       "subject_derived_ok", "lineage_ok"],
    })
    return r


def verify_outcome_receipt_or_raise(envelope: dict, public_key: bytes, *, strict: bool = False,
                                    expected_decision_ref: str | None = None,
                                    decision_maker_id: str | None = None,
                                    expected_audience: str | None = None,
                                    expected_nonce: str | None = None,
                                    require_derived_subject: bool = False,
                                    trust_pack: dict | None = None,
                                    evidence_resolver: Callable[[dict], bool] | None = None,
                                    receiver_attestation_resolver: Callable[[dict], bool] | None = None,
                                    related: dict | None = None, policy: dict | None = None) -> dict:
    """Explicit-exception variant of :func:`verify_outcome_receipt`: raises :class:`BundleFormatError`
    when the payload is not a well-formed in-toto Statement, instead of returning a fail-closed verdict.
    Use :func:`verify_outcome_receipt` (never-raise) for untrusted input (PB-2026-0717-07). The explicit
    signature (not ``*args``) keeps it a first-class, fuzz-soakable/parity-discoverable verify surface."""
    return verify_outcome_receipt(
        envelope, public_key, strict=strict, expected_decision_ref=expected_decision_ref,
        decision_maker_id=decision_maker_id, expected_audience=expected_audience,
        expected_nonce=expected_nonce, require_derived_subject=require_derived_subject,
        trust_pack=trust_pack, evidence_resolver=evidence_resolver,
        receiver_attestation_resolver=receiver_attestation_resolver, related=related, policy=policy,
        _raise_on_malformed=True)


def verify_outcome_receipt(envelope: dict, public_key: bytes, *, strict: bool = False,
                           expected_decision_ref: str | None = None, decision_maker_id: str | None = None,
                           expected_audience: str | None = None, expected_nonce: str | None = None,
                           require_derived_subject: bool = False, trust_pack: dict | None = None,
                           evidence_resolver: Callable[[dict], bool] | None = None,
                           receiver_attestation_resolver: Callable[[dict], bool] | None = None,
                           related: dict | None = None, policy: dict | None = None,
                           _raise_on_malformed: bool = False) -> dict:
    """Verify a DSSE-signed Outcome Receipt. Crypto first, then structure over the EXACT signed bytes.

    Outcome-specific fail-closed checks (each applies only after crypto passes; non-applicable = None):

    - ``decision_bound`` — when ``expected_decision_ref`` is supplied, the predicate's ``decisionRef.sha256``
      MUST equal it. Replay of an outcome against a DIFFERENT decision fails (False + error).
    - ``role_separation_ok`` — when ``decision_maker_id`` is supplied, the executor's id MUST differ from it.
      An executor witnessing their own decision fails (False + error).
    - ``execution_proven`` — status=executed with a real effect/action digest is True; self-asserted executed
      is False + a No-Overclaim warning (not a hard aggregate fail — it is an honest limit, not tampering).
    - ``executor_role_trusted`` (Finding 01, additive) — when ``trust_pack`` is supplied (the PREDICATE of an
      ALREADY-authenticated Trust Pack, verified separately by the caller via
      ``trust_pack.verify_trust_pack``), the executor's ``keyId`` MUST be a non-revoked member of the pack's
      ``outcomeExecutors`` role (``outcome.executor_trusted_by_role``) — the "independent attestation of
      executor.id" gap docs/predicates/action-outcome.md §7 lists as open. Fail-closed when supplied; stays
      None (not evaluated) when ``trust_pack`` is omitted — fully backward compatible.

    Read ``ok`` (or ``crypto_ok``) — never an individual ``*_ok`` alone. On a forged envelope every trust-
    derived field stays None and an error is recorded, so a consumer cannot read a claim about unsigned bytes.

    ``evidence_resolver`` (Finding 03, additive): an optional callable ``f(digest_obj) -> bool`` checking a
    digest against ACTUALLY RESOLVED content; when supplied, ``evidence_levels["effect"]`` may reach
    ``assurance.EvidenceLevel.CONTENT_RESOLVED`` instead of stopping at ``REFERENCE_WELL_FORMED``. Never
    changes ``execution_proven`` (unchanged, additive) or the aggregate ``ok``.

    ``receiverRefs`` / Finding 16 (self-fixable part, additive) — third-party receiver/observer
    corroboration of this outcome, digest-bound exactly like ``evidenceRefs[]``:

    - ``receiver_bound`` — mirrors ``evidence_bound``: True iff every present ``receiverRefs[]`` entry is
      digest-shaped, ``None`` when ``receiverRefs`` is absent/empty (nothing to bind is not "bound").
    - ``evidence_levels["receiverRefs"]`` — the STRONGEST applicable entry (OR semantics: one corroborating
      receiver suffices), classified via ``assurance.classify_receiver_corroboration``. ``evidence_resolver``
      (reused, same param) lets an entry reach ``CONTENT_RESOLVED``; the NEW ``receiver_attestation_resolver``
      (an optional callable ``f(digest_obj) -> bool`` confirming the referenced content is itself a validly-
      signed statement from a party DISTINCT from the executor) lets it reach
      ``assurance.EvidenceLevel.INDEPENDENTLY_ATTESTED`` — this is the built, self-fixable half of Finding 16;
      ``EvidenceLevel.EFFECT_OBSERVED`` stays honestly unreachable (see
      ``assurance.EFFECT_OBSERVED_NOT_IMPLEMENTED``, the INHERENT half proofbundle cannot itself close).
    - ``receiver_role_trusted`` (Finding 16, additive) — when ``trust_pack`` is supplied AND ``receiverRefs``
      is non-empty, True iff AT LEAST ONE entry's ``receiverKeyId`` is a non-revoked member of the pack's
      ``outcomeReceivers`` role (``outcome.receiver_trusted_by_role``); ``None`` when there is nothing to
      evaluate. Deliberately NOT wired into the aggregate ``ok`` (unlike ``executor_role_trusted``):
      ``receiverRefs`` is OPTIONAL supplementary evidence, so an untrusted-labeled receiver must not break an
      otherwise-valid outcome's own core verdict — it only affects the STRENGTH classification above.

    None of the receiverRefs/sequence additions change any field documented above them, or the aggregate
    ``ok`` — fully backward compatible with every existing caller.
    """
    from . import dsse  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    r = _empty_result()

    r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
    if not r["crypto_ok"]:
        r["errors"].append("DSSE signature verification failed — payload is unauthenticated")
    body = dsse.load_payload(envelope)
    # Finding 15b: refuse an absurdly oversized payload BEFORE any JSON parsing/canonicalization work runs.
    DEFAULT_BUDGET.check("input_bytes", len(body))
    try:
        statement = loads_strict(body.decode("utf-8"))
    except (BundleFormatError, ValueError, UnicodeDecodeError) as exc:
        # PB-2026-0717-07 never-raise: untrusted unparseable input -> STABLE fail-closed verdict, never a
        # raw exception. The specific reason is preserved in errors[]. verify_outcome_receipt_or_raise() is
        # the explicit exception variant.
        r["structure_ok"] = False
        r["errors"].append(f"DSSE payload is not a well-formed in-toto Statement: {exc}")
        if _raise_on_malformed:
            raise BundleFormatError(f"DSSE payload is not a well-formed in-toto Statement: {exc}") from exc
        return _finalize_failclosed(r)

    ptype = statement.get("predicateType") if isinstance(statement, dict) else None
    r["predicate_type_ok"] = ptype == ACTION_OUTCOME_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(f"predicateType is {ptype!r}, expected action-outcome/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_outcome_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)

    # hash_binding: received bytes must BE their own RFC-8785 canonicalization (verify never re-canonicalizes).
    # PB-2026-0717-06 (Owner-GO 3.6.1): rfc8785 is a HARD core dependency; an absent canonicalizer is a broken
    # install, not a lenient mode. The security-verify path fails closed REGARDLESS of `strict` — never a
    # silent ok=true over possibly non-canonical bytes (the strict=False False Accept). Only present+equal passes.
    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        r["errors"].append(
            "RFC-8785 (JCS) canonicalizer unavailable — proofbundle requires rfc8785 (core dependency); "
            "hash_binding fail-closed, cannot verify canonicality")

    canonicality_ok = canonical_ok is True  # absent (None) or non-canonical (False) never passes (fail-closed)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if isinstance(predicate, dict) and r["crypto_ok"]:
        # decisionRef binding (replay against another decision fails).
        _dref = (predicate.get("decisionRef") or {}).get("sha256") if isinstance(predicate.get("decisionRef"), dict) else None
        if expected_decision_ref is not None:
            r["decision_bound"] = _dref == expected_decision_ref
            if not r["decision_bound"]:
                r["errors"].append(
                    "decisionRef mismatch — this outcome is bound to a DIFFERENT decision than expected "
                    "(replay across decisions?, fail-closed)")

        # role separation (executor must differ from the decision maker).
        _exid = (predicate.get("executor") or {}).get("id") if isinstance(predicate.get("executor"), dict) else None
        if decision_maker_id is not None:
            r["role_separation_ok"] = bool(_exid) and _exid != decision_maker_id
            if not r["role_separation_ok"]:
                r["errors"].append(
                    "role separation violated — executor.id equals the decisionMaker id; whoever decides "
                    "must not witness their own execution (fail-closed)")

        # relation/v0.1 (EXPERIMENTAL, additive): evaluate the OPTIONAL relationships edges against
        # caller-attached targets (offline --with-related). Only over AUTHENTICATED bytes; NEVER feeds
        # the crypto verdict (lattice monotonicity) — a lineage FAIL surfaces via errors[] + policy.
        if "relationships" in predicate or related:
            from . import anchors as _anchors_for_rel  # noqa: PLC0415
            from .relation import successor_warning, verify_relationship_edges  # noqa: PLC0415
            try:
                _subject_hex = _anchors_for_rel.statement_content_root(body).hex()
            except Exception:
                _subject_hex = None
            r["lineage"] = verify_relationship_edges(
                predicate.get("relationships"), related, subject_hex=_subject_hex)
            _sw = successor_warning(predicate.get("relationships"), related, subject_hex=_subject_hex)
            r["lineage"]["supersededByAttached"] = _sw
            if _sw:
                r["warnings"].append(f"lineage: {_sw}")
            if r["lineage"]["lineage"] == "FAIL":
                r["errors"].extend(r["lineage"]["errors"] or ["relation: lineage verification FAILED"])
            # No-Fake (6-Linsen-Audit L2): mirror of the decision path — a REQUESTED lineage FAIL is
            # visible in `ok`/`automation`, not only at the CLI exit code. FAIL->False, else None.
            r["lineage_ok"] = False if r["lineage"]["lineage"] == "FAIL" else None

        # execution proof (honesty limit, warning not hard-fail).
        r["execution_proven"] = outcome_execution_proven(predicate)
        if r["execution_proven"] is False:
            r["warnings"].append(
                "status=executed is self-asserted (no effectDigest/actualActionDigest) — a signed claim, "
                "not proof the effect occurred")

        # Finding 01: independent attestation of executor.id via the trust pack's outcomeExecutors role
        # (docs/predicates/action-outcome.md §7 "open, not yet built" — now closed additively).
        if trust_pack is not None:
            r["executor_role_trusted"] = executor_trusted_by_role(predicate.get("executor"), trust_pack)
            if not r["executor_role_trusted"]:
                r["errors"].append(
                    "executor.keyId is not a non-revoked member of the trust pack's outcomeExecutors role "
                    "(fail-closed — independent executor attestation requested via trust_pack but not met)")

        # Finding 03 (additive): classify the same execution-proof digest(s) onto the EvidenceLevel ladder.
        # OR semantics (mirrors outcome_execution_proven: either digest satisfies the claim) — the STRONGER
        # of the two applicable fields wins. Never changes execution_proven above (unchanged, for compat).
        from . import assurance as _assurance  # noqa: PLC0415
        _exec_applicable = predicate.get("status") == "executed"
        r["evidence_levels"] = {
            "effect": _assurance.evidence_ladder_best(
                _assurance.classify_digest_evidence(predicate.get("effectDigest"), applicable=_exec_applicable,
                                                    evidence_resolver=evidence_resolver),
                _assurance.classify_digest_evidence(predicate.get("actualActionDigest"),
                                                    applicable=_exec_applicable,
                                                    evidence_resolver=evidence_resolver),
            ),
        }

        # Finding 16 (additive, self-fixable part): receiverRefs — third-party receiver/observer
        # corroboration, digest-bound exactly like decision.py's evidenceRefs[]. receiver_bound mirrors
        # evidence_bound (shape-only, None when there is nothing to bind — mirrors the vacuous-None
        # convention decision.py already documents). evidence_levels["receiverRefs"] uses OR semantics (one
        # corroborating receiver suffices) over classify_receiver_corroboration, which can reach
        # INDEPENDENTLY_ATTESTED via the new receiver_attestation_resolver — never EFFECT_OBSERVED (the
        # honestly-documented inherent limit, assurance.EFFECT_OBSERVED_NOT_IMPLEMENTED).
        _recv = predicate.get("receiverRefs")
        if isinstance(_recv, list) and _recv:
            r["receiver_bound"] = all(isinstance(x, dict) and _is_digest(x.get("digest")) for x in _recv)
            # Structural independence (crypto-review, 2026-07-15): pass the executor's own key id so
            # classify_receiver_corroboration can REFUSE to promote a receiver that is the executor itself
            # (self-corroboration). A receiverRefs entry only reaches INDEPENDENTLY_ATTESTED when its
            # receiverKeyId is present AND distinct from the executor — never on a resolver-says-signed alone.
            _executor = predicate.get("executor")
            _executor_key_id = _executor.get("keyId") if isinstance(_executor, dict) else None
            r["evidence_levels"]["receiverRefs"] = _assurance.evidence_ladder_best(*[
                _assurance.classify_receiver_corroboration(
                    x.get("digest") if isinstance(x, dict) else None,
                    evidence_resolver=evidence_resolver,
                    independent_attestation_resolver=receiver_attestation_resolver,
                    executor_key_id=_executor_key_id,
                    receiver_key_id=x.get("receiverKeyId") if isinstance(x, dict) else None)
                for x in _recv
            ])
            # Finding 16: outcomeReceivers role membership (mirrors executor_role_trusted, but NEVER wired
            # into the aggregate `ok` below — receiverRefs is optional supplementary evidence; an untrusted-
            # labeled receiver only affects the strength classification above, not the outcome's own core
            # verdict, see the verify docstring).
            if trust_pack is not None:
                r["receiver_role_trusted"] = any(
                    receiver_trusted_by_role(x.get("receiverKeyId") if isinstance(x, dict) else None,
                                             trust_pack)
                    for x in _recv)
        else:
            r["evidence_levels"]["receiverRefs"] = None

        # replay/audience binding (fail-closed when requested), mirrors decision.py.
        _val = predicate.get("validity")
        _validity = _val if isinstance(_val, dict) else {}
        if expected_audience is not None:
            _aud = _validity.get("audience")
            r["audience_ok"] = isinstance(_aud, list) and expected_audience in _aud
            if not r["audience_ok"]:
                r["errors"].append(
                    "audience mismatch or absent validity.audience — requested audience binding cannot be "
                    "enforced (cross-audience replay?, fail-closed)")
        if expected_nonce is not None:
            r["nonce_ok"] = _validity.get("nonce") == expected_nonce
            if not r["nonce_ok"]:
                r["errors"].append(
                    "nonce mismatch or absent validity.nonce — requested replay binding cannot be enforced "
                    "(replay?, fail-closed)")

    # Subject binding (release-review #4): classify whether the subject genuinely commits to the predicate so a
    # consumer never gets ZERO signal on a subject-rehang. An EXTERNAL_ATTESTED subject is ALWAYS warned;
    # require_derived_subject makes it a hard fail-closed error (opt-in, preserves the documented override use).
    if isinstance(statement, dict) and r["crypto_ok"]:
        if _rfc8785_available():
            from . import subject_binding as _sb  # noqa: PLC0415
            try:
                _cls = _sb.classify_subject(statement)
            except Exception:  # noqa: BLE001
                _cls = None
            if _cls is not None:
                r["subject_binding"] = {"mode": _cls["mode"], "matches": _cls["matches"]}
                if not _cls["matches"]:
                    r["warnings"].append(
                        "subject is EXTERNAL_ATTESTED — it does not commit to this predicate (subject-rehang); "
                        "trust it only via a policy that pins the external attester")
                if require_derived_subject:
                    r["subject_derived_ok"] = _cls["matches"]
                    if not _cls["matches"]:
                        r["errors"].append(
                            "require_derived_subject: subject is not a DERIVED commitment to the predicate "
                            "(fail-closed)")
            elif require_derived_subject:
                # classify_subject raised (e.g. a predicate the JCS canonicalizer rejects). Do NOT silently pass
                # the gate on a coincidence elsewhere — make the fail-closed explicit (release-review #4 hardening).
                r["subject_derived_ok"] = False
                r["errors"].append(
                    "require_derived_subject: could not classify the subject binding (canonicalization raised) "
                    "— fail-closed")
        elif require_derived_subject:
            r["subject_derived_ok"] = False
            r["errors"].append(
                "require_derived_subject but RFC-8785 canonicalizer unavailable — cannot verify subject "
                "derivation (install proofbundle[eval]), fail-closed")

    # WP-B (3.4.0): the relations trust-policy gate — enforced IDENTICALLY to the decision path
    # (require_relation_resolution, reject_superseded, relation_signer, require_relation_target) via the
    # SAME shared evaluator. NEVER touches crypto (lattice monotonicity); a violation lands only in
    # policy_ok (exit-3 class at the CLI). trust_pack role auth (executor_role_trusted) is unchanged and
    # SEPARATE — this comes DAZU, it replaces nothing.
    if policy is not None and isinstance(policy.get("relations"), dict) and r["crypto_ok"]:
        import base64 as _b64_rel  # noqa: PLC0415
        from .relation import evaluate_relations_policy  # noqa: PLC0415
        _viol = evaluate_relations_policy(
            policy["relations"], r.get("lineage") or {},
            successor_key_b64=_b64_rel.b64encode(public_key).decode())
        r["policy_ok"] = not _viol
        if _viol:
            r["relations_policy_failed"] = True
            _codes = {v["code"] for v in _viol}
            if "LINEAGE_REQUIREMENT_FAILED" in _codes:
                r["lineage_requirement_failed"] = True
            for v in _viol:
                r["errors"].append(f"{v['code']}: {v['message']}")
            r["relations_policy_codes"] = sorted(_codes)

    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["decision_bound"] is not False and r["role_separation_ok"] is not False
        and r["audience_ok"] is not False and r["nonce_ok"] is not False
        and r["subject_derived_ok"] is not False
        # Finding 01 (additive, backward compatible): None (no trust_pack supplied, the pre-existing
        # default for every caller) passes exactly like every other optional check above; only an explicit
        # False (a trust_pack WAS supplied and the executor is not a trusted role member) fails ok.
        and r["executor_role_trusted"] is not False
        and r["lineage_ok"] is not False
        and r["policy_ok"] is not False)

    # Finding 01 (additive): the STRICTER automation-safety verdict — never changes `ok` above. Outcome has
    # no separate trust-policy layer (yet); executor_role_trusted (the outcomeExecutors role gate) is the
    # closest analog to decision.py's policy_ok, so it fills the "policy" dimension here.
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": "executor_role_trusted",
        "references": ["decision_bound", "role_separation_ok", "audience_ok", "nonce_ok",
                       "subject_derived_ok", "lineage_ok"],
    })
    return r
