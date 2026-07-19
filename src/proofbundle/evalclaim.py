"""Eval receipts (v0.4): sign + Merkle-anchor a canonical eval CLAIM.

A receipt is tamper-evident signed evidence of exactly one thing — *suite S scored `comparator` threshold
T, passed=…* — carrying only SALTED commitments to the model and dataset identifiers,
never the weights, the data, or the plaintext names. A third party verifies the
threshold was met, offline, from one file, without ever seeing the model or dataset.

Honest scope (see EVAL_CLAIM.md): the receipt proves `passed` against `threshold`
and hides the model/dataset via salted commitments. It does NOT prove the evaluation
itself was well designed or that the suite measures what it claims — those are human
judgements. What it removes is the need to simply *trust the number*.

Layering: the claim payload is canonicalized with RFC 8785 JCS **only on the emit
path** (a lazy dependency). The verify path (`decode_eval_claim`) never canonicalizes —
it checks the exact stored bytes that `verify_bundle` already authenticated — so the
verifier stays dependency-free (cryptography + stdlib only).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import unicodedata
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .bundle import load_bundle, verify_bundle
from .emit import emit_bundle
from .errors import ProofBundleError

EVAL_CLAIM_SCHEMA = "proofbundle/eval-claim/v0.1"
COMMIT_ALG = "sha256-salted-v1"
_COMPARATORS = {">=", ">", "<=", "<"}
_MAX_SAFE_INT = 2 ** 53 - 1
# The published eval-claim schema's decimal pattern for threshold/score (no exponent, no sign+, no spaces).
_DECIMAL_RE = re.compile(r"\A-?[0-9]+(\.[0-9]+)?\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline
# Assurance level (v1.1): how much a PASS is worth. Signed into the claim (tamper-evident + bound to the
# issuer, so a third party cannot alter it) — but issuer-DECLARED: a dishonest issuer can sign a higher level,
# the signature attributes that claim to them, it does not make it true. Ordered weakest→strongest. Default
# self_attested — the 1.0 integrations emit self-attested, and claiming more would be dishonest.
ASSURANCE_LEVELS = ("self_attested", "third_party", "reproduced", "enclave_attested")
DEFAULT_ASSURANCE = "self_attested"
# The exact key set of an eval claim; decode/validate reject anything else.
_REQUIRED = {"schema", "suite", "suite_version", "metric", "comparator", "threshold",
             "passed", "n", "model_id_commit", "dataset_id_commit", "commit_alg", "issuer", "timestamp",
             "assurance_level"}
_OPTIONAL = {"context_binding", "ci95", "multiple_testing", "prereg_sha256", "provenance", "samples",
             "evaluation_card_sha256"}

__all__ = [
    "EVAL_CLAIM_SCHEMA", "COMMIT_ALG", "ASSURANCE_LEVELS", "canonicalize", "build_eval_claim",
    "emit_eval_receipt", "decode_eval_claim", "salted_commit", "issuer_fingerprint",
    "claim_warnings", "verify_commitment", "check_freshness", "sd_jwt_hidden_count",
    "eval_evidence_class", "SCORE_EVIDENCE_CLASSES", "EXACT_SCORE_VERIFIED",
    "THRESHOLD_VERDICT_VERIFIED", "SCORE_COMMITMENT_PRESENT", "SCORE_WITHHELD",
    "METHODOLOGY_NOT_EVALUATED", "enclave_assurance_proven",
]


class EvalClaimError(ValueError):
    """Raised for a malformed eval claim (float in payload, non-NFC string, unsafe int, …)."""


def issuer_fingerprint(signer: Ed25519PrivateKey) -> str:
    """The `issuer` field value: ed25519:<base64 of the 32-byte raw public key>."""
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def salted_commit(identifier: str, salt: bytes) -> str:
    """Salted commitment to an identifier: sha256:<hex> over salt || utf8(identifier).

    The salt (>=16 bytes, high entropy) stays with the issuer and is NEVER in the payload,
    so the identifier cannot be recovered from the commitment — not even via a rainbow table
    over known model names like gpt-4o.
    """
    if len(salt) < 16:
        raise EvalClaimError("commitment salt must be at least 16 bytes")
    return "sha256:" + hashlib.sha256(salt + identifier.encode("utf-8")).hexdigest()


def _reject_non_jcs(value) -> None:
    """Recursively reject values that RFC 8785 / this profile forbids in a claim."""
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise EvalClaimError("float values are forbidden; use a decimal STRING (e.g. \"0.80\")")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise EvalClaimError(f"integer {value} exceeds the IEEE-754 safe range (2**53-1)")
        return
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise EvalClaimError("string is not NFC-normalized")
        return
    if value is None:
        return
    if isinstance(value, dict):
        for v in value.values():
            _reject_non_jcs(v)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _reject_non_jcs(v)
        return
    raise EvalClaimError(f"unsupported value type {type(value).__name__}")


def canonicalize(claim: dict) -> bytes:
    """RFC 8785 JCS canonical bytes of a claim — EMIT PATH ONLY.

    Enforces the profile before serializing: no Python float, NFC strings, safe-range ints.
    Duplicate keys cannot exist in a Python dict; when parsing claim JSON from text, use
    `load_claim_text` which rejects duplicate keys. Uses the rfc8785 library (lazy import)
    for the UTF-16 code-unit key sort + compact UTF-8 serialization.
    """
    _reject_non_jcs(claim)
    try:
        import rfc8785  # noqa: PLC0415 — lazy: only the emit path pulls the JCS dependency
    except ImportError as e:
        raise EvalClaimError(
            "emitting eval receipts needs an RFC 8785 canonicalizer — install with: "
            "pip install \"proofbundle[eval]\"") from e
    try:
        return rfc8785.dumps(claim)
    except (rfc8785.FloatDomainError, rfc8785.IntegerDomainError, rfc8785.CanonicalizationError) as e:
        raise EvalClaimError(f"canonicalization failed: {e}") from e


def load_claim_text(text: str) -> dict:
    """Parse claim JSON text, rejecting duplicate keys (JCS forbids them).

    Delegates to the shared strict parser (:func:`proofbundle._strict_json.loads_strict`) so this
    path has the SAME robustness as every other verify path: a duplicate key and a pathologically
    deep nesting (``RecursionError``, CWE-674) both become a clean malformed-input error, never a
    raw traceback. Re-raised as :class:`EvalClaimError` (a ``ValueError``) so existing
    ``except (ValueError, EvalClaimError)`` handling at the call sites — including the batch
    verifier ``hf_evals.verify_eval_results_entry`` — stays correct and never crashes."""
    from ._strict_json import loads_strict  # noqa: PLC0415
    try:
        return loads_strict(text)
    except ProofBundleError as e:
        # Berkeley re-gate round 3: catch the BASE ProofBundleError — loads_strict raises a SIBLING
        # BudgetExceeded (over-width/over-node input) NOT a BundleFormatError, which `except BundleFormatError`
        # let escape as a raw traceback. Both map to the DOCUMENTED EvalClaimError (a ValueError).
        raise EvalClaimError(str(e)) from e


def build_eval_claim(*, suite: str, suite_version: str, metric: str, comparator: str,
                     threshold: str, score: str, n: int, model_id: str, dataset_id: str,
                     issuer: str, timestamp: str, context_binding: Optional[str] = None,
                     ci95: Optional[Sequence[str]] = None, multiple_testing: Optional[str] = None,
                     prereg_sha256: Optional[str] = None, provenance: Optional[dict] = None,
                     assurance_level: str = DEFAULT_ASSURANCE,
                     samples: Optional[dict] = None,
                     evaluation_card_sha256: Optional[str] = None,
                     model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Build a valid eval claim from raw values. Computes `passed` ITSELF from the comparator
    (never trusts the caller), creates salted commitments, and returns (claim, salts) with the
    salts SEPARATE (never in the payload).

    threshold/score are decimal STRINGS (never floats). Returns:
        (claim: dict, salts: {"model_salt": bytes, "dataset_salt": bytes})
    """
    if comparator not in _COMPARATORS:
        raise EvalClaimError(f"comparator must be one of {sorted(_COMPARATORS)}")
    if assurance_level not in ASSURANCE_LEVELS:
        raise EvalClaimError(f"assurance_level must be one of {list(ASSURANCE_LEVELS)}")
    # threshold/score must match the PUBLISHED schema's decimal pattern exactly — reject "1e2",
    # "Infinity", "+5", " 5 " etc. that Decimal() would accept but jsonschema rejects (schema-conformance).
    for name, val in (("threshold", threshold), ("score", score)):
        if not isinstance(val, str):
            raise EvalClaimError(f"{name} must be a decimal STRING, not {type(val).__name__}")
        if not _DECIMAL_RE.match(val):
            raise EvalClaimError(f"{name} must be a plain decimal string (^-?[0-9]+(\\.[0-9]+)?$), got {val!r}")
    if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > _MAX_SAFE_INT:
        raise EvalClaimError(f"n must be a non-negative integer <= 2**53-1, got {n!r}")
    from decimal import Decimal  # noqa: PLC0415
    s, t = Decimal(score), Decimal(threshold)
    passed = {">=": s >= t, ">": s > t, "<=": s <= t, "<": s < t}[comparator]
    m_salt = model_salt if model_salt is not None else os.urandom(16)
    d_salt = dataset_salt if dataset_salt is not None else os.urandom(16)
    claim = {
        "schema": EVAL_CLAIM_SCHEMA, "suite": suite, "suite_version": suite_version,
        "metric": metric, "comparator": comparator, "threshold": threshold, "passed": passed,
        "n": n, "model_id_commit": salted_commit(model_id, m_salt),
        "dataset_id_commit": salted_commit(dataset_id, d_salt), "commit_alg": COMMIT_ALG,
        "issuer": issuer, "timestamp": timestamp, "assurance_level": assurance_level,
    }
    if context_binding is not None:
        claim["context_binding"] = context_binding
    if ci95 is not None:
        claim["ci95"] = [str(x) for x in ci95]
    if multiple_testing is not None:
        claim["multiple_testing"] = multiple_testing
    if prereg_sha256 is not None:
        claim["prereg_sha256"] = prereg_sha256
    if evaluation_card_sha256 is not None:
        claim["evaluation_card_sha256"] = evaluation_card_sha256
    if provenance is not None:
        claim["provenance"] = provenance
    if samples is not None:
        # v1.5 per-sample commitment: {"root_b64", "n", "leaf_alg"} from
        # proofbundle.persample.build_sample_tree — the samples root is SIGNED with the claim,
        # so tree-size lies and post-hoc sample swaps are closed at the signature layer
        # (an RFC 6962 inclusion proof constrains n only up to path-shape equivalence).
        import base64 as _b64mod  # noqa: PLC0415
        if not isinstance(samples, dict) or set(samples) - {"root_b64", "n", "leaf_alg"}:
            raise EvalClaimError("samples must be {root_b64, n, leaf_alg} (see persample module)")
        try:
            root_raw = _b64mod.b64decode(samples["root_b64"], validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise EvalClaimError("samples.root_b64 must be valid base64") from exc
        if len(root_raw) != 32:
            raise EvalClaimError("samples.root_b64 must decode to a 32-byte SHA-256 root")
        s_n = samples.get("n")
        if isinstance(s_n, bool) or not isinstance(s_n, int) or s_n <= 0:
            raise EvalClaimError("samples.n must be a positive integer")
        if s_n != n:
            raise EvalClaimError(
                f"samples.n ({s_n}) must equal the claim's n ({n}) — the committed tree covers "
                "exactly the samples the aggregate was computed over, no more, no fewer")
        if samples.get("leaf_alg") != "sha256-rfc6962-sdjwt-v1":
            raise EvalClaimError("samples.leaf_alg must be 'sha256-rfc6962-sdjwt-v1'")
        claim["samples"] = {"root_b64": samples["root_b64"], "n": s_n,
                            "leaf_alg": samples["leaf_alg"]}
    _reject_non_jcs(claim)
    return claim, {"model_salt": m_salt, "dataset_salt": d_salt}


def emit_eval_receipt(claim: dict, signer: Ed25519PrivateKey, *, prior_leaves: Sequence[bytes] = (),
                      sd_jwt: Optional[dict] = None) -> dict:
    """Emit a proofbundle/v0.1 bundle whose payload is the canonical eval claim.

    Sets `issuer` to the signer's fingerprint automatically (binding the receipt to the key),
    canonicalizes, and calls emit_bundle. The returned bundle is verified unchanged by verify_bundle.
    """
    claim = dict(claim)
    claim["issuer"] = issuer_fingerprint(signer)
    # A claim without an explicit assurance_level is self_attested — the weakest, safest default; never
    # silently elevate. (v1.1: keeps pre-1.1 claim JSONs emittable while binding the honest level.)
    claim.setdefault("assurance_level", DEFAULT_ASSURANCE)
    if claim["assurance_level"] not in ASSURANCE_LEVELS:
        raise EvalClaimError(f"assurance_level must be one of {list(ASSURANCE_LEVELS)}")
    missing = _REQUIRED - set(claim)
    if missing:
        raise EvalClaimError(f"claim missing required fields: {sorted(missing)}")
    extra = set(claim) - _REQUIRED - _OPTIONAL
    if extra:
        raise EvalClaimError(f"claim has unknown fields: {sorted(extra)}")
    payload = canonicalize(claim)
    return emit_bundle(payload, signer, prior_leaves=prior_leaves, sd_jwt_vc=sd_jwt)


def decode_eval_claim(bundle, *, expected_context: Optional[str] = None) -> Optional[dict]:
    """Verify the bundle, then check the signing key matches the claim's `issuer` field.

    Returns the parsed claim on success, None on any failure. Dependency-free (no JCS import):
    it parses the exact in-memory payload bytes that verify_bundle already authenticated.

    A str ``bundle`` is a PATH. It is resolved to a dict EXACTLY ONCE, before verification, and the
    same object is both verified and parsed — a second re-read of the path would be a TOCTOU (CWE-367)
    file-race window (a swap between the two reads could return content whose signature was never
    checked). Release-review fix 2026-07-02.

    v1.6 verify-side invariants (external review: guarantees must hold on the VERIFY path, not
    only in the blessed emitter): when the claim carries ``samples``, its shape, 32-byte root,
    ``leaf_alg`` and ``samples.n == n`` are re-validated here — a hand-signed claim that lies
    about the committed tree size is rejected. ``expected_context`` enforces the signed
    ``context_binding`` field (cross-context replay guard): if supplied and the claim's binding
    is absent or different, the claim is rejected.
    """
    try:
        if isinstance(bundle, str):
            bundle = load_bundle(bundle)   # resolve the PATH to a dict ONCE — verify + parse the SAME bytes (no TOCTOU re-read)
        result = verify_bundle(bundle)
        if not result.ok:
            return None
        payload = base64.b64decode(bundle["payload_b64"])
        claim = load_claim_text(payload.decode("utf-8"))
        if claim.get("schema") != EVAL_CLAIM_SCHEMA:
            return None
        # F3 (v1.9.2): the exact key set is a VERIFY-path invariant, not only an emit-side one.
        # emit_eval_receipt enforces _REQUIRED/_OPTIONAL at emit, but a hand-signed claim bypasses
        # that path — a decoded claim missing a required field or carrying an unknown one was
        # previously ACCEPTED here (the emit-vs-verify asymmetry class this project documents; the
        # module comment on _REQUIRED, "decode/validate reject anything else", was aspirational on
        # this path). Reject fail-closed, mirroring the emit-side check.
        if (_REQUIRED - set(claim)) or (set(claim) - _REQUIRED - _OPTIONAL):
            return None
        # Issuer binding: the claim's issuer must be the key that signed the bundle.
        sig_pub_b64 = bundle["signature"]["public_key_b64"]
        want = "ed25519:" + base64.b64encode(base64.b64decode(sig_pub_b64)).decode("ascii")
        if claim.get("issuer") != want:
            return None
        # Verify-boundary schema invariants (release-review CRITICAL): emit_eval_receipt signs a hand-built claim
        # WITHOUT build_eval_claim's checks, so a signed claim could carry an out-of-enum comparator or a
        # non-decimal/non-finite threshold ("inf") — either silently collapses a downstream verdict check (e.g. the
        # HF value-vs-verdict guard) into a tautology. Enforce them here, fail-closed, so every decoded claim is sane.
        if claim.get("comparator") not in _COMPARATORS:
            return None
        _thr = claim.get("threshold")
        if not (isinstance(_thr, str) and _DECIMAL_RE.match(_thr)):
            return None
        # assurance_level is issuer-declared and (since WP-B2) printed VERBATIM on the CLI's ASSURANCE
        # line. A value outside the enum — e.g. one carrying embedded newlines to forge extra fake
        # CRYPTO:/POLICY: lines (verify-lens L3, 2026-07-09) — must be rejected on the VERIFY path too:
        # the blessed emit path already enforces the enum (build_eval_claim, emit_eval_receipt), so a
        # hand-signed claim must not bypass it (the emit-vs-verify asymmetry class this module guards).
        if claim.get("assurance_level") not in ASSURANCE_LEVELS:
            return None
        samples = claim.get("samples")
        if samples is not None:
            if not isinstance(samples, dict) or set(samples) != {"root_b64", "n", "leaf_alg"}:
                return None
            if samples.get("leaf_alg") != "sha256-rfc6962-sdjwt-v1":
                return None
            s_n = samples.get("n")
            c_n = claim.get("n")
            # type-check BOTH sides (release-review #8): a bool/non-int claim.n must not slip through the equality
            if (isinstance(s_n, bool) or not isinstance(s_n, int)
                    or isinstance(c_n, bool) or not isinstance(c_n, int) or s_n != c_n):
                return None
            if len(base64.b64decode(samples["root_b64"], validate=True)) != 32:
                return None
        if expected_context is not None and claim.get("context_binding") != expected_context:
            return None
        return claim
    except (ProofBundleError, KeyError, ValueError, TypeError, EvalClaimError, OSError):
        # MJSON-01 (RE-GATE never-raise): the documented contract is "Returns the parsed claim on success,
        # None on any failure". load_bundle (a bad path str -> OSError) and verify_bundle (a non-bundle dict
        # -> UnsupportedError / BundleFormatError, both ProofBundleError) previously ran OUTSIDE this try, so
        # a non-bundle / non-path argument raised a raw exception instead of returning None. Both now sit
        # inside the guard and the except covers the malformed-input family, so decode_eval_claim on
        # {'not':'a bundle'} / [1,2,3] / a bad path all return None as documented.
        return None


def claim_warnings(claim: dict) -> list:
    """Honest trust warnings for an already-verified claim (v1.1). A verified signature proves authorship +
    integrity, NOT that the number is true or the study was pre-registered. The weakest combination —
    self_attested with no pre-registration — is where an issuer could publish the best of many runs; surface
    it so a strong signature never masks a weak assurance. Returns a list of human-readable strings."""
    out = []
    level = claim.get("assurance_level", DEFAULT_ASSURANCE)
    if level == "self_attested" and not claim.get("prereg_sha256"):
        out.append("self_attested with no prereg_sha256 — the weakest assurance: trust rests entirely on the "
                   "issuer, who could publish the best of many runs. Pre-register (prereg_sha256) or use a "
                   "higher assurance_level (reproduced / enclave_attested) to strengthen it.")
    return out


# P0-B (Hardening 3.0.1 §7.1) — the machine-readable SCORE-evidence verdicts. A receipt today signs a
# THRESHOLD VERDICT (`passed` against the signed `comparator`/`threshold`): the exact score is used at
# emit time to COMPUTE `passed` and is then DISCARDED (build_eval_claim never stores it), so no output
# may imply an exact score was verified. The other classes are reachable only through the optional,
# additive exact-score profile (§7.2, EXPERIMENTAL, NOT part of the frozen 3.x core).
EXACT_SCORE_VERIFIED = "EXACT_SCORE_VERIFIED"
THRESHOLD_VERDICT_VERIFIED = "THRESHOLD_VERDICT_VERIFIED"
SCORE_COMMITMENT_PRESENT = "SCORE_COMMITMENT_PRESENT"
SCORE_WITHHELD = "SCORE_WITHHELD"
METHODOLOGY_NOT_EVALUATED = "METHODOLOGY_NOT_EVALUATED"
SCORE_EVIDENCE_CLASSES = (EXACT_SCORE_VERIFIED, THRESHOLD_VERDICT_VERIFIED,
                          SCORE_COMMITMENT_PRESENT, SCORE_WITHHELD)


def eval_evidence_class(claim: dict) -> dict:
    """Classify what SCORE evidence a VERIFIED eval claim carries (never call on an unverified claim).

    Returns ``{"score_evidence": <class>, "methodology": METHODOLOGY_NOT_EVALUATED, "detail": <str>}``.

    Today every receipt is ``THRESHOLD_VERDICT_VERIFIED``: the frozen v0.1 schema has no ``score``
    field, so a receipt proves only that ``passed`` holds for the signed ``comparator``/``threshold``.
    ``methodology`` is ALWAYS ``METHODOLOGY_NOT_EVALUATED`` — a receipt never judges whether the suite
    measures what it claims (No-Overclaim §0.5).

    The remaining classes are reachable only through the optional, additive exact-score profile (§7.2,
    field names provisional pending its ADR, EXPERIMENTAL, not in the 3.x core): a signed decimal-string
    ``score`` whose recomputed ``passed`` AGREES → ``EXACT_SCORE_VERIFIED`` (a score present but
    inconsistent with ``passed`` is a decode-time FAIL; if seen here it degrades to the threshold
    verdict, never a false EXACT); a signed score COMMITMENT → ``SCORE_COMMITMENT_PRESENT`` (a binding,
    NOT a range proof: it does not prove the hidden score crossed the threshold, §7.3); an explicit
    withheld marker → ``SCORE_WITHHELD``.
    """
    methodology = METHODOLOGY_NOT_EVALUATED
    comparator = claim.get("comparator")
    threshold = claim.get("threshold")
    passed = claim.get("passed")
    score = claim.get("score")
    if (isinstance(score, str) and _DECIMAL_RE.match(score) and comparator in _COMPARATORS
            and isinstance(threshold, str) and _DECIMAL_RE.match(threshold) and isinstance(passed, bool)):
        from decimal import Decimal, InvalidOperation  # noqa: PLC0415
        try:
            recomputed = {">=": Decimal(score) >= Decimal(threshold), ">": Decimal(score) > Decimal(threshold),
                          "<=": Decimal(score) <= Decimal(threshold), "<": Decimal(score) < Decimal(threshold)}[comparator]
        except InvalidOperation:
            recomputed = None
        if recomputed is passed:
            return {"score_evidence": EXACT_SCORE_VERIFIED, "methodology": methodology,
                    "detail": "exact score signed and consistent with the threshold verdict"}
        return {"score_evidence": THRESHOLD_VERDICT_VERIFIED, "methodology": methodology,
                "detail": "score present but not consistent with `passed` — only the threshold verdict stands"}
    if claim.get("score_commit") or claim.get("score_commitment"):
        return {"score_evidence": SCORE_COMMITMENT_PRESENT, "methodology": methodology,
                "detail": "a score COMMITMENT is present — a binding, NOT a range proof: it does not "
                          "prove the hidden score crossed the threshold"}
    if claim.get("score_withheld") is True:
        return {"score_evidence": SCORE_WITHHELD, "methodology": methodology,
                "detail": "the exact score is deliberately withheld; only the threshold verdict is signed"}
    return {"score_evidence": THRESHOLD_VERDICT_VERIFIED, "methodology": methodology,
            "detail": "proves `passed` against the signed threshold, not an exact score"}


def verify_commitment(identifier: str, salt: bytes, commitment: str) -> bool:
    """Check that a PRESENTED identifier (+ its salt) matches a salted commitment in a claim
    (``model_id_commit`` / ``dataset_id_commit``). Makes a model-swap visible: a claim that silently swapped
    the model cannot produce a matching (identifier, salt). Constant-time compare; the salt stays outside the
    payload (the holder presents it to a verifier out of band)."""
    if not isinstance(identifier, str) or not isinstance(salt, (bytes, bytearray)):
        return False   # RE-GATE never-raise: a non-str PRESENTED identifier is a fail-closed False, not a
        # raw AttributeError from identifier.encode() inside salted_commit (untrusted presentation input).
        # Berkeley re-gate round 7: the `salt` is the SAME out-of-band presentation channel — a non-bytes salt
        # is a raw TypeError from len(salt) in salted_commit; guard it here too (the identifier-only guard was
        # half-finished).
    try:
        expected = salted_commit(identifier, salt)
    except EvalClaimError:
        return False
    import hmac  # noqa: PLC0415
    return hmac.compare_digest(expected, str(commitment))


def check_freshness(claim: dict, max_age_seconds: Optional[int] = None, now=None) -> dict:
    """Replay check (v1.1): parse the claim's timestamp and report its age. A receipt carries a timestamp but
    verify never judged it — an old receipt could be replayed as new. Returns
    {"parsed": bool, "age_seconds": int|None, "fresh": bool|None, "reason": str}. ``fresh`` is None when no
    ``max_age_seconds`` bound is given (age reported, not judged). ISO parsing (normalizes a trailing Z)."""
    from datetime import datetime, timezone  # noqa: PLC0415
    if not isinstance(claim, dict):
        # Berkeley re-gate round 7: the natural RP pattern check_freshness(decode_eval_claim(bundle)) passes a
        # None (decode returns None on a non-eval bundle) straight into claim.get(...) — a raw AttributeError.
        # A non-dict claim is a fail-closed "not parsed" verdict, never a crash.
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": "claim is not a dict"}
    ts = claim.get("timestamp")
    if not isinstance(ts, str):
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": "no timestamp"}
    raw = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": f"unparseable timestamp {ts!r}"}
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    age = int((ref - dt).total_seconds())
    if max_age_seconds is None:
        return {"parsed": True, "age_seconds": age, "fresh": None, "reason": f"age {age}s (no bound given)"}
    fresh = 0 <= age <= max_age_seconds
    return {"parsed": True, "age_seconds": age, "fresh": fresh,
            "reason": (f"age {age}s within {max_age_seconds}s" if fresh
                       else f"age {age}s outside [0, {max_age_seconds}]s — possible replay or clock skew")}


def sd_jwt_hidden_count(bundle) -> Optional[int]:
    """Number of selectively-disclosable (currently withheld) SD-JWT fields in a bundle, so that OMISSION is
    visible: a receipt can hide claims behind the SD-JWT ``_sd`` digests. Returns the count, or None if the
    bundle carries no SD-JWT. Reads the issuer JWT payload's ``_sd`` array without verifying the SD-JWT
    (that is the holder/verifier's job); purely a disclosure-transparency signal."""
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    sd = bundle.get("sd_jwt_vc") if isinstance(bundle, dict) else None
    if not sd:
        return None
    # the canonical bundle form (the only one verify_bundle accepts) stores the compact SD-JWT under "compact";
    # sd_jwt/token are accepted as fallbacks for a bare token dict/string.
    token = sd if isinstance(sd, str) else (sd.get("compact") or sd.get("sd_jwt") or sd.get("token") or "")
    if not isinstance(token, str) or "." not in token:
        return None
    from ._strict_json import loads_strict  # noqa: PLC0415
    try:
        jwt = token.split("~", 1)[0]                     # issuer JWT, before any disclosures
        payload_b64 = jwt.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)     # restore base64url padding
        # F12 (release-audit follow-up 2026-07-12): loads_strict, not json.loads — a 5th SD-JWT
        # issuer-payload parse site of the same parser-differential class. A duplicate key (e.g. two
        # `_sd`) → BundleFormatError → None (honest "cannot count"), never a silent last-wins count.
        payload = loads_strict(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except (ProofBundleError, ValueError, KeyError, IndexError):
        # Berkeley re-gate round 3 (repro-confirmed): sd_jwt_hidden_count is PUBLIC — a node-heavy embedded
        # payload made loads_strict raise a SIBLING BudgetExceeded that `except BundleFormatError` let escape
        # as a raw DoS traceback. The BASE ProofBundleError catch maps every over-limit/malformed case to None.
        return None
    if not isinstance(payload, dict):                    # a valid-JSON non-object payload → nothing to count
        return None
    sd_arr = payload.get("_sd")
    return len(sd_arr) if isinstance(sd_arr, list) else None


def enclave_assurance_proven(claim: dict, bundle, *, eat_jws: Optional[str] = None,
                             verifier_pubkey: Optional[bytes] = None,
                             expected_profile: Optional[str] = None,
                             now: Optional[int] = None) -> Optional[bool]:
    """Whether a signed ``assurance_level=enclave_attested`` claim is BACKED by a verified TEE
    Attestation Result bound to THIS receipt — analogous to ``decision.action_outcome_proven``:
    presence + binding makes a declared level *verifiable*, not merely *asserted*.

    Returns ``None`` when the claim does not declare ``enclave_attested`` (not applicable — mirrors
    ``action_outcome_proven``'s ``None`` for a non-``executed`` outcome). Returns ``False`` when
    ``enclave_attested`` IS declared but no ``eat_jws``/``verifier_pubkey`` was supplied, or the
    supplied EAT does not verify or does not bind this receipt — the honesty limit:
    ``assurance_level`` is issuer-declared (THREAT_MODEL.md), and stays exactly that, a string,
    until corroborated. Returns ``True`` only when an EAT Attestation Result, checked offline
    against ``verifier_pubkey`` via ``proofbundle.experimental.enclave.verify_enclave_attestation``,
    reports ``ok=True`` with ``eat_nonce == enclave_binding_for(bundle)`` — bound to THIS receipt's
    exact signed payload, not merely well-formed.

    **Additive, EXPERIMENTAL by construction.** This reaches into
    ``proofbundle.experimental.enclave`` (the v2.0 preview TEE bridge, docs/EXPERIMENTAL_ENCLAVE.md)
    ONLY when actually called with an ``eat_jws`` — importing/using ``proofbundle.evalclaim`` never
    triggers the subpackage's ``ExperimentalWarning`` by itself (the import is lazy, function-local,
    mirroring the ``rfc8785`` lazy import in :func:`canonicalize`). **Never force-promotes:** an
    ``enclave_attested`` claim with no (or a failing) corroboration is NEITHER upgraded NOR
    downgraded in the claim itself — the signed ``assurance_level`` string is unchanged either way;
    this function only reports, additively, whether it is BACKED.
    """
    if not isinstance(claim, dict) or claim.get("assurance_level") != "enclave_attested":
        return None
    if not eat_jws or verifier_pubkey is None or bundle is None:
        return False
    try:
        from .experimental.enclave import enclave_binding_for, verify_enclave_attestation  # noqa: PLC0415
        binding = enclave_binding_for(bundle)
        res = verify_enclave_attestation(eat_jws, verifier_pubkey=verifier_pubkey,
                                         expected_binding=binding, expected_profile=expected_profile,
                                         now=now)
    except (ProofBundleError, ValueError, TypeError, KeyError):
        # Berkeley re-gate round 3: the enclave path funnels through loads_strict (BudgetExceeded) and may
        # hit PQUnavailable — both ProofBundleError SIBLINGS that `except BundleFormatError` let escape. The
        # BASE catch keeps this corroboration reporter fail-closed (unverifiable → not BACKED → False).
        return False
    return bool(res.get("ok"))
