"""Trust policy (v0.1) — a relying party's machine-readable, fail-closed trust decision, applied
OVER a completed crypto verification (WP-B3).

`verify` on its own makes NO trust decision: it proves authenticity + integrity of the bytes. A trust
policy is where the relying party states, explicitly and offline, *which* signer, schema, algorithm,
audience, freshness and assurance it will accept. Without a policy `verify` says `POLICY:
NOT_EVALUATED`; with one, the policy result is a separate `policy_ok` and exit code 3 on failure —
never conflated with a crypto failure (exit 1).

Design invariants:
  - **snake_case**, versioned (`schema: proofbundle/trust-policy/v0.1`), consistent with the bundle.
  - **fail-closed**: unknown fields are a parse error (additionalProperties: false); an enabled
    requirement that this verify path cannot evaluate (status, which needs a snapshot input v0.1 does
    not carry) fails closed with a clear reason rather than silently passing.
  - **offline**: no network; trust comes only from the policy file.
  - crypto FIRST, policy over the crypto result — a policy is never evaluated on unverified bytes.
"""

from __future__ import annotations

import copy
import json
from typing import Union

from .errors import ProofBundleError
from .evalclaim import ASSURANCE_LEVELS, check_freshness, decode_eval_claim
from .kbjwt import verify_key_binding

__all__ = ["POLICY_SCHEMA", "PolicyError", "load_policy", "evaluate_policy"]

POLICY_SCHEMA = "proofbundle/trust-policy/v0.1"
POLICY_SCHEMA_V0_2 = "proofbundle/trust-policy/v0.2"
# v0.2 adds ONE additive section (decision_receipt) for the decision-receipt/v0.1 predicate. A v0.1 policy is
# valid unchanged under the v0.2 parser (only additive; fail-closed preserved). The decision_receipt section is
# accepted ONLY when schema == v0.2 (a decision_receipt under a v0.1 schema is a fail-closed error).
_SUPPORTED_SCHEMAS = (POLICY_SCHEMA, POLICY_SCHEMA_V0_2)


class PolicyError(ProofBundleError):
    """The trust policy JSON is missing fields, malformed, or carries unknown fields (fail-closed)."""


_TOP_KEYS = {"schema", "policy_id", "allowed_schema_versions", "allowed_issuers", "signature",
             "merkle", "sd_jwt", "status", "assurance", "decision_receipt", "anchors"}
_ANCHORS_KEYS = {"require_anchor", "require_anchor_target", "allow_pending"}
_ANCHOR_TARGETS = ("receipt", "preRegistration", "statement")
_DECISION_KEYS = {"trusted_decision_makers", "allowed_decision_types", "allowed_verdicts",
                  "required_evidence_relations", "accepted_predicate_types", "require_policy_digest",
                  "require_external_anchor", "allow_pending", "require_audience", "require_nonce",
                  "require_not_checked", "require_decision_change_conditions", "require_trace_context",
                  "allow_raw_inputs"}
# The decision_receipt boolean knobs (§7.5 / addendum §2.2). allow_raw_inputs defaults FALSE (fail-closed:
# a receipt with privacy.rawInputsIncluded=true is rejected unless the relying party opts in).
_DECISION_BOOL_KEYS = ("require_policy_digest", "require_external_anchor", "allow_pending", "require_audience",
                       "require_nonce", "require_not_checked", "require_decision_change_conditions",
                       "require_trace_context", "allow_raw_inputs")
_DECISION_MAKER_KEYS = {"id", "public_key_b64", "kid"}
_DECISION_TYPES = {"preActionAuthorization", "postHocReview", "humanEscalation", "policySimulation"}
_VERDICTS = {"ALLOW", "DENY", "REFUSE", "ESCALATE", "DEFER", "OBSERVE"}
_ISSUER_KEYS = {"issuer", "public_key_b64", "kid"}
_SIG_KEYS = {"allowed_algs", "require_expected_signer"}
_MERKLE_KEYS = {"required_hash_alg"}
_SDJWT_KEYS = {"require_key_binding_when_cnf_present", "expected_aud", "require_nonce",
               "max_iat_age_seconds"}
_STATUS_KEYS = {"reject_self_issued", "allowed_status_authorities"}
_ASSURANCE_KEYS = {"minimum_level", "reject_self_attested_without_prereg"}


def _reject_unknown(obj: dict, allowed: set, where: str) -> None:
    extra = set(obj) - allowed
    if extra:
        raise PolicyError(f"unknown field(s) in {where}: {sorted(extra)} (trust policy is fail-closed)")


def _require_dict(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    return value


def _require_bool(obj: dict, key: str, where: str) -> None:
    """A present flag MUST be a real JSON boolean — a string like "false" is truthy and would
    silently flip a fail-closed toggle (the schema declares these boolean)."""
    if key in obj and not isinstance(obj[key], bool):
        raise PolicyError(f"{where}.{key} must be a boolean (true/false)")


def _require_str_or_null(obj: dict, key: str, where: str) -> None:
    if key in obj and obj[key] is not None and not isinstance(obj[key], str):
        raise PolicyError(f"{where}.{key} must be a string or null")


def _require_list_of_str(obj: dict, key: str, where: str) -> None:
    """A present list field MUST be a JSON array of strings — a bare string would degrade Python's
    ``in`` from set-membership to SUBSTRING matching in evaluate_policy, a real bypass (verify-lens
    L1/L3/L4, 2026-07-09: allowed_algs="xed25519y" matched "ed25519")."""
    if key in obj:
        val = obj[key]
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise PolicyError(f"{where}.{key} must be a list of strings")


def load_policy(source: Union[str, dict]) -> dict:
    """Parse and structurally validate a trust policy, fail-closed. ``source`` is a path or a dict.

    Every section is checked for unknown fields (a typo that silently weakens a policy is impossible),
    the schema version is pinned, and ``policy_id`` is required. No network, no I/O beyond reading the
    file. Raises :class:`PolicyError` on anything malformed."""
    if isinstance(source, str):
        try:
            with open(source, encoding="utf-8") as handle:
                policy = json.load(handle)
        except (OSError, ValueError, RecursionError) as exc:   # RecursionError: deeply-nested JSON → fail-closed, not a raw traceback (verify-lens L3)
            raise PolicyError(f"cannot read trust policy: {exc}") from exc
    else:
        # defensive copy (verify-lens L4): a caller who validates a dict then mutates the SAME object
        # before evaluate_policy must not be able to bypass these checks — evaluate the copy.
        policy = copy.deepcopy(source)
    policy = _require_dict(policy, "trust policy")

    if policy.get("schema") not in _SUPPORTED_SCHEMAS:
        raise PolicyError(
            f"unsupported trust policy schema {policy.get('schema')!r}, expected one of {list(_SUPPORTED_SCHEMAS)}")
    _reject_unknown(policy, _TOP_KEYS, "trust policy")
    # decision_receipt is a v0.2-only additive section; under v0.1 it is a fail-closed error.
    if "decision_receipt" in policy and policy.get("schema") != POLICY_SCHEMA_V0_2:
        raise PolicyError("decision_receipt section requires schema proofbundle/trust-policy/v0.2")
    if not (isinstance(policy.get("policy_id"), str) and policy["policy_id"]):
        raise PolicyError("trust policy requires a non-empty string policy_id")

    # Every declared field's TYPE is enforced (verify-lens L4/L3), not just its presence — the schema
    # declares these types and the hand-rolled parser must match it, or a mistyped field silently
    # weakens the policy (the substring-match bug for a string-not-list allowed_algs).
    _require_list_of_str(policy, "allowed_schema_versions", "trust policy")
    if "allowed_issuers" in policy and not isinstance(policy["allowed_issuers"], list):
        raise PolicyError("allowed_issuers must be a list")
    for issuer in policy.get("allowed_issuers", []) or []:
        issuer = _require_dict(issuer, "allowed_issuers[]")
        _reject_unknown(issuer, _ISSUER_KEYS, "allowed_issuers[]")
        if not (isinstance(issuer.get("public_key_b64"), str) and issuer["public_key_b64"]):
            raise PolicyError("each allowed_issuers[] entry needs a non-empty public_key_b64")
        _require_str_or_null(issuer, "issuer", "allowed_issuers[]")
        _require_str_or_null(issuer, "kid", "allowed_issuers[]")
    if "signature" in policy:
        sig = _require_dict(policy["signature"], "signature")
        _reject_unknown(sig, _SIG_KEYS, "signature")
        _require_list_of_str(sig, "allowed_algs", "signature")
        _require_bool(sig, "require_expected_signer", "signature")
    if "merkle" in policy:
        mk = _require_dict(policy["merkle"], "merkle")
        _reject_unknown(mk, _MERKLE_KEYS, "merkle")
        _require_str_or_null(mk, "required_hash_alg", "merkle")
    if "sd_jwt" in policy:
        sdj = _require_dict(policy["sd_jwt"], "sd_jwt")
        _reject_unknown(sdj, _SDJWT_KEYS, "sd_jwt")
        _require_bool(sdj, "require_key_binding_when_cnf_present", "sd_jwt")
        _require_str_or_null(sdj, "expected_aud", "sd_jwt")
        _require_bool(sdj, "require_nonce", "sd_jwt")
        mia = sdj.get("max_iat_age_seconds")
        if mia is not None and (isinstance(mia, bool) or not isinstance(mia, int) or mia < 0):
            raise PolicyError("sd_jwt.max_iat_age_seconds must be a non-negative integer or null")
    if "status" in policy:
        st = _require_dict(policy["status"], "status")
        _reject_unknown(st, _STATUS_KEYS, "status")
        _require_bool(st, "reject_self_issued", "status")
        _require_list_of_str(st, "allowed_status_authorities", "status")
    if "assurance" in policy:
        asr = _require_dict(policy["assurance"], "assurance")
        _reject_unknown(asr, _ASSURANCE_KEYS, "assurance")
        lvl = asr.get("minimum_level")
        if lvl is not None and lvl not in ASSURANCE_LEVELS:
            raise PolicyError(f"assurance.minimum_level must be one of {list(ASSURANCE_LEVELS)} or null")
        _require_bool(asr, "reject_self_attested_without_prereg", "assurance")
    if "anchors" in policy:
        # WP-A1: the anchor requirement as a POLICY key (v0.2-gated like decision_receipt) — so a
        # relying party pins "must carry a verifying preRegistration anchor" in the policy file
        # instead of remembering CLI flags.
        if policy.get("schema") != POLICY_SCHEMA_V0_2:
            raise PolicyError("anchors section requires schema proofbundle/trust-policy/v0.2")
        anc = _require_dict(policy["anchors"], "anchors")
        _reject_unknown(anc, _ANCHORS_KEYS, "anchors")
        _require_str_or_null(anc, "require_anchor", "anchors")
        rt = anc.get("require_anchor_target")
        if rt is not None and rt not in _ANCHOR_TARGETS:
            raise PolicyError(f"anchors.require_anchor_target must be one of {list(_ANCHOR_TARGETS)} or null")
        _require_bool(anc, "allow_pending", "anchors")
    if "decision_receipt" in policy:
        dr = _require_dict(policy["decision_receipt"], "decision_receipt")
        _reject_unknown(dr, _DECISION_KEYS, "decision_receipt")
        if "trusted_decision_makers" in dr and not isinstance(dr["trusted_decision_makers"], list):
            raise PolicyError("decision_receipt.trusted_decision_makers must be a list")
        for dm in dr.get("trusted_decision_makers", []) or []:
            dm = _require_dict(dm, "trusted_decision_makers[]")
            _reject_unknown(dm, _DECISION_MAKER_KEYS, "trusted_decision_makers[]")
            if not (isinstance(dm.get("public_key_b64"), str) and dm["public_key_b64"]):
                raise PolicyError("each trusted_decision_makers[] entry needs a non-empty public_key_b64")
            _require_str_or_null(dm, "id", "trusted_decision_makers[]")
            _require_str_or_null(dm, "kid", "trusted_decision_makers[]")
        for key in ("allowed_decision_types", "allowed_verdicts", "required_evidence_relations",
                    "accepted_predicate_types"):
            if key in dr:
                _require_list_of_str(dr, key, "decision_receipt")
        for key in _DECISION_BOOL_KEYS:
            if key in dr:
                _require_bool(dr, key, "decision_receipt")
    return policy


def evaluate_decision_policy(statement: dict, verify_result: dict, policy: dict, *,
                             signer_public_key_b64: str, anchor_status: str | None = None) -> dict:
    """Apply the v0.2 decision_receipt policy section over an already crypto-verified Decision Receipt. Returns
    ``{"policy_ok": bool|None, "signer_trusted": bool|None, "errors": [...]}``. Never trusts decisionMaker.id on
    the JSON claim alone: the signer key (that verified the DSSE) is matched against trusted_decision_makers.
    policy_ok is None when the policy carries no decision_receipt section (nothing decision-specific to check).

    ``anchor_status`` is the PASS/WARN/FAIL/SKIP verdict from the DETACHED anchor verification done in
    verify_decision_receipt (anchors are not in the signed predicate; Fix 2). require_external_anchor gates on
    it, never on a claimed in-predicate ``status`` field (which does not exist on a real anchor object)."""
    section = policy.get("decision_receipt")
    if not isinstance(section, dict):
        return {"policy_ok": None, "signer_trusted": None, "errors": []}
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    if not isinstance(predicate, dict):
        return {"policy_ok": False, "signer_trusted": False, "errors": ["statement has no predicate object"]}
    errors: list[str] = []

    # predicateType allow-list (confusion defense at the policy layer)
    apt = section.get("accepted_predicate_types")
    if apt and statement.get("predicateType") not in apt:
        errors.append(f"predicateType {statement.get('predicateType')!r} not in accepted_predicate_types")

    # signer <-> trusted_decision_makers (by public key; decisionMaker.id only as a hint that must not conflict)
    signer_trusted = None
    tdm = section.get("trusted_decision_makers")
    if tdm:
        claimed_id = (predicate.get("decisionMaker") or {}).get("id")
        match = next((m for m in tdm if m.get("public_key_b64") == signer_public_key_b64), None)
        signer_trusted = match is not None
        if match is None:
            errors.append("signer key is not in trusted_decision_makers")
        elif match.get("id") is not None and claimed_id is not None and match["id"] != claimed_id:
            signer_trusted = False
            errors.append("decisionMaker.id does not match the trusted entry for this signer key")

    dt = predicate.get("decisionType")
    if section.get("allowed_decision_types") and dt not in section["allowed_decision_types"]:
        errors.append(f"decisionType {dt!r} not allowed by policy")
    verdict = (predicate.get("decision") or {}).get("verdict")
    if section.get("allowed_verdicts") and verdict not in section["allowed_verdicts"]:
        errors.append(f"verdict {verdict!r} not allowed by policy")

    req_rel = section.get("required_evidence_relations") or []
    if req_rel:
        have = {r.get("relation") for r in predicate.get("evidenceRefs", []) if isinstance(r, dict)}
        missing = [r for r in req_rel if r not in have]
        if missing:
            errors.append(f"required evidence relations missing: {missing}")

    if section.get("require_policy_digest"):
        pd = (predicate.get("policyBoundary") or {}).get("policyDigest")
        if not (isinstance(pd, dict) and isinstance(pd.get("sha256"), str)):
            errors.append("policy requires policyBoundary.policyDigest but it is absent")

    # validity presence knobs (§7.5): the VALUE binding is still --aud/--nonce; these require the fields be
    # PRESENT so a receipt cannot silently drop replay protection.
    _vraw = predicate.get("validity")
    validity = _vraw if isinstance(_vraw, dict) else {}
    if section.get("require_audience") and not (isinstance(validity.get("audience"), list) and validity.get("audience")):
        errors.append("policy requires validity.audience but it is absent or empty")
    if section.get("require_nonce") and not (isinstance(validity.get("nonce"), str) and validity.get("nonce")):
        errors.append("policy requires validity.nonce but it is absent")

    # reviewability knobs (§5.5): notChecked / decisionChangeConditions must be present, non-empty lists.
    if section.get("require_not_checked") and not (
            isinstance(predicate.get("notChecked"), list) and predicate.get("notChecked")):
        errors.append("policy requires a non-empty notChecked[] but it is absent or empty")
    if section.get("require_decision_change_conditions") and not (
            isinstance(predicate.get("decisionChangeConditions"), list) and predicate.get("decisionChangeConditions")):
        errors.append("policy requires a non-empty decisionChangeConditions[] but it is absent or empty")
    if section.get("require_trace_context") and not isinstance(predicate.get("traceContext"), dict):
        errors.append("policy requires traceContext but it is absent")

    # privacy: allow_raw_inputs defaults FALSE — a receipt carrying raw inputs is rejected unless opted in.
    if not section.get("allow_raw_inputs"):
        _praw = predicate.get("privacy")
        priv = _praw if isinstance(_praw, dict) else {}
        if priv.get("rawInputsIncluded") is True:
            errors.append("privacy.rawInputsIncluded=true but the policy does not allow raw inputs (allow_raw_inputs)")

    if section.get("require_external_anchor"):
        allow_pending = bool(section.get("allow_pending"))
        # Anchors are DETACHED (Fix 2): the real anchor verification ran in verify_decision_receipt and its
        # status is passed in as anchor_status. A PASS (a full verifying anchor) always satisfies; a
        # pending/inclusion-only anchor (WARN) satisfies ONLY when allow_pending is set (default false —
        # pending is the ABSENCE of a time anchor, not a weaker one). SKIP (no anchors) and FAIL never satisfy.
        satisfied = anchor_status == "PASS" or (allow_pending and anchor_status == "WARN")
        if not satisfied:
            errors.append(
                f"policy requires an external anchor but none satisfies it (anchor status: {anchor_status or 'none'}"
                + ("" if allow_pending else "; pending excluded, set allow_pending to accept a pending anchor") + ")")

    policy_ok = (not errors) and (signer_trusted is not False)
    return {"policy_ok": policy_ok, "signer_trusted": signer_trusted, "errors": errors}


def policy_expected_aud(policy: dict):
    """The aud the policy wants bound (sd_jwt.expected_aud), or None. Used by the CLI to reconcile
    with the --aud flag (a policy/flag conflict is an error, never a silent override)."""
    return (policy.get("sd_jwt") or {}).get("expected_aud")


def evaluate_policy(bundle: dict, result, policy: dict, *, now=None) -> dict:
    """Evaluate a trust policy OVER a completed crypto verification.

    ``result`` is the VerificationResult from ``verify_bundle`` (already run, with the effective aud
    the CLI reconciled from policy + --aud). Returns ``{policy_ok, checks, reason}`` where ``checks``
    is a list of ``{name, ok, detail}``. Crypto must have passed for a meaningful verdict; a policy is
    never a reason to trust bytes whose signature failed.

    Offline: the only network-free trust inputs are the policy file and the already-verified bundle.
    """
    checks: list = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # A policy is NEVER evaluated on unverified bytes (verify-lens L2): enforce the module invariant
    # HERE, not only in the CLI caller, so any public-API consumer of evaluate_policy is safe too.
    if not getattr(result, "ok", False):
        return {"policy_ok": None, "checks": [],
                "reason": "crypto verification did not pass — policy not evaluated"}

    sig = bundle.get("signature") or {}

    # 1. schema version
    allowed_schemas = policy.get("allowed_schema_versions") or []
    if allowed_schemas:
        got = bundle.get("schema")
        add("policy:schema_version", got in allowed_schemas,
            f"schema {got!r} not in allowed {allowed_schemas}" if got not in allowed_schemas
            else f"schema {got!r} allowed")

    # 2. signature algorithm
    allowed_algs = (policy.get("signature") or {}).get("allowed_algs") or []
    if allowed_algs:
        got = sig.get("alg")
        add("policy:signature_alg", got in allowed_algs,
            f"alg {got!r} not in allowed {allowed_algs}" if got not in allowed_algs
            else f"alg {got!r} allowed")

    # 3. issuer / signer — matched by PUBLIC KEY (kid is a hint only)
    allowed_issuers = policy.get("allowed_issuers") or []
    require_signer = bool((policy.get("signature") or {}).get("require_expected_signer"))
    if allowed_issuers or require_signer:
        signer_key = sig.get("public_key_b64")
        allowed_keys = {i.get("public_key_b64") for i in allowed_issuers}
        matched = signer_key in allowed_keys and signer_key is not None
        if not allowed_issuers and require_signer:
            add("policy:signer_allowed", False,
                "require_expected_signer is set but allowed_issuers is empty — no signer can match (fail-closed)")
        else:
            add("policy:signer_allowed", matched,
                "signer public key is in allowed_issuers" if matched
                else "signer public key is NOT in allowed_issuers")

    # 4. merkle required hash alg
    required_hash = (policy.get("merkle") or {}).get("required_hash_alg")
    if required_hash is not None:
        got = (bundle.get("merkle") or {}).get("hash_alg")
        add("policy:merkle_hash_alg", got == required_hash,
            f"merkle.hash_alg {got!r} != required {required_hash!r}" if got != required_hash
            else f"merkle.hash_alg {got!r} matches")

    # 5. SD-JWT / KB-JWT policy. The aud VALUE was already bound by verify_bundle (the CLI passed the
    #    reconciled effective aud); here we enforce the remaining presence/structure requirements.
    sdj = policy.get("sd_jwt") or {}
    sd = bundle.get("sd_jwt_vc")
    kb = None
    if isinstance(sd, dict) and isinstance(sd.get("compact"), str):
        kb = verify_key_binding(sd["compact"])   # read aud/nonce/iat/present (value binding done in verify_bundle)
    if sdj.get("require_key_binding_when_cnf_present"):
        # verify_bundle already fails closed on a cnf-bound SD-JWT without a KB-JWT; reflect it here so
        # the policy states the requirement explicitly. The crypto result's sd-jwt-key-binding check is
        # authoritative when present.
        kb_check = next((c for c in result.checks if c.name == "sd-jwt-key-binding"), None)
        if kb_check is not None:
            add("policy:key_binding_present", kb_check.ok,
                "key binding verified" if kb_check.ok else f"key binding failed: {kb_check.detail}")
        elif kb is not None and kb.get("present"):
            # a KB-shaped segment IS attached but no crypto verdict exists for it (no cnf AND no issuer
            # key → sd-jwt-key-binding was never run). An UNVERIFIED KB is not an acceptable "key
            # binding present" → fail closed (verify-lens L1, the previously missing else branch).
            add("policy:key_binding_present", False,
                "a KB-JWT segment is attached but its issuer signature was never verified — cannot "
                "confirm key binding (fail-closed; supply sd_jwt_vc.issuer_public_key_b64)")
        else:
            # genuinely no cnf holder key bound and no KB attached → nothing to require, vacuous pass.
            add("policy:key_binding_present", True, "no cnf holder key bound; KB not required")
    if sdj.get("require_nonce"):
        # A nonce only means anything when it comes from a VERIFIED key binding (verify-lens L1/L2,
        # HIGH): reading kb["nonce"] straight from an unauthenticated/unsigned KB-JWT was a false PASS.
        # Gate on the authoritative crypto verdict (the sd-jwt-key-binding check's .ok); no verified KB
        # → fail closed (an unauthenticated nonce provides no replay protection). This enforces the
        # PRESENCE of a nonce in a verified KB-JWT; binding the nonce VALUE to this transaction still
        # requires --nonce (RFC 9901 challenge, exactly like --aud) — see docs/TRUST_ANCHORS.md.
        kb_check = next((c for c in result.checks if c.name == "sd-jwt-key-binding"), None)
        verified_nonce = bool(kb_check is not None and kb_check.ok and kb and kb.get("nonce"))
        add("policy:nonce_present", verified_nonce,
            "verified KB-JWT carries a nonce" if verified_nonce
            else "policy requires a nonce from a VERIFIED key binding, but none is present "
                 "(fail-closed: an unauthenticated nonce provides no replay protection)")

    # 6. status — verify --policy v0.1 has NO status-snapshot input, so an ENABLED status requirement
    #    cannot be evaluated here. Fail closed rather than silently pass (the honest boundary).
    status = policy.get("status") or {}
    if status.get("reject_self_issued") or (status.get("allowed_status_authorities") or []):
        add("policy:status", False,
            "policy enables a status requirement, but verify --policy (v0.1) has no status-snapshot "
            "input — evaluate revocation separately with verify_status_snapshot (fail-closed)")

    # 7. assurance + freshness — only meaningful for an issuer-bound eval receipt. Decode once.
    asr = policy.get("assurance") or {}
    max_age = sdj.get("max_iat_age_seconds")
    needs_claim = (asr.get("minimum_level") is not None
                   or asr.get("reject_self_attested_without_prereg") or max_age is not None)
    if needs_claim:
        claim = decode_eval_claim(bundle)
        if claim is None:
            add("policy:assurance", False,
                "policy constrains assurance/freshness but the bundle is not a valid issuer-bound eval receipt")
        else:
            min_level = asr.get("minimum_level")
            if min_level is not None:
                got_level = claim.get("assurance_level")
                ok = (got_level in ASSURANCE_LEVELS
                      and ASSURANCE_LEVELS.index(got_level) >= ASSURANCE_LEVELS.index(min_level))
                add("policy:assurance_min_level", ok,
                    f"assurance_level {got_level!r} below minimum {min_level!r}" if not ok
                    else f"assurance_level {got_level!r} meets minimum {min_level!r}")
            if asr.get("reject_self_attested_without_prereg"):
                weak = (claim.get("assurance_level") == "self_attested" and not claim.get("prereg_sha256"))
                add("policy:assurance_prereg", not weak,
                    "self_attested without prereg_sha256 (weakest, rejected by policy)" if weak
                    else "assurance/pre-registration acceptable")
            if max_age is not None:
                fresh = check_freshness(claim, max_age_seconds=max_age, now=now)
                add("policy:freshness", bool(fresh.get("fresh")),
                    fresh.get("reason", ""))

    policy_ok = all(c["ok"] for c in checks)
    reason = "" if policy_ok else next((c["detail"] for c in checks if not c["ok"]), "policy not satisfied")
    return {"policy_ok": policy_ok, "checks": checks, "reason": reason}
