"""The profile: the declarations the draft leaves to "the applicable protocol or profile".

Every check here names the requirement sentence it comes from (ids from requirements.json, lines
in the pinned plain-text copy of the draft). A profile with an error is still processed, but no
structural PASS and no supported claim can come out of a run under it (see reconcile.py).
"""
from __future__ import annotations

import copy

from . import canon

MIN_DISPOSITIONS = ("CONFIRMED", "EXPLICIT_FAILURE", "UNCONFIRMED", "SUBSTITUTION", "CONFLICT",
                    "INVALID", "INDETERMINATE")                       # Section 6.1, lines 1042-1085
NON_SUCCESS_PROTECTED = ("UNCONFIRMED", "INVALID", "CONFLICT", "INDETERMINATE")   # S5.10-5
ENFORCEMENT_MEANINGS = ("APPLIED", "REFUSED", "NO_EFFECT", "UNKNOWN")  # Section 4.4, S5.6-2
COVERAGE_CONDITIONS = ("VERIFIED", "DECLARED_ONLY", "INDETERMINATE")   # S5.15-3
SUPPORT_MEANINGS = ("FULLY_SUPPORTED", "CONDITIONALLY_SUPPORTED", "NOT_SUPPORTED")  # S6.6-5
NEGATIVE_CONDITIONS = ("deadline_elapsed", "counterpart_missing", "transport_rejected",
                       "verification_failed", "outcome_undetermined")  # S5.8-2
RESOLUTION_CASES = ("unresolved", "stale", "ambiguous", "inconsistent")  # S5.12-1
ACK_POINTS = ("parsing", "verification", "durable_persistence", "enforcement_queue_admission",
              "completed_enforcement")                                 # S9.2-1
DUPLICATE_RULES = ("earliest-time-then-record-id",)
CLAIM_KINDS = ("structural_reconciliation", "complete_delivery", "complete_mediation",
               "scoped_failure", "independent_effect", "preserved_disposition")
PREDICATES = ("structural_pass", "observer_authority_verified", "coverage_verified",
              "coverage_declared_only", "failure_observed", "effect_observed",
              "observer_independent", "lossless_path")


def example_profile() -> dict:
    """A complete profile, as used by the derived vectors. Every field answers one requirement."""
    return {
        "profile_id": "acde01-interop-example",
        "profile_revision": "1",
        "identifier": {                                     # S5.1-2, S5.1-3
            "uniqueness_scope": "one issuer deployment for the lifetime of the evidence store",
            "reuse_rule": "never reused; a second issuer record with the same identifier and a "
                          "different content digest is SUBSTITUTION (Section 9.1)",
            "correlate_by": "instruction_id",
        },
        "attempts": {"distinguished": True,                # S5.1-4
                     "rule": "every emission carries attempt_id; observations of different "
                             "attempt_id values are never merged"},
        "content_binding": {"projection": canon.PROJECTION, "digest_alg": canon.DIGEST_ALG,
                            "canonicalization": canon.CANONICALIZATION,
                            "domain_separation": canon.DOMAIN_SEPARATION},   # S5.2-2
        "observer_verification": "observer identity and authority come only from the frozen trust "
                                 "configuration (trust.observers); labels inside a record are never "
                                 "trusted",                                  # S5.3-2
        "structural_without_trust": True,                   # S5.3-4
        "native_verification": "consumed",                  # S8.1-1
        "time": {"ordering_mechanism": "trusted-timestamp bases listed in trusted_bases, or one "
                                       "observer's own clock for its own records",
                 "trusted_bases": ["tsa:example-tsa"]},     # S5.9-1, S5.9-2
        "empty_target_set_valid": True,                     # S5.11-8
        "resolution_failure": {"unresolved": "INDETERMINATE", "stale": "INDETERMINATE",
                               "ambiguous": "INDETERMINATE", "inconsistent": "INVALID"},  # S5.12-1
        "transport_equivalence": None,                      # S4.3-1: none declared
        "ack_point": {"point": "verification"},             # S9.2-1, S9.2-2
        "enforcement_mapping": {"APPLIED": "APPLIED", "REFUSED": "REFUSED",
                                "NO_EFFECT": "NO_EFFECT", "UNKNOWN": "UNKNOWN"},   # S5.6-2
        "extra_dispositions": {},                           # S5.10-5
        "reduction_rule": {"precedence": ["INVALID", "CONFLICT", "SUBSTITUTION", "EXPLICIT_FAILURE",
                                          "INDETERMINATE", "CONFIRMED", "UNCONFIRMED"]},  # S5.10-6
        "duplicate_selection_rule": "earliest-time-then-record-id",   # S6.3-1
        "claims": {                                         # S6.6-8, S6.6-9
            "conditional_predicates": ["observer_authority_verified", "coverage_verified"],
            "mandatory_predicates": {
                "structural_reconciliation": ["structural_pass"],
                "complete_delivery": ["structural_pass"],
                "complete_mediation": ["structural_pass"],
                "scoped_failure": ["failure_observed"],
                "independent_effect": ["effect_observed", "observer_independent"],
                "preserved_disposition": ["lossless_path"],
            },
        },
        "intermediary_mappings": {},                        # S5.16-2
        "uses_telemetry": False,                            # S8.3-1
        "exclusion_rules": [],                              # S6.4-8
        "negative_conditions": list(NEGATIVE_CONDITIONS),   # S5.8-2
        "control_activation": {                             # S9.4-1
            "effective_boundary": "provider_entry",
            "in_flight_rule": "an operation that crossed provider entry before activation keeps that "
                              "crossing; a later provider-entry attempt may be refused",
        },
    }


def _err(errors, req, msg):
    errors.append({"requirement": req, "error": msg})


def _nonempty_str(v):
    return isinstance(v, str) and v.strip() != ""


def validate_profile(profile) -> list:
    """All declaration errors of a profile, each with the requirement it violates. [] when valid."""
    errors: list = []
    if not isinstance(profile, dict):
        _err(errors, "S6.3", "profile must be an object")
        return errors
    if not _nonempty_str(profile.get("profile_id")) or not _nonempty_str(profile.get("profile_revision")):
        _err(errors, "S6.3", "profile_id and profile_revision must be frozen for the run (Section 6.3 step 1)")

    ident = profile.get("identifier")
    if not isinstance(ident, dict) or not _nonempty_str(ident.get("uniqueness_scope")) \
            or not _nonempty_str(ident.get("reuse_rule")):
        _err(errors, "S5.1-2", "identifier uniqueness scope and reuse rule must be defined")
    else:
        corr = ident.get("correlate_by", "instruction_id")
        if corr != "instruction_id" and ident.get("identical_uniqueness_and_lifecycle") is not True:
            _err(errors, "S5.1-3", f"correlation by {corr!r} replaces the instruction identifier "
                                   "without declared identical uniqueness and lifecycle semantics")

    att = profile.get("attempts")
    if not isinstance(att, dict) or not isinstance(att.get("distinguished"), bool):
        _err(errors, "S5.1-4", "the profile must say whether retries create distinct attempts")
    elif att["distinguished"] and not _nonempty_str(att.get("rule")):
        _err(errors, "S5.1-4", "distinct attempts need an attempt identifier rule")

    cb = profile.get("content_binding")
    want = {"projection": canon.PROJECTION, "digest_alg": canon.DIGEST_ALG,
            "canonicalization": canon.CANONICALIZATION, "domain_separation": canon.DOMAIN_SEPARATION}
    if not isinstance(cb, dict):
        _err(errors, "S5.2-2", "projection, digest algorithm, canonicalization and domain separation "
                               "must be identified")
    else:
        for k, v in want.items():
            if k not in cb:
                _err(errors, "S5.2-2", f"content_binding.{k} is not identified")
            elif cb[k] != v:
                _err(errors, "S5.2-2", f"content_binding.{k}={cb[k]!r} is not supported by this "
                                       f"implementation (only {v!r}); no fallback is taken")

    if not _nonempty_str(profile.get("observer_verification")):
        _err(errors, "S5.3-2", "the profile must state how observer identity and authority are verified")
    if not isinstance(profile.get("structural_without_trust"), bool):
        _err(errors, "S5.3-4", "the profile must say whether structural processing continues "
                               "without a trust binding")
    if profile.get("native_verification") != "consumed":
        _err(errors, "S8.1-1", "native verification must be performed or its result consumed; this "
                               "implementation consumes it ('consumed')")

    tm = profile.get("time")
    if not isinstance(tm, dict) or not _nonempty_str(tm.get("ordering_mechanism")) \
            or not isinstance(tm.get("trusted_bases"), list):
        _err(errors, "S5.9-2", "the profile reports precedence (Section 9.4) and must state the "
                               "ordering mechanism and its trusted bases")

    if not isinstance(profile.get("empty_target_set_valid"), bool):
        _err(errors, "S5.11-8", "the profile must define whether an empty Required Target Set is a "
                                "valid terminal resolution")

    rf = profile.get("resolution_failure")
    if not isinstance(rf, dict):
        _err(errors, "S5.12-1", "behavior for unresolved, stale, ambiguous and inconsistent "
                                "references must be defined")
    else:
        for case in RESOLUTION_CASES:
            if rf.get(case) not in ("INDETERMINATE", "INVALID"):
                _err(errors, "S5.12-1", f"resolution_failure.{case} must be INDETERMINATE or INVALID")

    te = profile.get("transport_equivalence", None)
    if te is not None:
        need = ("endpoint_binding", "delivery_semantics", "persistence_point", "failure_behavior")
        if not isinstance(te, dict) or not all(_nonempty_str(te.get(k)) for k in need):
            _err(errors, "S4.3-1", "a transport acknowledgement may count as enforcement-point receipt "
                                   "only with endpoint binding, delivery semantics, persistence point "
                                   "and failure behavior defined")

    ack = profile.get("ack_point")
    if not isinstance(ack, dict):
        _err(errors, "S9.2-1", "the acknowledgement point should be stated (object with 'point')")
    else:
        pts = ack.get("point")
        pts = [pts] if isinstance(pts, str) else pts
        if not isinstance(pts, list) or not pts or any(p not in ACK_POINTS for p in pts):
            _err(errors, "S9.2-1", f"ack_point.point must be one or more of {ACK_POINTS}")
        elif len(pts) > 1 and not (_nonempty_str(ack.get("combined_semantics"))
                                   and _nonempty_str(ack.get("residual_failure_window"))):
            _err(errors, "S9.2-2", "one acknowledgement value for several points needs combined "
                                   "semantics and a residual failure window")

    em = profile.get("enforcement_mapping")
    if not isinstance(em, dict) or not em:
        _err(errors, "S5.6-2", "enforcement states must be the four meanings or a lossless mapping to them")
    else:
        bad = {k: v for k, v in em.items() if v not in ENFORCEMENT_MEANINGS}
        if bad:
            _err(errors, "S5.6-2", f"enforcement_mapping targets outside the four meanings: {sorted(bad)}")
        missing = [m for m in ENFORCEMENT_MEANINGS if m != "UNKNOWN" and m not in em.values()]
        if missing:
            _err(errors, "S5.6-2", f"native states cannot express {missing}; the mapping is not lossless")

    xd = profile.get("extra_dispositions", {})
    if not isinstance(xd, dict):
        _err(errors, "S5.10-5", "extra_dispositions must be an object")
    else:
        for name, spec in xd.items():
            if not isinstance(spec, dict) or spec.get("maps_to") not in MIN_DISPOSITIONS:
                _err(errors, "S5.10-5", f"extra disposition {name!r} has no lossless mapping to the minimum set")
                continue
            if spec.get("refines") in NON_SUCCESS_PROTECTED and spec["maps_to"] == "CONFIRMED":
                _err(errors, "S5.10-5", f"extra disposition {name!r} weakens {spec['refines']} into success")
            if spec.get("refines") not in (None, spec["maps_to"]):
                _err(errors, "S5.10-5", f"extra disposition {name!r} refines {spec.get('refines')} but "
                                        f"maps to {spec['maps_to']}: not lossless")

    rr = profile.get("reduction_rule")
    prec = rr.get("precedence") if isinstance(rr, dict) else None
    if not isinstance(prec, list) or sorted(prec) != sorted(MIN_DISPOSITIONS):
        _err(errors, "S5.10-6", "the reduction rule must be a published total precedence over the "
                                "seven minimum dispositions (deterministic and reviewable)")

    if profile.get("duplicate_selection_rule") not in DUPLICATE_RULES:
        _err(errors, "S6.3-1", f"duplicate selection rule must be one of {DUPLICATE_RULES}")

    cl = profile.get("claims")
    if not isinstance(cl, dict) or not isinstance(cl.get("conditional_predicates"), list) \
            or not isinstance(cl.get("mandatory_predicates"), dict):
        _err(errors, "S6.6-8", "the profile must state which missing predicates may produce "
                               "CONDITIONALLY_SUPPORTED")
    else:
        unknown = [p for p in cl["conditional_predicates"] if p not in PREDICATES]
        if unknown:
            _err(errors, "S6.6-8", f"unknown conditional predicates {unknown}")
        for kind, preds in cl["mandatory_predicates"].items():
            if kind not in CLAIM_KINDS or not isinstance(preds, list):
                _err(errors, "S6.6-8", f"mandatory_predicates.{kind} is not a known claim kind with a list")
                continue
            both = sorted(set(preds) & set(cl["conditional_predicates"]))
            if both:
                _err(errors, "S6.6-9", f"{kind}: {both} declared mandatory and conditional at once; "
                                       "conditional support would be a silent fallback")
        for kind in CLAIM_KINDS:
            if kind not in cl["mandatory_predicates"]:
                _err(errors, "S6.6-8", f"mandatory_predicates.{kind} is not declared")
        if profile.get("structural_without_trust") is True \
                and "observer_authority_verified" not in cl["conditional_predicates"] \
                and not all("observer_authority_verified" in v for v in cl["mandatory_predicates"].values()
                            if isinstance(v, list)):
            _err(errors, "S5.3-4", "structural processing without a trust binding is permitted, so the "
                                   "missing binding must be exposed: declare observer_authority_verified "
                                   "conditional or mandatory")

    im = profile.get("intermediary_mappings", {})
    if not isinstance(im, dict):
        _err(errors, "S5.16-2", "intermediary_mappings must be an object")
    else:
        for mid, spec in im.items():
            if not isinstance(spec, dict) or not isinstance(spec.get("governance_states"), list) \
                    or not isinstance(spec.get("map"), dict):
                _err(errors, "S5.16-2", f"mapping {mid!r} must list governance_states and a map")
                continue
            unmapped = [s for s in spec["governance_states"] if s not in spec["map"]]
            if unmapped and spec.get("declared_incomplete") is not True:
                _err(errors, "S5.16-2", f"mapping {mid!r} leaves {unmapped} unmapped without exposing "
                                        "that the mapping is incomplete")

    if profile.get("uses_telemetry") is True:
        tb = profile.get("telemetry_bindings")
        kinds = ("native", "derived", "declared-only", "absent")
        if not isinstance(tb, dict) or not tb or any(v not in kinds for v in tb.values()):
            _err(errors, "S8.3-1", "a profile using telemetry must state for each required binding "
                                   "whether it is native, derived, declared-only or absent")
    elif not isinstance(profile.get("uses_telemetry"), bool):
        _err(errors, "S8.3-1", "uses_telemetry must be declared")

    ex = profile.get("exclusion_rules", [])
    if not isinstance(ex, list):
        _err(errors, "S6.4-8", "exclusion_rules must be a list")
    else:
        for rule in ex:
            if not isinstance(rule, dict) or not _nonempty_str(rule.get("rule_id")) \
                    or rule.get("applies_to") != "issuer_attribute" or not _nonempty_str(rule.get("attribute")):
                _err(errors, "S6.4-8", "an exclusion rule needs rule_id and must be stated over an "
                                       "issuer-side attribute (decided before receiver evidence)")

    ca = profile.get("control_activation")
    if not isinstance(ca, dict) or ca.get("effective_boundary") not in ("admission", "provider_entry") \
            or not _nonempty_str(ca.get("in_flight_rule")):
        _err(errors, "S9.4-1", "the profile reports APPLIED for freezes and should define the local effective "
                               "boundary and the rule for operations already admitted or in flight")

    neg = profile.get("negative_conditions")
    if not isinstance(neg, list) or any(c not in NEGATIVE_CONDITIONS for c in neg):
        _err(errors, "S5.8-2", f"negative_conditions must be a subset of {NEGATIVE_CONDITIONS}")
    return errors


def with_changes(profile: dict, **changes) -> dict:
    """A deep copy of ``profile`` with top-level fields replaced (``None`` deletes the field)."""
    out = copy.deepcopy(profile)
    for k, v in changes.items():
        if v is None and k != "transport_equivalence":
            out.pop(k, None)
        else:
            out[k] = v
    return out
