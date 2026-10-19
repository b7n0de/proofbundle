"""One bounded reconciliation run, following Section 6.3 of the draft step by step.

Input: a run object (profile, frozen inputs, records, requested claims); see README.md for the
shape. Output: a report object. Requirement ids in comments refer to requirements.json; line
numbers refer to the pinned plain-text copy of the draft.

Readings chosen where the text allows more than one are marked READING and listed in
requirements_map.json with the alternatives considered.
"""
from __future__ import annotations

import copy

from . import DRAFT, DRAFT_SHA256, IMPLEMENTATION_VERSION, canon
from .profile import MIN_DISPOSITIONS, validate_profile

REPORT_VERSION = "acde01-interop-report/1"
POSITIVE_FAILURES = ("EXPLICIT_FAILURE", "SUBSTITUTION")
RECEIVER_CLASSES = ("matched", "orphan", "duplicate", "invalid_receiver")
EFFECT_RESULTS = ("EFFECT_OBSERVED", "NO_EFFECT", "UNKNOWN")

_COMMON = ("record_id", "kind", "observer", "boundary_side", "boundary", "event", "time", "clock")
_KIND_FIELDS = {
    "issuer_emission": ("instruction_id", "content_digest", "target_set_ref"),          # S5.4-2
    "receiver_observation": ("instruction_id", "content_digest", "receiver_id", "target_id"),  # S5.5-2
    "transport_ack": ("instruction_id", "target_id"),
    "negative_observation": ("condition", "observed", "cutoff", "instruction_id", "target_id"),  # S5.8-1
    "enforcement_outcome": ("instruction_id", "target_id", "outcome"),
    "effect_observation": ("instruction_id", "target_id", "predicate", "method",
                           "observer_relationship", "window", "result"),                 # S5.7-2
    "intermediary_hop": ("path_id", "hop_index", "intermediary", "mapping_id", "source_state",
                         "delivered_state", "instruction_id", "target_id"),               # S5.16-1
    "operation_event": ("operation_id", "target_id", "op_boundary"),
    "control_activation": ("instruction_id", "target_id"),
}
_KIND_EVENTS = {
    "issuer_emission": ("emitted", "emission_failed"),
    "receiver_observation": ("read_and_matched", "verification_failed"),
    "transport_ack": ("accepted", "queued", "rejected"),
    "negative_observation": ("observed",),
    "enforcement_outcome": ("outcome",),
    "effect_observation": ("observed",),
    "intermediary_hop": ("forwarded",),
    "operation_event": ("crossed", "refused"),
    "control_activation": ("activated",),
}
_ATTEMPT_KINDS = ("issuer_emission", "receiver_observation", "transport_ack")


def _diag(code, **detail):
    d = {"code": code}
    d.update({k: v for k, v in detail.items() if v is not None})
    return d


def _check_record(rec, profile, seen_ids):
    """Structural validity of one input record. Returns (ok, reason)."""
    if not isinstance(rec, dict):
        return False, "record is not an object"
    rid = rec.get("record_id")
    if not isinstance(rid, str) or not rid:
        return False, "record_id missing"
    if rid in seen_ids:
        return False, "record_id repeated in the input"
    kind = rec.get("kind")
    if kind not in _KIND_FIELDS:
        return False, f"unknown record kind {kind!r}"
    for f in _COMMON + _KIND_FIELDS[kind]:
        if f not in rec or rec[f] in (None, ""):
            # S5.3-1 observer/boundary/event, S5.9-1 time + clock basis, kind-specific fields
            return False, f"required field {f!r} missing"
    if canon.parse_time(rec["time"]) is None:
        return False, "time is not an RFC 3339 UTC value"                               # S5.9-1
    if rec["event"] not in _KIND_EVENTS[kind]:
        return False, f"event {rec['event']!r} is not defined for {kind}"
    if kind in _ATTEMPT_KINDS and profile.get("attempts", {}).get("distinguished") is True \
            and not isinstance(rec.get("attempt_id"), str):
        return False, "attempt_id required: the profile distinguishes delivery attempts"  # S5.5-2
    if kind in ("issuer_emission", "receiver_observation") and not canon.is_digest(rec["content_digest"]):
        return False, "content_digest is not a sha-256 digest under the profile"           # S5.2-1
    if kind in ("issuer_emission", "receiver_observation") and "content" in rec:
        try:
            got = canon.instruction_digest(rec["content"])
        except canon.CanonError as exc:
            return False, f"content outside the canonical projection: {exc}"
        if got != rec["content_digest"]:
            # S5.5-5: the record acknowledges a digest that is not the digest of what it read.
            return False, "content_digest does not match the content the record carries"
    if kind == "negative_observation":
        if rec["condition"] not in profile.get("negative_conditions", []):
            return False, f"negative condition {rec['condition']!r} not supported by the profile"
        if canon.parse_time(rec["cutoff"]) is None:
            return False, "negative observation cutoff is not a time"                     # S5.8-1
    if kind == "effect_observation":
        w = rec["window"]
        if not isinstance(w, dict) or canon.parse_time(w.get("start")) is None \
                or canon.parse_time(w.get("end")) is None:
            return False, "effect observation needs start and end conditions"             # S5.7-2
        if rec["result"] not in EFFECT_RESULTS:
            return False, f"effect result {rec['result']!r} unknown"
    if kind == "operation_event" and rec["op_boundary"] not in ("admission", "provider_entry"):
        return False, "op_boundary must be admission or provider_entry"
    nv = rec.get("native")
    if nv == "failed":
        return False, "native verification failed"                                       # S8.1-1
    if nv != "verified":
        return False, "no native verification result to consume"                         # S8.1-1
    return True, None


def _comparable(a, b, profile):
    """Can the times of records a and b be ordered? S5.9-2, S5.9-3."""
    trusted = set(profile.get("time", {}).get("trusted_bases", []))
    if a["clock"] in trusted and b["clock"] in trusted and a["clock"] == b["clock"]:
        return True
    return a["observer"] == b["observer"] and a["clock"] == b["clock"]


def _resolve_member(member, directory):
    """A target-set member to (target_id or None, failure case or None)."""
    if isinstance(member, str):
        return (member, None) if member in directory.get("targets", {}) else (None, "unresolved")
    if isinstance(member, dict) and isinstance(member.get("ref"), str):
        hit = directory.get("refs", {}).get(member["ref"])
        if hit is None:
            return None, "unresolved"
        if isinstance(hit, list):
            if len(hit) == 1:
                hit = hit[0]
            else:
                return None, "ambiguous"
        return (hit, None) if hit in directory.get("targets", {}) else (None, "unresolved")
    return None, "malformed"


def reconcile(run) -> dict:
    run = copy.deepcopy(run)
    profile = run.get("profile") or {}
    perrors = validate_profile(profile)
    frozen = run.get("frozen") or {}
    records = run.get("records") or []
    claims_req = run.get("claims") or []
    cutoff_s = frozen.get("cutoff")
    cutoff = canon.parse_time(cutoff_s)
    window = frozen.get("window") or {}
    w_start, w_end = canon.parse_time(window.get("start")), canon.parse_time(window.get("end"))
    directory = frozen.get("target_directory") or {}
    trust_obs = (frozen.get("trust") or {}).get("observers") or {}
    run_errors = []
    if cutoff is None or w_start is None or w_end is None:
        run_errors.append({"requirement": "S5.11-1", "error": "cutoff and observation window must be declared"})
    if not isinstance(frozen.get("issuer_inclusion_rule"), str):
        run_errors.append({"requirement": "S5.11-1", "error": "issuer inclusion rule must be declared"})
    precedence = (profile.get("reduction_rule") or {}).get("precedence") or list(MIN_DISPOSITIONS)

    # ---- Step 1: frozen inputs, exclusions decided on issuer attributes only (S6.4-8, S6.5-4)
    exclusions = []
    excluded_ids = set()
    instr_specs = []
    for spec in frozen.get("instructions") or []:
        rule_hit = None
        for rule in profile.get("exclusion_rules") or []:
            if (spec.get("attributes") or {}).get(rule.get("attribute")) == rule.get("equals"):
                rule_hit = rule["rule_id"]
                break
        if rule_hit:
            excluded_ids.add(spec.get("instruction_id"))
            ex = next((e for e in exclusions if e["rule"] == rule_hit), None)
            if ex is None:
                ex = {"rule": rule_hit, "kind": "instruction", "count": 0, "ids": []}
                exclusions.append(ex)
            ex["count"] += 1
            ex["ids"].append(spec.get("instruction_id"))
        else:
            instr_specs.append(spec)

    # ---- Step 3/4: parse every record, keep the invalid ones (S5.10-2), consume native results
    input_class = {}
    valid = []
    seen = set()
    keys = []
    late = {"rule": "observed-after-cutoff", "kind": "record", "count": 0, "ids": []}
    for idx, rec in enumerate(records):
        rid = rec.get("record_id") if isinstance(rec, dict) else None
        key = rid if isinstance(rid, str) and rid and rid not in seen else f"#input[{idx}]"
        keys.append(key)
        ok, why = _check_record(rec, profile, seen)
        if isinstance(rid, str) and rid:
            seen.add(rid)
        if not ok:
            input_class[key] = {"class": f"{rec.get('kind', 'unknown') if isinstance(rec, dict) else 'unknown'}:invalid",
                                "reason": why}
            continue
        if rec.get("instruction_id") in excluded_ids:
            input_class[key] = {"class": "excluded", "reason": "instruction excluded before population construction"}
            continue
        if cutoff is not None and canon.parse_time(rec["time"]) > cutoff:
            late["count"] += 1
            late["ids"].append(rid)
            input_class[key] = {"class": "excluded", "reason": "observed after the reconciliation cutoff"}
            continue
        valid.append(rec)
    if late["count"]:
        exclusions.append(late)
    invalid_by_instr = {}
    for idx, rec in enumerate(records):
        if isinstance(rec, dict) and isinstance(rec.get("instruction_id"), str):
            cls = input_class.get(keys[idx])
            if cls and cls["class"].endswith(":invalid"):
                invalid_by_instr.setdefault(rec["instruction_id"], []).append((rec.get("kind"), keys[idx], cls["reason"]))

    by_kind = {}
    for rec in valid:
        by_kind.setdefault(rec["kind"], []).append(rec)
    for lst in by_kind.values():
        lst.sort(key=lambda r: (canon.parse_time(r["time"]), r["record_id"]))

    # ---- Step 2: expected population from issuer inclusion + target resolution (S5.10-4, S6.3)
    issuer_boundary = frozen.get("issuer_boundary")
    issuer_by_instr = {}
    computed_population = set()
    for rec in by_kind.get("issuer_emission", []):
        issuer_by_instr.setdefault(rec["instruction_id"], []).append(rec)
        t = canon.parse_time(rec["time"])
        at_boundary = rec["boundary"] == issuer_boundary or rec["event"] == "emission_failed"
        if at_boundary and w_start and w_end and w_start <= t <= w_end:
            computed_population.add(rec["instruction_id"])
    frozen_population = [s.get("instruction_id") for s in instr_specs]
    population_mismatch = sorted(set(frozen_population) ^ computed_population)

    instructions = []
    obligations = []
    obl_index = {}
    for spec in sorted(instr_specs, key=lambda s: str(s.get("instruction_id"))):
        iid = spec.get("instruction_id")
        tr = spec.get("target_resolution") or {}
        entry = {"instruction_id": iid, "class": None, "target_set": None, "dispatched": None,
                 "diagnostics": []}
        members = []
        set_fail = None
        if "empty" in tr:
            entry["class"] = "zero_obligations"
            entry["zero_obligation_condition"] = (tr["empty"] or {}).get("condition")
            entry["empty_set_permitted"] = profile.get("empty_target_set_valid") is True
            if not entry["zero_obligation_condition"]:
                entry["diagnostics"].append(_diag("EMPTY_SET_CONDITION_MISSING"))
        elif "open" in tr:
            entry["class"] = "not_closed"
            entry["open_scope"] = {"reason": (tr["open"] or {}).get("reason"),
                                   "known_targets": list((tr["open"] or {}).get("known_targets") or [])}
            members = list(entry["open_scope"]["known_targets"])
        elif "set_id" in tr:
            sid = tr["set_id"]
            ts = (frozen.get("target_sets") or {}).get(sid)
            entry["target_set"] = sid
            if not isinstance(ts, dict) or not isinstance(ts.get("members"), list):
                entry["class"] = "not_closed"
                entry["resolution_failure"] = {"case": "unresolved",
                                               "profile_behavior": (profile.get("resolution_failure") or {}).get("unresolved")}
            else:
                if not ts.get("closure_basis") or ts.get("coverage") not in ("VERIFIED", "DECLARED_ONLY", "INDETERMINATE"):
                    e = {"requirement": "S5.15-1",
                         "error": f"target set {sid}: closure basis and coverage condition must be stated"}
                    if e not in run_errors:
                        run_errors.append(e)
                vu = canon.parse_time(ts.get("valid_until")) if ts.get("valid_until") else None
                if vu is not None and cutoff is not None and vu < cutoff:
                    set_fail = "stale"
                members = list(ts["members"])
                entry["class"] = "with_obligations" if members else "zero_obligations"
                if not members:
                    entry["zero_obligation_condition"] = ts.get("empty_condition")
                    entry["empty_set_permitted"] = profile.get("empty_target_set_valid") is True
        else:
            entry["class"] = "not_closed"
            entry["resolution_failure"] = {"case": "unresolved",
                                           "profile_behavior": (profile.get("resolution_failure") or {}).get("unresolved")}
        instructions.append(entry)

        # issuer-side state for this instruction (S5.4, S9.1)
        irecs = issuer_by_instr.get(iid, [])
        emitted = [r for r in irecs if r["event"] == "emitted"]
        failed_emissions = [r for r in irecs if r["event"] == "emission_failed"]
        entry["dispatched"] = bool(emitted)                                              # S5.4-4
        attempts = {}
        issuer_dups = []
        for r in emitted:
            a = r.get("attempt_id", "-")
            if a in attempts and attempts[a]["content_digest"] == r["content_digest"]:
                issuer_dups.append(r["record_id"])
                continue
            attempts.setdefault(a, r)
        digests = sorted({r["content_digest"] for r in emitted})
        issuer_state = None
        if len(digests) > 1:
            issuer_state = ("SUBSTITUTION", _diag("ISSUER_ID_REUSED_WITH_DIFFERENT_CONTENT", digests=digests))
        elif not emitted and failed_emissions:
            issuer_state = ("EXPLICIT_FAILURE", _diag("EMISSION_FAILED_BEFORE_BOUNDARY",
                                                      records=[r["record_id"] for r in failed_emissions],
                                                      scope="issuer boundary; all targets of the failed attempt"))
        elif not irecs:
            if iid in invalid_by_instr and any(k == "issuer_emission" for k, _, _ in invalid_by_instr[iid]):
                issuer_state = ("INVALID", _diag("ISSUER_RECORD_INVALID",
                                                 records=[rid for k, rid, _ in invalid_by_instr[iid] if k == "issuer_emission"]))
            else:
                issuer_state = ("INDETERMINATE", _diag("ISSUER_RECORD_ABSENT"))
        for r in emitted:
            if entry["target_set"] is not None and r["target_set_ref"] != entry["target_set"]:
                set_fail = "inconsistent"
            ts = (frozen.get("target_sets") or {}).get(entry["target_set"]) if entry["target_set"] else None
            if isinstance(ts, dict) and "target_set_digest" in r \
                    and r["target_set_digest"] != canon.document_digest(ts.get("members")):
                set_fail = "inconsistent"
        entry["issuer_records"] = [r["record_id"] for r in irecs]
        entry["issuer_duplicates"] = issuer_dups
        if failed_emissions:
            entry["diagnostics"].append(_diag("EMISSION_FAILURE_RECORDED",
                                              records=[r["record_id"] for r in failed_emissions]))

        for m in members:
            tid, fail = _resolve_member(m, directory)
            label = tid if tid is not None else ("ref:" + m["ref"] if isinstance(m, dict) and isinstance(m.get("ref"), str)
                                                 else "malformed:" + canon.document_digest(m)[8:20] if _jsonable(m) else "malformed")
            ob = {"instruction_id": iid, "target_id": label, "disposition": None, "candidates": [],
                  "diagnostics": [], "matched_records": [], "attempts": sorted(attempts),
                  "open_scope": entry["class"] == "not_closed",
                  "scope": {"instruction_id": iid, "target_id": label,
                            "receiving_boundary": (directory.get("targets", {}).get(tid) or {}).get("boundary")}}
            if issuer_state is not None:
                ob["candidates"].append(issuer_state[0])
                ob["diagnostics"].append(issuer_state[1])
            if set_fail is not None:
                beh = (profile.get("resolution_failure") or {}).get(set_fail, "INDETERMINATE")
                ob["candidates"].append(beh)
                ob["diagnostics"].append(_diag("TARGET_SET_" + set_fail.upper(), set_id=entry["target_set"]))
            if fail == "malformed":
                ob["candidates"].append("INVALID")
                ob["diagnostics"].append(_diag("TARGET_MEMBER_MALFORMED", member=m))
            elif fail is not None:
                beh = (profile.get("resolution_failure") or {}).get(fail, "INDETERMINATE")
                ob["candidates"].append(beh)
                ob["diagnostics"].append(_diag("TARGET_" + fail.upper(), member=m))
            ob["_attempts"] = attempts
            obligations.append(ob)
            obl_index[(iid, label)] = ob

    # ---- Steps 5/6/8: receiver records, grouped by obligation identity without assuming equality
    rclass = {}
    dup_keys = {}
    for rec in by_kind.get("receiver_observation", []):
        rid = rec["record_id"]
        ob = obl_index.get((rec["instruction_id"], rec["target_id"]))
        if ob is None:
            rclass[rid] = ("orphan", _diag("NO_EXPECTED_OBLIGATION", instruction_id=rec["instruction_id"],
                                           target_id=rec["target_id"]))
            continue
        tdir = directory.get("targets", {}).get(rec["target_id"]) or {}
        obs = trust_obs.get(rec["observer"])
        if obs is None:
            # READING: an observer absent from the trust configuration is an unresolved trust
            # binding (6.1 INDETERMINATE), not a malformed record.
            rclass[rid] = ("matched", _diag("TRUST_BINDING_UNRESOLVED", observer=rec["observer"]))
            ob["candidates"].append("INDETERMINATE")
            ob["diagnostics"].append(_diag("TRUST_BINDING_UNRESOLVED", record=rid, observer=rec["observer"]))
            ob["matched_records"].append(rid)
            continue
        if rec["target_id"] not in (obs.get("binds_targets") or []) \
                or rec["receiver_id"] not in (tdir.get("receiver_ids") or []):
            # S5.5-3, S5.5-4: a record may satisfy only the obligation it is verified to represent.
            rclass[rid] = ("invalid_receiver", _diag("RECORD_NOT_BOUND_TO_TARGET", target_id=rec["target_id"],
                                                     observer=rec["observer"], receiver_id=rec["receiver_id"]))
            ob["diagnostics"].append(_diag("RECORD_NOT_BOUND_TO_TARGET", record=rid))
            continue
        if obs.get("authority_verified") is not True and profile.get("structural_without_trust") is False:
            # S5.3-4: this profile does not permit structural processing without a verified
            # authority binding, so the record lacks a binding required for structural validity.
            rclass[rid] = ("invalid_receiver", _diag("AUTHORITY_BINDING_REQUIRED", observer=rec["observer"]))
            ob["diagnostics"].append(_diag("AUTHORITY_BINDING_REQUIRED", record=rid))
            continue
        if rec["boundary"] != tdir.get("boundary"):
            rclass[rid] = ("invalid_receiver", _diag("RECEIVING_BOUNDARY_MISMATCH", boundary=rec["boundary"],
                                                     required=tdir.get("boundary")))
            ob["diagnostics"].append(_diag("RECEIVING_BOUNDARY_MISMATCH", record=rid))
            continue
        attempts = ob["_attempts"]
        a = rec.get("attempt_id", "-")
        if profile.get("attempts", {}).get("distinguished") and a not in attempts:
            # S5.1-4: an observation of an attempt the issuer never emitted is not merged into another.
            rclass[rid] = ("orphan", _diag("ATTEMPT_NOT_EMITTED", attempt_id=a))
            ob["diagnostics"].append(_diag("RECEIVER_RECORD_FOR_UNKNOWN_ATTEMPT", record=rid, attempt_id=a))
            continue
        issuer_digest = attempts[a]["content_digest"] if a in attempts else None
        key = (ob["instruction_id"], ob["target_id"], a, rec["content_digest"], rec["event"])
        if key in dup_keys:
            rclass[rid] = ("duplicate", _diag("DUPLICATE_OF", record=dup_keys[key]))
            ob["diagnostics"].append(_diag("DUPLICATE_RECEIVER_RECORD", record=rid, first=dup_keys[key]))
            continue
        dup_keys[key] = rid
        ob["matched_records"].append(rid)
        if rec["event"] == "verification_failed":
            rclass[rid] = ("matched", _diag("RECEIVER_FAILURE_OBSERVATION"))
            ob["candidates"].append(("EXPLICIT_FAILURE", a))
            ob["diagnostics"].append(_diag("RECEIVER_VERIFICATION_FAILED", record=rid, attempt_id=a))
        elif issuer_digest is None:
            rclass[rid] = ("matched", _diag("NO_ISSUER_DIGEST"))
            ob["diagnostics"].append(_diag("NO_ISSUER_DIGEST_FOR_ATTEMPT", record=rid))
        elif rec["content_digest"] == issuer_digest:
            rclass[rid] = ("matched", _diag("CONFIRMING"))
            ob["candidates"].append(("CONFIRMED", a))
            ob["diagnostics"].append(_diag("RECEIVER_MATCH", record=rid, attempt_id=a))
        else:
            rclass[rid] = ("matched", _diag("CONTENT_BINDING_DIFFERS"))
            ob["candidates"].append(("SUBSTITUTION", a))
            ob["diagnostics"].append(_diag("CONTENT_BINDING_DIFFERS", record=rid, attempt_id=a,
                                           issuer=issuer_digest, receiver=rec["content_digest"]))

    # transport acknowledgements: evidence about the transport boundary only (Section 4.3, S4.3-1)
    te = profile.get("transport_equivalence")
    for rec in by_kind.get("transport_ack", []):
        rid = rec["record_id"]
        ob = obl_index.get((rec["instruction_id"], rec["target_id"]))
        a = rec.get("attempt_id", "-")
        if ob is None:
            input_class[rid] = {"class": "transport:unmatched", "reason": "no expected obligation"}
            continue
        if rec["event"] == "rejected":
            input_class[rid] = {"class": "transport:failure_evidence", "reason": "positive rejection of one attempt"}
            ob["candidates"].append(("EXPLICIT_FAILURE", a))
            ob["diagnostics"].append(_diag("TRANSPORT_REJECTED_ATTEMPT", record=rid, attempt_id=a))
        elif te is not None and not perrors and a in ob["_attempts"] \
                and rec.get("content_digest") == ob["_attempts"][a]["content_digest"]:
            input_class[rid] = {"class": "transport:endpoint_equivalent", "reason": "profile defines equivalence"}
            ob["candidates"].append(("CONFIRMED", a))
            ob["diagnostics"].append(_diag("TRANSPORT_ACK_ENDPOINT_EQUIVALENT", record=rid))
        else:
            input_class[rid] = {"class": "transport:not_receipt", "reason": "transport acceptance is not receipt"}
            ob["diagnostics"].append(_diag("TRANSPORT_ACCEPTED_NOT_RECEIPT", record=rid))

    # negative observations: positive records of bounded conditions (S5.8-1); absence is not one
    for rec in by_kind.get("negative_observation", []):
        rid = rec["record_id"]
        ob = obl_index.get((rec["instruction_id"], rec["target_id"]))
        if ob is None:
            input_class[rid] = {"class": "negative:unmatched", "reason": "no expected obligation"}
            continue
        input_class[rid] = {"class": "negative:attached", "reason": rec["condition"]}
        a = rec.get("attempt_id", "-")
        d = _diag("NEGATIVE_" + rec["condition"].upper(), record=rid, observed=rec["observed"],
                  boundary=rec["boundary"], as_of=rec["cutoff"], attempt_id=rec.get("attempt_id"))
        ob["diagnostics"].append(d)
        if rec["condition"] in ("transport_rejected", "verification_failed"):
            ob["candidates"].append(("EXPLICIT_FAILURE", a))
        # READING: deadline_elapsed and counterpart_missing stay UNCONFIRMED (S5.8, lines 776-778;
        # Section 9.1 lines 1484-1486), with the record kept as a diagnostic.

    # ---- Step 7: exactly one disposition per obligation, deterministic reduction (S5.10-6/7)
    for ob in obligations:
        cands = ob["candidates"]
        plain = set()
        by_attempt = {}
        for c in cands:
            if isinstance(c, tuple):
                by_attempt.setdefault(c[1], set()).add(c[0])
            else:
                plain.add(c)
        conflict = False
        for a, kinds in by_attempt.items():
            if "CONFIRMED" in kinds and kinds & set(POSITIVE_FAILURES):
                conflict = True
                ob["diagnostics"].append(_diag("INCOMPATIBLE_ASSERTIONS_SAME_ATTEMPT", attempt_id=a,
                                               assertions=sorted(kinds)))
        derived = set(plain)
        any_confirmed = any("CONFIRMED" in k for k in by_attempt.values())
        for a, kinds in by_attempt.items():
            derived |= kinds
        if conflict:
            derived.add("CONFLICT")
        if any_confirmed:
            # READING: a confirmed attempt is not undone by a failure of a different attempt of
            # the same obligation; the failure stays visible as a diagnostic (Section 9.1).
            other_fail = [a for a, k in by_attempt.items() if k & set(POSITIVE_FAILURES) and "CONFIRMED" not in k]
            if other_fail and not conflict:
                derived -= set(POSITIVE_FAILURES) - {c for c in plain}
                ob["diagnostics"].append(_diag("OTHER_ATTEMPT_FAILED", attempts=sorted(other_fail)))
        if not derived:
            derived = {"UNCONFIRMED"}                                                     # S5.10-3
        chosen = next(d for d in precedence if d in derived)
        ob["disposition"] = chosen
        ob["reduction"] = {"rule": "profile precedence", "precedence": list(precedence),
                           "applicable": sorted(derived), "selected": chosen}
        ob["candidates"] = sorted({c if isinstance(c, str) else c[0] for c in cands})
        if chosen in ("EXPLICIT_FAILURE", "SUBSTITUTION"):
            ob["failure_scope"] = dict(ob["scope"])                                      # S6.1-2

    # receiver record accounting (S5.11-3, S6.4-5)
    per_receiver = {}
    for idx, rec in enumerate(records):
        if not (isinstance(rec, dict) and rec.get("kind") == "receiver_observation"):
            continue
        rid = keys[idx]
        ic = input_class.get(rid)
        if ic and ic["class"] == "excluded":
            continue
        if rid in rclass and not (ic and ic["class"].endswith(":invalid")):
            cls, d = rclass[rid]
            per_receiver[rid] = {"class": cls, "detail": d}
        else:
            per_receiver[rid] = {"class": "invalid_receiver", "detail": _diag("MALFORMED", reason=(ic or {}).get("reason"))}
    counts_r = {c: sum(1 for v in per_receiver.values() if v["class"] == c) for c in RECEIVER_CLASSES}
    matched_confirming = sum(1 for v in per_receiver.values()
                             if v["class"] == "matched" and v["detail"]["code"] == "CONFIRMING")
    for rid, v in per_receiver.items():
        input_class[rid] = {"class": "receiver:" + v["class"], "reason": v["detail"]["code"]}

    # enforcement and control-effect dimensions (S5.6, S5.7, Section 4.4/4.5)
    emap = profile.get("enforcement_mapping") or {}
    for ob in obligations:
        ob["enforcement"] = {"outcome": "UNKNOWN", "records": [], "diagnostics": []}
        ob["control_effect"] = {"summary": "UNKNOWN", "observations": []}
    for rec in by_kind.get("enforcement_outcome", []):
        rid = rec["record_id"]
        ob = obl_index.get((rec["instruction_id"], rec["target_id"]))
        obs = trust_obs.get(rec["observer"]) or {}
        if ob is None or rec["target_id"] not in (obs.get("binds_targets") or []):
            input_class[rid] = {"class": "enforcement:not_applicable",
                                "reason": "no obligation, or observer not bound to the target"}
            continue
        input_class[rid] = {"class": "enforcement:attached", "reason": "enforcement assertion"}
        ob["enforcement"]["records"].append(rid)
        mapped = emap.get(rec["outcome"])
        if mapped is None:
            ob["enforcement"]["diagnostics"].append(_diag("NATIVE_STATE_UNMAPPED", record=rid, state=rec["outcome"]))
            mapped = "UNKNOWN"
        if mapped == "NO_EFFECT" and not (rec.get("predicate") and isinstance(rec.get("window"), dict)):
            ob["enforcement"]["diagnostics"].append(_diag("NO_EFFECT_WITHOUT_PREDICATE_AND_WINDOW", record=rid))
            mapped = "UNKNOWN"
        ob["enforcement"].setdefault("_values", []).append(mapped)
    for ob in obligations:
        vals = sorted(set(ob["enforcement"].pop("_values", [])))
        if not vals:
            ob["enforcement"]["diagnostics"].append(_diag("NO_ENFORCEMENT_EVIDENCE"))     # S5.6-3
        elif len(vals) == 1:
            ob["enforcement"]["outcome"] = vals[0]
        else:
            ob["enforcement"]["diagnostics"].append(_diag("ENFORCEMENT_ASSERTIONS_DIFFER", values=vals))
        if ob["enforcement"]["outcome"] != "UNKNOWN" and ob["disposition"] != "CONFIRMED":
            ob["enforcement"]["diagnostics"].append(_diag("ENFORCEMENT_WITHOUT_CONFIRMED_DELIVERY"))
        for d in ob["diagnostics"]:
            if d["code"] == "NEGATIVE_OUTCOME_UNDETERMINED":
                ob["enforcement"]["diagnostics"].append(d)

    issuer_observers = {}
    for iid, recs in issuer_by_instr.items():
        issuer_observers[iid] = sorted({r["observer"] for r in recs})
    target_observers = {}
    for rec in valid:
        if rec["kind"] in ("receiver_observation", "enforcement_outcome") and isinstance(rec.get("target_id"), str):
            target_observers.setdefault(rec["target_id"], set()).add(rec["observer"])
    for rec in by_kind.get("effect_observation", []):
        rid = rec["record_id"]
        ob = obl_index.get((rec["instruction_id"], rec["target_id"]))
        if ob is None:
            input_class[rid] = {"class": "effect:unmatched", "reason": "no expected obligation"}
            continue
        input_class[rid] = {"class": "effect:attached", "reason": "scoped effect observation"}
        indep, why = _independence(rec, trust_obs, issuer_observers.get(rec["instruction_id"], []),
                                   sorted(target_observers.get(rec["target_id"], set())))
        ob["control_effect"]["observations"].append({
            "record": rid, "predicate": rec["predicate"], "method": rec["method"],
            "window": rec["window"], "result": rec["result"], "operation_id": rec.get("operation_id"),
            "observer": rec["observer"], "observer_relationship": rec["observer_relationship"],
            "independence_label_in_record": rec.get("independence_claimed"),
            "independent_under_trust_model": indep, "independence_basis": why,
            "scope": {"target_id": rec["target_id"], "operation_id": rec.get("operation_id")}})
    for ob in obligations:
        res = sorted({o["result"] for o in ob["control_effect"]["observations"]})
        ob["control_effect"]["summary"] = res[0] if len(res) == 1 else ("UNKNOWN" if not res else "MIXED")

    # ---- Step 9 extras: operations and control activation (Section 9.4)
    operations = _operations(by_kind, profile, input_class)
    paths = _paths(by_kind, profile, input_class)

    # issuer record classes
    for iid, recs in issuer_by_instr.items():
        for r in recs:
            if iid not in frozen_population:
                input_class[r["record_id"]] = {"class": "issuer:outside_population",
                                               "reason": "not in the frozen issuer population"}
            elif any(r["record_id"] in e.get("issuer_duplicates", []) for e in instructions):
                input_class[r["record_id"]] = {"class": "issuer:duplicate", "reason": "same attempt and digest"}
            else:
                input_class[r["record_id"]] = {"class": "issuer:used", "reason": r["event"]}

    # ---- Step 10: parent results (Section 6.2)
    for entry in instructions:
        obs = [o for o in obligations if o["instruction_id"] == entry["instruction_id"]]
        per_target = {o["target_id"]: o["disposition"] for o in obs}
        if entry["class"] == "zero_obligations":
            parent = None   # READING: 6.2 defines parent confirmation only for one or more targets
        elif entry["class"] == "not_closed":
            parent = False
        else:
            parent = bool(obs) and all(d == "CONFIRMED" for d in per_target.values())
        entry["parent"] = {"fully_confirmed_within_target_set": parent, "per_target": per_target}
        if entry["class"] == "zero_obligations":
            entry["contributed_obligations"] = 0                                          # S5.11-5

    # ---- conservation (Section 6.4)
    counts_o = {d: sum(1 for o in obligations if o["disposition"] == d) for d in MIN_DISPOSITIONS}
    n_with = sum(1 for e in instructions if e["class"] == "with_obligations")
    n_zero = sum(1 for e in instructions if e["class"] == "zero_obligations")
    n_open = sum(1 for e in instructions if e["class"] == "not_closed")
    total_inputs = len(records)
    accounted_inputs = len(input_class)
    conservation = {
        "obligations": {"O": len(obligations), "counts": counts_o,
                        "holds": len(obligations) == sum(counts_o.values())},
        "instructions": {"I": len(instructions), "with_obligations": n_with,
                         "zero_obligation_instructions": n_zero, "not_closed": n_open,
                         "draft_equation_holds": len(instructions) == n_with + n_zero,
                         "extended_equation_holds": len(instructions) == n_with + n_zero + n_open},
        "receiver_records": {"R": len(per_receiver), "counts": counts_r,
                             "matched_subdivision": {"confirming": matched_confirming,
                                                     "non_confirming": counts_r["matched"] - matched_confirming},
                             "holds": len(per_receiver) == sum(counts_r.values())},
        "inputs": {"presented": total_inputs, "accounted": accounted_inputs,
                   "holds": total_inputs == accounted_inputs},
        "population": {"frozen": sorted(map(str, frozen_population)),
                       "computed_from_issuer_records": sorted(computed_population),
                       "mismatch": population_mismatch},
    }
    exp = frozen.get("expected_counts")
    if isinstance(exp, dict):
        conservation["expected_counts"] = {
            "declared": exp, "matches": exp.get("instructions") == len(instructions)
            and exp.get("obligations") == len(obligations)}

    # ---- Step 11: structural aggregate result (Section 6.5)
    blockers = []
    if perrors:
        blockers.append(_diag("PROFILE_INVALID", errors=len(perrors)))
    if run_errors:
        blockers.append(_diag("RUN_DECLARATION_INCOMPLETE", errors=len(run_errors)))
    if frozen.get("population_closed") is not True:
        blockers.append(_diag("POPULATION_NOT_DECLARED_CLOSED"))
    if n_open:
        blockers.append(_diag("TARGET_SET_NOT_CLOSED",
                              instructions=[e["instruction_id"] for e in instructions if e["class"] == "not_closed"]))
    if population_mismatch:
        blockers.append(_diag("ISSUER_POPULATION_MISMATCH", ids=population_mismatch))
    for name in ("obligations", "receiver_records", "inputs"):
        if not conservation[name]["holds"]:
            blockers.append(_diag("CONSERVATION_FAILED", equation=name))
    if not conservation["instructions"]["draft_equation_holds"]:
        blockers.append(_diag("CONSERVATION_FAILED", equation="instructions"))
    if "expected_counts" in conservation and not conservation["expected_counts"]["matches"]:
        blockers.append(_diag("EXPECTED_COUNTS_DIFFER"))
    for e in instructions:
        if e["class"] == "zero_obligations" and not e.get("empty_set_permitted"):
            blockers.append(_diag("EMPTY_TARGET_SET_NOT_PERMITTED", instruction_id=e["instruction_id"]))  # S5.11-9
    not_ok = [o for o in obligations if o["disposition"] != "CONFIRMED"]
    if not_ok:
        blockers.append(_diag("OBLIGATIONS_NOT_CONFIRMED", count=len(not_ok)))
    positive = [{"instruction_id": o["instruction_id"], "target_id": o["target_id"],
                 "disposition": o["disposition"], "scope": o["scope"]}
                for o in obligations if o["disposition"] in POSITIVE_FAILURES]
    structural_invalid = bool(perrors) or bool(run_errors)
    if positive and not structural_invalid:
        result = "FAIL"
    elif not blockers:
        result = "PASS"
    else:
        result = "INCONCLUSIVE"

    for o in obligations:
        o.pop("_attempts", None)

    report = {
        "report_version": REPORT_VERSION,
        "implementation": {"name": "acde01", "version": IMPLEMENTATION_VERSION,
                           "draft": DRAFT, "draft_sha256": DRAFT_SHA256},
        "profile": {"profile_id": profile.get("profile_id"), "profile_revision": profile.get("profile_revision"),
                    "valid": not perrors, "errors": perrors},
        "run": {"cutoff": cutoff_s, "window": window, "issuer_boundary": issuer_boundary,
                "issuer_inclusion_rule": frozen.get("issuer_inclusion_rule"),
                "input_digest": canon.document_digest(run) if _jsonable(run) else None,
                "previous_report_digest": run.get("previous_report_digest"),
                "errors": run_errors},
        "target_sets": _target_sets_view(frozen),
        "exclusions": exclusions,
        "instructions": instructions,
        "obligations": obligations,
        "record_accounting": {"receiver_records": per_receiver,
                              "inputs": {k: input_class[k] for k in sorted(input_class)},
                              "duplicate_selection_rule": profile.get("duplicate_selection_rule")},
        "conservation": conservation,
        "operations": operations,
        "intermediary_paths": paths,
    }
    structural = {"structural_result": result, "positive_failing_conditions": positive,
                  "pass_blockers": blockers,
                  "class_counts": {"obligations": counts_o, "receiver_records": counts_r,
                                   "instructions": {"with_obligations": n_with, "zero": n_zero,
                                                    "not_closed": n_open}}}
    report["claims"] = _claims(report, structural, claims_req, profile, frozen, trust_obs, by_kind,
                               issuer_by_instr)
    default = next(c for c in report["claims"] if c["claim_id"] == "population")
    structural["claim_scope"] = default["claim_scope"]
    structural["claim_support"] = default["claim_support"]
    structural["conditions"] = default["conditions"]
    report["structural"] = structural
    report["non_claims"] = _non_claims(report)
    report["report_digest"] = canon.document_digest({k: v for k, v in report.items() if k != "report_digest"}) \
        if _jsonable(report) else None
    return report


def _jsonable(v):
    try:
        canon.canonical_bytes(v)
        return True
    except canon.CanonError:
        return False


def _target_sets_view(frozen):
    out = {}
    for sid, ts in sorted((frozen.get("target_sets") or {}).items()):
        if not isinstance(ts, dict):
            continue
        out[sid] = {"members": ts.get("members"), "closure_basis": ts.get("closure_basis"),
                    "coverage": ts.get("coverage"), "coverage_basis": ts.get("coverage_basis"),
                    "set_digest": canon.document_digest(ts.get("members")) if _jsonable(ts.get("members")) else None}
    return out


def _independence(rec, trust_obs, issuer_obs, target_obs):
    """Independence comes from the trust configuration, never from a label or a key (S4.5-1/2, S5.3-3)."""
    cfg = trust_obs.get(rec["observer"])
    if cfg is None:
        return False, "observer not in the trust configuration"
    if cfg.get("authority_verified") is not True:
        return False, "observer authority not verified"
    others = set(issuer_obs) | set(target_obs)
    if rec["observer"] in others:
        return False, "the observer is itself an issuer-side or enforcement-side observer"
    indep_of = set(cfg.get("independent_of") or [])
    missing = sorted(others - indep_of)
    if missing:
        return False, f"independence from {missing} not established in the trust configuration"
    writers = set(cfg.get("writable_by") or [])
    if writers & others:
        return False, f"record writable by {sorted(writers & others)}"
    if not issuer_obs or not target_obs:
        return False, "issuer or enforcement-side observer unknown; independence of both not established"
    return True, "independent of issuer and enforcement-side observers under the trust configuration"


def _operations(by_kind, profile, input_class):
    acts = by_kind.get("control_activation", [])
    for a in acts:
        input_class[a["record_id"]] = {"class": "activation:attached", "reason": "control activation"}
    ops = {}
    for e in by_kind.get("operation_event", []):
        ops.setdefault(e["operation_id"], []).append(e)
        input_class[e["record_id"]] = {"class": "operation:attached", "reason": e["op_boundary"] + ":" + e["event"]}
    out = []
    for oid in sorted(ops):
        events = ops[oid]
        tid = events[0]["target_id"]
        act = next((a for a in acts if a["target_id"] == tid), None)
        facts = []
        status = "no_control_activation"
        crossed_before = False
        blocked = None
        for e in events:
            rel = "INDETERMINATE"
            if act is not None:
                if _comparable(e, act, profile):
                    rel = "before_activation" if canon.parse_time(e["time"]) < canon.parse_time(act["time"]) \
                        else "after_activation"
            facts.append({"record": e["record_id"], "boundary": e["op_boundary"], "event": e["event"],
                          "relation_to_activation": rel})                                # S9.4-4
            if e["op_boundary"] == "provider_entry" and e["event"] == "crossed" and rel == "before_activation":
                crossed_before = True
            if e["event"] == "refused" and rel == "after_activation":
                blocked = e["op_boundary"]
        if act is not None:
            if crossed_before:
                # S9.4-2: never relabel; S9.4-5: outcome stays unresolved without its own evidence
                status = "crossed_before_activation_outcome_unresolved"
            elif blocked:
                status = f"blocked_at_{blocked}_within_target_{tid}"
            elif any(f["relation_to_activation"] == "INDETERMINATE" for f in facts):
                status = "ordering_indeterminate"                                         # S5.9-3
            else:
                status = "no_blocking_evidence"
        out.append({"operation_id": oid, "target_id": tid, "facts": facts, "status": status,
                    "activation_record": act["record_id"] if act else None})
    return out


def _paths(by_kind, profile, input_class):
    maps = profile.get("intermediary_mappings") or {}
    hops = {}
    for h in by_kind.get("intermediary_hop", []):
        hops.setdefault(h["path_id"], []).append(h)
        input_class[h["record_id"]] = {"class": "hop:attached", "reason": "intermediary transformation"}
    out = []
    for pid in sorted(hops):
        chain = sorted(hops[pid], key=lambda h: h["hop_index"] if isinstance(h["hop_index"], int) else 0)
        verdicts = []
        state = chain[0]["source_state"]
        source = state
        lossless = True
        for h in chain:
            spec = maps.get(h["mapping_id"])
            if h["source_state"] != state:
                verdicts.append({"hop": h["record_id"], "result": "chain_break"})
                lossless = False
            if spec is None:
                verdicts.append({"hop": h["record_id"], "result": "mapping_unavailable"})
                lossless = False
            else:
                m = spec["map"]
                gov = spec["governance_states"]
                target = m.get(h["source_state"])
                if target is None:
                    verdicts.append({"hop": h["record_id"], "result": "state_unmapped"})
                    lossless = False
                elif sum(1 for s in gov if m.get(s) == target) > 1:
                    verdicts.append({"hop": h["record_id"], "result": "states_collapsed",
                                     "collapsed": sorted(s for s in gov if m.get(s) == target)})
                    lossless = False                                                      # S5.16-3
                elif h["delivered_state"] != target:
                    verdicts.append({"hop": h["record_id"], "result": "mapping_not_followed"})
                    lossless = False
                else:
                    verdicts.append({"hop": h["record_id"], "result": "lossless"})
            state = h["delivered_state"]
        out.append({"path_id": pid, "source_state": source, "delivered_state": state,
                    "hops": verdicts,
                    "preservation": "PRESERVED" if lossless else "INDETERMINATE",          # S5.16-4
                    "source_state_recoverable": lossless,
                    "instruction_id": chain[0]["instruction_id"], "target_id": chain[0]["target_id"]})
    return out


def _scope_for(report, claim, frozen):
    sc = claim.get("scope") or {}
    instr = sc.get("instructions")
    if instr in (None, "all"):
        instr = [e["instruction_id"] for e in report["instructions"]]
    sets = sorted({e["target_set"] for e in report["instructions"]
                   if e["instruction_id"] in instr and e["target_set"]})
    bounds = sorted({o["scope"]["receiving_boundary"] or "unresolved" for o in report["obligations"]
                     if o["instruction_id"] in instr})
    return {"instructions": sorted(map(str, instr)), "target_sets": sets,
            "boundaries": [frozen.get("issuer_boundary") or "undeclared"] + bounds,
            "cutoff": frozen.get("cutoff"), "window": frozen.get("window"),
            "obligation": sc.get("obligation"), "path_id": sc.get("path_id"),
            "fact": sc.get("fact") or claim.get("kind")}


def _claims(report, structural, claims_req, profile, frozen, trust_obs, by_kind, issuer_by_instr):
    cl = profile.get("claims") or {}
    conditional = set(cl.get("conditional_predicates") or [])
    mandatory = cl.get("mandatory_predicates") or {}
    requested = [{"claim_id": "population", "kind": "structural_reconciliation",
                  "scope": {"instructions": "all", "fact": "the declared population reconciled under the "
                                                          "profile's structural rules"}}]
    requested += [c for c in claims_req if isinstance(c, dict) and c.get("claim_id") != "population"]
    rec_by_id = {r["record_id"]: r for lst in by_kind.values() for r in lst}
    out = []
    for c in requested:
        kind = c.get("kind")
        scope = _scope_for(report, c, frozen)
        obs = [o for o in report["obligations"] if o["instruction_id"] in scope["instructions"]]
        instr = [e for e in report["instructions"] if e["instruction_id"] in scope["instructions"]]
        global_block = [b for b in structural["pass_blockers"] if b["code"] not in ("OBLIGATIONS_NOT_CONFIRMED",
                                                                                    "EMPTY_TARGET_SET_NOT_PERMITTED",
                                                                                    "TARGET_SET_NOT_CLOSED")]
        scoped_pass = (not global_block and all(o["disposition"] == "CONFIRMED" for o in obs)
                       and all(e["class"] != "not_closed" for e in instr)
                       and all(e.get("empty_set_permitted", True) for e in instr if e["class"] == "zero_obligations"))
        scoped_fail = any(o["disposition"] in POSITIVE_FAILURES for o in obs) and not report["profile"]["errors"]
        scoped_result = "PASS" if scoped_pass else ("FAIL" if scoped_fail else "INCONCLUSIVE")
        driving = []
        for o in obs:
            driving += o["matched_records"]
        for e in instr:
            driving += e.get("issuer_records", [])
        unverified = sorted({rec_by_id[r]["observer"] for r in driving if r in rec_by_id
                             and (trust_obs.get(rec_by_id[r]["observer"]) or {}).get("authority_verified") is not True})
        preds = {}
        need = {"structural_reconciliation": ["structural_pass", "observer_authority_verified"],
                "complete_delivery": ["structural_pass", "observer_authority_verified"],
                "complete_mediation": ["structural_pass", "observer_authority_verified", "coverage_verified"],
                "scoped_failure": ["failure_observed", "observer_authority_verified"],
                "independent_effect": ["effect_observed", "observer_independent", "observer_authority_verified"],
                "preserved_disposition": ["lossless_path"]}.get(kind)
        conditions = []
        missing = []
        if need is None:
            support = "NOT_SUPPORTED"
            missing.append({"predicate": "known_claim_kind", "detail": f"claim kind {kind!r} is not defined"})
        else:
            preds["structural_pass"] = (scoped_result == "PASS", f"structural result over the scope: {scoped_result}")
            preds["observer_authority_verified"] = (not unverified,
                                                    "all driving observers authority-verified" if not unverified
                                                    else f"authority not verified for {unverified}")
            cov = sorted({(report["target_sets"].get(s) or {}).get("coverage") or "INDETERMINATE"
                          for s in scope["target_sets"]})
            preds["coverage_verified"] = (bool(cov) and cov == ["VERIFIED"],
                                          f"target-set coverage: {cov or ['no target set']}")
            ob_sel = None
            if c.get("scope", {}).get("obligation"):
                i, t = c["scope"]["obligation"]
                ob_sel = next((o for o in report["obligations"] if o["instruction_id"] == i and o["target_id"] == t), None)
            if kind == "scoped_failure":
                fobs = [ob_sel] if ob_sel else [o for o in obs if o["disposition"] in POSITIVE_FAILURES]
                ok = bool(fobs) and all(o and o["disposition"] in POSITIVE_FAILURES for o in fobs)
                preds["failure_observed"] = (ok, "positive failing condition on the scoped obligation" if ok
                                             else "no positive failing condition in scope")
                if ok:
                    drv = [r for o in fobs for r in o["matched_records"]] + \
                          [d.get("record") for o in fobs for d in o["diagnostics"] if d.get("record")] + \
                          [r for o in fobs for e in instr if e["instruction_id"] == o["instruction_id"]
                           for r in e.get("issuer_records", [])]
                    unv = sorted({rec_by_id[r]["observer"] for r in drv if r in rec_by_id
                                  and (trust_obs.get(rec_by_id[r]["observer"]) or {}).get("authority_verified") is not True})
                    preds["observer_authority_verified"] = (not unv, "failure observers authority-verified" if not unv
                                                            else f"authority not verified for {unv}")
                scope["fact"] = c.get("scope", {}).get("fact") or "the scoped obligation failed"
            if kind == "independent_effect":
                eobs = [x for o in ([ob_sel] if ob_sel else obs) if o for x in o["control_effect"]["observations"]]
                preds["effect_observed"] = (any(x["result"] == "EFFECT_OBSERVED" for x in eobs),
                                            "scoped effect observation present" if eobs else "no effect observation")
                ind = [x for x in eobs if x["independent_under_trust_model"]]
                preds["observer_independent"] = (bool(ind), (eobs[0]["independence_basis"] if eobs and not ind
                                                             else "independent observer" if ind else "no observer"))
                eu = sorted({x["observer"] for x in eobs
                             if (trust_obs.get(x["observer"]) or {}).get("authority_verified") is not True})
                preds["observer_authority_verified"] = (not eu, "effect observer authority verified" if not eu
                                                        else f"authority not verified for {eu}")
            if kind == "preserved_disposition":
                pid = c.get("scope", {}).get("path_id")
                p = next((x for x in report["intermediary_paths"] if x["path_id"] == pid), None)
                preds["lossless_path"] = (bool(p) and p["preservation"] == "PRESERVED",
                                          f"path {pid}: {p['preservation'] if p else 'absent'}")
            support = "FULLY_SUPPORTED"
            for pname in need:
                ok, detail = preds[pname]
                if ok:
                    continue
                if pname in (mandatory.get(kind) or []):
                    support = "NOT_SUPPORTED"
                    missing.append({"predicate": pname, "detail": detail, "class": "mandatory"})
                elif pname in conditional:
                    if support != "NOT_SUPPORTED":
                        support = "CONDITIONALLY_SUPPORTED"
                    conditions.append({"predicate": pname, "detail": detail})
                else:
                    support = "NOT_SUPPORTED"                                            # S6.6-9
                    missing.append({"predicate": pname, "detail": detail, "class": "not declared conditional"})
        if report["profile"]["errors"]:
            support = "NOT_SUPPORTED"
            missing.append({"predicate": "valid_profile", "detail": "profile declaration errors"})
        out.append({"claim_id": c.get("claim_id"), "kind": kind, "claim_scope": scope,
                    "structural_result": scoped_result, "claim_support": support,
                    "conditions": conditions, "missing_predicates": missing,
                    "assertable": support != "NOT_SUPPORTED"})                           # S6.6-7
    return out


def _non_claims(report):
    """What the results cover and what they do not (S5.13-1, S5.13-2)."""
    pop = next(c for c in report["claims"] if c["claim_id"] == "population")
    auth = all(m["predicate"] != "observer_authority_verified" for m in pop["missing_predicates"]) and \
        all(c["predicate"] != "observer_authority_verified" for c in pop["conditions"])
    cov = sorted({(v or {}).get("coverage") or "INDETERMINATE" for v in report["target_sets"].values()})
    any_indep = any(x["independent_under_trust_model"] for o in report["obligations"]
                    for x in o["control_effect"]["observations"])
    return [
        {"property": "integrity", "status": "consumed",
         "basis": "native verification results are consumed, not re-verified by this implementation"},
        {"property": "attribution", "status": "supported" if auth else "not_supported",
         "basis": "observer authority from the frozen trust configuration only"},
        {"property": "delivery", "status": "per_obligation",
         "basis": "each disposition is scoped to one instruction-target obligation"},
        {"property": "enforcement", "status": "assertion_only",
         "basis": "enforcement outcomes are enforcement-point assertions, not independent observation"},
        {"property": "observed_control_effect", "status": "scoped",
         "basis": "each effect observation covers its own target, predicate and window only"},
        {"property": "ordering", "status": "limited",
         "basis": "precedence only between records with comparable clocks under the profile"},
        {"property": "population_closure", "status": "declared",
         "basis": "closure is the frozen declaration, checked against issuer records and conservation"},
        {"property": "complete_mediation", "status": "verified" if cov == ["VERIFIED"] else "not_supported",
         "basis": f"target-set coverage conditions {cov}"},
        {"property": "independent_corroboration", "status": "supported_where_listed" if any_indep else "not_supported",
         "basis": "independence only from the trust configuration"},
        {"property": "truth_of_assertions", "status": "not_claimed",
         "basis": "records are assertions; signatures and digests establish correspondence, not truth"},
    ]


def reconcile_versions(run, cutoffs):
    """Reconcile the same input at several cutoffs; each report names its cutoff and the digest of
    the report before it, so an earlier result stays available beside a later one (Section 9.1)."""
    reports = []
    prev = None
    for c in cutoffs:
        r = copy.deepcopy(run)
        r["frozen"]["cutoff"] = c
        if prev is not None:
            r["previous_report_digest"] = prev
        rep = reconcile(r)
        reports.append(rep)
        prev = rep["report_digest"]
    return reports


def render_summary(report) -> str:
    """Text rendering. Every line that shows a structural result shows the claim scope and the
    claim-support qualification beside it (S6.6-3: the rule applies to every representation)."""
    lines = []
    s = report["structural"]
    sc = s["claim_scope"]
    lines.append(f"structural result: {s['structural_result']} | claim scope: {sc['fact']} over "
                 f"{len(sc['instructions'])} instruction(s), cutoff {sc['cutoff']} | claim support: "
                 f"{s['claim_support']}" + (f" (conditions: {', '.join(c['predicate'] for c in s['conditions'])})"
                                            if s["conditions"] else ""))
    for c in report["claims"]:
        if c["claim_id"] == "population":
            continue
        lines.append(f"claim {c['claim_id']}: structural result: {c['structural_result']} | claim scope: "
                     f"{c['claim_scope']['fact']} | claim support: {c['claim_support']}")
    co = report["conservation"]["obligations"]["counts"]
    lines.append("obligation counts: " + ", ".join(f"{k}={v}" for k, v in co.items()))
    return "\n".join(lines) + "\n"
