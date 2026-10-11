"""Builders for the derived vectors. Every vector is written from the draft text alone.

A vector has: id, type (profile | run | versions | report_check | render_check), the requirement
ids it tests (requirements.json), the conformance case of the appendix "Minimum Conformance
Cases" it exercises (if any), polarity (positive | negative), a description, the input, and the
expected result as selector -> value pairs (see tests/test_vectors.py for the selector syntax).
"""
from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from acde01 import canon  # noqa: E402
from acde01.profile import example_profile, with_changes  # noqa: E402

CONTENT = {"verb": "stop", "task": "task-9", "scope": "all-egress"}
OTHER_CONTENT = {"verb": "stop", "task": "task-9", "scope": "egress-a-only"}
D = canon.instruction_digest(CONTENT)
D2 = canon.instruction_digest(OTHER_CONTENT)
CUTOFF = "2026-09-10T12:00:00Z"


def frozen():
    return {
        "cutoff": CUTOFF,
        "window": {"start": "2026-09-10T09:00:00Z", "end": "2026-09-10T11:00:00Z"},
        "issuer_boundary": "issuer-egress",
        "issuer_inclusion_rule": "every instruction with an issuer record (emission at issuer-egress, "
                                 "or a recorded emission failure) whose time lies in the window",
        "population_closed": True,
        "instructions": [{"instruction_id": "ctrl-1", "target_resolution": {"set_id": "set-1"}}],
        "target_sets": {"set-1": {"members": ["EP-A", "EP-B"],
                                  "closure_basis": "deployment configuration snapshot frozen before the cutoff",
                                  "coverage": "VERIFIED",
                                  "coverage_basis": "relying-party inventory of egress paths, accepted under the trust model"}},
        "target_directory": {"targets": {"EP-A": {"boundary": "ep-a-ingress", "receiver_ids": ["ep-a"]},
                                         "EP-B": {"boundary": "ep-b-ingress", "receiver_ids": ["ep-b"]},
                                         "EP-C": {"boundary": "ep-c-ingress", "receiver_ids": ["ep-c"]}},
                             "refs": {}},
        "trust": {"observers": {
            "issuer-obs": {"authority_verified": True, "role": "issuer"},
            "ep-a-obs": {"authority_verified": True, "binds_targets": ["EP-A"]},
            "ep-b-obs": {"authority_verified": True, "binds_targets": ["EP-B"]},
            "ep-c-obs": {"authority_verified": True, "binds_targets": ["EP-C"]},
            "witness": {"authority_verified": True,
                        "independent_of": ["issuer-obs", "ep-a-obs", "ep-b-obs", "ep-c-obs"],
                        "writable_by": []},
        }},
    }


def issuer(rid="iss-1", iid="ctrl-1", attempt="a1", digest=D, time="2026-09-10T10:00:00Z", **kw):
    r = {"record_id": rid, "kind": "issuer_emission", "observer": "issuer-obs", "boundary_side": "issuer",
         "boundary": "issuer-egress", "event": "emitted", "instruction_id": iid, "attempt_id": attempt,
         "content_digest": digest, "target_set_ref": "set-1", "time": time, "clock": "tsa:example-tsa",
         "native": "verified"}
    r.update(kw)
    return r


def receiver(rid, target, iid="ctrl-1", attempt="a1", digest=D, time="2026-09-10T10:00:05Z", **kw):
    t = target.lower().replace("ep-", "ep-")
    r = {"record_id": rid, "kind": "receiver_observation", "observer": f"{t}-obs", "boundary_side": "receiver",
         "boundary": f"{t}-ingress", "event": "read_and_matched", "instruction_id": iid, "attempt_id": attempt,
         "content_digest": digest, "receiver_id": t, "target_id": target, "time": time,
         "clock": f"host:{t}", "native": "verified"}
    r.update(kw)
    return r


def transport(rid, target, event, attempt="a1", time="2026-09-10T10:00:03Z", **kw):
    r = {"record_id": rid, "kind": "transport_ack", "observer": "broker", "boundary_side": "transport",
         "boundary": "broker-relay", "event": event, "instruction_id": "ctrl-1", "attempt_id": attempt,
         "target_id": target, "time": time, "clock": "host:broker", "native": "verified"}
    r.update(kw)
    return r


def base_run(records=None, claims=None, profile=None, fz=None):
    return {"profile": profile or example_profile(), "frozen": fz or frozen(),
            "records": records if records is not None else
            [issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")],
            "claims": claims or []}


def V(vid, vtype, reqs, polarity, desc, inp, expect, case=None):
    """``reqs`` entries may carry a "+" or "-" prefix that overrides the vector polarity for that
    one requirement (a vector can show the conforming path of one requirement while it presents
    the defect another requirement must catch)."""
    cases = [] if case is None else (list(case) if isinstance(case, (list, tuple)) else [case])
    return {"id": vid, "type": vtype, "requirements": reqs, "conformance_cases": cases,
            "polarity": polarity, "description": desc, "input": inp, "expect": expect}


def profile_vectors():
    p = example_profile()
    out = [V("P-00", "profile", ["S5.1-2", "S5.1-4", "S5.2-2", "S5.3-2", "S5.3-4", "S5.9-2", "S5.11-8",
                                 "S5.12-1", "S5.6-2", "S5.10-6", "S6.3-1", "S6.6-8", "S8.1-1", "S8.3-1",
                                 "S9.2-1", "S5.8-2", "S5.15-3", "S6.6-5", "S6.1-1", "S9.4-1", "S4.4-1",
                                 "S5.1-3", "S5.16-2", "S5.10-5", "S6.4-8"],
             "positive", "the example profile makes every declaration the draft requires", p, {"errors": []})]
    neg = [
        ("P-01", ["S5.1-2"], "identifier uniqueness scope and reuse rule missing", dict(identifier=None)),
        ("P-02", ["S5.1-3"], "task reference replaces the instruction identifier without identical semantics",
         dict(identifier={**p["identifier"], "correlate_by": "task_id"})),
        ("P-03", ["S5.1-4"], "distinct attempts without an attempt rule", dict(attempts={"distinguished": True})),
        ("P-04", ["S5.2-2"], "digest algorithm outside the profile's identified set", dict(
            content_binding={**p["content_binding"], "digest_alg": "md5"})),
        ("P-05", ["S5.2-2"], "domain-separation rule not identified", dict(
            content_binding={k: v for k, v in p["content_binding"].items() if k != "domain_separation"})),
        ("P-06", ["S5.3-2"], "observer verification not stated", dict(observer_verification=None)),
        ("P-07", ["S5.3-4"], "structural processing without trust not declared", dict(structural_without_trust=None)),
        ("P-08", ["S8.1-1"], "native verification neither performed nor consumed", dict(native_verification="skipped")),
        ("P-09", ["S5.9-2"], "precedence reported without an ordering mechanism", dict(time={"trusted_bases": []})),
        ("P-10", ["S5.11-8"], "empty target-set semantics not defined", dict(empty_target_set_valid=None)),
        ("P-11", ["S5.12-1"], "behavior for stale references not defined", dict(
            resolution_failure={"unresolved": "INDETERMINATE", "ambiguous": "INDETERMINATE", "inconsistent": "INVALID"})),
        ("P-12", ["S4.3-1"], "transport acknowledgement treated as receipt without the four definitions", dict(
            transport_equivalence={"endpoint_binding": "broker id"})),
        ("P-13", ["S9.2-1"], "unknown acknowledgement point", dict(ack_point={"point": "whenever"})),
        ("P-14", ["S9.2-2"], "one acknowledgement value for two points without combined semantics", dict(
            ack_point={"point": ["parsing", "durable_persistence"]})),
        ("P-15", ["S5.6-2"], "native enforcement states cannot express REFUSED", dict(
            enforcement_mapping={"DONE": "APPLIED", "NOOP": "NO_EFFECT"})),
        ("P-16", ["S5.10-5"], "extra disposition weakens UNCONFIRMED into success", dict(
            extra_dispositions={"ACK_PENDING_OK": {"maps_to": "CONFIRMED", "refines": "UNCONFIRMED"}})),
        ("P-17", ["S5.10-6"], "reduction precedence is not a total order over the minimum set", dict(
            reduction_rule={"precedence": ["INVALID", "CONFIRMED"]})),
        ("P-18", ["S6.3-1"], "duplicate selection rule not reviewable", dict(duplicate_selection_rule="any")),
        ("P-19", ["S6.6-8"], "conditional predicates not stated", dict(claims=None)),
        ("P-20", ["S6.6-9"], "a predicate both mandatory and conditional", dict(claims={
            "conditional_predicates": ["observer_authority_verified", "coverage_verified", "structural_pass"],
            "mandatory_predicates": p["claims"]["mandatory_predicates"]})),
        ("P-21", ["S5.16-2"], "intermediary mapping leaves DEFER unmapped without saying so", dict(
            intermediary_mappings={"gw": {"governance_states": ["DENY", "DEFER"], "map": {"DENY": "REJECTED"}}})),
        ("P-22", ["S8.3-1"], "telemetry used without stating binding kinds", dict(uses_telemetry=True)),
        ("P-23", ["S6.4-8"], "exclusion rule decided on receiver evidence", dict(
            exclusion_rules=[{"rule_id": "x", "applies_to": "receiver_record", "attribute": "late"}])),
        ("P-24", ["S5.8-2"], "unknown negative condition", dict(negative_conditions=["deadline_elapsed", "vibes"])),
        ("P-25", ["S9.4-1"], "freeze semantics without an effective boundary", dict(control_activation=None)),
    ]
    for vid, reqs, desc, ch in neg:
        out.append(V(vid, "profile", list(reqs), "negative", desc, with_changes(p, **ch), {"errors_include": list(reqs)}))
    pos = [
        ("P-30", ["S5.1-3"], "task reference with declared identical uniqueness and lifecycle", dict(
            identifier={**p["identifier"], "correlate_by": "task_id", "identical_uniqueness_and_lifecycle": True})),
        ("P-31", ["S4.3-1"], "transport equivalence with all four definitions", dict(transport_equivalence={
            "endpoint_binding": "broker delivers only into the enforcement point's verified inbox",
            "delivery_semantics": "exactly-once into the inbox", "persistence_point": "inbox fsync",
            "failure_behavior": "broker reports rejection per attempt"})),
        ("P-32", ["S9.2-2"], "combined acknowledgement point with combined semantics and residual window", dict(
            ack_point={"point": ["verification", "durable_persistence"],
                       "combined_semantics": "ack after verify and fsync", "residual_failure_window": "none after fsync"})),
        ("P-33", ["S5.10-5"], "lossless extra disposition", dict(
            extra_dispositions={"UNCONFIRMED_DEADLINE": {"maps_to": "UNCONFIRMED", "refines": "UNCONFIRMED"}})),
        ("P-34", ["S5.16-2"], "incomplete mapping declared as incomplete", dict(
            intermediary_mappings={"gw": {"governance_states": ["DENY", "DEFER"], "map": {"DENY": "REJECTED"},
                                          "declared_incomplete": True}})),
        ("P-35", ["S8.3-1"], "telemetry with binding kinds stated", dict(
            uses_telemetry=True, telemetry_bindings={"instruction_id": "native", "content_digest": "absent"})),
        ("P-36", ["S5.6-2"], "native states with a lossless mapping", dict(
            enforcement_mapping={"BLOCKED": "APPLIED", "DECLINED": "REFUSED", "NOOP": "NO_EFFECT", "?": "UNKNOWN"})),
        ("P-37", ["S6.4-8"], "exclusion rule on an issuer attribute", dict(
            exclusion_rules=[{"rule_id": "drills", "applies_to": "issuer_attribute", "attribute": "class",
                              "equals": "drill"}])),
    ]
    for vid, reqs, desc, ch in pos:
        out.append(V(vid, "profile", reqs, "positive", desc, with_changes(p, **ch), {"errors": []}))
    return out


def run_vectors():
    out = []
    add = out.append
    add(V("R-01", "run", ["S5.5-1", "S5.10-1", "S5.11-2", "S6.2-1", "S6.5-2", "S5.2-1", "S6.6-1", "S6.6-2",
                          "S5.13-1", "S5.13-3", "S5.4-1", "S5.1-1", "S6.4-1", "S6.4-5"], "positive",
          "matching issuer and receiver records for both targets", base_run(),
          {"obl:ctrl-1/EP-A.disposition": "CONFIRMED", "obl:ctrl-1/EP-B.disposition": "CONFIRMED",
           "instr:ctrl-1.parent.fully_confirmed_within_target_set": True, "instr:ctrl-1.dispatched": True,
           "structural.structural_result": "PASS", "claim:population.claim_support": "FULLY_SUPPORTED",
           "conservation.obligations.holds": True, "conservation.receiver_records.holds": True,
           "check": []}, case=1))
    add(V("R-02", "run", ["S5.10-3", "S6.2-2", "S6.5-4", "S5.14-1", "S10.4-1", "S5.5-1"], "negative",
          "one instruction, two required targets, EP-A confirmed and EP-B without receiver record",
          base_run([issuer(), receiver("rcv-a", "EP-A")], claims=[
              {"claim_id": "cd", "kind": "complete_delivery", "scope": {"instructions": ["ctrl-1"],
                                                                         "fact": "complete delivery to set-1"}}]),
          {"obl:ctrl-1/EP-A.disposition": "CONFIRMED", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED",
           "instr:ctrl-1.parent.fully_confirmed_within_target_set": False,
           "structural.structural_result": "INCONCLUSIVE", "claim:cd.claim_support": "NOT_SUPPORTED",
           "claim:cd.assertable": False, "check": []}, case=17))
    add(V("R-02b", "run", ["S5.10-3", "S6.5-3"], "negative", "expected obligation with issuer evidence only",
          base_run([issuer()]),
          {"obl:ctrl-1/EP-A.disposition": "UNCONFIRMED", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED",
           "structural.structural_result": "INCONCLUSIVE", "check": []}, case=2))
    add(V("R-03", "run", ["S5.2-1", "S6.5-3"], "negative", "same obligation identity, receiver digest differs",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", digest=D2)]),
          {"obl:ctrl-1/EP-B.disposition": "SUBSTITUTION", "structural.structural_result": "FAIL",
           "receiver:rcv-b.class": "matched", "check": []}, case=3))
    add(V("R-04", "run", ["S5.11-3", "S6.4-5"], "negative", "receiver record with no expected obligation",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"),
                    receiver("rcv-x", "EP-A", iid="ctrl-9")]),
          {"receiver:rcv-x.class": "orphan", "conservation.receiver_records.counts.orphan": 1,
           "conservation.receiver_records.R": 3, "conservation.receiver_records.holds": True,
           "structural.structural_result": "PASS", "check": []}, case=4))
    add(V("R-05", "run", ["S6.1-2", "S4.5-3"], "negative", "transport rejection bound to attempt a1 and EP-B",
          base_run([issuer(), receiver("rcv-a", "EP-A"), transport("tr-b", "EP-B", "rejected")]),
          {"obl:ctrl-1/EP-B.disposition": "EXPLICIT_FAILURE", "obl:ctrl-1/EP-A.disposition": "CONFIRMED",
           "obl:ctrl-1/EP-B.failure_scope.target_id": "EP-B", "structural.structural_result": "FAIL",
           "check": []}, case=5))
    bad_iss = issuer()
    del bad_iss["content_digest"]
    add(V("R-06", "run", ["S5.10-2", "S5.4-2"], "negative", "malformed issuer record (no content binding)",
          base_run([bad_iss, receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")]),
          {"obl:ctrl-1/EP-A.disposition": "INVALID", "obl:ctrl-1/EP-B.disposition": "INVALID",
           "conservation.obligations.counts.INVALID": 2, "input:iss-1.class": "issuer_emission:invalid",
           "structural.structural_result": "INCONCLUSIVE", "check": []}, case=6))
    bad_rcv = receiver("rcv-b", "EP-B")
    del bad_rcv["receiver_id"]
    add(V("R-07", "run", ["S5.5-2", "S5.10-2"], "negative", "malformed receiver record (no receiver identity)",
          base_run([issuer(), receiver("rcv-a", "EP-A"), bad_rcv]),
          {"receiver:rcv-b.class": "invalid_receiver", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED",
           "conservation.receiver_records.counts.invalid_receiver": 1, "check": []}, case=7))
    add(V("R-08", "run", ["S6.3-1", "S5.11-3"], "positive", "duplicate matching receiver records for EP-A",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-a2", "EP-A", time="2026-09-10T10:00:09Z"),
                    receiver("rcv-b", "EP-B")]),
          {"receiver:rcv-a.class": "matched", "receiver:rcv-a2.class": "duplicate",
           "obl:ctrl-1/EP-A.disposition": "CONFIRMED", "record_accounting.duplicate_selection_rule":
           "earliest-time-then-record-id", "structural.structural_result": "PASS", "check": []}, case=8))
    add(V("R-09", "run", ["S6.1-1"], "negative", "receiver match and transport rejection for the same attempt",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"),
                    transport("tr-b", "EP-B", "rejected")]),
          {"obl:ctrl-1/EP-B.disposition": "CONFLICT", "structural.structural_result": "INCONCLUSIVE",
           "check": []}, case=9))
    neg = {"record_id": "neg-b", "kind": "negative_observation", "observer": "reconciler", "boundary_side": "issuer",
           "boundary": "issuer-egress", "event": "observed", "condition": "deadline_elapsed",
           "observed": "acknowledgement deadline of 60 s elapsed with no matching acknowledgement for EP-B",
           "cutoff": "2026-09-10T10:01:00Z", "instruction_id": "ctrl-1", "target_id": "EP-B", "attempt_id": "a1",
           "time": "2026-09-10T10:01:00Z", "clock": "tsa:example-tsa", "native": "verified"}
    add(V("R-10", "run", ["S5.8-1", "S5.10-3", "S6.5-3"], "negative",
          "deadline-elapsed negative observation for EP-B and no acknowledgement",
          base_run([issuer(), receiver("rcv-a", "EP-A"), neg]),
          {"obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "obl:ctrl-1/EP-B.has_diag": "NEGATIVE_DEADLINE_ELAPSED",
           "structural.structural_result": "INCONCLUSIVE", "check": []}, case=10))
    neg_bad = dict(neg)
    del neg_bad["observed"]
    add(V("R-10b", "run", ["S5.8-1"], "negative", "negative observation without what was positively observed",
          base_run([issuer(), receiver("rcv-a", "EP-A"), neg_bad]),
          {"input:neg-b.class": "negative_observation:invalid", "check": []}))
    late_rcv = receiver("rcv-b", "EP-B", time="2026-09-10T12:30:00Z")
    add(V("R-11", "versions", ["S9.1-2", "S6.4-8"], "positive",
          "deadline-elapsed observation, then a late matching receipt after the first cutoff",
          {"run": base_run([issuer(), receiver("rcv-a", "EP-A"), neg, late_rcv]),
           "cutoffs": [CUTOFF, "2026-09-10T13:00:00Z"]},
          {"v0.obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "v0.run.cutoff": CUTOFF,
           "v0.exclusions.observed-after-cutoff.count": 1,
           "v1.obl:ctrl-1/EP-B.disposition": "CONFIRMED", "v1.run.cutoff": "2026-09-10T13:00:00Z",
           "v1.previous_is_v0": True}, case=11))
    add(V("R-11a", "run", ["S9.1-2", "S5.10-3"], "negative",
          "a run at the first cutoff does not take in the late receipt",
          base_run([issuer(), receiver("rcv-a", "EP-A"), neg, late_rcv]),
          {"obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "exclusions.observed-after-cutoff.count": 1,
           "input:rcv-b.class": "excluded", "check": []}, case=11))
    add(V("R-12", "run", ["S5.6-1", "S5.6-3"], "positive", "delivery CONFIRMED, no enforcement evidence",
          base_run(), {"obl:ctrl-1/EP-A.disposition": "CONFIRMED", "obl:ctrl-1/EP-A.enforcement.outcome": "UNKNOWN",
                       "obl:ctrl-1/EP-A.enforcement.has_diag": "NO_ENFORCEMENT_EVIDENCE", "check": []}, case=12))
    enf = {"record_id": "enf-a", "kind": "enforcement_outcome", "observer": "ep-a-obs", "boundary_side": "receiver",
           "boundary": "ep-a-ingress", "event": "outcome", "instruction_id": "ctrl-1", "target_id": "EP-A",
           "outcome": "APPLIED", "time": "2026-09-10T10:00:07Z", "clock": "host:ep-a", "native": "verified"}
    add(V("R-13", "run", ["S5.7-1", "S5.6-1"], "positive", "enforcement APPLIED, control effect not observed",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), enf]),
          {"obl:ctrl-1/EP-A.enforcement.outcome": "APPLIED", "obl:ctrl-1/EP-A.control_effect.summary": "UNKNOWN",
           "obl:ctrl-1/EP-B.enforcement.outcome": "UNKNOWN", "check": []}, case=13))
    fz = frozen()
    fz["trust"]["observers"]["ep-a-obs"]["authority_verified"] = False
    add(V("R-14", "run", ["S5.3-4", "S5.3-5", "S8.1-4", "S5.13-4", "S8.1-2"], "negative",
          "EP-A observer authority only self-declared; structural processing continues",
          base_run([issuer(), receiver("rcv-a", "EP-A", authority_verified=True, observer_role="verified-endpoint"),
                    receiver("rcv-b", "EP-B")], fz=fz),
          {"obl:ctrl-1/EP-A.disposition": "CONFIRMED", "structural.structural_result": "PASS",
           "claim:population.claim_support": "CONDITIONALLY_SUPPORTED",
           "claim:population.condition": "observer_authority_verified", "check": []}, case=[14, 21]))
    prof = with_changes(example_profile(), structural_without_trust=False)
    add(V("R-14b", "run", ["S5.3-4"], "negative",
          "same records under a profile that does not permit processing without a verified binding",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")], fz=copy.deepcopy(fz), profile=prof),
          {"receiver:rcv-a.class": "invalid_receiver", "obl:ctrl-1/EP-A.disposition": "UNCONFIRMED",
           "structural.structural_result": "INCONCLUSIVE", "check": []}))
    add(V("R-14c", "run", ["S5.3-4", "S5.3-5"], "positive", "all observers authority-verified",
          base_run(), {"claim:population.claim_support": "FULLY_SUPPORTED"}))
    fz = frozen()
    fz["target_sets"]["set-1"]["members"] = ["EP-A", {"ref": "edge-gateway"}]
    add(V("R-15", "run", ["S5.12-1", "S5.12-2"], "negative", "required target reference cannot be resolved",
          base_run([issuer(), receiver("rcv-a", "EP-A")], fz=fz),
          {"obl:ctrl-1/ref:edge-gateway.disposition": "INDETERMINATE", "structural.structural_result": "INCONCLUSIVE",
           "check": []}, case=15))
    fz2 = copy.deepcopy(fz)
    fz2["target_directory"]["refs"]["edge-gateway"] = ["EP-B", "EP-C"]
    add(V("R-15b", "run", ["S5.12-1"], "negative", "required target reference resolves ambiguously",
          base_run([issuer(), receiver("rcv-a", "EP-A")], fz=fz2),
          {"obl:ctrl-1/ref:edge-gateway.disposition": "INDETERMINATE", "check": []}))
    fz3 = copy.deepcopy(fz)
    fz3["target_directory"]["refs"]["edge-gateway"] = "EP-B"
    add(V("R-15c", "run", ["S5.12-1", "S5.12-2"], "positive", "reference resolves to one known target",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")], fz=fz3),
          {"obl:ctrl-1/EP-B.disposition": "CONFIRMED", "structural.structural_result": "PASS", "check": []}))
    prof = with_changes(example_profile(), resolution_failure={"unresolved": "INVALID", "stale": "INDETERMINATE",
                                                               "ambiguous": "INDETERMINATE", "inconsistent": "INVALID"})
    add(V("R-15d", "run", ["S5.12-1"], "negative", "unresolved reference under a profile that maps it to INVALID",
          base_run([issuer(), receiver("rcv-a", "EP-A")], fz=copy.deepcopy(fz), profile=prof),
          {"obl:ctrl-1/ref:edge-gateway.disposition": "INVALID", "check": []}, case=15))
    fz = frozen()
    fz["expected_counts"] = {"instructions": 1, "obligations": 3}
    add(V("R-16", "run", ["S5.11-1", "S6.5-5"], "negative", "declared expected counts do not balance",
          base_run(fz=fz), {"structural.structural_result": "INCONCLUSIVE",
                            "structural.has_blocker": "EXPECTED_COUNTS_DIFFER", "check": []}, case=16))
    fz = frozen()
    fz["expected_counts"] = {"instructions": 1, "obligations": 2}
    add(V("R-16b", "run", ["S5.11-1"], "positive", "declared expected counts balance",
          base_run(fz=fz), {"structural.structural_result": "PASS", "check": []}))
    add(V("R-18", "run", ["S5.5-3", "S5.5-4"], "negative", "a record of EP-A's observer presented as EP-B's receipt",
          base_run([issuer(), receiver("rcv-a", "EP-A"),
                    receiver("rcv-ab", "EP-B", observer="ep-a-obs", receiver_id="ep-a", boundary="ep-b-ingress")]),
          {"obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "receiver:rcv-ab.class": "invalid_receiver",
           "check": []}, case=18))
    fz = frozen()
    fz["target_sets"]["set-1"]["coverage"] = "DECLARED_ONLY"
    fz["target_sets"]["set-1"]["coverage_basis"] = "producer configuration says the set is closed"
    cl = [{"claim_id": "cd", "kind": "complete_delivery", "scope": {"instructions": ["ctrl-1"],
                                                                     "fact": "every member of set-1 confirmed"}},
          {"claim_id": "cm", "kind": "complete_mediation", "scope": {"instructions": ["ctrl-1"],
                                                                      "fact": "every egress path received the stop"}}]
    add(V("R-19", "run", ["S5.15-2", "S5.15-4", "S5.11-13", "S9.3-2"], "negative",
          "both targets CONFIRMED while target-set coverage is DECLARED_ONLY",
          base_run(claims=cl, fz=fz),
          {"structural.structural_result": "PASS", "claim:cd.claim_support": "FULLY_SUPPORTED",
           "claim:cm.claim_support": "CONDITIONALLY_SUPPORTED", "claim:cm.condition": "coverage_verified",
           "target_sets.set-1.coverage": "DECLARED_ONLY", "check": []}, case=[19, 24]))
    prof = with_changes(example_profile(), claims={"conditional_predicates": ["observer_authority_verified"],
                                                   "mandatory_predicates": {**example_profile()["claims"]["mandatory_predicates"],
                                                                            "complete_mediation": ["structural_pass", "coverage_verified"]}})
    add(V("R-19b", "run", ["S6.6-9", "S5.15-4"], "negative",
          "DECLARED_ONLY coverage under a profile that makes coverage mandatory for complete mediation",
          base_run(claims=cl, fz=copy.deepcopy(fz), profile=prof),
          {"claim:cm.claim_support": "NOT_SUPPORTED", "claim:cm.assertable": False, "check": []}))
    prof_d = with_changes(example_profile(), claims={"conditional_predicates": ["observer_authority_verified"],
                                                     "mandatory_predicates": example_profile()["claims"]["mandatory_predicates"]})
    add(V("R-19d", "run", ["S6.6-8", "S6.6-9"], "negative",
          "DECLARED_ONLY coverage under a profile that lists coverage as neither conditional nor mandatory",
          base_run(claims=cl, fz=copy.deepcopy(fz), profile=prof_d),
          {"claim:cm.claim_support": "NOT_SUPPORTED", "claim:cd.claim_support": "FULLY_SUPPORTED", "check": []}))
    add(V("R-19c", "run", ["S5.15-2", "S5.11-13"], "positive", "coverage VERIFIED supports complete mediation",
          base_run(claims=cl), {"claim:cm.claim_support": "FULLY_SUPPORTED", "check": []}))
    fz = frozen()
    fz["instructions"][0]["target_resolution"] = {"open": {"reason": "service mesh membership not enumerable",
                                                           "known_targets": ["EP-A"]}}
    add(V("R-20", "run", ["S5.11-11", "S5.11-12"], "negative", "open Required Target Set",
          base_run([issuer(), receiver("rcv-a", "EP-A")], claims=cl[:1], fz=fz),
          {"instr:ctrl-1.class": "not_closed", "obl:ctrl-1/EP-A.open_scope": True,
           "structural.structural_result": "INCONCLUSIVE", "claim:cd.claim_support": "NOT_SUPPORTED",
           "conservation.instructions.draft_equation_holds": False,
           "conservation.instructions.extended_equation_holds": True, "check": []}, case=20))
    fz = frozen()
    fz["instructions"][0]["target_resolution"] = {"set_id": "set-unknown"}
    add(V("R-20b", "run", ["S5.11-11", "S5.12-1"], "negative", "target-set reference does not resolve",
          base_run([issuer(target_set_ref="set-unknown"), receiver("rcv-a", "EP-A")], claims=cl[:1], fz=fz),
          {"instr:ctrl-1.class": "not_closed", "structural.structural_result": "INCONCLUSIVE",
           "claim:cd.claim_support": "NOT_SUPPORTED", "receiver:rcv-a.class": "orphan", "check": []}))
    vf = receiver("rcv-b", "EP-B", event="verification_failed")
    add(V("R-22", "run", ["S6.5-3", "S5.5-6"], "positive",
          "verified receiver failure observation for EP-B: FAIL with a fully supported scoped failure",
          base_run([issuer(), receiver("rcv-a", "EP-A"), vf], claims=[
              {"claim_id": "fb", "kind": "scoped_failure",
               "scope": {"instructions": ["ctrl-1"], "obligation": ["ctrl-1", "EP-B"],
                         "fact": "EP-B did not accept ctrl-1 attempt a1"}}]),
          {"obl:ctrl-1/EP-B.disposition": "EXPLICIT_FAILURE", "structural.structural_result": "FAIL",
           "claim:fb.claim_support": "FULLY_SUPPORTED", "claim:fb.structural_result": "FAIL", "check": []}, case=22))
    out += race_vectors() + more_run_vectors()
    return out


def race_vectors():
    out = []
    act = {"record_id": "act-a", "kind": "control_activation", "observer": "ep-a-obs", "boundary_side": "receiver",
           "boundary": "ep-a-ingress", "event": "activated", "instruction_id": "ctrl-1", "target_id": "EP-A",
           "time": "2026-09-10T10:00:10Z", "clock": "tsa:example-tsa", "native": "verified"}

    def op(rid, oid, bnd, ev, t, clock="tsa:example-tsa"):
        return {"record_id": rid, "kind": "operation_event", "observer": "ep-a-obs", "boundary_side": "receiver",
                "boundary": "ep-a-provider", "event": ev, "operation_id": oid, "target_id": "EP-A", "op_boundary": bnd,
                "time": t, "clock": clock, "native": "verified"}
    enf = {"record_id": "enf-a", "kind": "enforcement_outcome", "observer": "ep-a-obs", "boundary_side": "receiver",
           "boundary": "ep-a-ingress", "event": "outcome", "instruction_id": "ctrl-1", "target_id": "EP-A",
           "outcome": "APPLIED", "time": "2026-09-10T10:00:10Z", "clock": "host:ep-a", "native": "verified"}
    eff = {"record_id": "eff-a", "kind": "effect_observation", "observer": "witness", "boundary_side": "witness",
           "boundary": "ep-a-provider", "event": "observed", "instruction_id": "ctrl-1", "target_id": "EP-A",
           "operation_id": "O2", "predicate": "O2 did not cross provider entry at EP-A during the window",
           "method": "provider-entry log of EP-A read by the witness", "observer_relationship": "independent witness",
           "window": {"start": "2026-09-10T10:00:10Z", "end": "2026-09-10T10:30:00Z"}, "result": "EFFECT_OBSERVED",
           "time": "2026-09-10T10:30:00Z", "clock": "tsa:example-tsa", "native": "verified"}
    recs = [issuer(), receiver("rcv-a", "EP-A"), enf, act, eff,
            op("o1-adm", "O1", "admission", "crossed", "2026-09-10T10:00:01Z"),
            op("o1-pe", "O1", "provider_entry", "crossed", "2026-09-10T10:00:02Z"),
            op("o2-adm", "O2", "admission", "crossed", "2026-09-10T10:00:08Z"),
            op("o2-pe", "O2", "provider_entry", "refused", "2026-09-10T10:00:12Z")]
    fz = frozen()
    fz["target_sets"]["set-1"]["coverage"] = "DECLARED_ONLY"
    out.append(V("R-23", "run", ["S9.4-2", "S9.4-3", "S9.4-4", "S9.4-5", "S4.5-3", "S9.4-1"], "positive",
                 "freeze applied after O1 crossed provider entry and before O2 attempted it; EP-B unconfirmed",
                 base_run(recs, fz=fz, claims=[
                     {"claim_id": "ie", "kind": "independent_effect",
                      "scope": {"instructions": ["ctrl-1"], "obligation": ["ctrl-1", "EP-A"],
                                "fact": "O2 did not cross provider entry at EP-A"}}]),
                 {"op:O1.status": "crossed_before_activation_outcome_unresolved",
                  "op:O2.status": "blocked_at_provider_entry_within_target_EP-A",
                  "op:O2.fact:admission": "before_activation", "op:O2.fact:provider_entry": "after_activation",
                  "obl:ctrl-1/EP-A.disposition": "CONFIRMED", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED",
                  "obl:ctrl-1/EP-A.enforcement.outcome": "APPLIED",
                  "obl:ctrl-1/EP-B.control_effect.summary": "UNKNOWN",
                  "instr:ctrl-1.parent.fully_confirmed_within_target_set": False,
                  "structural.structural_result": "INCONCLUSIVE", "claim:ie.claim_support": "FULLY_SUPPORTED",
                  "check": []}, case=[23, 24]))
    recs_b = [r if r["record_id"] not in ("o1-pe",) else op("o1-pe", "O1", "provider_entry", "crossed",
                                                              "2026-09-10T10:00:02Z", clock="host:ep-a-gateway")
              for r in recs]
    out.append(V("R-23b", "run", ["S5.9-3", "S5.9-1"], "negative",
                 "O1 provider entry recorded on an untrusted clock: precedence is not reported",
                 base_run(recs_b, fz=copy.deepcopy(fz)),
                 {"op:O1.fact:provider_entry": "INDETERMINATE", "op:O1.status": "ordering_indeterminate", "check": []}))
    eff_self = dict(eff, record_id="eff-self", observer="ep-a-obs", independence_claimed=True,
                    observer_relationship="independent (self-declared)")
    out.append(V("R-23c", "run", ["S4.5-1", "S4.5-2", "S8.1-2"], "negative",
                 "effect observed by the enforcement point's own observer, labelled independent",
                 base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), eff_self],
                          claims=[{"claim_id": "ie", "kind": "independent_effect",
                                   "scope": {"instructions": ["ctrl-1"], "obligation": ["ctrl-1", "EP-A"],
                                             "fact": "independently observed stop at EP-A"}}]),
                 {"claim:ie.claim_support": "NOT_SUPPORTED", "check": []}, case=14))
    fz = frozen()
    fz["trust"]["observers"]["witness"]["writable_by"] = ["ep-a-obs"]
    out.append(V("R-23d", "run", ["S5.3-3"], "negative", "the witness record is writable by the enforcement point",
                 base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), eff], fz=fz,
                          claims=[{"claim_id": "ie", "kind": "independent_effect",
                                   "scope": {"instructions": ["ctrl-1"], "obligation": ["ctrl-1", "EP-A"],
                                             "fact": "independently observed stop at EP-A"}}]),
                 {"claim:ie.claim_support": "NOT_SUPPORTED", "check": []}))
    noeff = dict(eff, record_id="eff-n", result="NO_EFFECT")
    out.append(V("R-23e", "run", ["S5.7-3", "S5.7-2"], "positive", "a bounded NO_EFFECT effect observation",
                 base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), noeff]),
                 {"obl:ctrl-1/EP-A.control_effect.summary": "NO_EFFECT",
                  "obl:ctrl-1/EP-B.control_effect.summary": "UNKNOWN", "check": []}))
    noeff_bad = dict(noeff, record_id="eff-nb")
    del noeff_bad["window"]
    out.append(V("R-23f", "run", ["S5.7-3", "S5.7-2"], "negative", "a NO_EFFECT claim without a window",
                 base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), noeff_bad]),
                 {"input:eff-nb.class": "effect_observation:invalid",
                  "obl:ctrl-1/EP-A.control_effect.summary": "UNKNOWN", "check": []}))
    return out


def more_run_vectors():
    out = []
    add = out.append
    p = example_profile()
    gw_lossy = {"gw": {"governance_states": ["DENY", "DEFER", "REJECT", "TIMEOUT"],
                       "map": {"DENY": "FAILURE", "DEFER": "FAILURE", "REJECT": "FAILURE", "TIMEOUT": "TIMEOUT"}}}
    gw_lossless = {"gw": {"governance_states": ["DENY", "DEFER", "REJECT", "TIMEOUT"],
                          "map": {"DENY": "ERR_DENY", "DEFER": "ERR_DEFER", "REJECT": "ERR_REJECT", "TIMEOUT": "ERR_TIMEOUT"}}}

    def hop(delivered, mapping="gw"):
        return {"record_id": "hop-1", "kind": "intermediary_hop", "observer": "gateway", "boundary_side": "intermediary",
                "boundary": "gateway-relay", "event": "forwarded", "path_id": "p1", "hop_index": 0, "intermediary": "gateway",
                "mapping_id": mapping, "source_state": "DEFER", "delivered_state": delivered, "instruction_id": "ctrl-1",
                "target_id": "EP-B", "time": "2026-09-10T10:00:06Z", "clock": "host:gateway", "native": "verified"}
    claim = [{"claim_id": "pd", "kind": "preserved_disposition",
              "scope": {"instructions": ["ctrl-1"], "path_id": "p1", "fact": "EP-B's DEFER reached the relying party"}}]
    add(V("R-25", "run", ["S5.16-1", "S5.16-3", "S5.16-4", "S5.13-5", "S7-2"], "negative",
          "source DEFER mapped to generic FAILURE by a collapsing mapping",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), hop("FAILURE")], claims=claim,
                   profile=with_changes(p, intermediary_mappings=gw_lossy)),
          {"path:p1.preservation": "INDETERMINATE", "path:p1.hop0": "states_collapsed",
           "claim:pd.claim_support": "NOT_SUPPORTED", "check": []}, case=25))
    add(V("R-25b", "run", ["S5.16-1", "S5.16-2"], "positive", "lossless mapping keeps DEFER distinguishable",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), hop("ERR_DEFER")], claims=claim,
                   profile=with_changes(p, intermediary_mappings=gw_lossless)),
          {"path:p1.preservation": "PRESERVED", "claim:pd.claim_support": "FULLY_SUPPORTED", "check": []}))
    add(V("R-25c", "run", ["S5.16-2", "S5.16-4"], "negative", "intermediary mapping unavailable",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), hop("FAILURE", mapping="none")],
                   claims=claim),
          {"path:p1.preservation": "INDETERMINATE", "path:p1.hop0": "mapping_unavailable",
           "claim:pd.claim_support": "NOT_SUPPORTED", "check": []}))
    add(V("R-26", "run", ["SA.MCC-2", "S5.2-1", "S5.5-5"], "negative",
          "stable identifier survives the intermediary, the content the receiver read changed",
          base_run([issuer(content=CONTENT), receiver("rcv-a", "EP-A"),
                    receiver("rcv-b", "EP-B", digest=D2, content=OTHER_CONTENT)]),
          {"obl:ctrl-1/EP-B.disposition": "SUBSTITUTION", "structural.structural_result": "FAIL", "check": []}, case=26))
    add(V("R-26b", "run", ["S5.5-5"], "negative", "receiver acknowledges a digest that is not the digest of what it read",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", digest=D, content=OTHER_CONTENT)]),
          {"receiver:rcv-b.class": "invalid_receiver", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "check": []}))
    add(V("R-26c", "run", ["S5.5-5", "S5.2-1"], "positive", "receiver carries the content it read and its digest matches",
          base_run([issuer(content=CONTENT), receiver("rcv-a", "EP-A", content=CONTENT), receiver("rcv-b", "EP-B")]),
          {"obl:ctrl-1/EP-A.disposition": "CONFIRMED", "check": []}))
    fz = frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2",
                               "target_resolution": {"empty": {"condition": "task-9 already terminated before ctrl-2; "
                                                                            "resolution rule selects only live runtimes"}}})
    recs = [issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"),
            issuer(rid="iss-2", iid="ctrl-2", target_set_ref="none")]
    add(V("R-27", "run", ["S5.11-4", "S5.11-5", "S5.11-6", "S5.11-7", "S6.4-2", "S6.4-3", "S6.4-4"], "positive",
          "an instruction whose target resolution yields an empty set, valid under the profile",
          base_run(recs, fz=fz),
          {"instr:ctrl-2.class": "zero_obligations", "instr:ctrl-2.contributed_obligations": 0,
           "instr:ctrl-2.zero_obligation_condition_present": True, "conservation.instructions.I": 2,
           "conservation.instructions.with_obligations": 1, "conservation.instructions.zero_obligation_instructions": 1,
           "conservation.instructions.draft_equation_holds": True, "conservation.obligations.O": 2,
           "structural.structural_result": "PASS", "check": []}, case=27))
    add(V("R-27b", "run", ["S5.11-9", "S5.11-10"], "negative", "the same empty set under a profile that does not permit it",
          base_run(copy.deepcopy(recs), fz=copy.deepcopy(fz), profile=with_changes(p, empty_target_set_valid=False)),
          {"instr:ctrl-2.class": "zero_obligations", "conservation.obligations.O": 2,
           "conservation.obligations.counts.EXPLICIT_FAILURE": 0, "structural.structural_result": "INCONCLUSIVE",
           "structural.has_blocker": "EMPTY_TARGET_SET_NOT_PERMITTED", "check": []}, case=27))
    many = [issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", digest=D2),
            receiver("rcv-b2", "EP-B", event="verification_failed", time="2026-09-10T10:00:06Z")]
    add(V("R-29", "run", ["S5.10-6", "S5.10-7"], "positive",
          "EP-B with a content mismatch and a verification failure reduced to one disposition",
          base_run(many),
          {"obl:ctrl-1/EP-B.disposition": "SUBSTITUTION",
           "obl:ctrl-1/EP-B.reduction.applicable": ["EXPLICIT_FAILURE", "SUBSTITUTION"],
           "obl:ctrl-1/EP-B.has_diag": "RECEIVER_VERIFICATION_FAILED", "deterministic_under_reorder": True,
           "check": []}, case=29))
    fz = frozen()
    fz["instructions"] = []
    fz["population_closed"] = False
    add(V("R-30", "run", ["S6.5-3", "S5.10-4"], "negative",
          "an unmatched receipt while the comparison population was never established",
          base_run([receiver("rcv-x", "EP-A")], fz=fz),
          {"structural.structural_result": "INCONCLUSIVE", "receiver:rcv-x.class": "orphan", "check": []}, case=30))
    # attempts (S5.1-1, S5.1-4, Section 9.1)
    add(V("R-31", "run", ["S5.1-4", "S5.1-1"], "negative", "receiver observation of an attempt the issuer never emitted",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", attempt="a2")]),
          {"receiver:rcv-b.class": "orphan", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "check": []}))
    add(V("R-31b", "run", ["S5.1-4", "S9.1-3"], "positive", "attempt a1 rejected in transport, retry a2 confirmed",
          base_run([issuer(), issuer(rid="iss-1b", attempt="a2", time="2026-09-10T10:02:00Z"), receiver("rcv-a", "EP-A"),
                    transport("tr-b", "EP-B", "rejected"), receiver("rcv-b", "EP-B", attempt="a2",
                                                                     time="2026-09-10T10:02:05Z")]),
          {"obl:ctrl-1/EP-B.disposition": "CONFIRMED", "obl:ctrl-1/EP-B.has_diag": "OTHER_ATTEMPT_FAILED",
           "structural.structural_result": "PASS", "check": []}))
    add(V("R-31c", "run", ["S5.1-1"], "negative", "identifier not stable across the boundary",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", iid="ctrl-1-rewritten")]),
          {"receiver:rcv-b.class": "orphan", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "check": []}))
    add(V("R-32", "run", ["S5.1-2"], "negative", "issuer reuses the identifier for different content",
          base_run([issuer(), issuer(rid="iss-1b", attempt="a2", digest=D2, time="2026-09-10T10:02:00Z"),
                    receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")]),
          {"obl:ctrl-1/EP-A.disposition": "SUBSTITUTION", "obl:ctrl-1/EP-B.disposition": "SUBSTITUTION",
           "obl:ctrl-1/EP-A.has_diag": "ISSUER_ID_REUSED_WITH_DIFFERENT_CONTENT", "check": []}))
    failed = issuer(event="emission_failed", boundary="issuer-internal-queue")
    add(V("R-33", "run", ["S5.4-4", "S5.4-5", "S6.1-2"], "negative", "emission failed before the issuer boundary",
          base_run([failed]),
          {"instr:ctrl-1.dispatched": False, "obl:ctrl-1/EP-A.disposition": "EXPLICIT_FAILURE",
           "obl:ctrl-1/EP-A.has_diag": "EMISSION_FAILED_BEFORE_BOUNDARY", "structural.structural_result": "FAIL",
           "check": []}))
    add(V("R-33b", "run", ["S5.4-1"], "negative", "no issuer-side observation at all", base_run([receiver("rcv-a", "EP-A")]),
          {"instr:ctrl-1.dispatched": False, "obl:ctrl-1/EP-A.disposition": "INDETERMINATE",
           "structural.has_blocker": "ISSUER_POPULATION_MISMATCH", "check": []}))
    ts_digest = canon.document_digest(["EP-A", "EP-B"])
    add(V("R-34", "run", ["S5.4-3", "S5.12-1"], "positive", "issuer binds the Required Target Set by its digest",
          base_run([issuer(target_set_digest=ts_digest), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")]),
          {"structural.structural_result": "PASS", "check": []}))
    add(V("R-34b", "run", ["S5.4-3", "S5.12-1"], "negative", "issuer's target-set digest is inconsistent with the frozen set",
          base_run([issuer(target_set_digest=canon.document_digest(["EP-A"])), receiver("rcv-a", "EP-A"),
                    receiver("rcv-b", "EP-B")]),
          {"obl:ctrl-1/EP-A.disposition": "INVALID", "obl:ctrl-1/EP-A.has_diag": "TARGET_SET_INCONSISTENT", "check": []}))
    fz = frozen()
    fz["target_sets"]["set-1"]["valid_until"] = "2026-09-10T11:30:00Z"
    add(V("R-34c", "run", ["S5.12-1", "S5.12-2"], "negative", "target-set reference stale at the cutoff",
          base_run(fz=fz), {"obl:ctrl-1/EP-A.disposition": "INDETERMINATE", "structural.structural_result": "INCONCLUSIVE",
                            "check": []}))
    add(V("R-35", "run", ["S4.3-1", "S5.5-1"], "negative", "only a transport acceptance for EP-B",
          base_run([issuer(), receiver("rcv-a", "EP-A"), transport("tr-b", "EP-B", "accepted")]),
          {"obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "input:tr-b.class": "transport:not_receipt", "check": []}))
    te = {"endpoint_binding": "broker delivers only into EP-B's verified inbox", "delivery_semantics": "exactly-once",
          "persistence_point": "inbox fsync", "failure_behavior": "per-attempt rejection"}
    add(V("R-35b", "run", ["S4.3-1", "S5.5-1"], "positive",
          "transport acceptance under a profile that defines endpoint equivalence, with content binding",
          base_run([issuer(), receiver("rcv-a", "EP-A"), transport("tr-b", "EP-B", "accepted", content_digest=D)],
                   profile=with_changes(p, transport_equivalence=te)),
          {"obl:ctrl-1/EP-B.disposition": "CONFIRMED", "check": []}))

    def enf(rid, outcome, **kw):
        r = {"record_id": rid, "kind": "enforcement_outcome", "observer": "ep-a-obs", "boundary_side": "receiver",
             "boundary": "ep-a-ingress", "event": "outcome", "instruction_id": "ctrl-1", "target_id": "EP-A",
             "outcome": outcome, "time": "2026-09-10T10:00:07Z", "clock": "host:ep-a", "native": "verified"}
        r.update(kw)
        return r
    native = with_changes(p, enforcement_mapping={"BLOCKED": "APPLIED", "DECLINED": "REFUSED", "NOOP": "NO_EFFECT",
                                                 "?": "UNKNOWN"})
    add(V("R-36", "run", ["S5.6-2"], "positive", "native enforcement state mapped losslessly",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), enf("enf-a", "BLOCKED")], profile=native),
          {"obl:ctrl-1/EP-A.enforcement.outcome": "APPLIED", "check": []}))
    add(V("R-36b", "run", ["S5.6-2", "S5.6-3"], "negative", "native state without a mapping",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), enf("enf-a", "HALTED")], profile=native),
          {"obl:ctrl-1/EP-A.enforcement.outcome": "UNKNOWN", "obl:ctrl-1/EP-A.enforcement.has_diag": "NATIVE_STATE_UNMAPPED",
           "check": []}))
    add(V("R-36c", "run", ["S5.6-2", "S5.7-3"], "negative", "enforcement NO_EFFECT without predicate and window",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"), enf("enf-a", "NO_EFFECT")]),
          {"obl:ctrl-1/EP-A.enforcement.outcome": "UNKNOWN", "check": []}))
    add(V("R-36d", "run", ["S5.6-2"], "positive", "enforcement NO_EFFECT with predicate and window",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"),
                    enf("enf-a", "NO_EFFECT", predicate="task-9 already stopped",
                        window={"start": "2026-09-10T10:00:07Z", "end": "2026-09-10T10:05:00Z"})]),
          {"obl:ctrl-1/EP-A.enforcement.outcome": "NO_EFFECT", "check": []}))
    add(V("R-37", "run", ["S8.1-1"], "negative", "receiver record whose native verification failed",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", native="failed")]),
          {"receiver:rcv-b.class": "invalid_receiver", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED", "check": []}))
    nonat = receiver("rcv-b", "EP-B")
    del nonat["native"]
    add(V("R-37b", "run", ["S8.1-1"], "negative", "receiver record without a native verification result",
          base_run([issuer(), receiver("rcv-a", "EP-A"), nonat]),
          {"receiver:rcv-b.class": "invalid_receiver", "check": []}))
    add(V("R-38", "run", ["S5.9-1"], "negative", "record time without a UTC designator",
          base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", time="2026-09-10T10:00:05")]),
          {"receiver:rcv-b.class": "invalid_receiver", "check": []}))
    noclock = receiver("rcv-b", "EP-B")
    del noclock["clock"]
    add(V("R-38b", "run", ["S5.9-1", "S5.3-1"], "negative", "record without its clock basis",
          base_run([issuer(), receiver("rcv-a", "EP-A"), noclock]), {"receiver:rcv-b.class": "invalid_receiver", "check": []}))
    noobs = receiver("rcv-b", "EP-B")
    del noobs["observer"]
    add(V("R-38c", "run", ["S5.3-1"], "negative", "record without an observer",
          base_run([issuer(), receiver("rcv-a", "EP-A"), noobs]), {"receiver:rcv-b.class": "invalid_receiver", "check": []}))
    fz = frozen()
    add(V("R-39", "run", ["S5.10-4", "S6.4-8"], "negative",
          "an issuer emission inside the window that the frozen population omits",
          base_run([issuer(), issuer(rid="iss-2", iid="ctrl-2"), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")], fz=fz),
          {"structural.has_blocker": "ISSUER_POPULATION_MISMATCH", "structural.structural_result": "INCONCLUSIVE",
           "input:iss-2.class": "issuer:outside_population", "check": []}))
    fz = frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2", "target_resolution": {"set_id": "set-1"},
                               "attributes": {"class": "drill"}})
    add(V("R-39b", "run", ["S6.4-8"], "positive", "an instruction excluded by a published issuer-side rule",
          base_run([issuer(), issuer(rid="iss-2", iid="ctrl-2"), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B")],
                   fz=fz, profile=with_changes(p, exclusion_rules=[{"rule_id": "drills", "applies_to": "issuer_attribute",
                                                                     "attribute": "class", "equals": "drill"}])),
          {"exclusions.drills.count": 1, "structural.structural_result": "PASS", "check": []}))
    fz = frozen()
    fz["population_closed"] = False
    add(V("R-40", "run", ["S6.5-2"], "negative", "population not declared closed", base_run(fz=fz),
          {"structural.structural_result": "INCONCLUSIVE", "structural.has_blocker": "POPULATION_NOT_DECLARED_CLOSED",
           "check": []}))
    fz = frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2", "target_resolution": {"set_id": "set-2"}})
    fz["target_sets"]["set-2"] = {"members": ["EP-C"], "closure_basis": "producer list", "coverage": "DECLARED_ONLY",
                                  "coverage_basis": "producer declaration"}
    recs = [issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"),
            issuer(rid="iss-2", iid="ctrl-2", target_set_ref="set-2"), receiver("rcv-c", "EP-C", iid="ctrl-2")]
    add(V("R-41", "run", ["S8.1-3", "S5.15-2"], "negative",
          "complete mediation over two sets, one VERIFIED and one DECLARED_ONLY",
          base_run(recs, fz=fz, claims=[{"claim_id": "cm", "kind": "complete_mediation",
                                         "scope": {"instructions": "all", "fact": "all paths of both controls"}}]),
          {"claim:cm.claim_support": "CONDITIONALLY_SUPPORTED", "claim:cm.condition": "coverage_verified", "check": []}))
    fz = frozen()
    del fz["issuer_inclusion_rule"]
    add(V("R-42", "run", ["S5.11-1"], "negative", "issuer inclusion rule not declared", base_run(fz=fz),
          {"structural.structural_result": "INCONCLUSIVE", "claim:population.claim_support": "NOT_SUPPORTED"}))
    fz = frozen()
    del fz["target_sets"]["set-1"]["closure_basis"]
    add(V("R-43", "run", ["S5.15-1"], "negative", "target set without a closure basis", base_run(fz=fz),
          {"structural.structural_result": "INCONCLUSIVE", "run.errors_include": "S5.15-1"}))
    fz = frozen()
    fz["target_sets"]["set-1"]["coverage"] = "MOSTLY"
    add(V("R-43b", "run", ["S5.15-3", "S5.15-1"], "negative", "coverage condition outside the three conceptual conditions",
          base_run(fz=fz), {"structural.structural_result": "INCONCLUSIVE", "run.errors_include": "S5.15-1"}))
    add(V("R-44", "run", ["S5.13-1", "S5.13-2"], "positive", "the report states what it does not cover",
          base_run(), {"non_claim:complete_mediation": "verified", "non_claim:truth_of_assertions": "not_claimed",
                       "non_claim:enforcement": "assertion_only", "check": []}))
    add(V("R-45", "run", ["S6.6-1", "S6.6-2"], "positive", "every claim carries scope and support separate from the result",
          base_run(), {"claim:population.claim_scope.cutoff": CUTOFF, "claim:population.has_scope_fields": True,
                       "check": []}))
    add(V("R-46", "run", ["S5.6-1", "S5.7-1", "S6.1-1"], "positive",
          "one obligation CONFIRMED/APPLIED/UNKNOWN while the other is UNCONFIRMED",
          base_run([issuer(), receiver("rcv-a", "EP-A"), enf("enf-a", "APPLIED")]),
          {"obl:ctrl-1/EP-A.disposition": "CONFIRMED", "obl:ctrl-1/EP-A.enforcement.outcome": "APPLIED",
           "obl:ctrl-1/EP-A.control_effect.summary": "UNKNOWN", "obl:ctrl-1/EP-B.disposition": "UNCONFIRMED",
           "check": []}))
    return out


def _S(path, value):
    return {"op": "set", "path": path, "value": value}


def _D(path):
    return {"op": "delete", "path": path}


def RC(vid, reqs, polarity, desc, run, ops, expect, case=None):
    """A report-check vector: reconcile ``run``, apply the edit ``ops`` to the report, check it."""
    return V(vid, "report_check", reqs, polarity, desc, {"from_run": run, "ops": ops}, expect, case)


def check_vectors():
    out = []
    good = base_run()
    fail = base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", digest=D2)])
    r02 = base_run([issuer(), receiver("rcv-a", "EP-A")])
    st = ["structural"]
    out.append(RC("C-00", ["S6.6-3", "S6.6-4", "S6.5-6", "S6.4-1", "S6.4-5", "S5.13-1", "S6.5-7"], "positive",
                  "an untampered PASS report", good, [], {"violations": []}))
    out.append(RC("C-00b", ["S6.6-3", "S6.5-3"], "positive", "an untampered FAIL report", fail, [], {"violations": []}))
    bare = [_D(st + ["claim_scope"]), _D(st + ["claim_support"]), _D(st + ["conditions"])]
    out.append(RC("C-01", ["S6.6-3", "S6.6-4", "S6.5-7", "S5.13-3"], "negative",
                  "bare structural PASS without claim scope and support", good, bare,
                  {"violations_include": ["S6.6-3"]}, case=28))
    out.append(RC("C-02", ["S6.6-3", "S6.6-4"], "negative", "bare structural FAIL without claim scope and support",
                  fail, bare, {"violations_include": ["S6.6-3"]}, case=28))
    out.append(RC("C-03", ["S6.4-1"], "negative", "published counts do not balance |O|", good,
                  [_S(["conservation", "obligations", "counts", "CONFIRMED"], 3)], {"violations_include": ["S6.4-1"]}, case=16))
    out.append(RC("C-04", ["S6.5-5"], "negative", "PASS reported while conservation fails", good,
                  [_S(["conservation", "obligations", "holds"], False)], {"violations_include": ["S6.5-5"]}, case=16))
    out.append(RC("C-05", ["S6.5-3"], "negative", "FAIL without a positive failing condition", good,
                  [_S(st + ["structural_result"], "FAIL")], {"violations_include": ["S6.5-3"]}, case=30))
    out.append(RC("C-06", ["S6.2-2"], "negative", "parent fully confirmed with an UNCONFIRMED obligation", r02,
                  [_S(["instructions", {"where": {"instruction_id": "ctrl-1"}}, "parent",
                       "fully_confirmed_within_target_set"], True)], {"violations_include": ["S6.2-2"]}, case=17))
    out.append(RC("C-07", ["S6.2-1"], "negative", "parent result without per-target dispositions", good,
                  [_D(["instructions", 0, "parent", "per_target"])], {"violations_include": ["S6.2-1"]}))
    out.append(RC("C-08", ["S6.5-4"], "negative", "PASS while an obligation is UNCONFIRMED", r02,
                  [_S(st + ["structural_result"], "PASS")], {"violations_include": ["S6.5-4"]}))
    out.append(RC("C-09", ["S5.6-3"], "negative", "APPLIED without enforcement evidence", good,
                  [_S(["obligations", 0, "enforcement", "outcome"], "APPLIED")], {"violations_include": ["S5.6-3"]}))
    out.append(RC("C-10", ["S6.6-6"], "negative", "conditional support without named conditions",
                  base_run(fz=_fz_unverified()), [_S(["claims", 0, "conditions"], [])], {"violations_include": ["S6.6-6"]}))
    out.append(RC("C-11", ["S6.6-7"], "negative", "unsupported claim rendered as assertable", good,
                  [_S(["claims", 0, "claim_support"], "NOT_SUPPORTED"), _S(["claims", 0, "assertable"], True)],
                  {"violations_include": ["S6.6-7"]}))
    out.append(RC("C-12", ["S5.13-1"], "negative", "report without non-claims", good, [_S(["non_claims"], [])],
                  {"violations_include": ["S5.13-1"]}))
    out.append(RC("C-13", ["S6.6-1"], "negative", "claim scope without cutoff", good,
                  [_D(["claims", 0, "claim_scope", "cutoff"])], {"violations_include": ["S6.6-1"]}))
    out.append(RC("C-14", ["S5.11-7"], "negative", "|I| not published consistently", good,
                  [_S(["conservation", "instructions", "I"], 5)], {"violations_include": ["S5.11-7"]}))
    fz = frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2", "target_resolution": {"empty": {"condition": "no live runtime"}}})
    zero = base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B"),
                     issuer(rid="iss-2", iid="ctrl-2", target_set_ref="none")], fz=fz)
    out.append(RC("C-15", ["S6.4-4", "S5.11-5"], "negative", "zero-obligation instruction without its condition", zero,
                  [_S(["instructions", {"where": {"instruction_id": "ctrl-2"}}, "zero_obligation_condition"], None)],
                  {"violations_include": ["S6.4-4"]}, case=27))
    out.append(RC("C-15b", ["S6.4-4", "S5.11-5", "S6.4-3"], "positive", "zero-obligation instruction reported with its condition",
                  zero, [], {"violations": []}, case=27))
    out.append(RC("C-16", ["S6.4-5"], "negative", "|R| does not balance", good,
                  [_S(["conservation", "receiver_records", "R"], 7)], {"violations_include": ["S6.4-5"]}))
    out.append(RC("C-17", ["S6.4-7", "S6.4-6"], "negative", "subdivision does not preserve the parent count", good,
                  [_S(["conservation", "receiver_records", "matched_subdivision", "confirming"], 0)],
                  {"violations_include": ["S6.4-7"]}))
    out.append(RC("C-18", ["S6.5-6"], "negative", "aggregate label without class counts", good, [_D(st + ["class_counts"])],
                  {"violations_include": ["S6.5-6"]}))
    out.append(RC("C-19", ["S5.11-2", "S5.10-5"], "negative", "obligation disposition outside the minimum set", good,
                  [_S(["obligations", 0, "disposition"], "DELIVERED")], {"violations_include": ["S5.11-2"]}))
    out.append(RC("C-20", ["S6.5-1"], "negative", "aggregate label outside PASS, FAIL, INCONCLUSIVE", good,
                  [_S(st + ["structural_result"], "DONE")], {"violations_include": ["S6.5-1"]}))
    out.append(RC("C-21", ["S6.6-5"], "negative", "claim support outside the three meanings", good,
                  [_S(st + ["claim_support"], "MOSTLY_TRUE")], {"violations_include": ["S6.6-5"]}))
    out.append(RC("C-22", ["S5.6-1", "S5.7-1"], "negative", "delivery reported without a separate enforcement fact", good,
                  [_D(["obligations", 0, "enforcement"])], {"violations_include": ["S5.6-1"]}))
    many = base_run([issuer(), receiver("rcv-a", "EP-A"), receiver("rcv-b", "EP-B", digest=D2),
                     receiver("rcv-b2", "EP-B", event="verification_failed", time="2026-09-10T10:00:06Z")])
    out.append(RC("C-23", ["S5.10-7"], "negative", "reduced diagnostics hidden", many,
                  [_S(["obligations", {"where": {"target_id": "EP-B"}}, "diagnostics"], [])],
                  {"violations_include": ["S5.10-7"]}, case=29))
    fz = frozen()
    fz["instructions"][0]["target_resolution"] = {"open": {"reason": "mesh not enumerable", "known_targets": ["EP-A"]}}
    out.append(RC("C-24", ["S5.11-12"], "negative", "per-known-target result without open scope",
                  base_run([issuer(), receiver("rcv-a", "EP-A")], fz=fz), [_S(["obligations", 0, "open_scope"], False)],
                  {"violations_include": ["S5.11-12"]}, case=20))
    out.append(RC("C-25", ["S6.1-2"], "negative", "a scoped failure generalised to all targets",
                  base_run([issuer(), receiver("rcv-a", "EP-A"), transport("tr-b", "EP-B", "rejected")]),
                  [_S(["obligations", {"where": {"target_id": "EP-B"}}, "failure_scope"],
                      {"instruction_id": "ctrl-1", "target_id": "all targets"})],
                  {"violations_include": ["S6.1-2"]}, case=5))
    race = next(v for v in race_vectors() if v["id"] == "R-23")["input"]
    out.append(RC("C-26", ["S9.4-4"], "negative", "blocked status without the refusal fact", race,
                  [_D(["operations", {"where": {"operation_id": "O2"}}, "facts", {"where": {"event": "refused"}}])],
                  {"violations_include": ["S9.4-4"]}, case=23))
    out.append(RC("C-27", ["S9.4-2", "S9.4-5"], "negative",
                  "O1 relabelled blocked although it crossed provider entry before the freeze", race,
                  [_S(["operations", {"where": {"operation_id": "O1"}}, "status"],
                      "blocked_at_provider_entry_within_target_EP-A")],
                  {"violations_include": ["S9.4-2", "S9.4-5"]}, case=23))
    out.append(RC("C-28", ["S9.4-2", "S9.4-4", "S9.4-5"], "positive", "the untampered freeze-race report", race, [],
                  {"violations": []}, case=23))
    out.append(V("T-01", "render_check", ["S6.6-3", "S5.13-3"], "positive", "the text rendering keeps the claim context",
                 {"from_run": base_run()}, {"violations": []}, case=28))
    out.append(V("T-02", "render_check", ["S6.6-3", "S5.13-3"], "negative", "a bare text line with the structural result",
                 {"text": "structural result: PASS\n"}, {"violations_include": ["S6.6-3"]}, case=28))
    return out


def _fz_unverified():
    fz = frozen()
    fz["trust"]["observers"]["ep-a-obs"]["authority_verified"] = False
    return fz


EXTRA = {
    "R-01": ["+S5.10-4", "+S5.11-11", "+S5.14-1", "+S5.15-1", "+S5.15-3", "+S5.4-2", "+S5.4-4", "+S5.5-2", "+S5.5-3",
             "+S5.5-4", "+S6.5-2", "+S6.6-7", "+S8.1-1", "+S5.9-1", "+S6.2-2", "+S6.1-1", "+S5.3-1", "+S6.4-6",
             "+S6.4-7", "+S5.1-2", "+S6.5-5", "+S6.5-4"],
    "R-02": ["-S6.6-7", "+S10.4-1"],
    "R-04": ["+S5.10-2"], "R-05": ["+S6.1-2"], "R-08": ["+S5.10-2"], "R-10": ["+S5.8-1"],
    "R-14c": ["+S5.13-4", "+S8.1-2", "+S8.1-4"], "R-16b": ["+S6.5-5"], "R-19c": ["+S5.15-4", "+S8.1-3", "+S9.3-2"],
    "R-22": ["+S6.1-2"], "R-23": ["+S9.4-3"], "R-23b": ["-S9.4-3", "-S9.4-2"],
    "R-25b": ["+S5.13-5", "+S5.16-3", "+S5.16-4", "+S7-2"], "R-31": ["-S9.1-3"], "R-35b": ["+S5.5-1"],
    "C-00": ["+S5.13-3", "+S6.6-5", "+S6.6-2", "+S6.5-1", "+S6.1-2"], "C-01": ["-S6.6-2"], "C-03": ["-S10.4-1"],
    "C-12": ["-S5.13-2"], "C-14": ["-S5.11-4", "-S5.11-6"], "C-15": ["-S6.4-2"],
    "P-15": ["-S4.4-1"], "P-36": ["+S4.4-1"], "R-12": ["+S5.6-1", "+S5.7-1"],
    "R-23-extra": [],
    "R-33": ["+S5.4-5"], "R-33b": ["-S5.4-5"], "R-26b": ["-S5.5-6"], "C-19": ["-S5.10-1"],
    "R-27": ["+S5.11-9", "+S5.11-10"], "R-20": ["+S5.11-12", "-S6.4-3"], "R-14": ["+S6.6-6"],
    "P-00": ["+S6.6-9"], "R-19": ["+S6.6-9"], "R-26c": ["+SA.MCC-2"],
}
EXTRA["R-23"] = ["+S9.4-3", "+S4.5-1", "+S4.5-2", "+S5.3-3", "+S5.9-3"]
EXTRA["R-01"] = EXTRA["R-01"] + ["+S5.10-3"]
EXTRA.pop("R-23-extra")


def all_vectors():
    vs = profile_vectors() + run_vectors() + check_vectors()
    for v in vs:
        for r in EXTRA.get(v["id"], []):
            if r not in v["requirements"] and r[1:] not in v["requirements"]:
                v["requirements"].append(r)
            elif r[1:] in v["requirements"]:
                v["requirements"][v["requirements"].index(r[1:])] = r
    return vs


def requirement_polarity(vec):
    """(requirement id, polarity) pairs of one vector."""
    out = []
    for r in vec["requirements"]:
        if r[0] in "+-":
            out.append((r[1:], "positive" if r[0] == "+" else "negative"))
        else:
            out.append((r, vec["polarity"]))
    return out
