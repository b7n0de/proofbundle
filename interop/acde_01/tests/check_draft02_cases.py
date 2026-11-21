"""The thirty Minimum Conformance Cases of revision -02 of the draft, measured against this reading of -01.

Revision -02 (11 October 2026) renumbers and tightens the appendix "Minimum Conformance Cases". The
implementation in this directory follows -01. Each case below states what the -02 text expects, in its
own words, and builds an input for this implementation from that text alone. The expected values come
from the -02 text, never from this implementation's output.

A case in ``BOUNDARY`` is one this implementation does not meet without a new function; README.md
names the limit. Its test asserts that the limit still stands, so the README cannot silently drift
from the code: if the limit goes away, the test turns red and the README has to be updated.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "vectors")]

from acde01.reconcile import reconcile, reconcile_versions, render_summary  # noqa: E402

with open(os.path.join(ROOT, "vectors", "acde01_vectors.json"), encoding="ascii") as fh:
    _BASE = json.load(fh)
PROFILE = _BASE["base_profile"]
FROZEN = _BASE["base_frozen"]


def digest(content):
    """Own derivation of the profile's content digest (canonical JSON, sorted keys, no whitespace,
    UTF-8, domain prefix ``acde01-instruction-v1`` and a zero byte), independent of acde01.canon."""
    body = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha-256:" + hashlib.sha256(b"acde01-instruction-v1\x00" + body).hexdigest()


STOP = digest({"action": "stop", "scope": "agent-7"})
STOP_OTHER = digest({"action": "stop", "scope": "agent-8"})


def run(records, frozen=None, profile=None, claims=None):
    f = copy.deepcopy(FROZEN)
    f.update(frozen or {})
    p = copy.deepcopy(PROFILE)
    p.update(profile or {})
    return {"profile": p, "frozen": f, "records": records, "claims": claims or []}


def single_target(**extra):
    """One instruction, one required target EP-A (Section 4.2: one base obligation)."""
    sets = copy.deepcopy(FROZEN["target_sets"])
    sets["set-1"]["members"] = ["EP-A"]
    d = {"target_sets": sets}
    d.update(extra)
    return d


def issuer(rid="iss-1", attempt="a1", content=STOP, time="2026-09-10T10:00:00Z", event="emitted", **kw):
    r = {"record_id": rid, "kind": "issuer_emission", "observer": "issuer-obs", "boundary_side": "issuer",
         "boundary": "issuer-egress", "event": event, "instruction_id": "ctrl-1", "attempt_id": attempt,
         "content_digest": content, "target_set_ref": "set-1", "time": time, "clock": "tsa:example-tsa",
         "native": "verified"}
    r.update(kw)
    return r


def receiver(rid, target="EP-A", attempt="a1", content=STOP, time="2026-09-10T10:00:05Z",
             event="read_and_matched", observer=None, receiver_id=None, boundary=None, instr="ctrl-1"):
    low = target[-1].lower()
    return {"record_id": rid, "kind": "receiver_observation", "observer": observer or f"ep-{low}-obs",
            "boundary_side": "receiver", "boundary": boundary or f"ep-{low}-ingress", "event": event,
            "instruction_id": instr, "attempt_id": attempt, "content_digest": content,
            "receiver_id": receiver_id or f"ep-{low}", "target_id": target, "time": time,
            "clock": f"host:ep-{low}", "native": "verified"}


def ob(rep, target, instr="ctrl-1"):
    return next(o for o in rep["obligations"] if o["instruction_id"] == instr and o["target_id"] == target)


def codes(diags):
    return {d["code"] for d in diags}


def result(rep):
    return rep["structural"]["structural_result"]


# Each case returns a list of (statement from the -02 text, observed truth value).

def case_1():
    rep = reconcile(run([
        issuer("iss-1", "a1"), issuer("iss-2", "a2", time="2026-09-10T10:01:00Z"),
        {"record_id": "tr-1", "kind": "transport_ack", "observer": "issuer-obs", "boundary_side": "issuer",
         "boundary": "issuer-egress", "event": "rejected", "instruction_id": "ctrl-1", "target_id": "EP-A",
         "attempt_id": "a1", "time": "2026-09-10T10:00:01Z", "clock": "tsa:example-tsa", "native": "verified"},
        receiver("rcv-2", attempt="a2", time="2026-09-10T10:01:05Z")], single_target()))
    o = ob(rep, "EP-A")
    inputs = rep["record_accounting"]["inputs"]
    return [("one base obligation", len(rep["obligations"]) == 1),
            ("disposition CONFIRMED", o["disposition"] == "CONFIRMED"),
            ("both attempts retained", o["attempts"] == ["a1", "a2"]),
            ("both attempt records accounted", {"iss-1", "iss-2", "tr-1", "rcv-2"} <= set(inputs)),
            ("earlier failure diagnostic retained", "TRANSPORT_REJECTED_ATTEMPT" in codes(o["diagnostics"]))]


def case_2():
    rep = reconcile(run([issuer()], single_target()))
    return [("issuer evidence only at cutoff: UNCONFIRMED", ob(rep, "EP-A")["disposition"] == "UNCONFIRMED")]


def case_3():
    a = reconcile(run([issuer(), receiver("rcv-a", content=STOP_OTHER)], single_target()))
    b = reconcile(run([issuer("iss-1", "a1"), issuer("iss-2", "a2", content=STOP_OTHER,
                                                     time="2026-09-10T10:01:00Z")], single_target()))
    acc_a = a["record_accounting"]["inputs"]
    return [("issuer-receiver mismatch: SUBSTITUTION", ob(a, "EP-A")["disposition"] == "SUBSTITUTION"),
            ("conflicting records retained (mismatch)",
             acc_a.get("iss-1", {}).get("class") == "issuer:used" and "rcv-a" in ob(a, "EP-A")["matched_records"]),
            ("issuer-issuer reuse with different content: SUBSTITUTION", ob(b, "EP-A")["disposition"] == "SUBSTITUTION"),
            ("conflicting issuer records retained", b["instructions"][0]["issuer_records"] == ["iss-1", "iss-2"])]


def case_4():
    rep = reconcile(run([issuer(), receiver("rcv-a"), receiver("rcv-x", instr="ctrl-unknown")], single_target()))
    return [("uncorrelated receiver record: ORPHAN accounting",
             rep["record_accounting"]["receiver_records"]["rcv-x"]["class"] == "orphan")]


def case_5():
    # bound: one attempt, one target (EP-A), the issuer boundary; the set has EP-A and EP-B
    bound = reconcile(run([issuer("iss-f", "a1", event="emission_failed", target_id="EP-A")]))
    unbound = reconcile(run([issuer("iss-f", "a1", event="emission_failed")]))
    return [("bound rejection: scoped EXPLICIT_FAILURE on EP-A", ob(bound, "EP-A")["disposition"] == "EXPLICIT_FAILURE"),
            ("bound rejection: not fanned out to EP-B", ob(bound, "EP-B")["disposition"] != "EXPLICIT_FAILURE"),
            ("unbound rejection: not fanned out to any obligation",
             all(o["disposition"] != "EXPLICIT_FAILURE" for o in unbound["obligations"])),
            ("unbound rejection: kept as instruction diagnostic",
             "EMISSION_FAILURE_RECORDED" in codes(unbound["instructions"][0]["diagnostics"]))]


def case_6():
    rep = reconcile(run([receiver("rcv-a")], single_target()))
    bad = issuer()
    del bad["content_digest"]
    mal = reconcile(run([bad, receiver("rcv-a")], single_target()))
    linked = any(d.get("record") == "rcv-a" for d in ob(rep, "EP-A")["diagnostics"])
    return [("receiver fact retained and linked to its obligation", "rcv-a" in rep["record_accounting"]["receiver_records"]
             and linked),
            ("correlatable receiver record not accounted as ORPHAN (case 4 reserves ORPHAN for uncorrelatable ones)",
             rep["record_accounting"]["receiver_records"]["rcv-a"]["class"] != "orphan"),
            ("obligation INDETERMINATE", ob(rep, "EP-A")["disposition"] == "INDETERMINATE"),
            ("no structural PASS", result(rep) != "PASS"),
            ("dispatch reported as NOT_ESTABLISHED", rep["instructions"][0]["dispatched"] == "NOT_ESTABLISHED"),
            ("malformed issuer record: INVALID", ob(mal, "EP-A")["disposition"] == "INVALID")]


def case_7():
    bad = receiver("rcv-bad")
    del bad["receiver_id"]
    rep = reconcile(run([issuer(), bad], single_target()))
    rr = rep["record_accounting"]["receiver_records"]
    o = ob(rep, "EP-A")
    kept = any(d.get("record") == "rcv-bad" for d in o["diagnostics"]) or \
        rr["rcv-bad"]["detail"].get("instruction_id") == "ctrl-1"
    return [("exactly one primary invalid class", rr["rcv-bad"]["class"] == "invalid_receiver"
             and sum(1 for k in rr if k == "rcv-bad") == 1),
            ("correlatable identity retained diagnostically", kept)]


def case_8():
    rep = reconcile(run([issuer(), receiver("rcv-1"), receiver("rcv-2")], single_target()))
    rr = rep["record_accounting"]["receiver_records"]
    c = rep["conservation"]["receiver_records"]
    return [("each duplicate in exactly one class", rr["rcv-1"]["class"] == "matched" and rr["rcv-2"]["class"] == "duplicate"),
            ("correlation visible", rr["rcv-2"]["detail"].get("record") == "rcv-1"),
            ("no double count", c["R"] == 2 and sum(c["counts"].values()) == 2 and c["holds"])]


def case_9():
    rep = reconcile(run([issuer(), receiver("rcv-ok"), receiver("rcv-fail", event="verification_failed",
                                                                  time="2026-09-10T10:00:06Z")], single_target()))
    o = ob(rep, "EP-A")
    return [("irreconcilable verified claims: CONFLICT", o["disposition"] == "CONFLICT"),
            ("all positive evidence retained", o["matched_records"] == ["rcv-ok", "rcv-fail"])]


def _deadline(rid="neg-1"):
    return {"record_id": rid, "kind": "negative_observation", "observer": "issuer-obs", "boundary_side": "issuer",
            "boundary": "issuer-egress", "event": "observed", "condition": "deadline_elapsed",
            "observed": "no receipt by the deadline", "cutoff": "2026-09-10T10:30:00Z", "instruction_id": "ctrl-1",
            "target_id": "EP-A", "attempt_id": "a1", "time": "2026-09-10T10:30:00Z", "clock": "tsa:example-tsa",
            "native": "verified"}


def case_10():
    rep = reconcile(run([issuer(), _deadline()], single_target()))
    o = ob(rep, "EP-A")
    return [("delivery stays UNCONFIRMED", o["disposition"] == "UNCONFIRMED"),
            ("deadline diagnostic", "NEGATIVE_DEADLINE_ELAPSED" in codes(o["diagnostics"]))]


def case_11():
    late = receiver("rcv-late", time="2026-09-10T12:30:00Z")
    v0, v1 = reconcile_versions(run([issuer(), _deadline(), late], single_target()),
                                ["2026-09-10T12:00:00Z", "2026-09-10T13:00:00Z"])
    return [("earlier result UNCONFIRMED with deadline diagnostic", ob(v0, "EP-A")["disposition"] == "UNCONFIRMED"
             and "NEGATIVE_DEADLINE_ELAPSED" in codes(ob(v0, "EP-A")["diagnostics"])),
            ("later result CONFIRMED", ob(v1, "EP-A")["disposition"] == "CONFIRMED"),
            ("earlier cutoff and result preserved", v1["run"]["previous_report_digest"] == v0["report_digest"]
             and v0["run"]["cutoff"] == "2026-09-10T12:00:00Z")]


def _enf(outcome, **kw):
    r = {"record_id": "enf-1", "kind": "enforcement_outcome", "observer": "ep-a-obs", "boundary_side": "receiver",
         "boundary": "ep-a-ingress", "event": "outcome", "instruction_id": "ctrl-1", "target_id": "EP-A",
         "outcome": outcome, "time": "2026-09-10T10:00:10Z", "clock": "host:ep-a", "native": "verified"}
    r.update(kw)
    return r


def _effect(result, **drop):
    r = {"record_id": "eff-1", "kind": "effect_observation", "observer": "witness", "boundary_side": "observer",
         "boundary": "witness-tap", "event": "observed", "instruction_id": "ctrl-1", "target_id": "EP-A",
         "predicate": "no outbound call from agent-7", "method": "egress capture",
         "observer_relationship": "separate operator", "window": {"start": "2026-09-10T10:00:10Z",
                                                                   "end": "2026-09-10T10:20:00Z"},
         "result": result, "time": "2026-09-10T10:20:00Z", "clock": "tsa:example-tsa", "native": "verified"}
    for k in drop:
        r.pop(k)
    return r


def case_12():
    rep = reconcile(run([issuer(), receiver("rcv-a")], single_target()))
    o = ob(rep, "EP-A")
    return [("delivery CONFIRMED", o["disposition"] == "CONFIRMED"),
            ("enforcement UNKNOWN", o["enforcement"]["outcome"] == "UNKNOWN")]


def case_13():
    win = {"start": "2026-09-10T10:00:10Z", "end": "2026-09-10T10:20:00Z"}
    rep = reconcile(run([issuer(), receiver("rcv-a"), _enf("NO_EFFECT", predicate="p", window=win)], single_target()))
    with_eff = reconcile(run([issuer(), receiver("rcv-a"), _effect("NO_EFFECT")], single_target()))
    no_window = reconcile(run([issuer(), receiver("rcv-a"), _effect("NO_EFFECT", window=1)], single_target()))
    o = ob(rep, "EP-A")
    return [("delivery CONFIRMED, enforcement NO_EFFECT", o["disposition"] == "CONFIRMED"
             and o["enforcement"]["outcome"] == "NO_EFFECT"),
            ("control effect UNKNOWN", o["control_effect"]["summary"] == "UNKNOWN"),
            ("NO_EFFECT accepted with predicate, window and evidence",
             ob(with_eff, "EP-A")["control_effect"]["summary"] == "NO_EFFECT"),
            ("NO_EFFECT without window not accepted", ob(no_window, "EP-A")["control_effect"]["summary"] == "UNKNOWN")]


def case_14():
    eff = _effect("EFFECT_OBSERVED")
    eff["observer"] = "self-declared"
    eff["independence_claimed"] = True
    rep = reconcile(run([issuer(), receiver("rcv-a"), eff], single_target(),
                        claims=[{"claim_id": "ind", "kind": "independent_effect", "scope": {"instructions": ["ctrl-1"]}}]))
    x = ob(rep, "EP-A")["control_effect"]["observations"][0]
    c = next(c for c in rep["claims"] if c["claim_id"] == "ind")
    return [("no independence from a self-declared role", x["independent_under_trust_model"] is False),
            ("no silent fully supported attribution", c["claim_support"] != "FULLY_SUPPORTED")]


def case_15():
    fz = copy.deepcopy(FROZEN)
    fz["target_sets"]["set-1"]["members"] = [{"ref": "nowhere"}]
    unres = reconcile(run([issuer()], {"target_sets": fz["target_sets"]}))
    fz["target_sets"]["set-1"]["members"] = [42]
    malf = reconcile(run([issuer()], {"target_sets": fz["target_sets"]}))
    bad = issuer()
    del bad["target_set_ref"]
    missing = reconcile(run([bad], single_target()))
    conflict = reconcile(run([issuer(), receiver("rcv-ok"), receiver("rcv-f", event="verification_failed",
                                                                     time="2026-09-10T10:00:06Z")], single_target()))
    st = single_target()
    st["target_sets"]["set-1"]["valid_until"] = "2026-09-10T11:30:00Z"
    stale = reconcile(run([issuer(), receiver("rcv-a")], st))
    return [("unresolved reference: INDETERMINATE", unres["obligations"][0]["disposition"] == "INDETERMINATE"),
            ("malformed member: INVALID", malf["obligations"][0]["disposition"] == "INVALID"),
            ("missing required binding: INVALID", ob(missing, "EP-A")["disposition"] == "INVALID"),
            ("irreconcilable verified records: CONFLICT", ob(conflict, "EP-A")["disposition"] == "CONFLICT"),
            ("age alone is not invalidity", ob(stale, "EP-A")["disposition"] != "INVALID")]


def case_16():
    prof = {"exclusion_rules": [{"rule_id": "maint-v1", "attribute": "maintenance", "equals": True}]}
    rep = reconcile(run([issuer()], {"instructions": [{"instruction_id": "ctrl-1", "target_resolution": {"set_id": "set-1"},
                                                       "attributes": {"maintenance": True}}]}, prof))
    e = rep["instructions"][0] if rep["instructions"] else {}
    return [("instruction stays in the population with |C_i|=2, |E_i|=2, |T_i|=0",
             e.get("candidates") == 2 and e.get("excluded_targets") == 2 and e.get("required_targets") == 0),
            ("accounted as exclusion-induced zero-obligation", e.get("class") == "exclusion_induced_zero_obligation"),
            ("no synthetic obligation", rep["obligations"] == []),
            ("no PASS", result(rep) != "PASS")]


def case_17():
    rep = reconcile(run([issuer(), receiver("rcv-a")]))
    return [("EP-A CONFIRMED", ob(rep, "EP-A")["disposition"] == "CONFIRMED"),
            ("EP-B UNCONFIRMED", ob(rep, "EP-B")["disposition"] == "UNCONFIRMED"),
            ("parent not fully confirmed", rep["instructions"][0]["parent"]["fully_confirmed_within_target_set"] is False),
            ("no complete-delivery PASS", result(rep) != "PASS")]


def case_18():
    rep = reconcile(run([issuer(), receiver("rcv-a"),
                         receiver("rcv-ab", target="EP-B", observer="ep-a-obs")]))
    return [("EP-B not CONFIRMED", ob(rep, "EP-B")["disposition"] != "CONFIRMED")]


def _both(coverage):
    fz = copy.deepcopy(FROZEN)
    fz["target_sets"]["set-1"]["coverage"] = coverage
    return reconcile(run([issuer(), receiver("rcv-a"), receiver("rcv-b", target="EP-B")], {"target_sets": fz["target_sets"]},
                         claims=[{"claim_id": "med", "kind": "complete_mediation", "scope": {"instructions": ["ctrl-1"]}}]))


def case_19():
    rep = _both("DECLARED_ONLY")
    c = next(c for c in rep["claims"] if c["claim_id"] == "med")
    return [("scoped structural completion", result(rep) == "PASS"),
            ("complete mediation not FULLY_SUPPORTED", c["claim_support"] != "FULLY_SUPPORTED")]


def case_20():
    a = reconcile(run([issuer()], {"instructions": [{"instruction_id": "ctrl-1",
                                                     "target_resolution": {"open": {"reason": "discovery running"}}}]}))
    b = reconcile(run([issuer()], {"instructions": [{"instruction_id": "ctrl-1",
                                                     "target_resolution": {"set_id": "set-missing"}}]}))
    return [("open set counted as unclosed", a["conservation"]["instructions"]["not_closed"] == 1),
            ("unresolved set counted as unclosed", b["conservation"]["instructions"]["not_closed"] == 1),
            ("no synthetic obligation", a["obligations"] == [] and b["obligations"] == []),
            ("no PASS", result(a) != "PASS" and result(b) != "PASS")]


def case_21():
    fz = copy.deepcopy(FROZEN)
    fz["trust"]["observers"]["ep-a-obs"]["authority_verified"] = False
    rep = reconcile(run([issuer(), receiver("rcv-a")], {"target_sets": single_target()["target_sets"],
                                                         "trust": fz["trust"]}))
    s = rep["structural"]
    return [("structural result preserved", s["structural_result"] == "PASS"),
            ("stronger claim CONDITIONALLY_SUPPORTED", s["claim_support"] == "CONDITIONALLY_SUPPORTED"),
            ("missing predicate named", [c["predicate"] for c in s["conditions"]] == ["observer_authority_verified"])]


def case_22():
    rep = reconcile(run([issuer(), receiver("rcv-a", content=STOP_OTHER)], single_target()))
    miss = reconcile(run([issuer()], single_target()))
    return [("SUBSTITUTION prevents PASS", result(rep) != "PASS"),
            ("no FAIL without a frozen positive profile condition", result(rep) != "FAIL"),
            ("missing evidence alone never FAIL", result(miss) != "FAIL")]


def _op_run(clock_act, clock_op):
    act = {"record_id": "act-1", "kind": "control_activation", "observer": "ep-a-obs", "boundary_side": "receiver",
           "boundary": "ep-a-ingress", "event": "activated", "instruction_id": "ctrl-1", "target_id": "EP-A",
           "time": "2026-09-10T10:00:10Z", "clock": clock_act, "native": "verified"}
    cr = {"record_id": "op-1", "kind": "operation_event", "observer": "gateway-obs", "boundary_side": "receiver",
          "boundary": "provider-entry", "event": "crossed", "operation_id": "O1", "target_id": "EP-A",
          "op_boundary": "provider_entry", "time": "2026-09-10T10:00:05Z", "clock": clock_op, "native": "verified"}
    return reconcile(run([issuer(), receiver("rcv-a"), act, cr], single_target()))


def case_23():
    trusted = _op_run("tsa:example-tsa", "tsa:example-tsa")
    asserted = _op_run("host:ep-a", "host:gateway")
    return [("supported ordering permits before/after", trusted["operations"][0]["facts"][0]["relation_to_activation"]
             == "before_activation"),
            ("independent asserted clocks: INDETERMINATE", asserted["operations"][0]["facts"][0]["relation_to_activation"]
             == "INDETERMINATE")]


def case_24():
    rep = _both("INDETERMINATE")
    c = next(c for c in rep["claims"] if c["claim_id"] == "med")
    return [("structural accounting proceeds", result(rep) == "PASS"
             and rep["conservation"]["obligations"]["holds"]),
            ("complete mediation stays qualified", c["claim_support"] != "FULLY_SUPPORTED")]


def case_25():
    prof = {"intermediary_mappings": {"gw-map": {"governance_states": ["DEFER", "FAILURE", "DENY"],
                                                 "map": {"DEFER": "FAILURE", "FAILURE": "FAILURE", "DENY": "DENY"}}}}
    hop = {"record_id": "hop-1", "kind": "intermediary_hop", "observer": "gw-obs", "boundary_side": "intermediary",
           "boundary": "gw", "event": "forwarded", "path_id": "P1", "hop_index": 0, "intermediary": "gw",
           "mapping_id": "gw-map", "source_state": "DEFER", "delivered_state": "FAILURE", "instruction_id": "ctrl-1",
           "target_id": "EP-A", "time": "2026-09-10T10:00:03Z", "clock": "tsa:example-tsa", "native": "verified"}
    rep = reconcile(run([issuer(), receiver("rcv-a"), hop], single_target(), prof))
    return [("DEFER mapped to generic FAILURE: not PRESERVED", rep["intermediary_paths"][0]["preservation"] != "PRESERVED")]


def case_26():
    rep = reconcile(run([issuer(), receiver("rcv-a", content=STOP_OTHER)], single_target()))
    return [("same identifier, changed content: SUBSTITUTION, not CONFIRMED",
             ob(rep, "EP-A")["disposition"] == "SUBSTITUTION")]


def case_27():
    rep = reconcile(run([issuer()], {"instructions": [
        {"instruction_id": "ctrl-1", "target_resolution": {"empty": {"condition": "no agent of the tenant runs"}}}]}))
    e = rep["instructions"][0]
    return [("zero obligations", rep["obligations"] == [] and e["class"] == "zero_obligations"),
            ("parent confirmation NOT_APPLICABLE or absent",
             e["parent"]["fully_confirmed_within_target_set"] in (None, "NOT_APPLICABLE")),
            ("instruction and empty-set rule reported", e.get("zero_obligation_condition") == "no agent of the tenant runs"),
            ("PASS only as profile-permitted", result(rep) == "PASS" and e["empty_set_permitted"] is True)]


def case_28():
    out = []
    for name, recs in (("PASS", [issuer(), receiver("rcv-a")]),
                       ("FAIL", [issuer(), receiver("rcv-a", event="verification_failed")]),
                       ("INCONCLUSIVE", [issuer()])):
        rep = reconcile(run(recs, single_target()))
        s = rep["structural"]
        line = render_summary(rep).splitlines()[0]
        out.append((f"{name}: scope and support beside the result",
                    s["structural_result"] == name and bool(s["claim_scope"]["fact"]) and bool(s["claim_support"])
                    and "claim scope:" in line and "claim support:" in line))
    return out


def case_29():
    recs = [issuer(), receiver("rcv-ok"), receiver("rcv-f", event="verification_failed", time="2026-09-10T10:00:06Z"),
            receiver("rcv-dup"), _deadline()]
    rep = reconcile(run(recs, single_target()))
    rev = reconcile(run(list(reversed(recs)), single_target()))
    o = ob(rep, "EP-A")
    linked = {d.get("record") for d in o["diagnostics"]} | set(o["matched_records"])
    return [("exactly one base disposition", len(rep["obligations"]) == 1 and isinstance(o["disposition"], str)),
            ("deterministic under reorder", o["disposition"] == ob(rev, "EP-A")["disposition"]),
            ("every non-selected input retained or linked", {"rcv-ok", "rcv-f", "rcv-dup", "neg-1"} <= linked)]


def case_30():
    no_receipt = reconcile(run([issuer()], single_target()))
    no_issuer = reconcile(run([receiver("rcv-a")], single_target()))
    no_pop = reconcile(run([issuer(), receiver("rcv-a")], dict(single_target(), population_closed=False)))
    return [("absent receipt: no FAIL", result(no_receipt) == "INCONCLUSIVE"),
            ("absent issuer object: no FAIL", result(no_issuer) == "INCONCLUSIVE"),
            ("absent population evidence: no FAIL", result(no_pop) == "INCONCLUSIVE")]


CASES = {n: globals()[f"case_{n}"] for n in range(1, 31)}

# Cases this reading of -01 does not meet; README.md names each limit. The value is the set of statements
# that do not hold today. Everything else in every case holds.
BOUNDARY = {
    5: {"bound rejection: not fanned out to EP-B", "unbound rejection: not fanned out to any obligation"},
    6: {"dispatch reported as NOT_ESTABLISHED",
        "correlatable receiver record not accounted as ORPHAN (case 4 reserves ORPHAN for uncorrelatable ones)"},
    16: {"instruction stays in the population with |C_i|=2, |E_i|=2, |T_i|=0",
         "accounted as exclusion-induced zero-obligation"},
    22: {"no FAIL without a frozen positive profile condition"},
}


@pytest.mark.parametrize("n", sorted(CASES))
def test_draft02_case(n):
    got = CASES[n]()
    failing = {s for s, ok in got if not ok}
    assert failing == BOUNDARY.get(n, set()), (n, sorted(failing))
