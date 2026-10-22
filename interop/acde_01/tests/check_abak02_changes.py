"""One test per rule that changed from draft -01 to draft -02 (plain-text copy, SHA-256
fe3baeb08c8e0979ca64efece098c972827fab483debe0b2bcbfd697bb714782, 2856 lines).

Each RED test was written against the -01 reading first and failed there; each CONTROL test names a
-02 rule that the -01 reading already met, so it could not fail first. Section and line numbers
refer to the -02 copy.
"""
from __future__ import annotations

import copy
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "vectors")]

import build  # noqa: E402
from acde01.profile import example_profile, validate_profile, with_changes  # noqa: E402
from acde01.reconcile import reconcile, reconcile_versions  # noqa: E402
from acde01.report_check import check_report  # noqa: E402


def _obl(rep, iid, tid):
    return next((o for o in rep["obligations"] if o["instruction_id"] == iid and o["target_id"] == tid), None)


def _instr(rep, iid):
    return next(e for e in rep["instructions"] if e["instruction_id"] == iid)


def _codes(diags):
    return {d["code"] for d in diags}


def _reqs(errors):
    return {e["requirement"] for e in errors}


def _excluding_profile(**extra):
    p = example_profile()
    rules = [{"rule_id": "canary-exempt", "version": "3", "reason": "canary targets are outside the stop scope",
              "applies_to": "target_attribute", "attribute": "tier", "equals": "canary"}]
    return with_changes(p, exclusion_rules=rules,
                        exclusion_inputs={"issuer_attribute": ["class"], "target_attribute": ["tier"]}, **extra)


def _canary_frozen(*targets):
    fz = build.frozen()
    for t in targets:
        fz["target_directory"]["targets"][t]["attributes"] = {"tier": "canary"}
    return fz


# ---- Section 5.4, lines 746-766: missing issuer observation and pre-boundary emission failure

def test_RED_absent_issuer_observation_is_dispatch_not_established():
    """5.4 lines 748-751: absence alone MUST NOT be rendered as dispatched=false."""
    rep = reconcile(build.base_run([build.receiver("rcv-a", "EP-A")]))
    e = _instr(rep, "ctrl-1")
    assert e.get("dispatch") == "NOT_ESTABLISHED"
    assert e.get("dispatched") is not False


def test_RED_receiver_fact_without_issuer_record_stays_correlated():
    """Case 6 and 6.5 lines 1443-1447: the receiver fact is retained, dispatch NOT_ESTABLISHED, the
    obligation INDETERMINATE, no PASS. ORPHAN is only for a record no expected obligation correlates."""
    rep = reconcile(build.base_run([build.receiver("rcv-a", "EP-A"), build.receiver("rcv-b", "EP-B")]))
    rr = rep["record_accounting"]["receiver_records"]
    assert rr["rcv-a"]["class"] == "matched" and rr["rcv-b"]["class"] == "matched"
    for t in ("EP-A", "EP-B"):
        ob = _obl(rep, "ctrl-1", t)
        assert ob["disposition"] == "INDETERMINATE"
        assert "ISSUER_RECORD_ABSENT" in _codes(ob["diagnostics"])
    assert rep["structural"]["structural_result"] != "PASS"
    assert "DISPATCH_NOT_ESTABLISHED" in _codes(rep["structural"]["pass_blockers"])


def test_RED_missing_issuer_evidence_does_not_suppress_a_scoped_failure():
    """5.4 lines 754-756: the missing-evidence diagnostic MUST NOT suppress scoped-failure evidence."""
    rep = reconcile(build.base_run([build.receiver("rcv-a", "EP-A"),
                                    build.receiver("rcv-b", "EP-B", event="verification_failed")]))
    ob = _obl(rep, "ctrl-1", "EP-B")
    assert ob["disposition"] == "EXPLICIT_FAILURE"
    assert {"ISSUER_RECORD_ABSENT", "RECEIVER_VERIFICATION_FAILED"} <= _codes(ob["diagnostics"])


def test_RED_unscoped_emission_failure_is_not_fanned_out():
    """5.4 lines 760-766 and case 5: without verified attempt, target and boundary bindings the failure
    stays an instruction diagnostic."""
    failed = build.issuer(event="emission_failed", boundary="issuer-internal-queue")
    rep = reconcile(build.base_run([failed]))
    e = _instr(rep, "ctrl-1")
    assert "EMISSION_FAILED_BEFORE_BOUNDARY" in _codes(e["diagnostics"])
    assert e.get("dispatch") == "NOT_ESTABLISHED"
    for t in ("EP-A", "EP-B"):
        assert _obl(rep, "ctrl-1", t)["disposition"] != "EXPLICIT_FAILURE"
    assert rep["structural"]["structural_result"] != "FAIL"


def test_RED_scoped_emission_failure_fails_only_its_target():
    """Case 5: a pre-boundary rejection bound to one attempt, target and issuer boundary is a scoped
    EXPLICIT_FAILURE for that obligation only."""
    failed = build.issuer(event="emission_failed", boundary="issuer-internal-queue", target_id="EP-B",
                          failed_before_boundary="issuer-egress")
    rep = reconcile(build.base_run([build.issuer(rid="iss-0", attempt="a0", time="2026-09-10T09:59:00Z"),
                                    build.receiver("rcv-a", "EP-A", attempt="a0"), failed]))
    assert _obl(rep, "ctrl-1", "EP-B")["disposition"] == "EXPLICIT_FAILURE"
    assert _obl(rep, "ctrl-1", "EP-B")["failure_scope"]["target_id"] == "EP-B"
    assert _obl(rep, "ctrl-1", "EP-A")["disposition"] == "CONFIRMED"


# ---- Sections 5.11 (lines 983-990) and 6.4 (lines 1365-1374): unclosed target resolution

def _open_run():
    fz = build.frozen()
    fz["instructions"][0]["target_resolution"] = {"open": {"reason": "service mesh membership not enumerable",
                                                           "known_targets": ["EP-A"]}}
    return build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A")], fz=fz)


def test_RED_unclosed_resolution_creates_no_obligation_and_balances_the_instruction_equation():
    rep = reconcile(_open_run())
    e = _instr(rep, "ctrl-1")
    assert e["class"] == "target_resolution_unclosed"
    assert e["unclosed_reason"]
    assert [o for o in rep["obligations"] if o["instruction_id"] == "ctrl-1"] == []
    ci = rep["conservation"]["instructions"]
    assert (ci["I"], ci["with_obligations"], ci["zero_obligation_instructions"], ci["target_resolution_unclosed"]) \
        == (1, 0, 0, 1)
    assert ci["equation_holds"] is True
    assert rep["record_accounting"]["receiver_records"]["rcv-a"]["class"] == "orphan"
    assert rep["structural"]["structural_result"] == "INCONCLUSIVE"
    assert check_report(rep) == []


def test_RED_report_check_refuses_an_obligation_of_an_unclosed_instruction():
    rep = reconcile(_open_run())
    bad = copy.deepcopy(reconcile(build.base_run()))
    bad["instructions"][0]["class"] = "target_resolution_unclosed"
    bad["instructions"][0]["unclosed_reason"] = "planted"
    assert "S6.4-4" in _reqs(check_report(bad))
    assert check_report(rep) == []


# ---- Sections 4.2 (lines 549-572), 5.11 (lines 921-937), 6.4 (lines 1349-1381), 6.5 (lines 1461-1470)

def test_RED_an_excluded_instruction_is_reported_with_rule_version_and_reason():
    fz = build.frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2", "target_resolution": {"set_id": "set-1"},
                               "attributes": {"class": "drill"}})
    p = with_changes(example_profile(),
                     exclusion_rules=[{"rule_id": "drills", "version": "2", "reason": "drills are not live controls",
                                       "applies_to": "issuer_attribute", "attribute": "class", "equals": "drill"}],
                     exclusion_inputs={"issuer_attribute": ["class"], "target_attribute": []})
    rep = reconcile(build.base_run([build.issuer(), build.issuer(rid="iss-2", iid="ctrl-2"),
                                    build.receiver("rcv-a", "EP-A"), build.receiver("rcv-b", "EP-B")], fz=fz, profile=p))
    ex = next(x for x in rep["exclusions"] if x["rule"] == "drills")
    assert (ex["version"], ex["reason"], ex["count"], ex["ids"]) == ("2", "drills are not live controls", 1, ["ctrl-2"])
    assert rep["structural"]["structural_result"] == "PASS"


def test_RED_all_target_exclusion_is_an_exclusion_induced_zero_obligation_instruction():
    """Case 16: |C_i|=2, |E_i|=2, |T_i|=0, zero base obligations, not terminal-empty, no PASS unless the
    profile expressly permits it."""
    rep = reconcile(build.base_run([build.issuer()], fz=_canary_frozen("EP-A", "EP-B"), profile=_excluding_profile(
        exclusion_induced_zero_pass=False)))
    assert rep["profile"]["errors"] == []
    e = _instr(rep, "ctrl-1")
    assert (e["class"], e["zero_cause"]) == ("zero_obligations", "exclusion_induced")
    assert (e["candidate_count"], e["excluded_count"], e["required_count"]) == (2, 2, 0)
    assert sorted(x["target_id"] for x in e["excluded_targets"]) == ["EP-A", "EP-B"]
    assert all(x["rule"] == "canary-exempt" and x["version"] == "3" and x["reason"] for x in e["excluded_targets"])
    assert rep["conservation"]["obligations"]["O"] == 0
    assert e["parent"]["fully_confirmed_within_target_set"] is not True
    assert rep["structural"]["structural_result"] == "INCONCLUSIVE"
    assert "EXCLUSION_INDUCED_ZERO_NOT_PERMITTED" in _codes(rep["structural"]["pass_blockers"])
    ok = reconcile(build.base_run([build.issuer()], fz=_canary_frozen("EP-A", "EP-B"), profile=_excluding_profile(
        exclusion_induced_zero_pass=True)))
    assert ok["structural"]["structural_result"] == "PASS"
    scope = next(c for c in ok["claims"] if c["claim_id"] == "population")["claim_scope"]
    zero = scope["zero_obligation_instructions"]
    assert zero == [{"instruction_id": "ctrl-1", "zero_cause": "exclusion_induced",
                     "condition": zero[0]["condition"], "excluded": 2}]
    assert check_report(ok) == []


def test_RED_one_excluded_target_leaves_one_obligation():
    rep = reconcile(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A")], fz=_canary_frozen("EP-B"),
                                   profile=_excluding_profile(exclusion_induced_zero_pass=False)))
    e = _instr(rep, "ctrl-1")
    assert (e["class"], e["candidate_count"], e["excluded_count"], e["required_count"]) == ("with_obligations", 2, 1, 1)
    assert [o["target_id"] for o in rep["obligations"]] == ["EP-A"]
    assert rep["structural"]["structural_result"] == "PASS"


def test_RED_terminal_empty_is_distinguished_from_exclusion_induced():
    fz = build.frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2", "target_resolution": {"empty": {"condition": "no live runtime"}}})
    rep = reconcile(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A"), build.receiver("rcv-b", "EP-B"),
                                    build.issuer(rid="iss-2", iid="ctrl-2", target_set_ref="none")], fz=fz))
    e = _instr(rep, "ctrl-2")
    assert (e["zero_cause"], e["candidate_count"], e["excluded_count"]) == ("terminal_empty", 0, 0)


def test_RED_an_exclusion_rule_without_a_version_is_unverifiable():
    p = _excluding_profile(exclusion_induced_zero_pass=False)
    del p["exclusion_rules"][0]["version"]
    assert "S6.5-9" in _reqs(validate_profile(p))


def test_RED_an_exclusion_over_an_input_the_profile_does_not_permit_is_refused():
    p = _excluding_profile(exclusion_induced_zero_pass=False)
    p["exclusion_inputs"] = {"issuer_attribute": ["class"], "target_attribute": []}
    assert "S5.11-5" in _reqs(validate_profile(p))


def test_RED_the_profile_must_predeclare_whether_an_all_target_exclusion_may_pass():
    p = _excluding_profile()
    p.pop("exclusion_induced_zero_pass", None)
    assert "S5.11-7" in _reqs(validate_profile(p))


def test_RED_an_emission_away_from_the_issuer_boundary_is_not_dispatch():
    """4.1 lines 536-545 and 5.4 lines 735-739 (unchanged from -01, found while reading for -02):
    an emission recorded at another boundary does not establish dispatch."""
    rep = reconcile(build.base_run([build.issuer(boundary="issuer-internal-queue"), build.receiver("rcv-a", "EP-A"),
                                    build.receiver("rcv-b", "EP-B")]))
    assert _instr(rep, "ctrl-1").get("dispatch") == "NOT_ESTABLISHED"
    assert rep["structural"]["structural_result"] != "PASS"
    for t in ("EP-A", "EP-B"):
        assert _obl(rep, "ctrl-1", t)["disposition"] != "CONFIRMED"


# ---- Section 6.5, lines 1420-1426: frozen positive FAIL conditions

def test_RED_a_profile_must_publish_its_fail_conditions():
    assert "S6.5-2" in _reqs(validate_profile(with_changes(example_profile(), fail_conditions=None)))


def test_RED_substitution_is_FAIL_only_where_the_profile_declares_it():
    """Case 22: two frozen profiles with different positive FAIL conditions."""
    recs = [build.issuer(), build.receiver("rcv-a", "EP-A"), build.receiver("rcv-b", "EP-B", digest=build.D2)]
    narrow = with_changes(example_profile(), fail_conditions={"EXPLICIT_FAILURE": True, "SUBSTITUTION": False,
                                                              "CONFLICT": False, "INVALID": False,
                                                              "exclusion_rule_violation": False})
    rep = reconcile(build.base_run(copy.deepcopy(recs), profile=narrow))
    assert rep["profile"]["errors"] == []
    assert _obl(rep, "ctrl-1", "EP-B")["disposition"] == "SUBSTITUTION"
    assert rep["structural"]["structural_result"] == "INCONCLUSIVE"
    wide = reconcile(build.base_run(copy.deepcopy(recs)))
    assert wide["structural"]["structural_result"] == "FAIL"
    assert check_report(rep) == [] and check_report(wide) == []


def test_RED_report_check_refuses_FAIL_from_a_disposition_the_profile_does_not_name():
    narrow = with_changes(example_profile(), fail_conditions={"EXPLICIT_FAILURE": True, "SUBSTITUTION": False,
                                                              "CONFLICT": False, "INVALID": False,
                                                              "exclusion_rule_violation": False})
    rep = reconcile(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A"),
                                    build.receiver("rcv-b", "EP-B", digest=build.D2)], profile=narrow))
    bad = copy.deepcopy(rep)
    bad["structural"]["structural_result"] = "FAIL"
    bad["structural"]["positive_failing_conditions"] = [{"instruction_id": "ctrl-1", "target_id": "EP-B",
                                                         "disposition": "SUBSTITUTION"}]
    assert "S6.5-2" in _reqs(check_report(bad))


# ---- Section 5.12, lines 1015-1028: the resolution classes are defined, not chosen

def test_RED_an_unresolved_reference_cannot_be_profiled_INVALID():
    p = with_changes(example_profile(), resolution_failure={"unresolved": "INVALID", "stale": "INDETERMINATE",
                                                            "ambiguous": "INDETERMINATE", "inconsistent": "INVALID"})
    assert "S5.12-1" in _reqs(validate_profile(p))


# ---- Section 5.10, lines 879-885: substitution and identifier scope

def test_RED_equal_identifiers_from_distinct_uniqueness_scopes_are_not_merged():
    other = build.issuer(rid="iss-x", digest=build.D2, identifier_scope="deployment-b")
    rep = reconcile(build.base_run([build.issuer(), other, build.receiver("rcv-a", "EP-A"),
                                    build.receiver("rcv-b", "EP-B")]))
    assert [_obl(rep, "ctrl-1", t)["disposition"] for t in ("EP-A", "EP-B")] == ["CONFIRMED", "CONFIRMED"]
    assert rep["record_accounting"]["inputs"]["iss-x"]["class"] == "issuer:outside_population"


def test_RED_issuer_issuer_substitution_names_its_records():
    rep = reconcile(build.base_run([build.issuer(), build.issuer(rid="iss-1b", attempt="a2", digest=build.D2,
                                                                 time="2026-09-10T10:02:00Z"),
                                    build.receiver("rcv-a", "EP-A"), build.receiver("rcv-b", "EP-B")]))
    d = next(x for x in _obl(rep, "ctrl-1", "EP-A")["diagnostics"]
             if x["code"] == "ISSUER_ID_REUSED_WITH_DIFFERENT_CONTENT")
    assert sorted(d["records"]) == ["iss-1", "iss-1b"]


# ---- Sections 5.11 (lines 939-947), 6.1 (lines 1212-1220): matched means correlated

def test_RED_a_receiver_record_of_an_attempt_never_emitted_is_correlated_not_orphan():
    rep = reconcile(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A"),
                                    build.receiver("rcv-b", "EP-B", attempt="a2")]))
    assert rep["record_accounting"]["receiver_records"]["rcv-b"]["class"] == "matched"
    assert _obl(rep, "ctrl-1", "EP-B")["disposition"] == "UNCONFIRMED"
    assert rep["conservation"]["receiver_records"]["matched_subdivision"]["non_confirming"] == 1


# ---- Section 6.6, lines 1487-1492: the default claim names the profile and the cutoff

def test_RED_the_default_claim_names_the_profile():
    rep = reconcile(build.base_run())
    scope = rep["structural"]["claim_scope"]
    assert scope["profile"] == {"profile_id": "acde01-interop-example", "profile_revision": "1"}
    assert scope["cutoff"] == build.CUTOFF


# ---- Sections 4.2 (lines 577-579) and 5.1 (lines 689-693): attempts are subaccounting

def _retry_run():
    return build.base_run([build.issuer(), build.issuer(rid="iss-1b", attempt="a2", time="2026-09-10T10:02:00Z"),
                           build.receiver("rcv-a", "EP-A"), build.transport("tr-b", "EP-B", "rejected"),
                           build.receiver("rcv-b", "EP-B", attempt="a2", time="2026-09-10T10:02:05Z")])


def test_CONTROL_a_retry_does_not_change_the_obligation_count():
    """Already met by the -01 reading (one obligation per instruction and target)."""
    rep = reconcile(_retry_run())
    assert rep["conservation"]["obligations"]["O"] == 2
    ob = _obl(rep, "ctrl-1", "EP-B")
    assert ob["disposition"] == "CONFIRMED" and ob["attempts"] == ["a1", "a2"]
    assert {"OTHER_ATTEMPT_FAILED", "TRANSPORT_REJECTED_ATTEMPT"} <= _codes(ob["diagnostics"])


def test_RED_report_check_refuses_a_second_obligation_for_one_instruction_and_target():
    rep = reconcile(_retry_run())
    bad = copy.deepcopy(rep)
    bad["obligations"].append(copy.deepcopy(_obl(bad, "ctrl-1", "EP-B")))
    bad["conservation"]["obligations"]["O"] = 3
    bad["conservation"]["obligations"]["counts"]["CONFIRMED"] = 3
    assert "S4.2-5" in _reqs(check_report(bad))


def test_RED_report_check_refuses_an_erased_failed_attempt():
    rep = reconcile(_retry_run())
    bad = copy.deepcopy(rep)
    _obl(bad, "ctrl-1", "EP-B")["attempts"] = ["a2"]
    assert "S5.1-6" in _reqs(check_report(bad))


def test_RED_report_check_refuses_PASS_over_a_dispatch_not_established():
    rep = reconcile(build.base_run())
    bad = copy.deepcopy(rep)
    bad["instructions"][0]["dispatch"] = "NOT_ESTABLISHED"
    assert "S6.5-7" in _reqs(check_report(bad))


# ---- Rules the -01 reading already met

def test_CONTROL_deadline_elapsed_leaves_UNCONFIRMED_with_a_diagnostic():
    """5.8 lines 835-836; the -01 reading (a) of S5.8-1."""
    neg = {"record_id": "neg-b", "kind": "negative_observation", "observer": "reconciler", "boundary_side": "issuer",
           "boundary": "issuer-egress", "event": "observed", "condition": "deadline_elapsed",
           "observed": "deadline of 60 s elapsed without a matching acknowledgement", "cutoff": "2026-09-10T10:01:00Z",
           "instruction_id": "ctrl-1", "target_id": "EP-B", "attempt_id": "a1", "time": "2026-09-10T10:01:00Z",
           "clock": "tsa:example-tsa", "native": "verified"}
    rep = reconcile(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A"), neg]))
    ob = _obl(rep, "ctrl-1", "EP-B")
    assert ob["disposition"] == "UNCONFIRMED" and "NEGATIVE_DEADLINE_ELAPSED" in _codes(ob["diagnostics"])


def test_CONTROL_a_terminal_empty_parent_is_not_fully_confirmed():
    """6.2 lines 1252-1254; the -01 reading (a) of S6.2-1 (null)."""
    fz = build.frozen()
    fz["instructions"].append({"instruction_id": "ctrl-2", "target_resolution": {"empty": {"condition": "none live"}}})
    rep = reconcile(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A"), build.receiver("rcv-b", "EP-B"),
                                    build.issuer(rid="iss-2", iid="ctrl-2", target_set_ref="none")], fz=fz))
    assert _instr(rep, "ctrl-2")["parent"]["fully_confirmed_within_target_set"] is None


def test_CONTROL_a_later_versioned_run_keeps_the_earlier_result():
    """9.1 lines 1693-1697."""
    late = build.receiver("rcv-b", "EP-B", time="2026-09-10T12:30:00Z")
    reps = reconcile_versions(build.base_run([build.issuer(), build.receiver("rcv-a", "EP-A"), late]),
                              [build.CUTOFF, "2026-09-10T13:00:00Z"])
    assert _obl(reps[0], "ctrl-1", "EP-B")["disposition"] == "UNCONFIRMED"
    assert _obl(reps[1], "ctrl-1", "EP-B")["disposition"] == "CONFIRMED"
    assert reps[1]["run"]["previous_report_digest"] == reps[0]["report_digest"]
