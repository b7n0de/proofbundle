"""The reported-version status: absence of a version field stops meaning two things at once.

THE GAP (deep-gate iteration 5, finding F-C, measured at head 529cd20). A harness-reported
version field was written when the harness reported one and simply ABSENT when it did not.
Absence therefore carried two meanings and the receipt did not say which:

    the harness ran and reported no version
    no harness was bound at all, or the adapter never fills the field

For a verifier that ambiguity is the failure class the product exists against.

THE FORM IS A STATUS WITH THREE VALUES, NOT A BOOLEAN — a boolean has three states of its own
(true, false, absent) and would move the ambiguity one level up.

THE CONTRACT `test_missing_version_field_stays_absent_not_invented` IS UNTOUCHED, and the first
test here says so from this side: when nothing was reported the version key stays ABSENT. The
status speaks about the REPORTING, never about the version.
"""
from __future__ import annotations

import json
import pathlib
import tempfile

import pytest

from proofbundle.adapters._provenance import (REPORTED_VERSION_FIELDS, VERSION_STATUS_VALUES,
                                              bind_reported_version, version_status_issues)


# --- the writer -----------------------------------------------------------------------------

def test_reported_writes_field_and_status_without_reason():
    p = bind_reported_version({}, "harness_version", "0.4.12", reason="unused here")
    assert p["harness_version"] == "0.4.12"
    assert p["harness_version_status"] == "reported"
    assert "harness_version_status_reason" not in p, "a reported version explains itself"


def test_not_reported_leaves_the_version_field_absent():
    """The contract from this side: no value the harness never reported is invented."""
    p = bind_reported_version({}, "harness_version", None, reason="lm-eval reported none")
    assert "harness_version" not in p, "an unreported version must stay ABSENT"
    assert p["harness_version_status"] == "not_reported"
    assert p["harness_version_status_reason"] == "lm-eval reported none"


def test_empty_string_counts_as_not_reported():
    p = bind_reported_version({}, "harness_version", "", reason="empty is not a version")
    assert "harness_version" not in p
    assert p["harness_version_status"] == "not_reported"


def test_not_bound_is_its_own_state():
    """The OTHER meaning bare absence used to carry."""
    p = bind_reported_version({}, "harness_version", None,
                              reason="this format carries no harness version", bound=False)
    assert p["harness_version_status"] == "not_bound"
    assert "harness_version" not in p


def test_reason_is_mandatory_and_its_absence_raises():
    """A status that says 'not reported' without saying why moves the ambiguity instead of
    closing it — which is the whole point of the rule."""
    for kwargs in ({"reason": ""}, {"reason": "   "}, {"reason": None}):
        with pytest.raises(ValueError, match="requires a reason"):
            bind_reported_version({}, "harness_version", None, **kwargs)
    with pytest.raises(ValueError, match="requires a reason"):
        bind_reported_version({}, "harness_version", None, reason="", bound=False)


def test_reported_clears_a_stale_reason():
    """A reason left over from an earlier not_reported state would contradict the new status."""
    p = {"harness_version_status": "not_reported", "harness_version_status_reason": "old"}
    bind_reported_version(p, "harness_version", "1.2", reason="unused")
    assert "harness_version_status_reason" not in p


def test_only_three_literals_exist():
    assert VERSION_STATUS_VALUES == ("reported", "not_reported", "not_bound")


# --- the verifier ---------------------------------------------------------------------------

def test_consistent_block_has_no_issues():
    assert version_status_issues({"harness_version": "1.0",
                                  "harness_version_status": "reported"}) == []


def test_reported_without_the_field_is_caught():
    got = version_status_issues({"harness_version_status": "reported"})
    assert got and "absent" in got[0]


def test_field_present_while_status_denies_it_is_caught():
    """The mirror contradiction — both directions must be caught, or the pair can lie in one."""
    got = version_status_issues({"harness_version": "1.0",
                                 "harness_version_status": "not_reported",
                                 "harness_version_status_reason": "x"})
    assert got and "is present" in got[0]


def test_missing_reason_is_caught():
    got = version_status_issues({"harness_version_status": "not_bound"})
    assert got and "reason is mandatory" in got[0]


def test_unknown_literal_is_caught():
    got = version_status_issues({"harness_version_status": "maybe"})
    assert got and "not one of" in got[0]


def test_the_rule_covers_the_whole_class_not_one_field():
    """Patching only `harness_version` would rebuild the hole next door — which is exactly what
    iteration 5 found in the promptfoo adapter."""
    got = version_status_issues({"task_version_status": "maybe",
                                 "promptfoo_version_status": "not_reported"})
    assert len(got) == 2, got
    assert any("task_version_status" in g for g in got)
    assert any("promptfoo_version_status" in g for g in got)


def test_not_reported_is_not_an_all_clear():
    """It must never read as PASS: the verifier reports no ISSUE for a well-formed
    not_reported block, and that is explicitly NOT a statement that a version exists."""
    p = {"harness_version_status": "not_reported", "harness_version_status_reason": "none given"}
    assert version_status_issues(p) == []
    assert "harness_version" not in p, "no version may be inferred from a clean status check"


# --- through the adapters (the class, end to end) --------------------------------------------

def _lm_eval_claim(mit_version: bool):
    from proofbundle.adapters.lm_eval import from_lm_eval_results
    d = {"results": {"t": {"acc,none": 0.9}}, "versions": {"t": 1},
         "n-samples": {"t": {"effective": 10}}}
    if mit_version:
        d["lm_eval_version"] = "0.4.12"
    p = pathlib.Path(tempfile.mkdtemp()) / "r.json"
    p.write_text(json.dumps(d))
    claim, _ = from_lm_eval_results(str(p), task="t", metric="acc,none", comparator=">=",
                                    threshold="0.5", timestamp="2026-08-26T00:00:00Z")
    return claim["provenance"]


def test_lm_eval_reports_a_version():
    pr = _lm_eval_claim(True)
    assert pr["harness_version"] == "0.4.12"
    assert pr["harness_version_status"] == "reported"
    assert version_status_issues(pr) == []


def test_lm_eval_reports_none_and_says_so():
    pr = _lm_eval_claim(False)
    assert "harness_version" not in pr
    assert pr["harness_version_status"] == "not_reported"
    assert pr["harness_version_status_reason"]
    assert version_status_issues(pr) == []


# --- the OTHER THREE adapters, both directions each ------------------------------------------
#
# WHY THESE EXIST (deep-gate iteration 6, 2026-08-26, finding
# STATUSKLASSE-UEBER-VIER-ADAPTER-EIN-TEST-FAEHRT-EINEN-ERZEUGERPFAD-01). The status is a format
# commitment across FOUR adapters, and until now this file exercised exactly one producer path
# (lm-eval). The behaviour of the other three was correct when measured by hand — but nothing in
# the suite would have noticed if a later edit made a call site syntactically valid and
# semantically wrong, for instance passing a constant placeholder instead of what the harness
# reported. A raising call site was already caught by the neighbouring adapter tests; a lying one
# was not, and that is precisely what
# `test_missing_version_field_stays_absent_not_invented` exists to prevent, one field over.
#
# Each adapter is checked in BOTH directions, because one direction alone cannot tell a working
# binding from a constant: an adapter that always writes `reported` passes the first half.

def _promptfoo_claim(mit_version: bool):
    from proofbundle.adapters.promptfoo import from_promptfoo_results
    d = {"evalId": "ev1",
         "config": {"description": "s", "tests": [{"vars": {"a": 1}}], "providers": ["p:1"]},
         "results": {"version": 3, "stats": {"successes": 3, "failures": 1, "errors": 0},
                     "results": [{"provider": {"id": "p:1"}}]},
         "metadata": {"promptfooVersion": "0.100.0"} if mit_version else {}}
    p = pathlib.Path(tempfile.mkdtemp()) / "results.json"
    p.write_text(json.dumps(d))
    claim, _ = from_promptfoo_results(str(p), comparator=">=", threshold="0.5",
                                      timestamp="2026-08-26T00:00:00Z")
    return claim["provenance"]


def test_promptfoo_reports_a_version_under_BOTH_names():
    """Iteration 5's asymmetric binding: three adapters bound `harness_version`, this one bound
    `promptfoo_version` only, so a reader could not tell 'reports nothing' from 'names it
    differently'. Both names carry a status, or the hole is rebuilt next door."""
    pr = _promptfoo_claim(True)
    assert pr["harness_version"] == "0.100.0"
    assert pr["promptfoo_version"] == "0.100.0"
    assert pr["harness_version_status"] == "reported"
    assert pr["promptfoo_version_status"] == "reported"
    assert version_status_issues(pr) == []


def test_promptfoo_reports_none_and_says_so_on_both():
    pr = _promptfoo_claim(False)
    for field in ("harness_version", "promptfoo_version"):
        assert field not in pr, f"{field} must stay absent, never invented"
        assert pr[f"{field}_status"] == "not_reported"
        assert pr[f"{field}_status_reason"]
    assert version_status_issues(pr) == []


def _inspect_claim(mit_version: bool):
    from proofbundle.adapters.inspect_ai import from_inspect_ai_log

    class _Metric:
        value = 0.9

    class _Score:
        metrics = {"accuracy": _Metric()}
        scorer = "s"
        name = "n"
        reducer = None
        scored_samples = 10
        params = None

    class _Eval:
        task = "t"
        model = "m"
        dataset = None
        revision = None
        run_id = "r"
        created = "2026-08-26"
        task_args = None
        packages = {"inspect_ai": "0.3.112"} if mit_version else {}
        task_version = 7 if mit_version else None

    class _Results:
        scores = [_Score()]
        total_samples = 10

    class _Log:
        eval = _Eval()
        results = _Results()

    claim, _ = from_inspect_ai_log(_Log(), "accuracy", comparator=">=", threshold="0.5",
                                   timestamp="2026-08-26T00:00:00Z")
    return claim["provenance"]


def test_inspect_ai_reports_both_of_its_version_fields():
    pr = _inspect_claim(True)
    assert pr["harness_version"] == "0.3.112"
    assert pr["harness_version_status"] == "reported"
    assert pr["task_version"] == "7"
    assert pr["task_version_status"] == "reported"
    assert version_status_issues(pr) == []


def test_inspect_ai_reports_none_and_says_so_on_both():
    pr = _inspect_claim(False)
    for field in ("harness_version", "task_version"):
        assert field not in pr, f"{field} must stay absent, never invented"
        assert pr[f"{field}_status"] == "not_reported"
        assert pr[f"{field}_status_reason"]
    assert version_status_issues(pr) == []


def _eee_provenance(mit_version: bool):
    from proofbundle.adapters.eee import from_eee_dataset
    fixture = pathlib.Path(__file__).resolve().parent / "fixtures" / "eee_arc_easy.json"
    rec = json.loads(fixture.read_text())
    if not mit_version:
        rec["eval_library"].pop("version", None)
    claim, _ = from_eee_dataset(rec, comparator=">=", threshold="0.30", validate=False)
    return claim["provenance"]


def test_eee_reports_a_version():
    pr = _eee_provenance(True)
    assert pr["harness_version"] == "0.4.12"
    assert pr["harness_version_status"] == "reported"
    assert version_status_issues(pr) == []


def test_eee_reports_none_and_says_so():
    pr = _eee_provenance(False)
    assert "harness_version" not in pr
    assert pr["harness_version_status"] == "not_reported"
    assert pr["harness_version_status_reason"]
    assert version_status_issues(pr) == []


def test_every_named_field_is_exercised_by_some_adapter_test():
    """A named set that grows without a producer test would re-open exactly the gap these tests
    close. This binds the two: every member of REPORTED_VERSION_FIELDS must appear in a status
    written by a real adapter above, not merely in a hand-built dict."""
    gesehen = set()
    for provenance in (_lm_eval_claim(True), _promptfoo_claim(True), _inspect_claim(True),
                       _eee_provenance(True)):
        gesehen |= {k[: -len("_status")] for k in provenance if k.endswith("_status")}
    fehlend = set(REPORTED_VERSION_FIELDS) - gesehen
    assert not fehlend, f"no adapter test writes a status for: {sorted(fehlend)}"


# --- Jury lens 1 (2026-08-26): two findings, one held, one did not ---------------------------
#
# FINDING 1 HELD AND IT WAS THE SERIOUS ONE. The first version matched EVERY provenance key
# ending in `_status`, so an unrelated `run_status` or `scorer_status` in the same block produced
# a FALSE finding. A verifier that invents a finding on a field it was never asked about is worse
# than one that misses something: it makes a VALID receipt look non-conformant, which is exactly
# the failure this product exists against, pointed the other way.
#
# FINDING 2 DID NOT HOLD. The jury argued that a provenance with no status at all should be
# rejected. It must not be: the change is additive and existing receipts stay valid — that is a
# stated requirement of the release, not an oversight. Requiring a status would invalidate every
# receipt ever issued. The test below nails that down so a later reading of the jury's report
# cannot quietly turn it into a change.
#
# A THIRD came from attacking the code myself after the jury answered: a non-dict provenance
# RAISED instead of reporting.


def test_an_unrelated_status_field_is_not_a_version_status():
    """The false-positive class. `run` does not end in `_version`, so it is none of our business."""
    for prov in ({"run_status": "active"}, {"scorer_status": "llm"},
                 {"anchor_status": "confirmed"}, {"_status": "x"}):
        assert version_status_issues(prov) == [], prov


def test_an_unrelated_status_does_not_mask_a_real_one():
    """The neighbour must neither create a finding nor swallow one."""
    got = version_status_issues({"run_status": "done", "harness_version_status": "maybe"})
    assert len(got) == 1 and "harness_version_status" in got[0], got


def test_the_rule_governs_a_NAMED_set_not_every_field_ending_in_version():
    """BERICHTIGT durch Jury-Linse 1, Runde 2 — der Reviewer hatte das bessere Argument.

    Die erste Fassung liess jedes Feld zu, dessen Name auf `_version` endet, mit der Begruendung,
    ein kuenftiges `foo_version` sei dann ohne Codeaenderung gedeckt. Das ueberzieht: `schema_version`
    endet ebenfalls so und ist KEIN von der Harness gemeldetes Feld. Fuer einen Verifier sind die
    beiden Fehlerrichtungen nicht gleich — ein erfundener Fund laesst einen gueltigen Beleg
    unkonform aussehen, ein uebersehenes Feld erzeugt nur keinen Fund. Also die enge Regel.
    """
    assert version_status_issues({"schema_version_status": "v1"}) == []
    assert version_status_issues({"foo_version_status": "maybe"}) == []
    for f in REPORTED_VERSION_FIELDS:
        got = version_status_issues({f"{f}_status": "maybe"})
        assert got and f in got[0], f


def test_the_writer_validates_the_field_against_the_same_set():
    """Schreiber und Verifier duerfen nicht in zwei Vorstellungen der Klasse auseinanderlaufen:
    ein Tippfehler im Adapter erzeugt sonst still einen Status, den nie jemand prueft."""
    with pytest.raises(ValueError, match="not a reported-version field"):
        bind_reported_version({}, "harnes_version", "1.0", reason="x")


def test_the_writer_does_not_create_the_contradiction_it_warns_about():
    """Zweimal gerufen — erst mit Wert, dann ohne — liess die vorige Fassung das Versionsfeld
    neben einem not_reported-Status stehen. Der Verifier fing es, aber ein Schreiber, der einen
    von seinem eigenen Verifier abgelehnten Block erzeugt, ist selbst der Defekt."""
    p = {}
    bind_reported_version(p, "harness_version", "1.0", reason="unused")
    bind_reported_version(p, "harness_version", None, reason="nothing reported")
    assert "harness_version" not in p, p
    assert p["harness_version_status"] == "not_reported"
    assert version_status_issues(p) == []


def test_a_receipt_without_any_status_stays_valid():
    """ADDITIVE, and this is a requirement rather than an omission: every receipt issued before
    5.0.0 carries no status, and demanding one would invalidate all of them."""
    assert version_status_issues({"harness": "lm-eval", "harness_version": "0.4.12"}) == []
    assert version_status_issues({}) == []


def test_a_non_dict_provenance_is_reported_not_raised():
    """A verifier must report, never crash: a traceback here would abort the verification of an
    otherwise valid bundle."""
    for bad in (None, 5, [], "x", True):
        got = version_status_issues(bad)
        assert got and "must be an object" in got[0], (bad, got)


def test_a_non_string_key_does_not_break_the_scan():
    assert version_status_issues({1: "x", "harness_version_status": "reported",
                                  "harness_version": "1.0"}) == []
