"""Z405 part 3 (DECISIONS.md D57): the reconciliation joins decisions and outcomes and computes M1 to M8.

The two cases the order requires, each checkable offline with the two public keys and the files alone: an allowed push
that arrives with the same bytes on the same surface, and a deliberately refused push with its receipt and no effect.
Then the counter-probes, each found: a refused push that arrives anyway (M6), an effect without an approval (M5),
other bytes (M2), another surface (M3), an outcome that points to a foreign decision, a changed receipt. The decisions
come from the gate of part 1, the outcomes from the observer of part 2, the API answers from recorded files.

The reconciliation applies the profile the records keep, and that profile needs the decision verifier of main 22aa954e
(verify_decision_receipt with now=). An interpreter whose proofbundle does not have it skips this file and says so;
the records keep the verifier the pilot runs with (contract, section 8). Red at fc6663ed, where reconcile.py does not
exist.
"""
from __future__ import annotations

import base64
import inspect
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

import test_plugin_z405_observer as o
from proofbundle.decision import verify_decision_receipt

p1, pd, pr, gate = o.p1, o.pd, o.pr, o.gate
sys.path.insert(0, str(o.PILOT))
import reconcile as rc  # noqa: E402

sys.path.pop(0)

pytestmark = pytest.mark.skipif("now" not in inspect.signature(verify_decision_receipt).parameters,
                                reason="the profile github-write/1 needs the decision verifier of main 22aa954e "
                                       "(verify_decision_receipt with now=); this proofbundle does not have it")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path):
    return pd.env.__wrapped__(tmp_path)


def result_of(records: pathlib.Path) -> dict:
    return rc.reconcile(pr.Records(records))


def only(result: dict, **where) -> dict:
    (row,) = [r for r in result["decisions"] if all(r.get(k) == v for k, v in where.items())]
    return row


def observe(records, tmp_path, events, start, name="run-1"):
    folder = o.recorded(tmp_path, events, name=f"recorded-{name}")
    return o.run_observer(records, folder, start, o.now_plus(120), run=name)


# --- the two required cases ---------------------------------------------------------------------------------------

def test_required_an_allowed_push_arrives_with_the_same_bytes_on_the_same_surface(env, tmp_path):
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))], start)
    result = result_of(records)
    row = only(result, verdict="ALLOW")
    assert row["class"] == "reconciled: approved and arrived as approved", row
    assert (row["M1"], row["M2"], row["M3"], row["M4"], row["M8"]) == ("arrived", "identical", "same", "yes", 1)
    assert isinstance(row["M7"], float) and row["M7"] >= 0
    assert row["profile"] == "accepted", row["profile_reasons"]
    assert (result["M5"], result["M6"], result["unverified_receipts"]) == (0, 0, [])


def test_required_a_refused_push_has_its_receipt_and_no_effect(env, tmp_path):
    start = o.now_plus(-60)
    r = pd.Repo(tmp_path)
    r.make("missing")
    records = o.start_records(env, tmp_path)
    assert p1.level2(env, r.path).returncode == 1
    observe(records, tmp_path, [], start)
    result = result_of(records)
    row = only(result, verdict="DENY")
    assert row["class"] == "reconciled: refused and not arrived" and row["M1"] == "not arrived"
    assert (row["M2"], row["M3"], row["M4"]) == ("not measured",) * 3
    assert row["profile"] == "not accepted" and (result["M5"], result["M6"]) == (0, 0)


def test_required_cases_rerun_offline_from_the_files_alone(env, tmp_path):
    """Criterion 4: a copy of the records, in a fresh process, with only the files and the two public keys they keep,
    gives the same bytes. No private key is among the files."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))], start)
    first = subprocess.run([sys.executable, str(o.PILOT / "reconcile.py"), "--records", str(records)],
                           capture_output=True, text=True, timeout=300, check=False)
    copy = tmp_path / "elsewhere" / "records"
    shutil.copytree(records, copy, ignore=shutil.ignore_patterns("reconciliation"))
    again = subprocess.run([sys.executable, str(o.PILOT / "reconcile.py"), "--records", str(copy)],
                           capture_output=True, text=True, timeout=300, check=False, cwd=str(tmp_path))
    assert first.returncode == again.returncode == 0, (first.stderr, again.stderr)
    assert (records / "reconciliation" / "reconciliation.json").read_bytes() == \
        (copy / "reconciliation" / "reconciliation.json").read_bytes()
    assert "reconciled: approved and arrived as approved" in again.stdout
    for path in copy.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"PRIVATE KEY" not in data and b"probe key, never" not in data, path


# --- the counter-probes, each found --------------------------------------------------------------------------------

def test_counter_a_refused_push_that_arrives_counts_under_m6(env, tmp_path):
    start = o.now_plus(-60)
    r = pd.Repo(tmp_path)
    r.make("missing")
    records = o.start_records(env, tmp_path)
    p1.level2(env, r.path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, pd._rev(r.path, "HEAD"), o.now_plus(0))], start)
    result = result_of(records)
    assert only(result, verdict="DENY")["class"] == "refused but arrived"
    assert (result["M5"], result["M6"]) == (1, 1)


def test_counter_an_effect_without_an_approval_counts_under_m5(env, tmp_path):
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0)),
                                o.push_event(2, o.AGENT_GITHUB_ID, "a" * 40, o.now_plus(0), ref="refs/heads/other")],
            start)
    result = result_of(records)
    assert result["M5"] == 1 and result["M6"] == 0
    assert [u["target"] for u in result["unapproved_effects"]] == ["https://github.com/b7n0de/pilot-probe#refs/heads/other"]
    assert only(result, verdict="ALLOW")["class"] == "reconciled: approved and arrived as approved"


def test_counter_other_bytes_are_found_under_m2(env, tmp_path):
    start = o.now_plus(-60)
    records, _sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, "b" * 40, o.now_plus(0))], start)
    row = only(result_of(records), verdict="ALLOW")
    assert (row["M1"], row["M2"], row["M3"]) == ("arrived", "different", "same")
    assert row["class"] == "approved, arrived with other bytes" and row["profile"] == "not accepted"


def test_counter_another_surface_is_found_under_m3(env, tmp_path):
    """The contract's first example: the approved bytes of a reply in a review thread arrive as a comment on the pull
    request's conversation. The gate asks on both surfaces today and approves neither, so the approval is issued by the
    gate's own issuance function, as the gate would issue it under a rule that frees the reply."""
    start = o.now_plus(-60)
    records = o.start_records(env, tmp_path)
    config = gate._pilot_config(env)
    body = "Fixed in the next push.\n\nWritten by an AI session of b7n0de under owner review."
    action = {"surface": "github.reviewThreadReply", "target": "https://github.com/b7n0de/pilot-probe/pull/7",
              "bytes": body.encode(), "media": "text/markdown"}
    gate._pilot_issue(config, env, action, "probe", "ALLOW", ["probe_rule"])
    observe(records, tmp_path, [o.comment_event(1, o.AGENT_GITHUB_ID, 7, body, o.now_plus(0))], start)
    row = only(result_of(records), verdict="ALLOW")
    assert (row["M1"], row["M2"], row["M3"]) == ("arrived", "identical", "different")
    assert row["class"] == "approved, arrived on another surface" and row["profile"] == "not accepted"


def test_counter_an_outcome_that_points_to_a_foreign_decision_is_found(env, tmp_path):
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    p1.level1(env, tmp_path / "r", p1.COMMENT.replace("b7n0de/proofbundle", "b7n0de/pilot-probe"))
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))], start)
    profile = pr.Records(records).profile()
    (path,) = [p for p in (records / "outcomes").glob("*.json") if not p.name.endswith(".scope.json")]
    foreign = [e for e in p1.receipts_in(records) if p1.predicate_of(e)["decision"]["verdict"] == "ESCALATE"][0]
    predicate = json.loads(base64.b64decode(json.loads(path.read_text())["payload"]))["predicate"]
    predicate["decisionRef"] = {"sha256": profile.content_root(foreign)}
    path.write_text(json.dumps(profile.sign_outcome(predicate, o.observer_key())), encoding="utf-8")
    result = result_of(records)
    allowed, escalated = only(result, verdict="ALLOW"), only(result, verdict="ESCALATE")
    assert allowed["class"] == escalated["class"] == "outcome and records disagree"
    assert allowed["notes"] == ["the records match an effect to this decision, and no outcome is bound to it"]
    assert escalated["profile"] == "not accepted"


def test_counter_a_changed_receipt_is_found(env, tmp_path):
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))], start)
    (path,) = (records / "decisions").glob("*.json")
    envelope = json.loads(path.read_text())
    raw = bytearray(base64.b64decode(envelope["payload"]))
    raw[raw.index(b"ALLOW")] = ord("B")
    envelope["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    path.write_text(json.dumps(envelope), encoding="utf-8")
    result = result_of(records)
    (row,) = result["decisions"]
    assert row["class"] == "receipt does not verify" and row["profile"] == "not accepted"
    assert result["unverified_receipts"] == [f"decisions/{path.name}"] and result["M5"] == 1


# --- the measures' own values -------------------------------------------------------------------------------------

def test_without_a_run_nothing_is_counted_as_none_found(env, tmp_path):
    records, _sent, _decision = o.allowed_push(env, tmp_path)
    result = result_of(records)
    assert (result["M5"], result["M6"]) == ("not measured", "not measured")
    row = only(result, verdict="ALLOW")
    assert (row["M1"], row["M7"], row["class"]) == ("not yet observed", "no observation", "approved, not yet observed")


def test_a_retry_counts_under_m8(env, tmp_path):
    start = o.now_plus(-60)
    r = pd.Repo(tmp_path)
    r.make("valid")
    records = o.start_records(env, tmp_path)
    p1.level2(env, r.path)
    p1.level2(env, r.path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, pd._rev(r.path, "HEAD"), o.now_plus(0))], start)
    rows = result_of(records)["decisions"]
    assert [row["M8"] for row in rows] == [2, 2]
    assert sorted(row["M1"] for row in rows) == ["arrived", "not arrived"]   # one effect takes one approval


def test_a_missing_closing_line_is_found_under_m4(env, tmp_path):
    start = o.now_plus(-60)
    records = o.start_records(env, tmp_path)
    config = gate._pilot_config(env)
    action = {"surface": "github.conversationComment", "target": "https://github.com/b7n0de/pilot-probe/pull/7",
              "bytes": b"No closing line here.", "media": "text/markdown"}
    gate._pilot_issue(config, env, action, "probe", "ALLOW", ["probe_rule"])
    observe(records, tmp_path, [o.comment_event(1, o.AGENT_GITHUB_ID, 7, "No closing line here.", o.now_plus(0))],
            start)
    row = only(result_of(records), verdict="ALLOW")
    assert (row["M2"], row["M3"], row["M4"]) == ("identical", "same", "no")
    assert row["class"] == "approved, arrived without the closing lines"


# --- the rules of the match, found by mutants of the first mutation run -------------------------------------------

def test_the_match_reads_the_identity_an_agent_does_not_take_another_agents_approval(env, tmp_path):
    """Mutant A05: an effect of a second agent on the same target with the same bytes takes no approval of the first."""
    start = o.now_plus(-60)
    roster = o.ROSTER + [{"id": 9000003, "login": "pilot-agent-b", "agent": "agent:session-b"}]
    r = pd.Repo(tmp_path)
    r.make("valid")
    records = o.start_records(env, tmp_path, roster=roster)
    p1.level2(env, r.path)
    observe(records, tmp_path, [o.push_event(1, 9000003, pd._rev(r.path, "HEAD"), o.now_plus(0))], start)
    result = result_of(records)
    assert only(result, verdict="ALLOW")["M1"] == "not arrived" and result["M5"] == 1


def test_an_effect_equal_to_an_approval_and_a_refusal_is_ambiguous(env, tmp_path):
    """Mutant A06: the same action approved and refused, one effect equal to both: `ambiguous` for each, counted under
    M6 because one was refused, and taken by the earliest decided, the approval, so not under M5."""
    start = o.now_plus(-60)
    records = o.start_records(env, tmp_path)
    config = gate._pilot_config(env)
    body = "Ready for review."
    action = {"surface": "github.conversationComment", "target": "https://github.com/b7n0de/pilot-probe/pull/7",
              "bytes": body.encode(), "media": "text/markdown"}
    gate._pilot_issue(config, env, action, "probe", "ALLOW", ["probe_rule"])
    gate._pilot_issue(config, env, action, "probe", "DENY", ["probe_rule"])
    observe(records, tmp_path, [o.comment_event(1, o.AGENT_GITHUB_ID, 7, body, o.now_plus(0))], start)
    result = result_of(records)
    assert {r["M1"] for r in result["decisions"]} == {"ambiguous"}
    assert {r["class"] for r in result["decisions"]} == {"ambiguous effect"}
    assert (result["M5"], result["M6"]) == (0, 1)


def test_an_effect_before_its_approval_is_no_effect_of_it(env, tmp_path):
    """Mutant A11: GitHub dates the effect before the decision. It counts under M5, the profile does not accept it, and
    the class says so instead of reconciled."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, tmp_path, [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(-30))], start)
    result = result_of(records)
    row = only(result, verdict="ALLOW")
    assert row["class"] == "approved, arrived before the approval" and row["profile"] == "not accepted"
    assert result["M5"] == 1


def test_an_event_two_runs_list_is_one_effect(env, tmp_path):
    """Mutant A12: the events API lists an event in every run until it falls out; two runs read it once."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    events = [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0)),
              o.push_event(2, o.AGENT_GITHUB_ID, "a" * 40, o.now_plus(0), ref="refs/heads/other")]
    observe(records, tmp_path, events, start, name="run-1")
    observe(records, tmp_path, events, start, name="run-2")
    result = result_of(records)
    assert result["runs"] == ["run-1", "run-2"] and (result["M5"], result["M6"]) == (1, 0)
    assert only(result, verdict="ALLOW")["class"] == "reconciled: approved and arrived as approved"
