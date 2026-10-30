"""D121 (Codex thread on pull request 403, observer.py): one GitHub event is one effect, and the observer signs what the
reconciliation matches.

The reconciliation read an event that two runs list once (D57, mutant A12), the observer read it as often as a response
listed it: on two pages of one run (the events API shifts its list when an event arrives between two requests), for a
repository named twice, and in a second run whose window overlaps the first. One write then took two decisions of a
retry, or got a second signed outcome, and the reconciliation no longer reproduced the observer's outcomes. The observer
also matched each run over its own window, the reconciliation over the window of every run, so an effect of a later run
that took a decision of an earlier window got no outcome while the reconciliation matched it.

Now both read the effects through pilot_records.effects_of_runs and match over pilot_records.window_of_runs: the
observer matches over every run the records keep, its own included, and signs an outcome only for an effect its own run
lists first that takes a decision no outcome is bound to yet. Red at 2081257c, where the observer reads its own run alone.
"""
from __future__ import annotations

import base64
import inspect
import json
import pathlib
import sys

import pytest

import test_plugin_z405_observer as o
from proofbundle.decision import verify_decision_receipt

p1, pd, pr = o.p1, o.pd, o.pr
sys.path.insert(0, str(o.PILOT))
import reconcile as rc  # noqa: E402

sys.path.pop(0)

#: The reconciliation applies the profile the records keep, which needs the decision verifier with now= (as in
#: tests/test_plugin_z405_reconcile.py); the observer's own cases run without it.
needs_reconcile = pytest.mark.skipif("now" not in inspect.signature(verify_decision_receipt).parameters,
                                     reason="the profile github-write/1 needs the decision verifier with now=")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return pd.env.__wrapped__(tmp_path, monkeypatch)


def pages(tmp_path: pathlib.Path, name: str, *listed: list[dict]) -> pathlib.Path:
    """A folder of recorded responses, one page of events each, then an empty page as GitHub answers past the end."""
    folder = tmp_path / name
    folder.mkdir()
    index = {}
    for n, events in enumerate([*listed, []][:o.observer.EVENT_PAGES], start=1):
        (folder / f"page{n}.json").write_bytes(json.dumps(events, indent=2).encode("utf-8"))
        index[f"/repos/{o.REPO}/events?per_page=100&page={n}"] = {"status": 200, "file": f"page{n}.json"}
    (folder / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return folder


def observe(records: pathlib.Path, folder: pathlib.Path, run: str, start: str, end: str,
            repos: list[str] | None = None) -> dict:
    return o.observer.observe(pr.Records(records), run, o.observer.RecordedTransport(folder),
                              [o.REPO] if repos is None else repos, start, end, o.observer_key())


def retried_push(env, tmp_path) -> tuple[pathlib.Path, str]:
    """The same push decided twice at Level 2 (a retry, M8 = 2): two approvals one write can take."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    records = o.start_records(env, tmp_path)
    assert p1.level2(env, r.path).returncode == 0
    assert p1.level2(env, r.path).returncode == 0
    assert len(p1.receipts_in(records)) == 2
    return records, pd._rev(r.path, "HEAD")


def bound_refs(records: pathlib.Path) -> list[str]:
    """The decision each outcome on disk is bound to, by its content root, one entry per outcome."""
    return [o.statement(envelope)["predicate"]["decisionRef"]["sha256"] for envelope, _scope in o.outcomes(records)]


# --- the cases of the thread ---------------------------------------------------------------------------------------

def test_an_event_on_two_pages_is_one_effect(env, tmp_path):
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    event = o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))
    summary = observe(records, pages(tmp_path, "shifted", [event], [event]), "run-1", start, o.now_plus(120))
    assert (summary["effects"], summary["M5"], summary["M6"], len(summary["outcomes"])) == (1, 0, 0, 1), summary


def test_an_event_on_two_pages_takes_one_decision_of_a_retry(env, tmp_path):
    """The thread's first effect: the same event listed twice took both approvals of a retry and got two outcomes."""
    start = o.now_plus(-60)
    records, sent = retried_push(env, tmp_path)
    event = o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))
    summary = observe(records, pages(tmp_path, "shifted", [event], [event]), "run-1", start, o.now_plus(120))
    assert (summary["effects"], len(summary["outcomes"])) == (1, 1), summary
    assert len(bound_refs(records)) == 1


def test_a_repository_named_twice_is_read_once(env, tmp_path):
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    folder = pages(tmp_path, "twice", [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))])
    summary = observe(records, folder, "run-1", start, o.now_plus(120), repos=[o.REPO, o.REPO])
    assert summary["requests"] == 4   # every response is kept as returned, the repository's twice
    assert (summary["effects"], summary["M5"], len(summary["outcomes"])) == (1, 0, 1), summary


@pytest.mark.parametrize("second", ["run-2", "a-run-named-before"])
def test_a_second_run_that_lists_the_event_again_signs_no_second_outcome(env, tmp_path, second):
    """Overlapping windows: the events API lists an event in every run until it falls out. A later run, whatever its
    name sorts before or after, signs no outcome for an event an earlier run took."""
    start = o.now_plus(-60)
    records, sent, decision = o.allowed_push(env, tmp_path)
    event = o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))
    first = observe(records, pages(tmp_path, "first", [event]), "run-1", start, o.now_plus(120))
    again = observe(records, pages(tmp_path, "again", [event]), second, start, o.now_plus(120))
    assert len(first["outcomes"]) == 1 and again["outcomes"] == [], again
    assert (again["M5"], again["M6"]) == (0, 0)
    assert bound_refs(records) == [pr.Records(records).profile().content_root(decision)]


# --- the window the reconciliation reads -----------------------------------------------------------------------------

@needs_reconcile
def test_the_observer_matches_over_the_window_the_reconciliation_reads(env, tmp_path):
    """A neighbour of the class: the reconciliation matches over the window of every run. An effect of a second run that
    takes a decision of the first window got no outcome at 2081257c, and the reconciliation named it so ("no outcome
    is bound to it")."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    observe(records, pages(tmp_path, "nothing-yet"), "run-1", start, o.now_plus(20))
    later = observe(records, pages(tmp_path, "arrived", [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(60))]),
                    "run-2", o.now_plus(30), o.now_plus(300))
    assert (later["effects"], later["M5"], len(later["outcomes"])) == (1, 0, 1), later
    row = rc.reconcile(pr.Records(records))["decisions"][0]
    assert (row["class"], row["notes"], row["outcome"]) == ("reconciled: approved and arrived as approved", [],
                                                             "outcomes/run-2-0001.json"), row


# --- the class over its triggers: every outcome is one the reconciliation reproduces --------------------------------

SCENARIOS = [(page, repo, second, retry) for page in (False, True) for repo in (False, True)
             for second in (None, "z-after", "a-before") for retry in (False, True)]


@needs_reconcile
@pytest.mark.parametrize("page,repo,second,retry", SCENARIOS,
                         ids=[f"page{int(p)}-repo{int(r)}-{s or 'one'}-retry{int(t)}" for p, r, s, t in SCENARIOS])
def test_every_outcome_is_one_the_reconciliation_reproduces(env, tmp_path, page, repo, second, retry):
    """One push, listed once or on two pages, for its repository once or twice, in one run or again in a second run that
    sorts after or before the first, with one approval or a retry: one outcome, bound to the decision the
    reconciliation matches the push to, and no row of the reconciliation that disagrees with an outcome."""
    start = o.now_plus(-60)
    if retry:
        records, sent = retried_push(env, tmp_path)
    else:
        records, sent, _decision = o.allowed_push(env, tmp_path)
    event = o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))
    listed = [[event], [event]] if page else [[event]]
    repos = [o.REPO, o.REPO] if repo else [o.REPO]
    observe(records, pages(tmp_path, "first", *listed), "m-first", start, o.now_plus(120), repos)
    if second:
        observe(records, pages(tmp_path, "second", *listed), second, start, o.now_plus(120), repos)
    result = rc.reconcile(pr.Records(records))
    refs = bound_refs(records)
    assert len(refs) == len(set(refs)) == 1, refs
    arrived = [r for r in result["decisions"] if r["M1"] == "arrived"]
    assert len(arrived) == 1 and arrived[0]["outcome"] is not None, result["decisions"]
    assert [r["notes"] for r in result["decisions"]] == [[] for _ in result["decisions"]], result["decisions"]
    assert arrived[0]["class"] == "reconciled: approved and arrived as approved"
    assert (result["M5"], result["M6"]) == (0, 0)


def test_a_second_run_signs_the_new_event_it_lists(env, tmp_path):
    """A second run that lists the first event again and a new one signs the new one, bound to the retry's second
    approval. At 2081257c it signed both, the new one bound to the first approval a second time."""
    start = o.now_plus(-60)
    records, sent = retried_push(env, tmp_path)
    first_event = o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))
    observe(records, pages(tmp_path, "first", [first_event]), "run-1", start, o.now_plus(120))
    again = observe(records, pages(tmp_path, "again", [o.push_event(2, o.AGENT_GITHUB_ID, sent, o.now_plus(1)),
                                                         first_event]), "run-2", start, o.now_plus(120))
    assert (again["effects"], len(again["outcomes"])) == (1, 1), again
    assert len(set(bound_refs(records))) == 2


def comment_decisions(env, tmp_path, body: str, times: int) -> pathlib.Path:
    """The records with `times` approvals of the same comment (a retry), issued by the gate's own function."""
    records = o.start_records(env, tmp_path)
    config = o.gate._pilot_config(env)
    action = {"surface": "github.conversationComment", "target": "https://github.com/b7n0de/pilot-probe/pull/7",
              "bytes": body.encode(), "media": "text/markdown"}
    for _ in range(times):
        o.gate._pilot_issue(config, env, action, "probe", "ALLOW", ["probe_rule"])
    return records


@needs_reconcile
def test_a_run_that_ran_later_but_sorts_first_reorders_nothing(env, tmp_path):
    """Found by the lens on D121 (T1 a): the records kept the runs in the order of their names. Run b-first signs the
    first comment, bound to the first approval of a retry; run a-later lists a second comment of the same bytes and the
    first again. Read in the order of the names, a-later came first, the second comment took the first approval and the
    reconciliation named the outcome of b-first as one that shows no effect."""
    start = o.now_plus(-60)
    body = "Ready for review."
    records = comment_decisions(env, tmp_path, body, 2)
    c1 = o.comment_event(1, o.AGENT_GITHUB_ID, 7, body, o.now_plus(0))
    c2 = o.comment_event(2, o.AGENT_GITHUB_ID, 7, body, o.now_plus(1))
    observe(records, pages(tmp_path, "first", [c1]), "b-first", start, o.now_plus(120))
    observe(records, pages(tmp_path, "later", [c2, c1]), "a-later", start, o.now_plus(120))
    result = rc.reconcile(pr.Records(records))
    assert result["runs"] == ["b-first", "a-later"]
    assert [r["notes"] for r in result["decisions"]] == [[], []], result["decisions"]
    assert sorted(r["outcome"] for r in result["decisions"]) == ["outcomes/a-later-0001.json",
                                                                 "outcomes/b-first-0001.json"]
    refs = bound_refs(records)
    assert len(refs) == len(set(refs)) == 2


@needs_reconcile
def test_the_summary_counts_the_runs_own_effects(env, tmp_path):
    """Found by the lens on D121 (T6): a run's M5 and M6 count its own effects, not those of every run."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    first = observe(records, pages(tmp_path, "unasked", [o.comment_event(1, o.AGENT_GITHUB_ID, 279, "unasked",
                                                                          o.now_plus(0))]), "run-1", start,
                    o.now_plus(120))
    assert (first["effects"], first["M5"]) == (1, 1)
    later = observe(records, pages(tmp_path, "push", [o.push_event(2, o.AGENT_GITHUB_ID, sent, o.now_plus(1))]),
                    "run-2", start, o.now_plus(120))
    assert (later["effects"], later["M5"], later["M6"], len(later["outcomes"])) == (1, 0, 0, 1), later
    assert rc.reconcile(pr.Records(records))["M5"] == 1


def test_records_that_do_not_read_leave_no_half_run(env, tmp_path):
    """Found by the lens on D121 (T3): the observer reads the outcomes and the earlier runs before it writes a byte.
    An outcome that is no JSON, or a response of an earlier run that is gone, refuses the run and writes nothing."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    event = o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))
    observe(records, pages(tmp_path, "first", [event]), "run-1", start, o.now_plus(120))
    broken = records / "outcomes" / "torn.json"
    broken.write_text('{"payloadType": "application/vnd.in-toto+json", "payl', encoding="utf-8")
    with pytest.raises(ValueError):
        observe(records, pages(tmp_path, "second", [event]), "run-2", start, o.now_plus(120))
    assert not (records / "api" / "run-2").exists()
    broken.rename(tmp_path / "torn.json")
    (records / "api" / "run-1" / "responses" / "0001.json").rename(tmp_path / "gone.json")
    with pytest.raises(OSError):
        observe(records, pages(tmp_path, "third", [event]), "run-3", start, o.now_plus(120))
    assert not (records / "api" / "run-3").exists()


def test_an_outcome_whose_statement_is_no_object_binds_no_decision(env, tmp_path):
    """The lens's second form (T3): a payload that reads as a JSON list raised AttributeError in the observer, whose
    main does not catch it; it binds no decision now, and the run signs the effect it finds."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    (records / "outcomes").mkdir(exist_ok=True)
    (records / "outcomes" / "list.json").write_text(json.dumps(
        {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(b"[]").decode(),
         "signatures": []}), encoding="utf-8")
    summary = observe(records, pages(tmp_path, "first", [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))]),
                      "run-1", start, o.now_plus(120))
    assert len(summary["outcomes"]) == 1


def test_a_run_names_at_least_one_repository(env, tmp_path):
    records, _sent, _decision = o.allowed_push(env, tmp_path)
    with pytest.raises(ValueError, match="at least one repository"):
        observe(records, pages(tmp_path, "none"), "run-1", o.now_plus(-60), o.now_plus(120), repos=[])
    assert not (records / "api" / "run-1").exists()


def test_the_reconciliation_runs_here():
    """The cases marked needs_reconcile skip where the decision verifier lacks now=; a skip is no measurement, so this
    case is red there instead of silent."""
    assert "now" in inspect.signature(verify_decision_receipt).parameters


# --- counter cases, each with the answer it had at 2081257c ----------------------------------------------------------

def test_two_events_on_two_pages_stay_two_effects(env, tmp_path):
    """Two writes are two effects, wherever they are listed: the second push takes no approval and counts under M5."""
    start = o.now_plus(-60)
    records, sent, _decision = o.allowed_push(env, tmp_path)
    folder = pages(tmp_path, "two", [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))],
                   [o.push_event(2, o.AGENT_GITHUB_ID, "a" * 40, o.now_plus(0), ref="refs/heads/other")])
    summary = observe(records, folder, "run-1", start, o.now_plus(120))
    assert (summary["effects"], summary["M5"], len(summary["outcomes"])) == (2, 1, 1), summary


def test_the_outcome_ids_count_the_runs_own_outcomes(env, tmp_path):
    start = o.now_plus(-60)
    records, sent = retried_push(env, tmp_path)
    observe(records, pages(tmp_path, "first", [o.push_event(1, o.AGENT_GITHUB_ID, sent, o.now_plus(0))]), "run-1",
            start, o.now_plus(120))
    again = observe(records, pages(tmp_path, "again", [o.push_event(2, o.AGENT_GITHUB_ID, sent, o.now_plus(1))]),
                    "run-2", start, o.now_plus(120))
    assert [x["outcomeId"] for x in again["outcomes"]] == ["run-2-0001"]
    names = sorted(p.name for p in (records / "outcomes").glob("*.json") if not p.name.endswith(".scope.json"))
    assert names == ["run-1-0001.json", "run-2-0001.json"]
    assert all(json.loads(base64.b64decode(json.loads((records / "outcomes" / n).read_text())["payload"]))
               ["predicate"]["outcomeId"] == n[:-5] for n in names)
