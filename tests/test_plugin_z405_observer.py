"""Z405 part 2 (DECISIONS.md D56): the observer reads what the GitHub API shows and signs an outcome bound to the decision.

The records of the pilot are made as the runbook makes them: pilot_records.py start keeps the contract, the profile,
AGENTS.md, the closing rules, the roster and the two public keys before the first decision; the gate of part 1 writes
its decisions into the same folder; the observer reads the events of the repository over a window, keeps every
response as returned, matches the effects of the roster's identities to the decisions (contract, section 5) and signs an
action-outcome/v0.1 per effect that takes a decision, bound to it by its content root. Here the API answers from
recorded files in the shapes GitHub documents for its events, made by these tests; the live path is the same code
against a local server, and against GitHub it runs first in the pilot on account A. The keys are probe keys.

Red at 2dcaa1d4, where the observer and the records do not exist.
"""
from __future__ import annotations

import base64
import datetime
import http.server
import json
import pathlib
import shutil
import sys
import threading

import pytest

import test_plugin_z405_decision_receipt as p1
from proofbundle.outcome import verify_outcome_receipt

pd, gate = p1.pd, p1.gate
ROOT = p1.ROOT
PILOT = ROOT / "plugins" / "proofbundle" / "pilot"
GATE_FILE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"
sys.path.insert(0, str(PILOT))
import observer  # noqa: E402
import pilot_records as pr  # noqa: E402
import probe_signer  # noqa: E402

sys.path.pop(0)

OBSERVER_LABEL = "z405 probe observer"
REPO = "b7n0de/pilot-probe"
AGENT_GITHUB_ID, AGENT_LOGIN = 9000001, "pilot-agent-a"
PERSON_GITHUB_ID = 9000002
ROSTER = [{"id": AGENT_GITHUB_ID, "login": AGENT_LOGIN, "agent": p1.AGENT_ID}]


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return pd.env.__wrapped__(tmp_path, monkeypatch)


def utc(seconds: float) -> str:
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_plus(seconds: float) -> str:
    return utc(datetime.datetime.now(datetime.timezone.utc).timestamp() + seconds)


def start_records(env: dict, tmp_path: pathlib.Path, roster: list | None = None) -> pathlib.Path:
    """The records folder as the runbook starts it, and the gate's pilot.json pointing its receipts there."""
    records = tmp_path / "records"
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "closing_rules.json").write_text(json.dumps(p1.CLOSING_RULES, sort_keys=True), encoding="utf-8")
    (sources / "roster.json").write_text(json.dumps(roster or ROSTER), encoding="utf-8")
    (sources / "verifier-stand-in.txt").write_text("the verifier's distribution file is kept here in the pilot\n",
                                                   encoding="utf-8")
    (sources / "environment.json").write_text(json.dumps({"python": sys.version.split()[0]}), encoding="utf-8")
    pr.start(records, contract=ROOT / "docs" / "pilot" / "pilot_contract.md",
             profile=ROOT / "tools" / "pilot" / "github_write_profile.py", agents=ROOT / "AGENTS.md",
             closing_rules=sources / "closing_rules.json", roster=sources / "roster.json",
             gate_public=p1.public_key(), observer_public=probe_signer.public_hex(observer_key()),
             verifier=sources / "verifier-stand-in.txt", environment=sources / "environment.json",
             gate_id=p1.GATE_ID, observer_id=p1.OBSERVER_ID,
             gate=GATE_FILE)
    receipts = p1.pilot_on(env, tmp_path)
    config_path = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.update(receipts=str(records), closing_rules=str(records / "closing_rules.json"))
    config_path.write_text(json.dumps(config), encoding="utf-8")
    assert not receipts.exists()
    return records


def observer_key():
    return probe_signer.probe_key(OBSERVER_LABEL)


def push_event(event_id: int, actor: int, head: str, at: str, ref: str = "refs/heads/main", repo: str = REPO) -> dict:
    """A PushEvent as GET /repos/{owner}/{repo}/events lists it (GitHub's documented shape)."""
    return {"id": str(event_id), "type": "PushEvent", "public": True, "created_at": at,
            "actor": {"id": actor, "login": AGENT_LOGIN if actor == AGENT_GITHUB_ID else "someone"},
            "repo": {"id": 1, "name": repo, "url": f"https://api.github.com/repos/{repo}"},
            "payload": {"repository_id": 1, "push_id": event_id, "ref": ref, "head": head, "before": "0" * 40}}


def comment_event(event_id: int, actor: int, number: int, body: str, at: str, repo: str = REPO) -> dict:
    return {"id": str(event_id), "type": "IssueCommentEvent", "public": True, "created_at": at,
            "actor": {"id": actor, "login": AGENT_LOGIN if actor == AGENT_GITHUB_ID else "someone"},
            "repo": {"id": 1, "name": repo},
            "payload": {"action": "created", "issue": {"number": number, "pull_request": {"url": "x"}},
                        "comment": {"id": 5851339484 + event_id, "body": body, "created_at": at,
                                    "user": {"id": actor}}}}


def recorded(tmp_path: pathlib.Path, events: list[dict], name: str = "recorded") -> pathlib.Path:
    """A folder of recorded responses: page 1 holds the events, page 2 is empty, as GitHub answers past the end."""
    folder = tmp_path / name
    folder.mkdir()
    (folder / "page1.json").write_bytes(json.dumps(events, indent=2).encode("utf-8"))
    (folder / "page2.json").write_bytes(b"[]")
    (folder / "index.json").write_text(json.dumps({
        f"/repos/{REPO}/events?per_page=100&page=1": {"status": 200, "file": "page1.json"},
        f"/repos/{REPO}/events?per_page=100&page=2": {"status": 200, "file": "page2.json"}}), encoding="utf-8")
    return folder


def run_observer(records: pathlib.Path, folder: pathlib.Path, start: str, end: str, run: str = "run-1") -> dict:
    return observer.observe(pr.Records(records), run, observer.RecordedTransport(folder), [REPO], start, end,
                            observer_key())


def outcomes(records: pathlib.Path) -> list[tuple[dict, dict]]:
    found = []
    for path in sorted((records / "outcomes").glob("*.json")):
        if not path.name.endswith(".scope.json"):
            found.append((json.loads(path.read_text(encoding="utf-8")),
                          json.loads(path.with_name(path.name[:-5] + ".scope.json").read_text(encoding="utf-8"))))
    return found


def statement(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))


def allowed_push(env, tmp_path) -> tuple[pathlib.Path, str, dict]:
    """A valid push decided at Level 2: the records, the commit it sends and its decision envelope."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    records = start_records(env, tmp_path)
    assert p1.level2(env, r.path).returncode == 0
    (decision,) = p1.receipts_in(records)
    return records, pd._rev(r.path, "HEAD"), decision


def test_an_allowed_push_that_arrives_gets_an_outcome_bound_to_its_decision(env, tmp_path):
    start = now_plus(-60)
    records, sent, decision = allowed_push(env, tmp_path)
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, sent, now_plus(0))])
    summary = run_observer(records, folder, start, now_plus(120))
    assert (summary["effects"], summary["M5"], summary["M6"]) == (1, 0, 0)
    ((envelope, scope),) = outcomes(records)
    profile = pr.Records(records).profile()
    root = profile.content_root(decision)
    nonce = p1.predicate_of(decision)["decisionId"]
    result = verify_outcome_receipt(envelope, bytes.fromhex(probe_signer.public_hex(observer_key())), strict=True,
                                    expected_decision_ref=root, expected_audience=p1.OBSERVER_ID,
                                    expected_nonce=nonce, require_derived_subject=True)
    assert result["ok"] is True and result["decision_bound"] is True, result
    pred = statement(envelope)["predicate"]
    approved = p1.predicate_of(decision)["proposedAction"]["parametersDigest"]["sha256"]
    assert pred["effectDigest"]["sha256"] == pred["requestedActionDigest"]["sha256"] == approved
    assert scope == {"surface": "git.push", "target": p1.PUSH_TARGET, "objectId": sent}
    assert pred["actualActionDigest"]["sha256"] == profile.scope_digest(scope)
    assert pred["status"] == "executed" and pred["executor"] == {"id": f"github:{AGENT_GITHUB_ID}"}


def test_every_response_is_kept_as_returned_with_the_time_it_was_asked(env, tmp_path):
    start = now_plus(-60)
    records, sent, _decision = allowed_push(env, tmp_path)
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, sent, now_plus(0))])
    run_observer(records, folder, start, now_plus(120))
    run = json.loads((records / "api" / "run-1" / "run.json").read_text(encoding="utf-8"))
    assert [r["path"] for r in run["requests"]] == [f"/repos/{REPO}/events?per_page=100&page=1",
                                                    f"/repos/{REPO}/events?per_page=100&page=2"]
    for request, source in zip(run["requests"], ("page1.json", "page2.json")):
        kept = (records / "api" / "run-1" / request["file"]).read_bytes()
        assert kept == (folder / source).read_bytes() and request["sha256"] == pr.sha256_hex(kept)
        assert pr.instant_key(request["requestedAt"]) is not None and request["status"] == 200
    assert run["window"] == {"start": start, "end": run["window"]["end"]} and run["transport"] == "recorded"


def test_an_effect_of_another_identity_or_outside_the_window_is_not_read(env, tmp_path):
    start = now_plus(-60)
    records, sent, _decision = allowed_push(env, tmp_path)
    folder = recorded(tmp_path, [push_event(1, PERSON_GITHUB_ID, sent, now_plus(0)),
                                 push_event(2, AGENT_GITHUB_ID, sent, now_plus(-3600))])
    summary = run_observer(records, folder, start, now_plus(120))
    assert (summary["effects"], summary["outcomes"], summary["M5"]) == (0, [], 0)   # a person's push is no agent write
    assert outcomes(records) == []


def test_a_refused_push_that_arrives_gets_an_outcome_and_counts_under_m6(env, tmp_path):
    start = now_plus(-60)
    r = pd.Repo(tmp_path)
    r.make("missing")
    records = start_records(env, tmp_path)
    assert p1.level2(env, r.path).returncode == 1
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, pd._rev(r.path, "HEAD"), now_plus(0))])
    summary = run_observer(records, folder, start, now_plus(120))
    assert (summary["M5"], summary["M6"], len(summary["outcomes"])) == (1, 1, 1)
    ((envelope, _scope),) = outcomes(records)
    (decision,) = p1.receipts_in(records)
    assert statement(envelope)["predicate"]["decisionRef"]["sha256"] == pr.Records(records).profile() \
        .content_root(decision)


def test_an_effect_without_a_decision_counts_under_m5_and_gets_no_outcome(env, tmp_path):
    start = now_plus(-60)
    records, _sent, _decision = allowed_push(env, tmp_path)
    folder = recorded(tmp_path, [comment_event(1, AGENT_GITHUB_ID, 279, "unasked", now_plus(0))])
    summary = run_observer(records, folder, start, now_plus(120))
    assert (summary["effects"], summary["M5"], summary["M6"], summary["outcomes"]) == (1, 1, 0, [])


def test_a_run_is_kept_as_it_was(env, tmp_path):
    start = now_plus(-60)
    records, sent, _decision = allowed_push(env, tmp_path)
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, sent, now_plus(0))])
    run_observer(records, folder, start, now_plus(120))
    with pytest.raises(ValueError, match="exists already"):
        run_observer(records, folder, start, now_plus(120))


class _Server(http.server.BaseHTTPRequestHandler):
    folder: pathlib.Path
    seen: list

    def do_GET(self):   # noqa: N802 - the name http.server calls
        type(self).seen.append({"path": self.path, "headers": dict(self.headers)})
        index = json.loads((self.folder / "index.json").read_text(encoding="utf-8"))
        entry = index.get(self.path)
        body = (self.folder / entry["file"]).read_bytes() if entry else b'{"message":"Not Found"}'
        self.send_response(entry["status"] if entry else 404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_the_live_path_is_the_same_code_and_sends_no_credential_of_the_environment(env, tmp_path, monkeypatch):
    """The live transport against a local server that answers what the recorded folder holds: the same effects, the
    same outcomes but for the run's own names and times. A token in the environment is not sent: the observer reads a
    token only from the operator's file. Each path observes its own copy of the same records: in one folder the second
    run would read the event the first took, and an event is one effect with one outcome (D121)."""
    start = now_plus(-60)
    records, sent, _decision = allowed_push(env, tmp_path)
    copy = tmp_path / "records-live"
    shutil.copytree(records, copy)
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, sent, now_plus(0))])
    run_observer(records, folder, start, now_plus(120), run="recorded")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_PLANTEDobserverZ405")
    handler = type("Handler", (_Server,), {"folder": folder, "seen": []})
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = observer.LiveTransport(base=f"http://127.0.0.1:{server.server_address[1]}")
        observer.observe(pr.Records(copy), "live", transport, [REPO], start, now_plus(120), observer_key())
    finally:
        server.shutdown()
    assert [s["path"] for s in handler.seen] == [f"/repos/{REPO}/events?per_page=100&page={n}" for n in (1, 2)]
    assert all("Authorization" not in s["headers"] and "PLANTED" not in json.dumps(s["headers"]) for s in handler.seen)
    by_run = {}
    for envelope, scope in outcomes(records) + outcomes(copy):
        pred = statement(envelope)["predicate"]
        by_run[pred["outcomeId"].split("-")[0]] = ({k: v for k, v in pred.items() if k not in ("outcomeId",
                                                                                                "recordedAt")}, scope)
    assert sorted(by_run) == ["live", "recorded"] and by_run["live"] == by_run["recorded"]
    live = json.loads((copy / "api" / "live" / "run.json").read_text(encoding="utf-8"))
    assert live["transport"] == "live" and all(r["status"] == 200 for r in live["requests"])


def test_the_records_refuse_a_kept_file_that_changed(env, tmp_path):
    records = start_records(env, tmp_path)
    pr.Records(records)
    rules = records / "closing_rules.json"
    rules.write_text(rules.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(pr.RecordsError, match="closing_rules"):
        pr.Records(records)


def test_the_inputs_are_kept_before_the_first_decision_only(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("valid")
    records = start_records(env, tmp_path)
    p1.level2(env, r.path)
    (records / pr.START).unlink()
    with pytest.raises(pr.RecordsError, match="already hold a decision"):
        pr.start(records, contract=ROOT / "docs" / "pilot" / "pilot_contract.md",
                 profile=ROOT / "tools" / "pilot" / "github_write_profile.py", agents=ROOT / "AGENTS.md",
                 closing_rules=records / "closing_rules.json", roster=records / "roster.json",
                 gate_public=p1.public_key(), observer_public=probe_signer.public_hex(observer_key()),
                 verifier=records / "roster.json", environment=records / "roster.json", gate_id=p1.GATE_ID,
                 observer_id=p1.OBSERVER_ID, gate=GATE_FILE)


def test_the_outcome_names_the_approved_bytes_as_requested_and_the_stored_ones_as_its_effect(env, tmp_path):
    """Other bytes arrive: the outcome says what was asked for (the decision's digest) and what GitHub stores, so the
    profile sees both (found by mutant R02 of the first mutation run)."""
    start = now_plus(-60)
    records, _sent, decision = allowed_push(env, tmp_path)
    other = "b" * 40
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, other, now_plus(0))])
    run_observer(records, folder, start, now_plus(120))
    ((envelope, _scope),) = outcomes(records)
    pred = statement(envelope)["predicate"]
    assert pred["requestedActionDigest"]["sha256"] == \
        p1.predicate_of(decision)["proposedAction"]["parametersDigest"]["sha256"]
    assert pred["effectDigest"]["sha256"] == pr.sha256_hex(f"{other}\n".encode())


# --- a name read from data reads a file only inside its folder (found by the review of 19d4a2a2) ---------------------

PAGE1 = f"/repos/{REPO}/events?per_page=100&page=1"


def escaping(tmp_path: pathlib.Path, how: str) -> pathlib.Path:
    """A recorded folder whose index.json names page 1 so that it reads a file outside the folder, or names it in a
    form the index does not take."""
    folder = recorded(tmp_path, [])
    secret = tmp_path / "secret.json"
    secret.write_bytes(b'[{"planted": "SECRET-OUTSIDE"}]')
    index = json.loads((folder / "index.json").read_text(encoding="utf-8"))
    if how == "dotdot":
        index[PAGE1]["file"] = "../secret.json"
    elif how == "absolute":
        index[PAGE1]["file"] = str(secret)
    elif how == "file-link":
        (folder / "link.json").symlink_to(secret)
        index[PAGE1]["file"] = "link.json"
    elif how == "folder-link":
        (folder / "up").symlink_to(tmp_path, target_is_directory=True)
        index[PAGE1]["file"] = "up/secret.json"
    elif how == "no-file":
        del index[PAGE1]["file"]
    elif how == "status-text":
        index[PAGE1]["status"] = "200"
    (folder / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return folder


@pytest.mark.parametrize("how", ["dotdot", "absolute", "file-link", "folder-link", "no-file", "status-text"])
def test_a_recorded_folder_hands_the_records_no_file_from_elsewhere(tmp_path, how):
    """index.json names each response by a relative path inside the folder, without . or .., reached through no
    symbolic link, with a numeric status. Red at 19d4a2a2: get() read ../secret.json and a link to it, and the observer
    kept those bytes as GitHub's answer."""
    with pytest.raises(pr.RecordsError):
        observer.RecordedTransport(escaping(tmp_path, how))


def test_a_recorded_folder_that_reads_elsewhere_leaves_no_run_behind(env, tmp_path):
    """The command refuses the folder before its first request: exit 1, no api/ folder, the planted bytes nowhere in the
    records. Red at 19d4a2a2, where the run was written with the file outside the folder as its first response."""
    records = start_records(env, tmp_path)
    code = observer.main(["--records", str(records), "--run", "run-1", "--repo", REPO, "--start", now_plus(-60),
                          "--end", now_plus(60), "--recorded", str(escaping(tmp_path, "dotdot")),
                          "--probe-label", OBSERVER_LABEL])
    assert code == 1 and not (records / "api").exists()
    assert not [p for p in records.rglob("*") if p.is_file() and b"SECRET-OUTSIDE" in p.read_bytes()]


def test_control_a_recorded_name_in_a_subfolder_reads(tmp_path):
    """The control: a name with a real subfolder is inside the folder and reads as before."""
    folder = recorded(tmp_path, [push_event(1, AGENT_GITHUB_ID, "a" * 40, now_plus(0))])
    (folder / "pages").mkdir()
    (folder / "page1.json").rename(folder / "pages" / "page1.json")
    index = json.loads((folder / "index.json").read_text(encoding="utf-8"))
    index[PAGE1]["file"] = "pages/page1.json"
    (folder / "index.json").write_text(json.dumps(index), encoding="utf-8")
    assert observer.RecordedTransport(folder).get(PAGE1) == (200, (folder / "pages" / "page1.json").read_bytes())


def plant_outside(records: pathlib.Path, tmp_path: pathlib.Path, plant: str) -> None:
    """A records folder whose kept input, response or run is a file outside it, with the bytes the records expect."""
    if plant in ("kept-dotdot", "kept-link"):
        start = json.loads((records / pr.START).read_text(encoding="utf-8"))
        kept = records / start["files"]["environment"]["file"]
        outside = tmp_path / "outside-environment.json"
        outside.write_bytes(kept.read_bytes())
        if plant == "kept-dotdot":
            start["files"]["environment"]["file"] = "../outside-environment.json"
            (records / pr.START).write_text(json.dumps(start), encoding="utf-8")
        else:
            kept.unlink()
            kept.symlink_to(outside)
        return
    run_file = records / "api" / "run-1" / "run.json"
    run = json.loads(run_file.read_text(encoding="utf-8"))
    if plant == "response-dotdot":
        (tmp_path / "outside-page.json").write_bytes(b"[]")
        run["requests"][0]["file"] = "../../../outside-page.json"
        run_file.write_text(json.dumps(run), encoding="utf-8")
    else:   # run-link: the run's own run.json is a link to a copy outside the records
        outside = tmp_path / "outside-run.json"
        outside.write_bytes(run_file.read_bytes())
        run_file.unlink()
        run_file.symlink_to(outside)


@pytest.mark.parametrize("plant", ["kept-dotdot", "kept-link", "response-dotdot", "run-link"])
def test_the_records_read_no_file_outside_them(env, tmp_path, plant):
    """The reconciliation reads the records and nothing else (contract, section 8). A name in pilot_start.json or
    run.json, or a kept file or run that is a symbolic link, reads nothing outside the records: Records or the effects
    of the runs end with RecordsError. Red at 19d4a2a2 for each, where the bytes outside read as the records' own."""
    records = start_records(env, tmp_path)
    run_observer(records, recorded(tmp_path, []), now_plus(-60), now_plus(60))
    plant_outside(records, tmp_path, plant)
    with pytest.raises(pr.RecordsError):
        kept = pr.Records(records)
        pr.effects_of_runs(kept.runs(), kept.agent_of)
