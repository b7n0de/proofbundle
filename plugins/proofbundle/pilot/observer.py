#!/usr/bin/env python3
"""The observer of the pilot of Z405 (part 2, DECISIONS.md D56): what the GitHub API shows after the writes.

It reads the events of the repositories it is given, over a window, keeps every response as GitHub returned it with
the time it asked, matches each effect of an agent identity to a decision by the rule of the contract (section 5,
pilot_records.match), and signs an action-outcome/v0.1 for each effect that takes a decision, bound to that decision by
its content root, with the scope descriptor {surface, target, objectId} beside it. The outcome is built and signed by
the profile the records keep (github-write/1), so it is the outcome the profile reads.

It matches as the reconciliation does (D121): over every run the records keep in the order they ran, its own included,
each GitHub event once and over the window of every run, and it signs an outcome only for a decision no outcome is
bound to yet. An event
listed on two pages, for a repository named twice or again by a later run is one effect and gets one outcome.

    observer.py --records DIR --run NAME --repo OWNER/REPO [--repo ...] --start T --end T
                (--recorded FOLDER | --live [--token-file F]) (--key-file PEM | --probe-label LABEL)

One code path reads: a transport answers GET requests, live against https://api.github.com or from responses recorded
in a folder (index.json maps a request path to a file). The live path runs first in the pilot at delta. The observer
needs no credential an agent session holds: the events of a public repository need none, and a token, if the operator
gives one, is read from the operator's file, never from the environment. Its key is the operator's (--key-file); a
probe label derives a key from a public label for tests, never for the pilot.
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pilot_records as pr  # noqa: E402

API = "https://api.github.com"
#: The events API lists at most 300 events of a repository, 100 to a page (GitHub's documentation); older ones are not
#: listed, which bounds M5 and M6 (contract, section 7).
EVENT_PAGES = 3
LIMITATIONS = ["read from the GitHub API at recordedAt; a later edit or deletion is not covered",
               "the signer is the observer; executor.id is the account GitHub reports, not a key"]


class LiveTransport:
    """GET against the GitHub API. No token unless the operator names a file that holds one."""

    def __init__(self, token_file: pathlib.Path | None = None, base: str = API):
        self.base = base
        self.token = token_file.read_text(encoding="ascii").strip() if token_file else None
        self.kind = "live"

    def get(self, path: str) -> tuple[int, bytes]:
        request = urllib.request.Request(self.base + path, headers={
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "proofbundle-pilot-observer", **({"Authorization": f"Bearer {self.token}"} if self.token else {})})
        try:
            with urllib.request.urlopen(request, timeout=30) as answer:
                return answer.status, answer.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


class RecordedTransport:
    """GET answered from a folder of recorded responses: index.json maps a request path to {status, file}."""

    def __init__(self, folder: pathlib.Path):
        self.folder = pathlib.Path(folder)
        self.index = pr.read_json(self.folder / "index.json")
        self.kind = "recorded"

    def get(self, path: str) -> tuple[int, bytes]:
        entry = self.index.get(path)
        if entry is None:
            return 404, b'{"message":"Not Found"}'
        return entry["status"], (self.folder / entry["file"]).read_bytes()


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def load_key(key_file: pathlib.Path | None, probe_label: str | None):
    if (key_file is None) == (probe_label is None):
        raise ValueError("name exactly one of --key-file and --probe-label")
    if probe_label is not None:
        import probe_signer   # noqa: PLC0415 - the probe key, from a public label
        return probe_signer.probe_key(probe_label)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import load_pem_private_key  # noqa: PLC0415
    key = load_pem_private_key(key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the observer's key is not an Ed25519 key")
    return key


def observe(records: pr.Records, run: str, transport, repos: list[str], start: str, end: str, key,
            clock=utc_now) -> dict:
    """One run of the observer: the responses under api/<run>/, the outcomes under outcomes/, the run's summary."""
    if not run.replace("-", "").replace("_", "").isalnum():
        raise ValueError("a run name holds letters, digits, - and _ only")
    if pr.instant_key(start) is None or pr.instant_key(end) is None or pr.instant_key(start) > pr.instant_key(end):
        raise ValueError("the window is two RFC 3339 instants in UTC, its start not after its end")
    if not repos or any(not pr._SLUG.fullmatch(repo) for repo in repos):
        raise ValueError("a run names at least one repository, each as owner/repo")
    folder = records.folder / "api" / run
    if folder.exists():
        raise ValueError(f"the run {run} exists already; a run is kept as it was")
    # D121: the outcomes and the earlier runs are read before this run writes a byte, so records that do not read leave
    # no half run behind
    profile = records.profile()
    bound = {pr.outcome_root(profile, outcome) for outcome in records.outcomes()}
    pr.effects_of_runs(records.runs(), records.agent_of)
    (folder / "responses").mkdir(parents=True)
    requests = []
    for repo in repos:
        for page in range(1, EVENT_PAGES + 1):
            path = f"/repos/{repo}/events?per_page=100&page={page}"
            asked = clock()
            status, body = transport.get(path)
            name = f"responses/{len(requests) + 1:04d}.json"
            (folder / name).write_bytes(body)
            requests.append({"kind": "events", "repo": repo, "path": path, "requestedAt": asked, "status": status,
                             "file": name, "sha256": pr.sha256_hex(body)})
            if status != 200 or body.strip() in (b"", b"[]"):
                break
    document = {"run": run, "window": {"start": start, "end": end}, "repos": repos, "requests": requests,
                "observer": records.observer_id, "transport": transport.kind}
    pr.write_json(folder / "run.json", document)
    # the decisions as the reconciliation reads them, one view per decisionId
    by_id = {}
    for entry in records.decisions():
        view = pr.decision_view(records, entry)
        if view is not None:
            by_id[view["decisionId"]] = view
    # D121: the match of the reconciliation, over every run the records keep in the order they ran, this one included;
    # an effect the records match to a decision gets an outcome once, from the first run that finds it unbound
    runs = records.runs()
    matched = pr.match(pr.effects_of_runs(runs, records.agent_of), list(by_id.values()), records.agent_of,
                       pr.window_of_runs(runs))
    own = [row for row in matched["rows"] if row["effect"]["run"] == run]
    issued, skipped = [], []
    for row in matched["rows"]:
        decision = by_id.get(row["decision"])
        if decision is None or decision["root"] in bound:
            continue
        effect = row["effect"]
        if decision["bytes_sha256"] is None:
            skipped.append({"decisionId": decision["decisionId"], "why": "the decision names no bytes"})
            continue
        scope = profile.scope_descriptor(effect["surface"], effect["target"], effect["objectId"])
        n = len(issued) + 1
        predicate = {"schemaVersion": "0.1.0", "outcomeId": f"{run}-{n:04d}", "decisionRef": {"sha256": decision["root"]},
                     "executor": {"id": f"github:{effect['actor']}"},
                     "requestedActionDigest": {"sha256": decision["bytes_sha256"]}, "status": "executed",
                     "performedAt": effect["performedAt"], "recordedAt": clock(), "limitations": LIMITATIONS,
                     "validity": {"audience": [records.observer_id], "nonce": decision["nonce"]},
                     "actualActionDigest": {"sha256": profile.scope_digest(scope)}}
        if effect["stored"] is not None:
            predicate["effectDigest"] = {"sha256": pr.sha256_hex(effect["stored"])}
        envelope = profile.sign_outcome(predicate, key)
        pr.write_json(records.folder / "outcomes" / f"{predicate['outcomeId']}.json", envelope)
        pr.write_json(records.folder / "outcomes" / f"{predicate['outcomeId']}.scope.json", scope)
        issued.append({"outcomeId": predicate["outcomeId"], "decisionId": decision["decisionId"]})
    # the run's own effects: those it lists first in the order the records keep the runs
    summary = {"run": run, "requests": len(requests), "effects": len(own), "outcomes": issued, "not_issued": skipped,
               "M5": sum(row["unapproved"] for row in own), "M6": sum(row["refused"] for row in own)}
    pr.write_json(folder / "observer_summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--records", required=True, type=pathlib.Path)
    parser.add_argument("--run", required=True)
    parser.add_argument("--repo", required=True, action="append")
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--recorded", type=pathlib.Path)
    source.add_argument("--live", action="store_true")
    parser.add_argument("--token-file", type=pathlib.Path)
    parser.add_argument("--key-file", type=pathlib.Path)
    parser.add_argument("--probe-label")
    args = parser.parse_args(argv)
    try:
        records = pr.Records(args.records)
        transport = RecordedTransport(args.recorded) if args.recorded else LiveTransport(args.token_file)
        summary = observe(records, args.run, transport, args.repo, args.start, args.end,
                          load_key(args.key_file, args.probe_label))
    except (pr.RecordsError, OSError, ValueError) as exc:
        print(f"observer: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
