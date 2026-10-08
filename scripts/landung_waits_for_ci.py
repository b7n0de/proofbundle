#!/usr/bin/env python3
"""The mutation layer of landung.yml starts only after test and coverage of ci.yml succeeded on the
same head.

WHY. In ci.yml the layer `needs: [test, coverage]`: on 2026-09-13 four CI runs kept 28 shards busy
for 65 to 255 minutes while test and coverage were long red in all four (see the mutation job in
ci.yml). When the label way moved to landung.yml, `needs` could not come along, because it does not
reach into another workflow. Codex on pull request 310, round two (P1): a push to a pull request
that carries `landung` started the 36 shards at once, beside CI, and a head whose ordinary tests
fail kept them running. This script is the `needs` across the two workflows: the layer's job
`ci-prerequisites` runs it, and `mutation` needs that job.

WHAT IT WAITS FOR. The jobs that the mutation job of ci.yml needs (`CI_NEEDS`, held equal to ci.yml
by a contract), and the collector `all-checks-passed` (`COLLECTOR`), whose needs are the same jobs
and which judges the matrix as a whole, in the latest ci.yml run of event `pull_request` for the
head of the event. A job counts by its name: the job itself, or a matrix leg `<job> (<value>)`.
Only the latest attempt of each job counts, so a re-run that turned green is green.

WHY THE COLLECTOR TOO (Codex on pull request 310, round three, P1). `needs.test.result` is success
whether the matrix ran five versions or one. A fork pull request without `landung` runs the 3.12 leg
only, and setting the label afterwards starts no run of ci.yml; with test and coverage green the
layer would have started on one leg. `all-checks-passed` holds the full-matrix condition and is red
there, so the layer waits for the fork's next push, which runs the full matrix under the label.

WHICH RUN COUNTS (Codex on pull request 310, round four, P1). A ci.yml run tested the merge of the head into
the base as the base stood when it started. When main moved on and the head did not, the label starts no new
run, and the old run is evidence for other bytes than the ones the layer checks out. So a run counts only when
it started after the current base landed, and, on `synchronize` and `reopened`, after this run of landung.yml
started, less `SKEW_S`: those events start a new ci.yml run, and the previous run of the same head must not be
read before the new one appears. A pull request's base in the run object cannot serve: GitHub reports the current
base there, not the one the run tested (measured 2026-10-08: a run of 2026-09-28 named c335c6ee, which landed on
2026-10-08).

WHEN THE BASE LANDED is the time the base branch moved to `BASE_SHA`, read from the repository activity, which
records each update of a ref with its time (measured 2026-10-08: main moved to c335c6ee at 08:19:17Z). It is not
a commit's own time (Codex on pull request 310, round five, P1): a merge commit exists before the branch moves to
it, in the merge queue in particular, and a run between the two tested the old base. A landing that is not among
the last `ACTIVITY_PAGE` entries of the activity is red: which run counts cannot be decided.

THREE OUTCOMES, AND ONLY ONE OF THEM STARTS THE LAYER. `green` when every needed job exists and
succeeded. `red` as soon as one needed job finished with anything but success (skipped and cancelled
included), when the run finished without one of them, when no ci.yml run appears for the head within
`APPEAR_S`, or when the API cannot be read `MAX_READ_ERRORS` times in a row. `wait` otherwise; the
job's own timeout in landung.yml bounds the waiting.

Usage (in landung.yml): GITHUB_REPOSITORY, HEAD_SHA, BASE_SHA, BASE_REF, EVENT_ACTION, GITHUB_RUN_ID and
GITHUB_TOKEN from the environment; a missing one is red.
Exit 0 green, 1 red. Standard library only.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
CI_WORKFLOW = "ci.yml"
#: The `needs` of the mutation job in ci.yml. tests/test_ein_label_startet_keine_ci.py holds the two equal.
CI_NEEDS = ("test", "coverage")
#: The collector of ci.yml: its needs are CI_NEEDS, and it is red when the full matrix did not run.
COLLECTOR = "all-checks-passed"
#: Everything the layer waits for.
WAITED = CI_NEEDS + (COLLECTOR,)
POLL_S = 30
#: How long the ci.yml run of the head may take to appear. Both workflows start on the same event.
APPEAR_S = 15 * 60
MAX_READ_ERRORS = 3
#: How much earlier than this run of landung.yml a ci.yml run of the same event may have been created.
SKEW_S = 120
#: The events on which ci.yml starts a new run for the head, together with this workflow.
NEW_RUN_EVENTS = ("synchronize", "reopened")
#: How many entries of the repository activity are read for the landing of the base, newest first.
ACTIVITY_PAGE = 100


def _instant(text: object) -> dt.datetime:
    if not isinstance(text, str):
        raise ReadError(f"not a timestamp: {text!r}")
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReadError(f"not a timestamp: {text!r}") from exc


class ReadError(RuntimeError):
    """The API could not be read."""


class Undecidable(RuntimeError):
    """The API was read, and which ci.yml run counts cannot be decided from it."""


def _get(path: str, token: str | None) -> dict:
    req = urllib.request.Request(f"{API}/{path}", headers={"Accept": "application/vnd.github+json",
                                                            "X-GitHub-Api-Version": "2022-11-28",
                                                            "User-Agent": "proofbundle-landung-waits"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed https host)
            data = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        raise ReadError(f"{path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(data, (dict, list)):
        raise ReadError(f"{path}: the answer is neither an object nor a list")
    return data


def _is(name: str, need: str) -> bool:
    """A job counts for `need` by its name: the job itself, or a matrix leg `<need> (<value>)`."""
    return name == need or name.startswith(f"{need} (")


def judge(jobs: list[dict], run_status: str) -> tuple[str, str]:
    """`green`, `red` or `wait`, with the reason, for the jobs of one ci.yml run."""
    wanted = [j for j in jobs if any(_is(str(j.get("name", "")), n) for n in WAITED)]
    red = sorted(f"{j['name']}={j.get('conclusion')}" for j in wanted
                 if j.get("status") == "completed" and j.get("conclusion") != "success")
    if red:
        return "red", f"a job the mutation layer needs did not succeed on this head: {', '.join(red)}"
    missing = [n for n in WAITED if not any(_is(str(j.get("name", "")), n) for j in wanted)]
    if missing:
        if run_status == "completed":
            return "red", f"the ci.yml run finished without {', '.join(missing)}"
        return "wait", f"ci.yml has not created {', '.join(missing)} yet"
    running = sorted(j["name"] for j in wanted if j.get("status") != "completed")
    if running:
        return "wait", f"waiting for {', '.join(running)}"
    return "green", f"{', '.join(sorted(j['name'] for j in wanted))} succeeded on this head"


def landed_at(fetch, repo: str, base_ref: str, base: str, token) -> dt.datetime:
    """When the base branch moved to `base`: the newest update of the ref to that commit in the repository
    activity (WHEN THE BASE LANDED)."""
    ref = f"refs/heads/{base_ref}"
    eintraege = fetch(f"repos/{repo}/activity?ref={urllib.parse.quote(ref, safe='')}&per_page={ACTIVITY_PAGE}", token)
    if not isinstance(eintraege, list):
        raise ReadError("the repository activity is not a list")
    for e in eintraege:
        if isinstance(e, dict) and e.get("ref") == ref and e.get("after") == base:
            return _instant(e.get("timestamp"))
    raise Undecidable(f"the update of {ref} to {base} is not among the last {len(eintraege)} entries of the "
                      "repository activity, so when the base landed is not known")


def earliest_counted(fetch, repo: str, base_ref: str, base: str, action: str, run_id: str, token) -> dt.datetime:
    """The earliest creation time of a ci.yml run that counts as evidence for the current merge candidate."""
    landed = landed_at(fetch, repo, base_ref, base, token)
    if action in NEW_RUN_EVENTS:
        own = _instant(fetch(f"repos/{repo}/actions/runs/{run_id}", token).get("created_at"))
        return max(landed, own - dt.timedelta(seconds=SKEW_S))
    return landed


def main(fetch=_get, sleep=time.sleep, clock=time.monotonic, env=os.environ) -> int:
    fehlt = [k for k in ("GITHUB_REPOSITORY", "HEAD_SHA", "BASE_SHA", "BASE_REF", "EVENT_ACTION", "GITHUB_RUN_ID")
             if not env.get(k)]
    if fehlt:
        print(f"::error::the environment lacks {', '.join(fehlt)}; which ci.yml run counts cannot be decided")
        return 1
    repo, sha, token = env["GITHUB_REPOSITORY"], env["HEAD_SHA"], env.get("GITHUB_TOKEN")
    start, errors, floor = clock(), 0, None
    while True:
        try:
            if floor is None:
                floor = earliest_counted(fetch, repo, env["BASE_REF"], env["BASE_SHA"], env["EVENT_ACTION"],
                                         env["GITHUB_RUN_ID"], token)
            runs = fetch(f"repos/{repo}/actions/workflows/{CI_WORKFLOW}/runs"
                         f"?head_sha={sha}&event=pull_request&per_page=100", token)
            alle = [r for r in runs.get("workflow_runs") or [] if r.get("head_sha") == sha]
            runs = [r for r in alle if _instant(r.get("created_at")) >= floor]
            if runs:
                run = max(runs, key=lambda r: (str(r.get("created_at")), int(r.get("id") or 0)))
                page = fetch(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100", token)
                jobs = page.get("jobs") or []
                if int(page.get("total_count") or 0) > len(jobs):
                    print(f"::error::run {run['id']} has more jobs than one page holds; not read to the end")
                    return 1
                state, why = judge(jobs, str(run.get("status")))
            elif clock() - start > APPEAR_S:
                alt = (f"; {len(alle)} earlier run(s) of this head started before {floor.isoformat()} and tested an "
                       "older merge candidate, so a new push (or closing and reopening) runs ci.yml on the current "
                       "one" if alle else "")
                state, why = "red", f"no ci.yml run of event pull_request for {sha} after {APPEAR_S} s{alt}"
            else:
                state, why = "wait", f"no ci.yml run for {sha} created after {floor.isoformat()} yet"
            errors = 0
        except Undecidable as exc:
            print(f"::error::{exc}")
            return 1
        except ReadError as exc:
            errors += 1
            if errors >= MAX_READ_ERRORS:
                print(f"::error::the API could not be read {errors} times in a row: {exc}")
                return 1
            state, why = "wait", f"read error {errors} of {MAX_READ_ERRORS}: {exc}"
        print(f"{state}: {why}", flush=True)
        if state == "green":
            return 0
        if state == "red":
            print(f"::error::{why}")
            return 1
        sleep(POLL_S)


if __name__ == "__main__":
    sys.exit(main())
