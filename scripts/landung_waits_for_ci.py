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

THREE OUTCOMES, AND ONLY ONE OF THEM STARTS THE LAYER. `green` when every needed job exists and
succeeded. `red` as soon as one needed job finished with anything but success (skipped and cancelled
included), when the run finished without one of them, when no ci.yml run appears for the head within
`APPEAR_S`, or when the API cannot be read `MAX_READ_ERRORS` times in a row. `wait` otherwise; the
job's own timeout in landung.yml bounds the waiting.

Usage (in landung.yml): GITHUB_REPOSITORY, HEAD_SHA and GITHUB_TOKEN from the environment.
Exit 0 green, 1 red. Standard library only.
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import time
import urllib.error
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


class ReadError(RuntimeError):
    """The API could not be read."""


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
    if not isinstance(data, dict):
        raise ReadError(f"{path}: the answer is not an object")
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


def main(fetch=_get, sleep=time.sleep, clock=time.monotonic, env=os.environ) -> int:
    repo, sha, token = env["GITHUB_REPOSITORY"], env["HEAD_SHA"], env.get("GITHUB_TOKEN")
    start, errors = clock(), 0
    while True:
        try:
            runs = fetch(f"repos/{repo}/actions/workflows/{CI_WORKFLOW}/runs"
                         f"?head_sha={sha}&event=pull_request&per_page=100", token)
            runs = [r for r in runs.get("workflow_runs") or [] if r.get("head_sha") == sha]
            if runs:
                run = max(runs, key=lambda r: (str(r.get("created_at")), int(r.get("id") or 0)))
                page = fetch(f"repos/{repo}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100", token)
                jobs = page.get("jobs") or []
                if int(page.get("total_count") or 0) > len(jobs):
                    print(f"::error::run {run['id']} has more jobs than one page holds; not read to the end")
                    return 1
                state, why = judge(jobs, str(run.get("status")))
            elif clock() - start > APPEAR_S:
                state, why = "red", f"no ci.yml run of event pull_request for {sha} after {APPEAR_S} s"
            else:
                state, why = "wait", f"no ci.yml run for {sha} yet"
            errors = 0
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
