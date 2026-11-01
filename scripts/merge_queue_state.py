#!/usr/bin/env python3
"""Whether the merge queue is on for a branch, read from the rules GitHub applies to it.

WHY (the reading of the head 37137a9d of pull request 462, P1, and the owner's answer A on card OA-75a1805115).
The first form of the three stages of ci.yml let a repository variable, MERGE_QUEUE, switch `coverage` off on a pull
request. Nothing tied the variable to the queue: set while a direct merge was still possible, a pull request could
land without the whole suite under its floor having run on it or on a candidate of the queue. Whether the queue is on
is a fact about the rules of the branch, and this reads it there. ci.yml (job merge-queue-state) and landung.yml (job
ci-prerequisites) ask this one reader, so the two workflows cannot disagree about it.

WHAT IT READS. `GET /repos/{repo}/rules/branches/{branch}`, the rules GitHub applies to the branch from every active
ruleset. The answer is `true` when one of them is of type `merge_queue` (the type the REST reference names for it),
otherwise `false`. A merge queue turned on in the classic branch protection instead of a ruleset is not among these
rules; it reads as off, which keeps `coverage` running.

THE SAFE SIDE. Anything that is not a readable list of rules answers `false`: an HTTP error, any other error while
reading, a list of something else, a missing repository or branch. `false` means `coverage` runs on the pull request, so a reader that cannot read
makes a pull request slower and never lets one land without the suite.

OUTPUT. One line `required=true` or `required=false` appended to the file named by GITHUB_OUTPUT (when set), the same
line and the reason on stdout, a `::notice` when the answer could not be read or written; an answer that could not be
written leaves the output empty, which the workflows read as off. Exit 0 always: the answer is the output, and a red
step here would read as a failed check where there is only an unknown state.

Usage (in a workflow): GITHUB_REPOSITORY, BRANCH, GITHUB_TOKEN and GITHUB_OUTPUT from the environment. Standard
library only.
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
#: The rule type of a merge queue in the REST reference (repos/rules, "Repository Rule").
MERGE_QUEUE = "merge_queue"


class ReadError(RuntimeError):
    """The API could not be read."""


def _get(path: str, token: str | None) -> object:
    req = urllib.request.Request(f"{API}/{path}", headers={"Accept": "application/vnd.github+json",
                                                            "X-GitHub-Api-Version": "2022-11-28",
                                                            "User-Agent": "proofbundle-merge-queue-state"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed https host)
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        raise ReadError(f"{path}: {type(exc).__name__}: {exc}") from exc


def required(rules: object) -> bool:
    """Whether a readable list of rules holds a merge queue."""
    return isinstance(rules, list) and any(isinstance(r, dict) and r.get("type") == MERGE_QUEUE for r in rules)


def _answer(value: bool, why: str, env) -> int:
    line = f"required={'true' if value else 'false'}"
    out = env.get("GITHUB_OUTPUT")
    if out:
        try:
            with open(out, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            # Without a written answer the output is empty in the workflow, which reads as off: coverage runs.
            print(f"::notice title=merge-queue-state::the answer could not be written to GITHUB_OUTPUT; the output "
                  f"stays empty and reads as off, so coverage runs ({type(exc).__name__}: {exc})")
    print(f"{line}: {why}", flush=True)
    return 0


def main(fetch=_get, env=os.environ) -> int:
    repo, branch = env.get("GITHUB_REPOSITORY"), env.get("BRANCH")
    if not repo or not branch:
        print("::notice title=merge-queue-state::the repository or the branch is not named; read as off, so "
              "coverage runs")
        return _answer(False, "repository or branch missing", env)
    path = f"repos/{repo}/rules/branches/{urllib.parse.quote(branch, safe='')}"
    try:
        rules = fetch(path, env.get("GITHUB_TOKEN"))
    except Exception as exc:  # noqa: BLE001 (THE SAFE SIDE: any error while reading is off, never a red step)
        print(f"::notice title=merge-queue-state::the rules of {branch} could not be read; read as off, so coverage "
              f"runs ({type(exc).__name__}: {exc})")
        return _answer(False, "rules not readable", env)
    if not isinstance(rules, list):
        print(f"::notice title=merge-queue-state::the rules of {branch} are not a list; read as off, so coverage runs")
        return _answer(False, "rules not a list", env)
    on = required(rules)
    return _answer(on, f"{len(rules)} rule(s) on {branch}, {'one of them' if on else 'none of them'} a merge queue",
                   env)


if __name__ == "__main__":
    sys.exit(main())
