#!/usr/bin/env python3
"""Round one belongs to the creator: a pull request without the creator's own review call is red.

WHY THIS EXISTS, measured 2026-09-19 over six pull requests of this repository. The reviewer answers
only when it is called, and nothing made anyone call it:

    PR 207   called 2026-09-14T17:34:59Z   answered 17:35:16Z    17 s
    PR 208   called 2026-09-14T17:35:08Z   answered 17:35:29Z    21 s
    PR 224   called 2026-09-18T08:59:33Z   answered 08:59:50Z    17 s
    PR 225   called 2026-09-18T09:40:53Z   answered 09:41:12Z    19 s
    PR 226   called 2026-09-18T20:06:13Z   answered 20:06:25Z    12 s
    PR 227   never called                  no answer at all

Five calls, five answers, none slower than twenty-one seconds. One pull request without a call and
nothing came. The summary comment on PR 226 names its own trigger as a manual request, and in this
range the automatic on-open trigger produced no review at all. So the missing review on PR 227 is
not slowness and not a quota; nobody asked.

WHAT THIS GATE HOLDS. A pull request carrying work must contain a comment BY ITS OWN AUTHOR that
calls the reviewer. Not a comment by anyone else, because round one belongs to the creator and a
call from a second person makes it round two. Not the reviewer's own summary, which quotes the
phrase back and would otherwise satisfy the check it is the subject of.

FAIL CLOSED in every direction that is not a proven call:

    NO_CALL          no comment by the author calls the reviewer
    AUTHOR_UNKNOWN   the author cannot be determined, so ownership of round one cannot be decided
    UNREADABLE       the comment list is not the shape this gate can read

HONEST LIMIT, stated rather than implied. This checks that the call was MADE, not that a review
came back, and not that its findings were answered. A pull request whose call went out one second
before the merge passes here. Convergence is a separate question and this gate does not claim it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

SCHEMA = "proofbundle.codex_round_one_gate.v1"

#: The call, as it is actually written in this repository. Deliberately narrow: a phrase that only
#: resembles the call is not the call, and widening this would let prose about the reviewer count.
CALL = re.compile(r"@codex\s+(review|security\s+review)\b", re.I)

#: The reviewer's own account. Its summary comment quotes the phrase, so it can never be the call.
REVIEWER_LOGINS = frozenset({"chatgpt-codex-connector"})


def judge(author: str | None, comments: list[dict] | None) -> dict:
    """Pure. Given the author's login and the comment list, did round one happen?

    ``comments`` entries are read as ``{"author": {"login": str}, "body": str, "createdAt": str}``,
    which is the shape the GitHub CLI returns. Anything else is UNREADABLE rather than a pass.
    """
    if not author or not isinstance(author, str):
        return {"schema": SCHEMA, "verdict": "AUTHOR_UNKNOWN",
                "reason": ("the author of the pull request cannot be determined, so it cannot be "
                           "decided whether round one belongs to whoever called")}
    if comments is None or not isinstance(comments, list):
        return {"schema": SCHEMA, "verdict": "UNREADABLE",
                "reason": "the comment list is missing or not a list; unknown is not a pass"}
    calls = []
    for c in comments:
        if not isinstance(c, dict):
            return {"schema": SCHEMA, "verdict": "UNREADABLE",
                    "reason": f"a comment is {type(c).__name__}, not an object"}
        login = ((c.get("author") or {}) if isinstance(c.get("author"), dict) else {}).get("login")
        body = c.get("body")
        if not isinstance(body, str):
            return {"schema": SCHEMA, "verdict": "UNREADABLE",
                    "reason": "a comment carries no readable body"}
        if login in REVIEWER_LOGINS:
            # The reviewer's summary quotes the phrase. Counting it would let the check be
            # satisfied by the very thing it exists to trigger.
            continue
        if login != author:
            continue
        if CALL.search(body):
            calls.append(c.get("createdAt") or "unknown")
    if not calls:
        return {"schema": SCHEMA, "verdict": "NO_CALL", "author": author,
                "reason": ("no comment by the author calls the reviewer. Round one belongs to the "
                           "creator: measured over six pull requests, the reviewer answered every "
                           "call within twenty-one seconds and never appeared without one")}
    return {"schema": SCHEMA, "verdict": "OK", "author": author, "called_at": sorted(calls)[0],
            "calls": len(calls)}


def _fetch(pr: str, repo: str) -> dict:
    out = subprocess.run(
        ["gh", "pr", "view", pr, "--repo", repo, "--json", "author,comments"],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        return {"error": (out.stderr or "").strip()[:300]}
    return json.loads(out.stdout)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pr", required=True)
    ap.add_argument("--repo", default="b7n0de/proofbundle")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    data = _fetch(a.pr, a.repo)
    if "error" in data:
        e = {"schema": SCHEMA, "verdict": "UNREADABLE", "reason": data["error"]}
    else:
        e = judge(((data.get("author") or {}) or {}).get("login"), data.get("comments"))
    if a.json:
        print(json.dumps(e, ensure_ascii=False, indent=2))
    else:
        print(f"codex-round-one: {e['verdict']}"
              + (f" · called {e['called_at']}" if e.get("called_at") else "")
              + (f" — {e['reason']}" if e.get("reason") else ""))
    return 0 if e["verdict"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
