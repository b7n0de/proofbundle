#!/usr/bin/env python3
# BETRIEBSART: ci · .github/workflows/codex-threads.yml runs it on every pull request
"""codex_threads_check.py: an advisory merge check for the Codex review loop of one pull request.

It measures three numbers at the origin, through the GitHub REST API, and reports them:

  rounds       issue comments of the repository owner's account whose first line is
               `@codex review`. The house budget is five per pull request (rule R2). The number is
               reported, not judged here: the budget is enforced where a request is made.
  open         Codex threads without an answer of the owner's account.
  not_at_head  answered Codex threads whose answer names no commit that is on the head.

Green only when `open` and `not_at_head` are both zero (the answer rule: a thread is closed only
when the fix is on the head of the pull request, or the refusal stands in the register).

WHAT COUNTS AS A CODEX THREAD. A review comment thread whose first comment comes from the Codex
app's bot account, identified by its login (`chatgpt-codex-connector[bot]`). A name in the text
counts for nothing, and a thread a person opened is outside this check.

WHAT COUNTS AS AN ANSWER. A reply of the owner's account inside the thread, or an issue comment of
the owner's account whose register line names the thread in the house form `<owner>/<repo>#<pr>:<id>`
or links its anchor `#discussion_r<id>`. A register line begins with the word `Thread` followed by a
space (`Threads still open` and `Threading` are prose). An issue comment answers ONE thread, as the
answer rule says; a comment whose register lines name more than one thread answers none of them,
because its one `Commit measured` line cannot belong to all of them. A thread id that only stands in
prose does not make a comment an answer, and a resolved thread without an answer is still open:
resolving is a click, an answer is a statement.

WHAT A READER SEES IS WHAT COUNTS. Lines inside an HTML comment or a fenced code block are not read
for either the register line or the measured line: GitHub does not show the first, and the second is
an example, not a statement.

WHAT COUNTS AS THE ANSWER'S COMMIT. The 40-hex id on the answer's `Commit measured` line, a line
that begins with those two words, and nothing else. An id elsewhere in the text is evidence of
something, not the answer's commit (Codex on PR 275: `Reproduced at <sha>; still investigating`
made a thread green through a fallback to the first id). An answer without that line, or with more
than one, is not at head. A commit is at head when the head contains it AND it contains the commit
Codex reviewed: any ancestor of the head is on the head, the first commit of the repository too, and
only a commit that comes after the reviewed one can carry a fix for it. For a pull request that has landed, a commit that CONTAINS its
merge commit is at head too: an answer measured on main after the landing measured the fix where it
now lives, while a commit of main from before the landing does not carry the fix at all. A commit
the repository does not know is not at head.

THREE STATES, NOT TWO. A page of the API that cannot be read makes the check red as NOT MEASURABLE
(exit 2), never green: a thread nobody could read is not an answered one. The same holds for any
error the check did not foresee (Codex on PR 275: a truncated response raised `IncompleteRead` out
of `main`): it is reported as not measurable with its type, never as a traceback and never green.

NAMED LIMIT. An answer posted after the last run is seen by the next run, which a push or a manual
dispatch starts. Between the two, the reported state is the state of the last run.

Usage: python3 scripts/codex_threads_check.py --repo OWNER/REPO --pr N [--owner LOGIN]
       [--summary FILE] [--json]
Exit 0 green, 1 red, 2 not measurable. Standard library only; the token is read from GH_TOKEN or
GITHUB_TOKEN.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.request

CODEX_BOT = "chatgpt-codex-connector[bot]"
API = "https://api.github.com"
_MEASURED = re.compile(r"(?m)^[ \t]*Commit measured[ \t`:]*([0-9a-f]{40})\b")
_REGISTER = re.compile(r"^[ \t]*Thread[ \t]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_FENCE = re.compile(r"(?ms)^[ \t]*(```|~~~).*?^[ \t]*\1[^\n]*$")
#: A pull request with more comments than this many pages holds is not read to the end, and a check
#: that did not read to the end is not measured.
MAX_PAGES = 50
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class NotMeasurable(RuntimeError):
    """The origin could not be read. Never a pass."""


class Missing(NotMeasurable):
    """The origin answered 404: the object does not exist there."""


def _get(url: str, token: str | None) -> tuple[object, str | None]:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "X-GitHub-Api-Version": "2022-11-28",
                                               "User-Agent": "proofbundle-codex-threads-check"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed https host)
            data = json.loads(r.read().decode("utf-8"))
            nxt = _NEXT.search(r.headers.get("Link") or "")
            return data, (nxt.group(1) if nxt else None)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise Missing(f"{url}: 404") from exc
        raise NotMeasurable(f"{url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError,
            TimeoutError) as exc:
        raise NotMeasurable(f"{url}: {type(exc).__name__}: {exc}") from exc


def _pages(path: str, token: str | None) -> list:
    """Every page of a list endpoint. A page that is not a list is not measurable."""
    out: list = []
    url: str | None = f"{API}/{path}{'&' if '?' in path else '?'}per_page=100"
    seen: set[str] = set()
    while url:
        # The next page comes from a header, so it is checked like input: it stays on the API host
        # (the token goes with every request), it is new, and there is a last page.
        if not url.startswith(API + "/") or url in seen or len(seen) >= MAX_PAGES:
            raise NotMeasurable(f"{path}: pagination left the API, repeated or exceeded "
                                f"{MAX_PAGES} pages at {url[:80]}")
        seen.add(url)
        data, url = _get(url, token)
        if not isinstance(data, list):
            raise NotMeasurable(f"{path}: the answer is not a list")
        out.extend(data)
    return out


def _login(c: dict) -> str:
    return str(((c or {}).get("user") or {}).get("login") or "")


def visible(text: str) -> str:
    """The text as a reader sees it: without HTML comments and without fenced code blocks."""
    return _FENCE.sub("", _HTML_COMMENT.sub("", text or ""))


def answer_commit(text: str) -> str | None:
    """The commit an answer names: the id on its ONE `Commit measured` line, and nothing else."""
    found = _MEASURED.findall(visible(text))
    return found[0] if len(set(found)) == 1 else None


def register_threads(text: str, repo: str, pr: int) -> set[int]:
    """The thread ids the register lines of a comment name, in either house form."""
    form = re.compile(rf"(?:{re.escape(f'{repo}#{pr}:')}|#discussion_r)(\d+)(?!\d)")
    return {int(m) for z in visible(text).splitlines() if _REGISTER.match(z)
            for m in form.findall(z)}


def is_round_request(text: str) -> bool:
    first = (text or "").strip().splitlines()[:1]
    return bool(first) and first[0].strip().lower() == "@codex review"


def measure(repo: str, pr: int, owner: str, review_comments: list, issue_comments: list,
            at_head) -> dict:
    """The verdict, from data alone. `at_head(sha, reviewed)` answers whether a commit is on the
    head and comes after the commit Codex reviewed."""
    rounds = sum(1 for c in issue_comments
                 if _login(c) == owner and is_round_request(c.get("body") or ""))
    threads = {c["id"]: c for c in review_comments
               if not c.get("in_reply_to_id") and _login(c) == CODEX_BOT}
    answers: dict[int, list[str]] = {t: [] for t in threads}
    for c in review_comments:
        root = c.get("in_reply_to_id")
        if root in answers and _login(c) == owner:
            answers[root].append(c.get("body") or "")
    for c in issue_comments:
        if _login(c) != owner:
            continue
        text = c.get("body") or ""
        named = register_threads(text, repo, pr)
        if len(named) == 1 and next(iter(named)) in answers:
            answers[next(iter(named))].append(text)
    still_open, not_at_head, closed = [], [], []
    for t in sorted(threads):
        if not answers[t]:
            still_open.append(t)
            continue
        commits = [answer_commit(a) for a in answers[t]]
        reviewed = threads[t].get("original_commit_id") or threads[t].get("commit_id")
        if any(s and at_head(s, reviewed) for s in commits):
            closed.append(t)
        else:
            not_at_head.append({"thread": t, "commits": commits})
    green = not still_open and not not_at_head
    return {"repo": repo, "pr": pr, "rounds": rounds, "codex_threads": len(threads),
            "open": len(still_open), "not_at_head": len(not_at_head),
            "open_threads": still_open, "not_at_head_threads": not_at_head,
            "closed_threads": closed, "verdict": "green" if green else "red"}


def measure_at_origin(repo: str, pr: int, owner: str, token: str | None) -> dict:
    pull, _ = _get(f"{API}/repos/{repo}/pulls/{pr}", token)
    head = ((pull or {}).get("head") or {}).get("sha") if isinstance(pull, dict) else None
    if not head:
        raise NotMeasurable(f"pull request {pr}: no head sha in the answer")
    # A LANDED PULL REQUEST IS MEASURED ON MAIN. Measured on PR 264 on 2026-09-25: its answers
    # written after the squash name a commit on main, which is no ancestor of the old branch head,
    # and the first version of this check called all four of them not at head. The second version
    # accepted a commit the merge commit CONTAINS, which is the wrong direction: a commit of main
    # from before the landing is contained in the merge commit and carries none of the fix. What
    # carries the fix is a commit that contains the merge commit.
    merged = pull.get("merge_commit_sha") if pull.get("merged") else None
    review = _pages(f"repos/{repo}/pulls/{pr}/comments", token)
    issue = _pages(f"repos/{repo}/issues/{pr}/comments", token)
    seen: dict[str, bool] = {}

    def contains(base: str, tip: str) -> bool:
        """Does `tip` contain `base`? The compare API reports `tip` identical to or ahead of it."""
        try:
            data, _ = _get(f"{API}/repos/{repo}/compare/{base}...{tip}", token)
        except Missing:
            return False                   # a commit the repository does not know is not at head
        status = data.get("status") if isinstance(data, dict) else None
        if status is None:
            raise NotMeasurable(f"compare {base[:12]}...{tip[:12]}: no status")
        return status in ("identical", "ahead")

    def at_head(sha: str, reviewed: str | None) -> bool:
        key = f"{sha}:{reviewed}"
        if key not in seen:
            # Open, or measured on the branch: on the head, and after the reviewed commit. Landed and
            # measured on main: after the merge commit, which came after every review of the branch.
            on_branch = contains(sha, head) and bool(reviewed) and contains(reviewed, sha)
            seen[key] = on_branch or bool(merged and contains(merged, sha))
        return seen[key]

    result = measure(repo, pr, owner, review, issue, at_head)
    result["head"] = head
    result["merge_commit"] = merged
    return result


def summary(e: dict) -> str:
    lines = [f"## codex-threads: {e['verdict']}", "",
             "| rounds | open | not at head | Codex threads |", "|---|---|---|---|",
             f"| {e['rounds']} | {e['open']} | {e['not_at_head']} | {e['codex_threads']} |", "",
             f"Measured at head `{e.get('head', '?')}` through the GitHub API. Green only when "
             "`open` and `not at head` are both zero. Advisory, not a required check."]
    if e["open_threads"]:
        lines += ["", "Open, without an answer of the owner's account: "
                  + ", ".join(f"`{t}`" for t in e["open_threads"])]
    if e["not_at_head_threads"]:
        lines += ["", "Answered, but no named commit is on the head: "
                  + ", ".join(f"`{x['thread']}`" for x in e["not_at_head_threads"])]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="advisory Codex thread check for one pull request")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True)
    ap.add_argument("--owner", default=None, help="the answering account (default: repo owner)")
    ap.add_argument("--summary", default=None, help="append a Markdown summary to this file")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    owner = a.owner or a.repo.split("/", 1)[0]
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        e = measure_at_origin(a.repo, int(a.pr), owner, token)
    except Exception as exc:  # noqa: BLE001 (fail-closed: whatever went wrong, nothing is green)
        text = (f"## codex-threads: NOT MEASURABLE\n\n{type(exc).__name__}: {exc}\n\n"
                "A thread nobody could read is not an answered one.\n")
        print(text)
        if a.summary:
            with open(a.summary, "a", encoding="utf-8") as fh:
                fh.write(text)
        return 2
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as fh:
            fh.write(summary(e))
    print(json.dumps(e, indent=1) if a.json else summary(e))
    return 0 if e["verdict"] == "green" else 1


if __name__ == "__main__":
    sys.exit(main())
