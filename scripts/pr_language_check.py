#!/usr/bin/env python3
"""pr-language-check — on GitHub we always write English.

Standard: the house standard "on GitHub we always write English" of 2026-09-13, rules R1 (marker
list), R2 (this job), R3 (the two-way catch proof).

WHY THIS EXISTS, measured: on 2026-09-13 PR 201 was written entirely in German and PR 200 carried a
German title over an English body. Both were repaired by hand. A rule that lives only in prose gets
followed until someone is in a hurry.

A CHECK, NOT A GATE (owner decision 2026-10-18, card OA-cb01830123, option A). It runs as its own job
of `.github/workflows/pr-form.yml`, on every event that changes the title, the body or the commits,
edits included, and like the form gate there it is not a required context of the ruleset
protect-main: its red shows and blocks no merge until the owner makes it required. Codex threads
4303690781 and 4303690782 on pull request 377 found the first form, a job in ci.yml, named a gate
that bound nothing and judged an edited text never.

With `--event` it reads the title, the body and the base and head commits of the pull request from
the runner's own event payload and the commit messages from `git log base..head`, so no text of the
pull request is spliced into a command line.

THE ONE THING THIS CHECK MUST NOT DO is flag its own house vocabulary. Measured on PR 189 the same
day: a naive marker scan reported it as German because the body contains `NICHT MESSBAR`, which is a
typed state of this house used as a term of art inside an English sentence. The order's own briefing
listed 189 as English, and it was right. A gate that cannot tell a declared state name from German
prose produces false reds on exactly the texts that are most careful about honesty.

Two escapes, both narrow and both declared:

  TYPED STATES   `NICHT MESSBAR`, `PARTIAL_…`, `BLOCKED_…`, `NICHT GEMESSEN`, `NICHT GEPRUEFT` and
                 the other house markers are removed before scanning. They are states, not language.

  QUOTED GERMAN  R3 requires that an English text quoting a German sentence stays green. A quote is
                 recognised as such: fenced code, inline backticks, or a blockquote line. Everything
                 else is prose and is scanned.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

#: The TOOL's own root. The shared word list is part of the tool, so it is looked up here, the same
#: way scripts/neue_zeilen_sind_englisch.py looks it up.
WERKZEUG_WURZEL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WERKZEUG_WURZEL))
from tests import _deutsche_prosa as DP  # noqa: E402

#: R1 verbatim: umlauts, eszett, and these stop words.
_STOPWOERTER = ("und", "nicht", "wird", "der", "die", "das", "wenn", "statt", "ohne", "keine")

#: ONE LIST FOR ONE QUESTION. The repository already answers "is this German prose?" with
#: tests/_deutsche_prosa.py, and its docstring says why a second list is a defect: two lists drift,
#: and the weaker one decides wherever it stands. The words here are R1 together with that list, and
#: the boundary is the shared one, which counts an underscore as part of a word.
_WOERTER = tuple(sorted(set(_STOPWOERTER) | set(DP.FUNKTIONSWOERTER)))
_GRENZE_VOR, _GRENZE_NACH = r"(?<![0-9a-zA-Z_])", r"(?![0-9a-zA-Z_])"
_WORT = re.compile(_GRENZE_VOR + "(" + "|".join(_WOERTER) + ")" + _GRENZE_NACH, re.IGNORECASE)
_UMLAUT = re.compile(r"[äöüÄÖÜß]")
#: Every raw marker, words and umlauts, before any threshold. Kept for the retraction probe.
MARKER = re.compile(r"[äöüÄÖÜß]|" + _GRENZE_VOR + "(?:" + "|".join(_WOERTER) + ")" + _GRENZE_NACH,
                    re.IGNORECASE)

#: How many list words one line of prose needs before it counts as German, the same threshold as
#: scripts/neue_zeilen_sind_englisch.py. MEASURED 2026-10-17 over the 32 open pull requests of this
#: repository: with a single word enough, five of them were red, and every hit was the English
#: acronym DER (`DER X.509`, `SubjectPublicKeyInfo DER`) in a commit message or body. One word is
#: noise; "die" is an English verb as well. An umlaut or an eszett stays enough on its own, as R1 says,
#: because English prose does not carry one.
SCHWELLE = 2

#: A TITLE IS ONE SHORT LINE (counter-reading of pull request 377, F1, P2). Two list words is the
#: threshold measured for a line of a body or of a commit message, but four of six German titles in
#: the house style carry only one (`feat: Tor ohne Ausnahme`), and R1 counts one. In the title one
#: list word is enough, unless it is written in capitals: every hit that set the threshold at two was
#: the acronym DER. MEASURED 2026-10-24 over the 151 titles that reached main since 2026-09-14: none
#: is red under this rule, and the four German titles are. The limit: an English title that uses the
#: verb "die" is red.
SCHWELLE_TITEL = 1

#: Typed house states. They contain German words by construction and are NOT prose.
#: Measured need: `NICHT MESSBAR` in PR 189 made a naive scan call an English text German.
TYPISIERTE_ZUSTAENDE = (
    "NICHT MESSBAR", "NICHT GEMESSEN", "NICHT GEPRUEFT", "NICHT ANWENDBAR",
    "UNBELEGT", "WITHSTANDS_DEEPGATE", "PARTIAL_GATE_NO_WITHSTANDS",
)
_TYPISIERT = re.compile(
    "|".join([re.escape(s) for s in TYPISIERTE_ZUSTAENDE] + [r"PARTIAL_[A-Z0-9_]+", r"BLOCKED_[A-Z0-9_]+"]))

_ZAUN = re.compile(r"```.*?```|~~~.*?~~~", re.S)
_INLINE = re.compile(r"`[^`\n]*`")
_ZITATZEILE = re.compile(r"^\s*>.*$", re.M)


def entkernen(text: str) -> str:
    """Remove what is not prose: typed states and quoted matter.

    Order matters. Fences first, because a fence may contain backticks.
    """
    t = _ZAUN.sub(" ", text)
    t = _ZITATZEILE.sub(" ", t)
    t = _INLINE.sub(" ", t)
    return _TYPISIERT.sub(" ", t)


def treffer(text: str, *, titel: bool = False) -> list[str]:
    """The German markers of the prose lines of `text` that count as German. Empty list means clean.

    A line counts when it carries an umlaut or an eszett, or at least SCHWELLE list words; a title
    at SCHWELLE_TITEL list words, of which a word written in capitals is none."""
    aus: list[str] = []
    for zeile in entkernen(text or "").splitlines():
        umlaute = _UMLAUT.findall(zeile)
        woerter = _WORT.findall(zeile)
        if titel:
            woerter = [w for w in woerter if not w.isupper()]
        if umlaute or len(woerter) >= (SCHWELLE_TITEL if titel else SCHWELLE):
            aus += umlaute + woerter
    return aus


def pruefe(titel: str, text: str, commits: list[str] | None = None) -> dict:
    teile = {"title": titel or "", "body": text or ""}
    for i, c in enumerate(commits or [], 1):
        teile[f"commit {i}"] = c
    befunde = {k: treffer(v, titel=(k == "title")) for k, v in teile.items()}
    befunde = {k: v for k, v in befunde.items() if v}
    return {"sauber": not befunde, "befunde": befunde}


#: A commit as the event payload names it. Anything else is not handed to git, so no value of the
#: payload can become an option of `git log`.
_SHA = re.compile(r"[0-9a-f]{40}")


def aus_ereignis(pfad: str) -> tuple[str, str, str, str]:
    """Title, body, base commit and head commit of the pull request in the runner's event payload.
    GitHub writes `null` for an empty body, which reads as the empty text."""
    with open(pfad, encoding="utf-8") as f:
        pr = (json.load(f) or {}).get("pull_request") or {}
    return (pr.get("title") or "", pr.get("body") or "",
            (pr.get("base") or {}).get("sha") or "", (pr.get("head") or {}).get("sha") or "")


def commit_nachrichten(basis: str, kopf: str, repo: str = ".") -> list[str]:
    """The messages of the commits basis..kopf, read with git in `repo`."""
    r = subprocess.run(["git", "-C", repo, "log", "--format=%B%x00", f"{basis}..{kopf}"],
                       capture_output=True, text=True, check=True)
    return [c for c in r.stdout.split("\0") if c.strip()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="on GitHub we always write English")
    p.add_argument("--event", help="the runner's event payload; title, body and base..head come from it")
    p.add_argument("--title", default="")
    p.add_argument("--body-file")
    p.add_argument("--commits-file")
    a = p.parse_args(argv)
    if a.event:
        if a.title or a.body_file or a.commits_file:
            p.error("--event reads the title, the body and the commits itself")
        titel, body, basis, kopf = aus_ereignis(a.event)
        if not (_SHA.fullmatch(basis) and _SHA.fullmatch(kopf)):
            # A check that reads no commits and reports clean would be green without a measurement.
            print("pr-language-check: NOT MEASURABLE, the event payload names no base and head commit")
            return 2
        try:
            commits = commit_nachrichten(basis, kopf)
        except subprocess.CalledProcessError as e:
            print(f"pr-language-check: NOT MEASURABLE, git log {basis[:12]}..{kopf[:12]} failed: "
                  f"{(e.stderr or '').strip()[:200]}")
            return 2
    else:
        titel = a.title
        body = open(a.body_file, encoding="utf-8").read() if a.body_file else ""
        commits = (open(a.commits_file, encoding="utf-8").read().split("\0")
                   if a.commits_file else [])
    erg = pruefe(titel, body, [c for c in commits if c.strip()])
    if erg["sauber"]:
        print("pr-language-check: clean, no German prose in title, body or commit messages")
        return 0
    print("pr-language-check: German prose found. On GitHub we always write English.")
    for ort, tr in erg["befunde"].items():
        print(f"  {ort}: {len(tr)} marker(s) -> {sorted(set(t.lower() for t in tr))[:8]}")
    print("  Typed house states and quoted matter are exempt; these hits are prose.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
