#!/usr/bin/env python3
"""pr-language-gate — on GitHub we always write English.

Standard: the house standard "on GitHub we always write English" of 2026-09-13, rules R1 (marker
list), R2 (this job), R3 (the two-way catch proof).

WHY THIS EXISTS, measured: on 2026-09-13 PR 201 was written entirely in German and PR 200 carried a
German title over an English body. Both were repaired by hand. A rule that lives only in prose gets
followed until someone is in a hurry.

THE ONE THING THIS GATE MUST NOT DO is flag its own house vocabulary. Measured on PR 189 the same
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
import re
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


def treffer(text: str) -> list[str]:
    """The German markers of the prose lines of `text` that count as German. Empty list means clean.

    A line counts when it carries an umlaut or an eszett, or at least SCHWELLE list words."""
    aus: list[str] = []
    for zeile in entkernen(text or "").splitlines():
        umlaute = _UMLAUT.findall(zeile)
        woerter = _WORT.findall(zeile)
        if umlaute or len(woerter) >= SCHWELLE:
            aus += umlaute + woerter
    return aus


def pruefe(titel: str, text: str, commits: list[str] | None = None) -> dict:
    teile = {"title": titel or "", "body": text or ""}
    for i, c in enumerate(commits or [], 1):
        teile[f"commit {i}"] = c
    befunde = {k: treffer(v) for k, v in teile.items()}
    befunde = {k: v for k, v in befunde.items() if v}
    return {"sauber": not befunde, "befunde": befunde}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="on GitHub we always write English")
    p.add_argument("--title", default="")
    p.add_argument("--body-file")
    p.add_argument("--commits-file")
    a = p.parse_args(argv)
    body = open(a.body_file, encoding="utf-8").read() if a.body_file else ""
    commits = (open(a.commits_file, encoding="utf-8").read().split("\0")
               if a.commits_file else [])
    erg = pruefe(a.title, body, [c for c in commits if c.strip()])
    if erg["sauber"]:
        print("pr-language-gate: clean, no German prose in title, body or commit messages")
        return 0
    print("pr-language-gate: German prose found. On GitHub we always write English.")
    for ort, tr in erg["befunde"].items():
        print(f"  {ort}: {len(tr)} marker(s) -> {sorted(set(t.lower() for t in tr))[:8]}")
    print("  Typed house states and quoted matter are exempt; these hits are prose.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
