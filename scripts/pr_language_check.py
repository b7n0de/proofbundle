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
                 recognised as such: fenced code, inline backticks, a blockquote line, an HTML
                 `<blockquote>` and text in straight double quotes. Everything else is prose and is
                 scanned.

Three more forms are no prose (counter-reading of pull request 377, F7): a finding identifier in
capitals (`DREI-VERBRAUCHER-...-EINER-01`), a trailer that names a person (`Co-authored-by: Name
<address>`), and a word counted twice, because a line needs two DIFFERENT list words.

THE CHECK RUNS THE COPY OF THE PULL REQUEST (counter-reading of pull request 377, F8, an
observation). `actions/checkout` on `pull_request` checks out the merge of the pull request, so this
script and the word list in `tests/_deutsche_prosa.py` are the ones the pull request carries, and a
pull request can change them and turn itself green, as it can with `scripts/b7_pr_form_gate.py`.
While the check is advisory that has no consequence; when the owner makes it required, the copy of
the base has to run.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import unicodedata
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
_UMLAUT = re.compile("[äöüÄÖÜß\u1e9e]")
#: Every raw marker, words and umlauts, before any threshold. Kept for the retraction probe.
MARKER = re.compile("[äöüÄÖÜß\u1e9e]|" + _GRENZE_VOR + "(?:" + "|".join(_WOERTER) + ")" + _GRENZE_NACH,
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
#: `[ \t]*`, not `\s*` (counter-reading of pull request 377, F9, P3): `\s*` ran over the line breaks
#: that follow, and a body of empty lines took quadratic time (65536 lines 4.28 s at e8748354).
_ZITATZEILE = re.compile(r"^[ \t]*>.*$", re.M)
_HTML_ZITAT = re.compile(r"<blockquote\b.*?</blockquote\s*>", re.S | re.I)
#: A quotation in straight double quotes, also over a line break, never over an empty line: a commit
#: message wraps a quoted sentence like any other.
_ANFUEHRUNG = re.compile(r'"(?:[^"\n]|\n(?![ \t]*\n))*"')
#: No `@` in the two parts of the address (counter-reading of pull request 419, F4): with `@` in both
#: classes, `Co-authored-by: x <` and `a@` repeated took quadratic time (65536 characters 10.96 s).
_PERSON = re.compile(r"^[ \t]*[A-Za-z][A-Za-z-]*-by:[ \t]+[^<>\n]+<[^<>\s@]+@[^<>\s@]+>[ \t]*$", re.M)
_KENNUNG = re.compile(r"(?<![0-9A-Za-z_-])[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){2,}(?![0-9A-Za-z_-])")


def _gelesen(text: str) -> str:
    r"""The text as it reads: after NFKC and without format characters (counter-reading of pull request
    377, F6, P3). A zero-width space inside each list word and a decomposed umlaut hid German prose.

    Every line boundary that `splitlines` knows becomes `\n` (Codex thread 4370565956 on pull request
    419): the expressions below know only `\n`, the line count in `treffer` knows more. With `\r\n` a
    quotation ran over an empty line and took German prose with it, and a trailer ending in `\r` was
    no trailer.

    The boundaries first, the format characters after (counter-reading of pull request 419, F1): a
    format character between `\r` and `\n` left a `\r\n` when it was removed, one boundary where the
    text has two, and the quotation ran over the empty line again. NFKC makes no boundary of its own."""
    t = "\n".join(text.splitlines())
    return "".join(z for z in unicodedata.normalize("NFKC", t) if unicodedata.category(z) != "Cf")


def entkernen(text: str) -> str:
    """Remove what is not prose: typed states and quoted matter.

    Order matters. Fences first, because a fence may contain backticks.
    """
    t = _ZAUN.sub(" ", _gelesen(text))
    t = _HTML_ZITAT.sub(" ", t)
    t = _ZITATZEILE.sub(" ", t)
    t = _INLINE.sub(" ", t)
    t = _ANFUEHRUNG.sub(" ", t)
    t = _PERSON.sub(" ", t)
    t = _KENNUNG.sub(" ", t)
    return _TYPISIERT.sub(" ", t)


def treffer(text: str, *, titel: bool = False) -> list[str]:
    """The German markers of the prose lines of `text` that count as German. Empty list means clean.

    A line counts when it carries an umlaut or an eszett, or at least SCHWELLE different list words; a
    title at SCHWELLE_TITEL list words, of which a word written in capitals is none. Different: one
    acronym twice on a line, `DER ... DER`, made it German (counter-reading of pull request 377, F7)."""
    aus: list[str] = []
    for zeile in entkernen(text or "").splitlines():
        umlaute = _UMLAUT.findall(zeile)
        woerter = _WORT.findall(zeile)
        if titel:
            woerter = [w for w in woerter if not w.isupper()]
        if umlaute or len({w.lower() for w in woerter}) >= (SCHWELLE_TITEL if titel else SCHWELLE):
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
    GitHub writes `null` for an empty body, which reads as the empty text. A payload of another
    shape raises ValueError (counter-reading of pull request 377, F5)."""
    with open(pfad, encoding="utf-8") as f:
        daten = json.load(f) or {}

    def objekt(wert: object, name: str) -> dict:
        if not isinstance(wert, dict):
            raise ValueError(f"{name} is no JSON object")
        return wert

    def text(wert: object, name: str) -> str:
        if wert is not None and not isinstance(wert, str):
            raise ValueError(f"{name} is no string")
        return wert or ""

    pr = objekt(objekt(daten, "the payload").get("pull_request") or {}, "pull_request")
    return (text(pr.get("title"), "title"), text(pr.get("body"), "body"),
            text(objekt(pr.get("base") or {}, "base").get("sha"), "base.sha"),
            text(objekt(pr.get("head") or {}, "head").get("sha"), "head.sha"))


def commit_nachrichten(basis: str, kopf: str, repo: str = ".") -> list[str]:
    """The messages of the commits basis..kopf, each read whole from its object, in its encoding.

    `git log --format=%B` writes a message only up to its first NUL byte, so German text after one
    was never read (counter-reading of pull request 377, F2, P3). A message that is not in the
    encoding its commit declares, UTF-8 when it declares none, raises ValueError (F5)."""
    liste = subprocess.run(["git", "-C", repo, "rev-list", f"{basis}..{kopf}"],
                           capture_output=True, text=True, check=True)
    nachrichten = []
    for sha in liste.stdout.split():
        roh = subprocess.run(["git", "-C", repo, "cat-file", "commit", sha],
                             capture_output=True, check=True).stdout
        kopfteil, _, nachricht = roh.partition(b"\n\n")
        kodierung = next((z[len(b"encoding "):].decode("ascii").strip() for z in kopfteil.split(b"\n")
                          if z.startswith(b"encoding ")), "utf-8")
        nachrichten.append(nachricht.decode(kodierung))
    return nachrichten


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="on GitHub we always write English")
    p.add_argument("--event", help="the runner's event payload; title, body and base..head come from it")
    p.add_argument("--title")
    p.add_argument("--body-file")
    p.add_argument("--commits-file")
    a = p.parse_args(argv)
    # NO SOURCE IS NO MEASUREMENT, and a crash is no finding (counter-reading of pull request 377, F4
    # and F5): an empty `--event` read as no event, no source at all measured nothing and said clean,
    # and an unreadable payload stopped with exit 1, the exit code of German prose found.
    if a.event is not None:
        if a.title is not None or a.body_file or a.commits_file:
            p.error("--event reads the title, the body and the commits itself")
        try:
            titel, body, basis, kopf = aus_ereignis(a.event)
        except (OSError, ValueError) as e:
            print(f"pr-language-check: NOT MEASURABLE, the event payload is not readable: "
                  f"{type(e).__name__}: {str(e)[:200]}")
            return 2
        if not (_SHA.fullmatch(basis) and _SHA.fullmatch(kopf)):
            # A check that reads no commits and reports clean would be green without a measurement.
            print("pr-language-check: NOT MEASURABLE, the event payload names no base and head commit")
            return 2
        try:
            commits = commit_nachrichten(basis, kopf)
        except subprocess.CalledProcessError as e:
            fehler = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else e.stderr
            print(f"pr-language-check: NOT MEASURABLE, git log {basis[:12]}..{kopf[:12]} failed: "
                  f"{(fehler or '').strip()[:200]}")
            return 2
        except (OSError, ValueError, LookupError) as e:
            print(f"pr-language-check: NOT MEASURABLE, a commit of {basis[:12]}..{kopf[:12]} is not "
                  f"readable: {type(e).__name__}: {str(e)[:200]}")
            return 2
        # The form the payload check above forbids, for the range (counter-reading of pull request
        # 377, F3): a head equal to the base, or behind it, reads no commit.
        if not commits:
            print(f"pr-language-check: NOT MEASURABLE, {basis[:12]}..{kopf[:12]} holds no commit")
            return 2
    elif a.title is None and not a.body_file and not a.commits_file:
        print("pr-language-check: NOT MEASURABLE, no source: name --event, or --title, --body-file "
              "or --commits-file")
        return 2
    else:
        titel = a.title or ""
        try:
            body = open(a.body_file, encoding="utf-8").read() if a.body_file else ""
            commits = (open(a.commits_file, encoding="utf-8").read().split("\0")
                       if a.commits_file else [])
        except (OSError, ValueError) as e:
            print(f"pr-language-check: NOT MEASURABLE, {type(e).__name__}: {str(e)[:200]}")
            return 2
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
