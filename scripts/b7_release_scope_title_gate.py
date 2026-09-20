#!/usr/bin/env python3
"""A pull request that carries a release-scope line names that line's identifier in its title.

WHY THIS GATE EXISTS. `docs/release_scope/<version>.md` maps each scope item to its own branch:
one identifier, one branch, one pull request. Without a gate that mapping is a promise in a
document — readable, and unenforced. The landing card counts what landed by reading identifiers
out of the pull-request titles on main, so a title without its identifier is not a cosmetic
omission: it makes the item invisible to the count that is supposed to track it.

Owner decision 2026-09-14: the title form is English, `[<version> <ID>] type(scope): subject`,
exactly one identifier per pull request.

WHAT THIS GATE DOES NOT DO, said plainly. It judges the BRANCH, not the diff. A pull request whose
head branch is named in the scope file must carry that line's identifier; a branch the scope file
does not name is not judged here at all, and is reported as such rather than as a pass. Deciding
"does this diff touch scope content" from the changed files would be a second, weaker oracle over
the same question, and a guess dressed as a measurement is worse than a stated limit.

THE RIDERS ARE AN EXCEPTION BY CONSTRUCTION, not by a hand-kept list. Scope lines whose branch
column says "mit X", "= X" or names no branch at all ride along with another item. They have no
branch of their own, so no pull request can ever match them, so they can never trigger this gate.
That is the same exception the order names, derived from the file instead of copied out of it —
a copied list is a second truth that ages the moment the file moves.

Exit: 0 green · 1 RED, with the reason. Never a third outcome: a gate that cannot measure and
says so quietly reads, in a pull-request check list, exactly like one that passed.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]

#: An identifier from the scope file: a letter, an optional dot or dash, an optional SECOND
#: letter, digits, optionally a sub-part. Covers A1, A5.1, B-3, N1-1a, N2-3a, S65-5, Z.278, R-A1.
#:
#: THE SECOND LETTER WAS ADDED 2026-09-19, and the way it was found matters more than the change.
#: The owner decision renamed three RESTRISIKO lines to R-A1, R-A2, R-A3 to end an ambiguity: the
#: names A1, A2, A3 led two lines each. After the rename the file check reported GREEN, no
#: collisions -- and it was wrong. This expression did not match `R-A1`, so all three lines were
#: dropped before they could collide with anything. The count fell from 56 lines to 53 and the
#: verdict turned green on the way. Whoever reads only the verdict sees a fix; whoever reads the
#: count sees three lines that stopped existing. The collision had not been resolved, it had been
#: made invisible.
_KENNUNG = r"[A-Z]\.?-?[A-Z]?\d+(?:[.\-][0-9a-z]+)*"

#: THE WHOLE TITLE FORM, anchored at both ends. The contract in the module docstring above reads
#: `[<version> <ID>] type(scope): subject`, exactly one identifier, at the start.
#:
#: UNTIL 2026-09-16 THIS WAS AN UNANCHORED `findall`, which asks a different question altogether,
#: namely whether a bracket of this version appears anywhere in the title. Measured at head
#: 1077c3d, three titles passed green: `WRONG PREFIX [6.1.0 N3-1] nonsense`, then
#: `irgendwas [6.1.0 N3-1]` with no subject form at all, and
#: `[6.1.0 N3-1] [6.0.1 R1] feat(scope): subject` carrying a second identifier of a FOREIGN
#: version, which went uncounted because only matches of the current version were counted. Three
#: titles, all green, none conforming. Codex round one raised it; it was re-measured here, and it
#: reaches further than reported, because the third form was not in the report.
#: THE SEPARATORS ARE PLAIN SPACES, not `\s`, and the title is ONE line. Both were measured on
#: the first version of this expression, by running it rather than by reading it.
#:
#: `\s` in Python matches U+00A0 and U+2009 as well, so `[6.1.0<narrow space>A1] feat(x): y`
#: passed. The landing card reads identifiers out of titles with its own reader, and two readers
#: that disagree about what a space is will disagree about which line landed. A separator that
#: looks like a space and is not one is exactly the kind of difference this gate exists to catch.
#:
#: And `\s` matches a newline, so `[6.1.0 A1] feat(x): y\nanything at all` passed as well:
#: the form bound the first line and said nothing about the rest. A pull-request title is one
#: line; whatever follows a line break was never judged, and a rule that stops at the first
#: newline judges a prefix while claiming to judge a title.
_TITELFORM = re.compile(
    rf"^\[ *(?P<version>[0-9]+(?:\.[0-9]+)*) +(?P<kennung>{_KENNUNG}) *\]"
    r" +(?P<typ>[a-z][a-z0-9]*)(?:\([^()]+\))?: +\S[^\r\n]*\Z")

#: EVERY identifier bracket in the title, whatever its version. The old expression counted only
#: the current one, so a second bracket of a foreign version stayed invisible, which is exactly the
#: ambiguity that "exactly one identifier" was written against.
_JEDE_KLAMMER = re.compile(rf"\[ *[0-9]+(?:\.[0-9]+)* +{_KENNUNG} *\]")

#: Where the scope ends. Everything after that (Out, rationales, owner doors) is NOT the set
#: against which a pull request is checked — those are lines that are explicitly not being built.
_ENDE_DES_UMFANGS = re.compile(r"^##\s+Out\b", re.M)


def lies_umfang(pfad: pathlib.Path) -> tuple[dict[str, list[str]], list[str], str]:
    """(Branch -> LIST of identifiers, riders, state). Only the In section counts.

    A LIST, BECAUSE A MAPPING IN EITHER DIRECTION CAN LOSE DATA. The first version mapped
    identifier -> branch and silently overwrote as soon as two lines carried the same identifier —
    and the 6.1.0 scope does exactly that three times (A1, A2, A3). The second version reversed
    the direction and lost data the mirror-image way, as soon as two lines named the same branch.
    Both times the loss was SILENT. A list loses nothing, and the ambiguity becomes a finding
    instead of an absence. Both versions were caught by the contract itself, not by reading.

    NOTE: AN IDENTIFIER DOES NOT IDENTIFY A LINE. Measured on the 6.1.0 scope: A1, A2 and A3 each
    lead TWO different lines, one from the collective order and one from RESTRISIKO_600, with a
    different subject and a different branch. The return value here therefore reliably maps only
    branch -> identifier (branches are unique); the reverse direction is ambiguous and is reported
    by `pruefe_umfangsdatei` as a finding about the FILE, rather than silently overwritten.

    Returns three things, because three different questions hang on it: which branch belongs to
    which identifier, which lines have no branch of their own at all (and can therefore never be a
    pull request), and whether the file was readable at all. The third is the most important: an
    empty mapping from a missing file looks like an empty mapping from an empty scope, and the two
    mean the opposite of each other.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return {}, [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        # FAIL-CLOSED, and that too was found by the foreign model family. Without the marker, the
        # WHOLE file previously counted as scope — including the lines under "Out", which are
        # explicitly NOT being built. A gate that ENLARGES the set it checks when structure is
        # missing then judges lines nobody wanted to build, and calls that a measurement.
        return {}, [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — ohne ihn ist die Grenze "
                        "des Umfangs nicht bestimmbar, und die ganze Datei als Umfang zu lesen "
                        "waere eine Vergroesserung der Pruefmenge, keine Messung")
    im_umfang = text[: schnitt.start()]
    zu_zweig: dict[str, list[str]] = {}
    mitlaeufer: list[str] = []
    for zeile in im_umfang.splitlines():
        if not zeile.startswith("|") or zeile.count("|") < 3:
            continue
        spalten = [s.strip() for s in zeile.strip("|").split("|")]
        if len(spalten) < 2:
            continue
        punkt, zweig = spalten[0], spalten[-1]
        if set(zweig) <= set("-: ") or not punkt:
            continue
        m = re.match(rf"^\**({_KENNUNG})", punkt)
        if not m:
            continue
        kennung = m.group(1)
        if zweig.startswith("`") and zweig.endswith("`"):
            # BRANCH -> IDENTIFIER, not the other way round. The reverse direction OVERWRITES
            # silently as soon as two lines carry the same identifier, and the 6.1.0 scope does
            # exactly that three times (A1, A2, A3). The first branch would lose its mapping in
            # that case and would then count as "outside the scope" — a pull request on a real
            # scope line would have run through unchecked. Found by the contract itself, not by
            # reading the text.
            zu_zweig.setdefault(zweig.strip("`"), []).append(kennung)
        else:
            mitlaeufer.append(kennung)
    if not zu_zweig:
        return {}, mitlaeufer, "NICHT MESSBAR: kein einziger Zweig im In-Abschnitt gefunden"
    return zu_zweig, mitlaeufer, "gemessen"


def fuehrende_kennungen(pfad: pathlib.Path) -> tuple[list[tuple[str, str, str]], str]:
    """Every In-line as (identifier, item, branch column) — LINE BY LINE, without collapsing.

    The counting unit is the LINE, not the identifier and not the branch. Measured on the 6.1.0
    scope: 56 lines, 56 distinct leading identifiers, 9 riders. Whoever counts by branch is short.

    THESE NUMBERS MOVED TWICE, and both moves are named because a stale number here teaches a
    wrong one. 55 lines / 52 identifiers held until 2026-09-18, when P19 landed with pull request
    224 and added one line. The identifiers caught up with the lines on 2026-09-19: three
    RESTRISIKO rows were renamed to R-A1, R-A2, R-A3 (owner card OA-23931230c0), which ended the
    only collision the file had. A number in a docstring is a claim about a measurement; when the
    measurement moves and the claim does not, the claim starts teaching the wrong thing.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        return [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — die Grenze des Umfangs ist "
                    "nicht bestimmbar")
    im_umfang = text[: schnitt.start()]
    aus: list[tuple[str, str, str]] = []
    for zeile in im_umfang.splitlines():
        if not zeile.startswith("|") or zeile.count("|") < 3:
            continue
        spalten = [s.strip() for s in zeile.strip("|").split("|")]
        if len(spalten) < 2 or set(spalten[-1]) <= set("-: ") or not spalten[0]:
            continue
        m = re.match(rf"^\**({_KENNUNG})", spalten[0])
        if m:
            aus.append((m.group(1), spalten[0], spalten[-1]))
    return aus, ("gemessen" if aus else "NICHT MESSBAR: keine Zeile im In-Abschnitt gefunden")


#: What the LAST column of a scope table is called. Two spellings because the file was translated
#: and the guard was not; a third language costs one entry here instead of another silent blindness.
_ZWEIGSPALTE = frozenset({"zweig", "branch"})

#: How many scope rows the last call examined. An empty finding list over ZERO examined rows and one
#: over forty are different facts, and this is where a caller can tell them apart.
ZULETZT_GEPRUEFT = 0


def zeilen_ohne_kennung(pfad: pathlib.Path) -> tuple[list[str], str]:
    """Every In-line whose first column carries NO identifier this module can read.

    THE CLASS, not the instance. Both readers above end their loop with "no match, next line".
    That is the quiet variant of a wrong answer: the line does not become a finding, it stops
    existing. The landing card then counts a scope it cannot see all of, and the count looks
    healthy because nothing complains.

    It was not a hypothetical. On 2026-09-19 the rename to R-A1, R-A2, R-A3 hit exactly this:
    the expression did not know the shape, three lines fell out of the count, and the file check
    answered GREEN -- the collision it was meant to report had disappeared along with the lines
    that caused it. Widening the expression fixes that one shape. This function is what catches
    the NEXT shape nobody thought of, because from here on an unreadable line is reported instead
    of dropped.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        return [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — die Grenze des Umfangs ist "
                    "nicht bestimmbar")
    aus: list[str] = []
    # ONLY TABLES THAT ASSIGN BRANCHES. The In section also carries the table of the three owner
    # decisions (Karte | Zeit | Entscheid), which names no branch and is not scope. A first
    # version checked every table row and reported eight findings on the only real file -- four
    # header rows and the three owner cards. A guard that fires eight times on the one input it
    # was written for is measuring its own reach, not the file. The header row names the column,
    # so the file itself says which table is which.
    #
    # THE HEADER WORD WAS GERMAN AND THE FILE IS ENGLISH, which made this guard blind on the only
    # file it guards. Measured 2026-09-20 by a counter-reading: `docs/release_scope/6.1.0.md` heads
    # its two In-tables with `| Identifier | PR | Merge commit | Title |` and
    # `| Identifier | Subject | Branch |`. Neither last column is `Zweig`, so `im_umfangstabelle`
    # never became True and this function returned an empty list for the whole file -- not because
    # nothing was unreadable, but because it never entered a table. A guard built against a line
    # that vanishes from a count had itself vanished, silently, at the translation.
    #
    # Both spellings are recognised now, and ZERO examined rows is its own state instead of an
    # empty finding list that reads like a clean one.
    global ZULETZT_GEPRUEFT
    im_umfangstabelle = False
    geprueft = 0
    for zeile in text[: schnitt.start()].splitlines():
        if not zeile.startswith("|") or zeile.count("|") < 3:
            im_umfangstabelle = False
            continue
        spalten = [s.strip() for s in zeile.strip("|").split("|")]
        if len(spalten) < 2 or not spalten[0]:
            continue
        if set(spalten[-1]) <= set("-: "):
            continue          # separator row; the header above it already decided
        if spalten[-1].lower() in _ZWEIGSPALTE:
            im_umfangstabelle = True   # header of a scope table; not itself a scope line
            continue
        if any(s.lower() in ("karte", "punkt", "eintrag", "tuer") for s in spalten[:1]):
            im_umfangstabelle = False  # header of a table WITHOUT a branch column
            continue
        if not im_umfangstabelle:
            continue
        geprueft += 1
        if not re.match(rf"^\**({_KENNUNG})", spalten[0]):
            aus.append(spalten[0][:60])
    ZULETZT_GEPRUEFT = geprueft
    if geprueft == 0:
        return aus, ("NICHT MESSBAR: keine Zeile einer Umfangstabelle erreicht — kein Tabellenkopf "
                     f"nennt eine Spalte aus {sorted(_ZWEIGSPALTE)}, es wurde nichts geprueft")
    return aus, "gemessen"


def pruefe_umfangsdatei(pfad: pathlib.Path) -> dict:
    """The file itself: does every identifier lead EXACTLY ONE line?

    This is a statement about the FILE, not about a pull request, and it belongs separately: an
    identifier assigned twice is not a mistake by the author who dutifully writes it into their
    title — it merely makes their title ambiguous. The landing card counts landed lines from
    titles; two lines under one identifier become one there, and the other disappears from the
    number that is supposed to prove it landed.
    """
    zeilen, zustand = fuehrende_kennungen(pfad)
    if zustand != "gemessen":
        return {"schema": "b7n0de.release_scope_datei.v1", "urteil": "ROT",
                "gruende": [f"Umfangsdatei {pfad} {zustand}"], "zeilen": 0,
                "kennungen": 0, "kollisionen": {}}
    von_kennung: dict[str, list[str]] = {}
    for k, punkt, _z in zeilen:
        von_kennung.setdefault(k, []).append(punkt[:60])
    kollisionen = {k: v for k, v in von_kennung.items() if len(v) > 1}
    gruende = [f"Kennung {k!r} fuehrt {len(v)} Zeilen an {v} — ein Titel [{'<version>'} {k}] "
               "zeigt damit auf mehr als eine Zeile, und die Landekarte zaehlt sie als eine"
               for k, v in sorted(kollisionen.items())]
    # A LINE THIS MODULE CANNOT READ IS A FINDING, NOT AN ABSENCE. Without this, an unknown
    # identifier shape leaves the count silently and the verdict gets GREENER, not redder.
    unlesbar, _ = zeilen_ohne_kennung(pfad)
    if unlesbar:
        gruende.append(
            f"{len(unlesbar)} Zeile(n) des In-Abschnitts fuehren keine lesbare Kennung {unlesbar} "
            "— sie fallen aus der Zaehlung und die Landekarte kann sie nie zaehlen. Zu tun ist es "
            "in der Umfangsdatei oder am Kennungsmuster, nicht am Titel")
    return {
        "schema": "b7n0de.release_scope_datei.v1",
        "urteil": "gruen" if not gruende else "ROT",
        "gruende": gruende,
        "zeilen": len(zeilen),
        "kennungen": len(von_kennung),
        "zeilen_ohne_kennung": unlesbar,
        "kollisionen": {k: v for k, v in sorted(kollisionen.items())},
    }


def pruefe(*, branch: str, title: str, version: str,
           scope_pfad: pathlib.Path | None = None) -> dict:
    """The verdict. Two-valued, and every RED carries its reason."""
    pfad = scope_pfad or (REPO / "docs" / "release_scope" / f"{version}.md")
    zu_zweig, mitlaeufer, zustand = lies_umfang(pfad)
    gruende: list[str] = []
    if zustand != "gemessen":
        gruende.append(f"Umfangsdatei {pfad} {zustand} — ohne sie ist nicht messbar, ob dieser "
                       "Pull Request eine Umfangszeile traegt; Unkenntnis sperrt")
        return _urteil(branch, title, version, gruende, None, zu_zweig, mitlaeufer, zustand)

    passend = sorted(zu_zweig.get(branch) or [])
    if not passend:
        # NOT A PASS, BUT A STATEMENT ABOUT REACH. The caller should see that nothing was checked
        # here, rather than reading a green checkmark as a statement about the content.
        return _urteil(branch, title, version, [], None, zu_zweig, mitlaeufer, zustand,
                       ausserhalb=True)
    if len(passend) > 1:
        gruende.append(f"der Zweig {branch!r} steht bei MEHREREN Umfangszeilen {passend} — "
                       "ein Zweig je Zeile, sonst zaehlt die Landekarte ihn doppelt oder gar nicht")
        return _urteil(branch, title, version, gruende, None, zu_zweig, mitlaeufer, zustand)

    kennung = passend[0]
    # AN UNREADABLE LINE IS A FINDING ABOUT THE FILE AND IT REACHES THE RUN. Reported in
    # `pruefe_umfangsdatei` alone it would never be seen: CI calls `main`, and `main` calls this
    # function. A guard nobody calls is the same shape of failure it exists to catch.
    unlesbar, _ul = zeilen_ohne_kennung(pfad)
    if unlesbar:
        gruende.append(
            f"die Umfangsdatei fuehrt {len(unlesbar)} Zeile(n) ohne lesbare Kennung {unlesbar} — "
            "sie fallen aus der Zaehlung, und kein Titel kann je auf sie zeigen")
    # A collision is a finding about the FILE. It is recorded in the result, but is not held
    # against the pull request's author: they can only write the one identifier that exists.
    datei_urteil = pruefe_umfangsdatei(pfad)
    kollision = kennung in (datei_urteil.get("kollisionen") or {})
    # THE WHOLE FORM, AT THE START, EXACTLY ONE IDENTIFIER, in that order, because each step is
    # what makes the next one meaningful. First, how many identifier brackets does the title carry
    # at all, whatever their version. Then, does the title as a WHOLE match the contract form. Only
    # then, does it name the right identifier.
    alle_klammern = _JEDE_KLAMMER.findall(title)
    if len(alle_klammern) > 1:
        gruende.append(f"der Titel nennt {len(alle_klammern)} Kennungen {alle_klammern} — genau "
                       "eine je Pull Request, sonst ist die Zuordnung zur Umfangszeile mehrdeutig. "
                       "Gezaehlt werden ALLE Versionen, nicht nur die eigene: eine zweite Klammer "
                       "fremder Version macht den Titel genauso mehrdeutig")
    form = _TITELFORM.match(title)
    if not form and not alle_klammern:
        # THE MOST COMMON CASE DESERVES ITS OWN SENTENCE. A title with no bracket at all and a
        # title with a bracket in the wrong place are two different jobs for whoever has to fix
        # them, and one shared shape message for both leaves the author guessing which one they
        # have. An existing case asserted exactly this wording and fell when the two were folded
        # together, and it was right to.
        gruende.append(f"der Titel nennt keine Umfangskennung: erwartet [{version} {kennung}] "
                       f"am Anfang, gelesen {title!r}")
    elif not form:
        gruende.append(
            f"der Titel haelt die Form nicht ein: erwartet [{version} {kennung}] "
            f"type(scope): subject AM ANFANG, gelesen {title!r}. Geprueft wird der ganze Titel, "
            "nicht ob die Klammer irgendwo vorkommt")
    else:
        if form.group("version") != version:
            gruende.append(f"der Titel nennt die Version {form.group('version')!r}, geprueft wird "
                           f"gegen {version!r} — Titel und Umfangsdatei zeigen auf verschiedene "
                           "Releases")
        elif form.group("kennung") != kennung:
            gruende.append(f"der Titel nennt [{version} {form.group('kennung')}], der Zweig "
                           f"{branch!r} gehoert aber zu {kennung} — Titel und Zweig zeigen auf "
                           "verschiedene Zeilen")
    if kollision:
        # RED, and the foreign model family talked me around here (2026-09-16). My first version
        # let a pull request like this through green, with a note: the author can, after all,
        # only write the one identifier that exists. Their objection carries: the PURPOSE of this
        # gate is unambiguous countability, and a title the landing card cannot assign misses it —
        # whoever is at fault. Green here would mean: the pull request is fine, even though its
        # landing is not countable. And the fix stands open, it just is not in the title: split
        # the identifier in the scope file.
        zeilen = (pruefe_umfangsdatei(pfad).get("kollisionen") or {}).get(kennung, [])
        gruende.append(
            f"die Kennung {kennung!r} fuehrt {len(zeilen)} Zeilen der Umfangsdatei an {zeilen} — "
            "ein Titel mit ihr ist nicht zuordenbar, und die Landekarte zaehlt zwei Zeilen als "
            "eine. Zu tun ist es in der Umfangsdatei, nicht im Titel: die Kennung aufteilen")
    d = _urteil(branch, title, version, gruende, kennung, zu_zweig, mitlaeufer, zustand)
    d["kennung_mehrdeutig"] = kollision
    return d


def _urteil(branch, title, version, gruende, kennung, zu_zweig, mitlaeufer, zustand,
            *, ausserhalb: bool = False) -> dict:
    gruen = not gruende
    return {
        "schema": "b7n0de.release_scope_title_gate.v1",
        "version": version, "branch": branch, "title": title,
        "urteil": "gruen" if gruen else "ROT",
        "gruende": gruende,
        "kennung_des_zweigs": kennung,
        "ausserhalb_des_umfangs": ausserhalb,
        "umfang_zustand": zustand,
        "umfangszeilen_mit_zweig": len(zu_zweig),
        "mitlaeufer_ohne_zweig": sorted(mitlaeufer),
        # EXPLICITLY STATED, so that nobody reads more into it than is there.
        "geprueft_wird": "der head-Zweig gegen die Umfangsdatei, NICHT der Diff",
        "nicht_geprueft": ("ob ein Pull Request auf einem nicht genannten Zweig inhaltlich eine "
                           "Umfangszeile beruehrt — das entscheidet dieser Riegel nicht"),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--branch", required=True, help="der head-Zweig des Pull Requests")
    p.add_argument("--title", required=True, help="der Titel des Pull Requests")
    p.add_argument("--version", default="6.1.0")
    p.add_argument("--scope", default=None, help="Pfad der Umfangsdatei (sonst aus --version)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    d = pruefe(branch=a.branch, title=a.title, version=a.version,
               scope_pfad=pathlib.Path(a.scope) if a.scope else None)
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        marke = "ausserhalb des Umfangs" if d["ausserhalb_des_umfangs"] else (
            d["kennung_des_zweigs"] or "—")
        print(f"release-scope-title: {d['urteil']} · {d['branch']} · {marke}")
        for g in d["gruende"]:
            print(f"  ! {g}")
        print(f"  geprueft: {d['geprueft_wird']}")
    return 0 if d["urteil"] == "gruen" else 1


if __name__ == "__main__":
    raise SystemExit(main())
