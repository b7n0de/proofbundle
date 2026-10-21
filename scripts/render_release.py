#!/usr/bin/env python3
"""Render a release body from the versioned content source, deterministically.

WHY A SOURCE AND NOT A TITLE PREFIX. The grouping of a release comes from
``release_notes/release-source.json``, a file that is reviewed and versioned like any other, not
from the conventional-commit prefix of a pull request title. Owner word of 2026-09-23: prefixes
such as ``feat``, ``docs`` and ``fix`` "are not on their own a reliable statement about whether an
entry concerns the verifier, the CI, or an internal review process". Measured over all 48 entries of this
release: five prefixes span more than one group, and ``fix`` alone spans three — the prefix
separates none of them.

WHAT THE SOURCE KEEPS. Every entry carries the editorial short form AND the original title, author
and URL. A short form that replaces its original loses the only thing a reader can check it
against, and the set of pull requests stops being traceable the moment nobody can say where it came
from.

WHY IT IS BOUND TO ONE VERSION. This renderer refuses to run unless the source declares the version
it was asked for. It is not a general generator: the 6.1.0 source carries 6.1.0 statements, and
copying them into a later tag would restate an audit status that was measured for a different tree.
Owner word of 2026-09-23, in translation: for future releases the example script must not be
wired in unchanged as a general generator; it binds deliberately to one version and carries an
explicit version check for that reason.

DETERMINISM IS A PROPERTY, NOT A HOPE. Two runs over the same source produce byte-identical output:
no timestamps, no set iteration, no locale-dependent sorting. The entry order is the order in the
source, because the source is the reviewed artefact.

No network. No packages beyond the standard library. Python 3.10 or newer.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
QUELLE = REPO / "release_notes" / "release-source.json"

#: The five groups a complete source carries.
#:
#: THIS IS A DELIBERATE SECOND STATEMENT, and an adversarial counter-reading was right to call it
#: duplication before accepting the reason. The names also live in the source, so adding a group
#: there means changing this tuple too. That friction is the point: without it, `pruefe` would read
#: the group set FROM the source and a source that had silently lost four of five groups would pass
#: every check, because it would be measured against itself. A release note listing one group
#: instead of five is exactly the failure nobody notices.
#:
#: The rendered ORDER comes from the source, not from here. This tuple decides membership only.
ERWARTETE_GRUPPEN = (
    "Verifier and receipt formats",
    "Build, CI and test infrastructure",
    "Audit and evidence",
    "Documentation and interoperability",
    "Dependencies",
)

#: The forms a source may declare in `form`. A source without the key is the grouped form of 6.1.0
#: and 6.2.0. Owner decision of 2026-10-09: from 6.2.1 the release page reads in two levels, a short
#: top for every reader and every fix as one line further down, and it names no internal process.
FORMEN = ("gruppen", "zwei_ebenen")

#: The section headings of one CHANGELOG version (Keep a Changelog 1.1.0), in its order. A two-level
#: source of a release that adds or changes as well as fixes lists its entries by these sections in
#: `abschnitte`, each line byte for byte as in the CHANGELOG; a release of fixes alone keeps `fixes`.
#: Owner decision of 2026-10-12 for 6.3.0, a feature release whose reviewed entries carry no bold lead.
ABSCHNITTE = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")

#: The fields that only the grouped form renders. A two-level source that carries one of them would
#: render without it, so a reviewed text would be dropped with nothing refusing it.
NUR_GRUPPEN = ("gruppen", "sicherheit", "was_sich_aenderte", "vor_dem_upgrade", "auditstatus", "danke")

#: Texts a two-level source MAY carry. Owner decision of 2026-10-13 on the text review of 6.3.0:
#: `frueherer_risikobericht` names the residual-risk record of an earlier release, linked beside the
#: record of this one; `referenzmessung` carries the values of the budget measurement on the reference
#: machine, which RELEASE.md asks the release notes to state. A source without them renders as before.
OPTIONALE_TEXTE = ("frueherer_risikobericht", "referenzmessung")

#: What a public two-level page must not name: the internal process behind a fix. Each entry is a
#: shape and the reason it is refused, so a finding says what it found.
INTERNE_MARKEN = (
    (re.compile(r"\bZ\d{3}\b"), "an order line of the maintainer's process"),
    (re.compile(r"\bOA-[0-9a-f]{10}\b"), "an owner card"),
    (re.compile(r"\bCodex\b", re.IGNORECASE), "a named review tool"),
    (re.compile(r"\b(?:R\d+[a-z]?|T\d|ZT|SI|CX|L\d-\d{3})-[0-9A-Za-z]+"), "a review finding id"),
    (re.compile(r"\breview rounds?\b|\brounds? of (?:the )?(?:external )?review\b"
                r"|\bclass search(?:es)?\b|\bcounter-reading\b", re.IGNORECASE),
     "a review round or class search"),
)


class QuellenFehler(ValueError):
    """The source cannot carry this release. Refused rather than rendered around."""


def lade(pfad: Path, version: str) -> Dict[str, Any]:
    """Read the source and REFUSE unless it declares the version that was asked for.

    The version check is the whole reason this refuses instead of adapting: a source that says
    6.1.0 carries an audit status measured on the 6.1.0 tree, and rendering it under another tag
    would publish a statement about a tree nobody examined.
    """
    if not pfad.is_file():
        raise QuellenFehler(f"no content source at {pfad}")
    try:
        daten = json.loads(pfad.read_text(encoding="utf-8"))
    except json.JSONDecodeError as fehler:
        raise QuellenFehler(f"{pfad} is not readable JSON: {fehler}") from None
    if not isinstance(daten, dict):
        raise QuellenFehler(f"{pfad} holds {type(daten).__name__}, expected an object")
    erklaert = daten.get("version")
    if erklaert != version:
        raise QuellenFehler(
            f"the source declares version {erklaert!r}, the render was asked for {version!r} — "
            f"refusing, because a source carries statements measured for ONE tree and reusing them "
            f"under another tag would publish a claim about a tree nobody examined")
    return daten


def kopf_des_baums(repo: Path) -> str | None:
    """The commit this tree is checked out at, or None when that is not measurable.

    None is NOT the same as "matches". The caller treats it as a finding, because a note that
    cannot say which tree it describes is the defect this function exists for.
    """
    import subprocess  # noqa: PLC0415 — only the CLI path needs it
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    kopf = r.stdout.strip()
    return kopf if r.returncode == 0 and len(kopf) == 40 else None


#: What may differ between the tree the notes describe and the tagged tree: paths the package does not
#: ship. MANIFEST.in never lists `release_notes/` and prunes `audit_artifacts/`, and the wheel is
#: built from `src/`, so a difference confined to these two leaves the shipped package unchanged.
NICHT_AUSGELIEFERT = ("release_notes/", "audit_artifacts/")


def _git(repo: Path, *args: str) -> str | None:
    import subprocess  # noqa: PLC0415 — only the CLI path needs it
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                           timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def liefert_dasselbe_paket(repo: Path, erklaert: str, kopf: str) -> str | None:
    """None when `erklaert` is an ancestor of `kopf` and every path that differs between them lies
    under `NICHT_AUSGELIEFERT`; otherwise the reason it does not.

    A SOURCE CANNOT NAME THE COMMIT THAT CARRIES IT. The release workflow renders in the checkout of
    the tag and compared the source's `release_commit` with that checkout's HEAD. The source is a
    file of the tagged commit, and a commit cannot hold its own id: measured on 2026-09-28, three
    rounds of writing HEAD into the source and committing gave three new heads and three refusals.

    THE FIRST FIX OF THIS WAS TOO NARROW. It accepted one single-parent commit on top of the described
    tree that changed only `release_notes/`. `v6.1.0` points at a merge commit (pull request 244, the
    receipt ceremony) whose first parent is the frozen head, with only `audit_artifacts/` between them,
    and that rule refused it. What the binding has to mean is that the tagged tree ships the package
    the notes describe, which is the line the tree digest already draws for the receipt and the
    readiness evidence: evidence stays out of the tree it binds.
    """
    ist_vorfahre = _git(repo, "merge-base", "--is-ancestor", erklaert, kopf)
    if ist_vorfahre is None:
        return f"the described tree {erklaert[:12]} is not an ancestor of HEAD, or this clone lacks it"
    geaendert = _git(repo, "diff", "--name-only", "--no-renames", "-z", erklaert, kopf)
    if geaendert is None:
        return "the change from the described tree to HEAD cannot be read"
    fremd = [p for p in geaendert.split("\0")
             if p and not any(p.startswith(n) for n in NICHT_AUSGELIEFERT)]
    if fremd:
        return (f"HEAD changes {len(fremd)} path(s) outside {' and '.join(NICHT_AUSGELIEFERT)} "
                f"against the described tree ({', '.join(fremd[:3])})")
    return None


def pruefe(daten: Dict[str, Any], kopf: str | None = None,
           baum: Path | None = None) -> List[str]:
    """Structural findings, all of them, rather than the first one.

    A renderer that stops at the first problem makes a caller fix them one run at a time.

    `kopf` is the commit of the tree being rendered IN. Pass it and the source's own
    `release_commit` is checked against it. See the block at that check for why.
    """
    form = daten.get("form", "gruppen")
    if form == "zwei_ebenen":
        return (_pruefe_zwei_ebenen(daten) + _pruefe_bindung(daten, kopf, baum)
                + (pruefe_verlinkte_dateien(daten, baum) if baum is not None else []))
    if form != "gruppen":
        return [f"the source declares the form {form!r}; this renderer knows {', '.join(FORMEN)}"]
    befunde: List[str] = []
    gruppen = daten.get("gruppen")
    if not isinstance(gruppen, list) or not gruppen:
        return ["the source carries no groups"]

    namen = [g.get("name") for g in gruppen if isinstance(g, dict)]
    fehlend = [n for n in ERWARTETE_GRUPPEN if n not in namen]
    if fehlend:
        befunde.append(f"group(s) missing from the source: {', '.join(fehlend)}")
    fremd = [n for n in namen if n not in ERWARTETE_GRUPPEN]
    if fremd:
        befunde.append(f"group(s) the renderer does not know: {', '.join(str(x) for x in fremd)}")
    # A MEMBERSHIP CHECK DOES NOT COUNT, and the two above are membership checks. Codex, review of
    # 2026-09-23 on PR 256: appending a second empty group with an ALREADY KNOWN name passes both —
    # nothing is missing and nothing is unknown — so `pruefe` reported no findings, the CLI exited 0,
    # and the rendered note carried that section TWICE. Reproduced before this line went in.
    #
    # The shape was already right one level down, where `nr in gesehen` counts pull requests instead
    # of testing membership. This is the same rule at the group level, and it is the one that matters
    # more: the five groups ARE the declared boundary of the release, so a sixth section widens what
    # the note claims to cover without anything refusing it.
    doppelt = sorted({str(n) for n in namen if namen.count(n) > 1})
    if doppelt:
        befunde.append(f"group name(s) declared more than once: {', '.join(doppelt)}")

    # THE SAME RULE IN THE OTHER DIRECTION (adversarial reading of 2026-10-13): the grouped form renders
    # neither optional text of the two-level form, so a grouped source carrying one would drop it.
    nur_zwei = [k for k in OPTIONALE_TEXTE if k in daten]
    if nur_zwei:
        befunde.append(f"the grouped source carries fields only the two-level form renders, which would be "
                       f"dropped: {', '.join(nur_zwei)}")

    befunde += _pruefe_bindung(daten, kopf, baum)

    s = daten.get("sicherheit")
    if s is not None:
        # A finding without its affected versions or its fix tells a user nothing to act on.
        if not isinstance(s, dict) or not all(s.get(f) for f in ("titel", "einleitung", "schluss")):
            befunde.append("the security section needs a titel, an einleitung and a schluss")
        zeilen = s.get("zeilen") if isinstance(s, dict) else None
        if not isinstance(zeilen, list) or not zeilen:
            befunde.append("the security section carries no rows")
        else:
            for i, z in enumerate(zeilen, 1):
                for feld in ("befund", "betroffen", "wirkung", "behoben"):
                    if not (isinstance(z, dict) and z.get(feld)):
                        befunde.append(f"security row {i} lacks {feld}")

    gesehen: Dict[int, str] = {}
    for g in gruppen:
        if not isinstance(g, dict):
            befunde.append("a group is not an object")
            continue
        for e in g.get("eintraege") or []:
            nr = e.get("nr") if isinstance(e, dict) else None
            if not isinstance(nr, int):
                befunde.append(f"an entry in {g.get('name')!r} carries no pull request number")
                continue
            if nr in gesehen:
                # EVERY PULL REQUEST EXACTLY ONCE. A number in two groups makes the total larger
                # than the set, and the total is what a reader takes for the size of the release.
                befunde.append(
                    f"#{nr} appears in {gesehen[nr]!r} and again in {g.get('name')!r}")
            gesehen[nr] = g.get("name")
            for feld in ("kurz", "originaltitel", "autor", "url"):
                if not e.get(feld):
                    befunde.append(f"#{nr} lacks {feld}")
    return befunde


def _pruefe_bindung(daten: Dict[str, Any], kopf: str | None, baum: Path | None) -> List[str]:
    """The tree binding, shared by both forms: a note of either form describes one tree."""
    befunde: List[str] = []
    # THE SOURCE NAMED THE TREE AND NOTHING COMPARED IT. Codex, review of 2026-09-23 on PR 256:
    # `release_commit` has always carried the commit the 48 entries describe, and the render bound
    # the VERSION and never the TREE. Measured on this branch at the time of the finding: HEAD sat
    # 12 commits beyond `dcac5aee`, including the first-parent merges #245, #247 and #253, the source
    # names none of the three, and the render exited 0 all the same. The workflow triggers on a tag
    # push, so a tag pushed from such a tree would ship those descendants while publishing "All
    # changes" and detail links for the older one.
    #
    # It is the same class as the digest this pull request already fixed one layer up: a value was
    # recorded and nothing checked it. A recorded commit nobody compares is not a binding.
    erklaert = daten.get("release_commit")
    if kopf is not None:
        if not isinstance(erklaert, str) or len(erklaert) != 40:
            befunde.append("the source declares no 40-character release_commit, so the notes cannot "
                           "say which tree they describe")
        elif erklaert != kopf:
            # With the tree at hand, HEAD may be a descendant that differs only in paths the package
            # does not ship (`liefert_dasselbe_paket`); a stated head without a tree keeps the exact
            # comparison.
            grund = (liefert_dasselbe_paket(baum, erklaert, kopf) if baum is not None
                     else "no tree was given to read the commit between them")
            if grund is not None:
                befunde.append(
                    f"the source describes tree {erklaert[:12]} but the render is running in "
                    f"{kopf[:12]} — the notes would describe a different tree than the artefacts "
                    f"({grund})")
    return befunde


def _pruefe_abschnitte(abschnitte: Any) -> List[str]:
    """Structural findings of `abschnitte`: known headings, each once, each with one or more single lines.
    Whether they are the CHANGELOG's sections is measured against the described tree
    (`pruefe_verlinkte_dateien`)."""
    if not isinstance(abschnitte, list) or not abschnitte:
        return ["the two-level source lists no abschnitte"]
    befunde: List[str] = []
    titel = [a.get("titel") if isinstance(a, dict) else None for a in abschnitte]
    for i, (a, t) in enumerate(zip(abschnitte, titel), 1):
        if t not in ABSCHNITTE:
            befunde.append(f"abschnitt {i} is titled {t!r}; a CHANGELOG section is one of {', '.join(ABSCHNITTE)}")
            continue
        zeilen = a.get("zeilen")
        if not isinstance(zeilen, list) or not zeilen or not all(
                isinstance(z, str) and z.strip() and "\n" not in z for z in zeilen):
            befunde.append(f"abschnitt {t} is not a list of one or more CHANGELOG lines")
    doppelt = sorted({str(t) for t in titel if t is not None and titel.count(t) > 1})
    if doppelt:
        befunde.append(f"abschnitt(e) declared more than once: {', '.join(doppelt)}")
    return befunde


def _zeilen_der_quelle(daten: Dict[str, Any]) -> List[str]:
    """Every entry line the page lists, in page order, whichever of the two keys carries them."""
    if "abschnitte" in daten:
        return [z for a in daten.get("abschnitte") or [] if isinstance(a, dict)
                for z in a.get("zeilen") or [] if isinstance(z, str)]
    return [f for f in daten.get("fixes") or [] if isinstance(f, str)]


def _text(daten: Dict[str, Any], feld: str) -> bool:
    return isinstance(daten.get(feld), str) and bool(daten[feld].strip())


def _pruefe_zwei_ebenen(daten: Dict[str, Any]) -> List[str]:
    """Structural findings of a two-level source, all of them."""
    befunde: List[str] = []
    for feld in ("kopfsatz", "selbst_pruefen", "nicht_bewiesen", "restrisiko", "schlusssatz"):
        if not _text(daten, feld):
            befunde.append(f"the two-level source needs a non-empty {feld}")
    # OPTIONAL, BUT NEVER EMPTY. A key that is present and empty would render a link without a target or
    # a section without a sentence, and nothing would refuse it.
    for feld in OPTIONALE_TEXTE:
        if feld in daten and not _text(daten, feld):
            befunde.append(f"the two-level source carries {feld}, and it is empty")
    # THE EARLIER RECORD IS A RESIDUAL-RISK RECORD OF ANOTHER RELEASE. It is linked as a bare path, so a
    # directory, another document or the record of this release would render a link that says
    # "Earlier risk record" and is not one.
    frueher = daten.get("frueherer_risikobericht")
    if _text(daten, "frueherer_risikobericht"):
        if not re.fullmatch(r"RESTRISIKO_\d+\.md", frueher):
            befunde.append(f"frueherer_risikobericht names {frueher!r}, not a residual-risk record "
                           f"RESTRISIKO_<digits>.md")
        elif frueher == _restrisiko(daten):
            befunde.append("frueherer_risikobericht names the record of this release")
    hl = daten.get("highlights")
    if not isinstance(hl, list) or not 3 <= len(hl) <= 4:
        befunde.append("the two-level source needs three or four highlights")
    else:
        for i, h in enumerate(hl, 1):
            for feld in ("kern", "text"):
                if not (isinstance(h, dict) and _text(h, feld)):
                    befunde.append(f"highlight {i} lacks {feld}")
    fixes = daten.get("fixes")
    if "abschnitte" in daten:
        if fixes is not None:
            befunde.append("the two-level source lists fixes and abschnitte; it lists exactly one of them")
        befunde += _pruefe_abschnitte(daten.get("abschnitte"))
    elif not isinstance(fixes, list) or not fixes:
        befunde.append("the two-level source lists no fixes")
    else:
        for i, f in enumerate(fixes, 1):
            if not (isinstance(f, str) and f.startswith("**") and "\n" not in f):
                befunde.append(f"fix {i} is not one CHANGELOG line that opens with its bold sentence")
    links = daten.get("weitere_links", [])
    if not isinstance(links, list) or not all(
            isinstance(x, dict) and _text(x, "text") and str(x.get("url", "")).startswith("https://")
            for x in links):
        befunde.append("weitere_links lists objects with a text and an https url")
    # A LINK WITHOUT A TARGET POINTS NOWHERE, in every form (6.3.1, RR1).
    for t in _seitentexte(daten):
        for _s, _e, ziel in _link_ziele(str(t)):
            if not ziel.strip():
                befunde.append(f"a link on the page has no target: {str(t)[:60]!r}")
    fremd = [k for k in NUR_GRUPPEN if k in daten]
    if fremd:
        befunde.append(f"the two-level source carries fields only the grouped form renders, which "
                       f"would be dropped: {', '.join(fremd)}")
    if not befunde:
        # THE RULE IS MEASURED ON THE RENDERED PAGE, not on the fields one by one, so a marker in any
        # text of the source is found wherever it sits.
        seite = _rendere_zwei_ebenen({**daten, "release_commit": daten.get("release_commit") or ""})
        for muster, was in INTERNE_MARKEN:
            for m in muster.finditer(seite):
                befunde.append(f"the page names {was}: {m.group(0)!r}")
    return befunde


#: A link whose target is a path. On a release page such a link resolves against the page, not the
#: repository, so it would point nowhere; the renderer binds it to the described commit.
#:
#: EVERY LINK FORM, NOT ONE (6.3.1, RR1). Until 6.3.1 one expression stood for all links, and it saw only
#: `[text](path)`: a title after the target, a target in angle brackets, a reference definition and an
#: HTML `href` were neither bound to the described commit nor checked in its tree, so such a link pointed
#: at the release page itself and a missing file passed the check. `_link_ziele` finds the target of each
#: form and the span it is written in; `_binde` and `verlinkte_ziele` both read it, so what is bound is
#: what is checked. A target that is a URL, a mail address or an anchor of the page is not a path.
_NICHT_IM_BAUM = re.compile(r"https?://|mailto:|#")
_REFERENZ_DEFINITION = re.compile(r"^ {0,3}\[(?:[^\]\\\n]|\\.)+\]:[ \t]*(?:\n[ \t]*)?(?:<([^<>\n]*)>|(\S+))", re.M)
_HTML_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?>")
_HTML_ZIEL = re.compile(r"""\s(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""", re.I)
_CODE = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)", re.S)


def _link_ziele(text: str) -> List[tuple]:
    """(start, end, target) of every link target in `text`, in text order: an inline link or image,
    `[t](target)` or `[t](target "title")`, the target bare or in angle brackets; a reference definition
    `[label]: target`, bare or in angle brackets; an HTML `href` or `src`, quoted or not. A link inside a
    code span is code, not a link. An empty target is returned with an empty span, so it can be named."""
    roh = _CODE.sub(lambda m: " " * len(m.group(0)), text)
    ziele: List[tuple] = []
    i = roh.find("](")
    while i != -1:
        j = i + 2
        while j < len(roh) and roh[j] in " \t":
            j += 1
        if roh.startswith("\n", j):
            j += 1
            while j < len(roh) and roh[j] in " \t":
                j += 1
        ende = roh.find(">", j + 1) if roh.startswith("<", j) else -1
        if ende != -1 and not any(c in roh[j + 1:ende] for c in "<\n"):
            ziele.append((j + 1, ende, text[j + 1:ende]))
        else:
            k, tiefe = j, 0
            while k < len(roh) and not roh[k].isspace():
                if roh[k] == "(":
                    tiefe += 1
                elif roh[k] == ")":
                    if tiefe == 0:
                        break
                    tiefe -= 1
                k += 1
            ziele.append((j, k, text[j:k]))
        i = roh.find("](", i + 2)
    for m in _REFERENZ_DEFINITION.finditer(roh):
        g = 1 if m.group(1) is not None else 2
        ziele.append((m.start(g), m.end(g), text[m.start(g):m.end(g)]))
    for tag in _HTML_TAG.finditer(roh):
        for m in _HTML_ZIEL.finditer(tag.group(0)):
            g = next(n for n in (1, 2, 3) if m.group(n) is not None)
            s, e = tag.start() + m.start(g), tag.start() + m.end(g)
            ziele.append((s, e, text[s:e]))
    return sorted(ziele)


def _ist_pfad(ziel: str) -> bool:
    return bool(ziel.strip()) and not _NICHT_IM_BAUM.match(ziel)


def _binde(text: str, basis: str) -> str:
    for s, e, ziel in reversed(_link_ziele(text)):
        if _ist_pfad(ziel):
            text = f"{text[:s]}{basis}/{ziel}{text[e:]}"
    return text


def _restrisiko(q: Dict[str, Any]) -> str:
    # The two-level source names its record (owner decision of 2026-10-09: RESTRISIKO_620.md for 6.2.1).
    return q.get("restrisiko") or ("RESTRISIKO_" + q["version"].replace(".", "") + ".md")


def verlinkte_ziele(daten: Dict[str, Any]) -> List[str]:
    """Every target in the tree a two-level page links, `path` or `path#anchor`, in page order, once."""
    frueher = daten.get("frueherer_risikobericht")
    ziele = ["CHANGELOG.md", _restrisiko(daten), frueher if isinstance(frueher, str) else "",
             f"docs/release_scope/{daten['version']}.md"]
    for t in _seitentexte(daten):
        ziele += [z for _s, _e, z in _link_ziele(str(t)) if _ist_pfad(z)]
    return list(dict.fromkeys(z for z in ziele if z))


def _seitentexte(daten: Dict[str, Any]) -> List[Any]:
    """Every text of the source that `_binde` renders onto a two-level page."""
    texte = [daten.get("kopfsatz", ""), daten.get("selbst_pruefen", ""),
             daten.get("nicht_bewiesen", ""), daten.get("referenzmessung", ""),
             daten.get("schlusssatz", "")]
    texte += [h.get("text", "") for h in daten.get("highlights") or [] if isinstance(h, dict)]
    return texte + _zeilen_der_quelle(daten)


def _anker(ueberschrift: str) -> str:
    """The anchor GitHub gives a markdown heading: lower case, punctuation dropped, spaces to hyphens."""
    s = ueberschrift.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _fixed_des_changelog(changelog: str, version: str) -> List[str] | None:
    """The bullets under `### Fixed` of `## [version]`, each without its `- `, or None without the section."""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.M | re.S)
    if m is None:
        return None
    f = re.search(r"^### Fixed\n\n(.*?)(?=^### |\Z)", m.group(1), re.M | re.S)
    if f is None:
        return None
    return [z[2:] for z in f.group(1).splitlines() if z.startswith("- ")]


def _abschnitte_des_changelog(changelog: str, version: str) -> List[tuple] | None:
    """[(heading, [bullets])] of `## [version]`, in order, each bullet without its `- `; None without the
    section."""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.M | re.S)
    if m is None:
        return None
    return [(k.group(1), [z[2:] for z in k.group(2).splitlines() if z.startswith("- ")])
            for k in re.finditer(r"^### ([^\n]+)\n(.*?)(?=^### |\Z)", m.group(1), re.M | re.S)]


def pruefe_verlinkte_dateien(daten: Dict[str, Any], baum: Path) -> List[str]:
    """A LINK TO A FILE THE TREE LACKS IS A PROMISE NOBODY CHECKED. Every path a two-level page links
    must exist in the commit the page describes, and every anchor must name a heading of that file;
    the grouped form linked `RESTRISIKO_610.md` from every later body until a reader noticed.

    THE DETAILS ARE THE CHANGELOG LINES, BYTE FOR BYTE (owner decision of 2026-10-09). The fixes of the
    source must be the bullets under `### Fixed` of this version's CHANGELOG section in the described
    tree, in the same order, so the page cannot say one thing and the CHANGELOG another."""
    commit = daten.get("release_commit")
    if not (isinstance(commit, str) and len(commit) == 40):
        return []  # the binding check already names a missing or malformed release_commit
    befunde: List[str] = []
    for ziel in verlinkte_ziele(daten):
        pfad, _, anker = ziel.partition("#")
        inhalt = _git(baum, "show", f"{commit}:{pfad}")
        if inhalt is None:
            befunde.append(f"the page links {pfad}, which the described tree {commit[:12]} does not carry")
            continue
        if anker and anker not in {_anker(z.lstrip("#")) for z in inhalt.splitlines()
                                   if re.match(r"^#{1,6} ", z)}:
            befunde.append(f"the page links {ziel}, and {pfad} at {commit[:12]} has no heading with "
                           f"that anchor")
    changelog = _git(baum, "show", f"{commit}:CHANGELOG.md")
    if "abschnitte" in daten:
        # EVERY SECTION, NOT ONLY ITS LINES. A source that leaves a whole section out lists the lines it
        # keeps byte for byte and still drops what the CHANGELOG says, so the set and order of the
        # headings are compared as well.
        soll = _abschnitte_des_changelog(changelog or "", daten["version"])
        ist = [(a.get("titel"), a.get("zeilen")) for a in daten.get("abschnitte") or []
               if isinstance(a, dict)]
        if soll is None:
            befunde.append(f"CHANGELOG.md at {commit[:12]} has no section `## [{daten['version']}]`")
        elif ist != soll:
            befunde.append(f"the abschnitte of the source are not the sections of {daten['version']} in "
                           f"CHANGELOG.md at {commit[:12]}, byte for byte and in order")
        return befunde
    zeilen = _fixed_des_changelog(changelog or "", daten["version"])
    if zeilen is None:
        befunde.append(f"CHANGELOG.md at {commit[:12]} has no `### Fixed` under `## [{daten['version']}]`")
    elif zeilen != list(daten.get("fixes") or []):
        befunde.append(f"the fixes of the source are not the `### Fixed` lines of {daten['version']} in "
                       f"CHANGELOG.md at {commit[:12]}, byte for byte and in order")
    return befunde


def _rendere_zwei_ebenen(q: Dict[str, Any]) -> str:
    """The two-level page: what the release brings and how to install it, three or four highlights,
    how to verify it and what a receipt does not prove, the reference measurement when the source
    carries one, then every fix as its CHANGELOG line, then the links and the closing sentence."""
    basis = f"https://github.com/b7n0de/proofbundle/blob/{q['release_commit']}"
    n = len(_zeilen_der_quelle(q))
    teile: List[str] = [_binde(q["kopfsatz"], basis), "", "```",
                        f"python -m pip install --upgrade proofbundle=={q['version']}", "```", "",
                        "## Highlights", ""]
    teile += [f"- **{h['kern']}** {_binde(h['text'], basis)}" for h in q["highlights"]]
    teile += ["", "## Verify this release yourself", "", _binde(q["selbst_pruefen"], basis), "",
              "## What a receipt still does not prove", "", _binde(q["nicht_bewiesen"], basis), ""]
    if q.get("referenzmessung"):
        teile += ["## Measured on the reference machine", "", _binde(q["referenzmessung"], basis), ""]
    teile += ["## Details", "", "<details>"]
    if "abschnitte" in q:
        teile += [f"<summary>All {n} entr{'ies' if n != 1 else 'y'}, one line each, as in the "
                  f"CHANGELOG</summary>"]
        for a in q["abschnitte"]:
            teile += ["", f"### {a['titel']}", ""]
            teile += [f"- {_binde(z, basis)}" for z in a["zeilen"]]
    else:
        teile += [f"<summary>All {n} fix{'es' if n != 1 else ''}, one line each, as in the "
                  f"CHANGELOG</summary>", ""]
        teile += [f"- {_binde(f, basis)}" for f in q["fixes"]]
    # TWO RECORDS NEED TWO NAMES. Beside an earlier record, "Known limitations" alone would not say which
    # release a link speaks for, so both carry their scope; a source without the earlier one keeps the
    # single link of 6.2.1.
    risiko = ([f"[Known limitations for {q['version']}]({basis}/{_restrisiko(q)})",
               f"[Earlier risk record]({basis}/{q['frueherer_risikobericht']})"]
              if q.get("frueherer_risikobericht") else
              [f"[Known limitations]({basis}/{_restrisiko(q)})"])
    links = [f"[Full changelog]({basis}/CHANGELOG.md)", *risiko,
             f"[Release scope]({basis}/docs/release_scope/{q['version']}.md)"]
    links += [f"[{x['text']}]({x['url']})" for x in q.get("weitere_links", [])]
    teile += ["", "</details>", "", " · ".join(links), "", _binde(q["schlusssatz"], basis)]
    return "\n".join(teile) + "\n"


def _zeile(e: Dict[str, Any]) -> str:
    return f"- {e['kurz']}. [#{e['nr']}]({e['url']})."


def rendere(daten: Dict[str, Any]) -> str:
    """The body. Order comes from the source; nothing here sorts or dedupes behind the reader."""
    if daten.get("form") == "zwei_ebenen":
        return _rendere_zwei_ebenen(daten)
    q = daten
    commit = q["release_commit"]
    basis = f"https://github.com/b7n0de/proofbundle/blob/{commit}"
    teile: List[str] = [q["kopfsatz"], ""]

    # THE RECORD IS NAMED AFTER ITS VERSION. This link was the literal `RESTRISIKO_610.md`, so every
    # later body would have pointed at the residual-risk record of 6.1.0.
    restrisiko = "RESTRISIKO_" + q["version"].replace(".", "") + ".md"
    teile.append(
        f"[Changelog]({basis}/CHANGELOG.md) · "
        f"[Known limitations]({basis}/{restrisiko}) · "
        f"[Release scope]({basis}/docs/release_scope/{q['version']}.md)")
    s = q.get("sicherheit")
    if s:
        # Owner decision of 2026-09-28 (Z296, option A): affected versions, effect and fix per
        # finding of a released version. Optional, so a source without it renders as before.
        teile += ["", f"## {s['titel']}", "", s["einleitung"], "",
                  "| Finding | Affected | Effect | Fixed by |", "|---|---|---|---|"]
        for z in s["zeilen"]:
            teile.append(f"| **{z['befund']}** | {z['betroffen']} | {z['wirkung']} | {z['behoben']} |")
        teile += ["", s["schluss"]]
    teile += ["", "## What changed", "", "| Area | Change | Evidence |", "|---|---|---|"]
    for z in q["was_sich_aenderte"]:
        teile.append(f"| **{z['bereich']}** | {z['aenderung']} | {z['beleg']} |")

    teile += ["", "## Before upgrading", ""]
    for v in q["vor_dem_upgrade"]:
        teile.append(f"- **{v['titel']}** {v['text']}")

    teile += ["", "<details>", "<summary>Audit status and known limitations</summary>", "",
              q["auditstatus"], "", "</details>", "", "## All changes", ""]
    gesamt = sum(len(g["eintraege"]) for g in q["gruppen"])
    teile += [f"{gesamt} pull requests, grouped by area. Shortened descriptions link to the "
              f"original discussions.", ""]
    for g in q["gruppen"]:
        n = len(g["eintraege"])
        teile += ["<details>",
                  f"<summary>{g['name']} · {n} pull request{'s' if n != 1 else ''}</summary>", ""]
        teile += [_zeile(e) for e in g["eintraege"]]
        teile += ["", "</details>", ""]

    danke = " and ".join(
        f"[@{a}](https://github.com/{'apps/' if a == 'dependabot' else ''}{a})" for a in q["danke"])
    teile += ["## Contributors", "", f"Thanks to {danke}.", "",
              f"[Full comparison {q['vorheriger_tag']}...{q['tag']}]"
              f"(https://github.com/b7n0de/proofbundle/compare/{q['vorheriger_tag']}...{q['tag']})"]
    return "\n".join(teile) + "\n"


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--version", required=True, help="the version the source must declare")
    p.add_argument("--quelle", type=Path, default=QUELLE)
    p.add_argument("--aus", type=Path, help="write here instead of stdout")
    p.add_argument("--baum", type=Path, default=Path(__file__).resolve().parents[1],
                   help="the tree whose HEAD the source's release_commit is checked against")
    p.add_argument("--kopf", help="state that HEAD instead of measuring it; for cases that must "
                                  "exercise both directions from one checkout")
    a = p.parse_args(argv)

    try:
        daten = lade(a.quelle, a.version)
    except QuellenFehler as fehler:
        print(f"  REFUSED: {fehler}", file=sys.stderr)
        return 2
    # A HEAD THAT CANNOT BE READ IS NOT A HEAD THAT MATCHES. `pruefe` checks the binding only when a
    # head is given, and this call passed `kopf_des_baums`'s None straight through, so a render
    # outside a git checkout skipped the binding and exited 0 (measured 2026-09-28 with the 6.1.0
    # source: 48 pull requests rendered). The docstring of `kopf_des_baums` already promised this.
    kopf = a.kopf or kopf_des_baums(a.baum)
    if kopf is None:
        print(f"  REFUSED: the HEAD of {a.baum} cannot be measured, so which tree the notes "
              f"describe cannot be checked", file=sys.stderr)
        return 2
    befunde = pruefe(daten, kopf=kopf, baum=None if a.kopf else a.baum)
    if befunde:
        print(f"  REFUSED: the source is not renderable ({len(befunde)} finding(s)):",
              file=sys.stderr)
        for b in befunde:
            print(f"    - {b}", file=sys.stderr)
        return 2

    text = rendere(daten)
    if a.aus:
        a.aus.write_text(text, encoding="utf-8")
        umfang = (f"{len(_zeilen_der_quelle(daten))} {'entries' if 'abschnitte' in daten else 'fixes'}"
                  if daten.get("form") == "zwei_ebenen" else
                  f"{sum(len(g['eintraege']) for g in daten['gruppen'])} pull requests")
        print(f"  {a.aus} · {len(text)} characters · {umfang}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
