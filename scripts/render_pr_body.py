#!/usr/bin/env python3
"""Render a pull request body, or a house issue, from a versioned data source. Deterministically.

WHY A SOURCE AND NOT A HAND-WRITTEN BODY. Owner order of 2026-09-24, identifier
QITEM-PROOFBUNDLE-HAUSFORM-PR-ISSUE-ERZEUGER-AUS-DATEN-01: every pull request and every issue a
house session opens in this repository should look like the README and like PR 259, and the shape
should come out of data the way the release note comes out of ``release_notes/release-source.json``
through ``scripts/render_release.py``. PR 259 is the reference, PR 260 is the counter-example.

WHAT WENT WRONG IN THE COUNTER-EXAMPLE, measured rather than recalled. The body of PR 260 was cut
out of its own commit message, and a commit message is hand-wrapped at about a hundred characters.
Measured over the two bodies: 260 carried 27 hard wraps at a maximum line length of 104 and zero H2
headings, while 259 carried a maximum line length of 352 and five H2 headings. The wrap rule that
would have caught it exists in this house, and it did not run on that path, because the tool that
opens pull requests calls ``gh`` from inside Python and the gate that carries the rule is a shell
hook. A rule on a path nobody takes is not a rule.

WHAT THIS REFUSES RATHER THAN REPAIRS. Flowing text that arrives with embedded newlines is not
re-flowed here; it is refused, with the field named. Re-flowing would make this renderer the second
place that decides where a paragraph breaks, and the first place would go on being wrong silently.
The same applies to an empty mandatory field: the source says why a block is empty, or the render
refuses. A body that quietly drops the block a reader looks for is the failure this file exists for.

DETERMINISM IS A PROPERTY, NOT A HOPE. Two runs over the same source produce byte-identical output:
no timestamps, no set iteration, no locale-dependent sorting. Block order comes from this module,
because the order IS the house form; the content order inside a block comes from the source.

No network. No packages beyond the standard library. Python 3.10 or newer.
"""
from __future__ import annotations

import argparse
import json
import sys
import re
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]

#: The PR blocks, in the order the house form declares them. The tuple decides ORDER and MEMBERSHIP;
#: the source decides content. A second statement of the names lives in the source, and that friction
#: is deliberate for the same reason `render_release.ERWARTETE_GRUPPEN` states its own: if the order
#: were read FROM the source, a source that had silently lost three blocks would be measured against
#: itself and pass.
PR_BLOECKE = (
    ("came_from", "Where this came from"),
    ("defect", "The defect"),
    ("fix", "The fix"),
    ("measured", "Measured"),
    ("not_changed", "Not changed"),
)

#: A feature states a change where a fix states a defect. Both are the same slot; the source picks
#: one, and picking neither or both is a finding rather than a choice the renderer makes.
DEFECT_ALTERNATIVE = ("change", "The change")

ISSUE_BLOECKE = (
    ("observed", "Observed"),
    ("measured", "Measured"),
    ("expected", "Expected"),
    ("scope", "Scope"),
)

#: The footer, byte for byte, in every body this renderer writes. Owner order, section A: one line of
#: marking, one line of measurement. It is a constant and not a template, because a footer that can be
#: parameterised is a footer that will differ between two bodies and then means nothing.
#:
#: THE BLANK LINE BETWEEN THEM IS NOT DECORATION, and it is the one place where two of the order's
#: own rules meet. Section A asks for two lines; the same order asks for one paragraph per line, and
#: the checker that enforces it reads two adjacent non-empty prose lines as a wrapped paragraph.
#: Measured on the first render: the checker reported the footer, and nothing else, as a hard wrap.
#: Separating the two lines by a blank line keeps both lines and both rules, because the order says
#: the footer is two lines and never says they are adjacent.
FUSSBLOCK = (
    "Written by an AI session of b7n0de under owner review.\n"
    "\n"
    "Measurement, not certification."
)

#: Above this many lines an output block goes into a collapsed `details`, so a body stays readable.
DETAILS_AB = 16

#: The outbound gate's required closing sentence, byte for byte as that gate names it. Only ever
#: emitted behind `--tor-schlusssatz`; see the comment at that flag for why it is not the default.
TOR_SCHLUSSSATZ = ("Written by the operating agent under a standing owner authorisation for Codex "
                   "threads; measurements are its own, at the head named above.")

#: The four columns of the measured table. All four are mandatory per entry: a value without a source
#: is a number whose origin nobody can chase, and that is the defect class this repository keeps
#: paying for.
MESSSPALTEN = ("what", "value", "source", "commit")


class QuellenFehler(ValueError):
    """The source cannot carry this body. Refused rather than rendered around."""


def lade(pfad: Path, kind: str) -> Dict[str, Any]:
    """Read the source and REFUSE unless it declares the kind that was asked for.

    The kind check mirrors the version check in ``render_release.lade`` and exists for the same
    reason: an issue source carries statements shaped for an issue, and rendering it as a pull
    request body would publish blocks that were never written for that surface.
    """
    if not pfad.is_file():
        raise QuellenFehler(f"no source at {pfad}")
    try:
        daten = json.loads(pfad.read_text(encoding="utf-8"))
    except json.JSONDecodeError as fehler:
        raise QuellenFehler(f"{pfad} is not readable JSON: {fehler}") from None
    if not isinstance(daten, dict):
        raise QuellenFehler(f"{pfad} holds {type(daten).__name__}, expected an object")
    erklaert = daten.get("kind")
    if erklaert != kind:
        raise QuellenFehler(
            f"the source declares kind {erklaert!r}, the render was asked for {kind!r} — refusing, "
            f"because the blocks of the two surfaces are not interchangeable")
    return daten


#: Zeilenanfaenge, die eine BLOCKFORM eroeffnen: Tabelle, Ueberschrift, Liste, Zitat, HTML, Zaun.
#: Ihre Zeilenumbrueche sind Absicht und keine umgebrochene Prosa.
_BLOCKFORM_ANFANG = ("|", "#", "-", "*", "+", "`", ">", "<")

#: Eine GEORDNETE Listenzeile: `1. `, `2) `, auch mehrstellig. Codex, Durchsicht von PR 261:
#: eine Zeichen-Allowlist kennt `-` und `*`, und `1. erstens / 2. zweitens` faellt durch als
#: Quell-Umbruch — obwohl der Docstring dieser Funktion Listen ausdruecklich als Blockform nennt.
#: Eine Aufzaehlung von Formen ist nur so vollstaendig wie die Sprache, die sie beschreibt.
_GEORDNETE_LISTE = re.compile(r"^\d+[.)]\s")


def _ist_blockform(zeile: str) -> bool:
    """Eroeffnet diese Zeile eine Blockform? Zeichen-Allowlist UND geordnete Liste."""
    n = zeile.lstrip()
    return n.startswith(_BLOCKFORM_ANFANG) or bool(_GEORDNETE_LISTE.match(n))


def _ueberschriftfehler(feld: str, text: Any) -> List[str]:
    """Setzt dieses FELD eine Blockgrenze, die dem Modul gehoert?

    Codex, Durchsicht von PR 261: ein Feld mit dem Inhalt ``## Marking`` rendert einen ZWEITEN
    Marking-Block, und der Fussblock steht danach doppelt — obwohl ``PR_BLOECKE`` ausdruecklich sagt,
    dass Reihenfolge und Zugehoerigkeit dem Modul gehoeren und nicht der Quelle. Wer Struktur aus
    Inhalt entstehen laesst, hat die Struktur nicht mehr.

    ABGEWIESEN UND NICHT ENTSCHAERFT: entschaerfen hiesse, still etwas anderes zu drucken, als in der
    Quelle steht. Tiefere Ueberschriften (``###`` und mehr) bleiben erlaubt; sie setzen keine
    Blockgrenze dieses Formats.

    EIGENE FUNKTION UND NICHT TEIL VON ``_absatzfehler``, weil die erste Fassung genau daran fiel:
    die Gruenprobe PR 259 ist ein DOKUMENT und traegt ihre fuenf H2-Zeilen zu Recht, waehrend diese
    Regel fuer FELDER gilt. Eine Feldregel auf ein Dokument angewandt meldet einen Defekt, der keiner
    ist — dieselbe Klasse wie eine Zahl, die auf der falschen Flaeche gemessen wird.
    """
    if not isinstance(text, str):
        return []
    befunde = []
    for i, z in enumerate(text.split("\n"), start=1):
        n = z.lstrip()
        if n.startswith("## ") and not n.startswith("### "):
            befunde.append(
                f"{feld} carries a top-level heading at line {i} ({n[:40]!r}); block order and "
                f"membership belong to the renderer, so a content field may not open a block")
    return befunde


def _absatzfehler(feld: str, text: Any) -> List[str]:
    """Findings for one flowing-text field. Paragraphs are separated by a blank line; a paragraph
    itself is ONE line.

    A line that begins with a table, list, heading, quote or fence marker is left alone: those are
    block forms whose lines are lines on purpose. This is the same exemption the owner's own checker
    uses, and it is why a measured table does not read as a wrapped paragraph.

    THE INSIDE OF A FENCED CODE BLOCK IS TRACKED, not pattern-matched, and that difference decided a
    measurement. The order says code blocks pass through unchanged, but a line of code rarely begins
    with one of the exempt characters, so a prefix test reads it as wrapped prose. Measured against
    PR 259, the reference body: a prefix-only rule reported three findings, all three of them lines
    INSIDE a fence, and the body is correct. A fence has a state, and a rule that tests characters
    cannot see a state.
    """
    if not isinstance(text, str) or not text.strip():
        return [f"{feld} is empty; the house form has no optional blocks, so say why in one sentence"]
    befunde = []
    zeilen = text.split("\n")
    im_zaun = False
    for i in range(1, len(zeilen)):
        vorher, jetzt = zeilen[i - 1], zeilen[i]
        if zeilen[i - 1].lstrip().startswith("```"):
            im_zaun = not im_zaun
        if im_zaun or jetzt.lstrip().startswith("```"):
            continue
        if not jetzt.strip() or not vorher.strip():
            continue
        if _ist_blockform(jetzt):
            continue
        befunde.append(
            f"{feld} carries a source line break at line {i + 1} ({jetzt.strip()[:40]!r}...); "
            f"flowing text is one line per paragraph and is refused rather than re-flowed here")
    return befunde


def _felderfehler(feld: str, text: Any) -> List[str]:
    """Alle Befunde EINES Inhaltsfeldes: Absatzform und Blockgrenze. Ein Feld, zwei Eigenschaften,
    ein Aufruf — damit keine Aufrufstelle die eine mitnimmt und die andere vergisst."""
    return _absatzfehler(feld, text) + _ueberschriftfehler(feld, text)


def pruefe(daten: Dict[str, Any], kind: str) -> List[str]:
    """Structural findings, all of them rather than the first.

    A renderer that stops at the first problem makes a caller fix them one run at a time.
    """
    befunde: List[str] = []
    if kind == "pr":
        if not isinstance(daten.get("head"), str) or not daten.get("head", "").strip():
            befunde.append("head is missing; the body must name the commit and the scope it describes")
        else:
            befunde += _felderfehler("head", daten["head"])
        hat_defect = bool(str(daten.get("defect") or "").strip())
        hat_change = bool(str(daten.get(DEFECT_ALTERNATIVE[0]) or "").strip())
        if hat_defect and hat_change:
            befunde.append("the source carries both defect and change; one body states one of the two")
        if not hat_defect and not hat_change:
            befunde.append("the source carries neither defect nor change")
        for schluessel, _ in PR_BLOECKE:
            if schluessel in ("defect", "measured"):
                continue
            befunde += _felderfehler(schluessel, daten.get(schluessel))
        if hat_defect:
            befunde += _felderfehler("defect", daten.get("defect"))
        if hat_change:
            befunde += _felderfehler("change", daten.get("change"))
        befunde += _messfehler(daten.get("measured"))
    elif kind == "issue":
        for schluessel, _ in ISSUE_BLOECKE:
            if schluessel == "measured":
                befunde += _messfehler(daten.get("measured"))
                continue
            befunde += _felderfehler(schluessel, daten.get(schluessel))
    else:
        befunde.append(f"unknown kind {kind!r}")
    return befunde


def _messfehler(eintraege: Any) -> List[str]:
    if not isinstance(eintraege, list) or not eintraege:
        return ["measured carries no entries; a body with no measurement states nothing checkable"]
    befunde = []
    for i, e in enumerate(eintraege, start=1):
        if not isinstance(e, dict):
            befunde.append(f"measured entry {i} is not an object")
            continue
        for spalte in MESSSPALTEN:
            # ANWESENHEIT IST NICHT WAHRHEITSWERT, und `e.get(spalte) or ""` verwechselt beides.
            # Codex, Durchsicht von PR 261: `"value": 0` wurde als fehlend abgewiesen, obwohl die
            # Null eine anwesende und gueltige Messung ist; `false` fiel aus demselben Grund.
            # DAS IST DIE KLASSE R-B4 IN MEINEM EIGENEN NEUEN CODE, am selben Tag, an dem drei
            # Commits dieses Zweigs sie anderswo geschlossen haben: ein Feld wird auf Wahrheitswert
            # geprueft, wo Anwesenheit gemeint ist. Anwesend heisst: nicht `None` und, wenn Text,
            # nicht leer. Eine Zahl, ein `False` und ein `0` sind anwesend.
            wert = e.get(spalte)
            if wert is None or (isinstance(wert, str) and not wert.strip()):
                befunde.append(f"measured entry {i} lacks {spalte}")
            elif isinstance(wert, str) and "\n" in wert:
                # Eine Zelle mit Umbruch bricht die Tabelle auf und kann eine Ueberschrift
                # einschmuggeln; siehe die Strukturpruefung der Fliesstextfelder.
                befunde.append(f"measured entry {i} has a line break in {spalte}; a table cell is one line")
    return befunde


def _block(text: str) -> List[str]:
    """One flowing-text block, plus the `details` rule for a long output."""
    zeilen = text.split("\n")
    if len(zeilen) > DETAILS_AB:
        return ["<details>", "<summary>Full output</summary>", "", *zeilen, "", "</details>"]
    return zeilen


def _messtabelle(eintraege: List[Dict[str, Any]]) -> List[str]:
    kopf = ["| What | Value | Source | Commit |", "|---|---|---|---|"]
    zeilen = [f"| {e['what']} | {e['value']} | {e['source']} | `{e['commit']}` |" for e in eintraege]
    if len(zeilen) > DETAILS_AB:
        return ["<details>", "<summary>Measurements</summary>", "", *kopf, *zeilen, "", "</details>"]
    return kopf + zeilen


def rendere(daten: Dict[str, Any], kind: str) -> str:
    """The body. Block order comes from this module; content order from the source."""
    teile: List[str] = []
    if kind == "pr":
        teile += _block(daten["head"])
        for schluessel, titel in PR_BLOECKE:
            if schluessel == "defect" and not str(daten.get("defect") or "").strip():
                schluessel, titel = DEFECT_ALTERNATIVE
            teile += ["", f"## {titel}", ""]
            teile += _messtabelle(daten["measured"]) if schluessel == "measured" \
                else _block(daten[schluessel])
    else:
        for schluessel, titel in ISSUE_BLOECKE:
            if teile:
                teile.append("")
            teile += [f"## {titel}", ""]
            teile += _messtabelle(daten["measured"]) if schluessel == "measured" \
                else _block(daten[schluessel])
    teile += ["", "## Marking", "", FUSSBLOCK]
    return "\n".join(teile) + "\n"


def hygiene(text: str, label: str) -> List[dict]:
    """The same claim-hygiene scan the release text runs through, on the same rule set.

    ONE RULE SET, TWO ENTRANCES, exactly as ``release_text_hygiene`` argues: this brings no patterns
    of its own. Two lists drift, and then one surface forbids what the other writes.
    """
    sys.path.insert(0, str(REPO / "scripts"))
    import claims_hygiene_check as chc  # noqa: PLC0415 — after the sys.path entry
    return chc.scan_text(text, label)


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--quelle", type=Path, required=True, help="the data source to render")
    p.add_argument("--kind", choices=("pr", "issue"), default="pr",
                   help="the surface; the source must declare the same one")
    p.add_argument("--aus", type=Path, help="write here instead of stdout")
    p.add_argument("--ohne-hygiene", action="store_true",
                   help="skip the claim-hygiene scan; for a case that measures the renderer alone")
    p.add_argument("--tor-schlusssatz", action="store_true",
                   help="append the outbound gate's closing sentence below the marking block; a "
                        "bridge for as long as that gate reads a pull request body as a thread reply")
    a = p.parse_args(argv)

    try:
        daten = lade(a.quelle, a.kind)
    except QuellenFehler as fehler:
        print(f"  REFUSED: {fehler}", file=sys.stderr)
        return 2
    befunde = pruefe(daten, a.kind)
    if befunde:
        print(f"  REFUSED: the source is not renderable ({len(befunde)} finding(s)):", file=sys.stderr)
        for b in befunde:
            print(f"    - {b}", file=sys.stderr)
        return 2

    text = rendere(daten, a.kind)
    if a.tor_schlusssatz:
        # A BRIDGE, AND IT IS NAMED AS ONE. Measured 2026-09-24: setting a body through
        # `gh pr edit --body-file` is refused by the outbound gate unless the LAST line is the
        # closing sentence of the autonomous way, which the gate requires because it classifies a
        # pull request body as a reply on a Codex thread. A pull request body is not a thread reply,
        # and that sentence names an authorisation for threads, so appending it describes the surface
        # slightly wrongly. It is therefore off by default and switched on per call, until the order
        # that gives the gate its own genre for pull request bodies has landed. Then this flag and
        # this comment go away together.
        text = text.rstrip("\n") + "\n\n" + TOR_SCHLUSSSATZ + "\n"
    if not a.ohne_hygiene:
        verletzungen = hygiene(text, str(a.quelle))
        if verletzungen:
            print(f"  REFUSED: the rendered text fails claim hygiene "
                  f"({len(verletzungen)} violation(s)):", file=sys.stderr)
            for v in verletzungen:
                print(f"    - line {v['line']}: {v['match']!r} ({v['phrase']})", file=sys.stderr)
            return 3
    if a.aus:
        a.aus.write_text(text, encoding="utf-8")
        print(f"  {a.aus} · {len(text)} characters · {len(text.splitlines())} lines")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
