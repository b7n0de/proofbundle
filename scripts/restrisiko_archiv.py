#!/usr/bin/env python3
"""Cut byte-identical excerpts out of the published record — or refuse.

Owner order 20260911T2233Z, decision one, item one: "under audit_artifacts/600/restrisiko lie
the byte-identical excerpts from the published prose, one file per finding, with source digest
and byte range, nothing shortened, nothing translated." Its prohibition: "not one byte of the
archive excerpts."

WHY A TOOL AND NOT A HAND-CUT. An excerpt made by hand is a claim about a file; an excerpt made
by a rule against a pinned digest is a measurement of it. This script writes the excerpts AND
verifies them, and the verification re-derives every range from the source instead of trusting
the recorded digest — a check that only compared a stored hash to itself would agree with
whatever it was given.

TWO CARRIERS, because the record has two and pretending otherwise would quietly drop 25 findings.
Measured on RESTRISIKO_600.md at v6.0.0: 118 identifiers carry a heading (`### R1 · …`), 25 stand
only in a table row (N1-N21, A1-A4). So:

  heading — from the first byte of the heading line to the byte before the next heading of the
            same or a higher level. That is the finding's own section, nothing of its neighbour.
  row     — the single table row, from the first byte of the line to its newline.

Offline and git-free by construction: the pinned source is HANDED to this script as a file, and
its digest must match the one the manifest records. A tool that fetched the state it verifies
would be judging its own choice of input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "proofbundle.restrisiko_archiv.v1"
# `[*_]*` statt `\**`, und `(?![A-Za-z0-9])` statt `\b`. Beides gemessen 12.09.2026, nachdem ein
# Juror die Sammelueberschrift trotz vorhandener Regel reproduziert hatte:
#   * Markdown zeichnet mit STERNCHEN UND UNTERSTRICH aus. Die erste Fassung kannte nur Sternchen,
#     also fiel `## __S102__ bis S114` GANZ aus der Erkennung — nicht als Sammlung, sondern gar
#     nicht. Ein Fund, den kein Muster sieht, hat keinen Ausschnitt.
#   * `_` IST ein Wortzeichen. Zwischen `S102` und dem schliessenden `__` steht damit gar keine
#     Wortgrenze; `\b` griff dort nie. Die zweite Haertung lag also an einer Eigenschaft der
#     Zeichenklasse, nicht an der Auszeichnung — und ohne sie blieb die erste wirkungslos.
ID_UEBERSCHRIFT_VOLL = re.compile(
    r"^(#{2,4})\s+(?:↳\s*)?[*_]*\s*([A-Z]\d+[a-z]?)(?![A-Za-z0-9])(.*)$", re.M)
# The ONE shape that means "this heading is about a RANGE of findings, not about one".
# Measured: exactly one heading in the record at v6.0.0 matches it (`## S102 bis S114 — …`).
# Deliberately NOT "the heading mentions a second identifier": `### Z5 — S51 haelt, mit zwei
# Praezisierungen` mentions one and is Z5's own section.
# Zwischen Kennung und Bereichswort duerfen SCHLIESSENDE Auszeichnungen stehen. Von Juror A an
# `## **S102** bis S114 — …` reproduziert: der Rest beginnt mit `**`, nicht mit Leerraum, das
# Muster griff nicht, die Sammlung galt wieder als Fund — und weil sie flacher steht als
# `### S102`, verschluckte ihr Ausschnitt S103 und S104 (byte_range [10, 217] im gestellten Fall).
# Genau der Fehler, den der Docstring oben als behoben beschreibt. Im Bestand steht heute keine
# solche Ueberschrift: latent im BESTAND ist nicht behoben in der REGEL.
# Der Geviertstrich bleibt DRAUSSEN — sonst wuerde `### Z5 — S51 haelt …` zur Sammlung und Z5
# verloere seinen eigenen Abschnitt. Eine Haertung, die jede Ueberschrift zur Sammlung macht, ist
# keine.
BEREICHSWORT = re.compile(r"^[\s*_]*(bis|to|through|\.\.+)\s*[A-Z]?\d", re.I)
ID_ROW = re.compile(r"^\|\s*([A-Z]\d+[a-z]?)\s*\|", re.M)
ALLE_UEBERSCHRIFTEN = re.compile(r"^(#{1,6})\s", re.M)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# Fenced code blocks are NOT markup — and a line inside one is not a heading, however it starts.
#
# MEASURED 12.09.2026 on the shipped archive, found by an adversarial lens and confirmed at the
# artefact: `ALLE_UEBERSCHRIFTEN` matched the Python comment line
#     `#                     = "schnellstes_ende"  # way B — stays red`
# inside a ```python block, counted it as a depth-1 heading, and ended S19's section there. S19.md
# was written 533 bytes long instead of its whole section; S37.md broke off inside a code example.
# "Nothing shortened" was false for two findings in the delivered archive, and the verifier said OK
# — because it re-derives the ranges with THIS function, so a systematic blind spot cannot show up
# in it. That is the deeper defect: derivation compared against derivation is not verification.
_FENCE = re.compile(r"^[ \t]{0,3}(```+|~~~+)", re.M)


def ausserhalb_der_codebloecke(text: str):
    """Return a predicate: is this character offset OUTSIDE every fenced block?

    Fences are paired in document order: the first marker opens, the next closes. An unclosed
    fence at the end of the file swallows the rest — which is what a Markdown reader does too, so
    the excerpt matches what a reader sees rather than what a tidier file would have contained.
    """
    spannen: list[tuple[int, int]] = []
    offen: int | None = None
    for m in _FENCE.finditer(text):
        if offen is None:
            offen = m.start()
        else:
            zeilen_ende = text.find("\n", m.start())
            spannen.append((offen, len(text) if zeilen_ende == -1 else zeilen_ende + 1))
            offen = None
    if offen is not None:
        spannen.append((offen, len(text)))

    def frei(pos: int) -> bool:
        return not any(a <= pos < b for a, b in spannen)

    return frei


def bereiche(text: str) -> list[dict]:
    """Every identifier with the byte range that carries it. Ranges are over UTF-8 bytes.

    Character offsets would be a different number on the same file, and the manifest is read by
    whoever wants to cut the same bytes again — so bytes are the unit, stated rather than implied.

    THREE CARRIER SHAPES, all measured in the record at v6.0.0 rather than assumed. Two earlier
    versions of this rule were wrong, and both were wrong in a way that still LOOKED like an
    excerpt, which is why the overlap check below exists:

      * "first heading wins" made S102's excerpt the whole of `## S102 bis S114 — …`, 17 KB to
        the end of the file, containing S103, S104 and the rest.
      * "deepest heading wins" then made S22's excerpt the `### S22, Nachtrag …` sitting INSIDE
        S24's section, and the same for S50.

    Measured: 9 identifiers carry more than one heading. Eight of them are one section plus its
    addenda; exactly ONE (S102) is a collection heading, and it is the only heading in the record
    where a range word follows the identifier. So:

      main      — the SHALLOWEST heading naming the identifier that is not a collection heading.
      addendum  — every further heading naming it, in document order. Kept as its own file: an
                  addendum belongs to the finding, and concatenating two non-contiguous ranges
                  would produce a run of bytes that never existed in the source.
      row       — for identifiers no heading carries (N1-N21, A1-A4): the single table row.

    A section ends at the next heading of the same or a higher level — collection headings
    included, since one of those does end the section before it.
    """
    # A character index is not a byte offset, and the manifest promises bytes. Precomputed once:
    # doing it per call would re-encode the whole file for every one of ~300 positions.
    laengen = [len(c.encode("utf-8")) for c in text]
    vorlauf = [0]
    for x in laengen:
        vorlauf.append(vorlauf[-1] + x)

    def byte_offset(zeichen_index: int) -> int:
        return vorlauf[zeichen_index]

    frei = ausserhalb_der_codebloecke(text)
    koepfe = [(m.start(), len(m.group(1))) for m in ALLE_UEBERSCHRIFTEN.finditer(text)
              if frei(m.start())]

    def ende_von(start: int, tiefe: int) -> int:
        for pos, t in koepfe:
            if pos > start and t <= tiefe:
                return pos
        return len(text)

    je_kennung: dict[str, list[tuple[int, int]]] = {}
    for m in ID_UEBERSCHRIFT_VOLL.finditer(text):
        if not frei(m.start()):                 # inside a fenced block — not a heading at all
            continue
        if BEREICHSWORT.match(m.group(3)):      # `S102 bis S114` — a collection, not a finding
            continue
        je_kennung.setdefault(m.group(2), []).append((len(m.group(1)), m.start()))

    aus: list[dict] = []
    for kid, vork in je_kennung.items():
        haupt = min(vork, key=lambda x: (x[0], x[1]))
        rest = sorted(v for v in vork if v != haupt)
        tiefe, start = haupt
        aus.append({"id": kid, "part": "main", "carrier": "heading", "file": f"{kid}.md",
                    "byte_range": [byte_offset(start), byte_offset(ende_von(start, tiefe))]})
        for i, (t2, s2) in enumerate(rest, start=1):
            aus.append({"id": kid, "part": f"addendum-{i}", "carrier": "heading",
                        "file": f"{kid}.addendum-{i}.md",
                        "byte_range": [byte_offset(s2), byte_offset(ende_von(s2, t2))]})

    for m in ID_ROW.finditer(text):
        kid = m.group(1)
        if not frei(m.start()):
            continue
        if kid in je_kennung or any(e["id"] == kid for e in aus):
            continue
        zeilen_ende = text.find("\n", m.start())
        ende = len(text) if zeilen_ende == -1 else zeilen_ende + 1
        aus.append({"id": kid, "part": "main", "carrier": "row", "file": f"{kid}.md",
                    "byte_range": [byte_offset(m.start()), byte_offset(ende)]})

    return sorted(aus, key=lambda x: x["byte_range"][0])


def ueberlappungen(eintraege: list[dict]) -> list[list]:
    """Which excerpts contain bytes of another. Re-derived, never trusted from the manifest.

    Not a defect by itself — Z2-Z5 are declared subordinate identifiers INSIDE S58, and an
    addendum sits inside whichever section it was written into. It is a FACT about the record, so
    it is recorded and compared: a source change that creates a new overlap must not pass as an
    unchanged archive. Both earlier versions of the rule above were caught by exactly this number.
    """
    sortiert = sorted(eintraege, key=lambda x: x["byte_range"][0])
    raus = []
    for i, a in enumerate(sortiert):
        for b in sortiert[i + 1:]:
            if b["byte_range"][0] >= a["byte_range"][1]:
                break
            raus.append([a["file"], b["file"]])
    return sorted(raus)


def schneide(roh: bytes, eintrag: dict) -> bytes:
    a, b = eintrag["byte_range"]
    return roh[a:b]


def manifest_bauen(text: str, quell_pfad: str, quell_sha: str) -> dict:
    roh = text.encode("utf-8")
    eintraege = []
    roh_eintraege = bereiche(text)
    for e in roh_eintraege:
        stueck = schneide(roh, e)
        eintraege.append({**e, "bytes": len(stueck), "sha256": sha256_bytes(stueck)})
    return {"schema": SCHEMA,
            "source": {"path": quell_pfad, "sha256": quell_sha, "bytes": len(roh)},
            "rule": ("heading: from the heading line to the byte before the next heading of the "
                     "same or a higher level. row: the single table row including its newline. "
                     "Ranges are UTF-8 byte offsets into the source named above."),
            "excerpts": eintraege,
            "overlaps": ueberlappungen(roh_eintraege)}


def schreiben(text: str, quell_pfad: str, quell_sha: str, ordner: Path) -> int:
    roh = text.encode("utf-8")
    man = manifest_bauen(text, quell_pfad, quell_sha)
    ordner.mkdir(parents=True, exist_ok=True)
    for e in man["excerpts"]:
        (ordner / e["file"]).write_bytes(schneide(roh, e))
    (ordner / "MANIFEST.json").write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n",
                                          encoding="utf-8")
    return len(man["excerpts"])


def pruefen(text: str, ordner: Path) -> list[str]:
    """Re-derive every range from the handed source and compare the bytes on disk.

    Deliberately NOT "does the file match its recorded digest": that would be true of any pair
    written together, including a pair where both are wrong. The source is the authority here.
    """
    f: list[str] = []
    mpfad = ordner / "MANIFEST.json"
    if not mpfad.is_file():
        return [f"no manifest at {mpfad}"]
    man = json.loads(mpfad.read_text(encoding="utf-8"))
    if man.get("schema") != SCHEMA:
        return [f"not a {SCHEMA} manifest: {man.get('schema')!r}"]

    roh = text.encode("utf-8")
    ist_quelle = sha256_bytes(roh)
    if man["source"]["sha256"] != ist_quelle:
        return [f"the handed source is not the one this archive was cut from "
                f"(manifest {man['source']['sha256'][:12]}…, handed {ist_quelle[:12]}…). "
                f"Nothing else was checked: every range below would be about a different file."]

    frisch = {e["file"]: e for e in bereiche(text)}
    for e in man["excerpts"]:
        kid = e["file"]
        if kid not in frisch:
            f.append(f"{kid}: recorded in the manifest but not found in the source any more")
            continue
        if frisch[kid]["byte_range"] != e["byte_range"]:
            f.append(f"{kid}: the range moved — manifest {e['byte_range']}, "
                     f"re-derived {frisch[kid]['byte_range']}")
            continue
        soll = schneide(roh, e)
        datei = ordner / e["file"]
        if not datei.is_file():
            f.append(f"{kid}: excerpt file missing: {e['file']}")
            continue
        ist = datei.read_bytes()
        if ist != soll:
            f.append(f"{kid}: {e['file']} is NOT byte-identical with the source range "
                     f"({len(ist)} bytes on disk, {len(soll)} in the source)")
        elif sha256_bytes(ist) != e["sha256"]:
            f.append(f"{kid}: {e['file']} matches the source but not its recorded digest")
    fehlend = sorted(set(frisch) - {e["file"] for e in man["excerpts"]})
    if fehlend:
        f.append(f"in the source but not in the archive: {fehlend}")
    # EINE UNABHAENGIGE EIGENSCHAFT, die `bereiche()` nicht fragt.
    #
    # Das ist die eigentliche Lehre des S19/S37-Fundes: `pruefen()` leitete jeden Bereich mit
    # DERSELBEN Funktion neu ab wie `schreiben()`. Ableitung gegen Ableitung stimmt immer mit sich
    # selbst ueberein, also kann eine systematische Erfassungsluecke darin nie auffallen — der
    # Verifizierer meldete OK, waehrend zwei Ausschnitte mitten im Codebeispiel abbrachen.
    #
    # Diese Pruefung fragt etwas anderes und rechnet nichts nach: ein Ausschnitt, der eine UNGERADE
    # Zahl von Codeblock-Marken enthaelt, endet INNERHALB eines Blocks. Das ist eine Eigenschaft des
    # Ausschnitts selbst, unabhaengig davon, wie seine Grenzen zustande kamen, und sie faengt genau
    # die Klasse, die hier durchkam.
    for e in man["excerpts"]:
        datei = ordner / e["file"]
        if not datei.is_file():
            continue
        marken = len(_FENCE.findall(datei.read_text(encoding="utf-8")))
        if marken % 2:
            f.append(f"{e['id']}: {e['file']} carries {marken} code-fence marker(s) — an odd count "
                     f"means the excerpt ENDS INSIDE a fenced block, so it was cut short. This does "
                     f"not re-derive the range; it asks a property of the excerpt itself.")

    ist_ueber = ueberlappungen(list(frisch.values()))
    if ist_ueber != man.get("overlaps", []):
        f.append(f"the overlap set changed — recorded {man.get('overlaps')}, "
                 f"re-derived {ist_ueber}. An excerpt that grew to contain a neighbour still "
                 f"looks like an excerpt; this number is what notices.")
    return f


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--quelle", type=Path, required=True,
                   help="the PINNED published prose, handed as a file (e.g. `git show "
                        "v6.0.0:RESTRISIKO_600.md > …`). This tool never fetches it itself.")
    p.add_argument("--quell-pfad", default="RESTRISIKO_600.md@v6.0.0", dest="quell_pfad",
                   help="how the source state is NAMED in the manifest")
    p.add_argument("--ordner", type=Path, default=Path("audit_artifacts/600/restrisiko"))
    p.add_argument("--schreiben", action="store_true", help="write the excerpts and the manifest")
    p.add_argument("--pruefen", action="store_true", help="re-derive and compare, write nothing")
    a = p.parse_args(argv)

    text = a.quelle.read_text(encoding="utf-8")
    quell_sha = sha256_bytes(text.encode("utf-8"))
    if not (a.schreiben or a.pruefen):
        print("neither --schreiben nor --pruefen given; nothing done", file=sys.stderr)
        return 2
    if a.schreiben:
        n = schreiben(text, a.quell_pfad, quell_sha, a.ordner)
        print(f"wrote {n} excerpt(s) and MANIFEST.json into {a.ordner}")
        print(f"source: {a.quell_pfad} sha256 {quell_sha}")
    if a.pruefen:
        f = pruefen(text, a.ordner)
        if f:
            print(f"REFUSED — {len(f)} archive finding(s):", file=sys.stderr)
            for x in f:
                print(f"  {x}", file=sys.stderr)
            return 1
        man = json.loads((a.ordner / "MANIFEST.json").read_text(encoding="utf-8"))
        print(f"OK — {len(man['excerpts'])} excerpt(s) byte-identical with "
              f"{man['source']['path']} (sha256 {man['source']['sha256'][:12]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
