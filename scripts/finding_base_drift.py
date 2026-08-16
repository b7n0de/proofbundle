#!/usr/bin/env python3
"""Wogegen wurde dieser Befund gemessen — und ist der Stamm seither weitergelaufen?

DER VORFALL, 2026-08-16, gemessen an der eigenen Zeitachse:

    17:47:54  PR #141 landet auf main: "derive the family population from the tree, not from a list"
    18:10:42  `origin/main` wird lokal geholt — das Repo WEISS es
    23:36:20  ich committe dieselbe Arbeit noch einmal, 5 h 48 min spaeter

Die Information lag die ganze Zeit da. Ich habe nicht hingesehen, weil ich aus
`audit_artifacts/380/FINDING_never_raise_population.md` gearbeitet habe und dort
`outcome: class_open` steht. **Dieses Feld ist ein Schnappschuss vom Zeitpunkt der Messung**, kein
Live-Zustand — und ich habe es als lebende Wahrheit gelesen.

WARUM EIN VORSATZ NICHT REICHT. Die Praeregistrierung verlangt in §9 seit jeher, dass ein Record den
Digest NENNT, den er benotet. Gemessen am 2026-08-16: drei von sechs Befunden nannten gar keinen,
und zwei der vorhandenen Hex-Werte waren stdout-Hashes, keine Commits. Eine Regel, die niemand
ausfuehrt, ist eine Absichtserklaerung. Deshalb hier ein Werkzeug und daneben ein Test.

WAS DIESES WERKZEUG TUT: es nimmt einen Befund, liest den Commit, gegen den er gemessen wurde, und
zeigt, was seither auf dem Stamm passiert ist — mit den Betreffzeilen. Wer "fix(never-raise):
derive the family population from the tree" in dieser Liste liest, sieht die Kollision in einer
Sekunde. Genau diese Sekunde hat heute gefehlt.

WAS ES NICHT TUT, und das ist eine ehrliche Grenze, keine Bescheidenheit: es kann nicht
entscheiden, ob eine Bewegung des Stamms fuer DIESEN Befund relevant ist. Ein Befund ist Prosa; er
nennt keine Dateien. Das Urteil bleibt beim Leser — das Werkzeug sorgt nur dafuer, dass er die Liste
ueberhaupt sieht. Deshalb meldet es DREI Zustaende und nie ein blosses "in Ordnung":

    AKTUELL         der genannte Stand IST die Stammspitze
    STAMM_WEITER    der Stamm ist seither gelaufen — die Liste steht darunter, LIES SIE
    NICHT_MESSBAR   kein Commit genannt, oder der genannte laesst sich nicht aufloesen

`NICHT_MESSBAR` ist ausdruecklich keine Freigabe. Es heisst, dass die Frage offen ist.

    python scripts/finding_base_drift.py audit_artifacts/380/FINDING_*.md
    python scripts/finding_base_drift.py --alle-offenen
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

_REPO = pathlib.Path(__file__).resolve().parents[1]
# Ein Commit wird NICHT am Aussehen erkannt — Hex sieht auch ein stdout-Hash. Erkannt wird, was git
# als Commit AUFLOESEN kann. Das ist die unterscheidende Eigenschaft, und sie ist messbar.
_HEX = re.compile(r"`([0-9a-f]{7,40})`")
_GESCHLOSSEN = re.compile(r"\bclass_closed\b|\*\*closed\*\*|\bCLOSED\b")


def _git(*args: str) -> "str | None":
    try:
        p = subprocess.run(["git", "-C", str(_REPO), *args], capture_output=True, text=True,
                           timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def gemessener_stand(text: str) -> "str | None":
    """Der erste genannte Hex-Wert, den git als COMMIT aufloest — nicht der erste Hex-Wert.

    Der Unterschied ist gemessen: die 380-Akte nennt `d4d6a953ea033c72` und `6f5177382070a08a`,
    beides sha256-Praefixe von stdout, keine Commits. Wer nach Aussehen sucht, findet sie und haelt
    einen Befund faelschlich fuer verankert.
    """
    for kandidat in _HEX.findall(text):
        typ = _git("cat-file", "-t", kandidat)
        if typ == "commit":
            return kandidat
    return None


def pruefe(pfad: pathlib.Path, stamm: str = "origin/main") -> dict:
    text = pfad.read_text(encoding="utf-8", errors="replace")
    aus: dict = {"datei": str(pfad.relative_to(_REPO)), "geschlossen": bool(_GESCHLOSSEN.search(text)),
                 "stand": None, "zustand": "NICHT_MESSBAR", "seither": [], "grund": None}
    spitze = _git("rev-parse", stamm)
    if spitze is None:
        aus["grund"] = f"{stamm} ist nicht aufloesbar (kein fetch? kein Remote?)"
        return aus
    stand = gemessener_stand(text)
    if stand is None:
        aus["grund"] = ("der Record nennt keinen Commit, gegen den er gemessen wurde — "
                        "Praeregistrierung §9 verlangt das")
        return aus
    aus["stand"] = stand
    voll = _git("rev-parse", stand) or stand
    if voll == spitze:
        aus["zustand"] = "AKTUELL"
        return aus
    log = _git("log", "--oneline", f"{stand}..{stamm}")
    if log is None:
        aus["grund"] = f"{stand}..{stamm} nicht auflistbar (flacher Klon?)"
        return aus
    aus["zustand"] = "STAMM_WEITER"
    aus["seither"] = [z for z in log.splitlines() if z.strip()]
    return aus


def main(argv: "list[str] | None" = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("dateien", nargs="*", type=pathlib.Path)
    p.add_argument("--alle-offenen", action="store_true",
                   help="jeden nicht geschlossenen FINDING_*.md unter audit_artifacts/")
    p.add_argument("--stamm", default="origin/main")
    a = p.parse_args(argv)

    dateien = list(a.dateien)
    if a.alle_offenen or not dateien:
        dateien = sorted((_REPO / "audit_artifacts").glob("*/FINDING_*.md"))
    if not dateien:
        print("keine Befund-Dateien gefunden — nichts zu pruefen", file=sys.stderr)
        return 2

    schlimmster = 0
    for f in dateien:
        r = pruefe(f if f.is_absolute() else _REPO / f, a.stamm)
        if a.alle_offenen and r["geschlossen"]:
            continue
        marke = {"AKTUELL": "  ", "STAMM_WEITER": "->", "NICHT_MESSBAR": "??"}[r["zustand"]]
        print(f"{marke} {r['datei']}")
        print(f"     Zustand: {r['zustand']}"
              + (f"  (gemessen gegen {r['stand']})" if r["stand"] else ""))
        if r["grund"]:
            print(f"     {r['grund']}")
        if r["seither"]:
            print(f"     {len(r['seither'])} Commit(s) auf {a.stamm} seither — LIES SIE, bevor du"
                  " an diesem Befund arbeitest:")
            for z in r["seither"][:15]:
                print(f"       {z}")
            if len(r["seither"]) > 15:
                print(f"       … und {len(r['seither']) - 15} weitere")
            schlimmster = max(schlimmster, 1)
        elif r["zustand"] == "NICHT_MESSBAR":
            schlimmster = max(schlimmster, 1)
        print()
    return schlimmster


if __name__ == "__main__":
    raise SystemExit(main())
