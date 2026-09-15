"""Vertrag: die Reifegrad-Marken der obersten CLI-Ebene bleiben ABLEITBAR und gezaehlt.

WARUM ES DIESEN VERTRAG GIBT, und die Begruendung ist eine Messung an mir selbst.
Am 15.09.2026 wurde die Hilfeausgabe der obersten Ebene vermessen, um eine GRUPPIERTE
Hilfe vorzubereiten (Auftrag Z43). Der erste Zaehler suchte die Marke am ANFANG der
Beschreibung, in eckigen Klammern, und meldete *zwei* markierte Kommandos. Nach der
EIGENSCHAFT gemessen — "nennt sich experimentell", egal an welcher Stelle und in welcher
Klammer — sind es **vier**. Ein Vierfaches uebersehen, weil nach der Schreibweise gesucht
wurde statt nach der Eigenschaft.

Die Marke steht heute in DREI Schreibweisen: ``[EXPERIMENTAL v2.0]`` fuehrend,
``(EXPERIMENTAL)`` mitten im Satz, ``[PROPOSED]`` fuehrend. Sie ist Prosa, kein Feld.
Solange das so ist, ist jede Gruppierung eine Regex-Uebung mit genau dieser Fehlerklasse.

WAS DIESER VERTRAG LEISTET und was nicht. Er macht die Marke NICHT zu einem Feld — das
ist eine Aenderung an ``cli.py`` und gehoert in einen eigenen Zug. Er haelt die gemessene
Verteilung fest, damit eine Verschiebung AUFFAELLT statt still zu passieren: ein neues
Kommando ohne Marke, eine Marke in einer VIERTEN Schreibweise, ein experimentelles
Kommando, das stillschweigend stabil wird. Das ist die billige Haelfte des Klassenfixes,
und sie ist sofort zu haben.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

WURZEL = Path(__file__).resolve().parents[1]

#: Gemessen 15.09.2026 an origin/main 4aeebe38. Eine Abweichung ist kein Fehler dieses
#: Tests, sondern eine Aenderung an der CLI, die jemand bewusst mitziehen muss.
ERWARTET = {"EXPERIMENTAL": 4, "PROPOSED": 2, "ohne_marke": 13}
ERWARTETE_KOMMANDOS = 19


def _hilfe() -> str:
    r = subprocess.run(
        [sys.executable, "-m", "proofbundle.cli", "--help"],
        capture_output=True, text=True, cwd=WURZEL,
        env={"PYTHONPATH": str(WURZEL / "src"), "PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert r.returncode == 0, f"--help endete mit {r.returncode}: {r.stderr[:400]}"
    return r.stdout


def _kommandos(hilfe: str) -> dict[str, str]:
    """Name -> vollstaendige Beschreibung, Fortsetzungszeilen angehaengt.

    DIE FORTSETZUNGSZEILEN SIND DER PUNKT: argparse bricht lange Beschreibungen um, und
    eine Marke kann in der ZWEITEN Zeile stehen. Wer nur die erste liest, misst die
    Schreibweise des Umbruchs.
    """
    aus: dict[str, str] = {}
    akt: str | None = None
    for z in hilfe.split("\n"):
        m = re.match(r"^ {4}([a-z][a-z0-9-]*)\s{2,}(\S.*)$", z)
        if m:
            akt = m.group(1)
            aus[akt] = m.group(2)
        elif akt is not None and re.match(r"^ {20,}\S", z):
            aus[akt] += " " + z.strip()
        elif not z.strip() or z.startswith("options:"):
            akt = None
    return aus


def _reifegrad(beschreibung: str) -> str:
    """Nach der EIGENSCHAFT, nicht nach der Schreibweise — das ist der ganze Punkt."""
    if "EXPERIMENTAL" in beschreibung:
        return "EXPERIMENTAL"
    if "PROPOSED" in beschreibung:
        return "PROPOSED"
    return "ohne_marke"


def test_die_oberste_ebene_fuehrt_die_gemessene_zahl_an_kommandos() -> None:
    cmds = _kommandos(_hilfe())
    assert len(cmds) == ERWARTETE_KOMMANDOS, (
        f"{len(cmds)} Unterkommandos statt {ERWARTETE_KOMMANDOS}. Wer eines hinzufuegt oder "
        f"entfernt, zieht diese Zahl mit — sie steht in einem Messblatt und in einem Auftrag. "
        f"Gefunden: {sorted(cmds)}"
    )


def test_die_reifegrad_verteilung_bleibt_wie_gemessen() -> None:
    cmds = _kommandos(_hilfe())
    ist: dict[str, int] = {"EXPERIMENTAL": 0, "PROPOSED": 0, "ohne_marke": 0}
    wer: dict[str, list[str]] = {k: [] for k in ist}
    for name, b in cmds.items():
        g = _reifegrad(b)
        ist[g] += 1
        wer[g].append(name)
    assert ist == ERWARTET, (
        f"Die Reifegrad-Verteilung hat sich verschoben: {ist} statt {ERWARTET}.\n"
        f"EXPERIMENTAL: {sorted(wer['EXPERIMENTAL'])}\n"
        f"PROPOSED:     {sorted(wer['PROPOSED'])}\n"
        f"ohne Marke:   {sorted(wer['ohne_marke'])}\n"
        "Das ist kein Fehler dieses Tests. Entweder ist ein Kommando reifer geworden — dann "
        "gehoert die Zahl hier nachgezogen —, oder eine Marke ist in einer Schreibweise "
        "dazugekommen, die `_reifegrad` nicht als solche liest. Der zweite Fall ist der "
        "gefaehrliche: er sieht aus wie ein stabiles Kommando."
    )


def test_eine_marke_wird_auch_in_einer_fortsetzungszeile_gefunden() -> None:
    """Anti-Fall gegen den Fehler, der diesen Vertrag ausgeloest hat.

    Die Marke von `outcome` steht NICHT am Anfang, sondern in Klammern mitten im Satz —
    und bei `verify-enclave` fuehrend in eckigen Klammern. Ein Zaehler, der nur den Anfang
    liest, findet einen von beiden. Dieser Fall stellt sicher, dass `_reifegrad` beide
    sieht, und er faellt, wenn jemand die Erkennung auf ein Praefix verengt.
    """
    cmds = _kommandos(_hilfe())
    fuehrend = [n for n, b in cmds.items() if b.lstrip().startswith("[EXPERIMENTAL")]
    innen = [n for n, b in cmds.items()
             if "EXPERIMENTAL" in b and not b.lstrip().startswith("[EXPERIMENTAL")]
    assert fuehrend, "kein Kommando mit fuehrender EXPERIMENTAL-Marke — Vorzustand war 1"
    assert innen, (
        "kein Kommando mit EXPERIMENTAL-Marke INNERHALB der Beschreibung. Gemessen waren es "
        "drei (outcome, relation-statement, anchor). Faellt dieser Fall weg, verliert der "
        "Vertrag genau die Eigenschaft, fuer die er gebaut wurde."
    )
