"""Das Findings-Register wird mit dem Restrisiko-Register VERGLICHEN, nicht aus ihm abgeleitet.

DIE KLASSE, gegen die dieser Riegel steht (gefunden 2026-09-08 beim Vorbereiten der kanonischen
Register-Bytes fuer 6.0.0, Owner-GO am selben Tag): ``scripts/gen_findings_register.py`` sagt in
seinem eigenen Kopfkommentar, die Liste sei „abgeleitet aus ``RESTRISIKO_600.md``" — und genau das
war sie: ABGELEITET, einmal, von Hand. Danach wuchs die Quelle weiter und die Ableitung nicht.
Gemessen am Kandidatenkopf: das Register trug ``N1..N20``, ``RESTRISIKO_600.md`` fuehrte
``N1..N21``, und ``audit_artifacts/600/README.md`` zaehlte ausdruecklich „R1-R7 and N1-N21".
Drei Dokumente, zwei Zahlen, kein Vergleich.

WARUM DAS NICHT AM TOR AUFFIEL: ``C12.2`` zaehlt OFFENE ``P0``/``P1`` im signierten Register. Eine
FEHLENDE Zeile kann dort nicht offen sein — die Luecke ist fuer diese Pruefung unsichtbar, egal wie
gross sie wird. Ein Riegel, der nur die Menge zaehlt, die er kennt, misst seine eigene
Vollstaendigkeit nie.

DIE UNTERSCHEIDUNG, die dieser Test macht und die Ableitung nicht machen kann: eine ABLEITUNG
beantwortet „welche Funde kenne ich?", ein VERGLEICH beantwortet „kenne ich alle?". Beide Fragen
brauchen ihren eigenen Riegel; die zweite ist die, die still altert.

RICHTUNG DES URTEILS, bewusst asymmetrisch. Ein Fund im Risiko-Register, der im Findings-Register
FEHLT, ist ein Fehler: das signierte Artefakt behauptet dann eine Vollstaendigkeit, die es nicht
hat. Umgekehrt ist ein Eintrag im Findings-Register, den das Risiko-Register nicht fuehrt, KEIN
Fehler dieses Tests — er kann aus einer anderen Quelle stammen (die Liste nennt selbst mehrere).
Er wird gemeldet, aber er faellt nicht.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RESTRISIKO = REPO / "RESTRISIKO_600.md"
ERZEUGER = REPO / "scripts" / "gen_findings_register.py"

#: Die N-Funde stehen im Restrisiko-Register als TABELLENZEILEN `| N<n> | ... |`. Bewusst an den
#: Zeilenanfang gebunden: `N12` kommt im Fliesstext mehrfach als Verweis vor, und ein Verweis ist
#: keine Deklaration. Gemessen 2026-09-08: 21 Tabellenzeilen, N1..N21, gegen 21 verschiedene IDs
#: im Fliesstext — die beiden Mengen sind hier zufaellig gleich, und genau deshalb steht die
#: Bindung an die Zeilenform hier und nicht im Kommentar.
_ZEILE = re.compile(r"^\|\s*(N\d+)\s*\|", re.M)


def _restrisiko_ids() -> set[str]:
    if not RESTRISIKO.is_file():
        pytest.skip("RESTRISIKO_600.md liegt hier nicht (sdist ohne Repo-Kontext)")
    return set(_ZEILE.findall(RESTRISIKO.read_text(encoding="utf-8")))


def _register_ids() -> set[str]:
    if not ERZEUGER.is_file():
        pytest.skip("scripts/gen_findings_register.py liegt hier nicht")
    spec = importlib.util.spec_from_file_location("_gen_reg_vergleich", str(ERZEUGER))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_gen_reg_vergleich"] = mod
    spec.loader.exec_module(mod)
    return {str(f["id"]) for f in mod.FINDINGS}


def test_kein_fund_des_restrisikos_fehlt_im_register():
    """Jede N-Kennung des Restrisiko-Registers steht auch im Findings-Register."""
    quelle, register = _restrisiko_ids(), _register_ids()
    assert quelle, "keine N-Zeile in RESTRISIKO_600.md gefunden — der Test misst dann nichts"
    fehlend = sorted(quelle - register, key=lambda s: int(s[1:]))
    assert not fehlend, (
        f"{len(fehlend)} Fund(e) stehen in RESTRISIKO_600.md, aber NICHT im Findings-Register: "
        f"{fehlend}. Das signierte Register behauptet damit eine Vollstaendigkeit, die es nicht "
        f"hat — und C12.2 kann das nicht sehen, weil eine fehlende Zeile dort nicht offen sein "
        f"kann. Aufnehmen in scripts/gen_findings_register.py::FINDINGS, oder mit Begruendung als "
        f"Kommentar ausschliessen (dann gehoert die Kennung hier in eine benannte Ausnahmemenge, "
        f"nicht ins Schweigen)."
    )


def test_das_register_nennt_seine_zusatzlichen_eintraege(capsys):
    """Die Gegenrichtung wird GEMELDET, nicht bestraft — sie ist kein Fehler dieses Tests.

    Ein Eintrag im Findings-Register ohne Zeile im Restrisiko-Register kann legitim aus einer
    anderen Quelle stammen. Er hier durchfallen zu lassen wuerde den Riegel zu einem Zwang machen,
    beide Dokumente deckungsgleich zu halten — das ist mehr, als die Sache verlangt, und es waere
    die Art Ueberbindung, die spaeter jemand mit einer Ausnahme aufweicht.
    """
    quelle, register = _restrisiko_ids(), _register_ids()
    nur_register = sorted(register - quelle, key=lambda s: int(s[1:]) if s[1:].isdigit() else 0)
    if nur_register:
        print(f"HINWEIS, kein Fehler: {len(nur_register)} Eintrag/Eintraege stehen nur im "
              f"Findings-Register: {nur_register}")
    assert True
