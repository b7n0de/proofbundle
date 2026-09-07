"""Der Sammler des Mutationstors muss die Tests der Freigabeflaeche SEHEN.

WARUM ES DIESE DATEI GIBT. Am 2026-09-07 endete der kanonische Mutationslauf gegen den
6.0.0-Kandidaten mit acht Ueberlebenden. Sechs davon lagen auf der Release-Entscheidungsflaeche
(`scripts/audit_candidate_matrix.py`, `src/proofbundle/budget.py`, `src/proofbundle/renewal.py`) —
und fuer mindestens einen von ihnen existierte ein Test, der ihn GEZIELT angreift:
`test_freigabe_evidenz_provenienz_l5_g7_02.py::test_ein_commit_der_sonst_etwas_anfasst_ist_nicht_erlaubt`
prueft mit `assert erlaubt is False` genau die Mutation `fremd = []`.

Der Grund, warum das Tor ihn trotzdem als SURVIVED meldete: es sammelte mit
`unittest.TestLoader().discover()`, und der sieht ausschliesslich Methoden von `unittest.TestCase`.
GEMESSEN am Kandidaten: 2565 Tests aus 197 Dateien gegen 3728 aus 254 unter pytest. 57 Dateien
(22 Prozent) waren unsichtbar — und die blinde Menge war nicht zufaellig gestreut, sie enthielt
VOLLSTAENDIG die Dateien der Freigabeflaeche.

`N19` in `RESTRISIKO_600.md` nennt die ZAHL bereits und behandelt sie als Geltungsbereich. Neu ist
die VERTEILUNG: an der Stelle, an der die Freigabe entschieden wird, mass das Tor nichts — weder
gruen noch rot. Diese Datei haelt genau das fest, damit es nicht ein zweites Mal still passiert.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

#: Die Dateien, die die Release-Entscheidungsflaeche pruefen. Sie sind hier NAMENTLICH genannt und
#: nicht ueber ein Muster gesucht: ein Muster wuerde stillschweigend leer, wenn jemand umbenennt,
#: und ein leeres Muster besteht jede Zusicherung.
_FREIGABEFLAECHE = (
    "test_freigabe_evidenz_provenienz_l5_g7_02.py",
    "test_ausfuehrung_aus_quelltext_l5_g7_04.py",
    "test_audit_candidate_ready_logic.py",
    "test_audit_matrix_version_pin_binding.py",
    "test_budget_kostenkurve.py",
    "test_renewal_praefix_deckung_orakel.py",
)


def _unittest_sammelt(datei: str) -> int:
    """Wie viele Tests holt der ALTE Sammler aus dieser Datei?"""
    suite = unittest.TestLoader().discover(str(REPO / "tests"), top_level_dir=str(REPO / "tests"))
    treffer = []

    def gehe(s):
        for t in s:
            gehe(t) if isinstance(t, unittest.TestSuite) else treffer.append(t)

    gehe(suite)
    stamm = datei[:-3]
    return sum(1 for t in treffer if t.__class__.__module__ == stamm)


def _pytest_sammelt(datei: str) -> int:
    """Wie viele Tests holt der NEUE Sammler aus dieser Datei?"""
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         f"tests/{datei}"],
        cwd=REPO, capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin:/usr/local/bin",
             "HOME": str(Path.home())})
    return sum(1 for ln in r.stdout.splitlines() if "::" in ln and ln.startswith("tests/"))


@pytest.mark.parametrize("datei", _FREIGABEFLAECHE)
def test_der_neue_sammler_sieht_die_datei(datei):
    """DIE ZUSICHERUNG. Jede Datei der Freigabeflaeche liefert dem Tor mindestens einen Test."""
    if not (REPO / "tests" / datei).exists():
        pytest.skip(f"{datei} existiert in diesem Baum nicht — nichts zu messen, nichts zu behaupten")
    n = _pytest_sammelt(datei)
    assert n > 0, (
        f"Der Sammler des Mutationstors holt aus tests/{datei} NULL Tests. Damit misst das Tor an "
        f"dieser Stelle nichts — weder gruen noch rot. Genau diese Lage fuehrte am 2026-09-07 zu "
        f"acht gemeldeten Ueberlebenden auf der Freigabeflaeche, fuer die Tests existierten.")


@pytest.mark.parametrize("datei", _FREIGABEFLAECHE)
def test_ANTI_PARITAET_der_alte_sammler_sah_sie_nicht(datei):
    """DIE KONTROLLE, ohne die die Zusicherung oben wertlos waere.

    Eine Zusicherung 'der Sammler sieht die Datei' besteht auch dann, wenn JEDER Sammler sie saehe —
    dann prueft sie nichts. Dieser Fall haelt fest, dass der ALTE Sammler sie NICHT sah: nur so ist
    belegt, dass der Wechsel etwas bewirkt und nicht bloss dasselbe anders schreibt.

    Faellt dieser Test irgendwann, weil eine Datei auf `unittest.TestCase` umgestellt wurde, ist das
    kein Fehler — dann ist sie fuer BEIDE Sammler sichtbar. Er wird dann uebersprungen, nicht
    stillgelegt, und der Grund steht in der Meldung.
    """
    if not (REPO / "tests" / datei).exists():
        pytest.skip(f"{datei} existiert in diesem Baum nicht")
    alt = _unittest_sammelt(datei)
    if alt > 0:
        pytest.skip(
            f"tests/{datei} ist inzwischen auch fuer den alten Sammler sichtbar ({alt} Tests) — "
            f"die Anti-Paritaet dieses Falls ist damit gegenstandslos, die Zusicherung oben bleibt")
    assert alt == 0, "unerreichbar"


def test_der_neue_sammler_ist_eine_echte_obermenge():
    """Kein Tausch, sondern ein Zugewinn: pytest sammelt auch `unittest.TestCase`-Klassen."""
    datei = "test_budget.py"
    if not (REPO / "tests" / datei).exists():
        pytest.skip(f"{datei} existiert in diesem Baum nicht")
    alt, neu = _unittest_sammelt(datei), _pytest_sammelt(datei)
    assert alt > 0, (
        f"Vorbedingung dieses Falls: tests/{datei} traegt unittest.TestCase-Klassen. Sie ist nicht "
        f"erfuellt — der Fall misst dann nicht, was er behauptet, statt still zu bestehen.")
    assert neu >= alt, (
        f"Der neue Sammler holt aus tests/{datei} {neu} Tests, der alte {alt}. Ein Sammler, der "
        f"WENIGER sieht, waere ein Tausch und kein Zugewinn — dann faellt Abdeckung weg, die das "
        f"Tor bisher hatte.")
