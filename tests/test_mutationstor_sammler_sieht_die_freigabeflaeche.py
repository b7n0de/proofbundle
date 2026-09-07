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


# ── Der Riegel gegen das Wiederkommen ────────────────────────────────────────────────────────────
#
# Der Fix oben stellt den Sammler um. Er verhindert NICHT, dass die blinde Menge auf einem anderen
# Weg zurueckkehrt — etwa wenn jemand den Sammler wieder tauscht, oder wenn eine Datei aus einem
# Grund unsichtbar wird, den niemand zaehlt. Genau so ist der Befund entstanden: die Zahl stand
# seit dem 02.09. in N19, aber NIEMAND mass sie fortlaufend, und als am 06.09. zwoelf Operatoren auf
# eine Flaeche kamen, deren Tests vollstaendig in der blinden Menge lagen, fiel es keinem auf.
#
# EINE MENGE, DIE NIEMAND ZAEHLT, WAECHST STILL. Dieser Fall zaehlt sie.

#: Dateien, die absichtlich keinen Test liefern duerfen — je mit Grund. Eine leere Liste ist die
#: richtige Vorgabe: wer eine Datei hier eintraegt, muss sagen warum, und der Grund steht dann im
#: Repo statt in einem Kopf.
_OHNE_TESTS_ERLAUBT: dict[str, str] = {}


def _gesehene_dateien() -> set[str]:
    """Welche Testdateien liefert der Sammler des Tors? Als eigene Funktion, damit ihr FEHLERFALL
    pruefbar ist — ein Riegel, dessen Absturzverhalten niemand misst, ist kein Riegel."""
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"],
        cwd=REPO, capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(Path.home())})
    return {ln.split("::", 1)[0].split("/", 1)[1]
            for ln in r.stdout.splitlines() if ln.startswith("tests/") and "::" in ln}


def test_der_sammler_des_tors_sieht_JEDE_testdatei():
    """DER RIEGEL. Jede tests/test_*.py liefert dem Sammler des Tors mindestens einen Test.

    Faellt dieser Fall, ist die Frage nicht 'welcher Test fehlt', sondern 'welche Flaeche misst das
    Tor gerade nicht'. Die Antwort steht in der Meldung, mit Dateinamen.
    """
    dateien = sorted(p.name for p in (REPO / "tests").glob("test_*.py"))
    assert dateien, "Vorbedingung: tests/ enthaelt Testdateien — sonst prueft dieser Fall nichts"
    gesehen = _gesehene_dateien()
    blind = [d for d in dateien if d not in gesehen and d not in _OHNE_TESTS_ERLAUBT]
    assert not blind, (
        f"{len(blind)} von {len(dateien)} Testdateien liefern dem Sammler des Mutationstors KEINEN "
        f"Test. Ueber diese Flaechen sagt das Tor nichts — weder gruen noch rot:\n  "
        + "\n  ".join(blind)
        + "\n\nAm 2026-09-07 waren es 57 von 254 (22 Prozent), und darunter lagen VOLLSTAENDIG die "
          "Dateien der Release-Entscheidungsflaeche. Der Lauf meldete daraufhin acht Ueberlebende, "
          "von denen sechs abgedeckt waren. Wer eine Datei bewusst ohne Test laesst, traegt sie mit "
          "Grund in _OHNE_TESTS_ERLAUBT ein — dann steht der Grund im Repo statt in einem Kopf.")


def test_ANTI_PARITAET_der_riegel_wuerde_eine_blinde_datei_melden():
    """KONTROLLE: der Riegel oben besteht auch, wenn er gar nichts prueft. Dieser Fall pflanzt eine
    blinde Datei in die Rechnung und verlangt, dass die Logik sie faengt."""
    dateien = ["test_echt.py", "test_blind.py"]
    gesehen = {"test_echt.py"}
    erlaubt: dict[str, str] = {}
    blind = [d for d in dateien if d not in gesehen and d not in erlaubt]
    assert blind == ["test_blind.py"], (
        "Die Logik des Riegels faengt eine eingepflanzte blinde Datei NICHT — dann wuerde der Fall "
        "oben auch eine echte nicht fangen und bestuende nur, weil nichts zu finden war.")
    # Und die Gegenrichtung: eine dokumentierte Ausnahme wird NICHT gemeldet.
    assert not [d for d in dateien if d not in gesehen and d not in {"test_blind.py": "Grund"}], (
        "Eine dokumentierte Ausnahme wird trotzdem gemeldet — dann waere _OHNE_TESTS_ERLAUBT wirkungslos.")


# ── Der dritte Zustand: NICHT MESSBAR ────────────────────────────────────────────────────────────
#
# `budget: data_digests-Schranke praktisch entfernt` meldete am 2026-09-07 `SURVIVED (red=0)`. Der
# mutierte Lauf war aber gar nicht zu Ende gekommen: die Mutation entfernt die Ressourcendecke,
# unter der der Lauf steht, und der Kernel beendete den Prozess (393,4 s gegen ~65 s, dann Killed).
# `red=0` hiess also nicht "kein Test wurde rot", sondern "es gab keine Bilanz".
#
# EIN ERSTER VERSUCH DIESES RIEGELS WAR WIRKUNGSLOS und steht hier als Warnung: er gab bei fehlender
# Bilanzzeile `1` zurueck, "fail-closed". Das Urteil lautet aber `killed = red > baseline`, und die
# Baseline dieses Repos ist 14 — `1 > 14` ist falsch, der Absturz haette sich WEITERHIN als SURVIVED
# gelesen. Ein Riegel, dessen Wert unter der Schwelle bleibt, gegen die er antritt, wirkt nicht.

def _mutation_check_modul():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_mc_dritter_zustand", str(REPO / "scripts" / "mutation_check.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_mc_dritter_zustand"] = m
    spec.loader.exec_module(m)
    return m


class _Ausgang:
    def __init__(self, stdout: str, stderr: str = ""):
        self.stdout, self.stderr, self.returncode = stdout, stderr, 1


def test_ein_lauf_ohne_bilanzzeile_ist_NICHT_MESSBAR_und_nicht_null(monkeypatch, tmp_path):
    """DIE ZUSICHERUNG. Ohne Bilanzzeile gibt `_red_count` None zurueck, nicht 0 und nicht 1."""
    m = _mutation_check_modul()
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang(""))
    assert m._red_count(tmp_path) is None, (
        "Ein Lauf ohne jede Bilanzzeile liefert eine ZAHL statt None. Damit landet er im Vergleich "
        "`killed = red > baseline` und liest sich als SURVIVED — genau der Fall, der am 2026-09-07 "
        "als 'SURVIVED (red=0)' gemeldet wurde, obwohl der Prozess vom Kernel beendet worden war.")


def test_ANTI_PARITAET_ein_lauf_MIT_bilanzzeile_liefert_weiter_eine_zahl(monkeypatch, tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende die Zusicherung oben auch, wenn `_red_count` IMMER None
    gaebe — dann waere jeder Operator nicht messbar und das Tor stumm."""
    m = _mutation_check_modul()
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang("3 failed, 120 passed in 1.0s"))
    assert m._red_count(tmp_path) == 3, "eine vorhandene Bilanzzeile muss weiterhin gezaehlt werden"
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang("120 passed in 1.0s"))
    assert m._red_count(tmp_path) == 0, (
        "ein gruener Lauf MIT Bilanzzeile muss 0 ergeben — nicht None. Sonst waere jeder gesunde "
        "Operator 'nicht messbar' und das Tor koennte nichts mehr toeten.")


def test_der_wert_bei_fehlender_bilanz_wuerde_die_schwelle_gar_nicht_erreichen(monkeypatch, tmp_path):
    """DER FALL, DER DEN ERSTEN VERSUCH WIDERLEGT HAETTE — er steht hier, damit die Klasse nicht
    wiederkommt. Haette `_red_count` bei fehlender Bilanz eine ZAHL geliefert, muesste sie groesser
    als jede plausible Baseline sein, um zu wirken. Genau das ist der Grund fuer None."""
    m = _mutation_check_modul()
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang(""))
    wert = m._red_count(tmp_path)
    baseline_dieses_repos = 14
    assert wert is None or wert > baseline_dieses_repos, (
        f"_red_count gibt bei fehlender Bilanzzeile {wert} zurueck. Das Urteil lautet "
        f"`killed = red > baseline`, und die Baseline dieses Repos ist {baseline_dieses_repos} — "
        f"ein Wert darunter wirkt NICHT und der Absturz liest sich weiter als SURVIVED.")


def test_der_riegel_faellt_SICHER_wenn_der_sammler_selbst_scheitert(monkeypatch):
    """K3, DIE GEFAEHRLICHSTE FRAGE AN DIESEN DIFF, gemessen statt begruendet.

    Der Riegel liest die Sammelmenge aus dem stdout eines Unterprozesses. Scheitert dieser — ein
    Importfehler in conftest, ein fehlendes pytest, ein Timeout —, ist stdout leer. Ein Riegel, der
    daraus 'nichts ist blind' schliesst, waere die schlimmste Fassung von allen: er meldete GRUEN
    genau dann, wenn er gar nicht messen konnte.

    Dieser Fall pflanzt den Ausfall ein und verlangt, dass der Riegel ROT wird.
    """
    monkeypatch.setattr(sys.modules[__name__], "_gesehene_dateien", lambda: set())
    with pytest.raises(AssertionError) as exc:
        test_der_sammler_des_tors_sieht_JEDE_testdatei()
    assert "liefern dem Sammler des Mutationstors KEINEN Test" in str(exc.value), (
        "Der Riegel faellt zwar, aber nicht mit seiner eigenen Meldung — dann faengt hier etwas "
        "anderes, und der geprueft geglaubte Pfad ist ein anderer als der gemessene.")


def test_ANTI_PARITAET_der_riegel_besteht_wenn_der_sammler_ALLES_sieht(monkeypatch):
    """Die Gegenrichtung zu oben. Ohne sie bestuende der Fall davor auch, wenn der Riegel IMMER
    faellt — dann waere er kein Riegel, sondern ein Dauerrot."""
    alle = {p.name for p in (REPO / "tests").glob("test_*.py")}
    monkeypatch.setattr(sys.modules[__name__], "_gesehene_dateien", lambda: alle)
    test_der_sammler_des_tors_sieht_JEDE_testdatei()   # muss ohne AssertionError durchlaufen
