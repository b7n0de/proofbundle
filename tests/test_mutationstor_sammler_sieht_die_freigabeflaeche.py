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
    def __init__(self, stdout: str, stderr: str = "", returncode: int = 1):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


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
    # DIE ZAHL 14 STAND HIER UND WAR AUS DER DOKUMENTATION UEBERNOMMEN, NICHT GEMESSEN. Die
    # Basislinie dieses Baums ist am 2026-09-07 mit beiden Sammlern nachgemessen worden und
    # betraegt 0 (alt `Ran 2534, rot=0`, neu `3675 passed, rot=0`). Das macht die Lage NICHT
    # harmloser, sondern kehrt sie um: bei `killed = red > 0` liest sich jede positive Zahl als
    # KILL. Ein abgestuerzter Lauf haette sich dann nicht als uebersehene Luecke gemeldet,
    # sondern als GEFANGENE Mutante — ein falsches Gruen auf der Release-Seite statt eines
    # falschen Rots. Deshalb ist hier jede Zahl falsch und nur der dritte Zustand richtig.
    assert wert is None, (
        f"_red_count gibt bei fehlender Bilanzzeile {wert} zurueck statt None. Bei der gemessenen "
        f"Basislinie 0 dieses Baums verbucht `killed = red > baseline` jeden positiven Wert als "
        f"KILL — ein Lauf, der gar nicht stattfand, meldete sich dann als gefangene Mutante.")


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


# ── DIE ZUSICHERUNGEN, DIE WIRKLICH AM FIX HAENGEN ───────────────────────────────────────────────
#
# EINE GEGENLESUNG HAT DIE FAELLE OBEN VERWORFEN (VERDIKT REJECT, 2026-09-07), und der Beleg war
# ausgefuehrt statt behauptet: sie setzte in einer Kopie den Sammler zurueck auf
# `unittest.TestLoader().discover()` — also genau den Defekt, gegen den diese Datei laut ihrem
# Docstring antritt — und ALLE Faelle blieben gruen.
#
# DER GRUND WAR EIN DENKFEHLER IM ORAKEL, nicht in der Messung. `_pytest_sammelt` und
# `_gesehene_dateien` bauen ihr EIGENES `subprocess.run([..., "pytest", "--collect-only", ...])`.
# Sie rufen `scripts/mutation_check.py` an keiner Stelle auf; `grep -rl "_lauf_der_suite" tests/`
# fand im ganzen Repo keine Datei. Geprueft wurde ein DUPLIKAT des Sammlers, nicht der Sammler.
# Ein Orakel, das die Implementierung nachbaut, teilt ihren Denkfehler — dieselbe Klasse, die in
# diesem Repo schon zweimal steht.
#
# DIE FAELLE UNTEN BEHEBEN DAS: sie fahren `mutation_check._red_count` und `_lauf_der_suite`
# SELBST. Faellt der Fix zurueck, fallen sie.

def _mini_baum(tmp_path, dateiname: str, inhalt: str):
    """Ein Miniaturbaum, den der ECHTE Sammler fahren kann."""
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "tests" / dateiname).write_text(inhalt, encoding="utf-8")
    return tmp_path


def test_der_ECHTE_sammler_des_moduls_sieht_eine_pytest_only_datei(tmp_path):
    """DIE ZUSICHERUNG, die am Fix haengt — sie ruft mutation_check.py, nicht eine Nachbildung.

    Eine Datei OHNE `unittest.TestCase` ist fuer `unittest discover` unsichtbar und fuer pytest
    nicht. Sieht der Sammler des Tors sie, wird ihr roter Test gezaehlt; sieht er sie nicht, meldet
    er 0 oder gar keine Bilanz. Genau diese Differenz ist der ganze Fund vom 2026-09-07.
    """
    m = _mutation_check_modul()
    baum = _mini_baum(tmp_path, "test_nur_pytest_und_rot.py",
                      "def test_der_rot_ist():\n    assert False, 'absichtlich rot'\n")
    rot = m._red_count(baum)
    assert rot is not None, (
        "Der Lauf hinterliess keine Bilanzzeile. Unter `unittest discover` ist genau das die "
        "Antwort auf einen Baum, der nur pytest-Funktionen enthaelt ('Ran 0 tests') — der Sammler "
        "sieht die Datei also nicht. Unter pytest muss eine Bilanz dastehen.")
    assert rot >= 1, (
        f"Der Sammler des Moduls holt aus einer pytest-only Testdatei NICHTS: er meldet {rot} rot, "
        f"obwohl die Datei einen Test enthaelt, der absichtlich faellt. Das ist der Zustand vom "
        f"2026-09-07: 57 von 254 Dateien unsichtbar, darunter VOLLSTAENDIG die "
        f"Release-Entscheidungsflaeche. Wer den Sammler zurueckdreht, faellt hier.")


def test_ANTI_PARITAET_der_echte_sammler_meldet_eine_gruene_suite_als_gruen(tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einem Sammler, der IMMER rot
    meldet — dann waere jede Mutante 'getoetet' und das Tor in der anderen Richtung wertlos."""
    m = _mutation_check_modul()
    baum = _mini_baum(tmp_path, "test_nur_pytest_und_gruen.py",
                      "def test_der_gruen_ist():\n    assert True\n")
    assert m._red_count(baum) == 0, (
        "Eine gruene pytest-only Suite wird als rot gemeldet. Ein Sammler, der Gesundes rot "
        "faerbt, macht jede Mutante zum Kill — das Tor bestuende dann immer und pruefte nichts.")


def test_jeder_ausschlusseintrag_zeigt_auf_eine_existierende_datei():
    """DIE ZUSAGE ALS ZUSICHERUNG, an der Stelle, wo die Frage hingehoert: gegen DIESES Repo.

    Gemessen 2026-09-07: `pytest --ignore=tests/gibt_es_nicht.py` bricht NICHT ab — rc=0, und alle
    Tests laufen trotzdem. Ein Eintrag mit Tippfehler, ein umbenanntes Modul oder eines in einem
    Unterordner schloesse also STILL nichts aus, waehrend der Kommentar am Ausschluss eine
    Garantie behauptet. Eine unbelegte Zusage im Kommentar ist keine Zusage.

    Ein erster Versuch liess das die LAUFZEIT pruefen und brach dabei zwei Faelle in
    `test_mutation_isolation.py`, die ein winziges Fixture-Repo fahren: die Ausschlussmenge ist
    eine Aussage ueber dieses Repo, nicht ueber jeden Baum. Deshalb steht sie hier.
    """
    m = _mutation_check_modul()
    assert m._AUSSCHLUSS_JE_MUTANTE, (
        "die Ausschlussmenge ist leer — dann prueft dieser Fall nichts, statt still zu bestehen")
    ohne_ziel = [name for name in m._AUSSCHLUSS_JE_MUTANTE
                 if not (REPO / "tests" / f"{name}.py").is_file()]
    assert not ohne_ziel, (
        f"Ausschlusseintrag/-eintraege ohne Ziel in diesem Repo: {ohne_ziel}. `--ignore` auf einen "
        f"nicht existierenden Pfad ist ein stiller Nulleffekt: die genannte Datei laeuft im Tor "
        f"weiter mit, und das Tor fuehre eine andere Menge als die, die es dokumentiert.")


def test_ANTI_PARITAET_ein_erfundener_ausschlusseintrag_wuerde_auffallen():
    """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch, wenn die Logik nie etwas faende."""
    erfunden = "test_diesen_namen_gibt_es_nicht_0907"
    assert not (REPO / "tests" / f"{erfunden}.py").is_file(), "Vorbedingung des Falls"
    ohne_ziel = [n for n in (erfunden,) if not (REPO / "tests" / f"{n}.py").is_file()]
    assert ohne_ziel == [erfunden], (
        "Die Logik des Falls oben faengt einen eingepflanzten Eintrag ohne Ziel NICHT — dann "
        "bestuende er nur, weil nichts zu finden war.")


def test_ANTI_PARITAET_der_ausschluss_laeuft_durch_wenn_sein_ziel_da_ist(monkeypatch, tmp_path):
    """Die Gegenrichtung: ohne sie bestuende der Fall oben auch bei einem Riegel, der IMMER haelt."""
    m = _mutation_check_modul()
    monkeypatch.setattr(m, "_AUSSCHLUSS_JE_MUTANTE", {"test_es_gibt_mich": "Grund"})
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "tests" / "test_es_gibt_mich.py").write_text("def test_x():\n    assert True\n",
                                                             encoding="utf-8")
    assert m._ausschluss_args(tmp_path) == ["--ignore=tests/test_es_gibt_mich.py"], (
        "Ein vorhandenes Ziel wird nicht in ein --ignore uebersetzt — dann schliesst das Tor die "
        "dokumentierte Datei gar nicht aus und der Riegel oben haelt einfach immer.")


def test_das_kommando_des_tors_traegt_die_drei_riegel(monkeypatch, tmp_path):
    """DIE FLAGS WERDEN AM AUFRUF GEMESSEN, nicht am Quelltext.

    Die Gegenlesung hat angemerkt, dass `-p no:randomly` und `timeout=1800` von keinem Test
    gehalten werden: ein versehentlicher Wegfall faellt nur per `grep` auf, also gar nicht. Dieser
    Fall faengt die ARGUMENTE ab, mit denen `_lauf_der_suite` den Unterprozess wirklich startet.
    """
    m = _mutation_check_modul()
    gesehen = {}

    def falle(argv, **kw):
        gesehen["argv"], gesehen["kw"] = argv, kw
        return _Ausgang("1 passed in 0.1s")

    monkeypatch.setattr(m.subprocess, "run", falle)
    monkeypatch.setattr(m, "_AUSSCHLUSS_JE_MUTANTE", {})
    m._lauf_der_suite(tmp_path)

    argv, kw = gesehen["argv"], gesehen["kw"]
    assert "pytest" in argv, (
        f"Das Tor startet die Suite nicht ueber pytest: {argv}. Damit ist der Fund vom 2026-09-07 "
        f"zurueck — und `_startet_suite` des Laeufer-Waechters klassifiziert diese Datei dann "
        f"nicht mehr als pytest-Laeufer.")
    for flag, warum in (
            ("no:randomly", "ohne dieses Flag vergleicht das Tor zwei verschieden gefahrene "
                            "Suiten; pytest-randomly ist in diesem Repo aktiv (K6)"),
            ("--continue-on-collection-errors",
             "ohne dieses Flag bricht pytest bei einem Sammelfehler die ganze Sitzung ab und "
             "schreibt `1 error` — bei Basislinie 0 verbucht `red > baseline` das als KILL, "
             "obwohl kein Test lief")):
        assert flag in argv, f"{flag} fehlt im Aufruf des Tors: {warum}. Gemessen: {argv}"
    assert kw.get("timeout") == 1800, (
        f"Der Lauf hat keinen Timeout ({kw.get('timeout')!r}). Ausgerechnet der Operator, der die "
        f"Ressourcendecke entfernt, kann haengen; ein Tor, dessen Unterprozess haengt, meldet "
        f"nichts und haelt den ganzen Lauf an (K5).")
    assert kw.get("errors") == "replace", (
        "Der Lauf dekodiert strikt — ein einzelnes Nicht-UTF8-Byte aus dem Kindprozess reisst "
        "ihn dann mit UnicodeDecodeError ab statt ihn als NICHT MESSBAR zu fuehren.")


def test_ein_abgebrochener_lauf_MIT_zaehlbarer_zahl_ist_NICHT_MESSBAR(monkeypatch, tmp_path):
    """DER SCHWERSTE FUND DER GEGENLESUNG, als Fall festgehalten.

    pytest bricht bei einem Sammelfehler die GESAMTE Sitzung ab und schreibt trotzdem eine Zahl:
    `1 error`. Der alte Riegel griff nur bei `rot == 0` — die Zahl kam also durch. Bei der
    gemessenen Basislinie 0 dieses Baums haette `1 > 0` die Mutante als GETOETET verbucht,
    obwohl von 3728 Tests keiner lief. Ein falsches Gruen, erzeugt vom Sicherheitsnetz selbst.
    """
    m = _mutation_check_modul()
    abbruch = ("==================================== ERRORS ====================================\n"
               "_______________________ ERROR collecting test_kaputt.py ________________________\n"
               "!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!\n"
               "1 error in 0.15s\n")
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang(abbruch))
    assert m._red_count(tmp_path) is None, (
        "Ein von pytest abgebrochener Lauf liefert eine ZAHL statt None. Genau diese Zahl ist die "
        "gefaehrlichste: sie ist klein, plausibel und steht fuer einen Lauf, in dem nichts lief.")


def test_ANTI_PARITAET_ein_ZUENDE_gelaufener_lauf_mit_fehlern_zaehlt_weiter(monkeypatch, tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einem Riegel, der jeden Lauf mit
    dem Wort 'error' fuer nicht messbar erklaert — dann koennte das Tor nichts mehr toeten."""
    m = _mutation_check_modul()
    zuende = "2 failed, 1 error, 3670 passed, 25 skipped in 850.10s\n"
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang(zuende))
    assert m._red_count(tmp_path) == 3, (
        "Ein Lauf, der ZU ENDE kam und dabei Fehler hatte, wird nicht mehr gezaehlt. Der Riegel "
        "gegen den Abbruch darf den Normalfall nicht mitnehmen — sonst ist jede echte Roete "
        "'nicht messbar' und das Tor stumm.")


def test_eine_stoerung_des_unterprozesses_ist_NICHT_MESSBAR(monkeypatch, tmp_path):
    """Der Fang-Pfad selbst, mit einer WIRKLICH geworfenen Ausnahme statt mit leerem stdout.

    Die Gegenlesung hat angemerkt, dass der `except`-Zweig von keinem Test durchlaufen wird: die
    vorhandenen Faelle pruefen nur den Text-Pfad. Hier wird geworfen.
    """
    m = _mutation_check_modul()
    for ausnahme in (m.subprocess.TimeoutExpired(cmd="pytest", timeout=1800),
                     OSError("kein Interpreter im PATH")):
        def wirf(*a, _e=ausnahme, **k):
            raise _e
        monkeypatch.setattr(m.subprocess, "run", wirf)
        assert m._red_count(tmp_path) is None, (
            f"{type(ausnahme).__name__} fuehrt nicht zu NICHT MESSBAR. Ein Timeout oder eine "
            f"Umgebungsstoerung darf weder als 0 gelesen werden noch den ganzen Shard-Lauf "
            f"mit rohem Traceback abreissen.")


# ── Das Kill-Signal darf nicht aus freiem Text kommen ────────────────────────────────────────────
#
# LINSE 5 DES DEEP GATE (Lauf 5, 2026-09-07) — REJECT mit ausgefuehrtem Gate-Meta-Test.
#
# `_rote_aus_text` las `re.search(r"(\d+) failed", blob)` ueber stdout+stderr — den ERSTEN Treffer
# im gesamten Ausgabetext. pytest kippt bei einem Fehlschlag den Testkoerper samt Docstring in die
# FAILURES-Sektion, und die steht VOR der Bilanz. Dieses Korpus traegt summary-foermige Zahlen in
# Docstrings (die Kommentare dieser Datei sind selbst voll davon). Gemessen mit dem ECHTEN Skript:
# ein gepflanzter Defekt der eigenen Klasse hob die WAHRE Roete von 1 auf 2, der Parser meldete
# beide Male 0, das Urteil lautete SURVIVED.
#
# DIE KLASSE, nicht die Zeile: eine Zeichenketten-Suche entscheidet ueber eine Groesse, die eine
# GRENZE meint — dort die Schlusszeile eines Berichts, in `pre_tag_receipt_lib._RECEIPT_MUSTER` eine
# Pfadgrenze. Beide sind in derselben Runde gefixt, beide mit einem Fangnachweis.

_EXPLOIT_BLOB = '''============================= test session starts ==============================
collected 3827 items

tests/test_irgendwas.py .F                                               [100%]

=================================== FAILURES ===================================
_________________________ test_der_die_bilanz_faelscht _________________________

    def test_der_die_bilanz_faelscht():
        """Ein Docstring, der eine Bilanz nachahmt: 0 failed, 3827 passed in 12.00s

        Genau so sieht ein Testkoerper aus, den pytest in die FAILURES-Sektion kippt.
        """
>       assert False
E       assert False

tests/test_irgendwas.py:9: AssertionError
=========================== short test summary info ============================
FAILED tests/test_irgendwas.py::test_der_die_bilanz_faelscht - assert False
2 failed, 3825 passed, 26 skipped in 1173.71s (0:19:33)
'''


def test_eine_zahl_im_DOCSTRING_entscheidet_NICHT_ueber_das_urteil(monkeypatch, tmp_path):
    """DIE ZUSICHERUNG, und sie ist der Fangnachweis zu Linse 5.

    Der Blob traegt zwei Bilanzen: eine gefaelschte im Docstring (`0 failed`) und die echte am Ende
    (`2 failed`). Der alte Parser nahm die erste, weil `re.search` von vorn liest. Damit meldete ein
    Lauf mit zwei roten Tests NULL — und `killed = red > baseline` machte daraus SURVIVED.
    """
    m = _mutation_check_modul()
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang(_EXPLOIT_BLOB))
    rot = m._red_count(tmp_path)
    assert rot == 2, (
        f"Der Lauf meldet {rot} rot statt 2. Die Zahl kommt aus dem Docstring in der "
        f"FAILURES-Sektion statt aus der Bilanzzeile — ein Defekt, der die Roete hebt, bleibt "
        f"damit unsichtbar und das Tor meldet SURVIVED fuer eine gefangene Mutante.")


def test_ANTI_PARITAET_eine_echte_bilanz_ohne_stoerung_zaehlt_unveraendert(monkeypatch, tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einem Parser, der die letzte Zahl
    im Text nimmt, egal was sie bedeutet — oder bei einem, der immer 2 liefert."""
    m = _mutation_check_modul()
    for blob, erwartet in (("7 failed, 100 passed in 3.0s", 7),
                           ("100 passed in 3.0s", 0),
                           ("1 failed, 2 error, 90 passed, 4 skipped in 9.99s", 3)):
        monkeypatch.setattr(m.subprocess, "run", lambda *a, _b=blob, **k: _Ausgang(_b))
        assert m._red_count(tmp_path) == erwartet, f"{blob!r} ergab nicht {erwartet}"


def test_die_bilanzzeile_wird_von_HINTEN_gelesen(monkeypatch, tmp_path):
    """Die EIGENSCHAFT statt des einen Blobs: erzeugt, nicht getippt.

    Vor die echte Bilanz wird eine wachsende Menge stoerender, bilanzfoermiger Zeilen gesetzt —
    so, wie sie in Tracebacks, Docstrings und Fehlermeldungen wirklich vorkommen. Der gemessene
    Wert muss IMMER der der echten Schlussbilanz sein.
    """
    m = _mutation_check_modul()
    stoerer = ["0 failed, 1 passed in 0.01s", "99 failed in 1.0s", "    3 failed, 3 passed in 2.5s",
               '"""Doku: 0 failed, 10 passed in 1.0s"""', "E   assert '5 failed in 1.0s'"]
    for n in range(len(stoerer) + 1):
        blob = "\n".join(stoerer[:n] + ["4 failed, 3820 passed, 26 skipped in 900.00s"])
        monkeypatch.setattr(m.subprocess, "run", lambda *a, _b=blob, **k: _Ausgang(_b))
        assert m._red_count(tmp_path) == 4, (
            f"Mit {n} vorangestellten bilanzfoermigen Zeilen meldet der Parser nicht 4. "
            f"Die Schlussbilanz ist die letzte Zeile, nicht die erste passende.")


def test_der_bericht_ist_die_erste_quelle_und_der_text_nur_der_rueckfall(tmp_path):
    """Der eigentliche Klassen-Fix: die Zahl kommt aus einer MASCHINENSCHNITTSTELLE.

    Ein JUnit-Bericht hat Felder statt Prosa. Steht er zur Verfuegung, entscheidet er — auch dann,
    wenn der Textpfad etwas anderes behauptet. Dieser Fall setzt beide Quellen bewusst in
    Widerspruch, damit sichtbar wird, welche traegt.
    """
    m = _mutation_check_modul()
    bericht = tmp_path / "bilanz.xml"
    bericht.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
        'errors="1" failures="2" skipped="26" tests="3827" time="1173.71"/></testsuites>',
        encoding="utf-8")
    assert m._rote_aus_bericht(bericht) == 3, "failures + errors muessen addiert werden"
    assert m._rote_aus_lauf(bericht, "0 failed, 3827 passed in 1.0s") == 3, (
        "Der Textpfad hat den Bericht ueberstimmt. Die strukturierte Quelle ist die erste; sonst "
        "ist der ganze Fix nur eine zweite Textsuche neben der ersten.")


def test_ein_fehlender_oder_kaputter_bericht_faellt_auf_den_GEHAERTETEN_text_zurueck(tmp_path):
    """Der Rueckfall muss existieren (fremde Baeume, ersetzter Unterprozess) und darf die Luecke
    NICHT wieder aufmachen — deshalb ist der Textpfad selbst gehaertet."""
    m = _mutation_check_modul()
    assert m._rote_aus_bericht(tmp_path / "gibt_es_nicht.xml") is None
    kaputt = tmp_path / "kaputt.xml"
    kaputt.write_text("<testsuites><nicht geschlossen", encoding="utf-8")
    assert m._rote_aus_bericht(kaputt) is None
    # und der Rueckfall zaehlt richtig, nicht nach dem ersten Treffer
    assert m._rote_aus_lauf(kaputt, _EXPLOIT_BLOB) == 2


def test_ein_bericht_ueber_NULL_tests_ist_keine_null_roete(tmp_path):
    """Dieselbe Unterscheidung wie im Textpfad, an der zweiten Quelle: ein Lauf, der nichts
    gefahren hat, ist nicht gruen — er ist nicht gelaufen."""
    m = _mutation_check_modul()
    leer = tmp_path / "leer.xml"
    leer.write_text('<testsuites><testsuite tests="0" failures="0" errors="0"/></testsuites>',
                    encoding="utf-8")
    assert m._rote_aus_bericht(leer) is None, (
        "Ein Bericht ueber null Tests liefert 0 statt None. Bei `killed = red > baseline` liest "
        "sich das als gruener Lauf — genau die Klasse, die der NICHT-MESSBAR-Zustand schliesst.")


def test_das_kommando_des_tors_fordert_den_bericht_an(monkeypatch, tmp_path):
    """Die Flags werden am AUFRUF gemessen, nicht am Quelltext — wie bei den drei Riegeln oben."""
    m = _mutation_check_modul()
    gesehen = {}
    monkeypatch.setattr(m.subprocess, "run",
                        lambda argv, **kw: (gesehen.update(argv=argv), _Ausgang("1 passed in 0.1s"))[1])
    monkeypatch.setattr(m, "_AUSSCHLUSS_JE_MUTANTE", {})
    m._lauf_der_suite(tmp_path, tmp_path / "b.xml")
    assert any(a.startswith("--junitxml=") for a in gesehen["argv"]), (
        f"Das Tor fordert keinen JUnit-Bericht an: {gesehen['argv']}. Dann haengt sein Urteil "
        f"wieder allein am Text, und der Fund von Linse 5 ist zurueck.")
    gesehen.clear()
    m._lauf_der_suite(tmp_path)          # ohne Bericht — der alte Vertrag bleibt
    assert not any(a.startswith("--junitxml=") for a in gesehen["argv"]), (
        "Ohne Berichtspfad darf kein --junitxml im Aufruf stehen; sonst schreibt ein fremder Baum "
        "eine Datei an einen Ort, den der Aufrufer nicht kennt.")


def test_ENDE_ZU_ENDE_ein_echter_lauf_mit_gefaelschter_bilanz_im_docstring(tmp_path):
    """DER GATE-META-TEST ZU LINSE 5, mit einem ECHTEN pytest-Unterprozess statt mit Textattrappen.

    Die Faelle oben ersetzen `subprocess.run` und pruefen damit den Parser. Dieser Fall pruefte den
    ganzen Pfad: echtes pytest, echte FAILURES-Sektion, echter JUnit-Bericht. Der rote Test traegt
    in seinem Docstring eine bilanzfoermige Zeile, und pytest kippt den Docstring bei Fehlschlag in
    die Ausgabe VOR die Bilanz — genau die Konstellation, mit der Linse 5 das Tor am 2026-09-07
    dazu gebracht hat, zwei rote Tests als null zu melden.

    Zwei rote Tests muessen als zwei gezaehlt werden. Wird hier 0 oder 1 gemeldet, ist das
    Kill-Signal wieder an freien Text gebunden und `killed = red > baseline` urteilt auf Prosa.
    """
    m = _mutation_check_modul()
    baum = _mini_baum(tmp_path, "test_mit_gefaelschter_bilanz.py", '''
def test_einer():
    """0 failed, 4711 passed in 0.01s — eine Bilanz, die keine ist."""
    assert False


def test_zwei():
    """Auch hier: 0 failed, 4711 passed in 0.02s"""
    assert False


def test_drei_ist_gruen():
    assert True
''')
    rot = m._red_count(baum)
    assert rot == 2, (
        f"Der echte Lauf meldet {rot} rote Tests statt 2. Die Zahl kommt dann aus dem Docstring in "
        f"der FAILURES-Sektion und nicht aus der Bilanz des Laufs — ein Defekt, der die Roete hebt, "
        f"bliebe unsichtbar und das Tor meldete SURVIVED fuer eine gefangene Mutante.")


def test_ein_ABGEBROCHENER_lauf_mit_pytest_exit_ist_NICHT_MESSBAR(tmp_path):
    """DER FUND DER ADVERSARIALEN GEGENLESUNG (2026-09-07), mit echtem pytest nachgestellt.

    Der Abbruch-Riegel kannte zwei WORTLAUTE (`!!!! Interrupted`, `INTERNALERROR`) und nicht die
    FORM. `pytest.exit()` schreibt aber ein Banner mit anderem Text:
    `!!!!!! _pytest.outcomes.Exit: <grund> !!!!!!`. Gemessen mit drei Tests, von denen der zweite
    `pytest.exit` ruft und der DRITTE gefallen waere: die Bilanz sagt `1 passed`, die JUnit-XML
    sagt `tests=1 failures=0 errors=0` — beide Quellen melden einen sauberen, VOLLSTAENDIGEN Lauf,
    waehrend der Test, der die Mutante haette toeten sollen, nie lief. Das ist die gefaehrliche
    Richtung: ein abgebrochener Lauf liest sich als gruen, und `killed = red > baseline` verbucht
    die Mutante als ueberlebend, obwohl niemand sie gemessen hat.

    Eine Liste von Abbruchgruenden waere beim naechsten stillschweigend zu kurz — deshalb bindet
    dieser Fall die FORM des Banners, nicht seinen Inhalt.
    """
    m = _mutation_check_modul()
    baum = _mini_baum(tmp_path, "test_bricht_ab.py", '''
import pytest


def test_eins():
    assert True


def test_zwei_bricht_ab():
    pytest.exit("erzwungener Abbruch mitten im Lauf")


def test_drei_waere_rot():
    assert False, "dieser Test laeuft nie — genau das ist der Punkt"
''')
    rot = m._red_count(baum)
    assert rot is None, (
        f"Ein mit pytest.exit abgebrochener Lauf liefert {rot} statt None. Beide Quellen — die "
        f"JUnit-XML und die Bilanzzeile — melden dann einen sauberen Lauf ueber eine Teilmenge, "
        f"und der Test, der die Mutante toeten sollte, wurde nie gefahren.")


def test_ANTI_PARITAET_ein_vollstaendiger_lauf_bleibt_messbar(tmp_path):
    """Die Kontrolle: der Formriegel darf den Normalfall nicht mitnehmen. Ohne sie waere ein
    Riegel, der JEDEN Lauf fuer nicht messbar erklaert, von einem richtigen nicht zu unterscheiden."""
    m = _mutation_check_modul()
    baum = _mini_baum(tmp_path, "test_laeuft_durch.py",
                      "def test_a():\n    assert True\n\n\ndef test_b():\n    assert False\n")
    assert m._red_count(baum) == 1, "ein vollstaendiger Lauf mit einem roten Test muss 1 ergeben"


def test_verschachtelte_testsuite_knoten_werden_NICHT_doppelt_gezaehlt(tmp_path):
    """Der zweite Fund der un-Gegenlesung, latent statt wirkend — und deshalb gebunden.

    `iter("testsuite")` steigt rekursiv ab. Schreibt ein Plugin verschachtelte Knoten, zaehlt die
    aeussere Summe die innere mit, und die rote Zahl entscheidet hier ueber KILLED/SURVIVED.
    Gemessen mit dem Laeufer dieses Tors: heute genau EIN Knoten, der Fund ist also nicht wirkend.
    Dieser Fall haelt die Annahme fest, statt sie unausgesprochen zu lassen.
    """
    m = _mutation_check_modul()
    b = tmp_path / "verschachtelt.xml"
    b.write_text(
        '<?xml version="1.0"?><testsuites>'
        '<testsuite name="aussen" tests="10" failures="2" errors="0">'
        '<testsuite name="innen" tests="5" failures="1" errors="0"/>'
        '</testsuite></testsuites>', encoding="utf-8")
    assert m._rote_aus_bericht(b) == 2, (
        "Der innere testsuite-Knoten wird mitgezaehlt (2 + 1 = 3 statt 2). Eine getoetete Mutante "
        "liest sich dann als ueberlebend oder umgekehrt — die Zahl entscheidet das Urteil.")


# ── Die Fuellbreite eines Banners ist keine Eigenschaft des Abbruchs ─────────────────────────────
#
# DIE un-GEGENLESUNG (2026-09-07, un_turbov1/qwen3.8:27b) hielt `_ABBRUCH_BANNER = ^!{5,} .* !{5,}$`
# fuer einen Release-Blocker, weil pytest angeblich VIER Ausrufezeichen schreibe. Nachgemessen im
# Laufpfad dieses Tors: der gewoehnliche Interrupt schreibt ZWANZIG je Seite, der Einwand traf so
# nicht zu. Die Messung fand aber den echten Weg daneben — und der ist schlimmer.
#
# `TerminalWriter.sep` rechnet `N = max((breite - len(titel) - 2) // 2, 1)`. Die Fuellbreite haengt
# also an der LAENGE DES TITELS, und `session.shouldstop` traegt einen beliebigen Text. Bei 80
# Spalten faellt N unter fuenf, sobald der Titel laenger als 68 Zeichen ist; bei einem langen Grund
# bleibt genau EIN Ausrufezeichen je Seite. AUSGEFUEHRT GEMESSEN mit echtem pytest: Banner mit
# einem `!`, `_ABBRUCH_BANNER` griff nicht, `_rote_aus_lauf` las die Bilanz `1 failed, 1 passed`
# und lieferte 1 — bei Basislinie 0 haette `1 > 0` die Mutante als GETOETET verbucht, obwohl der
# Lauf abbrach. Ein falsches Gruen, erzeugt vom Sicherheitsnetz selbst.
#
# DIESELBE KLASSE WIE DEN GANZEN TAG: eine Zahl, die eine GRENZE meint, wird aus einer Groesse
# gelesen, die etwas anderes misst. Der Fix nimmt sie aus einer MASCHINENSCHNITTSTELLE — dem
# Rueckgabewert von pytest (2 Interrupted, 3 intern, 4 Aufruf) —, so wie `--junitxml` die rote Zahl
# aus dem Text genommen hat. Die Bannerform bleibt als zweiter Riegel und ist auf `!+` geweitet.

def test_die_BANNERFORM_faengt_auch_ein_schmales_banner(monkeypatch, tmp_path):
    """ZUSICHERUNG AN DEN BANNER-RIEGEL, isoliert: OHNE Rueckgabewert traegt allein die Form.

    ZWEIMAL UMGEBAUT, BEIDE MALE VON EINEM FANGNACHWEIS ERZWUNGEN, und der Weg gehoert zum Fall:
    (1) Die erste Fassung benutzte `! Interrupted: <langer Grund> !` und traf damit den ALTEN
        Wortlaut-Riegel `^!+ Interrupted` in `_rote_aus_text` — gruen ohne den Fix, also blind.
    (2) Die zweite hiess "DIE ZUSICHERUNG" und gab rc=2 mit, band damit aber wieder nicht, was ihr
        Name behauptete: die un-Gegenlesung (un_turbov1/qwen3.8:27b, 2026-09-07) rechnete vor, dass
        derselbe Text auch das geweitete `^!+ .* !+$` trifft — bei isolierter Ruecknahme NUR des
        Rueckgabewert-Riegels waere sie gruen geblieben. Mein Fangnachweis hatte BEIDE Teile
        zugleich zurueckgenommen und konnte deshalb nicht sagen, welcher traegt.

    DIE KLASSE, und sie ist die des ganzen Tages: eine Pruefung, die zwei Ursachen zusammen
    aufhebt, misst keine von beiden. Jeder Riegel braucht eine Zusicherung, die bei SEINER
    isolierten Ruecknahme faellt — dieser Fall gehoert der Bannerform (rc=None), der naechste dem
    Rueckgabewert (kein Banner im Text).
    """
    m = _mutation_check_modul()
    # EIN Ausrufezeichen je Seite: bei 80 Spalten faellt N unter fuenf ab 68 Zeichen Titel.
    # rc=1 heisst "Tests rot, Lauf zu Ende" — der Rueckgabewert-Riegel greift hier ausdruecklich
    # NICHT, damit allein die Form geprueft wird.
    schmal = ("! _pytest.outcomes.Exit: abgebrochen, weil der Mutant die Umgebung unbrauchbar "
              "gemacht hat und nichts mehr messbar ist !\n1 failed, 1 passed in 0.14s\n")
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Ausgang(schmal, returncode=1))
    assert m._red_count(tmp_path) is None, (
        "Ein Banner mit EINEM Ausrufezeichen je Seite wird nicht als Abbruch erkannt. `!{5,}` "
        "verlangte fuenf — eine Fuellbreite ist aber eine Funktion der Titel-Laenge und keine "
        "Eigenschaft des Abbruchs.")


def test_der_RUECKGABEWERT_traegt_das_urteil_auch_ohne_jedes_banner(monkeypatch, tmp_path):
    """Die eigentliche Haertung, isoliert: OHNE Bannerzeile im Text traegt allein der rc.

    Ohne diesen Fall waere nicht unterscheidbar, ob der Fall oben am rc oder an der geweiteten
    Bannerform haengt — beide greifen dort zugleich, und ein Fix, dessen wirksamer Teil unbekannt
    ist, ist kein gemessener Fix.
    """
    m = _mutation_check_modul()
    ohne_banner = "1 failed, 1 passed in 0.14s\n"
    for rc, erwartet in ((2, None), (3, None), (4, None), (1, 1), (0, 1)):
        monkeypatch.setattr(m.subprocess, "run",
                            lambda *a, _rc=rc, **k: _Ausgang(ohne_banner, returncode=_rc))
        gemessen = m._red_count(tmp_path)
        assert gemessen == erwartet, (
            f"Rueckgabewert {rc} ergibt {gemessen!r} statt {erwartet!r}. 2/3/4 heissen 'der Lauf "
            f"ist nicht zu Ende gekommen'; 0 und 1 sind gemessene Laeufe und behalten ihre Zahl.")


def test_ANTI_PARITAET_der_rueckgabewert_riegel_nimmt_den_normalfall_NICHT_mit(monkeypatch, tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende die Zusicherung oben auch bei einem Riegel, der JEDEN Lauf
    fuer nicht messbar erklaert — dann koennte das Tor nichts mehr toeten und waere stumm."""
    m = _mutation_check_modul()
    monkeypatch.setattr(m.subprocess, "run",
                        lambda *a, **k: _Ausgang("3 failed, 3820 passed in 900.0s", returncode=1))
    assert m._red_count(tmp_path) == 3, "ein zu Ende gelaufener roter Lauf muss seine Zahl behalten"
    monkeypatch.setattr(m.subprocess, "run",
                        lambda *a, **k: _Ausgang("3836 passed, 25 skipped in 1193.0s", returncode=0))
    assert m._red_count(tmp_path) == 0, "ein gruener Lauf muss 0 ergeben, nicht None"


def test_ENDE_ZU_ENDE_ein_echter_abbruch_mit_langem_grund(tmp_path):
    """DER GATE-META-TEST, mit echtem pytest statt mit Textattrappen — so ist der Fund entstanden.

    Ein conftest setzt `session.shouldstop` auf einen langen Grund. pytest bricht dann NACH dem
    ersten roten Test ab, schreibt ein Banner mit genau EINEM Ausrufezeichen je Seite und trotzdem
    eine Bilanzzeile. Vor der Haertung las das Tor daraus 1 und haette die Mutante bei Basislinie 0
    als GETOETET verbucht.
    """
    m = _mutation_check_modul()
    baum = _mini_baum(tmp_path, "test_bricht_mit_langem_grund_ab.py",
                      "def test_eins():\n    assert True\n\n\n"
                      "def test_zwei():\n    assert False\n\n\n"
                      "def test_drei():\n    assert True\n")
    (baum / "conftest.py").write_text(
        "def pytest_runtest_protocol(item, nextitem):\n"
        "    if item.name == 'test_zwei':\n"
        "        item.session.shouldstop = (\n"
        "            'abgebrochen, weil der Mutant die Umgebung unbrauchbar gemacht hat und ein '\n"
        "            'Weiterlaufen keine Aussage mehr traegt')\n"
        "    return None\n", encoding="utf-8")
    rot = m._red_count(baum)
    assert rot is None, (
        f"Der abgebrochene Lauf liefert {rot} statt None. Das Banner traegt bei diesem Grund nur "
        f"EIN Ausrufezeichen — eine Fuellbreite ist keine Eigenschaft des Abbruchs, und genau "
        f"deshalb entscheidet jetzt der Rueckgabewert.")


def test_JEDER_der_zwei_riegel_wird_von_MINDESTENS_einer_zusicherung_einzeln_gehalten(tmp_path):
    """DER FANGNACHWEIS ALS ZUSICHERUNG — die Lehre der un-Gegenlesung, ausfuehrbar festgehalten.

    Zwei Riegel entscheiden hier dasselbe: der Rueckgabewert und die Bannerform. Wer nur PRUEFT,
    dass ein Abbruch NICHT MESSBAR ergibt, prueft die ODER-Verknuepfung — und merkt nicht, wenn
    einer der beiden verschwindet. Genau das war der Fund: mein Fangnachweis nahm beide zugleich
    zurueck, alle Faelle fielen, und die Ableitung "also binden sie den Fix" war falsch.

    Dieser Fall nimmt JEDEN Riegel EINZELN zurueck (an einer Kopie des Moduls im Speicher, das
    Original bleibt unberuehrt) und verlangt, dass fuer jeden mindestens eine Konstellation die
    Roete verliert. Faellt er, ist ein Riegel ungehalten geworden und kann still entfernt werden.
    """
    m = _mutation_check_modul()
    ohne_banner = "1 failed, 1 passed in 0.14s\n"
    schmal = ("! _pytest.outcomes.Exit: abgebrochen, weil der Mutant die Umgebung unbrauchbar "
              "gemacht hat und nichts mehr messbar ist !\n1 failed, 1 passed in 0.14s\n")
    leer = tmp_path / "kein_bericht.xml"

    # Beide da: beide Konstellationen sind NICHT MESSBAR.
    assert m._rote_aus_lauf(leer, ohne_banner, 2) is None, "Vorbedingung: rc faengt den Fall ohne Banner"
    assert m._rote_aus_lauf(leer, schmal, 1) is None, "Vorbedingung: die Form faengt das schmale Banner"

    # (a) NUR den Rueckgabewert-Riegel zuruecknehmen -> der Fall ohne Banner muss die Roete sehen.
    original_rcs = m._RC_NICHT_MESSBAR
    try:
        m._RC_NICHT_MESSBAR = frozenset()
        assert m._rote_aus_lauf(leer, ohne_banner, 2) == 1, (
            "Ohne den Rueckgabewert-Riegel bleibt der Fall ohne Bannerzeile trotzdem NICHT MESSBAR "
            "— dann haelt ihn etwas anderes, und keine Zusicherung bindet ihn.")
    finally:
        m._RC_NICHT_MESSBAR = original_rcs

    # (b) NUR die Bannerform zuruecknehmen (zurueck auf `!{5,}`) -> das schmale Banner muss durch.
    import re as _re                                        # noqa: PLC0415
    original_muster = m._ABBRUCH_BANNER
    try:
        m._ABBRUCH_BANNER = _re.compile(r"^!{5,} .* !{5,}$", _re.M)
        assert m._rote_aus_lauf(leer, schmal, 1) == 1, (
            "Mit der alten `!{5,}`-Form bleibt das schmale Banner trotzdem NICHT MESSBAR — dann "
            "haelt es etwas anderes, und die Weitung auf `!+` ist von keiner Zusicherung gebunden.")
    finally:
        m._ABBRUCH_BANNER = original_muster

    # Und zurueck: der Zustand des Moduls darf dieser Fall nicht hinterlassen.
    assert m._rote_aus_lauf(leer, ohne_banner, 2) is None and m._rote_aus_lauf(leer, schmal, 1) is None


def test_der_RUECKGABEWERT_schlaegt_den_BERICHT_und_das_ist_die_ganze_pointe(tmp_path):
    """DIE PRAEZEDENZ SELBST ALS ZUSICHERUNG — gefunden von Linse B der Verify-Lane, 07.09.2026.

    `_rote_aus_lauf` verspricht in seinem Docstring eine Reihenfolge: RUECKGABEWERT zuerst, dann die
    strukturierte Quelle, dann der Text. GEMESSEN: kein Fall band diese Reihenfolge. Verschiebt man
    den rc-Zweig hinter `_rote_aus_bericht` und macht ihn zum blossen Rueckfall, bleiben alle 45
    Faelle der Datei GRUEN — weil keiner von ihnen gleichzeitig einen ECHTEN, nicht-leeren Bericht
    UND ein rc aus der Nicht-Messbar-Menge liefert. Die vorhandenen Faelle benutzen dafuer einen
    nicht existierenden Berichtspfad, wo `_rote_aus_bericht` ohnehin None gibt; die Reihenfolge
    konnte sich dort nicht auswirken.

    WARUM DAS TRAEGT UND NICHT NUR ORDENTLICH IST (Linse A, gemessen mit echtem pytest): die
    JUnit-XML eines ABGEBROCHENEN Laufs ist wohlgeformt und traegt eine plausible Zahl —
    `tests="2" failures="1" errors="0"` fuer einen Lauf, der seinen dritten Test nie fuhr. Die
    strukturierte Quelle sagt NICHT, dass der Lauf abbrach; sie kann es gar nicht sagen. Der
    Rueckgabewert ist das einzige Feld im ganzen Bild, das es sagt. Steht der Bericht davor, liest
    das Tor die Teilzahl und verbucht bei Basislinie 0 eine KILLED-Mutante.

    DIESELBE KLASSE WIE ZWEIMAL ZUVOR AN DIESEM ABEND, jetzt in ihrer dritten Gestalt: nicht die
    Ruecknahme eines Riegels blieb ungeprueft, sondern ihr ZUSAMMENSPIEL. Ein Riegel kann
    vorhanden, wirksam und trotzdem an der falschen Stelle sein.
    """
    m = _mutation_check_modul()
    bericht = tmp_path / "abgebrochener_lauf.xml"
    # Genau die Form, die Linse A aus einem echten Abbruch gemessen hat.
    bericht.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
        'errors="0" failures="1" skipped="0" tests="2" time="0.15"/></testsuites>',
        encoding="utf-8")
    # Der Text traegt WEDER ein Banner NOCH INTERNALERROR NOCH eine zaehlbare Bilanz. Die letzte
    # Eigenschaft kam aus der un-Gegenlesung (2026-09-07, Runde 2) und ist der Unterschied zwischen
    # einer Gegenprobe und einer scheinbaren: mit "1 failed, 1 passed" haette die Gegenprobe unten
    # auch bei einem KAPUTTEN `_rote_aus_bericht` bestanden, weil `_rote_aus_text` dieselbe 1 aus
    # der Bilanzzeile liest. Sie haette dann bewiesen, dass IRGENDEINE Quelle 1 liefert — nicht,
    # dass der BERICHT es tut. Ohne Bilanzzeile kann die 1 nur aus dem Bericht kommen.
    text = "collected 2 items\n"

    assert m._rote_aus_bericht(bericht) == 1, (
        "Vorbedingung: der Bericht traegt eine ZAEHLBARE Zahl. Ohne sie prueft dieser Fall die "
        "Praezedenz nicht, sondern nur, dass irgendetwas None ergibt.")
    assert m._rote_aus_lauf(bericht, text, 2) is None, (
        "Der BERICHT hat den Rueckgabewert ueberstimmt. Ein abgebrochener Lauf hinterlaesst eine "
        "wohlgeformte JUnit-XML mit einer Teilzahl; nur der Rueckgabewert sagt, dass sie eine "
        "Teilzahl IST. Steht die strukturierte Quelle davor, verbucht `killed = red > baseline` "
        "bei Basislinie 0 eine gefangene Mutante fuer einen Lauf, der nie zu Ende kam.")

    # GEGENPROBE, sonst bestuende der Fall auch bei einem `_rote_aus_lauf`, das immer None gibt:
    # derselbe Bericht mit einem Rueckgabewert eines VOLLSTAENDIGEN Laufs muss die Zahl liefern.
    assert m._rote_aus_text(text) is None, (
        "Vorbedingung der Gegenprobe: der Text traegt KEINE zaehlbare Bilanz. Traegt er eine, kann "
        "die Zahl unten aus ihm statt aus dem Bericht kommen, und die Gegenprobe isoliert nichts.")
    assert m._rote_aus_lauf(bericht, text, 1) == 1, (
        "Mit rc=1 (Tests rot, Lauf zu Ende) muss der BERICHT zaehlen — und nur er kann es hier, "
        "weil der Text nichts Zaehlbares traegt. Sonst waere der Riegel oben kein Vorrang, sondern "
        "ein Dauer-Nichtmessbar.")
