"""Ein Modul, dessen Import an einer nicht ausgelieferten Datei scheitert, darf das SAMMELN nicht
abbrechen — sondern muss sich ehrlich als SKIP melden.

HERKUNFT: deep gate Lauf 5 auf dem 6.0.0-Kandidaten (2026-09-08), Fund `L6-600-01` /
`L3-600-SDIST-COLLECT-01`, P0, von zwei unabhaengigen Linsen gefunden, Jury 3/3. Unabhaengig
belegt vom CI-Job selbst: `published-artifact-gate / hermetic-cleanroom` brach an PR 194 mit
`FileNotFoundError: /tmp/sdisttree/scripts/budget_axis_measurement.py` und `exit code 2` ab.

DER VORGANG. `scripts/budget_axis_measurement.py` verliess die Auslieferungsliste in MANIFEST.in
(Owner-Entscheid zu `OA-dc37e26295`); `tests/test_budget_axis_measurement.py` blieb ausgeliefert
und laedt das Skript auf MODULEBENE. `pytest tests/` im entpackten sdist endet damit auf
`Interrupted: 1 error during collection` — und es laeuft NULL, auch keiner der 3935 anderen Tests.
`conftest.pytest_collection_modifyitems` kann das nicht auffangen: der Hook laeuft NACH dem Import.

DIE KLASSE STAND SEIT DEM 2026-09-07 WOERTLICH IM BAUM.
`tests/test_paketgrenze_zahlen_sind_abgeleitet.py::_wegwerfbaum` beschreibt genau diesen
Mechanismus an zwei anderen Modulen — und heilte ihn durch Mitkopieren der zwei Skripte, also als
Eigenschaft des MESSAUFBAUS statt als Defekt der PAKETINVARIANTE. Einen Tag spaeter war dieselbe
Luecke ein Release-Blocker. Eine beschriebene Klasse ist keine geschlossene Klasse.

WARUM DIESE DATEI SO VIELE FORM-FAELLE FUEHRT. Die erste Fassung des Fixes fragte den Syntaxbaum
("nennt das Modul auf Modulebene einen Pfad, den es hier nicht gibt?"). Eine adversariale
Gegenlesung hat sie mit fuenf ausgefuehrten Faellen widerlegt, alle Rueckgabewert 2: variables
Segment, `os.path.join`, `joinpath`, eine Wurzel aus `Path.cwd()`, und der Zugriff in einem
importierten NACHBARMODUL. Alle fuenf sind semantisch dasselbe und syntaktisch etwas anderes.
Sie stehen hier als Faelle, damit die Rueckkehr zu einer Form-Erkennung sofort auffaellt.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFTEST = REPO / "tests" / "conftest.py"

#: Die fuenf Schreibweisen, die dieselbe Wirkung haben. Schluessel = Name, Wert = Modulquelle.
#: Der Pfad `scripts/fehlt.py` existiert in keinem Wegwerfbaum.
_FORMEN = {
    "konstante_kette": '''\
import importlib.util
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_fehlt", REPO / "scripts" / "fehlt.py")
importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(importlib.util.module_from_spec(_spec))


def test_a():
    assert True
''',
    "variables_segment": '''\
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
teil = "scripts"
INHALT = (REPO / teil / "fehlt.py").read_text()


def test_b():
    assert INHALT
''',
    "os_path_join": '''\
import os
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
INHALT = open(os.path.join(str(REPO), "scripts", "fehlt.py")).read()


def test_c():
    assert INHALT
''',
    "joinpath": '''\
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
INHALT = REPO.joinpath("scripts", "fehlt.py").read_text()


def test_d():
    assert INHALT
''',
    # Die zwei Formen, die eine Gegenlesung an der VERWORFENEN, statischen Vorfassung gefunden hat.
    # Sie stehen hier, weil sie beide gewoehnlich sind und beide an einer Form-Erkennung vorbeigehen:
    # ein Lade-Helfer, der im FUNKTIONSKOERPER zusammensetzt und sofort auf Modulebene gerufen wird
    # (so laedt `tests/test_audit_marker_line_wrap.py` sein Skript), und ein Pfad, der vor dem Lesen
    # in einer Variablen zwischengespeichert wird.
    "helfer_auf_modulebene": '''\
import importlib.util
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]


def _lade(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


TOR = _lade("tor", "scripts/fehlt.py")


def test_k():
    assert TOR
''',
    "pfad_in_variable": '''\
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
_voll = REPO / "scripts" / "fehlt.py"
if _voll.is_file():
    pass
INHALT = _voll.read_text()


def test_l():
    assert INHALT
''',
    "wurzel_aus_cwd": '''\
from pathlib import Path
basis = Path.cwd()
INHALT = (basis / "scripts" / "fehlt.py").read_text()


def test_e():
    assert INHALT
''',
}

#: Der sechste Fall: der Zugriff steht gar nicht im Testmodul, sondern im Nachbarmodul.
_NACHBAR_TEST = '''\
from helfer import INHALT


def test_f():
    assert INHALT
'''
_NACHBAR_HELFER = '''\
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
INHALT = (REPO / "scripts" / "fehlt.py").read_text()
'''

#: Ein Modul, das sich selbst absichert — das Muster, das der Riegel erreichen will.
#:
#: MIT `pytest.mark.skipif`, NICHT mit `unittest.skipUnless`, und der Grund gehoert hierher: die
#: erste Fassung schrieb `import unittest` in diese Vorlage. Das ist ein STRING, kein Import — aber
#: `scripts/test_manifest_gate.py` leitet die pytest-only-Menge zweimal ab, einmal ueber den TEXT
#: und einmal ueber den SYNTAXBAUM, und verlangt Einigkeit. Der Text sah `import unittest` und hielt
#: dieses Modul fuer ein unittest-Modul, der Syntaxbaum sah keinen Import. Das Tor meldete die
#: Uneinigkeit — richtig, denn der Syntaxbaum hat recht: diese Datei IST pytest-only.
#:
#: Die Vorlage auf `skipif` umzustellen ist keine Umgehung des Melders, sondern bringt die
#: ERSCHEINUNG mit der Sache in Deckung. Die gepruefte Eigenschaft aendert sich nicht: ein Modul,
#: das seine nicht ausgelieferte Datei mit einer Existenzprobe absichert, importiert sauber und
#: ueberspringt ehrlich. Dass die schwaechere der beiden Ableitungen sich von einem Zeichenketten-
#: Inhalt taeuschen laesst, ist als eigener Befund festgehalten und NICHT hier geheilt.
_SICHERT_SICH_AB = '''\
import pytest
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not (REPO / "scripts" / "fehlt.py").is_file(), reason="nicht ausgeliefert")
def test_g():
    assert True
'''

#: Ein Importfehler EINER ANDEREN KLASSE — ein fehlendes Paket. Er soll NICHT weggeraeumt werden.
_FEHLENDES_PAKET = '''\
import ganz_sicher_kein_paket_xyz123  # noqa: F401


def test_h():
    assert True
'''


def _conftest_modul(pfad: Path = CONFTEST):
    spec = importlib.util.spec_from_file_location(f"_cf_{abs(hash(str(pfad)))}", pfad)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


#: Die Dateiliste, die eine Verteilung von sich selbst mitbringt (`*.egg-info/SOURCES.txt`).
#: `scripts/fehlt.py` steht NICHT darin — seine Abwesenheit ist Absicht.
#: `tests/fixtures/fehlt.json` steht darin; seine Abwesenheit ist ein Paketierungsfehler.
#:
#: NICHT `MANIFEST.in`, und das ist der Unterschied, auf den eine fremdfamiliaere Gegenlesung
#: gezeigt hat: MANIFEST.in ist eine DEKLARATION, die endgueltige Liste berechnet setuptools daraus
#: plus Vorgaben — und die beiden sind an genau dieser Stelle schon einmal auseinandergelaufen
#: (Restrisiko S27, gemessen 2026-09-08). SOURCES.txt IST das Ergebnis der Rechnung.
_SOURCES = ("MANIFEST.in\n"
            "tests/conftest.py\n"
            "tests/fixtures/fehlt.json\n"
            "scripts/mutation_check.py\n")


def _baum(ziel: Path, module: dict[str, str], *, mit_conftest: bool = True,
          mit_dateiliste: bool = True) -> Path:
    """Ein Baum OHNE Repo-Marker — genau die Lage, in der eine entpackte sdist laeuft."""
    (ziel / "tests").mkdir(parents=True)
    if mit_dateiliste:
        (ziel / "src" / "beispiel.egg-info").mkdir(parents=True)
        (ziel / "src" / "beispiel.egg-info" / "SOURCES.txt").write_text(_SOURCES, encoding="utf-8")
    if mit_conftest:
        shutil.copy2(CONFTEST, ziel / "tests" / "conftest.py")
    for name, quelle in module.items():
        (ziel / "tests" / f"{name}.py").write_text(quelle, encoding="utf-8")
    assert not any((ziel / marker).exists()
                   for marker in _conftest_modul()._REPO_ONLY_MARKERS), \
        "Vorbedingung: der Wegwerfbaum darf keinen Repo-Marker tragen"
    return ziel


def _lauf(baum: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "-rs", "-p", "no:cacheprovider",
         "-p", "no:randomly"],
        cwd=str(baum), capture_output=True, text=True, timeout=600,
        env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin:/usr/local/bin",
             "HOME": str(Path.home())})


def test_OHNE_den_riegel_bricht_das_sammeln_ab(tmp_path):
    """DER FANGNACHWEIS, und er geht den PFAD statt den Zustand zu stellen.

    Derselbe Baum ohne `conftest.py`: nichts entscheidet vor dem Import, der Lauf endet mit
    Rueckgabewert 2 und `errors during collection` — die Form, in der der CI-Job am Kandidatenkopf
    stand. Ohne diesen Fall bestuenden die folgenden auch dann, wenn der Riegel gar nichts taete.
    """
    baum = _baum(tmp_path / "ohne", {"test_x": _FORMEN["konstante_kette"]}, mit_conftest=False)
    proc = _lauf(baum)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode == 2, (
        f"Ohne den Riegel muesste das Sammeln mit 2 abbrechen, es endete mit {proc.returncode}. "
        f"Dann messen die Faelle unten nichts.\n{ausgabe[-800:]}")
    assert "error" in ausgabe.lower() and "collection" in ausgabe.lower(), ausgabe[-800:]


def test_JEDE_form_desselben_zugriffs_wird_zu_einem_ehrlichen_SKIP(tmp_path):
    """DIE ZUSICHERUNG, und sie ist ueber die FORMEN parametrisiert statt an einer zu haengen.

    Alle acht Module scheitern beim Import an derselben fehlenden Datei, in acht verschiedenen
    Schreibweisen. Eine Form-Erkennung faengt hoechstens die erste; eine Wirkungs-Erkennung faengt
    alle. Genau diese Differenz hat die Gegenlesung an der ersten Fassung ausgefuehrt.
    """
    module = {f"test_{name}": quelle for name, quelle in _FORMEN.items()}
    module["test_nachbar"] = _NACHBAR_TEST
    module["test_lauffaehig"] = "def test_z():\n    assert True\n"
    baum = _baum(tmp_path / "formen", module)
    (baum / "tests" / "helfer.py").write_text(_NACHBAR_HELFER, encoding="utf-8")

    proc = _lauf(baum)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode == 0, (
        f"Das Sammeln bricht ab: Rueckgabewert {proc.returncode}. Im ausgelieferten sdist heisst "
        f"das, dass KEIN einziger Test laeuft.\n{ausgabe[-1500:]}")
    assert "8 skipped" in ausgabe, (
        f"Nicht alle acht Formen wurden zu einem SKIP. Faengt der Riegel nur einen Teil, bricht "
        f"der Rest weiterhin die Sammlung ab.\n{ausgabe[-1500:]}")
    assert "1 passed" in ausgabe, (
        f"Der lauffaehige Fall laeuft nicht mit. Ein Riegel, der die ganze Sammlung leert, hat den "
        f"Abbruch nur leiser gemacht.\n{ausgabe[-800:]}")


def test_das_ueberspringen_nennt_die_fehlende_datei(tmp_path):
    """Ein `1 skipped` ohne seinen Grund ist eine Zahl, die alles heissen kann.

    Die erste Fassung dieser Meldung hing an `pytest_report_header` — der laeuft VOR dem Sammeln,
    die Menge war dort immer leer, und es erschien keine Zeile. Gemessen an der Ausgabe des
    entpackten sdist: keine einzige. Deshalb wird hier die AUSGABE geprueft.
    """
    baum = _baum(tmp_path / "meldung", {"test_x": _FORMEN["konstante_kette"],
                                        "test_lauffaehig": "def test_z():\n    assert True\n"})
    ausgabe = _lauf(baum).stdout
    assert "beim Import uebersprungen" in ausgabe and "test_x.py" in ausgabe, (
        f"Das Ueberspringen erscheint nicht in der Zusammenfassung. Dann faellt ein Modul lautlos "
        f"aus der Suite, und die Ausgabe liest sich als vollstaendiger Lauf.\n{ausgabe[-1200:]}")
    assert "fehlt.py" in ausgabe, (
        "Die Meldung nennt die fehlende Datei nicht — dann steht ein Ueberspringen ohne seinen "
        "Grund da, und wer es liest, muss den Lauf nachbauen, um zu erfahren, WAS fehlt.")


_IMPORT_FORM = '''\
from scripts.nicht_ausgeliefert import etwas  # noqa: F401


def test_import_form():
    assert etwas
'''

#: Ein Modul, das ein SYMBOL aus einer VORHANDENEN, ausgelieferten Datei importiert, das es dort
#: nicht gibt. Python wirft dafuer ein gewoehnliches ImportError ("cannot import name") mit
#: `.name` = dem MODULnamen — die Datei ist da, der Fehler ist ein Programmierfehler.
_SYMBOL_FEHLT = '''\
from scripts.mutation_check import nichtvorhanden  # noqa: F401


def test_symbol():
    assert nichtvorhanden
'''

#: Ein Modul, das seinen Importfehler SELBST in eine andere Klasse uebersetzt. Es hat damit etwas
#: anderes gesagt als "diese Datei fehlt" — und darf deshalb nicht als "nicht ausgeliefert" gelten.
_UEBERSETZT_SELBST = '''\
try:
    from scripts.nicht_ausgeliefert import etwas  # noqa: F401
except ImportError as e:
    raise RuntimeError("KONFIGURATION KAPUTT: Pflichtmodul fehlt") from e


def test_uebersetzt():
    assert etwas
'''

_IMPORT_GELISTET = '''\
from scripts.mutation_check import etwas  # noqa: F401


def test_import_gelistet():
    assert etwas
'''


def test_die_IMPORT_form_wird_EBENSO_zu_einem_ehrlichen_SKIP(tmp_path):
    """DER ZWEITE ZUGRIFFSWEG, und er war beim ersten Fix offen.

    GEMESSEN 08.09.2026 gegen die Fassung davor, ein Baum, eine fehlende Datei:
      `Path.read_text`                  -> 1 skipped, der Riegel griff
      `from scripts.X import ...`       -> Interrupted: 1 error during collection
    Also genau der P0, den der Riegel schliessen sollte, in der anderen Schreibweise. Grund war
    `except FileNotFoundError`: `ModuleNotFoundError` erbt von `ImportError`, nicht von `OSError`.

    Zwei Claude-Linsen fanden das unabhaengig. Der Fall haelt es fest, damit die Fehlerklasse nie
    wieder als Stellvertreter fuer die Wirkung durchgeht."""
    baum = _baum(tmp_path / "importform", {"test_import": _IMPORT_FORM,
                                           "test_lauffaehig": "def test_z():\n    assert True\n"})
    (baum / "scripts").mkdir()
    (baum / "scripts" / "mutation_check.py").write_text("etwas = 1\n", encoding="utf-8")
    r = _lauf(baum)
    assert r.returncode == 0, (
        "der Import einer nicht ausgelieferten Datei bricht das Sammeln weiter ab:\n"
        + r.stdout[-2500:])
    assert "1 skipped" in r.stdout, r.stdout[-2500:]
    assert "nicht ausgeliefert" in r.stdout, r.stdout[-2500:]


def test_die_URSACHENKETTE_wird_durch_PYTESTS_EIGENE_verpackung_abgegangen(tmp_path):
    """WARUM DIE KETTE UND NICHT DIE AEUSSERSTE AUSNAHME (gemessen im selben Zug):

    pytest REICHT einen `FileNotFoundError` aus dem Modulimport durch, VERPACKT einen
    `ImportError` aber in seine eigene Sammelmeldung. Die erste Fassung des Fixes las
    `fehler.name` der aeussersten Ausnahme — und sah beim Import-Fall nichts, obwohl sie
    `ModuleNotFoundError` ausdruecklich behandeln wollte. Die Wirkung stand in der Ursachenkette.

    DIESE FASSUNG VERPACKT MIT PYTESTS ECHTER KLASSE, nicht mit irgendeiner. Die erste Fassung
    dieses Falls nahm `RuntimeError` als Platzhalter fuer "verpackt" — und wurde damit zum
    Gegenteil ihrer Absicht: sie verlangte, dass eine FREMDE Uebersetzung durchgelassen wird.
    Genau das hat eine Gegenlesung als schlimmer als die Ausgangsluecke gemessen (der echte
    Grund verschwindet hinter einem freundlichen SKIP), und der Fix laesst es seither NICHT
    mehr durch. Der Fall lief deshalb rot, sobald die Korrektur im Baum lag — er hielt das
    alte Verhalten fest. Die Gegenrichtung steht direkt darunter.

    Dass pytest im ECHTEN Lauf wirklich so verpackt, belegt nicht dieser Fall, sondern
    `test_die_IMPORT_form_wird_EBENSO_zu_einem_ehrlichen_SKIP`: der geht den vollen Pfad durch
    einen echten pytest-Lauf und waere ohne die Kettenverfolgung rot."""
    from _pytest.nodes import Collector    # pytests eigene Sammelmeldung

    # Vorbedingung: nur DAFUER gibt es die Ausnahme in der Kettenregel. Waere die Klasse selbst
    # ein ImportError, traege sie den Grund schon und der Fall pruefte nichts Eigenes.
    assert Collector.CollectError.__module__.startswith("_pytest."), Collector.CollectError
    assert not issubclass(Collector.CollectError, (ImportError, OSError))

    cf = _conftest_modul()
    baum = _baum(tmp_path / "kette", {})
    (baum / "scripts").mkdir()
    (baum / "scripts" / "mutation_check.py").write_text("x = 1\n", encoding="utf-8")

    innen = ModuleNotFoundError("No module named 'scripts.nicht_ausgeliefert'")
    innen.name = "scripts.nicht_ausgeliefert"
    try:
        try:
            raise innen
        except ModuleNotFoundError as e:
            raise Collector.CollectError("ImportError while importing test module") from e
    except Collector.CollectError as verpackt:
        gefunden = cf._fehlende_datei_aus(verpackt, baum)

    assert gefunden is not None, (
        "die von pytest verpackte Ausnahme wird nicht gefunden — die Kettenverfolgung fehlt")
    assert gefunden.name == "nicht_ausgeliefert.py", gefunden


def test_eine_FREMDE_uebersetzung_wird_NICHT_durchgelassen(tmp_path):
    """DIE GEGENRICHTUNG, und sie ist die wichtigere Haelfte.

    GEMESSEN von einer Gegenlesung an der Zwischenfassung, die JEDES Glied der Kette annahm:
    ein Modul mit `except ImportError: raise RuntimeError("KONFIGURATION KAPUTT")` endete als
    `1 skipped: nicht ausgeliefert`. Die echte Meldung war weg. Das ist SCHLIMMER als die
    Ausgangsluecke, denn die war laut.

    Ein Modul, das seinen Importfehler in einen eigenen Fehler uebersetzt, hat damit etwas
    anderes gesagt — und das Gesagte gilt. Durchlaessig ist die Kette nur durch pytests eigene
    Verpackung."""
    cf = _conftest_modul()
    baum = _baum(tmp_path / "fremd", {})
    (baum / "scripts").mkdir()
    (baum / "scripts" / "mutation_check.py").write_text("x = 1\n", encoding="utf-8")

    innen = ModuleNotFoundError("No module named 'scripts.nicht_ausgeliefert'")
    innen.name = "scripts.nicht_ausgeliefert"
    try:
        try:
            raise innen
        except ModuleNotFoundError as e:
            raise RuntimeError("KONFIGURATION KAPUTT: Pflichtmodul fehlt") from e
    except RuntimeError as uebersetzt:
        gefunden = cf._fehlende_datei_aus(uebersetzt, baum)

    assert gefunden is None, (
        f"eine fremde Uebersetzung wird als 'nicht ausgeliefert' verbucht ({gefunden}) — dann "
        f"verschwindet jede Fehlklasse, die ein Modul selbst umbenennt, hinter einem SKIP")


def test_AUF_DEM_ECHTEN_PFAD_bleibt_eine_fremde_uebersetzung_laut(tmp_path):
    """Dieselbe Grenze, aber durch einen echten pytest-Lauf statt an der Hilfsfunktion.

    Ohne diesen Fall bindet nur die Innensicht: die Hilfsfunktion koennte richtig antworten und
    `collect()` sie trotzdem falsch verwenden. Hier zaehlt allein, was am Ende in der Ausgabe
    steht."""
    baum = _baum(tmp_path / "fremd_e2e", {"test_uebersetzt": _UEBERSETZT_SELBST,
                                          "test_lauffaehig": "def test_z():\n    assert True\n"})
    (baum / "scripts").mkdir()
    (baum / "scripts" / "mutation_check.py").write_text("etwas = 1\n", encoding="utf-8")
    r = _lauf(baum)
    ausgabe = r.stdout + r.stderr
    assert r.returncode != 0, (
        f"ein Modul, das seinen Importfehler selbst uebersetzt, laeuft gruen durch "
        f"(Rueckgabewert {r.returncode}) — der Riegel raeumt eine fremde Fehlklasse weg:\n"
        + ausgabe[-1500:])
    assert "nicht ausgeliefert" not in ausgabe, (
        "der Lauf verbucht die fremde Uebersetzung als 'nicht ausgeliefert'. Dann steht ein "
        "freundlicher Grund da, wo der echte gestanden haette.\n" + ausgabe[-1500:])
    assert "KONFIGURATION KAPUTT" in ausgabe, (
        "die eigene Meldung des Moduls erscheint nicht mehr — genau der Verlust, gegen den die "
        "Kettenregel steht.\n" + ausgabe[-1500:])


def test_ein_FEHLENDES_SYMBOL_in_einer_VORHANDENEN_datei_bleibt_laut(tmp_path):
    """DER FUND EINER GEGENLESUNG, 08.09.2026, an einem echten pytest-Subprozess gemessen.

    `from scripts.mutation_check import nichtvorhanden`, wobei die Datei EXISTIERT und in der
    Dateiliste der Verteilung steht — nur das Symbol fehlt. Das ist ein gewoehnliches ImportError
    mit `.name` = dem Modulnamen, also ein Programmierfehler und keine Paketierungsluecke.

    Die erste Fassung des Riegels pruefte die zwei Modulformen EINZELN und sprang bei einer
    vorhandenen mit `continue` zur naechsten: `scripts/mutation_check.py` war da, also weiter zu
    `scripts/mutation_check/__init__.py` — das gab es nie, `scripts/` ist der Verteilung aber
    bekannt, und der Riegel meldete einen erfundenen Pfad als fehlende Datei. Der Lauf endete mit
    `1 passed, 1 skipped` und einer freundlichen Begruendung. Ein entferntes oder umbenanntes
    Symbol waere damit als ehrlicher SKIP getarnt worden.

    Die zwei Formen beschreiben EIN Modul: existiert eine, ist das Modul da."""
    baum = _baum(tmp_path / "symbol", {"test_symbol": _SYMBOL_FEHLT,
                                       "test_lauffaehig": "def test_z():\n    assert True\n"})
    (baum / "scripts").mkdir()
    (baum / "scripts" / "mutation_check.py").write_text("etwas = 1\n", encoding="utf-8")
    r = _lauf(baum)
    ausgabe = r.stdout + r.stderr
    assert r.returncode != 0, (
        f"ein fehlendes SYMBOL in einer vorhandenen Datei laeuft gruen durch (Rueckgabewert "
        f"{r.returncode}) — der Riegel tarnt einen Programmierfehler als Paketierungsluecke:\n"
        + ausgabe[-1500:])
    assert "nicht ausgeliefert" not in ausgabe, (
        "der Lauf verbucht das fehlende Symbol als 'nicht ausgeliefert' und nennt dabei einen "
        "Pfad, den es nie gab.\n" + ausgabe[-1500:])


def test_ein_vorhandenes_NAMESPACE_PAKET_gilt_als_vorhanden(tmp_path):
    """DER FUND EINER FREMDFAMILIAEREN GEGENLESUNG (qwen, 08.09.2026), und er ist der NACHBAR des
    Symbol-Falls darueber: dieselbe verletzte Annahme, anderer Zugang.

    Seit Python 3.3 ist ein Verzeichnis OHNE `__init__.py` ein gueltiges Paket. Dieser Baum fuehrt
    zehn davon (`scripts/`, `tests/`, `conformance/`, `tools/…`). Die Formenliste des Riegels
    kannte nur `pkg.py` und `pkg/__init__.py` — ein vorhandenes Namespace-Paket erfuellte keine von
    beiden, und der Riegel meldete `pkg/__init__.py` als fehlend.

    GEMESSEN an einem gebauten Fall: bei VORHANDENEM `scripts/` und bei GANZ FEHLENDEM `scripts/`
    gab er dieselbe Antwort. Er konnte die zwei Lagen nicht unterscheiden — und im ersten Fall war
    sie falsch.

    Die Aufzaehlung war selbst der Fehler: gefragt ist, ob das Modul in IRGENDEINER Form existiert,
    und darauf antwortet auch ein Verzeichnis mit Ja."""
    cf = _conftest_modul()
    baum = _baum(tmp_path / "namespace", {})
    (baum / "scripts").mkdir()                       # Namespace-Paket: KEIN __init__.py
    (baum / "scripts" / "mutation_check.py").write_text("x = 1\n", encoding="utf-8")

    vorbedingung = not (baum / "scripts" / "__init__.py").exists()
    assert vorbedingung, "Vorbedingung: das Paket darf kein __init__.py haben"

    f = ModuleNotFoundError("No module named 'scripts'")
    f.name = "scripts"
    assert cf._fehlende_datei_aus(f, baum) is None, (
        "ein VORHANDENES Namespace-Paket wird als fehlende Datei gemeldet — der Riegel nennt "
        "scripts/__init__.py, das ein Namespace-Paket nie hat")

    # Die Gegenrichtung im selben Fall: fehlt das Verzeichnis WIRKLICH, muss er es weiterhin sagen.
    import shutil
    shutil.rmtree(baum / "scripts")
    gefunden = cf._fehlende_datei_aus(f, baum)
    assert gefunden is not None, (
        "ein wirklich fehlendes, aber der Verteilung bekanntes Paket wird nicht mehr gemeldet — "
        "dann hat die Erweiterung den Riegel entschaerft statt geschaerft")


def test_ANTI_PARITAET_ein_import_eines_AUSGELIEFERTEN_moduls_bleibt_ein_fehler(tmp_path):
    """Die Gegenrichtung auf dem IMPORT-Weg, gespiegelt zum Dateizugriff-Fall.

    `scripts/mutation_check.py` steht in der Dateiliste. Fehlt es trotzdem, ist das ein
    Paketierungsfehler und muss laut bleiben — sonst haette der Riegel gegen den Sammelabbruch
    den Riegel gegen falsche Paketierung entwaffnet."""
    baum = _baum(tmp_path / "gelistet", {"test_gelistet": _IMPORT_GELISTET})
    (baum / "scripts").mkdir()
    (baum / "scripts" / "andere.py").write_text("x = 1\n", encoding="utf-8")
    r = _lauf(baum)
    assert r.returncode != 0, (
        "eine Datei, die die Verteilung FUEHRT, fehlt — und der Lauf ist gruen:\n"
        + r.stdout[-2500:])


def test_ANTI_PARITAET_ein_fehlendes_PAKET_bleibt_ein_fehler(tmp_path):
    """DIE WICHTIGSTE GEGENRICHTUNG: der Riegel darf nicht jeden Importfehler wegraeumen.

    Ein fehlendes Paket ist eine ANDERE Klasse — dagegen steht der `[test]`-Extra der Auslieferung,
    nicht dieser Riegel. Wuerde er auch das ueberspringen, verwandelte er eine kaputte
    Abhaengigkeitsliste in eine stille, gruen aussehende Suite: der stumme Riegel selbst.
    """
    baum = _baum(tmp_path / "paket", {"test_paket": _FEHLENDES_PAKET})
    proc = _lauf(baum)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode != 0, (
        f"Ein fehlendes PAKET wird weggeraeumt (Rueckgabewert {proc.returncode}). Dann meldet eine "
        f"Suite mit kaputter Abhaengigkeitsliste einen sauberen Lauf.\n{ausgabe[-800:]}")
    assert "beim Import uebersprungen" not in ausgabe, (
        "Der Riegel hat einen fehlenden Paket-Import als 'nicht ausgeliefert' verbucht. Das ist "
        "die falsche Klasse; der Dateiname des Fehlers liegt gar nicht in diesem Baum.")


def test_ANTI_PARITAET_ein_modul_das_sich_selbst_absichert_laeuft_normal(tmp_path):
    """`skipUnless((REPO / "…").is_file(), …)` ist die LOESUNG: das Modul importiert sauber und
    ueberspringt ehrlich. Es darf nicht in den Riegel geraten, sondern muss den vorhandenen,
    abgeleiteten Weg gehen — erkennbar an dessen Kennung im Grund."""
    baum = _baum(tmp_path / "abgesichert", {"test_sicher": _SICHERT_SICH_AB})
    proc = _lauf(baum)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode == 0 and "1 skipped" in ausgabe, ausgabe[-800:]
    assert "beim Import uebersprungen" not in ausgabe, (
        "Ein Modul, das sauber importiert, landet im Import-Riegel. Dann bestraft der Riegel genau "
        "das Muster, das er erreichen will.")


def test_im_checkout_ist_der_riegel_ein_reiner_NOOP(tmp_path):
    """Im Checkout darf nichts weggeraeumt werden — dort ist eine fehlende Datei der Fehler des
    Autors und soll beim Sammeln knallen."""
    baum = _baum(tmp_path / "checkout", {"test_x": _FORMEN["konstante_kette"]})
    (baum / "SPEC.md").write_text("Marker\n", encoding="utf-8")   # jetzt ist es ein Checkout
    m = _conftest_modul(baum / "tests" / "conftest.py")
    assert m.running_in_repo_checkout(), "Vorbedingung: der Baum muss als Checkout gelten"
    assert m.pytest_pycollect_makemodule(baum / "tests" / "test_x.py", None) is None, (
        "Der Riegel greift im Checkout. Dann verschwindet ein echter Fehler des Autors still aus "
        "der Suite, statt ihn beim Sammeln zu zeigen.")
    proc = _lauf(baum)
    assert proc.returncode == 2, (
        f"Im Checkout bricht das Sammeln NICHT ab (Rueckgabewert {proc.returncode}) — dann ist der "
        f"No-op keiner.\n{(proc.stdout + proc.stderr)[-800:]}")


def test_ein_fehler_AUSSERHALB_des_baums_bleibt_ein_fehler(tmp_path):
    """Die Abgrenzung der Klasse, an ihrer Grenze gemessen.

    Fehlt eine Datei ausserhalb dieses Baums, hat die Verteilung damit nichts zu tun — sie haette
    sie nie mitbringen koennen. Ohne diese Grenze wuerde der Riegel jeden `FileNotFoundError`
    ueberspringen, den ein Testmodul beim Import ausloest, egal woher.
    """
    fremd = tmp_path / "fremdes_verzeichnis" / "gibt_es_nicht.txt"
    quelle = f'INHALT = open({str(fremd)!r}).read()\n\n\ndef test_i():\n    assert INHALT\n'
    baum = _baum(tmp_path / "fremd", {"test_fremd": quelle})
    m = _conftest_modul(baum / "tests" / "conftest.py")
    assert not m._liegt_im_baum(str(fremd), baum), (
        "Ein Pfad ausserhalb des Baums gilt als 'im Baum'. Dann raeumt der Riegel Fehler weg, mit "
        "denen die Verteilung nichts zu tun hat.")
    proc = _lauf(baum)
    assert proc.returncode == 2, (
        f"Ein Fehler ausserhalb des Baums wird weggeraeumt (Rueckgabewert {proc.returncode}).\n"
        f"{(proc.stdout + proc.stderr)[-800:]}")


#: Ein Modul, dessen fehlende Datei MANIFEST.in AUSLIEFERN WUERDE — also ein Paketierungsfehler.
_BRAUCHT_EINE_AUSGELIEFERTE_DATEI = '''\
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
INHALT = (REPO / "tests" / "fixtures" / "fehlt.json").read_text()


def test_j():
    assert INHALT
'''


def test_ANTI_PARITAET_eine_datei_die_AUSGELIEFERT_werden_sollte_bleibt_ein_fehler(tmp_path):
    """DER FALL, OHNE DEN DIESER RIEGEL EINE VERSCHLECHTERUNG WAERE.

    `published-artifact-gate / hermetic-cleanroom` existiert, um zu finden, dass die
    AUSGELIEFERTEN Bytes kaputt sind. Wuerde jeder fehlende Pfad zu einem SKIP, dann waere
    "eine Fixture wurde versehentlich nicht mitgeliefert" ab sofort ein gruener Lauf mit einem
    Skip — der Riegel gegen den Sammelabbruch haette den Riegel gegen falsche Paketierung
    entwaffnet. Dieselbe Klasse, gegen die er steht, eine Ebene hoeher.

    Entscheidend ist deshalb `MANIFEST.in`, nicht meine Meinung: `tests/fixtures/fehlt.json` liegt
    unter `graft tests` und WAERE ausgeliefert. Seine Abwesenheit ist ein Fehler und bleibt laut.
    """
    baum = _baum(tmp_path / "paketfehler", {"test_fixture": _BRAUCHT_EINE_AUSGELIEFERTE_DATEI})
    m = _conftest_modul(baum / "tests" / "conftest.py")
    assert m._verteilung_sollte_enthalten("tests/fixtures/fehlt.json", baum), \
        "Vorbedingung: die Dateiliste muss diesen Pfad fuehren, sonst misst der Fall nichts"
    proc = _lauf(baum)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode == 2, (
        f"Eine Datei, die ausgeliefert werden SOLLTE, fehlt — und der Lauf ist trotzdem nicht rot "
        f"(Rueckgabewert {proc.returncode}). Dann meldet ein falsch gepacktes Artefakt einen "
        f"sauberen Lauf.\n{ausgabe[-1000:]}")
    assert "beim Import uebersprungen" not in ausgabe, (
        "Ein Paketierungsfehler wurde als 'nicht ausgeliefert' verbucht.")


def test_OHNE_dateiliste_gibt_der_riegel_NICHT_nach(tmp_path):
    """FAIL-CLOSED an der Grundlage selbst.

    Fehlt die Dateiliste der Verteilung, kann niemand entscheiden, ob eine Datei mitgeliefert
    werden sollte. Ein Riegel, der bei fehlender Grundlage nachgibt, ist keiner — er waere genau
    dann am weichsten, wenn am wenigsten bekannt ist.
    """
    baum = _baum(tmp_path / "ohne_liste", {"test_x": _FORMEN["konstante_kette"]},
                 mit_dateiliste=False)
    proc = _lauf(baum)
    assert proc.returncode == 2, (
        f"Ohne Dateiliste wird uebersprungen statt laut zu bleiben (Rueckgabewert "
        f"{proc.returncode}).\n{(proc.stdout + proc.stderr)[-800:]}")


def test_ANTI_PARITAET_eine_VORHANDENE_aber_unlesbare_datei_bleibt_ein_fehler(tmp_path):
    """Die Datei IST da — dann ist "diese Verteilung enthaelt das nicht" schlicht falsch.

    Eine adversariale Gegenlesung hat drei solche Faelle ausgefuehrt (`PermissionError`,
    `IsADirectoryError`, `NotADirectoryError`), und in allen dreien uebersprang die erste Fassung
    das Modul mit einer Meldung, die eine falsche Tatsachenbehauptung enthielt. Deshalb faengt der
    Riegel jetzt nur `FileNotFoundError` UND verlangt zusaetzlich, dass die Datei wirklich fehlt.
    """
    ziel = tmp_path / "unlesbar"
    baum = _baum(ziel, {"test_u": 'from pathlib import Path\n'
                                  'REPO = Path(__file__).resolve().parents[1]\n'
                                  'INHALT = (REPO / "scripts" / "gesperrt.bin").read_bytes()\n\n\n'
                                  'def test_u():\n    assert INHALT\n'})
    (baum / "scripts").mkdir()
    gesperrt = baum / "scripts" / "gesperrt.bin"
    gesperrt.write_bytes(b"x")
    gesperrt.chmod(0o000)
    try:
        proc = _lauf(baum)
    finally:
        gesperrt.chmod(0o644)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode == 2, (
        f"Eine vorhandene, aber unlesbare Datei wird weggeraeumt (Rueckgabewert "
        f"{proc.returncode}). Das ist eine andere Fehlerklasse und muss laut bleiben."
        f"\n{ausgabe[-800:]}")
    assert "beim Import uebersprungen" not in ausgabe, (
        "Der Riegel verbucht eine VORHANDENE Datei als 'nicht ausgeliefert' — das ist eine falsche "
        "Tatsachenbehauptung ueber eine Datei, die nachweislich da ist.")


def test_ANTI_PARITAET_ein_verzeichnis_statt_einer_datei_bleibt_ein_fehler(tmp_path):
    """Zweite Gestalt derselben Verwechslung: der Pfad EXISTIERT, ist aber ein Verzeichnis."""
    ziel = tmp_path / "verzeichnis"
    baum = _baum(ziel, {"test_v": 'from pathlib import Path\n'
                                  'REPO = Path(__file__).resolve().parents[1]\n'
                                  'INHALT = (REPO / "scripts" / "dort").read_text()\n\n\n'
                                  'def test_v():\n    assert INHALT\n'})
    (baum / "scripts" / "dort").mkdir(parents=True)
    proc = _lauf(baum)
    ausgabe = proc.stdout + proc.stderr
    assert proc.returncode == 2, (
        f"Ein Verzeichnis, wo eine Datei erwartet wird, wird weggeraeumt (Rueckgabewert "
        f"{proc.returncode}).\n{ausgabe[-800:]}")
    assert "beim Import uebersprungen" not in ausgabe


# ── Mutationsmatrix: kippt jede Mutation GENAU ihre Achse? ──────────────────────────────────────
#
# Von Hand gemessen 08.09.2026, dann als Fall festgehalten. Die Zusicherung ist nicht "wird rot",
# sondern "wird GENAU HIER rot": jede Mutation muss ihre eigene Achse kippen und keine fremde.
# Eine Mutation, die alles kaputtmacht, schlaegt ueberall an und beweist damit nichts ueber die
# Stelle, die sie treffen sollte.
#
# WARUM DIE KONTROLLZEILE NICHT WEGGELASSEN WERDEN DARF: die erste Fassung dieser Auswertung
# fragte nach `ERROR tests/x.py`; im Ausgabetext steht aber `ERROR collecting tests/x.py`, und mit
# `-rs` zeigt die Zusammenfassung nur Skips. Alle vier Laeufe meldeten daraufhin dasselbe — und
# "kein Unterschied" liest sich als "der Riegel bindet nichts". Aufgefallen ist es nur, weil die
# UNMUTIERTE Kontrolle mitlief und sich ebenfalls nicht unterschied. Ohne sie waere aus einem
# Fehler im Messgeraet ein Befund gegen den Pruefgegenstand geworden.

_MUTATIONEN = {
    # (Vorlage im conftest, Ersatz, welche Achse kippen MUSS)
    "ohne_existenzpruefung": (
        "        if _liegt_im_baum(kandidat, wurzel) and not kandidat.exists():",
        "        if _liegt_im_baum(kandidat, wurzel):",
        "unlesbar"),
    "ort_immer_bekannt": (
        '    kopf = rel.split("/", 1)[0]',
        '    return True\n    kopf = rel.split("/", 1)[0]',
        "fremd"),
    "ohne_ursachenkette": (
        "        aktuell = aktuell.__cause__ or aktuell.__context__",
        "        aktuell = None",
        "eigener_import"),
}

_ACHSEN_SOURCES = ("tests/test_perm.py\ntests/test_fremd.py\ntests/test_import.py\n"
                   "scripts/gelistet.py\n")
_ACHSEN_MODULE = {
    "test_perm": ('import pathlib\n'
                  'INHALT = (pathlib.Path(__file__).resolve().parents[1] / "scripts"\n'
                  '          / "unlesbar.py").read_text()\n\n\ndef test_a():\n    assert INHALT\n'),
    "test_fremd": ("import gibt_es_nirgends_xyz\n\n\ndef test_b():\n"
                   "    assert gibt_es_nirgends_xyz\n"),
    "test_import": "from scripts.nicht_geliefert import y\n\n\ndef test_c():\n    assert y\n",
}


def _achsenbaum(ziel: Path, conftest_text: str) -> Path:
    (ziel / "tests").mkdir(parents=True)
    (ziel / "scripts").mkdir()
    (ziel / "src" / "beispiel.egg-info").mkdir(parents=True)
    (ziel / "src" / "beispiel.egg-info" / "SOURCES.txt").write_text(_ACHSEN_SOURCES,
                                                                   encoding="utf-8")
    (ziel / "scripts" / "gelistet.py").write_text("x = 1\n", encoding="utf-8")
    unlesbar = ziel / "scripts" / "unlesbar.py"
    unlesbar.write_text("geheim = 1\n", encoding="utf-8")
    unlesbar.chmod(0o000)
    (ziel / "tests" / "conftest.py").write_text(conftest_text, encoding="utf-8")
    for name, quelle in _ACHSEN_MODULE.items():
        (ziel / "tests" / f"{name}.py").write_text(quelle, encoding="utf-8")
    return ziel


def _achsen(baum: Path) -> dict:
    aus = _lauf(baum).stdout
    return {achse: ("fehler" if f"ERROR collecting tests/{modul}.py" in aus else "skip")
            for achse, modul in (("unlesbar", "test_perm"), ("fremd", "test_fremd"),
                                 ("eigener_import", "test_import"))}


def test_MUTATIONSMATRIX_jede_mutation_kippt_GENAU_ihre_achse(tmp_path):
    echt_text = CONFTEST.read_text(encoding="utf-8")
    kontrolle = _achsen(_achsenbaum(tmp_path / "kontrolle", echt_text))
    assert kontrolle == {"unlesbar": "fehler", "fremd": "fehler", "eigener_import": "skip"}, (
        "VORBEDINGUNG: der unmutierte Riegel muss die drei Achsen verschieden behandeln. Tut er "
        f"das nicht, misst diese Matrix nichts — gemessen: {kontrolle}")

    for name, (vorlage, ersatz, soll) in _MUTATIONEN.items():
        assert echt_text.count(vorlage) == 1, (
            f"{name}: die Mutations-Vorlage passt {echt_text.count(vorlage)}x statt genau einmal — "
            "der Riegel wurde umgebaut; diese Matrix muss nachgezogen werden, statt still zu bestehen")
        gemessen = _achsen(_achsenbaum(tmp_path / name, echt_text.replace(vorlage, ersatz)))
        for achse in ("unlesbar", "fremd", "eigener_import"):
            if achse == soll:
                assert gemessen[achse] != kontrolle[achse], (
                    f"{name}: die Achse {achse} haette kippen muessen, blieb {gemessen[achse]} — "
                    "der Zweig ist von keinem Fall gebunden")
            else:
                assert gemessen[achse] == kontrolle[achse], (
                    f"{name}: die Achse {achse} kippte mit, obwohl nur {soll} gemeint war — eine "
                    "Mutation, die mehr als ihre Stelle trifft, beweist nichts ueber ihre Stelle")
