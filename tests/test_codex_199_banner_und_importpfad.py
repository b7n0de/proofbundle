"""Fehlerbuch-Knoten zu den zwei Codex-Funden aus PR 199, je Fund Reproduktion und Eigenschaft.

FUND A, r3999288387, scripts/mutation_check.py. Das Muster `^!+ .* !+$` verlangt EIN Ausrufezeichen
je Seite, nicht fuenf. Es trifft damit die gewoehnliche Diagnosezeile eines FEHLGESCHLAGENEN Tests,
die pytest aus dem aufgefangenen stdout in seinen Fehlerbericht uebernimmt. Bei rc=1 und einem
gueltigen Bericht mit einem Fehlschlag galt der Lauf als NICHT MESSBAR und das Pflichttor brach ab,
obwohl pytest normal zu Ende lief. Ein gemessenes Rot wurde zum Abbruch.

FUND B, r3999288389, scripts/test_manifest_gate.py. Der Textpfad verlangte `unittest` UNMITTELBAR
nach `import` und sah `import os, unittest` nicht; der AST-Pfad sah es. Die beiden Ableitungen
wurden uneinig, und die Gleichheitspruefung wies ein gueltiges Testmodul ab.

WARUM BEIDE HIER UND NICHT AUF DEM PR-ZWEIG. Gemessen: beide Stellen stehen unveraendert auf main
(mutation_check.py:875 und test_manifest_gate.py:70 am Kopf 7616293). Die Antworten des Hauses vom
13.09. 10:11 nannten den Merge-Konflikt des PR-Zweigs als Grund, den Fix zu vertagen — der Konflikt
ist fuer diese Reparatur ohne Belang, weil die Defekte in der Basis liegen.

FESTER SOLLWERT. Die Reproduktionsknoten messen gegen EINGEFRORENE Proben, nicht gegen frisch
erzeugte Ausgabe. Was sie behaupten, steht als Erwartung im Fall und nicht als Ergebnis eines Laufs.

EHRLICHE GRENZE, Fund B: gemessen wird die Einigkeit der beiden Ableitungen ueber eine benannte
Menge von Importformen. Ob es eine dritte Form gibt, die beide gleich falsch lesen, entscheidet
dieser Riegel nicht — zwei Leser mit gleicher Fehlergeometrie waeren einer.
"""
from __future__ import annotations

import ast
import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _lade(rel: str, name: str):
    p = REPO / rel
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {rel} liegt nicht im Baum")
    s = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


# ── FUND A ────────────────────────────────────────────────────────────────────────────────

#: Eingefrorene Proben. Jede traegt ihre Erwartung MIT, damit der Fall nicht misst, was er erzeugt.
PROBEN_A = (
    ("gewoehnliche Diagnosezeile eines Fehlschlags", "! ordinary diagnostic !", True),
    ("drei Ausrufezeichen, harmloser Text", "!!! achtung !!!", True),
    ("echter Abbruch-Banner", "!!!!!! Interrupted: 1 error !!!!!!", True),
    ("gewoehnlicher Assertionsfehler", "E   assert 1 == 2", False),
    ("Tabellenzeile mit Ausrufezeichen", "| ! | a | ! |", False),
)


def test_A_knoten1_das_muster_trifft_eine_gewoehnliche_fehlschlagzeile():
    """[ZAEHLT] REPRODUKTION: die Form des Fundes, gegen eingefrorene Proben."""
    m = _lade("scripts/mutation_check.py", "_mc_a1")
    for name, zeile, soll in PROBEN_A:
        assert bool(m._ABBRUCH_BANNER.search(zeile)) is soll, name
    assert m._ABBRUCH_BANNER.search("! ordinary diagnostic !"), (
        "die Reproduktion trifft nicht mehr — dann misst dieser Knoten einen anderen Gegenstand "
        "als den, den Codex gemeldet hat")


#: Die ECHTE Form eines pytest-Fehlerberichts: die Ausgabe des Tests steht in einem Abschnitt, den
#: pytest AUSDRUECKLICH als solche beschriftet. Genau das unterscheidet sie von einem Laeufer-Banner.
BERICHT_MIT_AUFGEFANGENER_AUSGABE = (
    "=================================== FAILURES ===================================\n"
    "_________________________________ test_etwas __________________________________\n"
    "\n"
    "    def test_etwas():\n"
    ">       assert 1 == 2\n"
    "E       assert 1 == 2\n"
    "\n"
    "test_probe.py:3: AssertionError\n"
    "----------------------------- Captured stdout call -----------------------------\n"
    "! ordinary diagnostic !\n"
    "=========================== short test summary info ============================\n"
    "FAILED test_probe.py::test_etwas\n"
    "1 failed in 0.10s\n"
)

#: Ein ECHTER Abbruch von `pytest.exit`, auf der obersten Ebene und mit rc=1. Gemessener Fall aus
#: tests/test_mutationstor_sammler_sieht_die_freigabeflaeche.py: die Bilanz sieht sauber aus, und
#: der Test, der die Mutante toeten sollte, lief nie.
ECHTER_ABBRUCH_MIT_RC1 = (
    "! _pytest.outcomes.Exit: abgebrochen, weil der Mutant die Umgebung unbrauchbar gemacht hat !\n"
    "1 failed, 1 passed in 0.14s\n"
)


def _bericht(tmp_path, fehler=1):
    p = tmp_path / "junit.xml"
    p.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
        f'tests="1" failures="{fehler}" errors="0"><testcase name="t"><failure/></testcase>'
        "</testsuite></testsuites>\n", encoding="utf-8")
    return p


def test_A_knoten2_aufgefangene_ausgabe_macht_den_lauf_NICHT_unmessbar(tmp_path):
    """[ZAEHLT] EIGENSCHAFT: was der TEST ausgibt, ist kein Banner des LAEUFERS."""
    m = _lade("scripts/mutation_check.py", "_mc_a2")
    assert m._rote_aus_lauf(_bericht(tmp_path), BERICHT_MIT_AUFGEFANGENER_AUSGABE, rc=1) == 1, (
        "eine Zeile aus dem aufgefangenen stdout eines Tests darf den Lauf nicht unmessbar machen")


def test_A_ANTI_ein_echter_abbruch_bleibt_unmessbar_AUCH_bei_rc1(tmp_path):
    """[ZAEHLT] Anti-Paritaet, und sie ist der Grund gegen die erste Abhilfe des Berichts.

    Der Bericht schlug vor, die Formpruefung nur ohne Rueckgabewert anzuwenden. Dieser gemessene
    Fall zeigt, warum das falsch waere: `pytest.exit` schreibt sein Banner UND liefert rc=1.
    """
    m = _lade("scripts/mutation_check.py", "_mc_a3")
    assert m._rote_aus_lauf(_bericht(tmp_path), ECHTER_ABBRUCH_MIT_RC1, rc=1) is None


def test_A_ANTI_rueckgabewert_zwei_bleibt_unmessbar(tmp_path):
    """[ZAEHLT] Anti-Paritaet: rc=2 heisst abgebrochen, daran aendert der Fix nichts."""
    m = _lade("scripts/mutation_check.py", "_mc_a4")
    assert m._rote_aus_lauf(tmp_path / "fehlt.xml", "irgendwas\n", rc=2) is None


def test_A_die_flaeche_selbst_wird_richtig_geschnitten():
    """[ZAEHLT] Der Schnitt nimmt den aufgefangenen Block heraus und nur ihn."""
    m = _lade("scripts/mutation_check.py", "_mc_a5")
    ohne = m._ohne_aufgefangene_ausgabe(BERICHT_MIT_AUFGEFANGENER_AUSGABE)
    assert "! ordinary diagnostic !" not in ohne, "der aufgefangene Block blieb stehen"
    assert "short test summary info" in ohne, "der Schnitt hat zu viel weggenommen"
    assert "1 failed in 0.10s" in ohne, "die Bilanzzeile darf nicht verschwinden"
    assert m._ohne_aufgefangene_ausgabe(ECHTER_ABBRUCH_MIT_RC1) == ECHTER_ABBRUCH_MIT_RC1, (
        "ein Text ohne aufgefangenen Block darf unveraendert bleiben")


def test_A_der_irrefuehrende_kommentar_ist_weg():
    """[ZAEHLT] Der Text behauptete eine Grenze ueber fuenf Ausrufezeichen, die die Form nicht hat."""
    q = (REPO / "scripts" / "mutation_check.py").read_text(encoding="utf-8")
    assert "Die fuenf Ausrufezeichen halten die Grenze" not in q, (
        "der Kommentar beschreibt weiter eine Eigenschaft, die das Muster nicht traegt")


# ── FUND B ────────────────────────────────────────────────────────────────────────────────

#: Eingefrorene Quellen mit ihrer Erwartung: importiert das Modul `unittest`?
PROBEN_B = (
    ("import os, unittest", "import os, unittest\n\nclass T(unittest.TestCase):\n    pass\n", True),
    ("import unittest", "import unittest\n\nclass T(unittest.TestCase):\n    pass\n", True),
    ("import unittest.mock", "import unittest.mock\n", True),
    ("from unittest import mock", "from unittest import mock\n", True),
    ("import pytest", "import pytest\n\ndef test_x():\n    assert True\n", False),
    ("import my_unittest_helper", "import my_unittest_helper\n", False),
    ("import os, unittest_extras", "import os, unittest_extras\n", False),
)

_TEXTPFAD = re.compile(r"^\s*(?:import\s+[^\n]*\bunittest\b|from\s+unittest\b)", re.MULTILINE)


def _ast_pfad(quelle: str) -> bool:
    for n in ast.walk(ast.parse(quelle)):
        if isinstance(n, ast.Import) and any(a.name.split(".")[0] == "unittest" for a in n.names):
            return True
        if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] == "unittest":
            return True
    return False


def test_B_knoten1_das_alte_muster_sieht_den_mehrfachimport_NICHT():
    """[ZAEHLT] REPRODUKTION: das Muster von vor dem Fix, eingefroren im Fall."""
    alt = re.compile(r"^\s*(?:import\s+unittest|from\s+unittest\b)", re.MULTILINE)
    quelle = "import os, unittest\n\nclass T(unittest.TestCase):\n    pass\n"
    assert not alt.search(quelle), "das alte Muster sah den Mehrfachimport doch"
    assert _ast_pfad(quelle), "der Syntaxbaum muss ihn sehen, sonst gibt es keine Differenz"


def test_B_knoten2_beide_ableitungen_sind_ueber_alle_formen_EINIG():
    """[ZAEHLT] EIGENSCHAFT: Text und Syntaxbaum messen dieselbe Eigenschaft."""
    uneinig = [(n, bool(_TEXTPFAD.search(q)), _ast_pfad(q))
               for n, q, _ in PROBEN_B if bool(_TEXTPFAD.search(q)) != _ast_pfad(q)]
    assert not uneinig, f"Text und Syntaxbaum widersprechen sich: {uneinig}"


def test_B_knoten2_beide_treffen_die_eingefrorene_erwartung():
    """[ZAEHLT] Einigkeit allein genuegt nicht, beide koennten gleich falsch liegen."""
    falsch = [(n, bool(_TEXTPFAD.search(q)), _ast_pfad(q), soll)
              for n, q, soll in PROBEN_B
              if bool(_TEXTPFAD.search(q)) != soll or _ast_pfad(q) != soll]
    assert not falsch, f"gegen die eingefrorene Erwartung falsch: {falsch}"


def test_B_das_werkzeug_im_baum_traegt_denselben_pfad():
    """[ZAEHLT] Der Riegel misst nicht seine eigene Kopie, sondern die ausgelieferte Stelle."""
    m = _lade("scripts/test_manifest_gate.py", "_tmg")
    quelle = (REPO / "scripts" / "test_manifest_gate.py").read_text(encoding="utf-8")
    assert "import\\s+[^\\n]*\\bunittest\\b" in quelle, (
        "der Textpfad im Werkzeug liest nicht jeden Namen der Anweisung")
    assert hasattr(m, "pytest_only_modules") and hasattr(m, "pytest_only_modules_ast")
