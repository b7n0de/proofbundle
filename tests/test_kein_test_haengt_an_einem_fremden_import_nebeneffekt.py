"""Ein nackter Import eines Skripts unter ``scripts/`` braucht die Pfad-Vorbereitung IM SELBEN MODUL.

DIESE DATEI IST DIE KORREKTUR EINES EIGENEN FEHLURTEILS, und sie steht hier in der Form, die ihn
verhindert haette.

WAS ICH BEHAUPTET HABE. Die un-Gegenlesung (qwen3.8:27b, 2026-09-06) konnte zu einem
``import sign_readiness_artifact`` in ``tests/test_freigabe_evidenz_provenienz_l5_g7_02.py`` nicht
entscheiden, ob er aufloest, und sagte korrekt UNKNOWN. Ich habe daraus einen Befund gemacht: ich
prueste ``tests/conftest.py`` und ``pyproject.toml``, fand dort kein ``sys.path`` und schloss auf
einen Import-Nebeneffekt aus der Laufreihenfolge.

WAS WIRKLICH DER FALL IST, gemessen. Dieselbe Datei legt in ihren Zeilen 46-50 auf MODULEBENE
``REPO/"src"`` und ``REPO/"scripts"`` auf ``sys.path``, bevor irgendein Test laeuft. Der Import
trug sich also selbst. Ich hatte die zwei Stellen geprueft, an die ich zuerst dachte, und nicht die
Datei, um die es ging — die Kontrolle, die den Schluss widerlegt haette, war eine Zeile weit weg.

WAS DIE MESSUNG DANN ZEIGTE. Elf Testmodule holen ein Skript unter ``scripts/`` mit einem nackten
Import. ALLE ELF bereiten den Pfad selbst vor, in zwei Schreibweisen (``REPO / "scripts"`` und
``Path(__file__).resolve().parents[1] / "scripts"``). Es gibt also keinen Defekt, sondern eine
HAUSFORM — und die ist richtig, weil ``scripts/`` kein Paket ist und auf keinem Suchpfad liegt.

WAS DESHALB HIER STEHT. Nicht "kein nackter Import" (das waere ein Riegel gegen die eigene, gesunde
Hausform gewesen — und meine erste Fassung war genau das: rot auf elf Modulen), sondern die
Invariante, die die Hausform TRAEGT: wer so importiert, muss den Pfad im selben Modul und VOR der
Import-Zeile vorbereiten. Ein Modul, das sich auf die Vorbereitung eines anderen verlaesst, ist
gruen, solange die Reihenfolge passt, und bricht bei ``-k``, bei einem Einzellauf oder nach einer
Umsortierung — mit einem ``ImportError``, der wie ein kaputtes Paket aussieht und keiner ist.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _pfad_vorbereitungen(baum: ast.AST) -> list[int]:
    """Zeilen, in denen das Modul ``scripts/`` auf ``sys.path`` legt — Wirkung, nicht Erwaehnung.

    Gemessen wird ein AUFRUF von ``sys.path.insert``/``append``, in dessen Teilbaum die
    Zeichenkette ``scripts`` als Konstante vorkommt. Beide im Baum vorhandenen Schreibweisen sind
    damit gedeckt, ohne dass eine Namensliste gepflegt werden muss; ein Kommentar oder ein
    Docstring, der ``sys.path`` erwaehnt, ist kein Aufruf und zaehlt nicht.
    """
    # ZWEI TEILE, und der zweite steht getrennt, weil die erste Fassung daran scheiterte: sie
    # verlangte die Zeichenkette `scripts` IM Aufruf. Zwei Module im Baum schreiben aber
    # `for p in (REPO / "src", REPO / "scripts"): sys.path.insert(0, str(p))` — die Zeichenkette
    # steht im Schleifenkopf, der Aufruf sieht nur `p`. Der Riegel meldete sie als ungedeckt,
    # obwohl sie vorbereiten. Dieselbe Schleifenvariablen-Falle, die `tests/conftest.py` in ihrer
    # eigenen Ableitung schon einmal getroffen hat. Gemessen wird deshalb: gibt es einen
    # sys.path-Aufruf (die WIRKUNG), und nennt das Modul irgendwo `scripts` als Pfadbestandteil
    # (der GEGENSTAND). Beides zusammen ist die Vorbereitung; die Schreibweise dazwischen ist frei.
    nennt_scripts = any(isinstance(t, ast.Constant) and isinstance(t.value, str)
                        and "scripts" in t.value for t in ast.walk(baum))
    if not nennt_scripts:
        return []
    zeilen: list[int] = []
    for k in ast.walk(baum):
        if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr in ("insert", "append")):
            continue
        ziel = k.func.value
        if (isinstance(ziel, ast.Attribute) and ziel.attr == "path"
                and isinstance(ziel.value, ast.Name) and ziel.value.id == "sys"):
            zeilen.append(k.lineno)
    return sorted(zeilen)


def ungedeckte_skript_importe(quelltext: str, skriptnamen: set[str]) -> list[str]:
    """Nackte Skript-Importe OHNE eine Pfad-Vorbereitung davor im selben Modul."""
    try:
        baum = ast.parse(quelltext)
    except SyntaxError:                                        # pragma: no cover
        return []
    vorbereitungen = _pfad_vorbereitungen(baum)
    fund: list[str] = []
    for k in ast.walk(baum):
        namen: list[str] = []
        if isinstance(k, ast.Import):
            namen = [a.name for a in k.names if a.name.split(".")[0] in skriptnamen]
        elif isinstance(k, ast.ImportFrom) and k.level == 0 and k.module:
            if k.module.split(".")[0] in skriptnamen:
                namen = [k.module]
        for n in namen:
            if not any(v < k.lineno for v in vorbereitungen):
                fund.append(f"{n} (Zeile {k.lineno}, keine Vorbereitung davor)")
    return sorted(set(fund))


def _skriptnamen() -> set[str]:
    return {p.stem for p in (REPO / "scripts").glob("*.py")}


def test_jeder_nackte_skript_import_traegt_seine_eigene_vorbereitung():
    """Der Riegel. Gemessen am 06.09.2026: elf Module importieren so, alle elf bereiten vor."""
    if not (REPO / "scripts").is_dir():
        pytest.skip("kein Repo-Kontext — ohne scripts/ gibt es die Frage nicht")
    namen = _skriptnamen()
    assert namen, "keine Skripte gefunden — die Erhebung misst nichts"
    treffer = {}
    for t in sorted((REPO / "tests").glob("test_*.py")):
        f = ungedeckte_skript_importe(t.read_text(encoding="utf-8", errors="replace"), namen)
        if f:
            treffer[t.name] = f
    assert not treffer, (
        f"Testmodul(e) importieren ein Skript unter scripts/, ohne den Pfad im selben Modul davor "
        f"vorzubereiten: {treffer}. Das loest nur auf, solange ein ANDERER Test es vorher getan "
        "hat — gruen bei vollem Lauf, ImportError bei -k, Einzellauf oder Umsortierung. Eine Zeile "
        'sys.path.insert(0, str(REPO / "scripts")) vor dem Import traegt den Test selbst.')


def test_anti_tautologie_die_elf_echten_module_sind_wirklich_gedeckt():
    """Ohne diese Zeile waere auch ein Riegel gruen, der GAR NICHTS findet.

    Sie misst, dass es die Bauform ueberhaupt gibt: mindestens ein echtes Modul importiert nackt
    UND bereitet vor. Faellt sie eines Tages, ist die Hausform verschwunden — dann misst der Riegel
    oben eine leere Menge und sagt nichts mehr.
    """
    if not (REPO / "scripts").is_dir():
        pytest.skip("kein Repo-Kontext")
    namen = _skriptnamen()
    gedeckt = 0
    for t in sorted((REPO / "tests").glob("test_*.py")):
        q = t.read_text(encoding="utf-8", errors="replace")
        try:
            baum = ast.parse(q)
        except SyntaxError:
            continue
        hat_import = any(
            (isinstance(k, ast.Import) and any(a.name.split(".")[0] in namen for a in k.names))
            or (isinstance(k, ast.ImportFrom) and k.level == 0 and k.module
                and k.module.split(".")[0] in namen)
            for k in ast.walk(baum))
        if hat_import and _pfad_vorbereitungen(baum):
            gedeckt += 1
    assert gedeckt >= 5, (
        f"nur {gedeckt} Modul(e) zeigen die Bauform nackter Import PLUS eigene Vorbereitung — "
        "die Erhebung des Riegels oben laeuft dann ins Leere")


def test_meta_ein_import_ohne_vorbereitung_wird_gefunden():
    """Pflanzung: derselbe Import, einmal ohne und einmal mit Vorbereitung davor."""
    namen = _skriptnamen() or {"sign_readiness_artifact"}
    name = "sign_readiness_artifact" if "sign_readiness_artifact" in namen else sorted(namen)[0]
    ohne = f"def test_x():\n    import {name} as m\n    assert m\n"
    assert ungedeckte_skript_importe(ohne, namen), (
        "der ungedeckte Import wird nicht gefunden — der Riegel oben ist wirkungslos")
    mit = ('import sys\nfrom pathlib import Path\n'
           'sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))\n'
           f"import {name} as m\n")
    assert ungedeckte_skript_importe(mit, namen) == [], (
        "die gesunde Hausform wird gemeldet — dann ist der Riegel gegen den Baum gerichtet, "
        "nicht gegen den Fehler")


def test_meta_die_vorbereitung_muss_VOR_dem_import_stehen():
    """Die Reihenfolge ist die Eigenschaft, nicht die blosse Anwesenheit der Zeile."""
    namen = _skriptnamen() or {"sign_readiness_artifact"}
    name = "sign_readiness_artifact" if "sign_readiness_artifact" in namen else sorted(namen)[0]
    danach = ('import sys\nfrom pathlib import Path\n'
              f"import {name} as m\n"
              'sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))\n')
    assert ungedeckte_skript_importe(danach, namen), (
        "eine Vorbereitung NACH dem Import wird als Deckung gelesen — sie kommt zu spaet, "
        "der Import ist dann schon gelaufen")
