"""Ein ausgeliefertes Testmodul darf kein NICHT ausgeliefertes Modul mit BLANKEM Namen importieren.

HERKUNFT, gemessen: `published-artifact-gate / hermetic-cleanroom` brach an PR 198, Kopf
`12acf735a8601862a9da908103b4c408dfe984a9`, mit `ModuleNotFoundError: No module named
'gen_findings_register'` und `exit code 2` ab. Es lief NULL — auch keiner der uebrigen Tests des
Pakets. Ursache war `tests/test_belegdatei_traegt_ihren_eigenen_digest.py`, das
`sys.path.insert(0, REPO / "scripts")` setzte und danach `import gen_findings_register` schrieb.
`scripts/gen_findings_register.py` wird absichtlich nicht ausgeliefert (Owner-Auflage zu
OA-8b1a31cc4f, es liest einen privaten Schluessel).

WARUM DER BESTEHENDE RIEGEL DAS NICHT FING, und warum er RECHT HAT.
`tests/test_sammelabbruch_vor_dem_import.py` deckt diese Klasse — aber in ihrer GEPUNKTETEN Form,
`import scripts.nicht_ausgeliefert`. Dort traegt der Modulname sein Verzeichnis, und
`conftest._verteilung_kennt_den_ort` kann daran entscheiden, ob das Modul zu diesem Projekt gehoert.
Ein BLANKER Name traegt kein Verzeichnis. `conftest` ist an dieser Stelle ausdruecklich fail-closed
("kein Verzeichnis -> nicht entscheidbar") und laesst den Fehler laut — und das ist richtig, denn
sonst verschluckt derselbe Weg ein fehlendes `numpy`.

DIE INFORMATION FEHLT NICHT, SIE STEHT NUR WOANDERS. Welches Verzeichnis gemeint war, sagt das
importierende Modul selbst, mit seinem `sys.path`-Eintrag. Im entpackten sdist ist das nicht mehr
nachvollziehbar, weil die Zieldatei dort fehlt. Im CHECKOUT liegen beide Tatsachen nebeneinander:
die Datei und die Dateiliste der Verteilung. Deshalb entscheidet dieser Riegel HIER, wo die Frage
entscheidbar ist, statt im Reinraum zu raten — und er weicht `hermetic-cleanroom` um keinen Zoll
auf: dort bleibt jeder unerklaerte Fehler weiterhin laut.

DREI ZUSTAENDE, nie zwei. Ohne Dateiliste der Verteilung ist das Urteil NICHT MESSBAR und der Test
ueberspringt MIT GRUND. Eine leere Trefferliste aus einer leeren Messflaeche waere ein Freispruch,
deshalb wird die Messflaeche selbst gegen eine Untergrenze geprueft.

EHRLICHE GRENZE: gemessen werden `sys.path`-Eintraege, deren Verzeichnis als Zeichenkette im
Aufruf steht (`REPO / "scripts"`, `str(REPO / "scripts")`). Ein aus einer Variablen berechnetes
Verzeichnis faellt durch. Das ist eine Untergrenze der Messung, keine Zusicherung.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Untergrenze der Messflaeche. Faellt die Zahl der gelesenen Testmodule darunter, hat nicht der
#: Baum sich geaendert, sondern die Messung ist kaputt — und eine leere Trefferliste waere dann
#: kein Freispruch, sondern gar keine Aussage.
MINDESTENS_MODULE = 200


def _verteilungsliste() -> set[str] | None:
    """Die Dateiliste der Verteilung, aus dem Artefakt selbst — oder None.

    Gefragt wird `SOURCES.txt`, nicht `MANIFEST.in`: die eine ist das ERGEBNIS der Rechnung von
    setuptools, die andere eine DEKLARATION, und beide sind in diesem Baum nachweislich schon
    auseinandergelaufen (Restrisiko S27). Dieselbe Quelle benutzt `conftest`.
    """
    for liste in sorted(REPO.glob("*/*.egg-info/SOURCES.txt")) + sorted(REPO.glob("*.egg-info/SOURCES.txt")):
        try:
            eintraege = {z.strip() for z in liste.read_text(encoding="utf-8").splitlines() if z.strip()}
        except OSError:
            continue
        if eintraege:
            return eintraege
    return None


def _pfadeintraege(baum: ast.Module, wurzel: pathlib.Path) -> set[str]:
    """Welche Verzeichnisse DES UEBERGEBENEN Baums legt das Modul auf `sys.path`?

    `wurzel` ist ein Parameter und kein Modulwert. Die erste Fassung fragte die echte Repo-Wurzel,
    auch wenn ein Fall ueber einem gebauten Baum lief — damit war JEDER gebaute Fall still leer, und
    der rote Fangnachweis fiel als einziger auf. Eine Messung gegen eine andere Flaeche als die
    uebergebene ist keine Messung dieser Flaeche.
    """
    verz: set[str] = set()
    for n in ast.walk(baum):
        if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute):
            continue
        if n.func.attr not in ("insert", "append"):
            continue
        ziel = n.func.value
        if not (isinstance(ziel, ast.Attribute) and ziel.attr == "path"
                and isinstance(ziel.value, ast.Name) and ziel.value.id == "sys"):
            continue
        # AM BAUM, NICHT AM TEXT. Die erste Fassung las die Zeichenketten aus `ast.unparse`
        # mit einem Muster fuer DOPPELTE Anfuehrungszeichen — `unparse` schreibt aber EINFACHE.
        # Der Aufruf kehrte zurueck, die Liste war leer, und leer las sich wie "nichts gefunden".
        # Nur der rote Fangnachweis hat es gezeigt. Ein Syntaxbaum kennt keine Anfuehrungszeichen.
        for k in ast.walk(n):
            if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
                continue
            teil = k.value.strip().strip("/")
            if teil and (wurzel / teil).is_dir():
                verz.add(teil)
    return verz


def _blanke_namen(baum: ast.Module) -> set[str]:
    """Module, die OHNE Punkt importiert werden — nur die tragen kein Verzeichnis."""
    namen: set[str] = set()
    for n in ast.walk(baum):
        if isinstance(n, ast.Import):
            namen.update(a.name for a in n.names if "." not in a.name)
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module and "." not in n.module:
            namen.add(n.module)
    return namen


def befunde(wurzel: pathlib.Path, gelistet: set[str]) -> tuple[list[tuple[str, str]], int]:
    """Paare (Testmodul, nicht ausgelieferte Zieldatei) und die Zahl der gelesenen Module."""
    treffer: list[tuple[str, str]] = []
    gelesen = 0
    for t in sorted((wurzel / "tests").glob("test_*.py")):
        try:
            quelle = t.read_text(encoding="utf-8")
        except OSError:
            continue
        gelesen += 1
        if "sys.path" not in quelle:
            continue
        try:
            baum = ast.parse(quelle)
        except SyntaxError:
            continue
        verz = _pfadeintraege(baum, wurzel)
        if not verz:
            continue
        rel_test = str(t.relative_to(wurzel)).replace("\\", "/")
        if rel_test not in gelistet:
            continue                     # das Testmodul selbst faehrt nicht mit — kein Reinraumfall
        for v in sorted(verz):
            for name in sorted(_blanke_namen(baum)):
                rel = f"{v}/{name}.py"
                if not (wurzel / rel).is_file():
                    continue             # kein Modul DIESES Baums, etwa `numpy`
                if rel not in gelistet:
                    treffer.append((rel_test, rel))
    return treffer, gelesen


def test_kein_ausgeliefertes_testmodul_bricht_das_sammeln_im_paket_ab():
    """[ZAEHLT] Der Fall, der `hermetic-cleanroom` an PR 198 auf `exit code 2` brachte."""
    gelistet = _verteilungsliste()
    if gelistet is None:
        pytest.skip("NICHT MESSBAR: keine SOURCES.txt im Baum. Einmal `python -m build --sdist` "
                    "erzeugt sie. Das ist keine Freigabe, sondern eine fehlende Grundlage.")
    treffer, gelesen = befunde(REPO, gelistet)
    assert gelesen >= MINDESTENS_MODULE, (
        f"die Messflaeche ist zu klein: {gelesen} Testmodule gelesen, erwartet mindestens "
        f"{MINDESTENS_MODULE}. Eine leere Trefferliste aus einer leeren Flaeche ist kein Freispruch.")
    assert not treffer, "\n".join(
        f"{a} importiert {b!r} mit blankem Namen, aber die Verteilung liefert die Datei nicht aus. "
        f"Im entpackten sdist bricht das SAMMELN ab, und mit ihm die ganze Suite. Abhilfe: die "
        f"Pfadform (`importlib.util.spec_from_file_location`), dann meldet `conftest` ein ehrliches "
        f"SKIP." for a, b in treffer)


def _baue(tmp: pathlib.Path, *, ziel_gelistet: bool, ziel_name: str = "nicht_ausgeliefert",
          verzeichnis: str = "werkzeuge") -> tuple[pathlib.Path, set[str]]:
    (tmp / verzeichnis).mkdir(parents=True, exist_ok=True)
    (tmp / verzeichnis / f"{ziel_name}.py").write_text("WERT = 1\n", encoding="utf-8")
    (tmp / "tests").mkdir(parents=True, exist_ok=True)
    (tmp / "tests" / "test_probe.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "REPO = Path(__file__).resolve().parents[1]\n"
        f'sys.path.insert(0, str(REPO / "{verzeichnis}"))\n'
        f"import {ziel_name}\n", encoding="utf-8")
    gelistet = {"tests/test_probe.py"}
    if ziel_gelistet:
        gelistet.add(f"{verzeichnis}/{ziel_name}.py")
    return tmp, gelistet


def test_FANG_ein_nicht_ausgeliefertes_ziel_wird_gemeldet(tmp_path):
    """[ZAEHLT] Gegenrichtung rot: genau die Lage von PR 198, nachgebaut."""
    wurzel, gelistet = _baue(tmp_path, ziel_gelistet=False)
    treffer, _ = befunde(wurzel, gelistet)
    assert treffer == [("tests/test_probe.py", "werkzeuge/nicht_ausgeliefert.py")], treffer


def test_FANG_ein_ausgeliefertes_ziel_wird_NICHT_gemeldet(tmp_path):
    """[ZAEHLT] Gegenrichtung gruen: der Riegel darf nicht alles melden."""
    wurzel, gelistet = _baue(tmp_path, ziel_gelistet=True)
    treffer, _ = befunde(wurzel, gelistet)
    assert treffer == [], treffer


def test_FANG_ein_fremdes_paket_wird_NICHT_gemeldet(tmp_path):
    """[ZAEHLT] `import numpy` loest sich zu keiner Datei dieses Baums auf und bleibt unberuehrt.

    Das ist die Grenze, an der `conftest` bewusst fail-closed bleibt. Wuerde dieser Riegel sie
    ueberschreiten, verschluckte er eine fehlende Abhaengigkeit.
    """
    (tmp_path / "werkzeuge").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_probe.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "REPO = Path(__file__).resolve().parents[1]\n"
        'sys.path.insert(0, str(REPO / "werkzeuge"))\n'
        "import numpy\n", encoding="utf-8")
    treffer, _ = befunde(tmp_path, {"tests/test_probe.py"})
    assert treffer == [], treffer


def test_FANG_ein_nicht_ausgeliefertes_TESTMODUL_ist_kein_reinraumfall(tmp_path):
    """[ZAEHLT] Faehrt der Test selbst nicht mit, kann er im Paket auch nichts abbrechen."""
    wurzel, gelistet = _baue(tmp_path, ziel_gelistet=False)
    treffer, _ = befunde(wurzel, gelistet - {"tests/test_probe.py"})
    assert treffer == [], treffer


def test_FANG_die_gepunktete_form_bleibt_beim_bestehenden_riegel(tmp_path):
    """[ZAEHLT] `import werkzeuge.x` traegt sein Verzeichnis und gehoert nicht hierher.

    Kein Zustaendigkeitsstreit zwischen zwei Riegeln: diese Form deckt
    `tests/test_sammelabbruch_vor_dem_import.py` ueber `conftest`, und zwar wirkend.
    """
    (tmp_path / "werkzeuge").mkdir()
    (tmp_path / "werkzeuge" / "x.py").write_text("WERT = 1\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_probe.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "REPO = Path(__file__).resolve().parents[1]\n"
        'sys.path.insert(0, str(REPO / "werkzeuge"))\n'
        "import werkzeuge.x\n", encoding="utf-8")
    treffer, _ = befunde(tmp_path, {"tests/test_probe.py"})
    assert treffer == [], treffer


def test_FANG_ohne_dateiliste_gibt_es_kein_gruen():
    """[ZAEHLT] Der dritte Zustand existiert und ist nicht 'bestanden'."""
    quelle = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "pytest.skip(\"NICHT MESSBAR" in quelle
    assert "keine SOURCES.txt im Baum" in quelle
