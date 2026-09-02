"""Ein dokumentierter Testbefehl muss die Suite WIRKLICH fahren koennen.

DIE GESCHICHTE DIESER DATEI IST DER FUND, und sie gehoert hierher, weil sie die Klasse zeigt.

Ein Tiefen-Gate mass am 02.09.2026: `make test` fuhr `python -m unittest discover -s tests` und
lieferte aus dem entpackten sdist 12 failures und 25 errors, waehrend dieselbe Suite im Repo `OK`
sagte. Eine adversariale Linse hat diese Gruendungszahl am selben Tag am Artefakt nachgerechnet,
weil eine unbelegte Zahl die ganze Runde begruenden wuerde: die 25 errors stimmen exakt (verteilt
auf acht Module), und die failures waren 12 — bis diese Runde selbst eine dreizehnte Datei mit
einem ungeschuetzten `assertTrue(running_in_repo_checkout())` hinzufuegte. Genau die Klasse, gegen
die diese Datei steht, eine Ebene hoeher. Sie ist geloescht. Die Regel „ein Repo-Kontext-Test ist ausserhalb eines Checkouts nicht anwendbar" stand in
`tests/conftest.py::pytest_collection_modifyitems` — einem pytest-Haken, den unittest nie laedt.

MEINE ERSTE ANTWORT WAR EIN ZWEITER LAEUFER, und sie war falsch. Ein Skript unter
`scripts/` (run_stdlib_tests, seither geloescht)
importierte dieselbe Entscheidung und bediente damit die Zusage aus CONTRIBUTING.md („no pytest
required, standard library works too"). Eine weitere Linse hat dann gemessen, was diese Zusage
wert ist:

    35 von 217 Testmodulen importieren `pytest` auf Modulebene
    30 Module halten 345 Testfunktionen als freies `def test_*()` — fuer unittest UNSICHTBAR
    Folge: der stdlib-Lauf faellt nicht laut aus, er faehrt still mehrere hundert Tests weniger
           und meldet trotzdem OK

**Die Zusage war das Problem, nicht der fehlende zweite Laeufer.** Ein Mechanismus, der eine
unhaltbare Zusage bedient, macht sie glaubwuerdiger statt wahrer. Korrigiert wurde deshalb die
Zusage (CONTRIBUTING.md) und das Ziel (`make test` faehrt pytest); der zweite Laeufer ist entfernt.

WAS BLEIBT UND WARUM. Die Regel ist jetzt an EINEN Laeufer gebunden — und das ist richtig, solange
es nur EINEN gibt, der die Suite fahren kann. Ein Riegel an einem Laeufer ist nur dann ein Defekt,
wenn ein zweiter, DOKUMENTIERTER Weg existiert. Diese Datei haelt genau das fest.
"""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent

#: Laeufer, von denen GEMESSEN ist, dass sie diese Suite vollstaendig fahren UND die
#: Repo-Kontext-Regel tragen. Eine Allowlist des Tragenden: wer einen zweiten eintraegt, muss
#: zuerst belegen, dass er beides kann.
LAEUFER_DIE_DIE_SUITE_FAHREN = ("pytest",)

#: Was ueberhaupt eine Suite startet — unabhaengig davon, ob es sie fahren KANN.
#: DIE HEUTE BEKANNTEN LAEUFER OHNE pytest — ausgeschrieben, nicht stillgelegt.
#:
#: `scripts/mutation_check.py::_red_count` faehrt `python -B -m unittest discover -s tests` und
#: leitet daraus die TOETUNGSENTSCHEIDUNG des Mutations-Tors ab (`make mutation`, ein
#: dokumentiertes Ziel). Gefunden am 02.09.2026, nachdem die vorige Runde einen ANDEREN zweiten
#: Laeufer geloescht hatte: die Loeschung schloss die Instanz, nicht die Klasse.
#:
#: DIE FOLGE, so genau wie sie heute messbar ist: 30 Testmodule halten 345 Testfunktionen als
#: freies `def test_*()`, fuer unittest unsichtbar; 35 Module importieren pytest auf Modulebene.
#: Eine Mutation, die NUR von diesen Tests getoetet wird, erscheint dem Tor als UEBERLEBENDE.
#: Die Richtung ist damit konservativ (zu streng, nicht faelschlich gruen) — aber das Tor misst
#: nicht, was es zu messen vorgibt.
#:
#: WARUM HIER EINE LISTE UND KEIN FIX: den Laeufer des Mutations-Tors umzustellen aendert seine
#: Toetungszahlen, ist ein Mehrstunden-Lauf und liegt release-nah. Das gehoert dem Owner
#: vorgelegt, nicht nebenbei geaendert. Die Liste ist kein Freibrief: sie ist EXAKT, ein neuer
#: Laeufer faellt sofort auf, und ein verschwundener ebenso.
BEKANNTE_ZWEITE_LAEUFER = ["mutation_check.py"]


#: WAS EIN ZWEITER LAEUFER IST — die Eigenschaft, und zwar die AUSGEFUEHRTE.
#:
#: Zwei Fassungen waren vorher falsch, beide aus derselben Wurzel:
#:
#:   1. NAME. Gesucht wurde `stdlib` / `run_tests` im Dateinamen. Ein Pre-Sweep hat das am
#:      02.09.2026 in beide Richtungen widerlegt: `pruefstand_ohne_pytest.py` startete die Suite
#:      und lief mit `7 passed` durch, `run_tests_doku_generator.py` startete nichts und fiel.
#:   2. TEXT. Gesucht wurde dann im INHALT nach `unittest discover` & Co. Damit fielen drei
#:      bestehende Skripte — und alle drei Treffer standen in KOMMENTAREN und DOCSTRINGS:
#:      `mutation_check.py` erwaehnt den Laeufer in einer Notiz, `test_manifest_gate.py` und
#:      `audit_candidate_matrix.py` in ihren Docstrings. Gemessen wurde die Erwaehnung, nicht die
#:      Wirkung — genau die Unterscheidung, die der Meta-Test dieser Datei weiter unten schon
#:      trifft ("ein Zitat ist keine Anweisung, eine Anweisung schon").
#:
#: Gemessen wird deshalb am SYNTAXBAUM: ein Aufruf von `unittest.main()` / `pytest.main()`, oder
#: ein Unterprozess, dessen Argumente einen Testlaeufer STARTEN. Prosa ueber Testlaeufer ist
#: keine Ausfuehrung von Testlaeufern.
_UNTERPROZESS = ("run", "call", "check_call", "check_output", "Popen")


def _startet_suite(baum) -> bool:
    """Startet dieses Modul die Suite — ausgefuehrt, nicht erwaehnt?"""
    for k in ast.walk(baum):
        if not isinstance(k, ast.Call):
            continue
        # unittest.main(...) / pytest.main(...) / defaultTestLoader.discover(...)
        if isinstance(k.func, ast.Attribute):
            if k.func.attr in ("main",) and isinstance(k.func.value, ast.Name) \
                    and k.func.value.id in ("unittest", "pytest"):
                return True
            if k.func.attr == "discover":
                return True
            # subprocess.run([... "pytest" ...]) und Verwandte
            if k.func.attr in _UNTERPROZESS:
                woerter = [a.value for a in ast.walk(k)
                           if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                text = " ".join(woerter)
                # SCHARF: ein Laeufer UEBER pytest traegt die Regel (conftest-Haken laeuft mit).
                # Gefaehrlich ist nur der, der die Suite OHNE pytest startet.
                if "pytest" in text:
                    continue
                if "unittest" in text and "discover" in text:
                    return True
    return False


#: EIN FUND GEGEN DIESE DATEI SELBST, und er ist der peinlichste der Runde.
#:
#: Sie erklaert die Klasse "ungeschuetzter Repo-Kontext-Zugriff" fuer geschlossen (*„Sie ist
#: geloescht"*) — und war selbst ihr neuer Traeger: `test_die_doku_verspricht_keinen_laeufer…`
#: las `CONTRIBUTING.md` ungeschuetzt, und die wird vom sdist GAR NICHT ausgeliefert (gemessen:
#: null Treffer im Tarball). Unter pytest deckte `conftest` das als Modul-Skip zu; unter
#: `unittest discover` — dem Laeufer, aus dem `make mutation` seine Toetungszahl ableitet — war es
#: ein FEHLER. Gemessen von einer adversarialen Linse: die Gruendungszahl der Runde
#: ("12 failures und 25 errors auf acht Modulen") stimmte, bis DIESE Datei sie auf 26 Fehler und
#: neun Module verschob. Die Runde hat ihre eigene Begruendungszahl um genau eins entwertet.
#:
#: Nebenwirkung, die dabei sichtbar wurde: weil das Modul einen im sdist fehlenden Wurzelpfad
#: nennt, wird es DORT vollstaendig uebersprungen. Der Waechter, der belegen soll, dass `make
#: test` aus dem ausgelieferten Paket laeuft, laeuft dort selbst nicht mit.


#: WO EIN DOKUMENTIERTER EINSTIEG STEHEN KANN — gemessen, nicht vermutet.
#:
#: DRITTER FUND derselben Klasse an einem Tag (Linsen 51 und 55, unabhaengig voneinander): der
#: Riegel durchsuchte `scripts/*.py`. Er konnte damit strukturell nicht sehen, dass
#:
#:     .github/workflows/ci.yml:89     python -m unittest discover -s tests -v   (Matrix 3.10-3.14)
#:     .github/workflows/ci.yml:166    python -m unittest discover -s tests      (crypto-floor)
#:     .github/PULL_REQUEST_TEMPLATE.md:22   weist Beitragende ebendas an
#:
#: die Suite OHNE pytest fahren. Gemessen an diesem Baum: pytest sammelt 3001, `unittest discover`
#: meldet `Ran 2352, OK` — der CI-Lauf deckt damit rund 78 Prozent und ist trotzdem gruen. Genau
#: der Fehlermodus, den CONTRIBUTING.md in dieser Runde als Begruendung fuer die Streichung der
#: alten Zusage aufgeschrieben hat. Die Zeile 137 derselben Workflow-Datei WEISS es sogar
#: ("the unittest-discover CI job runs only TestCase classes").
#:
#: "Dokumentiert" heisst: eine Stelle, an der ein Mensch oder eine Maschine angewiesen wird, die
#: Suite zu fahren. Das ist das Makefile, der CI-Kanal, und was Beitragenden gesagt wird.
_EINSTIEGSFLAECHEN = (
    ("scripts", "*.py"), ("tools", "*.py"),
    (".github/workflows", "*.yml"), (".github/workflows", "*.yaml"),
)
_DOKUMENTE = (".github/PULL_REQUEST_TEMPLATE.md", "CONTRIBUTING.md", "README.md")

#: DIE HEUTE BEKANNTEN EINSTIEGE OHNE pytest — ausgeschrieben, nicht stillgelegt.
#:
#: Warum hier eine Liste und kein Fix: den CI-Laeufer umzustellen laesst pytest 3001 statt 2352
#: Faelle ueber eine Matrix von fuenf Python-Versionen fahren. Was dabei neu rot wird, ist
#: ungemessen, und das ist release-nah keine Nebenbei-Aenderung. Dasselbe fuer den Mutations-
#: Laeufer, dessen Toetungszahlen sich aendern wuerden. Die Liste ist kein Freibrief: sie ist
#: EXAKT, ein neuer Einstieg faellt sofort auf, ein verschwundener ebenso.
BEKANNTE_LAEUFER_OHNE_PYTEST = [
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/workflows/ci.yml",
    "scripts/mutation_check.py",
]


def _laeufer_ohne_pytest(wurzel) -> list[str]:
    """Dokumentierte Einstiege, die die Suite OHNE pytest starten — Wirkung, nicht Erwaehnung."""
    treffer: set[str] = set()
    for ordner, muster in _EINSTIEGSFLAECHEN:
        d = wurzel / ordner
        if not d.is_dir():
            continue
        for p in sorted(d.glob(muster)):
            try:
                quelle = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if p.suffix == ".py":
                try:
                    if _startet_suite(ast.parse(quelle)):
                        treffer.add(str(p.relative_to(wurzel)))
                except SyntaxError:
                    continue
            else:
                # YAML-Kanal: eine `run:`-Zeile IST Ausfuehrung, kein Zitat. Deshalb wird hier der
                # BEFEHLSTEXT gemessen und nicht die ganze Datei — ein Kommentar ueber den Laeufer
                # (Zeile 137 nennt ihn) darf nicht treffen.
                for z in quelle.splitlines():
                    z = z.strip()
                    if not z.startswith(("run:", "- run:", "-run:")):
                        continue
                    if "pytest" in z:
                        continue
                    if "unittest" in z and "discover" in z:
                        treffer.add(str(p.relative_to(wurzel)))
    for rel in _DOKUMENTE:
        p = wurzel / rel
        if not p.is_file():
            continue
        try:
            quelle = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # In einer Beitragenden-Doku ist eine ANWEISUNG der Gegenstand, nicht ein Vorkommen. Eine
        # Zeile, die den Lauf verlangt (Checkliste, Befehlsblock), zaehlt; ein Satz DARUEBER nicht.
        for z in quelle.splitlines():
            zs = z.strip()
            if "unittest" not in zs or "discover" not in zs:
                continue
            if "pytest" in zs:
                continue
            anweisung = zs.startswith(("- [", "$", "```", "    python", "python", "make")) or "`python -m unittest" in zs
            if anweisung:
                treffer.add(rel)
    return sorted(treffer)


def _zweite_laeufer(wurzel) -> list[str]:
    """Skripte unter `scripts/`, die die Suite STARTEN — unabhaengig vom Namen und vom Fliesstext."""
    ordner = wurzel / "scripts"
    if not ordner.is_dir():
        return []
    treffer = []
    for p in sorted(ordner.glob("*.py")):
        try:
            baum = ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, SyntaxError):
            continue
        if _startet_suite(baum):
            treffer.append(p.name)
    return treffer


SUITE_STARTER = ("unittest discover", "pytest", "run_stdlib_tests")


def _rezept(ziel: str) -> list[str]:
    """Die BEFEHLSZEILEN eines Ziels — ohne reine Ausgaben.

    `@echo …` startet nichts. Ein Gate mass, dass die Vorgaengerfassung das ganze Rezept nach der
    Zeichenkette „pytest" durchsuchte: eine `@echo "pytest is optional"`-Zeile ueber einem
    `unittest discover` liess den Riegel gruen. Ein Wort Prosa hob ihn auf.
    """
    mf = (REPO / "Makefile").read_text(encoding="utf-8")
    zeilen, sammeln = [], False
    for zeile in mf.splitlines():
        if zeile.startswith(f"{ziel}:"):
            sammeln = True
            continue
        if sammeln:
            if zeile.startswith("\t"):
                roh = zeile.strip()
                ohne = roh.lstrip("@-+")
                if ohne.startswith(("echo ", "echo\t", "printf ", "true", ":")):
                    continue
                zeilen.append(roh)
                continue
            break
    return zeilen


def _ziele_die_die_suite_fahren() -> dict[str, list[str]]:
    """JEDES Makefile-Ziel, dessen Befehle eine Suite starten — nicht nur `test`."""
    mf = (REPO / "Makefile").read_text(encoding="utf-8")
    ziele = [z.split(":", 1)[0] for z in mf.splitlines()
             if z and not z.startswith(("\t", "#", " ")) and ":" in z
             and not z.startswith(".PHONY")]
    return {z: b for z in ziele
            if any(st in " ".join(b := _rezept(z)) for st in SUITE_STARTER)}


def _freie_testfunktionen() -> tuple[int, int]:
    """(Module ohne TestCase-Klasse, darin freie `def test_*` Funktionen) — GEMESSEN."""
    module = 0
    funktionen = 0
    for p in sorted((REPO / "tests").glob("test_*.py")):
        try:
            baum = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        hat_tc = any(
            isinstance(k, ast.ClassDef) and any(
                (isinstance(b, ast.Attribute) and b.attr == "TestCase")
                or (isinstance(b, ast.Name) and b.id == "TestCase") for b in k.bases)
            for k in ast.walk(baum))
        frei = sum(1 for k in baum.body
                   if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and k.name.startswith("test_"))
        if not hat_tc and frei:
            module += 1
            funktionen += frei
    return module, funktionen


class DokumentierteLaeufer(unittest.TestCase):

    def test_jedes_ziel_das_die_suite_faehrt_kann_sie_auch_fahren(self):
        """Nicht nur `test`. `make coverage` fuhr ebenfalls `unittest discover` — derselbe Defekt,
        eine Zielzeile tiefer, und der Waechter war nur auf `test:` verdrahtet."""
        ziele = _ziele_die_die_suite_fahren()
        self.assertTrue(ziele, "kein Ziel faehrt eine Suite — die Erhebung misst nichts")
        ohne = {z: b for z, b in ziele.items()
                if not any(w in " ".join(b) for w in LAEUFER_DIE_DIE_SUITE_FAHREN)}
        self.assertFalse(ohne, (
            f"Ziel(e) starten eine Suite mit einem Laeufer, der sie nicht vollstaendig fahren "
            f"kann: {ohne}. Erlaubt: {LAEUFER_DIE_DIE_SUITE_FAHREN}."))

    @unittest.skipUnless((REPO / "CONTRIBUTING.md").is_file(),
                         "CONTRIBUTING.md wird NICHT ausgeliefert — ausserhalb eines Checkouts "
                         "hat diese Pruefung keinen Gegenstand")
    def test_die_doku_verspricht_keinen_laeufer_der_die_suite_nicht_fahren_kann(self):
        """DIE EIGENTLICHE KLASSE: eine Zusage, die der Code nicht halten kann.

        CONTRIBUTING.md sagte „no pytest required, standard library works too". Gemessen ist das
        falsch — und ein Leser, der dem folgt, bekommt einen gruenen Lauf ueber mehrere hundert
        Tests weniger.
        """
        doku = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")
        # NUR DIE BEFEHLSBLOECKE, nicht die ganze Datei.
        #
        # Die erste Fassung suchte die verbotene Zusage im GESAMTEN Text — und fiel sofort ueber
        # meine eigene Korrektur, die den alten Satz ZITIERT, um zu erklaeren, warum er weg ist.
        # Ein Zitat in einer Begruendung ist keine Zusage. Das ist dieselbe Klasse wie ueberall in
        # dieser Runde: gemessen wurde ein VORKOMMEN, gemeint war die EIGENSCHAFT — welchen Befehl
        # die Doku zum Ausfuehren ANWEIST.
        bloecke = re.findall(r"```(?:bash|sh|console)?\n(.*?)```", doku, re.S)
        self.assertTrue(bloecke, "CONTRIBUTING.md fuehrt keine Befehlsbloecke mehr")
        befehle = "\n".join(bloecke)
        stdlib_lauf = re.search(r"^\s*(python[0-9.]*\s+-m\s+)?unittest\s+discover", befehle, re.M)
        self.assertIsNone(stdlib_lauf, (
            f"CONTRIBUTING.md WEIST einen stdlib-Lauf an: {stdlib_lauf.group(0) if stdlib_lauf else ''!r}. "
            f"Gemessen kann diese Suite das nicht — siehe "
            f"test_die_suite_ist_ohne_pytest_nachweislich_unvollstaendig."))
        self.assertIn("pytest -q", befehle, "die Doku nennt keinen lauffaehigen Testbefehl mehr")

    def test_die_suite_ist_ohne_pytest_nachweislich_unvollstaendig(self):
        """DER BELEG fuer die Korrektur, als Messung statt als Behauptung.

        Faellt diese Zahl eines Tages auf null, ist ein stdlib-Lauf wieder ehrlich moeglich — dann
        gehoert die Zusage zurueck, und dieser Test sagt es.
        """
        module, funktionen = _freie_testfunktionen()
        self.assertGreater(funktionen, 0, (
            "es gibt keine freien `def test_*` mehr — ein stdlib-Lauf waere jetzt vollstaendig, "
            "die Korrektur in CONTRIBUTING.md gehoert dann geprueft"))
        mit_pytest_import = sum(
            1 for p in (REPO / "tests").glob("test_*.py")
            if re.search(r"^\s*(import pytest|from pytest)", p.read_text(encoding="utf-8",
                                                                        errors="replace"), re.M))
        self.assertGreater(mit_pytest_import, 0,
                           "kein Modul importiert pytest mehr — dieselbe Pruefung wie oben")

    def test_die_regel_hat_genau_einen_traeger_und_das_ist_belegt(self):
        """Ein Riegel an EINEM Laeufer ist nur dann ein Defekt, wenn es einen zweiten gibt."""
        cf = (REPO / "tests" / "conftest.py").read_text(encoding="utf-8")
        self.assertIn("def pytest_collection_modifyitems", cf,
                      "der Traeger der Repo-Kontext-Regel ist verschwunden")
        # UEBER DIE EIGENSCHAFT, NICHT UEBER DEN NAMEN — und das ist die zweite Fassung.
        #
        # Die erste suchte in `scripts/*.py` nach `stdlib` oder `run_tests` IM NAMEN und behauptete
        # im Kommentar, ein umbenannter Laeufer falle damit ebenfalls auf. Ein deterministischer
        # Pre-Sweep hat diese Behauptung am 02.09.2026 gemessen und WIDERLEGT, in beide Richtungen:
        #
        #     scripts/pruefstand_ohne_pytest.py    startet die Suite -> lief mit `7 passed` DURCH
        #     scripts/run_tests_doku_generator.py  startet nichts    -> fiel zu UNRECHT
        #
        # Das war dieselbe Klasse, gegen die diese ganze Runde steht — an den BEZEICHNER gebunden
        # statt an die EIGENSCHAFT —, begangen im Fix gegen ebendiese Klasse. Der Kommentar, der
        # das Gegenteil behauptete, ist damit auch ein Fund: er war eine unbelegte Zusage.
        #
        # Die Eigenschaft eines zweiten Laeufers ist, dass er die SUITE STARTET. Das steht im
        # Inhalt, nicht im Namen.
        #
        # Zweiter Grund, unveraendert gueltig: die Ableitung in `tests/conftest.py` stuft ein
        # Testmodul als "braucht einen Checkout" ein, sobald es einen wurzel-relativen Pfad nennt,
        # den es HIER NICHT GIBT. Eine ABWESENHEITS-Behauptung sieht fuer sie genauso aus wie ein
        # fehlender Checkout. Mit einem Pfad-Literal meldete `test_im_echten_checkout_...` genau
        # dieses Modul als uebersprungen, also rot. Ihr Waechter hatte recht.
        self.assertEqual(_laeufer_ohne_pytest(REPO), BEKANNTE_LAEUFER_OHNE_PYTEST, (
            f"die Menge der dokumentierten Einstiege OHNE pytest hat sich geaendert: gemessen "
            f"{_laeufer_ohne_pytest(REPO)}, bekannt {BEKANNTE_LAEUFER_OHNE_PYTEST}. Ein NEUER heisst, die "
            f"Regel braucht wieder zwei Traeger. Ein VERSCHWUNDENER ist eine gute Nachricht, "
            f"gehoert aber nachgezogen, sonst deckt die Liste beim naechsten Mal zu viel."))

    def test_meta_ein_zitat_ist_keine_anweisung_eine_anweisung_schon(self):
        """META fuer den eigenen Fehltritt: die Pruefung misst die ANWEISUNG, nicht das Vorkommen."""
        zitat = 'Text davor\n\n> This used to say "python -m unittest discover -s tests".\n'
        anweisung = "Text davor\n\n```bash\npython -m unittest discover -s tests\n```\n"
        def weist_an(md: str) -> bool:
            bloecke = re.findall(r"```(?:bash|sh|console)?\n(.*?)```", md, re.S)
            return bool(re.search(r"^\s*(python[0-9.]*\s+-m\s+)?unittest\s+discover",
                                  "\n".join(bloecke), re.M))
        self.assertFalse(weist_an(zitat), "ein ZITAT wird als Anweisung gelesen — Fehlalarm")
        self.assertTrue(weist_an(anweisung), "eine ANWEISUNG wird nicht gelesen — die Pruefung ist blind")

    def test_meta_ein_regelloser_laeufer_wird_gefangen(self):
        """META. Der Befehl, der den Befund erzeugt hat, MUSS durchfallen — auch mit Prosa davor."""
        for regellos in ("python3 -m unittest discover -s tests -v",
                         "$(PYTHON) -m unittest discover -s tests",
                         "$(PYTHON) -m coverage run -m unittest discover -s tests"):
            self.assertFalse(any(w in regellos for w in LAEUFER_DIE_DIE_SUITE_FAHREN),
                             f"{regellos!r} gilt als lauffaehig — dann faengt die Pruefung nichts")
        self.assertTrue(any(w in "$(PYTHON) -m pytest -q" for w in LAEUFER_DIE_DIE_SUITE_FAHREN),
                        "die Gegenrichtung traegt nicht — die Pruefung waere immer rot")

    def test_meta_eine_echo_zeile_zaehlt_nicht_als_laeufer(self):
        """META fuer den gemessenen Exploit: Prosa im Rezept ist kein Befehl."""
        for b in _rezept("test"):
            self.assertFalse(b.lstrip("@-+").startswith("echo "),
                             f"eine echo-Zeile ist in den Befehlen gelandet: {b!r}")


if __name__ == "__main__":
    unittest.main()


#: DER ENDSTAND, GEMESSEN — nicht behauptet.
#:
#: `make test` aus dem ECHTEN entpackten sdist dieses Baums, mit dem heutigen Makefile:
#:
#:     2811 passed · 181 skipped · 0 failed · rc=0
#:
#: Zum Vergleich der Ausgangszustand derselben Messung: 12 failures / 25 errors / rc=1. Und der
#: Nachbar `coverage:`, der beim ersten Anlauf zwei Zeilen zu frueh ungefixt blieb, fuhr damals
#: `unittest discover` und reproduzierte den Ausgangsbefund vollstaendig — heute faehrt er
#: dieselbe pytest-Zeile. Der Klassenfix endet nicht mehr an einer Makefile-Zeile.
