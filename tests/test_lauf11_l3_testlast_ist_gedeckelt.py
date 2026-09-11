"""Ein Budget-Wert wird BEHAUPTET oder GEDECKELT — nie roh in eine Testlast geführt.

WAS HIER GESCHLOSSEN WIRD. Deep Gate Lauf 11, Fund `LAUF11-L3`: `HARTER_LASTDECKEL`
(`tests/test_budget.py`) deckelte genau EINE Achse, `data_digests`. Die übrigen bauen ihre Last
weiter direkt aus der geprüften Konstante.

WARUM DAS ZÄHLT, gemessen am 11.09.2026: ein Mutationsoperator, der eine Budget-Konstante
hochsetzt (`idx=90`: `data_digests: 2.000 -> 2.000.000.000`), steuert damit die GRÖSSE der
Testlast. Drei Sampler massen 428,9 -> 51.129,2 MiB in 58 s (rund 874 MiB/s); unter `RLIMIT_AS`
von 6 GiB endete derselbe Ausdruck nach 7,87 s mit `MemoryError`. Auf dem Runner ist das kein
Fehlschlag des Tests, sondern sein **Tod** — und ein toter Test tötet den Mutanten nicht, er
meldet SIGKILL.

DIE EIGENSCHAFT, über die dieser Riegel quantifiziert, und sie ist bewusst nicht „jede Achse hat
einen Deckel": jeder Ausdruck, der einen Budget-Wert LIEST, steht entweder in einer **Zusicherung**
über diesen Wert (dann ist er die Aussage, nicht die Last) oder ist durch
`min(..., HARTER_LASTDECKEL)` **begrenzt** (dann ist er die Last, nicht die Aussage). Beides
zugleich ist der richtige Bau: die Zusicherung lässt den Mutanten an der Aussage sterben, der
Deckel hält den Lauf am Leben, damit er das kann.

Der Riegel liest den AST. Eine Aufzählung der heute bekannten Achsen wäre beim nächsten neuen
Budget-Feld stillschweigend zu kurz — dieselbe Klasse, gegen die er steht.
"""
from __future__ import annotations

import ast
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
DECKEL_NAME = "HARTER_LASTDECKEL"
BUDGET_NAMEN = ("DEFAULT_BUDGET", "budget")

#: Aufrufe, deren Argument eine Aussage ÜBER den Wert ist statt eine Last AUS ihm.
_ZUSICHERUNGEN = {"assertLess", "assertLessEqual", "assertGreater", "assertGreaterEqual",
                  "assertEqual", "assertNotEqual", "assertTrue", "assertFalse", "assertIn",
                  "assertIsNone", "assertIsNotNone", "within", "check"}


def _liest_budget(knoten: ast.AST) -> bool:
    """Enthält der Teilbaum einen Attributzugriff auf ein Budget-Objekt?"""
    for k in ast.walk(knoten):
        if isinstance(k, ast.Attribute) and isinstance(k.value, ast.Name) and k.value.id in BUDGET_NAMEN:
            return True
    return False


def _ist_gedeckelt(knoten: ast.AST) -> bool:
    """Ist die Groesse im Teilbaum begrenzt — durch `gedeckelt(...)` oder `min(..., DECKEL)`?

    ZWEI SCHREIBWEISEN, EINE EIGENSCHAFT: `gedeckelt()` aus `tests/_lastdeckel.py` ist der Weg,
    `min(..., HARTER_LASTDECKEL)` die aeltere Form, die `test_budget.py` zuerst trug. Beide
    begrenzen; der Riegel bindet an die Wirkung, nicht an eine davon.
    """
    for k in ast.walk(knoten):
        if isinstance(k, ast.Call) and getattr(k.func, "id", None) == "gedeckelt":
            return True
        if (isinstance(k, ast.Call) and getattr(k.func, "id", None) == "min"
                and any(isinstance(a, ast.Name) and a.id == DECKEL_NAME for a in k.args)):
            return True
    return False


def ungedeckelte_lastquellen(datei: Path) -> list[str]:
    """'datei:zeile — code' für jede Stelle, an der ein Budget-Wert die GRÖSSE einer erzeugten
    Datenstruktur bestimmt, ohne durch `min(..., HARTER_LASTDECKEL)` begrenzt zu sein.

    ZWEISTUFIG, und der Grund steht in der ersten Fassung dieses Riegels: sie meldete JEDE
    Zuweisung aus einem Budget-Wert und traf damit `knapp_drunter = 2 ** (int_bits - 1)` (eine
    ZAHL, keine Last) und `_SL = DEFAULT_BUDGET.string_len` (eine Konstante, aus der erst später
    etwas gebaut wird). Ein Riegel, der an der Schreibweise bindet statt an der Wirkung, erzeugt
    Fehlalarme — und ein Riegel mit Fehlalarmen wird umgangen statt gelesen. Gemessen: 9 Treffer,
    davon mindestens 4 ohne Last.

    Stufe 1 sammelt Namen, die aus einem Budget-Wert abgeleitet sind. Stufe 2 meldet nur, wo ein
    solcher Name ODER ein direkter Budget-Zugriff in einem LAST-Kontext steht: `range(...)` oder
    eine Wiederholung `x * n`. Eine Potenz ist kein Last-Kontext.
    """
    quelle = datei.read_text(encoding="utf-8")
    try:
        baum = ast.parse(quelle)
    except SyntaxError:
        return []
    zeilen = quelle.splitlines()

    ausgenommen: set[int] = set()
    for k in ast.walk(baum):
        if isinstance(k, ast.Call):
            name = k.func.attr if isinstance(k.func, ast.Attribute) else getattr(k.func, "id", "")
            if name in _ZUSICHERUNGEN:
                for kind in ast.walk(k):
                    ausgenommen.add(id(kind))
        if isinstance(k, ast.Assert):
            for kind in ast.walk(k):
                ausgenommen.add(id(kind))

    # Stufe 1: Namen, die eine aus einem Budget-Wert abgeleitete GRÖSSE tragen.
    abgeleitet: dict[str, int] = {}
    for k in ast.walk(baum):
        if isinstance(k, ast.Assign) and _liest_budget(k.value) and not _ist_gedeckelt(k.value):
            for ziel in k.targets:
                if isinstance(ziel, ast.Name):
                    abgeleitet[ziel.id] = k.lineno

    def _groesse_aus_budget(knoten: ast.AST) -> bool:
        if _liest_budget(knoten):
            return True
        for kk in ast.walk(knoten):
            if isinstance(kk, ast.Name) and kk.id in abgeleitet:
                return True
        return False

    treffer: list[str] = []
    gemeldete_zeilen: set[int] = set()
    for k in ast.walk(baum):
        # LAST-KONTEXT, und nur dieser: range(n) und die Wiederholung x * n. `2 ** n` ist eine Zahl.
        kandidat = None
        if isinstance(k, ast.Call) and getattr(k.func, "id", None) == "range":
            if any(_groesse_aus_budget(a) for a in k.args):
                kandidat = k
        elif isinstance(k, ast.BinOp) and isinstance(k.op, ast.Mult):
            if _groesse_aus_budget(k.left) or _groesse_aus_budget(k.right):
                kandidat = k
        if kandidat is None or id(kandidat) in ausgenommen:
            continue
        if _ist_gedeckelt(kandidat):
            continue
        # Die MELDUNG zeigt auf die Ableitung, wenn es eine gibt — dort gehört der Deckel hin.
        zl = kandidat.lineno
        for kk in ast.walk(kandidat):
            if isinstance(kk, ast.Name) and kk.id in abgeleitet:
                zl = abgeleitet[kk.id]
                break
        if zl in gemeldete_zeilen:
            continue
        gemeldete_zeilen.add(zl)
        treffer.append(f"{datei.name}:{zl} — {zeilen[zl - 1].strip()[:100]}")
    return treffer


def last_achsen(dateien) -> set[str]:
    """Die Budget-Achsen, die im Baum tatsaechlich eine Last bestimmen — abgeleitet, nicht getippt.

    Warum abgeleitet: `renewal_work` ist 40.000.000 und damit weit ueber jedem Deckel, aber es ist
    ein ARBEITS-Budget (Kette x Digests), aus dem nie eine Liste gebaut wird. Eine getippte Liste
    der Lastachsen waere beim naechsten neuen Feld still zu kurz oder zu lang; diese hier liest,
    was der Baum tut.
    """
    achsen: set[str] = set()
    for f in dateien:
        try:
            baum = ast.parse(f.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for k in ast.walk(baum):
            ist_last = (isinstance(k, ast.Call) and getattr(k.func, "id", None) == "range") or \
                       (isinstance(k, ast.BinOp) and isinstance(k.op, ast.Mult))
            if not ist_last:
                continue
            for kk in ast.walk(k):
                if isinstance(kk, ast.Attribute) and isinstance(kk.value, ast.Name) \
                        and kk.value.id in BUDGET_NAMEN:
                    achsen.add(kk.attr)
    return achsen


class TestKeineUngedeckelteTestlast(unittest.TestCase):

    def test_kein_test_baut_eine_ungedeckelte_last_aus_einem_budget_wert(self):
        offen: list[str] = []
        for f in sorted(TESTS.glob("test_*.py")):
            offen.extend(ungedeckelte_lastquellen(f))
        self.assertEqual(
            offen, [],
            "diese Stellen leiten eine Testlast direkt aus einem Budget-Wert ab, ohne Deckel: ein "
            "Mutationsoperator, der die Konstante hochsetzt, steuert damit den Speicherbedarf des "
            "Laufs und tötet den Test, statt von ihm getötet zu werden:\n  " + "\n  ".join(offen))

    def test_der_deckel_schneidet_keinen_legitimen_wert_ab(self):
        """DIE GEGENRICHTUNG, und ohne sie ist der Deckel ein Schaden statt eines Schutzes: kein
        heute geltender Budget-Wert darf durch ihn gekuerzt werden. Sonst prueft ein Test, der die
        Grenze erreichen will, sie nie mehr — und faellt gruen aus, weil er zu klein geworden ist.

        Die erste Fassung deckelte auf 100.000 Elemente quer ueber alle Achsen und haette
        `string_len` (1.000.000) auf ein Zehntel gekuerzt. Diese Zusicherung haette das gefangen.
        """
        sys.path.insert(0, str(TESTS))
        from _lastdeckel import gedeckelt  # noqa: PLC0415
        from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415
        # DIESELBE Tabelle wie die Aufrufstellen, aus _lastdeckel importiert statt hier getippt:
        # zwei Tabellen mit demselben Zweck sind zwei Wahrheiten, und die zweite altert unbemerkt.
        from _lastdeckel import KOSTEN_JE_ELEMENT  # noqa: PLC0415
        byte_achsen = {"string_len", "input_bytes"}
        # NUR die Achsen, aus denen der Baum wirklich eine Last baut. `renewal_work` (40.000.000)
        # ist ein ARBEITS-Budget, kein Elementzaehler — es erzeugt nie eine Liste, und ein Deckel
        # darauf waere eine Zahl ohne Gegenstand. Gemessen beim Bau dieses Tests: er meldete genau
        # diese eine Achse, und die Meldung war seine, nicht die des Deckels.
        achsen = last_achsen(sorted(TESTS.glob("test_*.py")))
        self.assertTrue(achsen, "keine Lastachse gefunden — dann misst dieser Test nichts")
        gekuerzt = []
        for dim in sorted(achsen):
            wert = getattr(DEFAULT_BUDGET, dim, None)
            if not isinstance(wert, int) or isinstance(wert, bool):
                continue
            bje = KOSTEN_JE_ELEMENT.get(dim, 64)
            g = gedeckelt(wert, bytes_je_element=bje)
            if g < wert:
                gekuerzt.append(f"{dim}: {wert:,} -> {g:,} (bytes_je_element={bje})")
        self.assertEqual(
            gekuerzt, [],
            "der Deckel kuerzt einen LEGITIMEN Budget-Wert — jeder Test, der diese Grenze erreichen "
            "will, prueft sie danach nicht mehr und wird gruen, weil er zu klein ist:\n  "
            + "\n  ".join(gekuerzt))

    def test_meta_eine_gepflanzte_ungedeckelte_last_wird_gefangen(self):
        """PLANT-AND-MUST-CATCH, in drei Formen: direkt in range(), über eine Zwischenvariable und
        als Wiederholung."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "test_gepflanzt.py"
            f.write_text(
                "from proofbundle.budget import DEFAULT_BUDGET\n"
                "def test_direkt():\n"
                "    xs = [i for i in range(DEFAULT_BUDGET.witnesses + 1)]\n"
                "def test_indirekt():\n"
                "    over = DEFAULT_BUDGET.signatures + 1\n"
                "    ys = list(range(over))\n"
                "def test_wiederholung():\n"
                "    s = 'a' * DEFAULT_BUDGET.string_len\n", encoding="utf-8")
            gefunden = ungedeckelte_lastquellen(f)
            self.assertEqual(len(gefunden), 3, f"nicht alle drei Formen gefangen: {gefunden}")

    def test_anti_tautologie_die_gedeckelte_form_wird_NICHT_gemeldet(self):
        """Die Gegenrichtung: der korrekt gebaute Test darf nicht melden — sonst misst der Riegel
        nur, ob das Wort DEFAULT_BUDGET vorkommt."""
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "test_sauber.py"
            f.write_text(
                "from proofbundle.budget import DEFAULT_BUDGET\n"
                "HARTER_LASTDECKEL = 100_000\n"
                "class T:\n"
                "    def test_ok(self):\n"
                "        self.assertLessEqual(DEFAULT_BUDGET.witnesses, HARTER_LASTDECKEL)\n"
                "        over = min(DEFAULT_BUDGET.witnesses, HARTER_LASTDECKEL) + 1\n"
                "        xs = list(range(over))\n", encoding="utf-8")
            self.assertEqual(ungedeckelte_lastquellen(f), [],
                             "der Riegel meldet die korrekt gedeckelte Form — dann misst er die "
                             "Schreibweise, nicht die Eigenschaft")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
