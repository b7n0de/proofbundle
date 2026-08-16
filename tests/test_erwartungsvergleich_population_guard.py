"""Jeder Erwartungsvergleich ueber Zeichenketten braucht ein Beinahe-Treffer-Korpus.

WARUM DIESE DATEI EXISTIERT — und sie ist die zweite ihrer Art, was der eigentliche Punkt ist.
`audit_artifacts/380/FINDING_erwartungsvergleich_klasse.md` wurde am 2026-08-16 als "7 von 7
Mitgliedern" geschlossen. Der DEEP-Lauf am 2026-08-17 hat die Grundmenge GEMESSEN statt sie zu
uebernehmen: 14 Vergleichsstellen an 10 Parametern, davon 8 gedeckt. Die Klasse war ueber eine
HANDGEPFLUECKTE Mitgliederliste geschlossen worden, nicht ueber eine abgeleitete — dieselbe
Fehlerform, die `test_never_raise_population_guard.py` einen Tag zuvor fuer die never-raise-Familie
festgehalten hat.

Zweimal dieselbe Form in zwei Tagen heisst: das Problem ist nicht die einzelne Liste, sondern dass
eine Klasse ueberhaupt ueber eine Liste geschlossen wird. Deshalb leitet dieser Waechter seine
Grundmenge aus dem BAUM ab und nicht aus einer Aufzaehlung.

WAS ER MISST. Jeden `==`/`!=`-Vergleich, an dem ein PARAMETER der umgebenden Funktion beteiligt ist,
dessen Name mit `expected_` beginnt. Und zwar:
  - ein Parameter, kein Modul-Global und kein aufgerufener Name. `expected_key_id(ident)` ist ein
    FUNKTIONSAUFRUF; die erste Fassung dieser Messung zaehlte ihn mit und blies den Befund auf.
  - die Korpus-Abdeckung wird ueber den PARAMETERNAMEN gesucht, nicht ueber die Schreibform des
    Aufrufs. Die erste Fassung suchte einzeilig und uebersah `test_kbjwt.py`, wo `pruefe_exakt(`
    ueber zwei Zeilen steht — zwei gedeckte Parameter galten faelschlich als ungedeckt.
Beide Fehler fing die Gegenprobe VOR der Behauptung. Sie stehen hier, weil ein Waechter, dessen
Messfehler nicht dokumentiert sind, beim naechsten Umbau still wieder eingebaut wird.

DIE AUSNAHME IST ABGELEITET, NICHT HANDVERLESEN. Ein Parameter, dessen Annotation kein `str`
zulaesst, ist ausgenommen: ein Beinahe-Treffer-Korpus ueber Gross/Klein, Leerzeichen und
Unicode-Formen hat auf einer Zahl keinen Gegenstand. `expected_tree_size: Optional[int]` faellt so
heraus, und zwar weil die Annotation es sagt — nicht weil jemand es eingetragen hat. Waechst der
Baum um einen `str`-Parameter, ist er am selben Tag drin.

DREI ZUSTAENDE: gedeckt · ungedeckt (FEHLER) · ausgenommen mit ableitbarem Grund. Ein Parameter,
dessen Annotation sich nicht lesen laesst, gilt als UNGEDECKT und nicht als ausgenommen — im
Zweifel fordern, nicht erlassen.
"""
from __future__ import annotations

import ast
import pathlib
import re
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_SRC = _REPO / "src" / "proofbundle"
_TESTS = _REPO / "tests"


def _parameter(fn: ast.AST) -> dict:
    """Parametername -> Annotation als Quelltext (oder '' wenn keine)."""
    a = getattr(fn, "args", None)
    if a is None:
        return {}
    alle = list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
    return {x.arg: (ast.unparse(x.annotation) if x.annotation is not None else "")
            for x in alle}


def _nimmt_zeichenkette(annotation: str) -> bool:
    """Kann dieser Parameter eine Zeichenkette sein? Ohne Annotation: JA (im Zweifel fordern)."""
    if not annotation:
        return True
    return "str" in annotation


def vergleichsstellen() -> list[tuple[str, int, str, str, str]]:
    """(datei, zeile, parameter, funktion, annotation) je Vergleich gegen einen expected_*-Parameter."""
    aus: list[tuple[str, int, str, str, str]] = []
    for p in sorted(_SRC.rglob("*.py")):
        try:
            baum = ast.parse(p.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            continue
        for fn in ast.walk(baum):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            par = _parameter(fn)
            erwartungen = {k for k in par if k.startswith("expected_")}
            if not erwartungen:
                continue
            aufgerufen = {n.func.id for n in ast.walk(fn)
                          if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            for k in ast.walk(fn):
                if not isinstance(k, ast.Compare):
                    continue
                if not any(isinstance(o, (ast.Eq, ast.NotEq)) for o in k.ops):
                    continue
                namen = {n.id for n in ast.walk(k) if isinstance(n, ast.Name)}
                for t in sorted(namen & erwartungen):
                    if t in aufgerufen:
                        continue
                    aus.append((str(p.relative_to(_REPO)), k.lineno, t, fn.name, par[t]))
    return aus


def vom_korpus_gedeckt() -> set[str]:
    """Parameternamen, die irgendwo durch `pruefe_exakt` gefahren werden."""
    aus: set[str] = set()
    for p in sorted(_TESTS.glob("test_*.py")):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"pruefe_exakt\(", txt):
            fenster = txt[m.start():m.start() + 400]
            # ZIFFERN GEHOEREN IN DIE KLASSE. Die erste Fassung schrieb `[a-z_]+` und uebersah
            # damit `expected_root_b64` — den EINZIGEN Parameter mit Ziffern im Namen. Das
            # Muster war aus den Beispielen abgeschrieben, die gerade vor mir lagen, und die
            # waren alle ziffernlos. Wirkung: der Waechter forderte ein Korpus, das es laengst
            # gab — er meldete also eine Luecke zu viel, nicht zu wenig. Falsch ist beides.
            aus.update(re.findall(r"\b(expected_[a-z0-9_]+)\s*=", fenster))
    return aus


class JederZeichenkettenVergleichHatEinKorpus(unittest.TestCase):

    def test_der_messaufbau_findet_ueberhaupt_etwas(self) -> None:
        """Gegenprobe zuerst. Eine tote Suche sieht aus wie ein makelloses Ergebnis."""
        st = vergleichsstellen()
        self.assertGreaterEqual(len(st), 10,
                                f"nur {len(st)} Vergleichsstellen gefunden — das Muster ist tot, "
                                "und ein gruenes Urteil darauf bedeutet nichts")
        self.assertTrue(vom_korpus_gedeckt(),
                        "kein einziger Parameter als korpus-gedeckt erkannt — die zweite Haelfte "
                        "der Messung ist tot")

    def test_kein_zeichenketten_vergleich_ohne_korpus(self) -> None:
        gedeckt = vom_korpus_gedeckt()
        offen: dict[str, list[str]] = {}
        for datei, zeile, param, fn, ann in vergleichsstellen():
            if param in gedeckt or not _nimmt_zeichenkette(ann):
                continue
            offen.setdefault(param, []).append(f"{datei}:{zeile} in {fn}()")
        self.assertEqual(
            offen, {},
            f"{len(offen)} Erwartungsvergleich(e) ueber Zeichenketten ohne Beinahe-Treffer-Korpus: "
            f"{offen}. Jeder von ihnen laesst sich auf startswith/casefold/strip lockern, ohne dass "
            "ein Test es merkt — genau die Klasse, die diese Runde fuer acht andere Parameter "
            "geschlossen hat. Korpus aus tests/_beinahe_treffer.py anhaengen.")

    def test_die_ausnahme_ist_abgeleitet_nicht_gepflegt(self) -> None:
        """Die Ausnahme muss aus der Annotation folgen, sonst ist sie eine Liste mit anderem Namen.

        Positiv UND negativ geprueft: eine int-Annotation nimmt keine Zeichenkette, eine
        str-Annotation und eine FEHLENDE Annotation sehr wohl. Die fehlende ist der wichtige Fall —
        im Zweifel wird gefordert, nicht erlassen.
        """
        self.assertFalse(_nimmt_zeichenkette("Optional[int]"))
        self.assertFalse(_nimmt_zeichenkette("int | None"))
        self.assertTrue(_nimmt_zeichenkette("str | None"))
        self.assertTrue(_nimmt_zeichenkette("Optional[str]"))
        self.assertTrue(_nimmt_zeichenkette(""), "ohne Annotation muss gefordert werden")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
