"""Die Extraktion im Bauweg glaubt dem Archiv nicht — auch nicht dem eigenen.

Fangnachweis zu ``scripts/build_reproducible.py::_entpacke_sicher``. Anlass: CodeQL meldete auf dem
6.0.0-Kandidaten ``py/tarslip`` (Alert 114, hohe Schwere) an der Stelle, die das selbst gebaute
sdist auspackt. Dort stand ``tf.extractall(...)`` mit einem ``noqa`` und der Begruendung "eigenes,
soeben gebautes Archiv". Die Begruendung war inhaltlich richtig und als Schutz wertlos: sie ist ein
Satz, kein Riegel, und sie wandert nicht mit, wenn jemand den Bauweg aendert.

Gepinnt wird die EIGENSCHAFT an synthetischen Archiven, nicht am echten sdist — ein Test, der das
echte sdist baut, misst den Bau und nicht die Extraktion, und er braeuchte Minuten statt
Millisekunden.
"""
from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _modul():
    spec = importlib.util.spec_from_file_location(
        "br_unter_test", REPO / "scripts" / "build_reproducible.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _archiv(pfad: Path, eintraege) -> None:
    """Ein tar.gz bauen. `eintraege` ist eine Folge von (name, typ, inhalt_oder_ziel)."""
    with tarfile.open(pfad, "w:gz") as tf:
        for name, typ, wert in eintraege:
            info = tarfile.TarInfo(name=name)
            if typ == "datei":
                daten = wert.encode("utf-8")
                info.size = len(daten)
                tf.addfile(info, io.BytesIO(daten))
            elif typ == "ordner":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            elif typ == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = wert
                tf.addfile(info)
            else:                                   # pragma: no cover — Testfehler, kein Zustand
                raise AssertionError(f"unbekannter Typ {typ!r}")


class DieExtraktionGlaubtDemArchivNicht(unittest.TestCase):

    def setUp(self):
        self.mod = _modul()
        self._tmp = tempfile.TemporaryDirectory(prefix="entpacken-")
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _entpacke(self, eintraege):
        quelle = self.dir / "a.tar.gz"
        _archiv(quelle, eintraege)
        ziel = self.dir / "aus"
        ziel.mkdir(exist_ok=True)
        with tarfile.open(quelle, "r:gz") as tf:
            self.mod._entpacke_sicher(tf, ziel)
        return ziel

    def test_ein_harmloses_archiv_wird_ausgepackt(self):
        """Die Kontrolle. Ohne sie waere ein Riegel, der ALLES ablehnt, ebenfalls gruen."""
        ziel = self._entpacke([("paket", "ordner", None),
                               ("paket/setup.py", "datei", "print('hallo')\n")])
        self.assertTrue((ziel / "paket" / "setup.py").is_file())
        self.assertEqual((ziel / "paket" / "setup.py").read_text(encoding="utf-8"),
                         "print('hallo')\n")

    def test_ein_mitglied_mit_punkt_punkt_wird_abgelehnt(self):
        """Der klassische Ausbruch nach oben."""
        with self.assertRaises(RuntimeError) as ctx:
            self._entpacke([("../entkommen.txt", "datei", "boese")])
        self.assertIn("escapes", str(ctx.exception))

    def test_ein_absoluter_pfad_wird_abgelehnt(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._entpacke([("/tmp/entkommen.txt", "datei", "boese")])
        self.assertIn("escapes", str(ctx.exception))

    def test_ein_symlink_wird_abgelehnt_auch_wenn_sein_pfad_harmlos_aussieht(self):
        """Der Fall, den eine reine PFAD-Pruefung durchlaesst.

        `harmlos` liegt sauber im Zielordner — sein ZIEL zeigt hinaus. Wer nur den Namen prueft,
        sieht daran nichts.
        """
        with self.assertRaises(RuntimeError) as ctx:
            self._entpacke([("harmlos", "symlink", "/etc/passwd")])
        self.assertIn("neither a regular file nor a directory", str(ctx.exception))

    def test_nichts_wird_geschrieben_wenn_ein_einziges_mitglied_faellt(self):
        """Alles-oder-nichts: die Pruefung laeuft VOR der ersten Extraktion.

        Ein Riegel, der Mitglied fuer Mitglied prueft UND auspackt, haette die harmlose Datei
        schon geschrieben, bevor er das boese Mitglied erreicht — und ein halb ausgepacktes
        Archiv sieht aus wie ein geglueckter Lauf.
        """
        quelle = self.dir / "gemischt.tar.gz"
        _archiv(quelle, [("gut.txt", "datei", "ok"), ("../boese.txt", "datei", "nein")])
        ziel = self.dir / "aus2"
        ziel.mkdir()
        with tarfile.open(quelle, "r:gz") as tf, self.assertRaises(RuntimeError):
            self.mod._entpacke_sicher(tf, ziel)
        self.assertEqual(sorted(p.name for p in ziel.iterdir()), [],
                         "der Zielordner muss leer bleiben, wenn die Pruefung faellt")

    def test_die_aufrufstelle_benutzt_den_riegel_und_nicht_extractall(self):
        """Ein Riegel ohne Aufrufer ist keine Faehigkeit.

        GEMESSEN AM SYNTAXBAUM, NICHT AM TEXT — und der erste Anlauf zeigte, warum. Er suchte die
        Zeichenkette ``tf.extractall(`` im Quelltext und wurde rot: getroffen hat er den DOCSTRING
        von ``_entpacke_sicher``, der genau diesen alten Aufruf zitiert, um zu erklaeren, was dort
        frueher stand. Ein Zitat ist keine Anweisung. Dieselbe Unterscheidung trifft
        ``tests/test_dokumentierte_laeufer_koennen_die_suite_fahren.py`` fuer Suite-Laeufer, mit
        derselben Begruendung.
        """
        import ast                                                        # noqa: PLC0415
        quelle = (REPO / "scripts" / "build_reproducible.py").read_text(encoding="utf-8")
        baum = ast.parse(quelle)
        nackte = [k for k in ast.walk(baum)
                  if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                  and k.func.attr == "extractall"]
        self.assertEqual(nackte, [],
                         "die Aufrufstelle ist auf einen nackten extractall-AUFRUF "
                         f"zurueckgefallen (Zeile(n) {[k.lineno for k in nackte]})")
        gerufen = [k for k in ast.walk(baum)
                   if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                   and k.func.id == "_entpacke_sicher"]
        self.assertEqual(len(gerufen), 1,
                         "der Riegel muss genau einmal AUFGERUFEN werden, nicht nur existieren")


if __name__ == "__main__":
    unittest.main()
