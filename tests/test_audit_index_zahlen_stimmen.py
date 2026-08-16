"""Die Zahlen im Akten-Index muessen zur tatsaechlichen Aktenlage passen.

WARUM ES DIESEN TEST GIBT. Der Index einer versionsbezogenen Akte fasst zusammen, wie viele Befunde
sie fuehrt und wie viele davon Altbefunde sind. Diese Zahl ist beim Schreiben richtig und wird beim
naechsten hinzugefuegten Befund STILL falsch — genau das ist am 2026-08-16 zweimal passiert:

  1. "all five are on main"        -> gemessen vier von fuenf
  2. "FOUR of the five"            -> korrekt, bis ein sechster Befund dazukam

Beide Male stand die falsche Zahl in dem Dokument, das ein Pruefer ZUERST oeffnet, und beide Male
verwischte sie eine Zustaendigkeit: ein Altbefund wird GEMELDET, ein Befund dieses Release wird
REPARIERT. Ein Sammelbegriff, der die beiden vermischt, nimmt dem Leser genau die Unterscheidung.

Der Fall ist nicht besonders. Er ist die haeufigste Fehlerklasse dieser Runde — eine Zahl ueber eine
Population gemessen und ueber eine andere berichtet — und die Runde hat gemessen, dass ein VORSATZ
sie nicht verhindert (sieben Faelle, null davon von Hand gefangen, bevor sie geschrieben waren). Ein
Test verhindert sie.

DIE REGEL, NICHT DER FALL: geprueft wird JEDE `audit_artifacts/<token>/00_INDEX.md`, nicht die eine
von 3.8.0. Eine Akte ohne Index ist kein Fehler (aeltere Releases hatten eine einzige Datei); ein
Index, dessen Zahl nicht stimmt, schon.
"""
from __future__ import annotations

import pathlib
import re
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_AKTEN = _REPO / "audit_artifacts"

# "FIVE of the six are on `main`" — Wort-Zahlen, weil der Index Prosa ist und bleiben soll.
_WORTZAHL = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
             "seven": 7, "eight": 8, "nine": 9, "ten": 10}
_AUSSAGE = re.compile(r"\b(" + "|".join(_WORTZAHL) + r")\s+of\s+the\s+(" + "|".join(_WORTZAHL) + r")\b",
                      re.IGNORECASE)
_ALTBEFUND_ZEILE = re.compile(r"->\s*Altbefund\s*$", re.MULTILINE)
_TABELLENZEILE = re.compile(r"^\|\s*`(FINDING_[A-Za-z0-9_]+\.md)`", re.MULTILINE)


def _indizes() -> list[pathlib.Path]:
    if not _AKTEN.is_dir():
        return []
    return sorted(p for p in _AKTEN.glob("*/00_INDEX.md") if p.is_file())


def _im_checkout() -> bool:
    """Repo-Checkout oder ausgeliefertes sdist? Gelesen aus conftest, der EINEN Quelle dafuer.

    Nicht nachgebaut: `_REPO_ONLY_MARKERS` hier ein zweites Mal zu pruefen waere eine zweite
    Messstelle fuer dieselbe Groesse und damit die naechste Drift. `tests/test_sdist_packaging_361`
    importiert conftest aus demselben Grund direkt.
    """
    try:
        from conftest import running_in_repo_checkout
    except Exception:                                     # noqa: BLE001
        return _AKTEN.is_dir()      # ohne conftest: die beobachtbare Tatsache statt eine Annahme
    return running_in_repo_checkout()


# DIESER TEST WIRD AUSGELIEFERT (`MANIFEST.in: graft tests`), UND SEIN GEGENSTAND NICHT
# (`prune audit_artifacts`). Gemessen an einem echt gebauten und entpackten sdist: ohne diese Zeile
# faellt `test_es_gibt_ueberhaupt_etwas_zu_pruefen` bei jedem Nutzer, der die mitgelieferte Suite
# faehrt — eine legitime Abwesenheit als Fehler ausgegeben. Die drei anderen Tests waeren dort
# still gruen durchgelaufen (leere Schleife), was die schlechtere Haelfte desselben Fehlers ist.
# Deshalb SKIPpt die ganze Klasse ausserhalb eines Checkouts, statt teils zu fallen und teils
# leer zu bestehen.
@unittest.skipUnless(_im_checkout(),
                     "audit_artifacts/ ist aus dem sdist geprunt — dieser Waechter gilt im "
                     "Repo-Checkout (PKG-2026-0718-01)")
class AktenIndexZahlenStimmen(unittest.TestCase):

    def test_es_gibt_ueberhaupt_etwas_zu_pruefen(self) -> None:
        """Die Gegenprobe des Messaufbaus. Ohne sie saehe ein leeres Verzeichnis wie ein
        makelloses Ergebnis aus — die Falle, die in dieser Runde mehrfach zugeschnappt ist."""
        self.assertTrue(_AKTEN.is_dir(), "audit_artifacts/ fehlt — dieser Test misst dann nichts")
        self.assertTrue(_indizes(), "kein einziger 00_INDEX.md gefunden — Suchmuster tot oder Akte leer")

    def test_die_gesamtzahl_passt_zur_dateimenge(self) -> None:
        """`N of the M` — M muss die Zahl der FINDING-Dateien sein, nicht die von gestern.

        ALLE Aussagen, nicht nur die erste. Eine Gegenlesung hat gemessen, dass `.search` bei zwei
        Saetzen im selben Index nur den ersten prueft und der zweite unbemerkt falsch sein kann.
        Heute traegt jeder Index genau eine — der Waechter existiert fuer morgen.
        """
        for idx in _indizes():
            with self.subTest(akte=idx.parent.name):
                text = idx.read_text(encoding="utf-8")
                dateien = sorted(p.name for p in idx.parent.glob("FINDING_*.md"))
                for m in _AUSSAGE.finditer(text):     # ein Index ohne Aussage ist erlaubt
                    self.assertEqual(
                        _WORTZAHL[m.group(2).lower()], len(dateien),
                        f"{idx.relative_to(_REPO)} sagt '{m.group(0)}', im Verzeichnis liegen "
                        f"{len(dateien)} FINDING-Dateien: {dateien}")

    def test_die_teilzahl_passt_zu_den_markierten_zeilen(self) -> None:
        """`N of the M` — N muss die Zahl der als Altbefund ausgewiesenen Zeilen sein.

        KEIN stiller Ausstieg bei null Markierungen. Die erste Fassung sprang dort heraus
        (`if markiert == 0: continue`), und eine Gegenlesung hat benannt, was das bedeutet: ein
        Index, der `three of the ten` behauptet und KEINE Zeile markiert, wurde nicht geprueft.
        Das ist die stille Form von "nichts gefunden = alles gut" — dieselbe, die in dieser Runde
        schon einen Nachbar-Test wertlos gemacht hat. Drei Zustaende: keine Aussage -> nichts zu
        pruefen · Aussage nennt 0 und es gibt 0 Markierungen -> stimmt · Aussage nennt >0 und es
        gibt 0 -> FEHLER, nicht Ueberspringen.
        """
        for idx in _indizes():
            with self.subTest(akte=idx.parent.name):
                text = idx.read_text(encoding="utf-8")
                markiert = len(_ALTBEFUND_ZEILE.findall(text))
                for m in _AUSSAGE.finditer(text):
                    behauptet_teil = _WORTZAHL[m.group(1).lower()]
                    self.assertEqual(
                        behauptet_teil, markiert,
                        f"{idx.relative_to(_REPO)} sagt '{m.group(0)}', im Nachweis-Block stehen "
                        f"{markiert} als Altbefund markierte Zeilen"
                        + (" — die Aussage nennt eine Zahl, der Nachweis fehlt ganz"
                           if markiert == 0 else ""))

    def test_jede_befund_datei_steht_in_der_tabelle(self) -> None:
        """Eine Datei, die der Index nicht nennt, ist fuer einen Leser nicht da.

        Der Nachbar-Fehler zur Zahl: nicht die Summe stimmt nicht, sondern ein Element fehlt in der
        Aufzaehlung. Beides erzeugt denselben Eindruck von Vollstaendigkeit.
        """
        for idx in _indizes():
            with self.subTest(akte=idx.parent.name):
                text = idx.read_text(encoding="utf-8")
                genannt = set(_TABELLENZEILE.findall(text))
                vorhanden = {p.name for p in idx.parent.glob("FINDING_*.md")}
                fehlt = sorted(vorhanden - genannt)
                self.assertFalse(
                    fehlt, f"{idx.relative_to(_REPO)} nennt diese Befund-Datei(en) nicht: {fehlt}")

    def test_der_index_kippt_das_pre_tag_tor_nicht(self) -> None:
        """Ein Index, der das Vokabular des Tors benennt, attestiert das Release, indem er es
        beschreibt. Der 3.8.0-Index sagt das ueber sich selbst — hier steht es ausfuehrbar.

        Geprueft wird gegen den ECHTEN Detektor des Tors, nicht gegen eine nachgebaute Kopie: eine
        zweite Messstelle fuer dieselbe Groesse waere die naechste Drift.
        """
        import importlib.util
        pfad = _REPO / "scripts" / "pre_tag_audit_gate.py"
        if not pfad.is_file():
            self.skipTest("pre_tag_audit_gate.py nicht vorhanden")
        spec = importlib.util.spec_from_file_location("_ptag_fuer_index", pfad)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        marker = getattr(m, "_positive_audit_marker", None)
        if marker is None:
            self.skipTest("_positive_audit_marker nicht exportiert")
        # Gegenprobe: der Detektor MUSS auf einer klaren Markerzeile anschlagen, sonst misst er nichts
        self.assertTrue(marker("the adversarial audit ran and passed"),
                        "der Detektor schlaegt nicht einmal auf einer klaren Markerzeile an")
        for idx in _indizes():
            with self.subTest(akte=idx.parent.name):
                self.assertFalse(
                    marker(idx.read_text(encoding="utf-8")),
                    f"{idx.relative_to(_REPO)} traegt eine nicht-negierte Markerzeile und wuerde das "
                    "Pre-Tag-Tor erteilen — ein Index darf ein Release nicht attestieren, indem er es "
                    "beschreibt")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
