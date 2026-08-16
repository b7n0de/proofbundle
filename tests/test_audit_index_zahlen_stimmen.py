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

# "FIVE of the six findings are on `main`" — Wort-Zahlen, weil der Index Prosa ist und bleiben soll.
# BIS ZWANZIG, nicht bis zehn. Die erste Fassung endete bei "ten" — und genau in dem Moment, in dem
# die Akte auf ELF Dateien wuchs und ich den Satz brav auf "eleven files" korrigierte, hoerte der
# Waechter auf, ihn zu pruefen. Eine Wortliste, die den vorkommenden Wert nicht enthaelt, macht aus
# einer gepruefen Zahl still eine ungepruefte; gefunden vom eigenen Meta-Test am 2026-08-17.
_WORTZAHL = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
             "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
             "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
             "eighteen": 18, "nineteen": 19, "twenty": 20}
# DAS HAUPTWORT IST PFLICHT, und das ist der eigentliche Fix. Die erste Fassung matchte jedes
# `N of the M` und behandelte es als die Altbefund-Aussage. Sobald der Index einen zweiten,
# voellig wahren Satz derselben Grammatik ueber eine ANDERE Groesse bekam ("Two of the six were
# closed"), meldete der Waechter ihn als Fehler. Genau die Verwechslung, gegen die er gebaut
# wurde — eine Zahl ueber eine Population gemessen und ueber eine andere geprueft. Wer zaehlt,
# nennt WAS er zaehlt; ohne Hauptwort ist die Aussage fuer eine Maschine nicht bestimmbar und
# wird deshalb NICHT geprueft statt falsch geprueft.
_AUSSAGE = re.compile(r"\b(" + "|".join(_WORTZAHL) + r")\s+of\s+the\s+(" + "|".join(_WORTZAHL)
                      + r")\s+findings\b", re.IGNORECASE)
_ALTBEFUND_ZEILE = re.compile(r"->\s*Altbefund\s*$", re.MULTILINE)
_TABELLENZEILE = re.compile(r"^\|\s*`(FINDING_[A-Za-z0-9_]+\.md)`", re.MULTILINE)

# Dieselbe Invariante in einer ANDEREN Grammatik: nicht `N of the M`, sondern eine Zahl direkt am
# gezaehlten Hauptwort. Nachgetragen, nachdem beide Formen im 3.8.0-Index gemessen FALSCH standen
# ("the five findings" bei sechs, "this one is eight" bei zehn) und die erste Fassung dieses
# Waechters an ihnen vorbeilas — sie band die Zahl an EINE Formulierung statt an die Aussage.
# `findings` ist eindeutig: in einer Befund-Akte zaehlt "N findings" die Befunde.
# `files` ist es NICHT — und das ist am 2026-08-17 gemessen worden, als eine Sonde derselben Bauart
# vier Falschtreffer meldete: "2 files changed" (der src/-Delta), "two files under `src/`" und
# "two files in this same directory" (eine Redewendung) zaehlen NICHT die Akte. Der Waechter ging
# bis dahin nur deshalb gut, weil im Index zufaellig kein src/-Delta stand — Glueck, kein Entwurf.
# Deshalb wird eine Datei-Zahl nur geprueft, wenn der Satz SICH SELBST als Gegenstand nennt.
# EHRLICHE GRENZE: eine falsche Datei-Zahl in anderer Formulierung entgeht damit. Das ist die
# bewusste Wahl gegen einen Waechter, der wahre Saetze als Fehler meldet — ein Waechter, der
# Fehlalarme streut, wird abgeschaltet, und dann faengt er auch die echten nicht mehr.
_SELBSTBEZUG = r"(?:this one is|this record is|the record is|dieser Record ist)\s+"
_AM_HAUPTWORT = re.compile(
    r"\b(" + "|".join(_WORTZAHL) + r"|\d+)\s+findings\b"
    r"|" + _SELBSTBEZUG + r"(" + "|".join(_WORTZAHL) + r"|\d+)\s+files\b",
    re.IGNORECASE)

# EIN ZITAT IST KEINE BEHAUPTUNG. Diese Akte korrigiert ihre eigenen Zahlen und muss dafuer die
# FALSCHE nennen duerfen ("the five findings" (there were six)). Ohne diese Ausnahme bestraft der
# Waechter genau die Offenlegung, die er erzwingen soll — und der billige Ausweg waere, die
# Korrektur nicht aufzuschreiben. Gerade Anfuehrungszeichen, eine Zeile, keine Schachtelung.
# EHRLICHE GRENZE: wer eine LEBENDE Behauptung in Anfuehrungszeichen setzt, entgeht der Pruefung.
# Das ist in Kauf genommen — der Test unten weist nach, dass die Ausnahme genau so wirkt und nicht
# weiter, damit die Grenze gemessen dasteht statt vermutet.
_ZITAT = re.compile(r'"[^"\n]*"')


def _ungezitiert(text: str, muster: "re.Pattern[str]"):
    """Treffer von ``muster``, die NICHT innerhalb eines Zitats liegen."""
    zitate = [(m.start(), m.end()) for m in _ZITAT.finditer(text)]
    for treffer in muster.finditer(text):
        if any(a <= treffer.start() < b for a, b in zitate):
            continue
        yield treffer


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
                for m in _ungezitiert(text, _AUSSAGE):   # ein Index ohne Aussage ist erlaubt
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
                for m in _ungezitiert(text, _AUSSAGE):
                    behauptet_teil = _WORTZAHL[m.group(1).lower()]
                    self.assertEqual(
                        behauptet_teil, markiert,
                        f"{idx.relative_to(_REPO)} sagt '{m.group(0)}', im Nachweis-Block stehen "
                        f"{markiert} als Altbefund markierte Zeilen"
                        + (" — die Aussage nennt eine Zahl, der Nachweis fehlt ganz"
                           if markiert == 0 else ""))

    def test_zahlen_am_hauptwort_passen_zur_aktenlage(self) -> None:
        """`N findings` / `N files` — dieselbe Invariante, andere Grammatik.

        WARUM NACHGETRAGEN: die erste Fassung dieses Waechters prueft nur `N of the M`. Im selben
        Dokument standen zwei Zaehlungen in anderer Form, und BEIDE waren falsch — "the five
        findings" bei sechs Dateien, "this one is eight" bei zehn. Der Waechter war an eine
        FORMULIERUNG gebunden, nicht an die Aussage; das ist die Instanz-statt-Klasse-Falle, die
        diese Runde an anderer Stelle protokolliert. Gefangen hat sie am Ende ein Mensch beim
        Lesen, nicht der Test — deshalb steht hier jetzt die Regel.

        Die Gegenrichtung ist mitgemessen: ein Index, der KEINE solche Zahl nennt, ist erlaubt
        (`finditer` laeuft leer). Der Test kann also nur durch eine falsche Zahl fallen, nie durch
        eine fehlende — und `test_es_gibt_ueberhaupt_etwas_zu_pruefen` haelt fest, dass ueberhaupt
        ein Index existiert, damit "leer" nicht wie "makellos" aussieht.
        """
        for idx in _indizes():
            with self.subTest(akte=idx.parent.name):
                text = idx.read_text(encoding="utf-8")
                ist = {"findings": len(list(idx.parent.glob("FINDING_*.md"))),
                       "files": len(list(idx.parent.glob("*.md")))}
                gefunden = 0
                for m in _ungezitiert(text, _AM_HAUPTWORT):
                    # Gruppe 1 = "<N> findings", Gruppe 2 = "<Selbstbezug> <N> files".
                    if m.group(1) is not None:
                        roh, hauptwort = m.group(1).lower(), "findings"
                    else:
                        roh, hauptwort = m.group(2).lower(), "files"
                    gefunden += 1
                    behauptet = _WORTZAHL.get(roh, None)
                    if behauptet is None:
                        behauptet = int(roh)
                    self.assertEqual(
                        behauptet, ist[hauptwort],
                        f"{idx.relative_to(_REPO)} sagt '{m.group(0)}', gezaehlt sind "
                        f"{ist[hauptwort]} {hauptwort}")
                # Gegenprobe des Messaufbaus an der EINEN Akte, die solche Saetze fuehrt: findet
                # das Muster dort nichts, ist es tot und der gruene Lauf bedeutungslos.
                if idx.parent.name == "380":
                    self.assertTrue(gefunden, "das Muster findet in 380/ keine einzige Zahl am "
                                              "Hauptwort — tot statt sauber")

    def test_die_zitat_ausnahme_wirkt_genau_so_weit_wie_behauptet(self) -> None:
        """Gate-Meta-Test: die Ausnahme darf den Waechter nicht abschalten.

        Ein Waechter mit einer Ausnahme ist zwei Behauptungen — er faengt X, und er faengt es
        TROTZ der Ausnahme. Die zweite steht sonst nur im Kommentar. Gemessen werden beide
        Richtungen plus die ehrliche Grenze, damit sie belegt dasteht statt vermutet.
        """
        offen = 'The six findings are listed above.'
        zitiert = 'An earlier draft said "the five findings" and that was wrong.'
        beides = offen + " " + zitiert

        self.assertEqual([m.group(0) for m in _ungezitiert(offen, _AM_HAUPTWORT)],
                         ["six findings"], "die offene Zahl wird NICHT mehr gesehen — Waechter tot")
        self.assertEqual(list(_ungezitiert(zitiert, _AM_HAUPTWORT)), [],
                         "eine zitierte Zahl wird geprueft — dann bestraft der Waechter die "
                         "Offenlegung der eigenen Korrektur")
        self.assertEqual([m.group(0) for m in _ungezitiert(beides, _AM_HAUPTWORT)],
                         ["six findings"],
                         "ein Zitat im selben Text darf die offene Zahl daneben nicht mitdecken")
        # EINE DATEI-ZAHL UEBER EINE ANDERE MENGE DARF NICHT FEUERN. Am 2026-08-17 meldete eine
        # Sonde derselben Bauart vier Falschtreffer, alle aus derselben Annahme: "N files" muesse
        # die Akte meinen. Gemessen meinten sie den src/-Delta ("2 files changed") oder waren eine
        # Redewendung ("two files in this same directory"). Der Waechter ging bis dahin nur gut,
        # weil im Index zufaellig kein src/-Delta stand.
        for harmlos in ("2 files changed, 49 insertions(+)",
                        "the shipped delta is two files under `src/`",
                        "a counter-read found the two files in this same directory"):
            with self.subTest(harmlos=harmlos):
                self.assertEqual(list(_ungezitiert(harmlos, _AM_HAUPTWORT)), [],
                                 "eine Datei-Zahl ueber eine ANDERE Menge wird geprueft — der "
                                 "Waechter meldet wahre Saetze als Fehler")
        # ... und die Selbstbezugs-Form muss weiterhin greifen, sonst ist die Verengung ein Ausfall.
        self.assertEqual([m.group(0) for m in _ungezitiert("This one is eleven files.", _AM_HAUPTWORT)],
                         ["This one is eleven files"],
                         "die Selbstbezugs-Form wird nicht mehr gesehen — Waechter tot")

        # Die EHRLICHE GRENZE, ausgeschrieben: eine LEBENDE Behauptung in Anfuehrungszeichen
        # entgeht der Pruefung. Das ist bewusst so und hier gemessen, nicht beschoenigt.
        self.assertEqual(list(_ungezitiert('The record has "ten findings" today.', _AM_HAUPTWORT)),
                         [], "die dokumentierte Grenze der Ausnahme gilt nicht mehr — dann ist der "
                             "Kommentar an _ZITAT falsch und muss nachgezogen werden")

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
