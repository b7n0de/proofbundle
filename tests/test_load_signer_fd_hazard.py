"""`load_signer(123)` darf keinen fremden Dateideskriptor lesen.

WARUM DIESE DATEI GETRENNT EXISTIERT. Die Gefahr wurde am 2026-08-16 gefunden, als die
never-raise-Familieneigenschaft ihre Module erstmals AUS DEM BAUM aufzaehlte statt aus einer
gepflegten Liste (`FINDING_never_raise_population.md`). `emit.load_signer` war nie in der gesweepten
Menge; die Eigenschaft war korrekt ueber ihre Liste und diese Liste war kleiner als die Klasse.

Beim Schliessen der Luecke musste `OSError` in die AKZEPTIERTEN Beendigungen der Familieneigenschaft
aufgenommen werden — "die Datei ist nicht da" ist fuer einen Lader eine ehrliche typisierte Antwort
und keine Typverwechslung. Genau diese Aufnahme haette den eigentlichen Fund WIEDER verdeckt:
`load_signer(123)` warf `OSError(EBADF)`, und ab dann waere das "akzeptiert" gewesen.

Deshalb liegt die Eigenschaft HIER und nicht in einer Liste: eine Schranke, die eine andere Schranke
lockert, muss ihren eigenen Waechter mitbringen, sonst ist die Lockerung eine stille Ruecknahme.

DIE SACHE SELBST. `open()` nimmt eine ganze Zahl als DATEIDESKRIPTOR. `load_signer(123)` scheitert
also nicht am falschen Typ — es liest, was zufaellig auf fd 123 offen ist, und versucht daraus einen
privaten Schluessel zu machen. Ein falsch getipptes Argument, das still eine fremde offene Datei
erreicht, ist ein schlechteres Ergebnis als ein Absturz.
"""
from __future__ import annotations

import os
import pathlib
import tempfile
import unittest

from proofbundle.emit import generate_signer, load_signer, save_signer
from proofbundle.errors import BundleFormatError


class LoadSignerNimmtKeineZahl(unittest.TestCase):

    def test_eine_zahl_wird_typisiert_abgelehnt(self) -> None:
        with self.assertRaises(BundleFormatError):
            load_signer(123)

    def test_die_zahl_erreicht_open_GAR_NICHT(self) -> None:
        """Der eigentliche Beleg — nicht "es wirft", sondern "es liest nichts".

        Ein echter, offener Deskriptor wird praepariert und SEINE Nummer uebergeben. Ohne die
        Schranke liest `open(fd)` daraus; mit ihr darf der Inhalt nirgends auftauchen und der
        Deskriptor muss danach unveraendert lesbar sein (ein `open(fd)` mit closefd haette ihn
        geschlossen).
        """
        import shutil
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        koeder = d / "koeder.bin"
        koeder.write_bytes(b"K" * 32)                       # 32 Byte: haette als Seed getaugt
        fd = os.open(koeder, os.O_RDONLY)

        def fd_offen() -> bool:
            try:
                os.fstat(fd)
                return True
            except OSError:
                return False

        self.addCleanup(lambda: os.close(fd) if fd_offen() else None)

        # Gegenprobe des Messaufbaus: der Deskriptor ist WIRKLICH offen und lesbar, sonst misst
        # dieser Test nichts.
        self.assertTrue(fd_offen(), "Vorbedingung: der praeparierte Deskriptor ist offen")

        with self.assertRaises(BundleFormatError):
            load_signer(fd)

        self.assertTrue(fd_offen(),
                        "der Deskriptor wurde geschlossen — dann hat open() ihn sehr wohl "
                        "uebernommen, und die Schranke greift nicht vor dem Zugriff")

    def test_ein_echter_pfad_funktioniert_weiterhin(self) -> None:
        """Die Gegenrichtung. Eine Schranke, die auch den richtigen Aufruf blockt, ist keine
        Haertung, sondern ein Ausfall — und sie faellt beim naechsten Mal als Erstes wieder raus."""
        d = pathlib.Path(tempfile.mkdtemp())
        p = d / "key.bin"
        self.addCleanup(p.unlink, True)
        key = generate_signer()
        save_signer(key, str(p))
        for form in (str(p), p, os.fsencode(str(p))):
            with self.subTest(form=type(form).__name__):
                geladen = load_signer(form)
                self.assertEqual(
                    geladen.public_key().public_bytes_raw(),
                    key.public_key().public_bytes_raw(),
                    "ein gueltiger Pfad in dieser Form wird nicht mehr geladen")


class SaveSignerHatDenSelbenBodenWieSeinNachbar(unittest.TestCase):
    """Der Nachbar in derselben Datei — 2026-08-18 nachgemessen, Befund PBNACHBAR-EMIT-TYPBODEN-01.

    `load_signer` bekam den Typboden am 16.08. mit ausfuehrlicher Begruendung. `save_signer` steht
    zwanzig Zeilen darueber, nimmt denselben aufrufer-gelieferten Pfad und hatte ihn nicht:
    `save_signer(echterSchluessel, 1)` warf einen rohen `TypeError` aus `os.open`. Der urspruengliche
    Beleg des Befunds mass mit `None` als Schluessel und traf damit den falschen Gegenstand — der
    rohe Fehler haette auch vom Schluessel kommen koennen. Mit echtem Schluessel gemessen liegt er
    am Pfad.

    WARUM ES DURCHRUTSCHTE: die Familieneigenschaft entdeckt ueber Namensfamilien (`load_` ja,
    `save_` nein), und in der Ausschlussmenge steht `save_signer` als ERZEUGER — eine Begruendung,
    die fuer sein `key`-Argument gilt und fuer seinen Pfad nicht. Sie bleibt dort richtig; deshalb
    steht der Beleg HIER, wo der Gegenstand liegt, statt die Familieneigenschaft zu verbiegen.
    """

    def _key(self):
        return generate_signer()

    def test_ein_nicht_pfad_wird_typisiert_abgelehnt(self) -> None:
        key = self._key()
        for falsch in (1, None, [1], {"p": 1}, 3.5):
            with self.subTest(argument=type(falsch).__name__):
                with self.assertRaises(BundleFormatError):
                    save_signer(key, falsch)

    def test_das_geheimnis_wird_gar_nicht_erst_materialisiert(self) -> None:
        """Nicht "es wirft", sondern "der Seed wird nie erzeugt" — die Schranke liegt VOR dem Rohwert.

        DER ERSTE ENTWURF DIESES TESTS WAR BEINAHE TAUTOLOGISCH, und die Sensitivitaetsprobe hat es
        gezeigt: er zaehlte ein Zielverzeichnis vorher und nachher auf. Bei `path=1` gibt es dort
        aber ohnehin nie eine Datei — der Test blieb gruen, als ich absichtlich einen Schreibvorgang
        VOR die Schranke setzte. Er mass die Abwesenheit von etwas, das an dieser Stelle nie
        entstehen konnte.

        Beobachtet wird deshalb der Gegenstand selbst: `save_signer` ruft `key.private_bytes(...)`,
        um den 32-Byte-Seed im Klartext zu erzeugen. Liegt der Typboden davor, wird dieser Aufruf
        NIE gemacht. Ein Attrappen-Schluessel merkt sich, ob er gefragt wurde.
        """
        gefragt = []

        class Attrappe:
            def private_bytes(self, *_a, **_k):
                gefragt.append(True)
                return b"S" * 32

        with self.assertRaises(BundleFormatError):
            save_signer(Attrappe(), 1)
        self.assertEqual([], gefragt,
                         "der private Seed wurde erzeugt, BEVOR der Pfad geprueft war — die "
                         "Schranke liegt hinter dem Rohwert statt davor")

    def test_ein_echter_pfad_schreibt_weiterhin_und_bleibt_0600(self) -> None:
        """Die Gegenrichtung, und sie prueft mehr als das Gelingen.

        Der Modus ist Teil des Vertrags dieser Funktion (ein Geheimnis darf nie, auch nicht kurz,
        breiter lesbar sein). Eine Schranke, die den richtigen Aufruf beschaedigt, ist ein Ausfall.
        """
        import shutil
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        key = self._key()
        for form in (str(d / "a.bin"), d / "b.bin", os.fsencode(str(d / "c.bin"))):
            with self.subTest(form=type(form).__name__):
                save_signer(key, form)
                p = pathlib.Path(os.fsdecode(form))
                self.assertTrue(p.is_file(), "der gueltige Aufruf hat nichts geschrieben")
                self.assertEqual(0o600, p.stat().st_mode & 0o777)
                self.assertEqual(load_signer(p).public_key().public_bytes_raw(),
                                 key.public_key().public_bytes_raw())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
