"""ERGAENZUNG fuer tests/test_lauf8_klassenfixes_600.py, nach dem Verdikt von Lauf 9 einzufuegen.

Die vorhandenen Faelle zu S83 pruefen DREI ausgedachte Schreibweisen. Das ist eine Aufzaehlung,
und Aufzaehlungen sind genau die Klasse, gegen die dieser ganze Lauf schreibt. Der Fall unten
ZAEHLT stattdessen: er fragt, WIE VIELE Schreibweisen derselben Bytes der Dekoder annimmt, und
vergleicht die Zahl mit der, die aus der Zahl der Fuellbits folgt.

Gemessen am Kopf 8626618: pad=0 ergibt 1, pad=1 ergibt 4, pad=2 ergibt 16 — exakt 2 hoch der Zahl
der Fuellbits. Dass die Zahlen aufgehen, ist der Beleg, dass die Regel die EIGENSCHAFT trifft und
nicht bloss die Faelle, an die der Autor gedacht hat. Waechst die Zahl, ist eine zweite Freiheit
dazugekommen; schrumpft sie, ist die dokumentierte Duldung verlorengegangen.
"""
from __future__ import annotations

import base64
import unittest

from proofbundle._wire_b64 import decode_b64_c2sp

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#: Die Materiallaengen, die auf dieser Flaeche wirklich vorkommen, ueber alle drei Fuellklassen.
_LAENGEN = (33, 68, 32, 1313, 2432, 76)


class DieFreiheitsachseIstGENAUDieDokumentierte(unittest.TestCase):
    """Zaehlen statt aufzaehlen: wie viele Schreibweisen ergeben dieselben Bytes?"""

    def _kanonisch(self, n: int) -> tuple[bytes, str]:
        roh = bytes(((i * 37 + 11) % 256) for i in range(n))   # deterministisch, kein Zufall
        return roh, base64.b64encode(roh).decode("ascii")

    def test_die_zahl_der_schreibweisen_folgt_aus_der_zahl_der_fuellbits(self):
        for n in _LAENGEN:
            roh, kanon = self._kanonisch(n)
            npad = kanon.count("=")
            kern = kanon[: len(kanon) - npad]
            # ZWEI ACHSEN, nicht eine (selbst gemessen, 09.09.2026). Die erste Fassung dieser
            # Schleife variierte NUR das letzte Datenzeichen und hielt die Zahl der Fuellzeichen
            # fest. Sie war damit auch am UNGEFIXTEN Dekoder gruen — 2 passed, 144 subtests — und
            # bewies nichts, denn der Defekt sass auf der PADDING-Achse, die sie nicht anfasste.
            # Genau die Klasse, gegen die diese Datei schreibt: eine Pruefung, die einen Zustand
            # feststellt, statt den Pfad zu gehen, auf dem der Fehler sitzt.
            akzeptiert = 0
            for c in _ALPHABET:                       # Achse 1: das letzte Datenzeichen
                for extra in range(0, 4):             # Achse 2: die ZAHL der Fuellzeichen
                    kandidat = kern[:-1] + c + "=" * extra
                    try:
                        if decode_b64_c2sp(kandidat) == roh:
                            akzeptiert += 1
                    except Exception:                 # noqa: BLE001 — jede Abweisung zaehlt gleich
                        pass
            erwartet = {0: 1, 1: 4, 2: 16}[npad]      # 2 hoch der Zahl der Fuellbits
            with self.subTest(laenge=n, pad=npad):
                self.assertEqual(
                    akzeptiert, erwartet,
                    f"len={n}, pad={npad}: {akzeptiert} Schreibweisen statt {erwartet} — "
                    "mehr heisst eine zweite Freiheit, weniger heisst die dokumentierte "
                    "Pad-Bit-Duldung ist weg")

    def test_GEGENRICHTUNG_an_JEDER_anderen_position_gibt_es_keine_zweite_form(self):
        """Ohne diesen Fall koennte der Test oben gruen sein, waehrend anderswo Freiheit besteht."""
        for n in _LAENGEN:
            roh, kanon = self._kanonisch(n)
            npad = kanon.count("=")
            kern = kanon[: len(kanon) - npad]
            if len(kern) < 3:
                continue
            for pos in (0, len(kern) // 2, len(kern) - 2):
                for c in _ALPHABET[:8]:
                    kandidat = kern[:pos] + c + kern[pos + 1:] + "=" * npad
                    if kandidat == kanon:
                        continue
                    with self.subTest(laenge=n, position=pos, zeichen=c):
                        try:
                            self.assertNotEqual(
                                decode_b64_c2sp(kandidat), roh,
                                "eine Aenderung abseits des letzten Datenzeichens ergibt "
                                "dieselben Bytes — das waere eine zweite Freiheitsachse")
                        except Exception:             # noqa: BLE001 — Abweisung ist der Normalfall
                            pass


if __name__ == "__main__":
    unittest.main()
