"""L2-600-BYTES-01 (deep gate Lauf 7, P2): die Strukturschranke band einen TYP, nicht die
EIGENSCHAFT.

DIE KLASSE. `_enforce_structural_budget` hatte vier Zweige (str, dict, list/tuple, int) und KEIN
Sonst — was auf keinen passte, fiel lautlos hindurch und wurde weder begrenzt noch betreten.
`bytes` ist auf genau diesen Flaechen eine UNTERSTUETZTE Form (`_wire_b64.decode_b64` ist als
`str | bytes` typisiert) und trug trotzdem keine Schranke. Der Tupel-Fix aus Lauf 3 hatte EINEN
Typ nachgetragen und die Familie offen gelassen; eine Aufzaehlung ist immer nur so vollstaendig
wie der Tag, an dem sie geschrieben wurde.

DIE EIGENSCHAFT, in zwei Haelften:
  (1) Jeder Werttyp, der eine Laenge oder eine Elementzahl traegt, faellt unter DIESELBE Achse wie
      sein Gegenstueck auf dem Datei-Weg — Bytes wie Strings, Mengen wie Listen.
  (2) Der Lauf ist GESCHLOSSEN, nicht aufgezaehlt: ein Wert, der auf keinen Zweig passt, wird
      abgewiesen, nie still uebersprungen. Das faengt auch den Typ, den morgen jemand einfuehrt.

Die Gegenrichtung steht mit im selben Testkoerper: gueltige JSON-Skalare duerfen NICHT abgewiesen
werden. Ein Fix, der alles abweist, waere so falsch wie einer, der nichts abweist.
"""
from __future__ import annotations

import unittest

from proofbundle._strict_json import enforce_structural_budget
from proofbundle.budget import DEFAULT_BUDGET, BudgetExceeded
from proofbundle.errors import BundleFormatError

_SL = DEFAULT_BUDGET.string_len
_JN = DEFAULT_BUDGET.json_nodes


class _TraegtLaengeIstAberKeinJson:
    """Der 'naechste Typ': er traegt eine Laenge, passt aber auf keinen bekannten Zweig."""

    def __len__(self) -> int:
        return _SL + 1


class TestDieselbeAchseFuerDieselbeEigenschaft(unittest.TestCase):
    def test_der_massstab_selbst_greift(self):
        """Ohne diesen Fall misst die ganze Datei nichts: er zeigt, dass die Referenzschranke
        ueberhaupt feuert, gegen die die anderen Faelle verglichen werden."""
        with self.assertRaises(BudgetExceeded) as ctx:
            enforce_structural_budget({"a": "x" * (_SL + 1)})
        self.assertEqual(ctx.exception.dimension, "string_len")

    def test_bytes_faellt_unter_string_len(self):
        with self.assertRaises(BudgetExceeded) as ctx:
            enforce_structural_budget({"a": b"x" * (_SL + 1)})
        self.assertEqual(ctx.exception.dimension, "string_len")

    def test_bytearray_faellt_unter_string_len(self):
        with self.assertRaises(BudgetExceeded) as ctx:
            enforce_structural_budget({"a": bytearray(b"x" * (_SL + 1))})
        self.assertEqual(ctx.exception.dimension, "string_len")

    def test_memoryview_faellt_unter_string_len(self):
        with self.assertRaises(BudgetExceeded) as ctx:
            enforce_structural_budget({"a": memoryview(b"x" * (_SL + 1))})
        self.assertEqual(ctx.exception.dimension, "string_len")

    def test_menge_faellt_unter_json_nodes_wie_eine_liste(self):
        with self.assertRaises(BudgetExceeded) as ctx:
            enforce_structural_budget({"a": set(range(_JN + 1))})
        self.assertEqual(ctx.exception.dimension, "json_nodes")

    def test_unveraenderliche_menge_ebenso(self):
        with self.assertRaises(BudgetExceeded) as ctx:
            enforce_structural_budget({"a": frozenset(range(_JN + 1))})
        self.assertEqual(ctx.exception.dimension, "json_nodes")


class TestDerLaufIstGeschlossenNichtAufgezaehlt(unittest.TestCase):
    def test_ein_unbekannter_typ_wird_abgewiesen_nicht_uebersprungen(self):
        """Die zweite Haelfte der Eigenschaft. Ohne diesen Arm waere der naechste Typ wieder offen —
        genau so, wie `bytes` nach dem Tupel-Fix offen blieb."""
        with self.assertRaises(BundleFormatError) as ctx:
            enforce_structural_budget({"a": _TraegtLaengeIstAberKeinJson()})
        self.assertIn("not a JSON value", str(ctx.exception))

    def test_auch_tief_verschachtelt(self):
        """Der Arm sitzt im Walk, nicht am Eingang — er greift auf jeder Ebene."""
        with self.assertRaises(BundleFormatError):
            enforce_structural_budget({"a": {"b": [{"c": _TraegtLaengeIstAberKeinJson()}]}})


class TestGegenrichtungGueltigesBleibtGueltig(unittest.TestCase):
    """Ein Fix, der alles abweist, waere so falsch wie einer, der nichts abweist."""

    def test_json_skalare_kommen_durch(self):
        for wert in (None, True, False, 0, 42, -1, 1.5, "kurz", b"kurz"):
            with self.subTest(typ=type(wert).__name__, wert=repr(wert)[:20]):
                enforce_structural_budget({"a": wert})

    def test_gewoehnliche_strukturen_kommen_durch(self):
        enforce_structural_budget({"a": [1, 2, {"b": "c"}], "d": (4, 5), "e": {"f": [None, True]}})

    def test_bytes_unter_der_grenze_kommt_durch(self):
        enforce_structural_budget({"a": b"x" * 1024})


if __name__ == "__main__":
    unittest.main()
