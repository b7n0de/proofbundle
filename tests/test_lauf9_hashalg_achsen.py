"""Zwei Funde aus deep gate Lauf 9 an derselben oeffentlichen Flaeche `verify_dual_hash`.

L1-600-HEXCASE-01 (P3): `actual == expected.lower()` normalisierte das ERWARTETE vor dem Vergleich.
Damit hatte ein signierter Digest mehr als eine akzeptierte Drahtform. Es ist dieselbe Eigenschaft,
die `_wire_b64` auf der base64-Achse durchsetzt — der Sweep von damals fegte eine Achse und liess
die benachbarte stehen.

L2-600-DUALHASH-NODES-INERT-01 (P3): `digests` ist eine unvertraute Abbildung, die NICHT das erste
Argument ist, und lief deshalb an `enforce_structural_budget` vorbei. Der Parse-Weg weist denselben
Inhalt an `json_nodes` ab; die Ablehnung muss auf beiden Wegen gleich ausfallen.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from proofbundle.hashalg import compute_dual_hash, verify_dual_hash  # noqa: E402

DATEN = b"lauf9 achsen"


def _ok(digests) -> bool:
    r = verify_dual_hash(DATEN, digests)
    return all(c.ok for c in r.checks)


class GenauEineDrahtformJeDigest(unittest.TestCase):
    def setUp(self):
        self.kanon = compute_dual_hash(DATEN, ["sha256", "sha512"])

    def test_die_kanonische_form_wird_angenommen(self):
        """Anti-Tautologie: ohne diese Zeile misst der Test nur, dass irgendetwas abgelehnt wird."""
        self.assertTrue(_ok(self.kanon))

    def test_grossschreibung_wird_abgelehnt(self):
        self.assertFalse(_ok({k: v.upper() for k, v in self.kanon.items()}))

    def test_gemischte_schreibung_wird_abgelehnt(self):
        self.assertFalse(_ok({k: v[:10].upper() + v[10:] for k, v in self.kanon.items()}))

    def test_umgebende_zeichen_werden_abgelehnt(self):
        for form in (lambda v: v + " ", lambda v: " " + v, lambda v: "0x" + v, lambda v: v + "\n"):
            with self.subTest(form=form(self.kanon["sha256"])[:12]):
                self.assertFalse(_ok({k: form(v) for k, v in self.kanon.items()}))

    def test_ein_falscher_digest_bleibt_falsch(self):
        self.assertFalse(_ok({k: "0" * len(v) for k, v in self.kanon.items()}))

    def test_die_schreibweise_bekommt_ihren_eigenen_grund(self):
        """Eine abweichende Schreibweise ist kein inhaltlicher Fehlschlag und darf nicht als einer
        gemeldet werden — sonst sucht der Leser den Fehler in den Bytes."""
        r = verify_dual_hash(DATEN, {k: v.upper() for k, v in self.kanon.items()})
        gruende = [c.detail for c in r.checks if not c.ok]
        self.assertTrue(any("canonical lowercase hex" in g for g in gruende), gruende)


class DasStrukturbudgetGiltAuchFuerDasZweiteArgument(unittest.TestCase):
    def test_ueber_der_grenze_wird_abgewiesen(self):
        r = verify_dual_hash(DATEN, {f"sha256-{i}": "0" * 64 for i in range(200_001)})
        gruende = [c.detail for c in r.checks if not c.ok]
        self.assertTrue(any("structural budget" in g for g in gruende), gruende[:1])

    def test_gegenrichtung_unter_der_grenze_wird_inhaltlich_geprueft(self):
        """Knapp unter der Grenze darf die Schranke NICHT feuern — sonst waere sie ein Denial und
        kein Budget. Der Inhalt faellt dann aus eigenem Grund durch."""
        r = verify_dual_hash(DATEN, {f"sha256-{i}": "0" * 64 for i in range(1000)})
        gruende = [c.detail for c in r.checks if not c.ok]
        self.assertTrue(gruende, "ein Beutel unbekannter Algorithmen muss durchfallen")
        self.assertFalse(any("structural budget" in g for g in gruende), gruende[:1])

    def test_gegenrichtung_ein_normaler_beutel_bleibt_gueltig(self):
        self.assertTrue(_ok(compute_dual_hash(DATEN, ["sha256", "sha512"])))

    def test_keine_ausnahme_entweicht_dieser_never_raise_flaeche(self):
        """DIE ZWEITE HAELFTE DES FIX, gefunden von der Gegenlesung (qwen3.8:27b, Frage F6) und
        nicht von mir: der Waechter wirft ZWEI Arten — `BudgetExceeded` bei Ueberbreite und
        `BundleFormatError` bei Uebertiefe. Der erste Entwurf fing nur die erste, und ein 300 Ebenen
        tiefer Wert liess `BundleFormatError` durch diese Flaeche entweichen. Ein Fix gegen eine
        Ueberlast hatte damit einen neuen Absturzweg geoeffnet.

        Geprueft werden alle Achsen des Waechters, nicht nur die, an der der Fund hing."""
        tief = {}
        cur = tief
        for _ in range(300):
            cur["a"] = {}
            cur = cur["a"]
        faelle = {
            "zu tief": {"sha256": tief},
            "zu breit": {f"sha256-{i}": "0" * 64 for i in range(200_001)},
            "zu langer String": {"sha256": "x" * 3_000_000},
            "riesige Ganzzahl": {"sha256": 2 ** 5000},
            "kein Mapping": ["nicht", "mal", "ein", "dict"],
        }
        for name, digests in faelle.items():
            with self.subTest(fall=name):
                try:
                    r = verify_dual_hash(DATEN, digests)
                except Exception as exc:                      # noqa: BLE001 — genau das ist der Test
                    self.fail(f"{name}: {type(exc).__name__} entweicht der never-raise-Flaeche: {exc}")
                self.assertFalse(all(c.ok for c in r.checks),
                                 f"{name} muss fail-closed abgelehnt werden")


if __name__ == "__main__":
    unittest.main()
