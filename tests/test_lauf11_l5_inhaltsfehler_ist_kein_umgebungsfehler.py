"""Ein Inhaltsfehler wird als Inhaltsfehler gemeldet — `DATA_BLOCKED` meint die UMGEBUNG, sonst nichts.

WAS HIER GESCHLOSSEN WIRD. Deep Gate Lauf 11, Fund `LAUF11-L5` (P0): in
`scripts/audit_candidate_matrix.py` lief `canonical.canonicalize_statement(body)` INNERHALB
desselben `try`, dessen `except Exception` als „fehlender Kanonisierer = Umgebung" kommentiert war.
Damit wurde jeder Fehler BEIM Kanonisieren zu `ART_UNMEASURABLE_HERE` und damit zu `DATA_BLOCKED`
— auch `BudgetExceeded` und `FloatDomainError`, die Eigenschaften des ARTEFAKTS sind, nicht der
Maschine.

DER AUSGEFÜHRTE FALL, ungestubbt gemessen am Kandidatenkopf `e95e72f`: zwei Artefakte mit
DERSELBEN gefälschten Signatur (32 Nullbytes Schlüssel, 64 Nullbytes Signatur):

    ohne Zusatzfeld       -> untrusted         -> _artifact_verdict = FAIL
    mit 1.000.001 Zeichen -> unmeasurable_here -> _artifact_verdict = DATA_BLOCKED

Dieselbe Fälschung, zwei Urteile — und das zweite sagt „hier nicht messbar" über ein Artefakt,
dessen Signatur schlicht falsch ist. Ein Leser des Berichts sieht einen Umgebungsmangel, wo eine
Fälschung liegt.

WARUM DIE BEREITSCHAFT TROTZDEM NICHT KIPPTE, und warum das den Fund nicht entschärft: `ready`
verlangt `verdict == PASS` für jede entscheidende Zeile, und weder FAIL noch DATA_BLOCKED ist
PASS. Das Tor wurde also nicht grün. Dass die Verwechslung folgenlos blieb, ist Glück der Bauart
— die Eigenschaft, die diese Datei über hunderte Zeilen begründet, war trotzdem verletzt.

DIE REIHENFOLGE IST DER FIX. Die Abwesenheit des Verifiers ist eine Aussage über die Umgebung und
wird VOR der Kanonisierung geprüft; alles, was danach beim Kanonisieren schiefgeht, ist eine
Aussage über das Artefakt.
"""
from __future__ import annotations

import base64
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _matrix():
    if str(REPO / "scripts") not in sys.path:
        sys.path.insert(0, str(REPO / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "_acm_l5", REPO / "scripts" / "audit_candidate_matrix.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acm_l5"] = mod
    spec.loader.exec_module(mod)
    return mod


NULL_PUB = base64.b64encode(b"\x00" * 32).decode()
NULL_SIG = base64.b64encode(b"\x00" * 64).decode()


def _gefaelschtes_artefakt(zusatzfeld: str | None = None) -> dict:
    """Ein Artefakt mit einer SIGNATUR, die nicht verifiziert — 32/64 Nullbytes. Der Unterschied
    zwischen den beiden Fällen ist AUSSCHLIESSLICH ein Zusatzfeld, dessen Länge die Budgetgrenze
    des Kanonisierers überschreitet. Die Fälschung ist in beiden Fällen dieselbe."""
    art = {
        "schema": "b7n0de.readiness_artifact.v1",
        "version": "6.0.0",
        "produced_at": "2026-09-11T09:00:00Z",
        "signature": {"alg": "ed25519", "public_key_b64": NULL_PUB, "sig_b64": NULL_SIG},
    }
    if zusatzfeld is not None:
        art["zusatz"] = zusatzfeld
    return art


class TestDieselbeFaelschungDasselbeUrteil(unittest.TestCase):

    def setUp(self):
        self.m = _matrix()
        self.trusted = {NULL_PUB: {"role": "readiness_und_register_signierer_600"}}

    def _zustand(self, art):
        return self.m._artifact_signature_ok(art, self.trusted, "ok", repo=REPO)

    def test_die_gefaelschte_signatur_ohne_zusatzfeld_ist_untrusted(self):
        """ANTI-PARITÄT und Vorbedingung: ohne diese Zeile wäre die Probe darunter leer-wahr,
        weil ein Prüfer, der ALLES als untrusted meldet, sie bestünde."""
        zustand, grund = self._zustand(_gefaelschtes_artefakt())
        self.assertEqual(zustand, self.m.ART_UNTRUSTED,
                         f"Kontrolle gefallen: die Fälschung wird nicht als untrusted erkannt ({grund})")

    def test_dasselbe_artefakt_mit_grossem_feld_bleibt_ein_inhaltsfehler(self):
        """DER FUND. Ein Feld über der Budgetgrenze macht aus derselben Fälschung keinen
        Umgebungsmangel."""
        gross = "x" * 1_000_001
        zustand, grund = self._zustand(_gefaelschtes_artefakt(gross))
        self.assertNotEqual(
            zustand, self.m.ART_UNMEASURABLE_HERE,
            "eine gefälschte Signatur wird als 'hier nicht messbar' gemeldet, sobald das Artefakt "
            f"ein Feld über der Budgetgrenze trägt — das ist eine Aussage über die Umgebung, und "
            f"die Umgebung ist in Ordnung ({grund})")

    def test_beide_faelle_liefern_DASSELBE_verdikt(self):
        """Die Eigenschaft in einem Satz: der Unterschied ist ein Zusatzfeld, das Urteil darf sich
        dadurch nicht ändern."""
        def verdikt(art):
            zustand, grund = self._zustand(art)
            return self.m._artifact_verdict({"state": zustand, "detail": grund})

        ohne = verdikt(_gefaelschtes_artefakt())
        mit = verdikt(_gefaelschtes_artefakt("x" * 1_000_001))
        self.assertEqual(ohne[0], mit[0],
                         f"dieselbe Fälschung, zwei Verdikte: ohne Zusatzfeld {ohne[0]}, mit {mit[0]}")

    def test_ein_fehlender_kanonisierer_bleibt_ein_umgebungsmangel(self):
        """DIE GEGENRICHTUNG, und sie ist die Hälfte, die den Fix von einer Verschärfung
        unterscheidet: ist der Kanonisierer WIRKLICH nicht da, ist `DATA_BLOCKED` richtig. Ein Fix,
        der auch das zu FAIL macht, hätte die Ehrlichkeit über Nicht-Gemessenes zerstört."""
        import proofbundle
        echtes = proofbundle.canonical
        try:
            del sys.modules["proofbundle.canonical"]
            proofbundle.canonical = None  # der Import gelingt, das Modul ist unbrauchbar
            m = _matrix()
            zustand, grund = m._artifact_signature_ok(
                _gefaelschtes_artefakt(), self.trusted, "ok", repo=REPO)
        finally:
            proofbundle.canonical = echtes
            sys.modules["proofbundle.canonical"] = echtes
        self.assertEqual(zustand, m.ART_UNMEASURABLE_HERE,
                         f"ohne brauchbaren Kanonisierer muss das Urteil UMGEBUNG bleiben ({grund})")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
