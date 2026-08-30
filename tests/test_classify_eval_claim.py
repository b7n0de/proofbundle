"""Three-outcome classification (5.1, additive) — R2: a refusal is not `invalid`.

`decode_eval_claim` returns None for BOTH "I do not know this schema" and "this receipt is broken".
That is its documented, released contract and callers depend on it, so it is left alone.
`classify_eval_claim` is the additive way to get the distinction R2 requires.
"""
import json
import unittest

from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.evalclaim import (
    CLAIM_INVALID,
    CLAIM_REFUSED_UNKNOWN_SCHEMA,
    CLAIM_VALID,
    build_eval_claim,
    canonicalize,
    classify_eval_claim,
    decode_eval_claim,
)

TS = "2026-08-30T00:00:00Z"


def _good(signer, **over):
    kw = dict(suite="s", suite_version="1", metric="m", comparator=">=", threshold="0.80",
              score="0.92", n=10, model_id="a", dataset_id="b", issuer="ed25519:x", timestamp=TS)
    kw.update(over)
    claim, _ = build_eval_claim(**kw)
    from proofbundle.evalclaim import emit_eval_receipt
    return emit_eval_receipt(claim, signer)


class TestDreiAusgaenge(unittest.TestCase):
    def test_gueltig(self):
        outcome, claim = classify_eval_claim(_good(generate_signer()))
        self.assertEqual(outcome, CLAIM_VALID)
        self.assertIsInstance(claim, dict)

    def test_fremde_schema_id_wird_abgelehnt_nicht_fuer_ungueltig_erklaert(self):
        s = generate_signer()
        c = decode_eval_claim(_good(s))
        assert c is not None
        b = emit_bundle(canonicalize(dict(c, schema="acme/other/v9")), s)
        outcome, claim = classify_eval_claim(b)
        self.assertEqual(outcome, CLAIM_REFUSED_UNKNOWN_SCHEMA)
        self.assertIsNone(claim)
        # Der Punkt der Regel: der Ausgang ist ein ANDERER als bei einem kaputten Beleg.
        self.assertNotEqual(outcome, CLAIM_INVALID)

    def test_kaputter_beleg_mit_bekanntem_schema_ist_ungueltig(self):
        s = generate_signer()
        c = decode_eval_claim(_good(s))
        assert c is not None
        b = emit_bundle(canonicalize(dict(c, threshold="inf")), s)
        self.assertEqual(classify_eval_claim(b)[0], CLAIM_INVALID)

    def test_echtheit_wird_zuerst_entschieden(self):
        # Die scharfe Kante: unpruefbar UND fremde schema-id. Eine kaputte Signatur IST
        # beurteilbar, also darf hier NICHT 'ich kann nicht urteilen' herauskommen — sonst
        # erkauft ein Faelscher Schweigen, indem er das Schema-Feld umbenennt.
        s = generate_signer()
        c = decode_eval_claim(_good(s))
        assert c is not None
        b = emit_bundle(canonicalize(dict(c, schema="acme/other/v9")), s)
        sig = b["signature"]["sig_b64"]
        b["signature"] = dict(b["signature"], sig_b64=("B" + sig[1:]) if sig[0] != "B" else ("C" + sig[1:]))
        self.assertEqual(classify_eval_claim(b)[0], CLAIM_INVALID)

    def test_niemals_werfen(self):
        for schrott in ({"not": "a bundle"}, [1, 2, 3], "/kein/pfad.json", "", None, 42, True,
                        {"payload_b64": "!!!", "signature": {}, "merkle": {}, "schema": "x"}):
            outcome, claim = classify_eval_claim(schrott)
            self.assertEqual(outcome, CLAIM_INVALID, f"{schrott!r}")
            self.assertIsNone(claim)

    def test_erwarteter_kontext_wird_durchgereicht(self):
        s = generate_signer()
        b = _good(s, context_binding="ctx-a")
        self.assertEqual(classify_eval_claim(b, expected_context="ctx-a")[0], CLAIM_VALID)
        self.assertEqual(classify_eval_claim(b, expected_context="ctx-b")[0], CLAIM_INVALID)

    def test_vertrag_von_decode_bleibt_unveraendert(self):
        # Die additive Funktion darf den veroeffentlichten Vertrag nicht verschieben.
        s = generate_signer()
        c = decode_eval_claim(_good(s))
        assert c is not None
        fremd = emit_bundle(canonicalize(dict(c, schema="acme/other/v9")), s)
        kaputt = emit_bundle(canonicalize(dict(c, threshold="inf")), s)
        self.assertIsNone(decode_eval_claim(fremd))
        self.assertIsNone(decode_eval_claim(kaputt))


class TestKorpusDeckung(unittest.TestCase):
    """Die Vektorfamilie ist die AEUSSERE Autoritaet fuer diese Regeln — sie muss existieren und
    je Regel eine Gegenprobe UND eine Positivkontrolle fuehren."""

    def test_je_regel_gegenprobe_und_positivkontrolle(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        cases = json.loads((root / "conformance" / "manifest.json").read_text())["cases"]
        eigene = [c for c in cases if c.startswith("envelope_profile/")]
        self.assertGreaterEqual(len(eigene), 9)
        rollen: dict = {}
        for rel in eigene:
            case = json.loads((root / "conformance" / rel / "case.json").read_text())
            self.assertEqual(case["kind"], "envelope_profile_rule", rel)
            rollen.setdefault(case["rule"], set()).add(case["role"])
        for regel in ("R1", "R2", "R3", "R4"):
            self.assertIn(regel, rollen, f"{regel} hat keinen Vektor")
            self.assertIn("counter_proof", rollen[regel], f"{regel} ohne Gegenprobe")
            self.assertIn("positive_control", rollen[regel], f"{regel} ohne Positivkontrolle")
        # R5 traegt in dieser Runde ABSICHTLICH keine Vektoren, Owner-Berichtigung Fassung 8:
        # die Feldform ist offen, seit CAP-1 (draft-hillier-coverage-attestation-00, 20.08.2026)
        # gemessen einen nur durch Subtraktion ausgeglichenen Rest zurueckweist. Eine Gegenprobe
        # gegen eine zurueckgezogene Form waere wertlos. Der Test HAELT das fest, statt es
        # wegzulassen — eine stillschweigend fehlende Regel sieht aus wie eine vergessene.
        self.assertNotIn("R5", rollen,
                         "R5 soll in dieser Runde KEINE Vektoren haben (Fassung 8); "
                         "taucht wieder einer auf, ist die Entscheidung unbemerkt zurueckgenommen")

    def test_die_zahl_im_text_ist_die_gemessene_zahl(self):
        """Die Prosa nennt eine Vektorzahl. Sie muss die GEZAEHLTE sein.

        Am 30.08.2026 stand dort 'twelve', gezaehlt waren dreizehn — die Zahl war nach dem
        Hinzufuegen eines Vektors nicht mitgewachsen. Das ist der Instanzfehler; der Klassenfehler
        ist, dass eine Zahl in einem Dokument an nichts gebunden war. Jetzt ist sie es.
        """
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        gezaehlt = len(list((root / "conformance" / "envelope_profile").glob("*/case.json")))
        WORT = {10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
                15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen"}
        self.assertIn(gezaehlt, WORT, f"{gezaehlt} Vektoren — Zahlwort-Tabelle erweitern")
        wort = WORT[gezaehlt]
        for rel in ("docs/RECEIPT_ENVELOPE_PROFILE.md", "CONFORMANCE.md"):
            text = (root / rel).read_text(encoding="utf-8")
            stellen = [z for z in text.splitlines() if "envelope_profile/" in z and " vectors" in z]
            self.assertTrue(stellen, f"{rel} nennt die Vektorzahl nicht mehr — Test anpassen oder Text")
            for z in stellen:
                self.assertIn(wort, z, f"{rel}: '{z.strip()[:80]}' nennt nicht {wort} ({gezaehlt} gezaehlt)")


if __name__ == "__main__":
    unittest.main()


class TestNeverRaiseUnterTiefe(unittest.TestCase):
    """Die never-raise-Zusage unter PATHOLOGISCHER Verschachtelung (CWE-674).

    Eine Gegenlesung am 30.08.2026 meldete, RecursionError entkomme dem except-Block von
    classify_eval_claim. Gemessen ist der Fund WIDERLEGT: load_claim_text delegiert an den
    budget-begrenzten strikten Parser, der Tiefe auf ein typisiertes EvalClaimError abbildet
    ('JSON nesting is too deep'). Der Test steht trotzdem hier — die Eigenschaft war vorher nur
    an flachem Unsinn geprueft, und genau die interessante Eingabe fehlte.
    """

    def _bundle_mit_nutzlast(self, roh: bytes):
        from proofbundle.emit import emit_bundle
        return emit_bundle(roh, generate_signer())

    def test_tiefe_liste_wirft_nicht(self):
        roh = (b"[" * 20000) + (b"]" * 20000)
        outcome, claim = classify_eval_claim(self._bundle_mit_nutzlast(roh))
        self.assertEqual(outcome, CLAIM_INVALID)
        self.assertIsNone(claim)

    def test_tiefes_objekt_wirft_nicht(self):
        roh = (b"{" + b'"a":{' * 5000 + b"}" * 5001)
        outcome, claim = classify_eval_claim(self._bundle_mit_nutzlast(roh))
        self.assertEqual(outcome, CLAIM_INVALID)
        self.assertIsNone(claim)

    def test_decode_eval_claim_wirft_ebenfalls_nicht(self):
        # Derselbe Vertrag eine Ebene tiefer — classify ruft decode, also muss auch das halten.
        for roh in ((b"[" * 20000) + (b"]" * 20000), b"{" + b'"a":{' * 5000 + b"}" * 5001):
            self.assertIsNone(decode_eval_claim(self._bundle_mit_nutzlast(roh)))

    def test_die_tiefe_wird_typisiert_abgewiesen_nicht_als_recursionerror(self):
        # Der Kern: eine SAUBERE Fehlermeldung statt eines rohen RecursionError.
        from proofbundle.evalclaim import EvalClaimError, load_claim_text
        with self.assertRaises(EvalClaimError) as ctx:
            load_claim_text("[" * 20000 + "]" * 20000)
        self.assertNotIsInstance(ctx.exception, RecursionError)
