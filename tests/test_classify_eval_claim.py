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
        self.assertGreaterEqual(len(eigene), 10)
        rollen: dict = {}
        for rel in eigene:
            case = json.loads((root / "conformance" / rel / "case.json").read_text())
            self.assertEqual(case["kind"], "envelope_profile_rule", rel)
            rollen.setdefault(case["rule"], set()).add(case["role"])
        for regel in ("R1", "R2", "R3", "R4", "R5"):
            self.assertIn(regel, rollen, f"{regel} hat keinen Vektor")
            self.assertIn("counter_proof", rollen[regel], f"{regel} ohne Gegenprobe")
            self.assertIn("positive_control", rollen[regel], f"{regel} ohne Positivkontrolle")


if __name__ == "__main__":
    unittest.main()
