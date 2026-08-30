"""Typed digest reference on evidenceRefs[] (5.1, additive) — one red test per invariant.

G3 of docs/SCITT_CPB_MAPPING.md: our evidence references carry the algorithm inside the KEY NAME
(`digest.sha256`), while the draft's typed reference carries it in a field of its own next to what
the referenced thing IS and what role the digest plays. `relationDigest` in the same schema already
does it the conformant way — the gap was internal inconsistency, not absence.

`typedDigest` is an ADDITIONAL shape. It replaces nothing: an entry may carry `digest` alone,
`typedDigest` alone, or both. The schema is DOCS, decision.py is ENFORCED — so every case here is
checked on BOTH, because a divergence between them is the class test_schema_parity.py exists for.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from proofbundle.decision import _typed_digest_error, validate_decision_predicate

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "decision-receipt-v0.1.schema.json").read_text(encoding="utf-8"))
EXAMPLES = ROOT / "examples"
GOOD = {"type": "eval-receipt", "purpose": "threshold-evidence",
        "digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64}


def _deny() -> dict:
    return json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))


class TestTypedDigestHelfer(unittest.TestCase):
    def test_gute_referenz(self):
        self.assertIsNone(_typed_digest_error(GOOD))

    def test_purpose_ist_optional(self):
        self.assertIsNone(_typed_digest_error({k: v for k, v in GOOD.items() if k != "purpose"}))

    def test_pflichtfelder(self):
        for fehlt in ("type", "digestAlgorithm", "digest"):
            err = _typed_digest_error({k: v for k, v in GOOD.items() if k != fehlt})
            self.assertIsNotNone(err)
            assert err is not None
            self.assertIn(fehlt, err)

    def test_algorithmus_wird_nie_vorbelegt(self):
        # Der Grund, den relationDigest im selben Schema nennt: ein fehlender Wert ist genau die
        # Stelle, an der sich Algorithmus-Verwechslung versteckt.
        for schlecht in ("sha256", "SHA-256", "", None, "legacy-sortkeys-json-v0"):
            self.assertIsNotNone(_typed_digest_error(dict(GOOD, digestAlgorithm=schlecht)))

    def test_digest_muss_64_hex_klein_sein(self):
        for schlecht in ("ab", "A" * 64, "g" * 64, "a" * 63, "a" * 65, 12345, None):
            self.assertIsNotNone(_typed_digest_error(dict(GOOD, digest=schlecht)))

    def test_leere_strings_zaehlen_nicht_als_wert(self):
        for k in ("type", "purpose"):
            self.assertIsNotNone(_typed_digest_error(dict(GOOD, **{k: ""})))

    def test_kein_objekt(self):
        for schlecht in ("a" * 64, ["a"], 1, None, True):
            self.assertIsNotNone(_typed_digest_error(schlecht))


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestTypedDigestParitaet(unittest.TestCase):
    """Doku-Schema und erzwungener Validator muessen sich EINIG sein: beide annehmen oder beide ablehnen."""

    def _beide(self, ref_over, *, erwartet: bool, msg: str):
        p = _deny()
        p["evidenceRefs"][0].update(ref_over)
        hand = not validate_decision_predicate(p, strict=True)
        try:
            jsonschema.validate(instance=p, schema=SCHEMA)
            schema = True
        except jsonschema.ValidationError:
            schema = False
        self.assertEqual(hand, erwartet, f"{msg}: Validator sagt {hand}")
        self.assertEqual(schema, erwartet, f"{msg}: Schema sagt {schema}")
        self.assertEqual(hand, schema, f"{msg}: DIVERGENZ Validator={hand} Schema={schema}")

    def test_ohne_typed_digest_unveraendert(self):
        self._beide({}, erwartet=True, msg="ohne typedDigest")

    def test_mit_gueltiger_typed_digest(self):
        self._beide({"typedDigest": GOOD}, erwartet=True, msg="gueltig")

    def test_ohne_purpose(self):
        self._beide({"typedDigest": {k: v for k, v in GOOD.items() if k != "purpose"}},
                    erwartet=True, msg="ohne purpose")

    def test_fehlender_typ_faellt_auf_beiden_durch(self):
        self._beide({"typedDigest": {k: v for k, v in GOOD.items() if k != "type"}},
                    erwartet=False, msg="type fehlt")

    def test_fehlender_algorithmus_faellt_auf_beiden_durch(self):
        self._beide({"typedDigest": {k: v for k, v in GOOD.items() if k != "digestAlgorithm"}},
                    erwartet=False, msg="digestAlgorithm fehlt")

    def test_falscher_algorithmus_faellt_auf_beiden_durch(self):
        self._beide({"typedDigest": dict(GOOD, digestAlgorithm="sha256")},
                    erwartet=False, msg="digestAlgorithm falsch")

    def test_kaputter_digest_faellt_auf_beiden_durch(self):
        self._beide({"typedDigest": dict(GOOD, digest="ZZ")}, erwartet=False, msg="digest kaputt")

    def test_unbekanntes_feld_im_block_faellt_auf_beiden_durch(self):
        # Der verschachtelte Verschluss (Finding 04) muss auch den NEUEN Pfad decken.
        self._beide({"typedDigest": dict(GOOD, sneaky=1)}, erwartet=False, msg="sneaky im typedDigest")

    def test_typed_digest_ersetzt_das_pflichtfeld_digest_nicht(self):
        p = _deny()
        del p["evidenceRefs"][0]["digest"]
        p["evidenceRefs"][0]["typedDigest"] = GOOD
        self.assertNotEqual(validate_decision_predicate(p, strict=True), [],
                            "typedDigest darf das erforderliche digest NICHT ersetzen")
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=p, schema=SCHEMA)


if __name__ == "__main__":
    unittest.main()


class TestHelferTraegtAllein(unittest.TestCase):
    """Der Helfer wird direkt aufgerufen und direkt geprueft — er muss ALLEIN tragen, nicht nur
    im Verbund mit dem verschachtelten Verschluss des Aufrufers."""

    def test_unbekanntes_feld_ohne_den_verschluss(self):
        err = _typed_digest_error(dict(GOOD, sneaky=1))
        self.assertIsNotNone(err)
        assert err is not None
        self.assertIn("sneaky", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class TestKonformitaetsHandlerFailClosed(unittest.TestCase):
    """Der envelope_profile_rule-Handler muss in BEIDE Richtungen fail-closed sein: ein Fall ohne
    Erwartungsachse kann nicht fehlschlagen, ein Fall mit ZWEI verbirgt alles nach der ersten.
    Beide Funde kamen aus der Gegenlesung am 30.08.2026 und wurden vor dem Fix am Quelltext
    bestaetigt."""

    def _handler(self):
        import sys
        sys.path.insert(0, str(ROOT / "conformance"))
        import run_conformance  # noqa: PLC0415
        return run_conformance._check_envelope_profile_rule

    def _fall(self):
        d = ROOT / "conformance" / "envelope_profile" / "r1-positive-control-canonical-root"
        return json.loads((d / "case.json").read_text()), d

    def test_ein_fall_ohne_achse_faellt_durch(self):
        case, d = self._fall()
        case = dict(case, expected={})
        r = self._handler()(case, d)
        self.assertFalse(r["ok"])
        self.assertIn("EXACTLY ONE", r["detail"])

    def test_ein_fall_mit_zwei_achsen_faellt_durch(self):
        # Vor dem Fix wurde dieser Fall GRUEN: die erste Achse stimmte, die zweite war Unsinn
        # und wurde nie geprueft.
        case, d = self._fall()
        case = dict(case, expected=dict(case["expected"], classification="voelliger_unsinn"))
        r = self._handler()(case, d)
        self.assertFalse(r["ok"], "eine zweite Achse darf nicht still ignoriert werden")
        self.assertIn("EXACTLY ONE", r["detail"])

    def test_genau_eine_achse_geht_durch(self):
        # Positivkontrolle: ohne sie wuerde ein Handler, der ALLES ablehnt, diese Klasse bestehen.
        case, d = self._fall()
        self.assertTrue(self._handler()(case, d)["ok"])
