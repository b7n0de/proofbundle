"""Coverage block (5.1, additive) — one red test per invariant.

R5 of the receipt-envelope profile: a cryptographically clean receipt over an EMPTY check set must
not be indistinguishable from a clean receipt over a FULL one. Integrity does not imply coverage.

The block is optional as a whole and COMPLETE when present. Every invariant is enforced on all
three paths (build, emit, verify) from ONE definition — a rule enforced only at emit is bypassed by
a hand-signed claim, which is the asymmetry class this module already guards for `samples`.
"""
import json
import unittest
from pathlib import Path

from proofbundle import verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.evalclaim import (
    EvalClaimError,
    _coverage_error,
    build_eval_claim,
    canonicalize,
    decode_eval_claim,
    emit_eval_receipt,
)

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev-only dependency
    jsonschema = None

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "eval_claim_v0_1.schema.json").read_text(encoding="utf-8"))
TS = "2026-08-30T12:00:00Z"
GOOD = {"population_size": 620, "evaluated_count": 500, "unresolved_count": 40}


def _claim(signer, *, coverage=None, n=500):
    claim, _ = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate", comparator=">=",
        threshold="0.80", score="0.92", n=n, model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer="ed25519:placeholder", timestamp=TS, coverage=coverage)
    return claim


class TestCoveragePositiv(unittest.TestCase):
    def test_beleg_mit_coverage_geht_durch_und_ueberlebt(self):
        signer = generate_signer()
        decoded = decode_eval_claim(emit_eval_receipt(_claim(signer, coverage=GOOD), signer))
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["coverage"], GOOD)

    def test_ohne_coverage_unveraendert(self):
        # Rueckwaertskompatibilitaet: ein Beleg ohne den Block bleibt gueltig wie zuvor.
        signer = generate_signer()
        decoded = decode_eval_claim(emit_eval_receipt(_claim(signer), signer))
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertNotIn("coverage", decoded)

    def test_leere_pruefmenge_ist_unterscheidbar(self):
        # Der GRUND fuer R5: zwei kryptografisch einwandfreie Belege, einer ueber eine volle und
        # einer ueber eine LEERE Pruefmenge, muessen fuer einen Konsumenten unterscheidbar sein.
        signer = generate_signer()
        voll = decode_eval_claim(emit_eval_receipt(
            _claim(signer, coverage={"population_size": 500, "evaluated_count": 500,
                                     "unresolved_count": 0}), signer))
        leer = decode_eval_claim(emit_eval_receipt(
            _claim(signer, n=0, coverage={"population_size": 500, "evaluated_count": 0,
                                          "unresolved_count": 500}), signer))
        for d in (voll, leer):
            self.assertIsNotNone(d)
        assert voll is not None and leer is not None
        self.assertTrue(verify_bundle(emit_eval_receipt(_claim(signer, coverage=GOOD), signer)).ok)
        self.assertNotEqual(voll["coverage"]["evaluated_count"], leer["coverage"]["evaluated_count"])


class TestCoverageMussFehlschlagen(unittest.TestCase):
    """Je Invariante ein roter Test. Alle am BAU-Pfad."""

    def _build_muss_scheitern(self, coverage, teil, *, n=500):
        with self.assertRaises(EvalClaimError) as ctx:
            _claim(generate_signer(), coverage=coverage, n=n)
        self.assertIn(teil, str(ctx.exception))

    def test_unvollstaendiger_block(self):
        self._build_muss_scheitern({"population_size": 620, "evaluated_count": 500}, "complete")

    def test_unbekanntes_feld_im_block(self):
        self._build_muss_scheitern(dict(GOOD, sneaky=1), "complete")

    def test_evaluated_count_ungleich_n(self):
        self._build_muss_scheitern(dict(GOOD, evaluated_count=499), "must equal the claim's n")

    def test_summe_ueber_population(self):
        self._build_muss_scheitern({"population_size": 500, "evaluated_count": 500,
                                    "unresolved_count": 1}, "DISJOINT")

    def test_negative_zahl(self):
        self._build_muss_scheitern(dict(GOOD, unresolved_count=-1), "non-negative integer")

    def test_bool_ist_kein_integer(self):
        # True == 1 in Python; ohne die bool-Pruefung rutscht es durch jede >=0-Schranke.
        self._build_muss_scheitern(dict(GOOD, unresolved_count=True), "non-negative integer")

    def test_kein_objekt(self):
        self._build_muss_scheitern("100/620", "must be an object")


class TestCoverageVerifyPfad(unittest.TestCase):
    """Die eigentliche Klasse: eine nur am Emit-Pfad erzwungene Garantie wird von einem
    HANDSIGNIERTEN Beleg umgangen. Die Signatur bleibt gueltig, nur decode weist zurueck."""

    def test_handsignierter_beleg_mit_kaputter_coverage_decodiert_nicht(self):
        signer = generate_signer()
        gut = decode_eval_claim(emit_eval_receipt(_claim(signer, coverage=GOOD), signer))
        assert gut is not None
        for kaputt in (dict(GOOD, evaluated_count=1),
                       {"population_size": 1, "evaluated_count": 500, "unresolved_count": 0},
                       {"population_size": 620, "evaluated_count": 500},
                       dict(GOOD, sneaky=1),
                       dict(GOOD, unresolved_count=-1)):
            c = dict(gut, coverage=kaputt)
            bundle = emit_bundle(canonicalize(c), signer)
            self.assertTrue(verify_bundle(bundle).ok, f"{kaputt}: Signatur muss weiter gelten")
            self.assertIsNone(decode_eval_claim(bundle), f"{kaputt}: darf NICHT decodieren")

    def test_emit_weist_kaputte_coverage_ab(self):
        # Einen Beleg auszugeben, den der EIGENE Verifier zurueckweist, ist eine Falle.
        signer = generate_signer()
        c = dict(_claim(signer, coverage=GOOD), coverage=dict(GOOD, evaluated_count=7))
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(c, signer)


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
class TestCoverageSchemaParitaet(unittest.TestCase):
    """Die Schemata sind DOKU, erzwungen wird im Modul. Driften sie auseinander, ist das genau die
    Klasse, gegen die test_schema_parity.py gebaut wurde — hier fuer eval_claim, das dort fehlt."""

    def _schema_ok(self, claim):
        try:
            jsonschema.validate(instance=claim, schema=SCHEMA)
            return True
        except jsonschema.ValidationError:
            return False

    def test_beide_seiten_stimmen_ueberein(self):
        basis = _claim(generate_signer())
        faelle = [
            (GOOD, True),
            ({"population_size": 0, "evaluated_count": 0, "unresolved_count": 0}, True),
            ({"population_size": 620, "evaluated_count": 500}, False),
            (dict(GOOD, sneaky=1), False),
            (dict(GOOD, unresolved_count=-1), False),
            (dict(GOOD, population_size="620"), False),
        ]
        for cov, erwartet in faelle:
            n = cov.get("evaluated_count") if isinstance(cov.get("evaluated_count"), int) else 500
            claim = dict(basis, n=n, coverage=cov)
            modul_ok = _coverage_error(cov, n) is None
            schema_ok = self._schema_ok(claim)
            self.assertEqual(modul_ok, erwartet, f"{cov}: Modul sagt {modul_ok}")
            self.assertEqual(schema_ok, erwartet, f"{cov}: Schema sagt {schema_ok}")
            self.assertEqual(modul_ok, schema_ok, f"{cov}: DIVERGENZ Modul={modul_ok} Schema={schema_ok}")

    def test_gemessene_grenze_additiv_ist_nur_eine_richtung(self):
        """EHRLICHE GRENZE, als ausfuehrbare Tatsache statt als Behauptung.

        Die Schemata fahren additionalProperties:false. Ein ALTER Beleg gilt unter dem NEUEN Schema
        weiter (rueckwaerts). Ein NEUER Beleg mit coverage faellt unter dem ALTEN Schema durch —
        und zwar als UNGUELTIG, nicht als unbekannt. Das ist genau die Unterscheidung, die R2 des
        Profils von einem Verifier verlangt, und unsere eigene Schemaform leistet sie hier nicht.
        """
        alt = json.loads(json.dumps(SCHEMA))
        del alt["properties"]["coverage"]
        basis = _claim(generate_signer())
        self.assertTrue(self._schema_ok(basis), "alter Beleg unter NEUEM Schema: muss gelten")
        neu = dict(basis, coverage=GOOD)
        self.assertTrue(self._schema_ok(neu), "neuer Beleg unter NEUEM Schema: muss gelten")
        try:
            jsonschema.validate(instance=neu, schema=alt)
            self.fail("neuer Beleg unter ALTEM Schema: haette durchfallen muessen")
        except jsonschema.ValidationError as e:
            self.assertIn("Additional properties", str(e))


if __name__ == "__main__":
    unittest.main()


class TestFehlerformIstEinheitlich(unittest.TestCase):
    """Alle Aufrufstellen pruefen `is not None`, nie den Wahrheitswert. Ein leerer Fehlerstring
    waere falsy und rutschte an einer Wahrheitspruefung vorbei, waehrend die Identitaetspruefung
    ihn zurueckwiese — zwei Formen, die sich widersprechen, sind die Asymmetrie eine Ebene tiefer.
    Aufgeworfen von der Gegenlesung am 30.08.2026."""

    def test_kein_rueckgabewert_ist_ein_leerer_string(self):
        import ast
        import inspect
        from proofbundle import evalclaim
        quelle = inspect.getsource(evalclaim._coverage_error)
        baum = ast.parse(quelle.lstrip())
        rueck = [n for n in ast.walk(baum) if isinstance(n, ast.Return)]
        self.assertTrue(rueck)
        for r in rueck:
            if isinstance(r.value, ast.Constant):
                self.assertNotEqual(r.value.value, "", "ein leerer Fehlerstring waere falsy")

    def test_alle_aufrufstellen_pruefen_identitaet(self):
        import inspect
        from proofbundle import evalclaim
        quelle = inspect.getsource(evalclaim)
        zeilen = [z.strip() for z in quelle.splitlines() if "_coverage_error(" in z]
        aufrufe = [z for z in zeilen if not z.startswith("def ")]
        self.assertGreaterEqual(len(aufrufe), 3, "build, emit und verify muessen rufen")
        for z in aufrufe:
            # entweder direkt `is not None`, oder Zuweisung an err (die naechste Zeile prueft sie)
            self.assertTrue("is not None" in z or z.startswith("err = "), f"Form nicht einheitlich: {z}")
        self.assertNotIn("if err:", quelle, "Wahrheitspruefung auf einen Fehlerstring")
