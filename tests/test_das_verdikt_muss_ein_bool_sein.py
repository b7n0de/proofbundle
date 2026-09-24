"""R-B4: a verdict field must hold a verdict, at every public surface that reads one.

WHAT THIS FILE IS FOR, and it is not "the type is checked". It is the MONOTONICITY of the emit path:
writing a value that merely LOOKS like a non-pass must never produce a more permissive outcome than
the non-pass itself. The in-toto attestation spec states the principle for consumers — ignoring an
attestation or a field within it must never turn a DENY into an ALLOW — and the measurement below is
the same principle on the producing side.

MEASURED BEFORE THE FIX, 2026-09-24 on `d8c9c61` in a throwaway worktree of that exact commit, by
calling the exporters DIRECTLY, which is the reach the register describes:

    to_test_result_statement   passed=False -> result='FAILED'   passed='false' -> result='PASSED'
    to_eval_result_predicate   passed=False -> passed=False      passed='false' -> passed=True
    svr_properties             passed=False -> []                passed='false' -> ['…THRESHOLD_MET']
    to_intoto_statement        passed=False -> False             passed='false' -> 'false' passed on raw

`bool("false")` is `True`, and `"false"` is a non-empty string, so it also survived the presence check
`claim.get(k) in (None, "")` that made `passed` look validated because it was required.

WHAT THE REGISTER GOT RIGHT, and the first version of this file said otherwise.
`DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01` (RESTRISIKO_610.md:150-185) scopes the
exposure to the DIRECT library caller and argues that every path through `decode_eval_claim` is safe.
Measured on `d8c9c61`, that is exactly true: the A-15 boundary check refuses `'false'`, `'0'` and `1`,
and `export_svr_dsse`, which decodes first, refuses them with it. An earlier draft of this file
asserted the opposite and described a signed SVR carrying PROOFBUNDLE_THRESHOLD_MET for a string
verdict. That measurement was taken in `/home/konrad/proofbundle`, a checkout 47 commits behind main
and 9 ahead of it, where A-15 is absent. The number was real and it was about another tree.

WHAT THE REGISTER UNDERSTATES is narrower than that draft claimed, and it is still worth writing down:
it names THREE sites, and reading the file finds FIVE in the same reach — `intoto.py:99` passes the raw
value through into the self-hosted predicate, and `:251` picks `passedTests` versus `failedTests`
alongside the `:246` result mapping. It names the string `'false'`; `'False'`, `'FALSE'`, `'0'`, `'no'`,
`1`, `[1]` and `{'a': 1}` behave the same way.

WHICH CASES BELOW ARE CATCH PROOFS AND WHICH ARE CONTROLS, measured rather than assumed, because a
case that was already green proves nothing about this change. Run against `d8c9c61` without the fix:
the four `*_weist_ab` exporter cases fail (61 subtest failures), and so do the message-form case, the
numpy-limit case and the scanner. The verify-boundary case and the end-to-end SVR case PASS there —
they are regression guards for A-15, and they are marked as such where they stand.

WHY THE CASES DRIVE THE PUBLIC FUNCTIONS AND NOT THE CLI. The register asks for the catch proof at the
public functions, because a library caller reaches them without any CLI. A CLI-level case would pass
over the same defect.
"""
import base64
import json
import unittest

from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import (EvalClaimError, build_eval_claim, decode_eval_claim, emit_eval_receipt,
                                   issuer_fingerprint)
from proofbundle.intoto import (export_svr_dsse, svr_properties, to_eval_result_predicate,
                                to_intoto_statement, to_test_result_statement)

#: Values that are NOT booleans and that a truthiness test or `bool()` would read as a PASS.
#: `'0'` and `1` are in here on purpose: `'0'` is a non-empty string, and `bool` subclasses `int`, so
#: an int-typed check would have accepted `1` while rejecting nothing that matters.
NICHT_BOOL_ABER_WAHR = ("false", "False", "FALSE", "0", "no", 1, 1.0, [1], {"a": 1})

#: Values that are not booleans and that a truthiness test would read as a non-pass. They must be
#: refused TOO. A guard that only catches the dangerous direction teaches that the other one is fine,
#: and the next reader writes `passed: 0` expecting it to mean False.
NICHT_BOOL_UND_FALSCH = (0, 0.0, "", None, [], {})


def _echter_anspruch(signer):
    claim, _ = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="accuracy", comparator=">=",
        threshold="0.65", score="0.92", n=500, model_id="acme/model-x", dataset_id="acme/set",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-01T12:00:00Z",
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class _Ergebnis:
    """The minimal shape `svr_properties` reads: `.checks`, each with `.name` and `.ok`."""

    ok = True
    checks = ()


class TestDieSechsStellenWeisenEinenNichtBoolAb(unittest.TestCase):
    """One case per public surface that reads `passed`. Six, not the three the register names."""

    def setUp(self):
        self.signer = generate_signer()
        self.echt = _echter_anspruch(self.signer)

    def _mit(self, wert):
        c = dict(self.echt)
        c["passed"] = wert
        return c

    def _alle_fremden(self):
        return (*NICHT_BOOL_ABER_WAHR, *NICHT_BOOL_UND_FALSCH)

    def test_to_intoto_statement_weist_ab(self):
        """intoto.py:99 passed the raw value THROUGH, so the predicate carried the string itself."""
        for wert in self._alle_fremden():
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError) as ctx:
                    to_intoto_statement(self._mit(wert))
                self.assertIn("passed", str(ctx.exception))

    def test_to_test_result_statement_weist_ab(self):
        """intoto.py:246 and :251 — `_RESULT_ENUM[bool(...)]` and the passedTests/failedTests key."""
        for wert in self._alle_fremden():
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError):
                    to_test_result_statement(self._mit(wert), subject_digest={"sha256": "0" * 64})

    def test_to_eval_result_predicate_weist_ab(self):
        """intoto.py:424 via `_require_export_fields` — where presence was mistaken for validation."""
        for wert in self._alle_fremden():
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError):
                    to_eval_result_predicate(self._mit(wert))

    def test_svr_properties_weist_ab(self):
        """intoto.py:551, the most load-bearing of the six: what it decides gets SIGNED."""
        for wert in self._alle_fremden():
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError):
                    svr_properties(_Ergebnis(), self._mit(wert))

    def test_die_verify_schwelle_weist_ab_REGRESSIONSWACHE(self):
        """NOT A CATCH PROOF. Measured green on `d8c9c61` before this change, and it must stay green.

        A-15 typed `passed` at this boundary on 2026-09-19, and that is why the CLI paths and
        `export_svr_dsse` were never exposed. This case exists so a later edit cannot quietly remove
        that check while the exporter cases above keep the file green — the two halves guard different
        callers and either one alone would read like the whole.

        Saying so in the name matters more than it looks: a reader counting green cases as evidence for
        this change would otherwise count this one, and it was already true.
        """
        for wert in ("false", "0", 1, None, [1]):
            with self.subTest(passed=wert):
                bundle = emit_eval_receipt(self._mit(wert), self.signer)
                self.assertIsNone(decode_eval_claim(bundle),
                                  f"a signed claim with passed={wert!r} decoded as valid")

    def test_export_svr_dsse_emittiert_kein_signiertes_svr_REGRESSIONSWACHE(self):
        """NOT A CATCH PROOF either, and an earlier draft of this file claimed it was the worst case.

        Measured green on `d8c9c61`: `export_svr_dsse` decodes first, so the A-15 boundary already
        refuses a string verdict here. The draft that called this the severe path had measured a
        checkout 47 commits behind main. It stays as a regression guard, because this is the path where
        a signed artefact would carry the claim, and that is worth a case even when it holds.
        """
        for wert in ("false", "False", "0", 1):
            with self.subTest(passed=wert):
                bundle = emit_eval_receipt(self._mit(wert), self.signer)
                with self.assertRaises(BundleFormatError):
                    export_svr_dsse(bundle, self.signer)


class TestDieGegenrichtungEinEchterBoolGehtWeiterDURCH(unittest.TestCase):
    """WITHOUT THIS CLASS THE ONE ABOVE PROVES NOTHING.

    A guard that refuses everything passes every rejection case. These cases pin that both booleans
    still produce exactly the outcome they produced before, including the ASYMMETRY that is the whole
    point of an SVR: True is summarised, False is refused.
    """

    def setUp(self):
        self.signer = generate_signer()
        self.echt = _echter_anspruch(self.signer)

    def _mit(self, wert):
        c = dict(self.echt)
        c["passed"] = wert
        return c

    def test_beide_booleans_erreichen_jede_stelle(self):
        for wert in (True, False):
            with self.subTest(passed=wert):
                c = self._mit(wert)
                self.assertEqual(to_intoto_statement(c)["predicate"]["claims"][0]["passed"], wert)
                stmt = to_test_result_statement(c, subject_digest={"sha256": "0" * 64})
                self.assertEqual(stmt["predicate"]["result"], "PASSED" if wert else "FAILED")
                self.assertEqual(to_eval_result_predicate(c)["claims"][0]["passed"], wert)
                props = svr_properties(_Ergebnis(), c)
                self.assertEqual("PROOFBUNDLE_THRESHOLD_MET" in props, wert)

    def test_die_verify_schwelle_nimmt_beide_booleans_an(self):
        for wert in (True, False):
            with self.subTest(passed=wert):
                zurueck = decode_eval_claim(emit_eval_receipt(self._mit(wert), self.signer))
                self.assertIsNotNone(zurueck, "a genuine boolean must still decode")
                self.assertIs(zurueck["passed"], wert)

    def test_die_asymmetrie_des_svr_bleibt(self):
        """True is summarised, False is refused — and the refusal names the threshold, not the type."""
        env = export_svr_dsse(emit_eval_receipt(self._mit(True), self.signer), self.signer)
        props = json.loads(base64.b64decode(env["payload"]))["predicate"]["properties"]
        self.assertIn("PROOFBUNDLE_THRESHOLD_MET", props)
        with self.assertRaises(BundleFormatError) as ctx:
            export_svr_dsse(emit_eval_receipt(self._mit(False), self.signer), self.signer)
        self.assertIn("did not pass its threshold", str(ctx.exception))

    def test_die_passedTests_schluessel_folgen_dem_verdikt(self):
        """The second site inside `to_test_result_statement`, measured in both directions."""
        for wert, erwartet, verboten in ((True, "passedTests", "failedTests"),
                                         (False, "failedTests", "passedTests")):
            with self.subTest(passed=wert):
                p = to_test_result_statement(self._mit(wert),
                                            subject_digest={"sha256": "0" * 64})["predicate"]
                self.assertIn(erwartet, p)
                self.assertNotIn(verboten, p)


class TestDieMonotonieIstDieEIGENTLICHEAussage(unittest.TestCase):
    """THE PROPERTY, not the six instances: no non-boolean is treated more permissively than `False`.

    This is what a count of guarded call sites can never say. A seventh site added tomorrow, reading
    `passed` with a truthiness test, breaks this class even though no case above mentions it — as long
    as it sits behind one of the entry points these cases drive.
    """

    def setUp(self):
        self.signer = generate_signer()
        self.echt = _echter_anspruch(self.signer)

    def _mit(self, wert):
        c = dict(self.echt)
        c["passed"] = wert
        return c

    def _positiv_am_direkten_ausgang(self, wert):
        """Does ANY direct exporter read this value as a pass? Any refusal counts as no.

        THE DIRECT EXPORTERS AND NOT `export_svr_dsse`, and the first version of this class got that
        wrong. It routed through the SVR export, which decodes first, so the A-15 boundary refused every
        value and the property held on `d8c9c61` without the fix — a property test over a path that was
        already closed. The DENY-to-ALLOW actually happened here, where a library caller arrives with a
        claim in hand and no boundary in between.

        Both typed refusals are caught. A float never reaches these functions from a signed receipt,
        but a direct caller can hand one over, and `_require_bool_verdict` is what stops it; the claim
        profile's `EvalClaimError` only appears on the signing path. Anything OTHER than the two typed
        refusals propagates on purpose: a bare `except Exception` would turn a crash into a quiet
        "not a pass", which is the shape this whole file exists against.
        """
        c = self._mit(wert)
        for lies in (
            lambda: to_test_result_statement(c, subject_digest={"sha256": "0" * 64})
                    ["predicate"]["result"] == "PASSED",
            lambda: to_eval_result_predicate(c)["claims"][0]["passed"] is True,
            lambda: "PROOFBUNDLE_THRESHOLD_MET" in svr_properties(_Ergebnis(), c),
            lambda: to_intoto_statement(c)["predicate"]["claims"][0]["passed"] is not False,
        ):
            try:
                if lies():
                    return True
            except (BundleFormatError, EvalClaimError):
                continue
        return False

    def _summiert_signiert(self, wert):
        """The SVR path, kept as the SECOND statement: already closed by A-15, and it must stay closed."""
        try:
            env = export_svr_dsse(emit_eval_receipt(self._mit(wert), self.signer), self.signer)
        except (BundleFormatError, EvalClaimError):
            return False
        props = json.loads(base64.b64decode(env["payload"]))["predicate"]["properties"]
        return "PROOFBUNDLE_THRESHOLD_MET" in props

    def test_welches_tor_welchen_wert_abweist(self):
        """WHICH gate refuses WHICH value, recorded rather than folded into one pass/fail.

        A single "everything is refused" assertion cannot tell a value stopped by the new verdict check
        from one stopped by the JCS profile years ago — and if the new check were removed, the second
        group would keep the test green.
        """
        for wert in (*NICHT_BOOL_ABER_WAHR, *NICHT_BOOL_UND_FALSCH):
            # BY TYPE AND NOT BY SET MEMBERSHIP, and the first version of this case got it wrong in
            # exactly the way this file is about. `1 == 1.0 == True` and all three hash the same, so
            # `wert in {1.0, 0.0}` answered True for the INT `1`; and `[1]`/`{}` are unhashable, so the
            # membership test raised instead of answering. A form that looks like the value is not the
            # value. Measured 2026-09-24: of these fifteen, exactly the two floats are refused by the
            # claim profile, every other one reaches the verdict check.
            vom_jcs_profil = type(wert) is float
            with self.subTest(passed=wert):
                try:
                    export_svr_dsse(emit_eval_receipt(self._mit(wert), self.signer), self.signer)
                except EvalClaimError:
                    self.assertTrue(vom_jcs_profil,
                                    f"passed={wert!r} was refused by the claim profile, not by the "
                                    f"verdict check — say so here instead of counting it as proof")
                except BundleFormatError:
                    self.assertFalse(vom_jcs_profil,
                                     f"passed={wert!r} is a float and should have been stopped by the "
                                     f"claim profile one layer earlier")
                else:
                    self.fail(f"passed={wert!r} produced a signed SVR")

    def test_nur_das_echte_True_liest_am_direkten_ausgang_als_pass(self):
        """THE CATCH PROOF of this class. Fails on `d8c9c61` for eight of the fifteen values."""
        self.assertTrue(self._positiv_am_direkten_ausgang(True),
                        "the honest pass must still read as a pass, or this class would hold over a "
                        "surface that refuses everything")
        self.assertFalse(self._positiv_am_direkten_ausgang(False))
        for wert in (*NICHT_BOOL_ABER_WAHR, *NICHT_BOOL_UND_FALSCH):
            with self.subTest(passed=wert):
                self.assertFalse(self._positiv_am_direkten_ausgang(wert),
                                 f"passed={wert!r} read as a pass at a direct exporter, so a value "
                                 f"that is not a verdict was treated as one")

    def test_der_signierte_weg_bleibt_geschlossen_REGRESSIONSWACHE(self):
        """The same property on the SVR path, which A-15 already closed. Green before this change."""
        self.assertTrue(self._summiert_signiert(True))
        self.assertFalse(self._summiert_signiert(False))
        for wert in (*NICHT_BOOL_ABER_WAHR, *NICHT_BOOL_UND_FALSCH):
            with self.subTest(passed=wert):
                self.assertFalse(self._summiert_signiert(wert))

    def test_die_meldung_nennt_feld_und_typ_statt_nur_zu_scheitern(self):
        """A refusal a caller cannot act on sends them guessing. The one thing they need is which
        field and what arrived; `"false"` came from somewhere, and only they know from where."""
        with self.assertRaises(BundleFormatError) as ctx:
            svr_properties(_Ergebnis(), self._mit("false"))
        text = str(ctx.exception)
        self.assertIn("passed", text)
        self.assertIn("str", text)
        self.assertIn("'false'", text)

    def test_die_genannte_grenze_ein_numpy_bool_wird_ABGEWIESEN(self):
        """RECORDED AS A LIMIT, not as an assurance, because this repository imports numpy.

        `numpy.bool_` is not a `bool` subclass, so it is refused here. For a signed attestation that
        is the safe direction, and `adapters/eee.py` makes it a real edge rather than a theoretical
        one: a harness handing a numpy scalar straight into a claim gets a refusal naming the type.
        The fix belongs at that harness boundary, where the value is known.
        """
        try:
            import numpy  # noqa: PLC0415
        except ImportError:
            self.skipTest("numpy is not installed here — the limit stands, it is NOT MEASURABLE in "
                          "this environment, and a silent pass would read like a checked one")
        with self.assertRaises(BundleFormatError) as ctx:
            svr_properties(_Ergebnis(), self._mit(numpy.bool_(True)))
        self.assertIn("passed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
