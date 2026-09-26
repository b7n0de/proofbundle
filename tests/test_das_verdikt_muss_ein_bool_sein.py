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

AND A SIXTH SITE OUTSIDE THAT FILE, found only after the five were fixed, committed and pushed:
`sdjwt_issue.issue_sd_jwt` copied `passed` into the always-open claims of an SD-JWT and SIGNED it, and
`check_binds_bundle` then accepted that receipt as bound, because it compares the field to the bundle
payload for EQUALITY and both sides carried the same string. Measured at tag `v6.1.0` (`dcac5aee`).
So the count in the paragraph above was not the final count, and the reason it was not is worth more
than the number: five of six sites were in one file, I swept that file, and a sweep of a FILE is not a
sweep of a CLASS. The scanner beside this suite did not help, because it modelled the class as coercion
and this site coerces nothing — it hands an unexamined value to someone else's truthiness test, under a
valid signature. It looks for the pass-through shape too now, and its own catch proof is measured
against this real site rather than against a planted one.

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

from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import (EvalClaimError, build_eval_claim, decode_eval_claim, emit_eval_receipt,
                                   issuer_fingerprint)
from proofbundle.intoto import (export_svr_dsse, svr_properties, to_eval_result_predicate,
                                to_intoto_statement, to_test_result_statement)
from proofbundle.sdjwt_issue import check_binds_bundle, issue_sd_jwt

ROOT_B64 = "cm9vdA=="


def _immer_offen(compact: str) -> dict:
    """The always-open JWT claims of a compact SD-JWT, decoded here rather than via `_jwt_payload`.

    Decoded in this file on purpose: the question is what went UNDER THE SIGNATURE, and routing it
    through the module's own decoder would let a change in that decoder answer it.
    """
    nutzteil = compact.split("~", 1)[0].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(nutzteil + "=" * (-len(nutzteil) % 4)))

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
    """One case per public surface that reads `passed`.

    SIX CODE SITES ACROSS FIVE PUBLIC FUNCTIONS, and the register names three: `intoto.py` carries five
    (`:99`, `:246`, `:251`, `:424`, `:551`) behind four entry points, and `sdjwt_issue.py:88` is the
    sixth, in a fifth. The class name kept its number when the meaning of the number changed, which is
    worth a line rather than a silent rename: it first meant "the five the file has plus the boundary",
    and it now means the six sites of the class.
    """

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

    def test_issue_sd_jwt_weist_ab(self):
        """THE SIXTH SITE, and the only one that puts a signature over the value itself.

        Found after the other five were already fixed and pushed, which is why it has its own case
        rather than a line in the loop above: `sdjwt_issue.py:88` copies `passed` into the always-open
        claims and `signer.sign` runs three lines later. The four `intoto` sites BUILD a statement a
        caller may sign; this one signs.
        """
        for wert in self._alle_fremden():
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError) as ctx:
                    issue_sd_jwt(self._mit(wert), self.signer, root_b64=ROOT_B64)
                self.assertIn("passed", str(ctx.exception))

    def test_kein_signiertes_sd_jwt_traegt_ein_verdikt_das_keines_ist(self):
        """WHAT WAS ACTUALLY POSSIBLE BEFORE, written as the outcome and not as the call.

        Measured at tag `v6.1.0` (`dcac5aee`) and at this branch's head before the guard: the string
        `"false"` was issued verbatim into a signed SD-JWT, and `check_binds_bundle` then accepted that
        receipt as bound — because it compares the field to the bundle payload for EQUALITY, and both
        sides carried the same string. So the defect did not stop at issuance: it produced an artefact
        that passes the binding check a relying party is told to run, whose always-open `passed` reads
        as a pass under Python's truthiness.

        The assertion is deliberately about the ARTEFACT, not about the exception. A case asserting
        `assertRaises` would stay green if a later refactor moved the guard somewhere that still let one
        value through; this one fails unless nothing non-boolean reaches the signature.
        """
        for wert in self._alle_fremden():
            with self.subTest(passed=wert):
                try:
                    compact = issue_sd_jwt(self._mit(wert), self.signer, root_b64=ROOT_B64)
                except BundleFormatError:
                    continue
                gesehen = _immer_offen(compact)["passed"]
                self.fail(f"a SIGNED SD-JWT carries passed={gesehen!r}, and check_binds_bundle "
                          f"accepts it as bound: "
                          f"{check_binds_bundle(compact, self._mit(wert), ROOT_B64)}")

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
                # Signed past the emitter: it runs decode's own claim validation since the follow-up
                # to R-B1 and refuses these before signing, so it cannot produce the carrier.
                bundle = emit_bundle(json.dumps(self._mit(wert)).encode(), self.signer)
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
                # Signed past the emitter, for the reason given in the case above.
                bundle = emit_bundle(json.dumps(self._mit(wert)).encode(), self.signer)
                with self.assertRaises(BundleFormatError):
                    export_svr_dsse(bundle, self.signer)


class TestGEPRUEFTUNDVERWENDETMussDERSELBEWertSein(unittest.TestCase):
    """A CHECK THROUGH ONE ACCESSOR AND A USE THROUGH ANOTHER are two values.

    Review finding on PR 257, P2, 2026-09-24, and it hit an assumption that also lives in my own
    scanner: `_require_export_fields` validates `claim.get("passed")` while
    `to_eval_result_predicate` emitted `claim["passed"]`. For a dict those are the same value; for a
    SUBCLASS they are not.

    Measured with a dict subclass whose `get("passed")` returns True while the stored item is
    `"false"`: the validation passed, the predicate carried the string, and the DSSE path signed it.
    The old comment at the emit site argued the opposite and reasoned about COERCION -- right on that
    point, aimed at the wrong thing.

    The guard is not a third accessor but passing the value on: the validator RETURNS the validated
    value and the emit site uses it. Then there is only ONE accessor left, and the class is closed
    rather than tested.
    """

    class _Zweizuengig(dict):
        """`get` and `__getitem__` disagree. No honest producer builds this; an attacker does, and
        the property has to hold without assumptions about the producer."""

        def get(self, k, d=None):  # noqa: D102
            return True if k == "passed" else super().get(k, d)

    def setUp(self):
        self.signer = generate_signer()
        self.echt = _echter_anspruch(self.signer)

    def test_der_export_gibt_den_gepruefte_wert_aus_nicht_ein_zweites_lesen(self):
        c = self._Zweizuengig(self.echt)
        c["passed"] = "false"
        # The validation sees True (through `get`). What MUST be emitted is exactly that value, not
        # the stored `"false"` -- otherwise a signed predicate carries a verdict nobody ever
        # validated.
        p = to_eval_result_predicate(c)
        gesehen = p["claims"][0].get("passed")
        self.assertIs(gesehen, True,
                      f"das Praedikat traegt {gesehen!r}; geprueft wurde True. Eine Pruefung durch "
                      f"einen Zugriff und eine Verwendung durch einen anderen sind zwei Werte.")

    def test_beide_echten_booleans_bleiben_unveraendert(self):
        """Without this case the site could turn every value into True and the case above would pass."""
        for wert in (True, False):
            with self.subTest(passed=wert):
                c = dict(self.echt)
                c["passed"] = wert
                self.assertIs(to_eval_result_predicate(c)["claims"][0].get("passed"), wert)


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

    def test_beide_booleans_werden_weiter_ausgestellt_und_binden(self):
        """The sixth site's counter-direction: issuance and the binding check are UNCHANGED for a bool.

        Both halves matter. Issuance alone would pass if the guard turned every verdict into `True`;
        the binding check is what says the value in the signature is still the one in the claim.
        """
        for wert in (True, False):
            with self.subTest(passed=wert):
                c = self._mit(wert)
                compact = issue_sd_jwt(c, self.signer, root_b64=ROOT_B64)
                self.assertIs(_immer_offen(compact)["passed"], wert)
                self.assertTrue(check_binds_bundle(compact, c, ROOT_B64),
                                "a genuine boolean must still bind to its bundle")

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
            # THE SIXTH SITE JOINS THE PROPERTY, not just the instance list above. The property is the
            # only part of this file that could have caught it without someone naming the function, and
            # it did not, because it enumerated four surfaces. It enumerates five now, and that is still
            # an enumeration — which is why `test_verdikt_truthiness_scanner` had to change too.
            lambda: _immer_offen(
                issue_sd_jwt(c, self.signer, root_b64=ROOT_B64))["passed"] is not False,
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

        THE ANSWER CHANGED WITH THE FOLLOW-UP TO R-B1, and this case records the new answer instead of
        being loosened. Measured 2026-09-24: of these fifteen, the two floats were refused by the claim
        profile (canonicalization), the other thirteen reached the export and were refused by the
        verdict check there. The emitter now runs decode's own claim validation BEFORE it
        canonicalizes, so all fifteen stop at the emitter's verdict check, floats included, and the
        refusal names `passed`. The export's refusal stays as the second half, over a bundle signed
        past the emitter, so removing either gate turns this case red.
        """
        for wert in (*NICHT_BOOL_ABER_WAHR, *NICHT_BOOL_UND_FALSCH):
            with self.subTest(passed=wert):
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(self._mit(wert), self.signer)
                self.assertIn("passed must be a boolean", str(ctx.exception),
                              f"passed={wert!r} was refused by another gate than the verdict check")
                vorbei = emit_bundle(json.dumps(self._mit(wert)).encode(), self.signer)
                with self.assertRaises(BundleFormatError):
                    export_svr_dsse(vorbei, self.signer)

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
