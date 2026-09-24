"""The binding check compares JSON types, not only values — and does not over-refuse.

WHERE THIS CAME FROM. On 2026-09-24, after the R-B4 establisher landed as `_verdict.require_bool_verdict`
(PR 260, merge `058ed6fc`), an adversarial lens of the house deep-gate was asked for an EXECUTED bypass
rather than an opinion. It found that `sdjwt_issue.check_binds_bundle` never calls the establisher and
compares with a bare `!=`, and `bool` subclasses `int`.

MEASURED ON `058ed6fc` BEFORE ANY CHANGE, which is why these are cases and not a paragraph:

    SD-JWT passed=True  vs claim passed=1          -> bound      (require_bool_verdict: REFUSES the claim)
    SD-JWT passed=True  vs claim passed=1.0        -> bound      (require_bool_verdict: REFUSES the claim)
    SD-JWT threshold=0  vs claim threshold=False   -> bound
    SD-JWT passed=True  vs claim passed=False      -> not bound  (the control: not blindly true)
    SD-JWT passed=True  vs claim passed="true"     -> not bound

TWO CORRECTIONS TO THE LENS, both from the measurement above and both kept here as cases. It named only
`passed`; the loop compares FIVE fields the same way and `threshold` falls identically. And it called
this a bypass, which does not carry: `1` and `True` are the same verdict, so no verdict flips and
nothing false-passes. What breaks is the promise the function makes about itself, `check_binds_bundle`
docstring: the always-open claims "MUST match the signed bundle payload bit-exact".

THE OVER-REFUSAL GUARD IS THE LOAD-BEARING ONE HERE, because the obvious fix is wrong. A rule of
"equal value AND identical type" would also refuse `1` against `1.0`. Measured with the `rfc8785`
canonicalizer: JCS serialises `true`/`1`/`1.0` as `true`/`1`/`1` — so `true` and `1` differ and must
refuse, while `1` and `1.0` are the SAME canonical bytes and must keep binding. A fix that refused them
would be a new defect pointing the other way, and nothing in the red probe would have caught it.

AND THE BACKWARD-COMPATIBILITY ARM, stated because this changes a verify verdict. An honest issuance
copies `passed` from the claim verbatim, so both sides always carried the SAME type and no honestly
issued receipt is affected. A pre-establisher bundle whose claim held `passed: 1` had an SD-JWT holding
`1` too; that pair must still bind. Only CROSS-type pairs change, and those arise from no honest path.
"""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle._membership import same_json_value
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt_issue import check_binds_bundle, issue_sd_jwt
from proofbundle._verdict import require_bool_verdict

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
TS = "2026-09-19T12:00:00Z"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _claim(signer, **ueberschreibt) -> dict:
    """A claim from the blessed emitter, so a refusal below means something."""
    claim, _salts = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=">=", threshold="0.80", score="0.92", n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp=TS,
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    claim = dict(claim)
    claim.update(ueberschreibt)
    return claim


def _sd_jwt_von_hand(claim: dict, signer: Ed25519PrivateKey, *, root_b64: str = ROOT) -> str:
    """A compact SD-JWT built the way `issue_sd_jwt` built one BEFORE the establisher landed.

    Needed because `issue_sd_jwt` now refuses a non-bool `passed` — which is correct, and which means
    the pre-establisher artefact can only be reconstructed by hand. It copies `passed` verbatim, as the
    old code did, so the issuance side of the measurement is the real one and not a stand-in.
    """
    payload = {"passed": claim["passed"], "threshold": claim["threshold"],
               "comparator": claim["comparator"], "suite": claim["suite"],
               "issuer": claim["issuer"], "receipt": {"root_b64": root_b64},
               "vct": "https://b7n0de.com/proofbundle/vct/eval-receipt/v1"}
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = (_b64url(json.dumps(header).encode("utf-8")) + "."
                     + _b64url(json.dumps(payload).encode("utf-8")))
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii"))) + "~"


class TestDieRotprobeGegenDenElternstand(unittest.TestCase):
    """Every case here BOUND on `058ed6fc`. That they now refuse is the whole change."""

    def setUp(self):
        self.signer = generate_signer()
        self.echt = issue_sd_jwt(_claim(self.signer, passed=True), self.signer, root_b64=ROOT)

    def test_wahr_bindet_nicht_an_eins(self):
        self.assertFalse(check_binds_bundle(self.echt, _claim(self.signer, passed=1), ROOT),
                         "an SD-JWT for `true` bound to a claim carrying the number 1")

    def test_wahr_bindet_nicht_an_eins_komma_null(self):
        self.assertFalse(check_binds_bundle(self.echt, _claim(self.signer, passed=1.0), ROOT))

    def test_die_abgewiesene_seite_ist_wirklich_abgewiesen(self):
        """The pairing that makes the finding sharp: the bundle claim these bound to is one the
        establisher refuses outright. Without this the case would only be about a type."""
        for wert in (1, 1.0):
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError):
                    require_bool_verdict(_claim(self.signer, passed=wert), wo="probe")

    def test_die_klasse_trifft_nicht_nur_passed(self):
        """The lens named `passed`. The loop compares five fields the same way."""
        compact = _sd_jwt_von_hand(_claim(self.signer, passed=True, threshold=0), self.signer)
        self.assertFalse(
            check_binds_bundle(compact, _claim(self.signer, passed=True, threshold=False), ROOT),
            "threshold 0 bound to threshold false — the fix reached only the field it was named for")

    def test_verschachtelt_faellt_genauso(self):
        """A scalar-only rule would close the instance and leave this open."""
        self.assertFalse(same_json_value([True], [1]))
        self.assertFalse(same_json_value({"a": {"b": [False]}}, {"a": {"b": [0]}}))


class TestKeineUeberAbweisung(unittest.TestCase):
    """THE GUARD AGAINST FIXING TOO HARD. Nothing in the red probe would catch these."""

    def test_eins_bleibt_gleich_eins_komma_null(self):
        """RFC 8785 serialises both as `1`. Refusing them would be a new defect facing the other way."""
        self.assertTrue(same_json_value(1, 1.0))
        self.assertTrue(same_json_value([1, {"a": 2}], [1.0, {"a": 2.0}]))

    def test_ein_ehrlich_abgeleitetes_sd_jwt_bindet_weiter(self):
        """WITHOUT THIS THE FILE PROVES NOTHING: a rule that refused everything would pass every case
        above."""
        signer = generate_signer()
        claim = _claim(signer, passed=True)
        self.assertTrue(check_binds_bundle(issue_sd_jwt(claim, signer, root_b64=ROOT), claim, ROOT))

    def test_ein_falsches_verdikt_bindet_auch_weiter(self):
        """The other polarity of the same guard: `False` is a verdict, not an absence."""
        signer = generate_signer()
        claim = _claim(signer, passed=False)
        self.assertTrue(check_binds_bundle(issue_sd_jwt(claim, signer, root_b64=ROOT), claim, ROOT))

    def test_rueckwaertskompatibel_gleicher_typ_auf_beiden_seiten(self):
        """A pre-establisher receipt: the old issuance copied `passed` verbatim, so both sides held the
        same type. Such a pair must still bind — only CROSS-type pairs change."""
        signer = generate_signer()
        for wert in (1, 0, "false"):
            with self.subTest(passed=wert):
                claim = _claim(signer, passed=wert)
                self.assertTrue(check_binds_bundle(_sd_jwt_von_hand(claim, signer), claim, ROOT))


class TestDieNegativkontrolleHaelt(unittest.TestCase):
    """Proof the comparison did not become blindly false."""

    def test_wahr_bindet_nicht_an_falsch(self):
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        self.assertFalse(check_binds_bundle(echt, _claim(signer, passed=False), ROOT))

    def test_ein_fremdes_feld_bindet_nicht(self):
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        self.assertFalse(check_binds_bundle(echt, _claim(signer, passed=True, suite="andere"), ROOT))

    def test_ein_fehlendes_feld_bindet_nicht(self):
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        ohne = _claim(signer, passed=True)
        ohne.pop("suite")
        self.assertFalse(check_binds_bundle(echt, ohne, ROOT))


class TestDasPrimitivSelbst(unittest.TestCase):
    """Direct arm, so a later caller inherits a measured function rather than a measured call site."""

    def test_die_bool_zahl_grenze_in_beide_richtungen(self):
        for a, b, erwartet in [(True, 1, False), (1, True, False), (False, 0, False),
                               (0, False, False), (True, True, True), (False, False, True),
                               (True, False, False), (True, 1.0, False), (True, "true", False)]:
            with self.subTest(a=a, b=b):
                self.assertIs(same_json_value(a, b), erwartet)

    def test_die_uebrigen_json_arten_vergleichen_wie_zuvor(self):
        for a, b, erwartet in [(None, None, True), (None, 0, False), ("a", "a", True),
                               ("a", "b", False), ([], [], True), ([], {}, False),
                               ({"a": 1}, {"a": 1}, True), ({"a": 1}, {"b": 1}, False),
                               ([1, 2], [1, 2, 3], False)]:
            with self.subTest(a=a, b=b):
                self.assertIs(same_json_value(a, b), erwartet)

    def test_tiefe_verschachtelung_wirft_nicht(self):
        """The `!=` this replaces recursed in C, where CPython guards the depth. A hand-written
        recursion would raise RecursionError out of a never-raise verify surface."""
        tief_a: object = "grund"
        tief_b: object = "grund"
        for _ in range(5000):
            tief_a = [tief_a]
            tief_b = [tief_b]
        self.assertIs(same_json_value(tief_a, tief_b), True)
        self.assertIs(same_json_value(tief_a, [tief_b]), False)

    def test_das_budget_weist_ab_und_wirft_nicht(self):
        gross = list(range(50))
        self.assertIs(same_json_value(gross, gross, pair_budget=5), False)
        self.assertIs(same_json_value(gross, gross), True)

    def test_ein_wert_dessen_eq_wirft_ist_nicht_gleich(self):
        class Bissig:
            def __eq__(self, andere):
                raise RuntimeError("no comparison for you")

        self.assertIs(same_json_value(Bissig(), 1), False)


class TestEinZugriffNichtZwei(unittest.TestCase):
    """THE DEEP-GATE ROUND ON THIS CHANGE, and all three cases are defects of the fix itself.

    Lens F2 attacked the new comparison and found the SAME class the fix was written against, one level
    down: a decision taken through one accessor and a walk taken through another. `_verdict` states the
    rule in its own docstring — "the accessor is read once and the value is returned" — written a day
    before this function and not carried into it.
    """

    def test_der_schluesselsatz_und_der_lauf_lesen_dasselbe(self):
        """CATCH PROOF. The first version decided with `keys()` and walked with `__iter__`."""

        class IterLuegt(dict):
            def __iter__(self):
                return iter(["a"])          # hides "b"; keys() stays truthful

        x = IterLuegt({"a": 1, "b": 999})
        self.assertEqual(set(x.keys()), {"a", "b"}, "the probe itself is broken, not the function")
        self.assertIs(same_json_value(x, {"a": 1, "b": 2}), False,
                      "a key the walk never reached was reported equal")

    def test_ein_luegendes_eq_ist_nicht_gleich(self):
        """The existing case covers a RAISING `__eq__`. A LYING one is the other half."""

        class EqLuegt:
            def __eq__(self, andere):
                return True

            __hash__ = None

        self.assertIs(same_json_value(EqLuegt(), "an unrelated string"), False)
        self.assertIs(same_json_value("an unrelated string", EqLuegt()), False)

    def test_ein_luegendes_contains_bindet_nicht(self):
        """`field in claim` plus `claim.get(field)` asked one object twice. An object that says yes to
        the first and holds nothing for the second used to reach the comparison; now the single read
        reports absent, and absent never binds."""
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)

        class ContainsLuegt(dict):
            def __contains__(self, k):
                return True                 # truthful `get`, so the object holds nothing

        self.assertIs(check_binds_bundle(echt, ContainsLuegt(), ROOT), False)

    def test_STATED_LIMIT_ein_durchgehend_erfundener_anspruch_ist_nicht_unterscheidbar(self):
        """THE HONEST HALF, written as a case so nobody re-discovers it as a finding.

        A lens reported that a `claim` whose `get` FABRICATES whatever the SD-JWT carries binds. It
        does, and no read-once fix closes it: unlike the hidden-key case above, such an object holds no
        contradicting value — there is no second source of truth for the comparison to consult. It is a
        caller lying to itself with an object `json.loads` cannot produce, and `check_binds_bundle` has
        exactly one production caller, which always hands it a plain dict from `loads_strict`.
        Asserting that this refuses would be asserting something false.

        AND THIS CASE IS A TRADE, NOT A PURE WIN, which is why it is spelled out rather than left as a
        green line. On `c120c5a9` the two-accessor form REFUSED exactly this object, because its
        `__contains__` was truthful and empty while only `get` lied. Reading once gives that accidental
        catch up. It was accidental: the same cross-check is what the lens exploited in the other
        direction, with an object whose `__contains__` says yes to everything, and that one bound on
        both states. A cross-check between two accessors catches some liars and admits others by
        coincidence; it is not a defense, and the raw TypeError it threw on a non-dict `claim` was a
        real defect on the real path. The trade is: lose a coincidence, gain a verdict where there was
        an exception. Neither half is reachable through `loads_strict`.
        """
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        p = json.loads(base64.urlsafe_b64decode(echt.split("~")[0].split(".")[1] + "=="))

        class GetErfindet(dict):
            def get(self, k, standard=None):
                return p.get(k, standard)

        self.assertIs(check_binds_bundle(echt, GetErfindet(), ROOT), True,
                      "if this ever refuses, the limit above closed and the docstring must say how")

    def test_ein_nicht_dict_anspruch_bindet_nicht_und_wirft_nicht(self):
        for anspruch in (None, [], "x", 1, True):
            with self.subTest(claim=anspruch):
                signer = generate_signer()
                echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
                self.assertIs(check_binds_bundle(echt, anspruch, ROOT), False)


class TestDasBudgetIstAbgeleitetNichtGewaehlt(unittest.TestCase):
    """Lens F1 built an HONEST claim, both sides bit-identical, and the budget refused it — reported by
    `verify_bundle` as "cross-receipt substitution". A fail-closed stop wearing another finding's label
    is worse than no stop, because the reader acts on the diagnosis."""

    def test_das_budget_liegt_ueber_dem_knotenbudget_des_hauses(self):
        """THE PIN. The first value was 100_000 against a parser that admits 200_000 nodes per document,
        so it refused input this package itself calls legal. This case fails if either number moves."""
        from proofbundle._membership import _COMPARE_PAIR_BUDGET
        from proofbundle.budget import VerificationBudget

        knoten = VerificationBudget().json_nodes
        self.assertGreaterEqual(_COMPARE_PAIR_BUDGET, 2 * knoten,
                                f"the pair budget {_COMPARE_PAIR_BUDGET} sits under two documents of "
                                f"{knoten} nodes — it would refuse a legal pair as a mismatch")

    def test_ein_grosser_aber_ehrlicher_wert_wird_nicht_als_ungleich_gemeldet(self):
        """The shape of F1's finding, without the crypto: above the OLD bound, below the new one."""
        gross = list(range(150_000))
        self.assertIs(same_json_value(gross, list(gross)), True)
        self.assertIs(same_json_value(gross, list(range(149_999))), False)

    def test_das_budget_greift_bevor_die_paare_gebaut_werden(self):
        """CATCH PROOF for the ordering. A lens set the budget to 100, handed in two million keys and
        measured 744 MB allocated BEFORE the refusal fired — the bound cost exactly what it exists to
        prevent, because the check sat after the materialisation. The count is knowable from the key
        list, so nothing needs building to know it is too much.

        IN A FRESH PROCESS, and that is the load-bearing detail rather than a precaution.
        `ru_maxrss` is a HIGH-WATER MARK: measured inside this suite it carries whatever the tests
        before it allocated, and the difference this case looks for (measured 153 MB against 15 MB)
        disappears under a mark some earlier case already raised. A peak that cannot fall cannot
        answer a question about one function. Time alone would not do either — measured 0.215 s
        against 0.015 s, a gap a loaded machine can close.
        """
        programm = (
            "import resource, sys\n"
            "sys.path.insert(0, %r)\n"
            "from proofbundle._membership import same_json_value\n"
            "gross = list(range(2_000_000))\n"
            "vorher = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024\n"
            "erg = same_json_value(gross, list(gross), pair_budget=100)\n"
            "nachher = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024\n"
            "print(erg, nachher - vorher)\n" % str(REPO / "src")
        )
        r = subprocess.run([sys.executable, "-c", programm],
                           capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode, 0, r.stderr)
        erg, zuwachs = r.stdout.split()
        self.assertEqual(erg, "False")
        self.assertLess(int(zuwachs), 80,
                        f"refusing at a budget of 100 grew by {zuwachs} MB — the pairs were built "
                        "before the bound was consulted")

    def test_eine_gegenseitige_referenz_terminiert_auch_schmal(self):
        """A second lens reproduced non-termination at width 1000, not only at 200_000, and for a
        MUTUAL reference as well. The first measurement named the widest case somebody tried; that is
        not the bound, and a case that only covers 200_000 would leave the reachable shape open."""
        a: dict = {}
        b: dict = {}
        for i in range(1000):
            a[str(i)] = b
            b[str(i)] = a
        start = time.monotonic()
        self.assertIs(same_json_value(a, b), False)
        self.assertLess(time.monotonic() - start, 10.0)


class TestDerWaechterWirdNichtSelbstZumDefekt(unittest.TestCase):
    """Lens F3 attacked the guard the way the guard attacks its subject. Three of its four routes were
    real and are cases here; the fourth is the one the fix got right and is kept as the guard.
    """

    def test_tiefe_wirft_nicht_wo_der_elternstand_wirft(self):
        """THE ROUTE THAT HELD. Measured: the `!=` this replaces raises RecursionError from depth ~1000;
        the explicit stack never does. Kept so a later 'simplification' back to `==` fails here."""
        tief_a: object = "grund"
        tief_b: object = "grund"
        for _ in range(20_000):
            tief_a = [tief_a]
            tief_b = [tief_b]
        self.assertIs(same_json_value(tief_a, tief_b), True)

    def test_eine_breite_selbstreferenz_terminiert(self):
        """CATCH PROOF. The budget counted POPS, so a self-referential node of width W pushed W pairs
        on every pop while the counter rose by one. Measured before the fix: 235 MB to 2988 MB in
        twelve seconds, monotone, no end. Counting pushes stops it at the first pop."""
        d: dict = {}
        for i in range(20_000):
            d[str(i)] = d
        start = time.monotonic()
        self.assertIs(same_json_value(d, d), False)
        self.assertLess(time.monotonic() - start, 10.0, "the walk did not terminate promptly")

        schmal: list = []
        schmal.append(schmal)
        self.assertIs(same_json_value(schmal, schmal), False)

    def test_ein_werfendes_protokoll_gibt_falsch_statt_zu_werfen(self):
        """CATCH PROOF. A guard around only the scalar `!=` left `keys()`, `__getitem__` and `__len__`
        raising straight out of a surface whose contract is a verdict."""

        class KeysWirft(dict):
            def keys(self):
                raise RuntimeError("boom")

        class GetItemWirft(dict):
            def __getitem__(self, k):
                raise RuntimeError("boom")

        class LenWirft(list):
            def __len__(self):
                raise RuntimeError("boom")

        for name, x, y in (("keys", KeysWirft({"a": 1}), {"a": 1}),
                           ("getitem", GetItemWirft({"a": 1}), {"a": 1}),
                           ("len", LenWirft([1]), [1]),
                           ("verschachtelt", {"o": GetItemWirft({"a": 1})}, {"o": {"a": 1}})):
            with self.subTest(protokoll=name):
                self.assertIs(same_json_value(x, y), False)

    def test_ein_werfender_anspruch_gibt_falsch_statt_zu_werfen(self):
        """CATCH PROOF, and the sharper half: `same_json_value` guarding its own walk does nothing for
        an exception raised BEFORE the value reaches it. This one left `check_binds_bundle` raw."""
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)

        class GetWirft(dict):
            def get(self, k, standard=None):
                raise RuntimeError("boom")

        self.assertIs(check_binds_bundle(echt, GetWirft(_claim(signer, passed=True)), ROOT), False)


if __name__ == "__main__":
    unittest.main()
