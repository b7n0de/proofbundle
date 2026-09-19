"""A required context that was never created blocks silently — this gate says so out loud.

WHY A SECOND GATE NEXT TO THE REACHABILITY ONE. They answer different questions, and the
difference decided a real pull request. `required_check_reachability_gate.py` asks whether some
workflow CAN produce each required context. This one asks whether it WAS produced on a given head.
Measured 2026-09-19 on pull request 228: the reachability gate reported `produced` for both
required contexts and exited 0, while `all-checks-passed` did not exist on the head at all and the
pull request sat at BLOCKED with nothing red. The same pairing stood on 2026-09-17 at pull request
218.

THE CASES BELOW FEED THE SETS DIRECTLY instead of calling GitHub. That is deliberate: a contract
that needs a token and a network is a contract that silently stops testing the day either is
missing, and a gate built because something was invisible must not have an invisible failure mode
of its own.
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "required_context_presence", REPO / "scripts" / "required_context_presence_gate.py")
GATE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(GATE)


class _Netz:
    """Replaces the two readers, so the verdict is tested and not the network."""

    def __init__(self, verlangt, vorhanden, z1="gemessen", z2="gemessen"):
        self.verlangt, self.vorhanden, self.z1, self.z2 = verlangt, vorhanden, z1, z2

    def __enter__(self):
        self._p, self._v = GATE.pflichtkontexte, GATE.vorhandene_kontexte
        GATE.pflichtkontexte = lambda repo: (set(self.verlangt), self.z1)
        GATE.vorhandene_kontexte = lambda repo, sha: (set(self.vorhanden), self.z2)
        return self

    def __exit__(self, *a):
        GATE.pflichtkontexte, GATE.vorhandene_kontexte = self._p, self._v


class TestEinAbwesenderKontextIstEinBefund(unittest.TestCase):

    def test_ein_fehlender_pflichtkontext_ist_rot(self):
        """The case the gate exists for, in the shape it really had on pull request 228."""
        with _Netz({"guard", "all-checks-passed"}, {"guard", "mutant-signature-guard"}):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "ROT")
        self.assertEqual(d["fehlend"], ["all-checks-passed"])

    def test_alle_da_ist_gruen(self):
        with _Netz({"guard", "all-checks-passed"},
                   {"guard", "all-checks-passed", "coverage"}):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "gruen")
        self.assertEqual(d["fehlend"], [])

    def test_der_ausgang_zaehlt_nicht_nur_die_existenz(self):
        """A failing context is PRESENT. This gate must not double as a pass/fail reader —
        that job belongs to `gh pr checks`, and two gates answering one question is how a
        finding gets repaired twice and measured never."""
        with _Netz({"guard"}, {"guard"}):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "gruen")
        self.assertIn("NICHT der Ausgang", d["geprueft_wird"])

    def test_unlesbares_ruleset_ist_nicht_messbar_und_nicht_gruen(self):
        with _Netz(set(), {"guard"}, z1="NICHT MESSBAR: rulesets nicht lesbar"):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "NICHT_MESSBAR")

    def test_unlesbare_check_runs_sind_nicht_messbar_und_nicht_gruen(self):
        """Fail-closed on the second reader too. The first version guarded only the ruleset;
        an unreadable check-run list would then have produced an EMPTY present-set and reported
        every required context as absent — a loud wrong answer instead of an honest unknown."""
        with _Netz({"guard"}, set(), z2="NICHT MESSBAR: check-runs nicht lesbar"):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "NICHT_MESSBAR")

    def test_kein_pflichtkontext_ist_kein_freibrief(self):
        """An empty required-set means protection is off or the read is wrong. Neither is a pass."""
        self.assertTrue(GATE.pflichtkontexte.__doc__)
        with _Netz(set(), {"guard"}, z1="NICHT MESSBAR: kein Ruleset nennt einen Pflichtkontext"):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "NICHT_MESSBAR")


if __name__ == "__main__":
    unittest.main()
