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

    def __init__(self, verlangt, vorhanden, z1="gemessen", z2="gemessen",
                 zurueck=0, streng=False, z3="gemessen"):
        self.verlangt, self.vorhanden, self.z1, self.z2 = verlangt, vorhanden, z1, z2
        # The default is the unremarkable case: head current, ruleset not strict. A contract that
        # does not mean the new state must not change colour because of it.
        self.zurueck, self.streng, self.z3 = zurueck, streng, z3

    def __enter__(self):
        self._p, self._v = GATE.pflichtkontexte, GATE.vorhandene_kontexte
        self._b = GATE.basisstand
        GATE.pflichtkontexte = lambda repo: (set(self.verlangt), self.z1)
        GATE.vorhandene_kontexte = lambda repo, sha: (set(self.vorhanden), self.z2)
        GATE.basisstand = lambda repo, sha, basis="main": (self.zurueck, self.streng, self.z3)
        return self

    def __exit__(self, *a):
        GATE.pflichtkontexte, GATE.vorhandene_kontexte = self._p, self._v
        GATE.basisstand = self._b


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


class TestDieDritteLageAllesDaUndTrotzdemBlockiert(unittest.TestCase):
    """Present, green, and unmergeable. The shape pull request 228 really had on 2026-09-19.

    THE GATE SAID `gruen` AND THE MERGE WAS REFUSED, seventy seconds after pull request 226 landed:
    both required contexts existed on the head, both had passed, and GitHub answered
    "2 of 2 required status checks are expected". Absence was never the problem — staleness was.
    Under `strict_required_status_checks_policy` the contexts must have run on a head that is
    current with the base, so a head one commit behind carries results that no longer count.
    Presence alone answers a question the ruleset stops asking the moment it is strict.
    """

    def test_streng_und_hinter_der_basis_ist_rot_obwohl_nichts_fehlt(self):
        with _Netz({"guard", "all-checks-passed"}, {"guard", "all-checks-passed"},
                   zurueck=1, streng=True) as _:
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "ROT")
        self.assertEqual(d["fehlend"], [])          # nothing absent — that is exactly the point
        self.assertTrue(d["veraltet_unter_streng"])
        self.assertIn("hinter main", d["grund"])

    def test_nicht_streng_macht_rueckstand_folgenlos(self):
        """Without the strict policy a lagging head merges fine, so it must not turn the gate red —
        otherwise the gate would block work for a reason the repository does not have."""
        with _Netz({"guard"}, {"guard"}, zurueck=7, streng=False):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "gruen")
        self.assertFalse(d["veraltet_unter_streng"])

    def test_streng_und_aktuell_ist_gruen(self):
        with _Netz({"guard"}, {"guard"}, zurueck=0, streng=True):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "gruen")

    def test_ein_fehlender_kontext_bleibt_der_genannte_grund(self):
        """Both faults at once: the message must name the absent context, not the staleness,
        because that is the one a person can act on first."""
        with _Netz({"guard", "all-checks-passed"}, {"guard"}, zurueck=3, streng=True):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "ROT")
        self.assertEqual(d["fehlend"], ["all-checks-passed"])
        # THE TEST WAS NAMED FOR THIS AND DID NOT CHECK IT: the first version asserted only
        # `fehlend`, while the reason said "every required context exists" — the real run against
        # pull request 230 carried exactly that contradiction in its output.
        self.assertIn("existieren auf diesem Kopf NICHT", d["grund"])
        self.assertNotIn("Alle Pflichtkontexte existieren", d["grund"])
        self.assertIn("zusaetzlich", d["grund"])

    def test_unlesbarer_basisstand_ist_nicht_messbar_und_nicht_gruen(self):
        """Fail-closed on the third reader as well, for the same reason as the other two."""
        with _Netz({"guard"}, {"guard"}, z3="NICHT MESSBAR: Vergleich zur Basis nicht lesbar"):
            d = GATE.pruefe("o/r", "a" * 40)
        self.assertEqual(d["urteil"], "NICHT_MESSBAR")


if __name__ == "__main__":
    unittest.main()
