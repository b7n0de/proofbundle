"""The pilot contract keeps the parts that make it a contract, and its measures fail closed.

docs/pilot/pilot_contract.md fixes the first pilot of the decision and outcome receipts: scope,
non-claims, roles, measures and exit criteria. These cases hold the document to that shape and to its
own rule that `unknown` and `not measured` are values of their own, never folded into agreement, so an
edit that drops a section or a fail-closed value fails here instead of passing review unseen.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_CONTRACT = REPO / "docs/pilot/pilot_contract.md"


def _text() -> str:
    return _CONTRACT.read_text(encoding="utf-8")


def _measures(text: str) -> dict:
    """Measure id -> the values cell of the measures table."""
    zeilen = {}
    for zeile in text.splitlines():
        treffer = re.match(r"\| (M[0-9]+) [^|]*\|[^|]*\| ([^|]*) \|$", zeile)
        if treffer:
            zeilen[treffer.group(1)] = treffer.group(2)
    return zeilen


class ThePilotContract(unittest.TestCase):
    def test_it_names_the_question_and_has_every_part(self) -> None:
        text = _text()
        self.assertIn("**Which approved action actually arrived on GitHub, and in which form?**", text)
        for teil in ("## 2. Scope", "## 3. Roles", "## 5. Measures", "## 6. Exit criteria",
                     "## 7. What the pilot does not claim", "## 9. First reconciliation example"):
            with self.subTest(part=teil):
                self.assertIn(teil, text)

    def test_every_yes_no_measure_has_a_value_for_what_was_not_seen(self) -> None:
        messungen = _measures(_text())
        self.assertEqual(sorted(messungen, key=lambda m: int(m[1:])), [f"M{i}" for i in range(1, 9)])
        for mid in ("M1", "M2", "M3", "M4", "M5", "M6"):
            with self.subTest(measure=mid):
                self.assertRegex(messungen[mid], r"\b(not measured|unknown)\b")

    def test_the_agent_holds_neither_signing_key(self) -> None:
        text = _text()
        self.assertIn("The agent never holds the gate's or the observer's key.", text)
        rollen = [z for z in text.splitlines() if z.startswith("| producer |")]
        self.assertEqual(len(rollen), 1)
        self.assertIn("none of the keys below", rollen[0])

    def test_it_sets_no_target(self) -> None:
        text = _text()
        self.assertIn("no\nnumber in it is a target", text)
        self.assertIn("never judged against a target", text)

    def test_a_refused_action_that_did_not_arrive_reconciles(self) -> None:
        """An enforced refusal is the gate working, so it reconciles and asks no maintainer decision.

        The rule branches on the verdict and keeps its fail-closed else. Reconciling on `not arrived` is
        honest only with the bound on what the API listed, so the bound is held here too.
        """
        text = " ".join(_text().split())
        rule = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("An approved action reconciles only when M1 is arrived and M2, M3 and M4 each hold.", rule)
        self.assertIn("A refused action reconciles only when M1 is not arrived;", rule)
        self.assertIn("Every other combination is a mismatch with a name.", rule)
        self.assertIn('"Not arrived" for M1 and "none found" for M5 and M6 are bounded by what the API returned',
                      text)

    def test_arrival_is_asked_of_every_proposed_action(self) -> None:
        rows = [line for line in _text().splitlines() if line.startswith("| M1 ")]
        self.assertEqual(len(rows), 1)
        self.assertIn("for this proposed action?", rows[0].split("|")[2])

    def test_the_record_promise_matches_the_refused_rule(self) -> None:
        """A refused action with no effect has a decision receipt and nothing for the observer to sign."""
        text = " ".join(_text().split())
        records = text[text.index("## 4. Records"):text.index("## 5. Measures")]
        self.assertNotIn("For every proposed action the pilot keeps two signed records", records)
        self.assertIn("For every proposed action the pilot keeps a signed decision receipt and, once GitHub shows "
                      "an effect of it, a signed outcome receipt, and joins them:", records)

    def test_the_first_example_keeps_what_was_not_measured_apart(self) -> None:
        text = _text()
        beispiel = text[text.index("## 9. First reconciliation example"):text.index("## 10.")]
        self.assertRegex(beispiel, r"SHA-256 `[0-9a-f]{64}`")
        self.assertIn("**not measured**", beispiel)


if __name__ == "__main__":
    unittest.main()
