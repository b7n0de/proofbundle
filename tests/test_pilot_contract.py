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

    def test_every_measure_has_a_value_for_what_was_not_seen(self) -> None:
        """Every measure, M7 and M8 included (Codex thread 4218703335): a measure without such a value cannot record
        that it was not taken, and an exit criterion cannot ask for it."""
        messungen = _measures(_text())
        self.assertEqual(sorted(messungen, key=lambda m: int(m[1:])), [f"M{i}" for i in range(1, 9)])
        for mid in messungen:
            with self.subTest(measure=mid):
                self.assertRegex(messungen[mid], r"\b(not measured|unknown)\b")

    def test_every_measure_is_asked_for_by_an_exit_criterion(self) -> None:
        """Codex thread 4218703335: criterion 1 asked for M1 to M4 and criterion 2 for M5 and M6, and nothing asked
        for M7 or M8, so the pilot could end with both unmeasured for every action. The class: a measure the contract
        defines that no criterion names. Each measure of section 5 is named in section 6, with what keeps it open."""
        text = " ".join(_text().split())
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        for mid in _measures(_text()):
            with self.subTest(measure=mid):
                self.assertRegex(kriterien, rf"\b{mid}\b")

    def test_every_per_action_measure_is_required_for_every_proposed_action(self) -> None:
        """Codex thread 4219200257: a mention is not a quantifier. M1 to M4 were required only of the one witness
        per surface, so a second approved action with its form `not measured` let the pilot end. The measures
        section 5 defines per action, all but the two it measures over the window, stand in the clause that holds
        for every proposed action, with what keeps the pilot open."""
        text = " ".join(_text().split())
        massnahmen = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("M5 and M6 are measured over the observation window, not per action", massnahmen)
        je_aktion = [m for m in _measures(_text()) if m not in ("M5", "M6")]
        self.assertEqual(je_aktion, ["M1", "M2", "M3", "M4", "M7", "M8"])
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        klausel = kriterien[kriterien.index("every proposed action carries"):kriterien.index("3. ")]
        for mid in je_aktion:
            with self.subTest(measure=mid):
                self.assertRegex(klausel, rf"\b{mid}\b")
        self.assertIn("`unknown` or `not yet observed` in M1, or `not measured` where one of the others is required, "
                      "keeps the pilot open", klausel)

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

    def test_no_exit_criterion_needs_an_action_the_rules_forbid_to_agents(self) -> None:
        """Codex thread 4122523782: criterion 1 asked for an approved action on every surface in scope, and merges are
        in scope while AGENTS.md forbids agents to merge, so the pilot could never end. The criterion now counts only
        the surfaces an agent may write and covers the forbidden ones through M5 and M6."""
        text = " ".join(_text().split())
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        self.assertIn("every surface in scope that the repository's rules let an agent session write", kriterien)
        self.assertIn("needs no approved action and is covered by M5 and M6", kriterien)
        self.assertNotIn("1. every surface in scope has at least one action", kriterien)

    def test_no_write_leaves_the_scope_by_the_client_it_used(self) -> None:
        """Codex thread 4122523796: section 10 put writes through an API client that skip the gate out of scope,
        although section 2 names every write through the GitHub API. Such a write stays in scope and counts under
        M5 as an unapproved effect."""
        text = " ".join(_text().split())
        offen = text[text.index("## 10. Open before the pilot starts"):]
        self.assertNotIn("out of scope until they do", offen)
        self.assertIn("They stay in scope either way", offen)
        self.assertIn("reports it under M5 as an unapproved effect", offen)

    def test_the_pilot_cannot_end_with_the_forbidden_surfaces_unmeasured(self) -> None:
        """Codex thread 4217196629: criterion 1 waives the approved action on a forbidden surface and leaves it to M5
        and M6, and no criterion asked for either to be measured, so an agent merge beside M5 and M6 `not measured`
        let the pilot end. A criterion now requires both, on every surface, the forbidden ones included."""
        text = " ".join(_text().split())
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        self.assertIn("2. M5 and M6 have each been measured over the whole observation window, on every surface in "
                      "scope, the forbidden ones included: a `not measured` value for either keeps the pilot open",
                      kriterien)
        nach_der_ueberschrift = kriterien[len("## 6. Exit criteria"):]
        self.assertEqual(re.findall(r"(?<= )([1-9])\. ", nach_der_ueberschrift), ["1", "2", "3", "4", "5"])
        self.assertIn("so that criterion 4 can be met without calling the API again", text)

    def test_an_action_counts_toward_exit_only_with_m1_to_m4_measured(self) -> None:
        """Codex thread 4217987319: one approved, arrived action per surface with M2, M3 and M4 `not measured`
        met criterion 1, and criterion 3 let the maintainer accept each such mismatch, so the pilot could end
        without answering in which form any action arrived."""
        text = " ".join(_text().split())
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        self.assertIn("reconciliation is recorded with M1, M2, M3 and M4 each measured: an action with `not measured` "
                      "or `unknown` in any of them does not count here", kriterien)

    def test_the_writes_that_bypass_the_gate_are_counted(self) -> None:
        """Codex thread 4217196633: M5 recorded found or none found, so two writes that bypass the gate gave the value
        of one, while section 10 promises to say how many there were. M5 and M6 are counts."""
        messungen = _measures(_text())
        for mid in ("M5", "M6"):
            with self.subTest(measure=mid):
                self.assertIn("a count", messungen[mid])
                self.assertNotIn("found, not measured", messungen[mid])
        text = " ".join(_text().split())
        self.assertIn("each is a count, so two writes are recorded as two", text)
        self.assertIn("the result says how many there were", text)

    def test_the_first_example_keeps_what_was_not_measured_apart(self) -> None:
        text = _text()
        beispiel = text[text.index("## 9. First reconciliation example"):text.index("## 10.")]
        self.assertRegex(beispiel, r"SHA-256 `[0-9a-f]{64}`")
        self.assertIn("**not measured**", beispiel)


if __name__ == "__main__":
    unittest.main()
