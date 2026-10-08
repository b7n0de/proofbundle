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

    def test_every_receipt_of_every_action_must_verify(self) -> None:
        """Codex thread 4219683451: criterion 1 verified the receipts of one witness per surface, so a second action
        whose receipts failed under the operator's keys could be accepted as a mismatch and the pilot ended without
        establishing who approved or observed it. The records section 4 defines per action are quantified like the
        measures: a decision receipt for every proposed action and an outcome receipt for every effect, each
        verifying, or the pilot stays open."""
        text = " ".join(_text().split())
        records = text[text.index("## 4. Records"):text.index("## 5. Measures")]
        self.assertIn("For every proposed action the pilot keeps a signed decision receipt", records)
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        klausel = kriterien[kriterien.index("every proposed action carries"):kriterien.index("3. ")]
        self.assertIn("a decision receipt that verifies offline with the operator's gate key", klausel)
        self.assertIn("for every effect GitHub shows of it, an outcome receipt that verifies with the operator's "
                      "observer key", klausel)
        self.assertIn("A receipt that does not verify", klausel)

    def test_the_witness_of_a_surface_is_an_approved_action(self) -> None:
        """Codex thread 4220257554: criterion 1 asked for an action per writable surface without its verdict, so a
        refused action that arrived, with verifying receipts and M1 to M4 measured, could be the only witness of
        every surface, and the pilot ended without having observed any approved action arrive."""
        text = " ".join(_text().split())
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        eins = kriterien[kriterien.index("1. "):kriterien.index("2. M5 and M6")]
        self.assertIn("has at least one action the gate approved before the write", eins)
        self.assertIn("whose decision and outcome receipts verify offline", eins)
        self.assertIn("a refused action does not count here even when it arrived", eins)
        self.assertIn("a refused action that arrived is a mismatch under M6", eins)

    def test_an_effect_matching_several_proposals_is_matched_to_none(self) -> None:
        """Codex thread 4220774964: the API effect carries no proposal identifier, so an effect matching an allowed and
        a refused proposal with the same bytes could be assigned to either, and the choice decided M6 and criterion 1.
        It is matched to none, M1 is unknown for each, and it counts under M6 when one of them was refused."""
        text = " ".join(_text().split())
        massnahmen = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("An effect that equals, in surface and bytes, actions of different verdicts is the mismatch class "
                      "`ambiguous effect`: M1 is `ambiguous` for each of them", massnahmen)
        self.assertIn("it counts under M6 when any of them was refused", massnahmen)

    def test_the_witness_was_authorized_before_the_write(self) -> None:
        """Codex thread 4220774980: an ALLOW recorded after the effect, or a post-hoc review or simulation, could be
        the witness of a surface, although the pilot's premise is a gate that decides before the write."""
        text = " ".join(_text().split())
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        eins = kriterien[kriterien.index("1. "):kriterien.index("2. M5 and M6")]
        self.assertIn("by a decision of type `preActionAuthorization` whose `decidedAt` is not later than the "
                      "`performedAt` of the effect", eins)
        self.assertIn("a post-hoc review, a simulation, or an approval recorded after the effect does not count here",
                      eins)

    def test_the_data_rule_says_where_refused_bytes_that_arrived_are_kept(self) -> None:
        """Codex thread 4220774987: refused bytes were never to be kept, and the stored API response of a refused
        action that arrived holds them; the rule names that response as the one record that keeps them."""
        text = " ".join(_text().split())
        daten = text[text.index("## 8. Data"):text.index("## 9. First reconciliation example")]
        self.assertIn("in the gate's records and in the decision receipt", daten)
        self.assertIn("that response is the only record of the pilot that holds them", daten)

    def test_an_ambiguous_effect_can_reach_a_result(self) -> None:
        """Codex thread 4221183314: an ambiguous effect gave M1 unknown, which criterion 2 never lets pass, and a
        decision under criterion 3 could not change it, so the pilot could never end. M1 has its own value for it,
        which criterion 2 accepts once the maintainer decided the class, and which never witnesses a surface."""
        text = " ".join(_text().split())
        self.assertIn("arrived, not arrived, ambiguous, not yet observed, unknown", text)
        massnahmen = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("M1 is `ambiguous` for each of them", massnahmen)
        kriterien = text[text.index("## 6. Exit criteria"):text.index("It stops early")]
        self.assertIn("`ambiguous` once the maintainer has decided that class under criterion 3", kriterien)
        self.assertIn("an action whose M1 is `ambiguous` is never the witness of criterion 1", kriterien)

    def test_one_approval_covers_at_most_one_write(self) -> None:
        """Codex thread 4221183326: two identical writes both matched the one allowed proposal, and the second
        disappeared with M5 at 0."""
        text = " ".join(_text().split())
        massnahmen = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("each takes one proposed action of the window with the same target and identity that no earlier "
                      "effect took", massnahmen)
        self.assertIn("An effect that finds no action left counts under M5 as an unapproved effect", massnahmen)

    def test_the_closing_rule_at_approval_time_is_kept(self) -> None:
        """Codex thread 4221183336: M4 reads the closing rule at approval time, and nothing kept that rule, so a
        rerun after a rule change could classify the same action differently."""
        text = " ".join(_text().split())
        daten = text[text.index("## 8. Data"):text.index("## 9. First reconciliation example")]
        self.assertIn("The closing rule each surface requires at approval time is kept with the decision record", daten)
        self.assertIn("as recorded with the decision (section 8)", text)

    def test_the_compared_fields_are_not_part_of_the_match(self) -> None:
        """Codex thread 4221644932: bytes and surface had to be equal for a match, so an approved action that arrived
        altered or on another surface became not arrived plus an unapproved effect, and M2 or M3 `different` could
        never be recorded. The match uses target and identity; surface, bytes and closing lines are compared."""
        text = " ".join(_text().split())
        massnahmen = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("An effect is matched to a proposed action by its target and by the agent identity that wrote it",
                      massnahmen)
        self.assertIn("Surface, bytes and closing lines are not part of the match", massnahmen)
        self.assertNotIn("matched to a proposed action by surface, target and bytes", massnahmen)

    def test_an_ambiguous_effect_still_takes_an_approval(self) -> None:
        """Codex thread 4221644945: an ambiguous effect took no action, so with two identical approvals and three
        identical effects all three were ambiguous and M5 stayed 0. Every effect takes one action, and approvals of
        one verdict are interchangeable, so the third effect counts under M5."""
        text = " ".join(_text().split())
        massnahmen = text[text.index("## 5. Measures"):text.index("## 6. Exit criteria")]
        self.assertIn("actions of different verdicts", massnahmen)
        self.assertIn("it still takes the earliest decided of them", massnahmen)
        self.assertIn("a rerun under criterion 4 reproduces every match", massnahmen)

    def test_identities_are_agent_only_and_a_shared_one_stops_the_pilot(self) -> None:
        """Codex thread 4222122338: a person and an agent writing under one account share the API's actor identity,
        and the match by identity could take the person's write as the approved one. Agent identities are dedicated
        and named before the pilot, and a known person's write under one stops it."""
        text = " ".join(_text().split())
        self.assertIn("Matching by identity needs identities that only agent sessions write under", text)
        stopp = text[text.index("It stops early"):text.index("## 7.")]
        self.assertIn("a person is known to have written under an identity the pilot reads as an agent's", stopp)
        offen = text[text.index("## 10. Open before the pilot starts"):]
        self.assertIn("The identities that only agent sessions write under", offen)

    def test_the_order_of_decisions_is_total(self) -> None:
        """Codex thread 4222122346: two decisions with the same decidedAt left the earliest decided undefined, and two
        reruns could match an effect differently. The decisionId breaks the tie."""
        text = " ".join(_text().split())
        self.assertIn("among decisions with the same `decidedAt` the one whose `decisionId` sorts first, so the order "
                      "is total", text)

    def test_m8_reads_the_action_id_from_the_records(self) -> None:
        """Codex thread 4222122355: M8 counts verdicts per action id, and no stored record carried the action id."""
        text = " ".join(_text().split())
        aufzeichnungen = text[text.index("## 4. Records"):text.index("## 5. Measures")]
        self.assertIn("Each decision receipt names its action and attempt in its `decisionId`, as `<action id>#<attempt>`",
                      aufzeichnungen)
        self.assertIn("read from the `decisionId` of the decision receipts (section 4)", text)

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
