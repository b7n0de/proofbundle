"""O46-5, the owner answer of Nachtrag 51 carried out with Nachtrag 47: the short line of an end the Stop hook holds
names what can go wrong, as D116 does for an ask and a block (the form stop among _SHORT_DANGER_FORMS).

RED at its parent, the commit of D118, where the held end still named only the gap ("a claim has no evidence (D80)", "a receipt of a
required check is missing (D26)").
"""
from __future__ import annotations

import pytest

import test_plugin_done_check as dc
import test_plugin_n32_claims_d80 as d80

env = dc.env
repo = dc.repo
transcript = d80.transcript
gate = dc.gate


def test_O46_5_the_line_of_a_held_claim_names_the_danger(env, repo, transcript):
    answer = d80._stop(env, repo, transcript, "N46 hält.")
    assert answer["systemMessage"] == ("Gate holds the end because the owner would take an unmeasured completion for "
                                       "a measured one (D80)."), answer


@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize("reason_id", sorted(gate._SHORT_DANGER))
def test_O46_5_every_held_end_names_its_danger_within_the_line(reason_id, language):
    verdict = gate.Verdict("deny", "detail (DECISIONS.md D3).", reason_id)
    line = gate.short_line("deny", gate.Outcome("deny", verdict.text(), [verdict]), None, language, form="stop")
    danger = gate._short_danger(verdict)
    assert danger is not None and danger[1 if language == "de" else 0] in line, (reason_id, line)
    assert len(line) <= gate.SHORT_LINE_MAX and line.endswith(").") and "(D" in line, line
