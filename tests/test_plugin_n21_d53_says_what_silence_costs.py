"""D53, follow-up note 21 part 4 (review round 24, question 3): DECISIONS.md and the README say what a silent pass costs.

The reviewer: no blocker of its own, but describe it honestly. A free call shows no explanation at the call any more,
the log keeps the verdict and the reason id, not the long reason (O20-2), and no duty to approve went away; visibility
was never a power to decide, as the gate gave no allow before either. RED at 6459ff53, where neither file said so.
"""
from __future__ import annotations

import pathlib

import pytest

PLUGIN = pathlib.Path(__file__).resolve().parent.parent / "plugins" / "proofbundle"


def _d53() -> str:
    text = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
    start = text.index("## D53.")
    return " ".join(text[start:text.index("\n## ", start + 1)].split())


def _readme() -> str:
    return " ".join((PLUGIN / "README.md").read_text(encoding="utf-8").split())


@pytest.mark.parametrize("read", [_d53, _readme], ids=["DECISIONS.md D53", "README.md"])
def test_N21_the_cost_of_a_silent_pass_is_named(read):
    text = read()
    for named in ("why the gate let it through", "the verdict and the reason ids of the call", "not the long reason",
                  "O20-2", "removes no duty to approve", "no permission decision (D4)"):
        assert named in text, named
