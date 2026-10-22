"""631 part 2, P2 group 2 of CODEX-DEFEKTSUCHE-630-KANDIDAT-01 (at 98b168b9): a form rule admits the one spelling it
names.

Measured at 063b4e22. The v0.2 shape check read `evaluatedAt` with `\\d`, which in a str pattern matches every Unicode
decimal digit: a signed v0.2 statement with `evaluatedAt` "٢٠٢٦-07-05T12:00:00Z" (Arabic-Indic year), with a
fullwidth hour, a Devanagari offset or a Bengali fraction verified ok=True with predicate_shape_ok True, exactly as
the ASCII spelling. `MerkleAccumulator.restore` read the frontier by iterating it: a correctly signed empty state with
`frontier` {} or "" restored like the [] that `state()` writes. Controls: the ASCII date-time and the written [] keep
their verdicts, and a frontier of another type with members stays refused.
"""
from __future__ import annotations

import base64
import copy
import importlib.util

import pytest

import test_intoto_eval_result_v02 as V02
import test_merkle_accumulator as ACC
from proofbundle import intoto as I

_RFC8785 = importlib.util.find_spec("rfc8785") is not None


def _verdict(evaluated_at: str) -> dict:
    statement = V02._base_statement()
    statement["predicate"]["evaluatedAt"] = evaluated_at
    return I.verify_eval_result_dsse(V02._sign(statement), V02._pub(), expected_predicate_type=None)


@pytest.mark.parametrize("value", [
    "٢٠٢٦-07-05T12:00:00Z", "2026-٠٧-05T12:00:00Z", "2026-07-05T１２:00:00Z",
    "2026-07-05T12:00:00+०१:00", "2026-07-05T12:00:00.১Z",
], ids=["Arabic-Indic year", "Arabic-Indic month", "fullwidth hour", "Devanagari offset", "Bengali fraction"])
def test_a_date_time_in_other_digits_is_no_rfc3339_date_time(value):
    res = _verdict(value)
    assert res["ok"] is False and res["predicate_shape_ok"] is False, res
    assert "evaluatedAt" in res["predicate_shape_detail"], res["predicate_shape_detail"]


@pytest.mark.parametrize("value", ["2026-07-05T12:00:00Z", "2026-07-05T12:00:00.5+01:30", "2024-02-29t23:59:60z"])
def test_control_an_ascii_date_time_keeps_its_verdict(value):
    res = _verdict(value)
    assert res["ok"] is True and res["predicate_shape_ok"] is True, res


def test_control_a_date_time_that_is_none_stays_refused():
    assert _verdict("2026-13-05T12:00:00Z")["predicate_shape_ok"] is False


# --- the accumulator's signed empty state -------------------------------------------------------------------------

@pytest.fixture
def empty_state():
    if not _RFC8785:
        pytest.skip("the persisted state is signed over its RFC 8785 form (the [eval] extra)")
    import rfc8785
    a, signer = ACC._load(), ACC._emitter_key()

    def signed(content) -> dict:
        return {"state": content, "signature": base64.b64encode(
            signer.sign(a.STATE_SIGNATURE_PREFIX + rfc8785.dumps(content))).decode()}

    state = a.MerkleAccumulator().state(signer, event_public_key=ACC._event_pub())["state"]
    assert state["frontier"] == [] and state["tree_size"] == 0
    return a, signed, state, ACC._pub(signer)


@pytest.mark.parametrize("frontier", [{}, "", {"0": 1}, "ab", None, 0],
                         ids=["empty object", "empty string", "an object", "a string", "null", "zero"])
def test_a_frontier_that_is_no_list_is_refused(empty_state, frontier):
    a, signed, state, pub = empty_state
    content = copy.deepcopy(state)
    content["frontier"] = frontier
    with pytest.raises(a.AccumulatorStateError, match="frontier"):
        a.MerkleAccumulator.restore(signed(content), pub, event_public_key=ACC._event_pub())


def test_control_the_written_empty_frontier_restores(empty_state):
    a, signed, state, pub = empty_state
    restored = a.MerkleAccumulator.restore(signed(copy.deepcopy(state)), pub, event_public_key=ACC._event_pub())
    assert restored.root() == a.MerkleAccumulator().root()
