"""OQ-21 (owner answer of 2026-10-27): `agent_review.load_policy` reads the policy file with the strict JSON reader,
as the trust policy is read.

Before this, the agent-review policy was read with Python's json and the duplicate-key rule alone
(`loads_reject_duplicate_keys`). NaN, Infinity, 1e400, an integer literal outside +-(2**53 - 1), nesting past the
depth bound, more members than the node budget and a lone surrogate all passed into a policy whose digest then bound
bytes that another JSON reader would read differently or refuse. The trust policy of the command line refuses each of
them (`loads_strict`). Each sample sits in a further key, which decides nothing, so only the reader can refuse it.
"""
from __future__ import annotations

import json

import pytest

from proofbundle import agent_review as AR
from proofbundle._strict_json import loads_strict
from proofbundle.errors import ProofBundleError

_BASIS = '{"name":"test","blocking":["COVERAGE_PARTIAL"],"x":@@}'

NOT_STRICT_JSON = {
    "NaN": "NaN",
    "Infinity": "Infinity",
    "-Infinity": "-Infinity",
    "1e400": "1e400",
    "2^53+1": "9007199254740993",
    "nesting 70": "[" * 70 + "]" * 70,
    "200001 members": "[" + ",".join(["0"] * 200001) + "]",
    "lone surrogate": '"\\ud800"',
}


def _policy(tmp_path, name: str, value: str):
    f = tmp_path / f"{name.replace(' ', '_')}.json"
    f.write_bytes(_BASIS.replace("@@", value).encode("utf-8"))
    return f


@pytest.mark.parametrize("case", sorted(NOT_STRICT_JSON))
def test_load_policy_refuses_what_the_strict_reader_refuses(tmp_path, case):
    f = _policy(tmp_path, case, NOT_STRICT_JSON[case])
    with pytest.raises(ProofBundleError):
        loads_strict(f.read_bytes())          # the trust policy's reader refuses it
    with pytest.raises(AR.AgentReviewError):
        AR.load_policy(f)


@pytest.mark.parametrize("value", ["1", "9007199254740991", "-9007199254740991", "1.5e300", '"\\u00e4"',
                                   "[" * 60 + "]" * 60, "null"])
def test_control_strict_json_in_the_same_place_loads(tmp_path, value):
    pol = AR.load_policy(_policy(tmp_path, "ok", value))
    assert pol["blocking"] == ["COVERAGE_PARTIAL"]
    assert pol["x"] == json.loads(value)


def test_control_the_default_policy_loads():
    pol = AR.load_policy()
    assert pol["_digest"].startswith("sha256:")
