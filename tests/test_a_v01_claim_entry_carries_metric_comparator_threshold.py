"""An eval-result v0.1 statement verifies only when each claim entry carries metric, comparator and threshold.

docs/IN_TOTO_PROFILE.md, the v0.1 table: "`claims[]` | one or more `{metric, comparator, threshold,
passed}`. ... In v0.1 `passed` is optional: a claim without it verifies and carries no verdict, and a
present `passed` must be a boolean." So `metric`, `comparator` and `threshold` are required in every
entry, and `passed` is not.

WHERE THIS COMES FROM. The deep gate of 6.5.0, iteration 1 (tag note of v6.5.0, "Known limitations of
this release"): a validly signed v0.1 statement whose `claims` held an empty object verified, measured
again at ac4129f7 with `verify_eval_result_dsse` (ok True, predicate_claim_ok True) and with
`proofbundle intoto --verify` (PASS, exit 0). The claim rule judged the fields an entry carried, and
the member check judged only that `claims` was not empty.

The 14 statements of tests/fixtures/eval_result_v0_1/corpus.json carry all three in every entry.
"""
from __future__ import annotations

import base64
import copy
import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse
from proofbundle import intoto as I

REPO = Path(__file__).resolve().parents[1]
_RELEASED = REPO / "tests/fixtures/eval_result_v0_1/envelope_jcs.json"
_CORPUS = REPO / "tests/fixtures/eval_result_v0_1/corpus.json"
_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))   # the throwaway example key
FULL = {"metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True}


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _signed(claims: list) -> dict:
    env = json.loads(_RELEASED.read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(env["payload"]))
    statement["predicate"] = dict(statement["predicate"], claims=claims)
    body = I._serialize_statement(statement, statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG))
    return dsse.sign_envelope(body, _SIGNER, payload_type=I.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _cli(env: dict) -> tuple:
    from proofbundle.cli import main
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "env.json"
        path.write_text(json.dumps(env), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["intoto", "--verify", "--pub", base64.b64encode(_pub()).decode(), str(path)])
    return rc, out.getvalue() + err.getvalue()


@pytest.mark.parametrize("missing", [("metric", "comparator", "threshold"), ("metric",), ("comparator",),
                                     ("threshold",), ("metric", "threshold")])
def test_a_claim_entry_without_a_required_member_does_not_verify(missing: tuple) -> None:
    entry = {k: v for k, v in FULL.items() if k not in missing}
    res = I.verify_eval_result_dsse(_signed([entry]), _pub())
    assert res["signature_ok"] is True
    assert res["ok"] is False and res["predicate_claim_ok"] is False
    # The verdict names the first reason, as it does for a missing top-level member.
    first = next(t for t in ("metric", "comparator", "threshold") if t in missing)
    assert res["content_root_detail"] == f"predicate claims[0].{first}: is required by eval-result v0.1 and absent"


def test_the_reason_names_the_index_of_the_entry() -> None:
    res = I.verify_eval_result_dsse(_signed([FULL, FULL, {"metric": "m", "comparator": ">="}]), _pub())
    assert res["ok"] is False
    assert "predicate claims[2].threshold: is required by eval-result v0.1 and absent" in res["content_root_detail"]
    assert "claims[0]" not in res["content_root_detail"] and "claims[1]" not in res["content_root_detail"]


def test_the_command_answers_fail_with_exit_1() -> None:
    rc, text = _cli(_signed([{}]))
    assert rc == 1, text
    assert "predicate claims[0].metric: is required by eval-result v0.1 and absent" in text


@pytest.mark.parametrize("entry", [FULL, {k: v for k, v in FULL.items() if k != "passed"}])
def test_an_entry_with_the_three_verifies_with_or_without_passed(entry: dict) -> None:
    res = I.verify_eval_result_dsse(_signed([entry]), _pub())
    assert res["ok"] is True, res["content_root_detail"]


def test_an_entry_that_is_no_object_keeps_its_own_reason() -> None:
    res = I.verify_eval_result_dsse(_signed([5]), _pub())
    assert res["ok"] is False
    assert "predicate claims[0]: must be an object" in res["content_root_detail"]
    assert "claims[0].metric" not in res["content_root_detail"]


def test_every_statement_of_the_released_corpus_verifies_as_before() -> None:
    corpus = json.loads(_CORPUS.read_text(encoding="utf-8"))
    public = base64.b64decode(corpus["public_key_b64"])
    assert len(corpus["entries"]) == 14
    for item in corpus["entries"]:
        claims = json.loads(base64.b64decode(item["envelope"]["payload"]))["predicate"]["claims"]
        assert all(type(c) is dict and {"metric", "comparator", "threshold"} <= set(c) for c in claims), item["id"]
        assert I.verify_eval_result_dsse(copy.deepcopy(item["envelope"]), public)["ok"] is True, item["id"]
