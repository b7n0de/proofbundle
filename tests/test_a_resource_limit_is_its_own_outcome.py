"""A check that stops at a resource limit gives a resource-limit outcome: no verdict, no status, no FAIL.

Draft 1 Section 5: a Receiver that stops at a resource limit reports neither PASS nor the failure of a
step. Draft 2 Section 5.2.2: a Receiver that stops at a resource limit, in any step, reports a
resource-limit error; that is no status, and the statement is not accepted. The limits themselves stay
as they are: the interpreter's recursion limit for JSON, and a nesting depth of 400 for CBOR, the depth
cbor2 6.1.4 enforced before the statement reader judged its own bytes.

Before this test the receipt verifier reported such a stop as FAIL of step 1 or 4 (the parser's
RecursionError), and raised RecursionError where B parsed but its RFC 8785 serialization did not; the
statement check turned the receipt's stop into receipt_not_verified and its own depth limit into
malformed; show-eval answered exit 1 "FAILED at step 4" or exit 2 "unexpected RecursionError".
The surfaces still never raise for what they read: the outcome is a value, as every refusal is.
"""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import signed_eval_receipt as ser
from proofbundle.cli import main

REPO = Path(__file__).resolve().parents[1]
DRAFT1 = json.loads((REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json")
                    .read_text(encoding="utf-8"))
COSE = json.loads((REPO / "tests" / "fixtures" / "receipt_cose" / "vectors.json").read_text(encoding="utf-8"))
#: The Draft 1 PURE TEST seed of the issuer key, written out (tests/test_sdist_ohne_signierwerkzeug.py).
_DRAFT_TEST_SEED = b'#eR\x04\x10t\x8d\xe8w\x8bTD\x10\xb1W\x92\xfc\xf1t\xe0\xfb\xa4\x80j\x8c\x1a\xfb\xdb\xb0\x94k\x07'
KEY = Ed25519PrivateKey.from_private_bytes(_DRAFT_TEST_SEED)
PUB = KEY.public_key().public_bytes_raw()
B1_TEXT = DRAFT1["payloads"]["B1"]["text"].encode("utf-8")
P1 = next(x for x in DRAFT1["vectors"] if x["id"] == "P1")["receipt_text"].encode("utf-8").replace(
    b"@B1@", base64.b64encode(B1_TEXT))
needs_cbor2 = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                 reason="the [scitt] extra (cbor2) is not installed")


def _deep_schema(depth: int) -> bytes:
    """P1 with its schema member replaced by an array nested DEPTH deep."""
    old = b'"schema":"application/eval-receipt+json"'
    assert P1.count(old) == 1
    return P1.replace(old, b'"schema":' + b"[" * depth + b"]" * depth)


def _signed(b: bytes) -> bytes:
    """A receipt for B under the issuer test key, so that only B decides the outcome."""
    sig = KEY.sign(ser.pae(ser.RECEIPT_TYPE, b))
    receipt = {"payload_b64": base64.b64encode(b).decode(), "schema": ser.RECEIPT_TYPE,
               "signature": {"alg": "ed25519", "key": base64.b64encode(PUB).decode(),
                             "sig": base64.b64encode(sig).decode()}}
    return json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()


def _deep_b(depth: int) -> bytes:
    """A receipt whose B holds, beside its members, one more member nested DEPTH deep."""
    return _signed(B1_TEXT.replace(b'"suite":"', b'"suite":' + b"[" * depth + b"]" * depth + b',"x":"', 1))


def _limit(verdict: ser.ReceiptVerdict) -> tuple:
    return (verdict.ok, verdict.step, verdict.resource_limit, verdict.step_label)


@pytest.mark.parametrize("make,depth", [(_deep_schema, 200000), (_deep_b, 200000), (_deep_b, 450)],
                         ids=["receipt 200000 deep", "B 200000 deep", "B 450 deep, parses, serializes not"])
def test_the_receipt_verifier_reports_a_resource_limit_and_does_not_raise(make, depth):
    verdict = ser.verify_signed_eval_receipt(make(depth), PUB)
    assert _limit(verdict) == (False, None, True, "resource limit"), verdict


def test_a_shallow_nesting_still_fails_at_its_step():
    """The same construction 300 deep is read and fails step 5 (B is not its own RFC 8785 form)."""
    verdict = ser.verify_signed_eval_receipt(_deep_b(300), PUB)
    assert (verdict.ok, verdict.step, verdict.step_label) == (False, 5, "5"), verdict
    assert getattr(verdict, "resource_limit", False) is False
    assert ser.verify_signed_eval_receipt(P1, PUB).ok


@needs_cbor2
def test_the_statement_check_passes_the_receipts_resource_limit_on():
    from proofbundle import receipt_cose as rc
    b1 = bytes.fromhex(next(v for v in COSE["backward"] if v["id"] == "B1")["statement_hex"])
    pairs = [(COSE["issuer"], PUB)]
    for receipt in (_deep_schema(200000), _deep_b(450)):
        result = rc.check_statement(b1, receipt=receipt, receipt_key=PUB, statement_keys=pairs)
        assert (result.status, result.ok) == (rc.RESOURCE_LIMIT, False), result.detail
        assert result.status not in ("malformed", "receipt_not_verified")
    assert rc.check_statement(b1, receipt=P1, receipt_key=PUB, statement_keys=pairs).ok


@needs_cbor2
def test_the_statement_reader_reports_its_nesting_limit():
    from proofbundle import receipt_cose as rc
    import cbor2
    b1 = bytes.fromhex(next(v for v in COSE["backward"] if v["id"] == "B1")["statement_hex"])
    protected, _u, payload, _s = cbor2.loads(b1).value
    pairs = sorted([(rc._enc(k), rc._enc(v)) for k, v in cbor2.loads(protected).items()])

    def statement(depth: int) -> bytes:
        extra = sorted(pairs + [(b"\x00", b"\x81" * depth + b"\x00")])
        header = rc._head(5, len(extra)) + b"".join(k + v for k, v in extra)
        sig = KEY.sign(rc._sig_structure(header, payload))
        return rc._head(6, 18) + b"\x84" + rc._enc(header) + b"\xa0" + rc._enc(payload) + rc._enc(sig)
    check = lambda s: rc.check_statement(s, receipt=P1, receipt_key=PUB,  # noqa: E731
                                         statement_keys=[(COSE["issuer"], PUB)])
    deep = check(statement(1000))
    assert (deep.status, deep.ok) == (rc.RESOURCE_LIMIT, False), deep.detail
    assert check(statement(300)).status == "outside_profile"
    assert rc.RESOURCE_LIMIT in rc.STATUSES


def _show_eval(tmp_path, raw: bytes, capsys) -> tuple:
    path = tmp_path / "receipt.json"
    path.write_bytes(raw)
    code = main(["show-eval", str(path), "--expect-issuer", "ed25519:" + base64.b64encode(PUB).decode()])
    out = capsys.readouterr()
    return code, out.out + out.err


@pytest.mark.parametrize("depth", [200000, 450])
def test_show_eval_reports_a_resource_limit_with_its_own_exit_code(tmp_path, capsys, depth):
    code, text = _show_eval(tmp_path, _deep_b(depth), capsys)
    assert code == 4, text
    assert "resource limit" in text and "FAILED" not in text and "=> OK" not in text


def test_show_eval_keeps_its_other_exit_codes(tmp_path, capsys):
    assert _show_eval(tmp_path, P1, capsys)[0] == 0
    assert _show_eval(tmp_path, _deep_b(300), capsys)[0] == 1
    sig = json.loads(P1)["signature"]["sig"]
    flipped = base64.b64encode(bytes([base64.b64decode(sig)[0] ^ 1]) + base64.b64decode(sig)[1:]).decode()
    assert _show_eval(tmp_path, P1.replace(sig.encode(), flipped.encode()), capsys)[0] == 1


def _deep_member(depth: int) -> bytes:
    """P1 with one more member before its schema, an array nested DEPTH deep: too deep, from about 1000 on,
    for the JSON decoder that tells the formats apart."""
    return P1.replace(b'"schema":', b'"x":' + b"[" * depth + b"]" * depth + b',"schema":', 1)


def _large_member(n: int) -> bytes:
    """P1 with one more member after its schema, a text of N bytes."""
    return P1.replace(b'"signature":', b'"x":"' + b"a" * n + b'","signature":', 1)


@pytest.mark.parametrize("depth", [2000, 200000])
def test_a_receipt_too_deep_to_tell_its_format_still_reaches_the_receipt_path(tmp_path, capsys, depth):
    """The format is told apart by the schema member. A receipt too deep for the decoder that reads it is
    still a receipt: show-eval reports the resource limit with exit 4, not the eval-claim path's exit 2."""
    assert ser.names_receipt_type(_deep_member(depth)) is True
    code, text = _show_eval(tmp_path, _deep_member(depth), capsys)
    assert code == 4, text
    assert "resource limit" in text and "eval-receipt-v1" in text and "nesting is too deep" not in text


def test_a_receipt_larger_than_the_input_limit_reaches_the_receipt_path(tmp_path, capsys):
    """A receipt larger than the CLI's input limit, its schema before the cut, stops at that limit: exit 4."""
    from proofbundle.budget import DEFAULT_BUDGET
    raw = _large_member(DEFAULT_BUDGET.input_bytes)
    assert len(raw) > DEFAULT_BUDGET.input_bytes
    code, text = _show_eval(tmp_path, raw, capsys)
    assert code == 4, text
    assert "input limit" in text and "eval-receipt-v1" in text


def test_the_dispatch_controls_keep_their_exit_codes(tmp_path, capsys):
    """900 deep is read and fails step 1 (exit 1); a file of another schema, too deep or too large, stays
    in the eval-claim path (exit 2); a weak pin is refused before the size is reported (exit 2)."""
    from proofbundle.budget import DEFAULT_BUDGET
    assert _show_eval(tmp_path, _deep_member(900), capsys)[0] == 1
    other = b'"schema":"application/other+json"'
    assert _show_eval(tmp_path, _deep_member(2000).replace(b'"schema":"application/eval-receipt+json"',
                                                           other), capsys)[0] == 2
    large_other = _large_member(DEFAULT_BUDGET.input_bytes).replace(b'"schema":"application/eval-receipt+json"',
                                                                    other)
    assert ser.names_receipt_type(large_other) is False
    cut = DEFAULT_BUDGET.input_bytes
    assert ser._names_receipt_type_before_cut(_large_member(cut)[:cut]) is True
    assert ser._names_receipt_type_before_cut(large_other[:cut]) is False
    assert ser._names_receipt_type_before_cut(_large_member(cut).replace(b'"schema"', b'"z"', 1)[:cut]) is False
    assert _show_eval(tmp_path, large_other, capsys)[0] == 2
    path = tmp_path / "large.json"
    path.write_bytes(_large_member(DEFAULT_BUDGET.input_bytes))
    assert main(["show-eval", str(path), "--expect-issuer", "ed25519:" + base64.b64encode(b"\x00" * 32).decode()]) == 2


def test_names_receipt_type_answers_for_deep_and_cut_texts_without_raising():
    """The dispatch never raises; a deep receipt names the type, a deep text of another schema does not,
    and a schema inside a nested object is no top-level schema."""
    assert ser.names_receipt_type(_deep_member(200000)) is True
    assert ser.names_receipt_type(b'{"a":' + b"[" * 200000 + b"]" * 200000 + b',"schema":"x"}') is False
    nested = b'{"a":{"schema":"application/eval-receipt+json"},"b":' + b"[" * 5000 + b"]" * 5000 + b"}"
    assert ser.names_receipt_type(nested) is False
    assert ser.names_receipt_type(b"[" * 200000) is False
    assert ser.names_receipt_type(b'{"x":' + b"[" * 200000) is False
