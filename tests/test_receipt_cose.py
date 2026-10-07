"""The receipt <-> COSE_Sign1 translator (``proofbundle.receipt_cose``), against its vectors.

Each vector of tests/fixtures/receipt_cose/vectors.json is one lock: a forward vector is a receipt that
gives these statement bytes or no statement, a backward vector a statement that gets this status and no
other. F1 must be vector M2 of draft-gruszka-evaluation-receipt-mappings-00 byte for byte. The vectors are
written by tools/receipt_cose_vectors/generate.py; a divergence is red and is never adjusted silently.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import receipt_cose as rc

REPO = Path(__file__).resolve().parents[1]
VECTORS = json.loads((REPO / "tests" / "fixtures" / "receipt_cose" / "vectors.json").read_text(encoding="utf-8"))
DRAFT1 = json.loads((REPO / "tests" / "fixtures" / "signed_eval_receipt" / "draft1_vectors.json")
                    .read_text(encoding="utf-8"))
KEYS = {name: bytes.fromhex(value) for name, value in VECTORS["keys_hex"].items()}
#: Vector M2 of draft-gruszka-evaluation-receipt-mappings-00: its kid and the SHA-256 of its bytes.
M2_KID = "c94d618c32417cedb44280d4d66029e6486aa834802d12cd919c817453eb1561"
M2_SHA256 = "c987b06017a54d89b3c3553c54544bc7d95f7220e6e87e1a9a6369505401260e"
#: The Draft 1 PURE TEST seed of the issuer key, written out as in tests/test_signed_eval_receipt_conformance.py:
#: a shipped test builds a throwaway key from a literal and loads no key from outside
#: (tests/test_sdist_ohne_signierwerkzeug.py). A test below holds it equal to the fixture's seed.
_DRAFT_TEST_SEED = b'#eR\x04\x10t\x8d\xe8w\x8bTD\x10\xb1W\x92\xfc\xf1t\xe0\xfb\xa4\x80j\x8c\x1a\xfb\xdb\xb0\x94k\x07'
needs_cbor2 = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                 reason="the [scitt] extra (cbor2) is not installed")


def _receipt(vid: str) -> bytes:
    payloads = {n: (p["text"].encode("utf-8") if "text" in p else base64.b64decode(p["b64"]))
                for n, p in DRAFT1["payloads"].items()}
    v = next(x for x in DRAFT1["vectors"] if x["id"] == vid)
    raw = v["receipt_text"].encode("utf-8") if "receipt_text" in v else base64.b64decode(v["receipt_b64"])
    for name, b in payloads.items():
        raw = raw.replace(b"@" + name.encode("ascii") + b"@", base64.b64encode(b))
    assert hashlib.sha256(raw).hexdigest() == v["receipt_sha256"], vid
    return raw


def _issuer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_DRAFT_TEST_SEED)


def test_the_written_seed_is_the_draft_1_test_seed():
    assert _DRAFT_TEST_SEED.hex() == DRAFT1["issuer_seed_hex"]
    assert _issuer_key().public_key().public_bytes_raw() == KEYS["issuer"]


def _check(vector: dict) -> rc.StatementCheck:
    extra = {"algs": tuple(vector["algs"])} if "algs" in vector else {}
    return rc.check_statement(bytes.fromhex(vector["statement_hex"]), receipt=_receipt(vector["receipt"]),
                              receipt_key=KEYS[VECTORS["receipt_key"]],
                              statement_keys=[KEYS[k] for k in vector["statement_keys"]], **extra)


def test_the_kid_is_the_rfc9679_thumbprint_of_the_issuer_test_key():
    assert rc.cose_key_thumbprint(KEYS["issuer"]).hex() == M2_KID


@needs_cbor2
@pytest.mark.parametrize("vector", VECTORS["forward"], ids=[v["id"] for v in VECTORS["forward"]])
def test_every_forward_vector_gives_its_statement_or_none(vector):
    """A receipt that verifies gives exactly these bytes; one that does not gives no statement."""
    receipt, key = _receipt(vector["receipt"]), KEYS[vector["receipt_key"]]
    if vector["expect"] == "statement":
        data = rc.receipt_to_statement(receipt, key, _issuer_key(), issuer=VECTORS["issuer"], alg=vector["alg"])
        assert data.hex() == vector["statement_hex"]
    else:
        with pytest.raises(rc.ReceiptCoseError, match="no statement is made"):
            rc.receipt_to_statement(receipt, key, _issuer_key(), issuer=VECTORS["issuer"], alg=vector["alg"])


@needs_cbor2
def test_f1_is_vector_m2_of_the_mappings_draft():
    f1 = next(v for v in VECTORS["forward"] if v["id"] == "F1")
    assert hashlib.sha256(bytes.fromhex(f1["statement_hex"])).hexdigest() == M2_SHA256
    data = rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=VECTORS["issuer"], alg=-19)
    assert hashlib.sha256(data).hexdigest() == M2_SHA256


@needs_cbor2
@pytest.mark.parametrize("vector", VECTORS["backward"], ids=[v["id"] for v in VECTORS["backward"]])
def test_every_backward_vector_gets_its_status(vector):
    """Only the three valid statements pass; every deviation is a refusal with its own status."""
    result = _check(vector)
    assert result.status == vector["expect_status"], (result.status, result.detail)
    assert result.ok is (vector["expect_status"] == rc.ACCEPTED)


@needs_cbor2
def test_the_three_cases_the_order_names():
    """A receipt that does not verify gives no statement (F4); a statement on another digest (B4) and one
    with a valid signature under a foreign key (B5) are refused."""
    statuses = {v["id"]: v["expect_status"] for v in VECTORS["backward"]}
    expects = {v["id"]: v["expect"] for v in VECTORS["forward"]}
    assert (expects["F4"], statuses["B4"], statuses["B5"]) == ("refused", "digest_mismatch", "untrusted_key")


# ---- the forward direction's own locks ------------------------------------------------------------------
@needs_cbor2
@pytest.mark.parametrize("alg", [-7, True, 19, "-19", None])
def test_the_forward_direction_writes_only_alg_minus_19_or_minus_8(alg):
    with pytest.raises(rc.ReceiptCoseError, match="no default"):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=VECTORS["issuer"], alg=alg)


def test_the_forward_direction_has_no_default_alg():
    with pytest.raises(TypeError):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(),  # type: ignore[call-arg]
                                issuer=VECTORS["issuer"])


@needs_cbor2
@pytest.mark.parametrize("issuer", ["issuer example", "", "https://issuer.example/a b", 7])
def test_the_forward_direction_writes_a_uri_as_iss(issuer):
    with pytest.raises(rc.ReceiptCoseError, match="URI"):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=issuer, alg=-19)


@needs_cbor2
def test_the_forward_direction_signs_only_with_an_ed25519_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    with pytest.raises(rc.ReceiptCoseError, match="Ed25519"):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], ec.generate_private_key(ec.SECP256R1()),
                                issuer=VECTORS["issuer"], alg=-19)


@needs_cbor2
def test_the_forward_direction_returns_nothing_its_own_check_refuses(monkeypatch):
    """Function contract of the read-back: when the check of the written bytes does not accept them, no
    bytes are returned."""
    monkeypatch.setattr(rc, "check_statement", lambda *a, **k: rc.StatementCheck("outside_profile", "planted"))
    with pytest.raises(rc.ReceiptCoseError, match="did not read back"):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=VECTORS["issuer"], alg=-19)


# ---- the backward direction's own locks ------------------------------------------------------------------
@needs_cbor2
def test_a_relying_party_entry_that_is_no_ed25519_key_is_absent_trust():
    f1 = next(v for v in VECTORS["backward"] if v["id"] == "B1")
    result = rc.check_statement(bytes.fromhex(f1["statement_hex"]), receipt=_receipt("P1"),
                                receipt_key=KEYS["issuer"], statement_keys=[KEYS["issuer"][:31], "x"])
    assert result.status == "untrusted_key"
    assert len(result.ignored_keys) == 2


@needs_cbor2
@pytest.mark.parametrize("statement", ["d284", None, bytearray(b"\xd2"), 18])
def test_the_check_never_raises_for_what_it_reads(statement):
    result = rc.check_statement(statement, receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[KEYS["issuer"]])
    assert result.status == "malformed"


@pytest.mark.parametrize("algs", [(), (-7,), (True,), "-19", None])
def test_the_accepted_algs_are_a_choice_among_minus_19_and_minus_8(algs):
    with pytest.raises(ValueError):
        rc.check_statement(b"", receipt=b"", receipt_key=b"", statement_keys=[], algs=algs)


# ---- CBOR only through the [scitt] extra ------------------------------------------------------------------
def test_without_cbor2_the_check_says_no_lib_and_the_forward_direction_refuses(monkeypatch):
    monkeypatch.setitem(sys.modules, "cbor2", None)
    result = rc.check_statement(b"\xd2\x84", receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[KEYS["issuer"]])
    assert result.status == "no_lib"
    with pytest.raises(rc.CoseUnavailable):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=VECTORS["issuer"], alg=-19)


def test_a_cbor2_without_the_strict_options_is_no_lib(monkeypatch):
    class Old:
        CBORTag = object

        @staticmethod
        def loads(data, **options):
            if options:
                raise TypeError("unexpected keyword argument")
            return {}
    monkeypatch.setitem(sys.modules, "cbor2", Old)
    result = rc.check_statement(b"\xd2\x84", receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[KEYS["issuer"]])
    assert result.status == "no_lib"


def test_the_core_and_the_package_import_no_cbor():
    code = ("import sys, proofbundle, proofbundle.signed_eval_receipt, proofbundle.receipt_cose; "
            "print(sorted(m for m in sys.modules if m.split('.')[0] == 'cbor2'))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={"PYTHONPATH": str(REPO / "src")}, cwd=REPO)
    assert out.stdout.strip() == "[]"


def test_cbor2_is_named_only_by_the_scitt_extra():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = re.search(r"^dependencies = \[(.*?)\]", text, re.M | re.S)
    assert dependencies and "cbor2" not in dependencies.group(1)
    assert re.search(r'^scitt = \["cbor2==6\.1\.4"\]$', text, re.M)
