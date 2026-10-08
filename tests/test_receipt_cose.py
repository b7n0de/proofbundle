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
ISSUER = VECTORS["issuer"]
#: The relying party's configuration of most checks below: the issuer test key, trusted for ISSUER only.
PAIRS = [(ISSUER, KEYS["issuer"])]
#: Vector M2 of draft-gruszka-evaluation-receipt-mappings-00: its kid and the SHA-256 of its bytes.
M2_KID = "c94d618c32417cedb44280d4d66029e6486aa834802d12cd919c817453eb1561"
M2_SHA256 = "64e78be4636b8d1e90cb7a1ebe06c4cfba2848603d6f64958d7c2080a901c575"
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
                              statement_keys=[(iss, KEYS[k]) for iss, k in vector["statement_keys"]], **extra)


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
    """Only the four valid statements pass; every deviation is a refusal with its own status."""
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
@pytest.mark.parametrize("alg", [-8, -7, True, 19, "-19", None])
def test_the_forward_direction_writes_only_alg_minus_19(alg):
    """Owner choice B of 2026-10-04: -8 (EdDSA, deprecated by RFC 9864) is read, never written."""
    with pytest.raises(rc.ReceiptCoseError, match="writes alg -19 .* only"):
        rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=VECTORS["issuer"], alg=alg)


@needs_cbor2
def test_the_forward_direction_without_an_alg_writes_minus_19():
    data = rc.receipt_to_statement(_receipt("P1"), KEYS["issuer"], _issuer_key(), issuer=VECTORS["issuer"])
    assert hashlib.sha256(data).hexdigest() == M2_SHA256


@needs_cbor2
@pytest.mark.parametrize("issuer", ["issuer example", "", "https://issuer.example/a b", 7,
                                    "https://issuer.example/eval#frag", "https://issuer.example/<x>"])
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
                                receipt_key=KEYS["issuer"], statement_keys=[(ISSUER, KEYS["issuer"][:31]), (ISSUER, "x")])
    assert result.status == "untrusted_key"
    assert len(result.ignored_keys) == 2


def _vector(vid: str) -> bytes:
    return bytes.fromhex(next(v for v in VECTORS["backward"] if v["id"] == vid)["statement_hex"])


@needs_cbor2
def test_a_statement_key_counts_only_for_the_issuer_it_is_paired_with():
    """B37 is B1 with another iss, signed by the same key. The received iss
    selects a pair; it never makes a key trusted for an issuer the relying party did not pair it with."""
    b1, b37 = _vector("B1"), _vector("B37")
    other = rc._read(b37).protected[15][1]
    assert other == "https://other-issuer.example/eval"

    def status(statement, pairs):
        return rc.check_statement(statement, receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                  statement_keys=pairs).status
    assert status(b37, PAIRS) == "untrusted_key"
    assert status(b37, [(other, KEYS["issuer"])]) == rc.ACCEPTED
    assert status(b37, [(ISSUER, KEYS["issuer"]), (other, KEYS["issuer"])]) == rc.ACCEPTED
    assert status(b1, [(other, KEYS["issuer"])]) == "untrusted_key"
    assert status(b1, [(other, KEYS["issuer"]), (ISSUER, KEYS["foreign"])]) == "untrusted_key"


@needs_cbor2
@pytest.mark.parametrize("configured", [ISSUER + "/", ISSUER.upper(), "HTTPS://issuer.example/eval",
                                        "https://issuer.example:443/eval", ISSUER + "?", " " + ISSUER])
def test_the_issuer_of_a_pair_is_compared_exactly(configured):
    """No URI normalization: a pair names the iss string it trusts the key for, byte for byte."""
    result = rc.check_statement(_vector("B1"), receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[(configured, KEYS["issuer"])])
    assert result.status == "untrusted_key"


@needs_cbor2
@pytest.mark.parametrize("entry", [KEYS["issuer"], [KEYS["issuer"]], (ISSUER, KEYS["issuer"], "extra"),
                                   (KEYS["issuer"], ISSUER), (ISSUER.encode(), KEYS["issuer"]), {ISSUER: KEYS["issuer"]}])
def test_an_entry_that_is_no_pair_of_issuer_and_key_is_absent_trust(entry):
    """A bare key, the form before 2026-10-07, names no issuer and is never counted."""
    result = rc.check_statement(_vector("B1"), receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[entry])
    assert result.status == "untrusted_key"
    assert len(result.ignored_keys) == 1


@needs_cbor2
def test_the_statement_signature_meets_the_rules_of_section_4_4():
    """B38's R is the neutral element. The cofactorless equation holds, so the
    plain library check accepts it; rule 2 of Section 4.4 of the receipts draft refuses it."""
    from proofbundle.signature import verify_ed25519
    st = rc._read(_vector("B38"))
    assert st.signature[:32] == (1).to_bytes(32, "little")
    assert verify_ed25519(KEYS["issuer"], st.signature, rc._sig_structure(st.protected_raw, st.payload)) is True
    result = rc.check_statement(_vector("B38"), receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=PAIRS)
    assert result.status == "signature_invalid"


@needs_cbor2
def test_neither_a_statement_key_of_mixed_order_nor_one_without_a_point_counts():
    """T-B04: rules 1 and 2 of Section 4.4 decide which entry counts. B41's key is the mixed-order key of
    Draft 1 vector P11, which is not of order L (rule 2); B39's entry has y = 2, which names no curve point
    (rule 1). Neither counts."""
    p11 = next(x for x in DRAFT1["vectors"] if x["id"] == "P11")
    assert base64.b64decode(p11["key_b64"]) == KEYS["mixed_order"]
    result = rc.check_statement(_vector("B41"), receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[(ISSUER, KEYS["mixed_order"])])
    assert result.status == "untrusted_key"
    assert "rule 2 of Section 4.4" in result.ignored_keys[0]
    result = rc.check_statement(_vector("B39"), receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=[(ISSUER, KEYS["off_curve"])])
    assert result.status == "untrusted_key"
    assert "rule 1 of Section 4.4" in result.ignored_keys[0]


@needs_cbor2
def test_alg_minus_8_is_read_only_under_an_ed25519_statement_key():
    """B2 carries -8: accepted under the Ed25519 issuer key, untrusted under a P-256 key alone (B36), and
    outside the profile for a relying party that reads -19 only (B10)."""
    b2 = bytes.fromhex(next(v for v in VECTORS["backward"] if v["id"] == "B2")["statement_hex"])
    assert rc._read(b2).protected[1] == -8

    def status(keys, **kw):
        return rc.check_statement(b2, receipt=_receipt("P1"), receipt_key=KEYS["issuer"], statement_keys=keys,
                                  **kw).status
    assert status(PAIRS) == rc.ACCEPTED
    assert status([(ISSUER, KEYS["p256"])]) == "untrusted_key"
    assert status([(ISSUER, KEYS["p256"]), (ISSUER, KEYS["issuer"])]) == rc.ACCEPTED
    assert status(PAIRS, algs=(-19,)) == "outside_profile"


@needs_cbor2
@pytest.mark.parametrize("statement", ["d284", None, bytearray(b"\xd2"), 18])
def test_the_check_never_raises_for_what_it_reads(statement):
    result = rc.check_statement(statement, receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=PAIRS)
    assert result.status == "malformed"


@pytest.mark.parametrize("algs", [(), (-7,), (True,), "-19", None])
def test_the_accepted_algs_are_a_choice_among_minus_19_and_minus_8(algs):
    with pytest.raises(ValueError):
        rc.check_statement(b"", receipt=b"", receipt_key=b"", statement_keys=[], algs=algs)


# ---- CBOR only through the [scitt] extra ------------------------------------------------------------------
def test_without_cbor2_the_check_says_no_lib_and_the_forward_direction_refuses(monkeypatch):
    monkeypatch.setitem(sys.modules, "cbor2", None)
    result = rc.check_statement(b"\xd2\x84", receipt=_receipt("P1"), receipt_key=KEYS["issuer"],
                                statement_keys=PAIRS)
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
                                statement_keys=PAIRS)
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
