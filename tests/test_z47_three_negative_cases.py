"""Stage 1 of the plugin path (Z47): three negative cases on a REAL receipt and its REAL reply.

The receipt `receipts/agent_review/proofbundle_239_4057990627.receipt.json` was issued for the reply
posted on #239 (comment 4060008036). The fixture holds that reply byte for byte, as the GitHub API
returned it on 2026-09-22 (no trailing newline added). Built on published objects on purpose: a
fixture the test builds itself tests the shape the author had in mind, not the one that exists.

The positive case verifies. Each negative case must fail for its own reason:
1. the reply's bytes are changed outside the disclosure block (the bound body);
2. the signature is valid, but the relying party asks about a different candidate head;
3. the key that verifies is not the key the relying party trusts.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR

REPO = Path(__file__).resolve().parents[1]
NAME = "proofbundle_239_4057990627"
ENV = json.loads((REPO / "receipts" / "agent_review" / f"{NAME}.receipt.json").read_text())
PK = bytes.fromhex((REPO / "receipts" / "agent_review" / f"{NAME}.publickey.hex").read_text().strip())
BODY = (REPO / "tests" / "fixtures" / "agent_review_bodies" / "proofbundle_239_4060008036_reply.md").read_text(
    encoding="utf-8")
PRED = json.loads(base64.b64decode(ENV["payload"]))["predicate"]


def _verify(body: str = BODY, public_key: bytes = PK, subject_digest: str | None = None) -> dict:
    return AR.verify_agent_review(ENV, public_key, strict=True,
                                  expected_subject_digest=subject_digest or AR._subject_digest(PRED),
                                  observed_body=body)


def test_the_real_receipt_verifies_against_the_real_reply():
    r = _verify()
    assert r["ok"] is True, r["errors"]
    assert r["body_core_digest_match"] == "MATCH"


def test_1_changed_reply_bytes_fail():
    head, sep, tail = BODY.partition(AR.DISCLOSURE_BEGIN)
    assert sep, "the fixture must carry its disclosure block"
    changed = head.replace("Confirmed", "Rejected", 1) if "Confirmed" in head else head + " "
    r = _verify(body=changed + sep + tail)
    assert r["ok"] is False
    assert r["body_core_digest_match"] == "MISMATCH"


def test_2_a_valid_signature_for_another_candidate_head_does_not_answer_the_question():
    other = json.loads(json.dumps(PRED))
    other["subjectContext"]["headSha"] = "0" * 40
    r = _verify(subject_digest=AR._subject_digest(other))
    assert r["ok"] is False
    assert r["errors"], "a failed subject binding must name its reason"


def test_3_a_key_outside_the_trust_rule_yields_no_trusted_statement():
    """THE REASON IS CHECKED, NOT ONLY THE VERDICT. Linse 3 measured on 2026-09-22 that a mutant
    dropping `crypto_ok` from the conjunction behind `ok` survived this file: `ok is False` is true
    for any rejection, including one for the wrong reason. A relying party that is told "no" about
    the signature must be told no BECAUSE of the signature."""
    foreign = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    r = _verify(public_key=foreign)
    assert r["ok"] is False
    assert r["crypto_ok"] is False, "the rejection must be the signature, not something else"
    assert r["structure_ok"] is True, "the envelope is well formed; only the key is foreign"
    assert any("signature verification failed" in str(e) for e in r["errors"]), r["errors"]
    # The axes that are NOT about the key keep their own answer — a wrong key does not make the
    # visible text disagree with the receipt, and saying so would be a second, invented finding.
    assert r["body_core_digest_match"] == "MATCH"
    # MEASURED GAP, pinned so it cannot change silently: this path sets NO `reason_code`. The
    # reason lives in `errors` only, so a consumer that branches on `reason_code` sees None for a
    # failed signature. Pinning the measured state is not endorsing it — it is what a later change
    # has to walk past. (2026-09-22, while hardening this oracle after Linse 3.)
    assert r["reason_code"] is None and r["reason_codes"] == []
