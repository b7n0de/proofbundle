"""Builders for the derived EQR vectors. Every vector is written from the draft text alone.

A vector has: id, type (verify | set), the requirement ids it tests (requirements.json, a "+" or "-"
prefix overriding the vector's polarity for that one id), polarity (positive: the reader accepts what
the vector shows; negative: the vector presents a defect the reader must refuse or must not let
qualify), a description, the input and the expected result as selector -> value pairs (see
vectors/evaluate.py).

Signed receipts use JWS compact serialization with EdDSA over Ed25519. The signing keys are derived
from fixed labels so the file regenerates byte for byte; they are test keys and sign nothing else.
Only their public halves are in the vectors.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from eqr00.wire import jcs, sha256_b64u  # noqa: E402

NOW = "2026-09-12T23:55:00Z"
ISSUER = "https://qualifier.example"
OTHER_ISSUER = "https://other-qualifier.example"
PROFILE_ID = "https://example.org/profiles/invoice-overdue/v1"
PROFILE_JSON = {"profile": "invoice-overdue", "version": 1,
                "required_conditions": ["signed_invoice_record", "due_date_passed", "no_duplicate_payment",
                                        "fresh_under_five_minutes"],
                "missing": "indeterminate", "stale": "indeterminate", "contradiction": "fail"}
EMPTY_PROFILE_ID = "https://example.org/profiles/no-conditions/v1"
EMPTY_PROFILE_JSON = {"profile": "no-conditions", "version": 1, "required_conditions": []}
PROPOSITION = {"claim": "invoice 8472 is overdue", "invoice": "8472"}
OTHER_PROPOSITION = {"claim": "invoice 8473 is overdue", "invoice": "8473"}
ACTION = {"op": "pay", "invoice": "8472", "amount_cents": 125000}
OTHER_ACTION = {"op": "pay", "invoice": "8472", "amount_cents": 990000}
CONTEXT = {"snapshot": "ledger@2026-09-12T23:49:00Z"}
EVIDENCE_DIGEST = sha256_b64u(b"signed invoice record 8472")
CONTRA_DIGEST = sha256_b64u(b"duplicate payment service: unresolved")


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"eqr00 test vector key: " + label.encode()).digest())


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwk(label: str) -> dict:
    pub = _key(label).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub)}


def payload(**changes) -> dict:
    """The EQR payload of the Section 5.2 example with real digests; keyword None deletes a member."""
    p = {
        "version": "1",
        "receipt_id": "urn:uuid:6ac9f8f0-30e1-4b4c-a142-9f5cb5ad58f1",
        "issuer": ISSUER,
        "issued_at": "2026-09-12T23:50:00Z",
        "expires_at": "2026-09-13T00:05:00Z",
        "profile": {"id": PROFILE_ID, "hash_alg": "sha-256", "digest": sha256_b64u(jcs(PROFILE_JSON))},
        "claim": {"id": "urn:example:claim:invoice-8472-overdue", "hash_alg": "sha-256",
                  "digest": sha256_b64u(jcs(PROPOSITION))},
        "context_digest": sha256_b64u(jcs(CONTEXT)),
        "action_digest": sha256_b64u(jcs(ACTION)),
        "evaluation": {"status": "pass", "requirements_satisfied": True, "blocking_contradictions": []},
        "evidence": [{"class": "signed_invoice_record", "hash_alg": "sha-256", "digest": EVIDENCE_DIGEST,
                      "fresh_until": "2026-09-13T00:05:00Z"}],
        "nonce": "t9mS6wqz2Dbf",
        "supersedes": None,
    }
    for k, v in changes.items():
        if v is None:
            p.pop(k, None)
        else:
            p[k] = v
    return p


def text(p) -> str:
    """Pretty JSON text of a payload: the exact bytes the issuer emits (not canonical on purpose)."""
    return json.dumps(p, indent=2, ensure_ascii=False)


def sign(body, label="issuer-1", kid="k1", header=None) -> str:
    """Compact JWS over the exact payload text."""
    h = header if header is not None else {"alg": "EdDSA", "kid": kid}
    hb = _b64u(json.dumps(h, separators=(",", ":")).encode("utf-8"))
    pb = _b64u(body.encode("utf-8") if isinstance(body, str) else body)
    sig = _key(label).sign((hb + "." + pb).encode("ascii"))
    return f"{hb}.{pb}.{_b64u(sig)}"


def jws_receipt(p=None, **kw):
    return {"form": "jws", "compact": sign(text(p if p is not None else payload()), **kw)}


def context(**changes) -> dict:
    c = {
        "now": NOW,
        "inter_domain": True,
        "trust": {"issuers": {
            ISSUER: {"keys": {"k1": jwk("issuer-1")}, "profiles": [PROFILE_ID, EMPTY_PROFILE_ID]},
            OTHER_ISSUER: {"keys": {"k9": jwk("issuer-9")}, "profiles": [PROFILE_ID]}}},
        "profiles": {
            PROFILE_ID: {"json": PROFILE_JSON, "required_conditions": 4,
                         "evidence_classes": ["signed_invoice_record", "duplicate_payment_check"]},
            EMPTY_PROFILE_ID: {"json": EMPTY_PROFILE_JSON, "required_conditions": 0,
                               "evidence_classes": ["signed_invoice_record"]}},
        "proposition": {"claim_id": "urn:example:claim:invoice-8472-overdue", "json": PROPOSITION},
        "action": {"json": ACTION},
        "context": {"json": CONTEXT},
        "expected_nonce": "t9mS6wqz2Dbf",
        "policy_requires_pass": True,
    }
    for k, v in changes.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    return c


def V(vid, vtype, reqs, polarity, desc, inp, expect):
    return {"id": vid, "type": vtype, "requirements": list(dict.fromkeys(reqs)), "polarity": polarity,
            "description": desc, "input": inp, "expect": expect}


def R(vid, reqs, polarity, desc, receipt, ctx, expect):
    return V(vid, "verify", reqs, polarity, desc, {"receipt": receipt, "context": ctx}, expect)


QUALIFIES = {"receipt_validity": "VALID", "evaluation_status": "pass", "qualification.qualifies": True}


def verify_vectors():
    out = []
    add = out.append
    add(R("E-01", ["S8-1", "S6-1", "S8.1-1", "S15-1", "S15-3", "S5-1", "S5-3", "S5-5", "S5.1-1", "S5.1-4", "S7-1",
                   "S5-4", "S15-2", "S3-1", "S3-2", "S3-3", "S6-2"], "positive",
          "the Section 5.2 example with real digests, signed by the configured issuer key, every binding checked",
          jws_receipt(), context(high_consequence=True, max_validity_seconds=900),
          {**QUALIFIES, "integrity": "verified", "table1": "VALID receipt with PASS",
           "authorization": "not decided here: an EQR is one input to a separate authorization decision "
                            "(Sections 3 and 9)", "refusals": [], "unverifiable": []}))
    add(R("E-02", ["S8.1-1", "+S5.1-2", "S3-2", "S6-2"], "negative",
          "a validly signed FAIL receipt: valid, FAIL exposed unchanged, does not qualify",
          jws_receipt(payload(evaluation={"status": "fail", "requirements_satisfied": False,
                                          "blocking_contradictions": [CONTRA_DIGEST]})), context(),
          {"receipt_validity": "VALID", "evaluation_status": "fail", "table1": "VALID receipt with FAIL",
           "qualification.qualifies": False}))
    add(R("E-03", ["S8.1-1", "S3-3", "+S5.1-3", "S3-2", "S6-2"], "negative",
          "a validly signed INDETERMINATE receipt for a time-sensitive action: never converted into PASS",
          jws_receipt(payload(evaluation={"status": "indeterminate", "requirements_satisfied": False,
                                          "blocking_contradictions": 0})), context(time_sensitive=True),
          {"receipt_validity": "VALID", "evaluation_status": "indeterminate", "qualification.qualifies": False,
           "table1": "VALID receipt with INDETERMINATE"}))
    add(R("E-03b", ["S5.1-3"], "positive", "INDETERMINATE with unresolved contradiction digests is consistent",
          jws_receipt(payload(evaluation={"status": "indeterminate", "requirements_satisfied": False,
                                          "blocking_contradictions": [CONTRA_DIGEST]})), context(),
          {"receipt_validity": "VALID", "evaluation_status": "indeterminate"}))
    tampered = jws_receipt()["compact"].split(".")
    tampered[1] = base64.urlsafe_b64encode(text(payload(evaluation={
        "status": "pass", "requirements_satisfied": True, "blocking_contradictions": 0},
        receipt_id="urn:uuid:00000000-0000-4000-8000-000000000001")).encode()).rstrip(b"=").decode()
    add(R("E-04", ["S6-1", "S3-2"], "negative", "payload changed after signing",
          {"form": "jws", "compact": ".".join(tampered)}, context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "SIGNATURE_INVALID", "qualification.qualifies": False,
           "evaluation_status": None, "table1": "INVALID receipt"}))
    add(R("E-05", ["S6-1"], "negative", "an inter-domain receipt without integrity protection",
          {"form": "json", "text": text(payload())}, context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "NOT_INTEGRITY_PROTECTED"}))
    add(R("E-05b", ["S6-1", "S8-1"], "positive", "the same unprotected receipt where local policy declares it intra-domain",
          {"form": "json", "text": text(payload())}, context(inter_domain=False),
          {**QUALIFIES, "notes.has_code": "INTRA_DOMAIN_UNPROTECTED"}))
    add(R("E-06", ["S6-1", "S15-1"], "negative", "signed with the key of another issuer than the one the receipt names",
          jws_receipt(label="issuer-9", kid="k9"), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "ISSUER_KEY_MISMATCH"}))
    add(R("E-06b", ["S6-1"], "negative", "signed with a key the trust configuration does not hold",
          jws_receipt(label="stranger", kid="k7"), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "ISSUER_KEY_UNKNOWN"}))
    add(R("E-07", ["S6-1"], "negative", "alg none with an empty signature part",
          {"form": "jws", "compact": _b64u(b'{"alg":"none","kid":"k1"}') + "." + _b64u(text(payload()).encode()) + "."},
          context(), {"receipt_validity": "INVALID", "refusals.has_code": "JWS_HEADER"}))
    add(R("E-07b", ["S6-1"], "negative", "a crit header the reader does not support",
          jws_receipt(header={"alg": "EdDSA", "kid": "k1", "crit": ["exp"], "exp": 1}), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "JWS_HEADER"}))
    add(R("E-08", ["S15-4", "S6-1"], "negative",
          "a key URL in the header and a kid the trust configuration lacks: nothing is fetched, the receipt is refused",
          jws_receipt(label="stranger", kid="k-remote",
                      header={"alg": "EdDSA", "kid": "k-remote", "jku": "http://169.254.169.254/keys"}), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "ISSUER_KEY_UNKNOWN", "notes.has_code": "HEADER_NOT_USED"}))
    ev_ref = payload(evidence=[{"class": "signed_invoice_record", "hash_alg": "sha-256", "digest": EVIDENCE_DIGEST,
                                "fresh_until": "2026-09-13T00:05:00Z",
                                "retrieval": "http://169.254.169.254/latest/meta-data/"}])
    add(R("E-08b", ["S15-4"], "positive", "an evidence retrieval reference is kept as local metadata and never fetched",
          jws_receipt(ev_ref), context(), {**QUALIFIES, "notes.has_code": "LOCAL_METADATA_NOT_DEREFERENCED"}))
    # strict decoding (standard of 14 October 2026)
    dup = text(payload()).replace('"version": "1",', '"version": "1",\n  "version": "1",', 1)
    add(R("E-09", ["S8-1"], "negative", "a duplicated member in the signed payload",
          jws_receipt_raw(dup), context(), {"receipt_validity": "INVALID", "refusals.has_code": "STRICT_DECODING"}))
    dup_eval = text(payload()).replace('"status": "pass",', '"status": "fail",\n    "status": "pass",', 1)
    add(R("E-09b", ["S8-1"], "negative", "a duplicated status inside evaluation, the last value pass",
          jws_receipt_raw(dup_eval), context(), {"receipt_validity": "INVALID", "refusals.has_code": "STRICT_DECODING"}))
    hdr_dup = _b64u(b'{"alg":"EdDSA","kid":"k1","kid":"k9"}')
    body = _b64u(text(payload()).encode())
    add(R("E-09c", ["S6-1"], "negative", "a duplicated kid in the protected header",
          {"form": "jws", "compact": f"{hdr_dup}.{body}.{_b64u(_key('issuer-1').sign((hdr_dup + '.' + body).encode()))}"},
          context(), {"receipt_validity": "INVALID", "refusals.has_code": "JWS_FORM"}))
    raw_bom = b"\xef\xbb\xbf" + text(payload()).encode()
    add(R("E-09d", ["S8-1"], "negative", "a byte order mark before the payload",
          {"form": "json", "b64u": _b64u(raw_bom)}, context(inter_domain=False),
          {"receipt_validity": "INVALID", "refusals.has_code": "STRICT_DECODING"}))
    add(R("E-09e", ["S8-1"], "negative", "the payload in UTF-16",
          {"form": "json", "b64u": _b64u(text(payload()).encode("utf-16"))}, context(inter_domain=False),
          {"receipt_validity": "INVALID", "refusals.has_code": "STRICT_DECODING"}))
    add(R("E-09f", ["S8-1"], "negative", "NaN in the payload",
          {"form": "json", "text": text(payload()).replace('"blocking_contradictions": []',
                                                            '"blocking_contradictions": NaN')},
          context(inter_domain=False), {"receipt_validity": "INVALID", "refusals.has_code": "STRICT_DECODING"}))
    add(R("E-09g", ["S8-1"], "negative", "bytes after the JSON value",
          {"form": "json", "text": text(payload()) + "\n{}"}, context(inter_domain=False),
          {"receipt_validity": "INVALID", "refusals.has_code": "STRICT_DECODING"}))
    add(R("E-10", ["S5.1-1"], "negative", "evaluation.status in upper case",
          jws_receipt(payload(evaluation={"status": "PASS", "requirements_satisfied": True,
                                          "blocking_contradictions": []})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "STATUS_UNKNOWN"}))
    add(R("E-10b", ["S5.1-1"], "negative", "evaluation.status outside the three values",
          jws_receipt(payload(evaluation={"status": "ok", "requirements_satisfied": True,
                                          "blocking_contradictions": []})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "STATUS_UNKNOWN"}))
    add(R("E-11", ["S5.1-4"], "negative", "pass while requirements_satisfied is false",
          jws_receipt(payload(evaluation={"status": "pass", "requirements_satisfied": False,
                                          "blocking_contradictions": []})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "EVALUATION_INCONSISTENT"}))
    add(R("E-11b", ["S5.1-4"], "negative", "pass with one unresolved blocking contradiction (as a count)",
          jws_receipt(payload(evaluation={"status": "pass", "requirements_satisfied": True,
                                          "blocking_contradictions": 1})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "EVALUATION_INCONSISTENT"}))
    add(R("E-11c", ["S5.1-2"], "negative", "fail while requirements_satisfied is true",
          jws_receipt(payload(evaluation={"status": "fail", "requirements_satisfied": True,
                                          "blocking_contradictions": []})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "EVALUATION_INCONSISTENT"}))
    add(R("E-11d", ["S5.1-3"], "negative", "indeterminate while requirements_satisfied is true",
          jws_receipt(payload(evaluation={"status": "indeterminate", "requirements_satisfied": True,
                                          "blocking_contradictions": []})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "EVALUATION_INCONSISTENT"}))
    add(R("E-12", ["S15-3"], "negative", "a profile digest that does not match the accepted profile bytes",
          jws_receipt(payload(profile={"id": PROFILE_ID, "hash_alg": "sha-256",
                                       "digest": sha256_b64u(jcs({**PROFILE_JSON, "stale": "pass"}))})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "PROFILE_DIGEST_MISMATCH"}))
    add(R("E-12b", ["S15-3", "S15-1"], "negative", "a profile the verifier does not accept",
          jws_receipt(payload(profile={"id": "https://example.org/profiles/anything-goes/v1", "hash_alg": "sha-256",
                                       "digest": sha256_b64u(b"anything goes")})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "PROFILE_NOT_ACCEPTED"}))
    add(R("E-13", ["S15-1", "S7-1"], "negative", "a PASS for another proposition offered for this action",
          jws_receipt(payload(claim={"id": "urn:example:claim:invoice-8472-overdue", "hash_alg": "sha-256",
                                     "digest": sha256_b64u(jcs(OTHER_PROPOSITION))})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "CLAIM_DIGEST_MISMATCH"}))
    add(R("E-13b", ["S15-1"], "negative", "the right proposition digest under another claim id",
          jws_receipt(payload(claim={"id": "urn:example:claim:invoice-8473-overdue", "hash_alg": "sha-256",
                                     "digest": sha256_b64u(jcs(PROPOSITION))})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "CLAIM_ID_MISMATCH"}))
    add(R("E-13c", ["S7-1", "S8-1"], "negative", "a receipt without a claim binding",
          jws_receipt(payload(claim=None)), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "MISSING_MEMBER"}))
    add(R("E-14", ["S15-1"], "negative", "a PASS bound to another action",
          jws_receipt(payload(action_digest=sha256_b64u(jcs(OTHER_ACTION)))), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "ACTION_DIGEST_MISMATCH"}))
    add(R("E-14b", ["S5-4"], "negative", "a high-consequence policy and a receipt without action_digest",
          jws_receipt(payload(action_digest=None)), context(high_consequence=True),
          {"receipt_validity": "INVALID", "refusals.has_code": "ACTION_BINDING_MISSING"}))
    add(R("E-14c", ["S5-4", "S8-1"], "positive", "no action_digest where local policy does not require one",
          jws_receipt(payload(action_digest=None)), context(), QUALIFIES))
    add(R("E-14d", ["S8-1"], "negative", "local policy requires a context binding the receipt lacks",
          jws_receipt(payload(context_digest=None)), context(require_context_binding=True),
          {"receipt_validity": "INVALID", "refusals.has_code": "CONTEXT_BINDING_MISSING"}))
    add(R("E-15", ["S8-1"], "negative", "verified after expires_at",
          jws_receipt(), context(now="2026-09-13T00:05:00Z"),
          {"receipt_validity": "INVALID", "refusals.has_code": "EXPIRED"}))
    add(R("E-15b", ["S8-1"], "negative", "verified before issued_at",
          jws_receipt(), context(now="2026-09-12T23:49:59Z"),
          {"receipt_validity": "INVALID", "refusals.has_code": "NOT_YET_VALID"}))
    add(R("E-15c", ["S5-3"], "negative", "expires_at before issued_at",
          jws_receipt(payload(expires_at="2026-09-12T23:40:00Z")), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "VALIDITY_INTERVAL_EMPTY"}))
    add(R("E-15d", ["S15-2"], "negative", "a validity interval longer than the local bound",
          jws_receipt(payload(expires_at="2026-09-14T23:50:00Z")), context(max_validity_seconds=900),
          {"receipt_validity": "INVALID", "refusals.has_code": "VALIDITY_TOO_LONG"}))
    add(R("E-16", ["S15-2"], "negative", "a nonce other than the expected one",
          jws_receipt(payload(nonce="replayed-nonce")), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "NONCE_MISMATCH"}))
    add(R("E-16b", ["S15-2"], "negative", "an expected nonce the receipt does not carry",
          jws_receipt(payload(nonce=None)), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "NONCE_MISSING"}))
    add(R("E-16c", ["S8-1"], "positive", "a nonce where local policy expects none is kept as a note",
          jws_receipt(), context(expected_nonce=None), {**QUALIFIES, "notes.has_code": "NONCE_NOT_CHECKED"}))
    add(R("E-17", ["S5-3"], "negative", "a timestamp with a space instead of T",
          jws_receipt(payload(issued_at="2026-09-12 23:50:00Z")), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "TIME_FORM"}))
    add(R("E-17b", ["S5-3"], "negative", "a timestamp without an offset",
          jws_receipt(payload(expires_at="2026-09-13T00:05:00")), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "TIME_FORM"}))
    add(R("E-17c", ["S5-3"], "positive", "timestamps with a numeric offset",
          jws_receipt(payload(issued_at="2026-09-13T01:50:00+02:00", expires_at="2026-09-13T02:05:00+02:00")),
          context(), QUALIFIES))
    add(R("E-18", ["S5-5"], "negative", "a digest with base64 padding",
          jws_receipt(payload(context_digest=sha256_b64u(jcs(CONTEXT)) + "=")), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "DIGEST_FORM"}))
    add(R("E-18b", ["S5-5"], "negative", "a digest with a character of the standard base64 alphabet",
          jws_receipt(payload(evidence=[{"class": "signed_invoice_record", "hash_alg": "sha-256",
                                         "digest": "+" + EVIDENCE_DIGEST[1:]}])), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "DIGEST_FORM"}))
    add(R("E-18c", ["S5-5"], "negative", "a digest of the wrong length",
          jws_receipt(payload(action_digest=_b64u(hashlib.sha256(b"x").digest()[:20]))), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "DIGEST_FORM"}))
    add(R("E-18d", ["S5-5"], "negative", "a hash algorithm the reader does not implement",
          jws_receipt(payload(claim={"id": "urn:example:claim:invoice-8472-overdue", "hash_alg": "sha-512",
                                     "digest": sha256_b64u(jcs(PROPOSITION))})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "HASH_ALG_UNSUPPORTED"}))
    noncanon = sha256_b64u(json.dumps(PROPOSITION).encode())
    add(R("E-19", ["S5-1"], "negative", "a proposition digest over a non-canonical JSON serialization",
          jws_receipt(payload(claim={"id": "urn:example:claim:invoice-8472-overdue", "hash_alg": "sha-256",
                                     "digest": noncanon})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "CLAIM_DIGEST_MISMATCH"}))
    text_prop = "invoice 8472 is overdue"
    add(R("E-19b", ["S5-1", "S8-1"], "positive", "a non-JSON proposition hashed as its exact UTF-8 bytes",
          jws_receipt(payload(claim={"id": "urn:example:claim:invoice-8472-overdue", "hash_alg": "sha-256",
                                     "digest": sha256_b64u(text_prop.encode())})),
          context(proposition={"claim_id": "urn:example:claim:invoice-8472-overdue", "text": text_prop}), QUALIFIES))
    add(R("E-20", ["S5.1-5"], "negative", "PASS under a profile with an empty required-condition set",
          jws_receipt(payload(profile={"id": EMPTY_PROFILE_ID, "hash_alg": "sha-256",
                                       "digest": sha256_b64u(jcs(EMPTY_PROFILE_JSON))})), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "EMPTY_REQUIRED_SET_PASS"}))
    add(R("E-20b", ["S5.1-5"], "positive", "INDETERMINATE under that profile is no PASS and stays valid",
          jws_receipt(payload(profile={"id": EMPTY_PROFILE_ID, "hash_alg": "sha-256",
                                       "digest": sha256_b64u(jcs(EMPTY_PROFILE_JSON))},
                              evaluation={"status": "indeterminate", "requirements_satisfied": False,
                                          "blocking_contradictions": 0})), context(),
          {"receipt_validity": "VALID", "evaluation_status": "indeterminate", "qualification.qualifies": False}))
    add(R("E-20c", ["S5.1-5"], "negative", "PASS without a single evidence descriptor does not qualify",
          jws_receipt(payload(evidence=[])), context(),
          {"receipt_validity": "VALID", "qualification.qualifies": False, "policy.has_code": "PASS_WITHOUT_EVIDENCE"}))
    add(R("E-21", ["S8-1"], "negative", "an evidence class local policy does not accept for the profile",
          jws_receipt(payload(evidence=[{"class": "model_summary", "hash_alg": "sha-256",
                                         "digest": EVIDENCE_DIGEST}])), context(),
          {"receipt_validity": "VALID", "qualification.qualifies": False,
           "policy.has_code": "EVIDENCE_CLASS_NOT_ACCEPTED"}))
    add(R("E-21b", ["S15-2"], "negative", "an evidence descriptor stale at verification time",
          jws_receipt(payload(evidence=[{"class": "signed_invoice_record", "hash_alg": "sha-256",
                                         "digest": EVIDENCE_DIGEST, "fresh_until": "2026-09-12T23:52:00Z"}])),
          context(), {"receipt_validity": "VALID", "qualification.qualifies": False, "policy.has_code": "EVIDENCE_STALE"}))
    other_profile_ctx = context()
    other_profile_ctx["trust"]["issuers"][OTHER_ISSUER]["profiles"] = []
    add(R("E-21c", ["S15-1"], "negative", "a trusted issuer that local policy does not accept for this profile",
          jws_receipt(payload(issuer=OTHER_ISSUER), label="issuer-9", kid="k9"), other_profile_ctx,
          {"receipt_validity": "VALID", "qualification.qualifies": False,
           "policy.has_code": "ISSUER_NOT_ACCEPTED_FOR_PROFILE"}))
    add(R("E-22", ["S3-1"], "negative", "a receipt member that claims an authorization is never read as one",
          jws_receipt(payload(authorization="ALLOW", evaluation={"status": "indeterminate",
                                                                 "requirements_satisfied": False,
                                                                 "blocking_contradictions": 0})), context(),
          {"receipt_validity": "VALID", "qualification.qualifies": False,
           "authorization": "not decided here: an EQR is one input to a separate authorization decision "
                            "(Sections 3 and 9)", "notes.has_code": "MEMBERS_NOT_INTERPRETED"}))
    add(R("E-23", ["S8-1"], "negative", "version as a number",
          jws_receipt(payload(version=1)), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "VERSION_UNSUPPORTED"}))
    add(R("E-23b", ["S8-1"], "negative", "a receipt_id that is no URI",
          jws_receipt(payload(receipt_id="6ac9f8f0 30e1")), context(),
          {"receipt_validity": "INVALID", "refusals.has_code": "URI_FORM"}))
    add(R("E-24", ["S8-1"], "negative", "no proposition in the local context: the receipt cannot be bound",
          jws_receipt(), context(proposition=None),
          {"receipt_validity": "UNVERIFIABLE", "unverifiable.has_code": "PROPOSITION_NOT_SUPPLIED",
           "qualification.qualifies": False}))
    add(R("E-25", ["S8-1"], "positive", "a policy that requires no PASS EQR: the evaluation is exposed, no "
                                        "qualification is claimed",
          jws_receipt(), context(policy_requires_pass=False),
          {"receipt_validity": "VALID", "evaluation_status": "pass", "qualification.qualifies": None}))
    return out


def jws_receipt_raw(body_text: str):
    return {"form": "jws", "compact": sign(body_text)}


def set_vectors():
    out = []
    v1 = payload(receipt_id="urn:example:eqr:v1",
                 evaluation={"status": "indeterminate", "requirements_satisfied": False, "blocking_contradictions": 0})
    v2 = payload(receipt_id="urn:example:eqr:v2", supersedes="urn:example:eqr:v1")
    out.append(V("H-01", "set", ["S10-2", "S10-3", "S10-1", "S7-4"], "positive",
                 "v1 INDETERMINATE, then v2 PASS superseding it: v1 is kept as history, v2 qualifies",
                 {"receipts": [jws_receipt(v1), jws_receipt(v2)], "context": context()},
                 {"r0.receipt_validity": "VALID", "r0.superseded_by": ["urn:example:eqr:v2"],
                  "r0.qualification.qualifies": False, "r1.qualification.qualifies": True,
                  "history.retained": ["urn:example:eqr:v1", "urn:example:eqr:v2"], "history.findings": []}))
    m1 = payload(receipt_id="urn:example:eqr:m",
                 evaluation={"status": "indeterminate", "requirements_satisfied": False, "blocking_contradictions": 0})
    m2 = payload(receipt_id="urn:example:eqr:m")
    out.append(V("H-02", "set", ["S10-1", "S7-4"], "negative",
                 "one receipt id first INDETERMINATE, then PASS: a mutation, neither qualifies",
                 {"receipts": [jws_receipt(m1), jws_receipt(m2)], "context": context()},
                 {"history.has_code": "RECEIPT_MUTATED", "r0.qualification.qualifies": False,
                  "r1.qualification.qualifies": False}))
    p1 = payload(receipt_id="urn:example:eqr:p1")
    p2 = payload(receipt_id="urn:example:eqr:p2", supersedes="urn:example:eqr:p1",
                 evaluation={"status": "fail", "requirements_satisfied": False, "blocking_contradictions": [CONTRA_DIGEST]})
    out.append(V("H-03", "set", ["S10-3"], "negative",
                 "a PASS superseded by a FAIL after new evidence: the PASS stays valid history and no longer qualifies",
                 {"receipts": [jws_receipt(p1), jws_receipt(p2)], "context": context()},
                 {"r0.receipt_validity": "VALID", "r0.evaluation_status": "pass", "r0.qualification.qualifies": False,
                  "r1.evaluation_status": "fail", "history.retained": ["urn:example:eqr:p1", "urn:example:eqr:p2"]}))
    a = payload(receipt_id="urn:example:eqr:a", supersedes="urn:example:eqr:b")
    b = payload(receipt_id="urn:example:eqr:b", supersedes="urn:example:eqr:a")
    out.append(V("H-04", "set", ["S10-2"], "negative", "two receipts that supersede each other",
                 {"receipts": [jws_receipt(a), jws_receipt(b)], "context": context()},
                 {"history.has_code": "SUPERSESSION_CYCLE", "r0.qualification.qualifies": False,
                  "r1.qualification.qualifies": False}))
    s = payload(receipt_id="urn:example:eqr:s", supersedes="urn:example:eqr:s")
    out.append(V("H-05", "set", ["S10-2"], "negative", "a receipt that names itself as its predecessor",
                 {"receipts": [jws_receipt(s)], "context": context()},
                 {"r0.receipt_validity": "INVALID", "r0.refusals.has_code": "SELF_SUPERSESSION"}))
    bad = jws_receipt(payload(receipt_id="urn:example:eqr:x2", supersedes="urn:example:eqr:x1"))
    bad["compact"] = bad["compact"][:-4] + ("AAAA" if not bad["compact"].endswith("AAAA") else "BBBB")
    out.append(V("H-06", "set", ["S10-3", "S6-1"], "positive",
                 "an invalid successor does not supersede: its predecessor PASS still qualifies",
                 {"receipts": [jws_receipt(payload(receipt_id="urn:example:eqr:x1")), bad], "context": context()},
                 {"r0.qualification.qualifies": True, "r1.receipt_validity": "INVALID"}))
    out.append(V("H-07", "set", ["S10-3"], "positive", "a successor whose predecessor is not presented keeps qualifying",
                 {"receipts": [jws_receipt(payload(receipt_id="urn:example:eqr:y2", supersedes="urn:example:eqr:y1"))],
                  "context": context()},
                 {"history.has_code": "PREDECESSOR_NOT_PRESENTED", "r0.qualification.qualifies": True}))
    return out


def all_vectors():
    return verify_vectors() + set_vectors()


def requirement_polarity(vec):
    out = []
    for r in vec["requirements"]:
        if r[0] in "+-":
            out.append((r[1:], "positive" if r[0] == "+" else "negative"))
        else:
            out.append((r, vec["polarity"]))
    return out


def snapshot_context():
    return copy.deepcopy(context())
