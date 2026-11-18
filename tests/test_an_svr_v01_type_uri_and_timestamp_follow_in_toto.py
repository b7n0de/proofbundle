"""An SVR v0.1 statement verifies only with `verifier.id` a TypeURI and `timeCreated` a Timestamp as in-toto writes them.

in-toto spec/v1/field_types.md writes a TypeURI with a lower-case scheme and a Timestamp in UTC with the designator Z.
svr v0.1 types `verifier.id` as TypeURI and `timeCreated` as Timestamp. Measured with the second verifier built from
the text (findings M06 and M07): at the head 20f6a993 of the pull request that reads both members in their form, a
validly signed SVR with `verifier.id` "HTTPS://b7n0de.com/proofbundle" and one with `timeCreated`
"2026-10-31T10:00:00+01:00" verified. By the owner's choice of 2026-11-02 the SVR reads both as in-toto does, from 6.6.0.

The cases are built here after the pattern of that corpus, signed with a key made for this module; the corpus itself
carries no licence statement and is not copied. `export_svr_dsse` writes no statement its own verifier refuses, and
every SVR a released version wrote carries the lower-case `https` of VERIFIER_ID and a time with Z.
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

from proofbundle import dsse, generate_signer
from proofbundle import intoto as I
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint

_SIGNER = Ed25519PrivateKey.generate()
_ROOT = "0191e2d1d171c8a2effd253b3d6dbd250cc6d4dfa28ffc18e0a7bf2ad1c95242"
_SALT = b"\x11" * 16

UPPER_SCHEMES = ("HTTPS://b7n0de.com/proofbundle", "Https://b7n0de.com/proofbundle", "hTTps://b7n0de.com/proofbundle",
                 "URN:example:verifier")
OFFSET_TIMES = ("2026-10-31T10:00:00+01:00", "2026-10-31T09:00:00+00:00", "2026-10-31T04:00:00-05:00",
                "2026-10-31T09:00:00.25+00:00")
CONTROL_URIS = ("https://b7n0de.com/proofbundle", "urn:example:verifier", "https://B7N0DE.com/Proofbundle")
CONTROL_TIMES = ("2026-10-31T09:00:00Z", "2026-10-31T09:00:00.25Z", "2026-10-31t09:00:00z")


def _pub() -> bytes:
    return _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(statement: dict) -> dict:
    alg = statement.get("contentRootAlg", I.LEGACY_CONTENT_ROOT_ALG)
    return dsse.sign_envelope(I._serialize_statement(statement, alg), _SIGNER,
                              payload_type=I.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _svr(verifier_id: str = I.VERIFIER_ID, time_created: str = "2026-10-31T09:00:00Z") -> dict:
    """An SVR v0.1 statement in the form `export_svr_dsse` writes, with the two members under test set."""
    return {"_type": I.STATEMENT_TYPE, "contentRootAlg": I.CONTENT_ROOT_ALG,
            "predicate": {"verifier": {"id": verifier_id}, "timeCreated": time_created,
                          "properties": ["PROOFBUNDLE_SIGNATURE_VALID"]},
            "predicateType": I.SVR_PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": _ROOT}, "name": "eval-receipt"}]}


def _verify(statement: dict) -> dict:
    return I.verify_svr_dsse(_sign(statement), _pub())


def _receipt(signer):
    claim, _ = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate", comparator=">=",
        threshold="0.98", score="0.99", n=500, model_id="acme/secret-model", dataset_id="acme/secret-set",
        issuer=issuer_fingerprint(signer), timestamp="2026-07-05T12:00:00Z", model_salt=_SALT, dataset_salt=_SALT)
    return emit_eval_receipt(claim, signer)


@pytest.mark.parametrize("verifier_id", UPPER_SCHEMES)
def test_a_verifier_id_with_an_upper_case_scheme_does_not_verify(verifier_id):
    r = _verify(_svr(verifier_id=verifier_id))
    assert r["signature_ok"] is True, "precondition: the signature itself holds"
    assert r["ok"] is False and r["predicate_shape_ok"] is False, r
    assert "lower-case scheme (TypeURI)" in r["content_root_detail"], r["content_root_detail"]


@pytest.mark.parametrize("time_created", OFFSET_TIMES)
def test_a_time_created_with_a_numeric_offset_does_not_verify(time_created):
    r = _verify(_svr(time_created=time_created))
    assert r["signature_ok"] is True, "precondition: the signature itself holds"
    assert r["ok"] is False and r["predicate_shape_ok"] is False, r
    assert "in UTC with Z (Timestamp)" in r["content_root_detail"], r["content_root_detail"]


@pytest.mark.parametrize("verifier_id", CONTROL_URIS)
def test_control_a_lower_case_scheme_verifies_whatever_the_rest_of_the_uri(verifier_id):
    r = _verify(_svr(verifier_id=verifier_id))
    assert r["ok"] is True and r["predicate_shape_ok"] is True, r


@pytest.mark.parametrize("time_created", CONTROL_TIMES)
def test_control_a_time_in_utc_with_z_verifies(time_created):
    r = _verify(_svr(time_created=time_created))
    assert r["ok"] is True and r["predicate_shape_ok"] is True, r


def test_the_classifier_names_each_member_alone():
    stmt = _svr(verifier_id="HTTPS://b7n0de.com/proofbundle", time_created="2026-10-31T10:00:00+01:00")
    ok, detail = I.classify_svr_predicate_shape(stmt)
    assert ok is False and "verifier.id" in detail, detail
    fixed = copy.deepcopy(stmt)
    fixed["predicate"]["verifier"]["id"] = I.VERIFIER_ID
    ok, detail = I.classify_svr_predicate_shape(fixed)
    assert ok is False and "timeCreated" in detail, detail
    fixed["predicate"]["timeCreated"] = "2026-10-31T09:00:00Z"
    assert I.classify_svr_predicate_shape(fixed) == (True, "")


@pytest.mark.parametrize("time_created", OFFSET_TIMES)
def test_the_export_refuses_a_time_created_its_verifier_refuses(time_created):
    s = generate_signer()
    with pytest.raises(BundleFormatError, match="in UTC with Z"):
        I.export_svr_dsse(_receipt(s), s, time_created=time_created)


def test_control_the_export_with_a_time_in_utc_signs_what_its_verifier_accepts():
    s = generate_signer()
    pub = s.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    for kw in ({}, {"time_created": "2026-07-05T12:34:56Z"}):
        assert I.verify_svr_dsse(I.export_svr_dsse(_receipt(s), s, **kw), pub)["ok"] is True, kw


def test_control_the_verifier_id_the_exporter_writes_is_a_type_uri():
    assert I._is_type_uri(I.VERIFIER_ID) is True
    assert I._is_utc_timestamp(I._now_rfc3339z()) is True


@pytest.mark.parametrize("statement", [_svr(verifier_id=UPPER_SCHEMES[0]), _svr(time_created=OFFSET_TIMES[0])],
                         ids=["upper-case scheme", "numeric offset"])
def test_the_command_answers_such_a_statement_as_malformed(statement):
    from proofbundle.cli import main  # noqa: PLC0415
    with tempfile.TemporaryDirectory() as td:
        env_path = Path(td) / "svr.dsse.json"
        env_path.write_text(json.dumps(_sign(statement)), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["svr", "--verify", "--pub", base64.b64encode(_pub()).decode(), str(env_path)])
    assert rc == 2, (rc, out.getvalue(), err.getvalue())
    assert "PASS" not in out.getvalue(), out.getvalue()
