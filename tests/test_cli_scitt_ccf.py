"""The scitt-ccf command line: each exit code of both subcommands, reached by real ledger bytes (6.6.0).

WHAT IS HELD. `proofbundle scitt-ccf verify-statement` and `proofbundle scitt-ccf verify-consistency` run the
scitt-ccf/v1 reader of ADR 0009 with trust from their options only: the issuer, the service's COSE_KeySet, the
statement signer's SubjectPublicKeyInfo and the digest or older root. Each exit code is reached here by an input
that produces it: 0 confirmed, 1 a verdict against what was given, 2 an input or trust option that cannot be used
or the [scitt] extra missing, 3 needs_rp_trust. The REAL bytes are the committed vectors of a local
scitt-ccf-ledger run, tests/fixtures/scitt_ccf/local_ledger_control.json and local_ledger_consistency.json.

THE TABLES ARE HELD TO THE LIBRARY. The command maps each status of the reader to an exit code through
`cli._SCITT_STATEMENT_EXIT` and `cli._SCITT_CONSISTENCY_EXIT`. Both are held equal to the library's set of statuses,
so a status the reader adds without an exit code fails here instead of reaching a caller as exit 2.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from proofbundle import cli
from proofbundle import scitt_ccf as S

READER = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                            reason="the scitt-ccf reader needs the [scitt] extra")
FIX = Path(__file__).resolve().parent / "fixtures" / "scitt_ccf"
CONTROL = json.loads((FIX / "local_ledger_control.json").read_text(encoding="utf-8"))
CONSISTENCY = json.loads((FIX / "local_ledger_consistency.json").read_text(encoding="utf-8"))


def _run(argv) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _other_p384_spki() -> bytes:
    return ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _other_keyset() -> bytes:
    """A COSE_KeySet with one P-384 key that is not the service's, its kid derived as CCF derives it."""
    import cbor2  # noqa: PLC0415
    key = ec.generate_private_key(ec.SECP384R1()).public_key()
    nums = key.public_numbers()
    return cbor2.dumps([{1: 2, -1: 2, -2: nums.x.to_bytes(48, "big"), -3: nums.y.to_bytes(48, "big"),
                         2: S._derived_kid(key.public_bytes(serialization.Encoding.DER,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo))}])


def _statement_argv(tmp_path: Path, *, digest=None, issuer=None, keyset=None, spki=None, statement=None,
                    json_out=True) -> list:
    v = CONTROL
    argv = ["scitt-ccf", "verify-statement",
            _write(tmp_path, "ts.cose", base64.b64decode(v["transparent_statement_b64"]) if statement is None
                   else statement),
            "--expected-digest", v["canonical_root_hex"] if digest is None else digest,
            "--issuer", v["issuer"] if issuer is None else issuer,
            "--service-keys", _write(tmp_path, "keys.cbor", base64.b64decode(v["service_keyset_b64"])
                                     if keyset is None else keyset),
            "--statement-key", _write(tmp_path, "signer.der", base64.b64decode(v["statement_signer_spki_b64"])
                                      if spki is None else spki)]
    return argv + (["--json"] if json_out else [])


def _consistency_argv(tmp_path: Path, *, older=None, issuer=None, keyset=None, sizes=None, older_issuer=None,
                      json_out=True) -> list:
    v = CONSISTENCY
    argv = ["scitt-ccf", "verify-consistency",
            _write(tmp_path, "cr.cose", base64.b64decode(v["consistency_receipt_b64"])),
            "--older-root", v["states"]["older"]["root_hex"] if older is None else older,
            "--issuer", v["issuer"] if issuer is None else issuer,
            "--service-keys", _write(tmp_path, "keys.cbor", base64.b64decode(v["service_keyset_b64"])
                                     if keyset is None else keyset)]
    if older_issuer is not None:
        argv += ["--older-issuer", older_issuer]
    if sizes is not None:
        argv += ["--older-size", str(sizes[0]), "--newer-size", str(sizes[1])]
    return argv + (["--json"] if json_out else [])


# ------------------------------------------------------------------------------------------------
# The tables are the library's statuses, each with an exit code
# ------------------------------------------------------------------------------------------------
def test_every_statement_status_has_an_exit_code():
    assert set(cli._SCITT_STATEMENT_EXIT) == set(S.STATUS_ORDER) | {S.CONFIRMED}


def test_every_consistency_status_has_an_exit_code():
    assert set(cli._SCITT_CONSISTENCY_EXIT) == (set(S.CONSISTENCY_STATUS_ORDER)
                                                | {S.CONFIRMED, S.CONFIRMED_WITHOUT_TREE_SIZES})


def test_only_confirmed_is_exit_zero_and_only_needs_rp_trust_is_exit_three():
    for table in (cli._SCITT_STATEMENT_EXIT, cli._SCITT_CONSISTENCY_EXIT):
        assert {s for s, c in table.items() if c == 0} <= {S.CONFIRMED, S.CONFIRMED_WITHOUT_TREE_SIZES}
        assert {s for s, c in table.items() if c == 3} == {"needs_rp_trust"}
        assert {s for s, c in table.items() if c == 2} == {"malformed", "no_lib"}


# ------------------------------------------------------------------------------------------------
# verify-statement, one case per exit code
# ------------------------------------------------------------------------------------------------
@READER
def test_statement_control_is_confirmed_exit_0(tmp_path):
    code, out, _err = _run(_statement_argv(tmp_path))
    doc = json.loads(out)
    assert (code, doc["exit"], doc["ok"], doc["status"], doc["profile_satisfied"]) == (0, 0, True, "confirmed", True)
    assert doc["trust"] == {"issuer": CONTROL["issuer"], "service_keys": 1, "statement_keys": 1}


@READER
def test_statement_control_text_names_the_profile_and_ends_ok(tmp_path):
    code, out, _err = _run(_statement_argv(tmp_path, json_out=False))
    assert code == 0
    assert "STATUS: confirmed" in out and "PROFILE: scitt-cc/v1" not in out
    assert f"PROFILE: {S.PROFILE} satisfied" in out and "=> OK (exit 0)" in out


@READER
def test_statement_for_another_digest_is_unbound_exit_1(tmp_path):
    code, out, _err = _run(_statement_argv(tmp_path, digest="11" * 32))
    doc = json.loads(out)
    assert (code, doc["status"], doc["profile_satisfied"]) == (1, "unbound", False)


@READER
def test_statement_bytes_cut_short_are_malformed_exit_2(tmp_path):
    raw = base64.b64decode(CONTROL["transparent_statement_b64"])
    code, out, _err = _run(_statement_argv(tmp_path, statement=raw[: len(raw) // 2]))
    assert (code, json.loads(out)["status"]) == (2, "malformed")


@READER
def test_statement_key_of_another_signer_is_needs_rp_trust_exit_3(tmp_path):
    code, out, _err = _run(_statement_argv(tmp_path, spki=_other_p384_spki()))
    doc = json.loads(out)
    assert (code, doc["status"], doc["statement_status"]) == (3, "needs_rp_trust", "needs_rp_trust")


@READER
def test_statement_under_another_issuer_name_is_needs_rp_trust_exit_3(tmp_path):
    code, out, _err = _run(_statement_argv(tmp_path, issuer="other.example"))
    doc = json.loads(out)
    assert (code, doc["status"]) == (3, "needs_rp_trust")
    assert [r["status"] for r in doc["receipts"]] == ["needs_rp_trust"]


@READER
def test_service_keys_of_another_service_are_needs_rp_trust_exit_3(tmp_path):
    code, out, _err = _run(_statement_argv(tmp_path, keyset=_other_keyset()))
    assert (code, json.loads(out)["status"]) == (3, "needs_rp_trust")


# ------------------------------------------------------------------------------------------------
# verify-consistency, one case per exit code
# ------------------------------------------------------------------------------------------------
@READER
def test_consistency_without_sizes_is_confirmed_without_tree_sizes_exit_0(tmp_path):
    code, out, _err = _run(_consistency_argv(tmp_path))
    doc = json.loads(out)
    assert (code, doc["status"], doc["signature_valid"], doc["older_root_matches"]) == (
        0, S.CONFIRMED_WITHOUT_TREE_SIZES, True, True)
    assert doc["newer_root"] == CONSISTENCY["states"]["newer"]["root_hex"]


@READER
def test_consistency_without_sizes_says_so_in_the_text(tmp_path):
    code, out, _err = _run(_consistency_argv(tmp_path, json_out=False))
    assert code == 0 and "TREE-SIZES: NOT_CHECKED" in out and "=> OK (exit 0)" in out


@READER
def test_consistency_with_both_sizes_is_confirmed_exit_0(tmp_path):
    m, n = CONSISTENCY["states"]["older"]["tree_size"], CONSISTENCY["states"]["newer"]["tree_size"]
    code, out, _err = _run(_consistency_argv(tmp_path, sizes=(m, n)))
    doc = json.loads(out)
    assert (code, doc["status"], doc["older_size"], doc["newer_size"]) == (0, S.CONFIRMED, m, n)


@READER
def test_consistency_against_the_middle_root_is_a_mismatch_exit_1(tmp_path):
    code, out, _err = _run(_consistency_argv(tmp_path, older=CONSISTENCY["states"]["middle"]["root_hex"]))
    assert (code, json.loads(out)["status"]) == (1, "consistency_older_root_mismatch")


@READER
def test_consistency_with_sizes_in_the_wrong_order_is_exit_1(tmp_path):
    m, n = CONSISTENCY["states"]["older"]["tree_size"], CONSISTENCY["states"]["newer"]["tree_size"]
    code, out, _err = _run(_consistency_argv(tmp_path, sizes=(n, m)))
    assert (code, json.loads(out)["status"]) == (1, "consistency_tree_sizes_invalid")


@READER
def test_consistency_from_another_older_issuer_is_exit_1(tmp_path):
    code, out, _err = _run(_consistency_argv(tmp_path, older_issuer="other.example"))
    assert (code, json.loads(out)["status"]) == (1, "consistency_issuer_mismatch")


@READER
def test_consistency_receipt_cut_short_is_malformed_exit_2(tmp_path):
    argv = _consistency_argv(tmp_path)
    raw = base64.b64decode(CONSISTENCY["consistency_receipt_b64"])
    argv[2] = _write(tmp_path, "cut.cose", raw[:-3])
    code, out, _err = _run(argv)
    assert (code, json.loads(out)["status"]) == (2, "malformed")


@READER
def test_consistency_under_another_service_key_is_needs_rp_trust_exit_3(tmp_path):
    code, out, _err = _run(_consistency_argv(tmp_path, keyset=_other_keyset()))
    assert (code, json.loads(out)["status"]) == (3, "needs_rp_trust")


# ------------------------------------------------------------------------------------------------
# Inputs and trust that cannot be used: exit 2 before any verdict
# ------------------------------------------------------------------------------------------------
@READER
@pytest.mark.parametrize("digest", ["", "ab" * 31, "zz" * 32, "ab " * 32, "ab" * 33])
def test_a_digest_that_is_not_64_hex_digits_is_refused_exit_2(tmp_path, digest):
    code, out, _err = _run(_statement_argv(tmp_path, digest=digest))
    doc = json.loads(out)
    assert (code, doc["exit"], doc["status"]) == (2, 2, "input_refused") and "--expected-digest" in doc["error"]


@READER
def test_the_digest_is_read_with_the_white_space_around_it_stripped(tmp_path):
    code, _out, _err = _run(_statement_argv(tmp_path, digest=f"  {CONTROL['canonical_root_hex'].upper()}\n"))
    assert code == 0


@READER
@pytest.mark.parametrize("what, kw", [
    ("empty issuer", dict(issuer="")),
    ("key set that is not CBOR", dict(keyset=b"not cbor")),
    ("key set without a usable key", dict(keyset=b"\x80")),
    ("statement key that is not DER", dict(spki=b"-----BEGIN PUBLIC KEY-----")),
])
def test_trust_that_cannot_be_used_is_refused_exit_2(tmp_path, what, kw):
    code, out, _err = _run(_statement_argv(tmp_path, **kw))
    doc = json.loads(out)
    assert (code, doc["status"]) == (2, "input_refused"), what


@READER
def test_a_statement_key_of_a_type_v1_does_not_verify_with_is_refused_exit_2(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415
    spki = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    code, out, _err = _run(_statement_argv(tmp_path, spki=spki))
    doc = json.loads(out)
    assert (code, doc["status"]) == (2, "input_refused") and "--statement-key" in doc["error"]


@READER
def test_a_missing_statement_file_is_refused_exit_2_in_text(tmp_path):
    argv = _statement_argv(tmp_path, json_out=False)
    argv[2] = str(tmp_path / "absent.cose")
    code, out, err = _run(argv)
    assert code == 2 and out == "" and err.startswith("ERROR: statement ")


@READER
def test_an_empty_older_issuer_is_refused_exit_2(tmp_path):
    code, out, _err = _run(_consistency_argv(tmp_path, older_issuer=""))
    assert (code, json.loads(out)["status"]) == (2, "input_refused")


def test_without_the_scitt_extra_both_commands_say_no_lib_exit_2(tmp_path, monkeypatch):
    """The reader refuses before it reads a byte (`_scitt_second_reader.library`); the command says why."""
    from proofbundle import _scitt_second_reader as second  # noqa: PLC0415

    def absent():
        raise second.ScittUnavailable("cbor2 is not installed")
    monkeypatch.setattr(second, "library", absent)
    keys = _write(tmp_path, "keys.cbor", b"\x80")
    for argv in (["scitt-ccf", "verify-statement", keys, "--expected-digest", "00" * 32, "--issuer", "s",
                  "--service-keys", keys, "--statement-key", keys, "--json"],
                 ["scitt-ccf", "verify-consistency", keys, "--older-root", "00" * 32, "--issuer", "s",
                  "--service-keys", keys, "--json"]):
        code, out, _err = _run(argv)
        doc = json.loads(out)
        assert (code, doc["status"]) == (2, "no_lib") and "[scitt]" in doc["error"], argv[1]


def test_the_command_is_listed_under_verify_and_marked_experimental():
    lines = dict(z for _t, zeilen in cli._COMMAND_GROUPS for z in zeilen)
    assert "(experimental)" in lines["scitt-ccf"]
    assert any(n == "scitt-ccf" for t, zeilen in cli._COMMAND_GROUPS if t == "Verify" for n, _ in zeilen)
