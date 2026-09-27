"""The inputs of ToBeSigned in tools/scitt_ccf_datahash_vector, and the two counter-probes on them.

A reviewer on the list asked whether a statement identifier built from ToBeSigned can be computed
from the stored statement alone. Two inputs decide that: external_aad is never in a COSE_Sign1, and
a detached payload is nil in the envelope. These cases bind what the recomputation reports about
both. They are hermetic: the committed D vector for the real cases, and a key generated inside the
test for the probe logic, never the upstream seed.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "scitt_ccf_datahash_vector"


def _load():
    spec = importlib.util.spec_from_file_location("_nachrechnen_tbs_under_test", TOOL / "nachrechnen.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


N = _load()
PROTECTED = b"\xa1\x01\x27"                      # {1: -8}, EdDSA


def _committed_cases() -> dict[str, bytes]:
    d = bytes.fromhex(json.loads((TOOL / "vektor_d.json").read_text(encoding="utf-8"))
                      ["D_indefinite_array"]["hex"])
    a = b"\xd2\x84" + d[2:-1]
    return {"A": a, "C": a[1:], "D": d}


def _bstr(b: bytes) -> bytes:
    return N.C.kopf_bytes(2, len(b)) + b


def _signed(payload: bytes, aad: bytes = b"") -> tuple[bytes, str]:
    """A tagged COSE_Sign1 signed over its Sig_structure with the given external_aad."""
    key = Ed25519PrivateKey.generate()
    sig = key.sign(N.sig_structure(PROTECTED, payload, aad))
    raw = b"\xd2\x84" + _bstr(PROTECTED) + b"\xa0" + _bstr(payload) + _bstr(sig)
    return raw, key.public_key().public_bytes_raw().hex()


def test_the_committed_cases_carry_the_same_embedded_payload_and_no_external_aad():
    rows = {k: N.tobesigned_inputs(b) for k, b in _committed_cases().items()}
    assert {r["payload_embedded"] for r in rows.values()} == {True}
    assert {r["payload_type"] for r in rows.values()} == {"bstr"}
    assert {r["payload_length"] for r in rows.values()} == {59}
    assert len({r["payload_sha256"] for r in rows.values()}) == 1
    assert {r["external_aad_length"] for r in rows.values()} == {0}


def test_a_non_empty_external_aad_breaks_verification():
    raw, pub = _signed(b"statement")
    probe = N.external_aad_probe(raw, pub)
    assert probe["verifies_with_empty_external_aad"] is True
    assert probe["verifies_with_this_external_aad"] is False
    assert probe["caught"] is True


def test_CONTROL_an_envelope_signed_with_that_aad_is_not_reported_as_caught():
    """The counter-direction: signed WITH external_aad 00, it verifies only with it."""
    raw, pub = _signed(b"statement", aad=b"\x00")
    probe = N.external_aad_probe(raw, pub)
    assert probe["verifies_with_empty_external_aad"] is False
    assert probe["verifies_with_this_external_aad"] is True
    assert probe["caught"] is False


def test_an_empty_external_aad_is_no_probe():
    raw, pub = _signed(b"statement")
    with pytest.raises(ValueError, match="non-empty"):
        N.external_aad_probe(raw, pub, aad=b"")


def test_a_detached_envelope_needs_its_payload_supplied():
    payload = b"statement"
    raw, pub = _signed(payload)
    probe = N.detached_probe(raw, pub)
    assert probe["payload_in_envelope"] == "nil"
    assert probe["sig_structure_from_envelope_alone"].startswith("not formable")
    assert probe["equals_sig_structure_of_the_embedded_envelope"] is True
    assert probe["verifies_with_supplied_payload"] is True
    assert probe["caught"] is True
    assert probe["size_bytes"] == len(raw) - len(_bstr(payload)) + 1


def test_detach_splices_by_structure_also_for_an_indefinite_outer_array():
    """The payload bytes appear elsewhere in the envelope too; a search would cut the wrong span."""
    d = _committed_cases()["D"]
    payload = N.zerlege(d)["payload"]
    det = N.detach(d)
    t = N.zerlege(det)
    assert t["payload"] is None and t["aeusseres_array_indefinit"] is True
    assert det[-1:] == b"\xff" and len(det) == len(d) - len(_bstr(payload)) + 1
    raw, _pub = _signed(PROTECTED)                 # payload equal to the protected header bytes
    assert N.zerlege(N.detach(raw))["protected"] == PROTECTED


def test_an_already_detached_envelope_is_no_probe():
    raw, pub = _signed(b"statement")
    with pytest.raises(ValueError, match="embedded payload"):
        N.detached_probe(N.detach(raw), pub)


def test_a_taken_over_signature_is_evidenced_by_verification_only():
    raw, pub = _signed(b"statement")
    with pytest.raises(ValueError, match="public key"):
        N.pruefe("x", raw.hex(), len(raw), hashlib.sha256(raw).hexdigest(), "00" * 32, None,
                 evidence="taken_over")
    row = N.pruefe("x", raw.hex(), len(raw), hashlib.sha256(raw).hexdigest(), "00" * 32, pub,
                   evidence="taken_over")
    assert row["signatur_aus_seed_reproduziert"] is None
    assert row["signature_ok"] is True and "taken over" in row["signature_evidence"]


def test_the_exit_code_follows_both_probes():
    row = {"size_trifft": True, "sha256_trifft": True, "signature_ok": True}
    good, bad = {"caught": True}, {"caught": False}
    assert N.exit_code([row], {"all_identical": True}, good, good, good) == 0
    assert N.exit_code([row], {"all_identical": True}, good, bad, good) == 1
    assert N.exit_code([row], {"all_identical": True}, good, good, bad) == 1
    assert N.exit_code([{**row, "signature_ok": False}], {"all_identical": True}, good, good, good) == 1


def test_the_recorded_run_names_d_as_taken_over_and_both_probes_as_caught():
    """The committed record is the run's output; it must say what the code measures, per case."""
    rec = json.loads((TOOL / "nachrechnung.json").read_text(encoding="utf-8"))
    inputs = rec["tobesigned_inputs"]
    assert sorted(inputs) == ["A", "B", "C", "D"]
    assert all("reproduced" in inputs[k]["signature_evidence"] for k in "ABC")
    assert "taken over" in inputs["D"]["signature_evidence"]
    assert {v["external_aad_length"] for v in inputs.values()} == {0}
    assert rec["external_aad_probe_on_A"]["caught"] is True
    assert rec["A_detached"]["caught"] is True
    assert rec["A_detached"]["payload_in_envelope"] == "nil"
    d_row = [f for f in rec["faelle"] if f["name"].startswith("D ")][0]
    assert d_row["signatur_aus_seed_reproduziert"] is None and d_row["signature_verifies_with_public_key"] is True


def test_a_signature_that_verifies_nowhere_proves_nothing_about_external_aad():
    """Without the control (empty external_aad verifies), "does not verify with 00" says nothing:
    a broken signature fails with every external_aad. The probe must not report that as caught."""
    raw, pub = _signed(b"statement")
    broken = raw[:-1] + bytes([raw[-1] ^ 0x01])            # last signature byte flipped
    probe = N.external_aad_probe(broken, pub)
    assert probe["verifies_with_empty_external_aad"] is False
    assert probe["verifies_with_this_external_aad"] is False
    assert probe["caught"] is False


def test_the_readme_never_calls_d_reproduced():
    """A review lens found the summary sentence above the table read as if D were regenerated."""
    text = (TOOL / "README.md").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("| D ") or " D is " in line or line.startswith("D is"):
            assert "reproduced" not in line or "rather than regenerated" in line, line
    assert "D is not a published state" in text
