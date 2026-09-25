"""Reader matrix: cbor2 and pycose over the four cases A, B, C, D, with a control per library.

WHY THIS FILE EXISTS. The README carried a reader table for A and D only, measured once by hand
in a throwaway venv and not reproducible from this directory. A reviewer measured C with pycose
1.1.0 on 2026-09-25 and got "AttributeError, Message was not tagged"; B was never measured. This
script makes the full table a run instead of a recollection.

WHAT "ACCEPTED" MEANS HERE: the call returned without raising. Nothing more. Whether the
signature verifies is its own column, measured with pycose against the published public key.

A RED CONTROL PROVES NOTHING. Each library first reads back something it wrote itself. If that
fails, the rows of that library are not a finding about the vectors; they are marked
NOT MEASURABLE. This is how the first run on 2026-09-04 was caught: pycose 1.1.0 against cbor2
6.1.4 rejected A and D, and also its own message.

NO KEY IS GENERATED. The control signs with the seed published in the upstream vector.

Needs: the two upstream vectors (run fetch_upstream_vectors.py first), cbor2 and pycose at the
versions named in the README. Prints JSON; reader_matrix.json is the recorded run.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import platform
import sys
from importlib.metadata import version

import cbor2
from pycose.algorithms import EdDSA
from pycose.headers import Algorithm
from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519
from pycose.messages import CoseMessage, Sign1Message

HERE = pathlib.Path(__file__).resolve().parent


def _error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def cases() -> dict[str, bytes]:
    v1 = json.load(open(HERE / "data-hash-vector.json", encoding="utf-8"))
    a = bytes.fromhex(v1["A_signed_statement_as_registered"]["bytes_hex"])
    d = json.load(open(HERE / "vektor_d.json", encoding="utf-8"))["D_indefinite_array"]
    return {"A": a,
            "B": bytes.fromhex(v1["B_same_statement_carrying_a_receipt"]["bytes_hex"]),
            "C": a[1:],
            "D": bytes.fromhex(d["hex"])}


def keys() -> tuple[bytes, bytes]:
    v1 = json.load(open(HERE / "data-hash-vector.json", encoding="utf-8"))
    return bytes.fromhex(v1["test_key"]["seed_hex"]), bytes.fromhex(v1["test_key"]["public_key_hex"])


def cbor2_row(raw: bytes, a_sha: str) -> dict:
    try:
        value = cbor2.loads(raw)
    except Exception as exc:  # noqa: BLE001 — the error text IS the measurement
        return {"accepted": False, "error": _error(exc)}
    row = {"accepted": True, "top_level": type(value).__name__,
           "tag": getattr(value, "tag", None)}
    for label, kwargs in (("reencode_default", {}), ("reencode_canonical", {"canonical": True})):
        out = cbor2.dumps(value, **kwargs)
        row[label] = {"size": len(out), "sha256": hashlib.sha256(out).hexdigest(),
                      "equals_input": out == raw,
                      "equals_A": hashlib.sha256(out).hexdigest() == a_sha}
    return row


def pycose_row(raw: bytes, public: bytes, a_sha: str) -> dict:
    row = {}
    for call, fn in (("CoseMessage.decode", CoseMessage.decode),
                     ("Sign1Message.decode", Sign1Message.decode)):
        try:
            msg = fn(raw)
        except Exception as exc:  # noqa: BLE001 — the error text IS the measurement
            row[call] = {"accepted": False, "error": _error(exc)}
            continue
        entry = {"accepted": True, "type": type(msg).__name__}
        try:
            msg.key = OKPKey(crv=Ed25519, x=public)
            entry["verify_signature"] = bool(msg.verify_signature())
        except Exception as exc:  # noqa: BLE001
            entry["verify_signature"] = _error(exc)
        try:
            out = msg.encode(tag=True, sign=False)
            entry["reencode"] = {"size": len(out), "sha256": hashlib.sha256(out).hexdigest(),
                                 "equals_input": out == raw,
                                 "equals_A": hashlib.sha256(out).hexdigest() == a_sha}
        except Exception as exc:  # noqa: BLE001
            entry["reencode"] = _error(exc)
        row[call] = entry
    return row


def controls(seed: bytes, public: bytes) -> dict:
    out = {}
    try:
        own = cbor2.dumps(cbor2.CBORTag(18, [b"\xa1\x01\x27", {}, b"control", b"\x00" * 64]))
        back = cbor2.loads(own)
        out["cbor2_reads_its_own_output"] = (isinstance(back, cbor2.CBORTag) and back.tag == 18
                                             and cbor2.dumps(back) == own)
    except Exception as exc:  # noqa: BLE001
        out["cbor2_reads_its_own_output"] = _error(exc)
    try:
        key = OKPKey(crv=Ed25519, d=seed, x=public)
        msg = Sign1Message(phdr={Algorithm: EdDSA}, payload=b"control")
        msg.key = key
        own = msg.encode()
        back = CoseMessage.decode(own)
        back.key = OKPKey(crv=Ed25519, x=public)
        out["pycose_reads_and_verifies_its_own_message"] = bool(back.verify_signature())
        out["pycose_own_message_size"] = len(own)
    except Exception as exc:  # noqa: BLE001
        out["pycose_reads_and_verifies_its_own_message"] = _error(exc)
    return out


def main() -> int:
    seed, public = keys()
    raw = cases()
    a_sha = hashlib.sha256(raw["A"]).hexdigest()
    ctl = controls(seed, public)
    cbor2_ok = ctl.get("cbor2_reads_its_own_output") is True
    pycose_ok = ctl.get("pycose_reads_and_verifies_its_own_message") is True
    matrix = {}
    for name, b in raw.items():
        matrix[name] = {
            "size": len(b), "sha256": hashlib.sha256(b).hexdigest(),
            "cbor2": cbor2_row(b, a_sha) if cbor2_ok else "NOT MEASURABLE: cbor2 control failed",
            "pycose": (pycose_row(b, public, a_sha) if pycose_ok
                       else "NOT MEASURABLE: pycose control failed"),
        }
    report = {
        "schema": "b7n0de.scitt_ccf_reader_matrix/0.1",
        "platform": {"system": platform.system(), "machine": platform.machine(),
                     "python": platform.python_version()},
        "versions": {p: version(p) for p in ("cbor2", "pycose", "cryptography")},
        "accepted_means": "the call returned without raising; signature verification is its own field",
        "controls": ctl,
        "cases": matrix,
    }
    print(json.dumps(report, indent=2))
    return 0 if cbor2_ok and pycose_ok else 2


if __name__ == "__main__":
    sys.exit(main())
