#!/usr/bin/env python3
"""Hold cbor2 and pycose against the same real statements, and record what each version does.

WHY. ADR 0009 names cbor2 as the CBOR library of the optional extra and pycose as a comparison
in tests only. Both choices depend on version facts, and a version fact is only worth the
environment it was measured in. This script is run once per environment; each run adds one
entry, keyed by the cbor2 version, to reader_crosscheck.json.

WHAT IS MEASURED, per environment:

  * the decoder options this cbor2 has (allow_duplicate_keys, allow_indefinite, max_depth) and
    what each does on a one-line probe, including the default
  * whether cbor2.loads ignores trailing bytes, and whether CBORDecoder can report where the
    first item ended
  * the Python type cbor2 returns for the content of tag 18 and for a map inside it
  * for each real statement: the data-hash recomputed from cbor2's decoded values with the
    rule measured by recompute.py (tag 18, unprotected header emptied, other three elements
    re-encoded by cbor2), held against the data-hash in the receipt
  * pycose: whether it reads back a message it wrote itself (the control), and whether it
    decodes and verifies the real statements' receipts. A failed control marks the pycose
    rows NOT MEASURABLE instead of reporting them.

Needs cbor2 and cryptography; pycose is optional. Reads ./fetched (fetch_external.py).
"""
from __future__ import annotations

import hashlib
import importlib.metadata as md
import inspect
import io
import json
import platform
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FETCHED = HERE / "fetched"
OUT = HERE / "reader_crosscheck.json"
STATEMENTS = ("transparent-statement.cose", "cbor-header.cose", "nested-sign1.cose")


def _version(dist: str):
    try:
        return md.version(dist)
    except md.PackageNotFoundError:
        return None


def _try(fn):
    try:
        return {"outcome": "returned", "value": repr(fn())[:120]}
    except TypeError as exc:
        return {"outcome": "TypeError", "detail": str(exc)[:160]}
    except Exception as exc:  # noqa: BLE001 - the exception type IS the measurement
        return {"outcome": type(exc).__name__, "detail": str(exc)[:160]}


def cbor2_facts(cbor2) -> dict:
    dup = bytes.fromhex("a201010102")                 # {1: 1, 1: 2}
    indef = bytes.fromhex("9f0102ff")                 # [_ 1, 2]
    deep = b"\x81" * 20 + b"\x00"                     # 20 nested arrays
    try:
        sig = str(inspect.signature(cbor2.loads))
    except (TypeError, ValueError):
        sig = "not introspectable"
    fp = io.BytesIO(b"\x01\x02")
    first = cbor2.CBORDecoder(fp).decode()
    tagged = cbor2.loads(bytes.fromhex("d28443a10126a1182a00f640"))

    def refuse(*_a, **_k):
        raise ValueError("tag refused")
    tags = {                                          # what a tag turns into by default
        "tag 1 epoch time": "c11a5f5e1000",
        "tag 2 bignum": "c24101",
        "tag 24 embedded CBOR": "d81841f6",
        "tags 28/29 shared reference": "82d81c8101d81d00",
        "tags 256/25 string reference": "d901008243616263d81900",
        "tag 55799 self-describe": "d9d9f701",
        "tag 99999 unregistered": "da0001869f01",
    }
    return {
        "default_tag_handling": {k: _try(lambda h=h: cbor2.loads(bytes.fromhex(h)))
                                 for k, h in tags.items()},
        "tag_hook_called_for_tag_2": _try(lambda: cbor2.loads(bytes.fromhex("c24101"),
                                                              tag_hook=refuse)),
        "tag_hook_called_for_tag_99999": _try(lambda: cbor2.loads(bytes.fromhex("da0001869f01"),
                                                                  tag_hook=refuse)),
        "semantic_decoders_refuses_tag_2": _try(lambda: cbor2.loads(
            bytes.fromhex("c24101"), semantic_decoders={2: refuse})),
        "loads_signature": sig,
        "duplicate_key_default": _try(lambda: cbor2.loads(dup)),
        "duplicate_key_rejected_on_request": _try(lambda: cbor2.loads(dup, allow_duplicate_keys=False)),
        "indefinite_default": _try(lambda: cbor2.loads(indef)),
        "indefinite_rejected_on_request": _try(lambda: cbor2.loads(indef, allow_indefinite=False)),
        "max_depth_16_on_depth_20": _try(lambda: cbor2.loads(deep, max_depth=16)),
        "trailing_byte_after_item": _try(lambda: cbor2.loads(b"\x01\x02")),
        "decoder_position_after_first_item": {"value": first, "tell": fp.tell(), "input": 2},
        "non_shortest_head_0x1801": _try(lambda: cbor2.loads(bytes.fromhex("1801"))),
        "type_of_tag18_content": type(tagged.value).__name__,
        "type_of_map_inside_tag18": type(tagged.value[1]).__name__,
    }


def datahash_via_cbor2(cbor2, raw: bytes) -> dict:
    kw = {}
    try:
        cbor2.loads(b"\x00", allow_duplicate_keys=False, allow_indefinite=False)
        kw = {"allow_duplicate_keys": False, "allow_indefinite": False}
    except TypeError:
        pass
    t = cbor2.loads(raw, max_depth=16, **kw)
    prot, _unprot, payload, sig = t.value
    rebuilt = cbor2.dumps(cbor2.CBORTag(18, [prot, {}, payload, sig]))
    rec = t.value[1][394][0]
    r = cbor2.loads(rec, max_depth=16, **kw)
    proof = cbor2.loads(r.value[1][396][-1][0], max_depth=16, **kw)
    leaf_dh = proof[1][2]
    return {"strict_options_used": sorted(kw), "rebuilt_length": len(rebuilt),
            "rebuilt_sha256": hashlib.sha256(rebuilt).hexdigest(),
            "receipt_data_hash": leaf_dh.hex(),
            "equal": hashlib.sha256(rebuilt).digest() == leaf_dh}


def pycose_rows(files: dict) -> dict:
    try:
        from pycose.algorithms import EdDSA  # noqa: PLC0415
        from pycose.headers import Algorithm  # noqa: PLC0415
        from pycose.keys import EC2Key, OKPKey  # noqa: PLC0415
        from pycose.messages import CoseMessage, Sign1Message  # noqa: PLC0415
    except ImportError as exc:
        return {"installed": False, "detail": str(exc)}
    out = {"installed": True}
    key = OKPKey.generate_key(crv="ED25519")
    msg = Sign1Message(phdr={Algorithm: EdDSA}, payload=b"control")
    msg.key = key
    enc = msg.encode()

    def control():
        back = Sign1Message.decode(enc)
        back.key = key
        return back.verify_signature()
    out["control_read_back_own_message"] = _try(control)
    if out["control_read_back_own_message"].get("value") != "True":
        out["statements"] = "NOT MEASURABLE: the control failed, so no row below would mean anything"
        return out
    import cbor2  # noqa: PLC0415
    ks = cbor2.loads(files["mst-test-scitt-keys.cbor"])[0]
    rows = {}
    for name in STATEMENTS:
        raw = files[name]
        row = {"decode_statement": _try(lambda raw=raw: CoseMessage.decode(raw))}
        t = cbor2.loads(raw)
        rec = t.value[1][394][0]
        proof = cbor2.loads(cbor2.loads(rec).value[1][396][-1][0])
        itx, ev, dh = proof[1]
        h = hashlib.sha256(itx + hashlib.sha256(ev.encode()).digest() + dh).digest()
        for left, sib in proof[2]:
            h = hashlib.sha256(sib + h if left else h + sib).digest()

        def verify(rec=rec, root=h):
            m = Sign1Message.decode(rec)
            m.payload = root
            m.key = EC2Key(crv="P_384", x=ks[-2], y=ks[-3])
            return m.verify_signature()
        row["receipt_signature_over_recomputed_root"] = _try(verify)
        rows[name] = row
    out["statements"] = rows
    return out


def main() -> int:
    try:
        import cbor2  # noqa: PLC0415
    except ImportError:
        print("NOT MEASURABLE: cbor2 is not installed in this environment.", file=sys.stderr)
        return 2
    files = {p.name: p.read_bytes() for p in FETCHED.glob("*") if p.is_file()}
    missing = [n for n in (*STATEMENTS, "mst-test-scitt-keys.cbor") if n not in files]
    if missing:
        print(f"NOT MEASURABLE: {missing} missing; run fetch_external.py first.", file=sys.stderr)
        return 2
    env = {"python": platform.python_version(), "cbor2": _version("cbor2"),
           "pycose": _version("pycose"), "cryptography": _version("cryptography")}
    entry = {"environment": env, "cbor2": cbor2_facts(cbor2),
             "datahash_via_cbor2": {n: datahash_via_cbor2(cbor2, files[n]) for n in STATEMENTS},
             "pycose": pycose_rows(files)}
    doc = json.loads(OUT.read_text(encoding="utf-8")) if OUT.is_file() else {}
    doc.setdefault("tool", "tools/scitt_ccf_external/reader_crosscheck.py")
    doc.setdefault("runs", {})[f"cbor2-{env['cbor2']}"] = entry
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(json.dumps(entry, indent=1)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
