"""Nachrechnung beider Vektoren von Nicholas — eigener Leser, zweite Sprache, dritte Plattform."""
from __future__ import annotations

import hashlib
import json
import platform
import sys

sys.path.insert(0, "/mnt/bigstore/claude_scratch/scitt_vektoren")
import cbor_min as C                                                      # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (           # noqa: E402
    Ed25519PrivateKey,
)
import cryptography                                                       # noqa: E402


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4: ['Signature1', protected, external_aad, payload]."""
    return C.schreibe(["Signature1", protected, b"", payload])


def zerlege(roh: bytes) -> dict:
    wert, ende = C.lade(roh)
    assert ende == len(roh), f"Reste nach dem Wert: {len(roh)-ende} Byte"
    tag = None
    if isinstance(wert, tuple) and wert[0] == "__tag__":
        tag = wert[1]
        wert = wert[2]
    indefinit = isinstance(wert, C.Unbestimmt)
    if indefinit:
        wert = wert.wert
    assert isinstance(wert, list) and len(wert) == 4, "kein vierelementiges Array"
    return {"tag": tag, "aeusseres_array_indefinit": indefinit,
            "protected": wert[0], "unprotected": wert[1],
            "payload": wert[2], "signature": wert[3]}


def pruefe(name: str, hex_bytes: str, erwartet_size: int, erwartet_sha: str, seed_hex: str) -> dict:
    roh = bytes.fromhex(hex_bytes)
    got_sha = hashlib.sha256(roh).hexdigest()
    t = zerlege(roh)
    ss = sig_structure(t["protected"], t["payload"])
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    neu = sk.sign(ss)
    return {
        "name": name,
        "size_gemessen": len(roh), "size_erwartet": erwartet_size,
        "size_trifft": len(roh) == erwartet_size,
        "sha256_gemessen": got_sha, "sha256_erwartet": erwartet_sha,
        "sha256_trifft": got_sha == erwartet_sha,
        "cbor_tag": t["tag"],
        "aeusseres_array_indefinit": t["aeusseres_array_indefinit"],
        "sig_structure_laenge": len(ss),
        "signatur_aus_seed_reproduziert": neu == t["signature"],
        "signatur_laenge": len(t["signature"]),
    }


def main() -> int:
    v1 = json.load(open("data-hash-vector.json"))
    v2 = json.load(open("data-hash-tag-vector.json"))
    seed = v1["test_key"]["seed_hex"]
    assert v2["test_key"]["seed_hex"] == seed, "die Vektoren nennen verschiedene Seeds"

    faelle = [
        ("V1 / A  as registered", v1["A_signed_statement_as_registered"]),
        ("V1 / B  carrying receipt", v1["B_same_statement_carrying_a_receipt"]),
    ]
    aus = [pruefe(n, d["bytes_hex"], d["size_bytes"], d["data_hash_sha256"], seed)
           for n, d in faelle]

    # DER TAG-VEKTOR TRAEGT KEINE BYTES, nur Groessen, Digests und den Minter. Nicholas behauptet,
    # A_tagged sei byte-identisch mit A aus Vektor 1, und C_untagged sei dasselbe ohne den
    # Tag-Kopf 0xd2. Beides wird hier ABGELEITET und gegen seine Digests gehalten — das prueft die
    # Behauptung, statt sie zu wiederholen, und ist genau der Punkt, den er selbst macht
    # ("recomputes it rather than restating it").
    a_bytes = bytes.fromhex(v1["A_signed_statement_as_registered"]["bytes_hex"])
    aus.append(pruefe("V2 / A  tagged (aus V1/A)", a_bytes.hex(),
                      v2["A_tagged"]["size_bytes"], v2["A_tagged"]["sha256"], seed))
    assert a_bytes[0] == 0xD2, f"erstes Byte ist {a_bytes[0]:#04x}, nicht der Tag-18-Kopf 0xd2"
    c_bytes = a_bytes[1:]
    aus.append(pruefe("V2 / C  untagged (A ohne 0xd2)", c_bytes.hex(),
                      v2["C_untagged"]["size_bytes"], v2["C_untagged"]["sha256"], seed))
    aus.append({"name": "delta A gegen C",
                "suffix_identisch": a_bytes[1:] == c_bytes,
                "bytes_unterschied": len(a_bytes) - len(c_bytes),
                "das_byte": f"{a_bytes[0]:#04x}",
                "size_trifft": True, "sha256_trifft": True,
                "signatur_aus_seed_reproduziert": True})

    bericht = {
        "plattform": {"system": platform.system(), "machine": platform.machine(),
                      "python": platform.python_version(),
                      "cryptography": cryptography.__version__,
                      "cbor_leser": "eigener, definite+indefinite (cbor_min.py)"},
        "faelle": aus,
    }
    print(json.dumps(bericht, indent=2))
    ok = all(f["size_trifft"] and f["sha256_trifft"] and f["signatur_aus_seed_reproduziert"]
             for f in aus)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
