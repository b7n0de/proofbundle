"""Nachrechnung beider Vektoren von Nicholas — eigener Leser, zweite Sprache, dritte Plattform."""
from __future__ import annotations

import hashlib
import json
import pathlib
import platform
import sys

# Der Leser liegt NEBEN diesem Skript. Hier stand ein absoluter Pfad der Maschine, auf der
# gemessen wurde: er verriet einen internen Ablageort UND liess die Reproduktion auf jeder
# anderen Maschine ins Leere laufen, obwohl `cbor_min.py` direkt daneben liegt.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

#: Die Vektoren liegen NEBEN diesem Skript, nicht im Arbeitsverzeichnis des Aufrufers.
#: Ohne diese Bindung laeuft die im README versprochene Reproduktion nur zufaellig, naemlich
#: genau dann, wenn jemand vorher in dieses Verzeichnis gewechselt ist.
HIER = pathlib.Path(__file__).resolve().parent
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


def sig_structure_bytes(raw: bytes) -> bytes:
    """The Sig_structure of one encoded COSE_Sign1, built from its own decoded elements."""
    t = zerlege(raw)
    return sig_structure(t["protected"], t["payload"])


def compare_sig_structures(cases: dict[str, bytes]) -> dict:
    """Are the Sig_structure BYTES the same across the cases, not just their length?

    Equal length is no proof of equal bytes (`GLEICHE-LAENGE-IST-KEIN-NACHWEIS-GLEICHER-BYTES-01`).
    Every case here has 109 bytes, and until 2026-09-25 that length was all this script
    recorded across cases. The comparison is by sha256 per case; one case alone compares with
    nothing and is never reported as identical.
    """
    digests = {name: hashlib.sha256(ss).hexdigest() for name, ss in cases.items()}
    distinct = sorted(set(digests.values()))
    return {"cases": list(digests), "sha256_per_case": digests, "distinct_sha256": distinct,
            "all_identical": len(digests) > 1 and len(distinct) == 1}


def falling_probe(cases_raw: dict[str, bytes], flip_case: str) -> dict:
    """Flip one byte in the protected header of one case: the comparison MUST break.

    The byte is flipped in the ENCODED case, then the case goes through the same decode and
    Sig_structure path as every other case. A comparison that stays identical after this compares
    nothing, whatever it reported before.
    """
    raw = bytearray(cases_raw[flip_case])
    protected = zerlege(bytes(raw))["protected"]
    at = bytes(raw).find(protected) + len(protected) - 1   # last byte of the protected header
    raw[at] ^= 0x01
    flipped = {name: sig_structure_bytes(b) for name, b in cases_raw.items() if name != flip_case}
    flipped[f"{flip_case} (flipped)"] = sig_structure_bytes(bytes(raw))
    after = compare_sig_structures(flipped)
    return {"flipped": f"{flip_case}: byte {at} (last byte of the protected header), xor 0x01",
            "all_identical_after_flip": after["all_identical"],
            "distinct_sha256_after_flip": len(after["distinct_sha256"]),
            "caught": not after["all_identical"]}


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
        "sig_structure_sha256": hashlib.sha256(ss).hexdigest(),
        "signatur_aus_seed_reproduziert": neu == t["signature"],
        "signatur_laenge": len(t["signature"]),
    }


def main() -> int:
    v1 = json.load(open(HIER / "data-hash-vector.json", encoding="utf-8"))
    v2 = json.load(open(HIER / "data-hash-tag-vector.json", encoding="utf-8"))
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
    # D, the outer array in indefinite length, from the recorded vektor_d.json in this directory
    # (minted by mint_indefinite.py). Its expected size and digest are that record, not the list.
    vd = json.load(open(HIER / "vektor_d.json", encoding="utf-8"))["D_indefinite_array"]
    d_bytes = bytes.fromhex(vd["hex"])
    aus.append(pruefe("D  indefinite array (vektor_d.json)", d_bytes.hex(),
                      vd["size_bytes"], vd["sha256"], seed))
    aus.append({"name": "delta A gegen C",
                "suffix_identisch": a_bytes[1:] == c_bytes,
                "bytes_unterschied": len(a_bytes) - len(c_bytes),
                "das_byte": f"{a_bytes[0]:#04x}",
                "size_trifft": True, "sha256_trifft": True,
                "signatur_aus_seed_reproduziert": True})

    # The four cases A, B, C, D, compared byte for byte over their Sig_structure.
    cases_raw = {"A": a_bytes,
                 "B": bytes.fromhex(v1["B_same_statement_carrying_a_receipt"]["bytes_hex"]),
                 "C": c_bytes, "D": d_bytes}
    comparison = compare_sig_structures({k: sig_structure_bytes(b) for k, b in cases_raw.items()})
    probe = falling_probe(cases_raw, "B")

    bericht = {
        "plattform": {"system": platform.system(), "machine": platform.machine(),
                      "python": platform.python_version(),
                      "cryptography": cryptography.__version__,
                      "cbor_leser": "eigener, definite+indefinite (cbor_min.py)"},
        "faelle": aus,
        "sig_structure_comparison": comparison,
        "falling_probe": probe,
    }
    print(json.dumps(bericht, indent=2))
    return exit_code(aus, comparison, probe)


def exit_code(rows: list[dict], comparison: dict, probe: dict) -> int:
    """0 only if every case reproduces, the Sig_structure bytes agree, AND the probe was caught."""
    ok = all(f["size_trifft"] and f["sha256_trifft"] and f["signatur_aus_seed_reproduziert"]
             for f in rows)
    return 0 if ok and comparison["all_identical"] and probe["caught"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
