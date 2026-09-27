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
from cryptography.exceptions import InvalidSignature                      # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (           # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import cryptography                                                       # noqa: E402


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 9052 4.4: ['Signature1', protected, external_aad, payload]."""
    return C.schreibe(["Signature1", protected, external_aad, payload])


def _verifies(public_hex: str, signature: bytes, to_be_signed: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, to_be_signed)
        return True
    except InvalidSignature:
        return False


def tobesigned_inputs(raw: bytes) -> dict:
    """The inputs of ToBeSigned for one encoded COSE_Sign1, and where each one comes from.

    Two of the four inputs are not both in the envelope. external_aad is never carried by a
    COSE_Sign1; it is recomputed here as the empty byte string. The payload is carried only when it
    is embedded; a detached payload is nil in the envelope and has to be supplied from outside.
    """
    payload = zerlege(raw)["payload"]
    embedded = isinstance(payload, bytes)
    return {"payload_embedded": embedded,
            "payload_type": "bstr" if embedded else ("nil" if payload is None else type(payload).__name__),
            "payload_length": len(payload) if embedded else None,
            "payload_sha256": hashlib.sha256(payload).hexdigest() if embedded else None,
            "external_aad_length": 0,
            "external_aad_source": "not carried by the COSE_Sign1, recomputed here as the empty byte string"}


def external_aad_probe(raw: bytes, public_hex: str, aad: bytes = b"\x00") -> dict:
    """The same envelope, recomputed with a non-empty external_aad: the signature MUST NOT verify.

    That is what makes external_aad part of what the signature binds while the envelope does not
    carry it. "caught" needs both directions: it verifies with the empty external_aad and does not
    verify with this one.
    """
    if not aad:
        raise ValueError("the probe needs a non-empty external_aad")
    t = zerlege(raw)
    with_empty = _verifies(public_hex, t["signature"], sig_structure(t["protected"], t["payload"]))
    with_aad = _verifies(public_hex, t["signature"], sig_structure(t["protected"], t["payload"], aad))
    return {"external_aad_hex": aad.hex(), "verifies_with_empty_external_aad": with_empty,
            "verifies_with_this_external_aad": with_aad, "caught": with_empty and not with_aad}


def _element_spans(raw: bytes) -> list[tuple[int, int]]:
    """Byte spans of the four array elements, read from the CBOR structure (tag optional)."""
    mt, _arg, i, _indef = C._kopf(raw, 0)
    if mt == 6:
        mt, _arg, i, _indef = C._kopf(raw, i)
    if mt != 4:
        raise ValueError("not a CBOR array after the optional tag")
    spans = []
    for _ in range(4):
        start = i
        _value, i = C.lade(raw, i)
        spans.append((start, i))
    return spans


def detach(raw: bytes) -> bytes:
    """The same COSE_Sign1 with the payload element replaced by nil (CBOR simple value 22, 0xf6)."""
    start, end = _element_spans(raw)[2]
    return raw[:start] + b"\xf6" + raw[end:]


def detached_probe(raw: bytes, public_hex: str) -> dict:
    """A detached variant: the envelope alone yields no Sig_structure, the supplied payload does.

    "caught" needs both: the detached envelope carries nil where the payload was, so no
    Sig_structure can be formed from it, and with the payload supplied from outside the unchanged
    signature verifies again.
    """
    payload = zerlege(raw)["payload"]
    if not isinstance(payload, bytes):
        raise ValueError("the probe needs an envelope with an embedded payload to detach")
    det = detach(raw)
    t = zerlege(det)
    try:
        sig_structure(t["protected"], t["payload"])
        alone = "formed"
    except TypeError:
        alone = "not formable: the payload element is nil"
    supplied = sig_structure(t["protected"], payload)
    verifies = _verifies(public_hex, t["signature"], supplied)
    return {"size_bytes": len(det), "sha256": hashlib.sha256(det).hexdigest(),
            "payload_in_envelope": "nil" if t["payload"] is None else type(t["payload"]).__name__,
            "sig_structure_from_envelope_alone": alone,
            "sig_structure_with_supplied_payload_sha256": hashlib.sha256(supplied).hexdigest(),
            "equals_sig_structure_of_the_embedded_envelope": supplied == sig_structure_bytes(raw),
            "verifies_with_supplied_payload": verifies,
            "caught": t["payload"] is None and alone != "formed" and verifies}


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


def _last_protected_byte(raw: bytes) -> int:
    """Offset of the last byte of the protected header, read from the CBOR structure.

    Not searched for: a first version used `raw.find(protected)`, and a review lens showed that
    a search finds a pattern, not the field (`count` does not see overlapping occurrences, and a
    self-similar header moved the position by one). Here the heads are parsed: an optional tag,
    the array head, then the first element, whose end is where the protected header ends.
    """
    mt, _arg, i, _indef = C._kopf(raw, 0)
    if mt == 6:                                   # tag 18, then the array head follows
        mt, _arg, i, _indef = C._kopf(raw, i)
    if mt != 4:
        raise ValueError("not a CBOR array after the optional tag")
    _protected, end = C.lade(raw, i)
    return end - 1


def falling_probe(cases_raw: dict[str, bytes], flip_case: str) -> dict:
    """Flip one byte in the protected header of one case: the comparison MUST break.

    The byte is flipped in the ENCODED case, then the case goes through the same decode and
    Sig_structure path as every other case. A comparison that stays identical after this compares
    nothing, whatever it reported before.

    "caught" needs both: the cases were identical BEFORE the flip, and the comparison broke AFTER
    it. A review lens showed on 2026-09-25 that "broke after" alone certifies nothing: with an
    empty protected header the flip lands in the signature, and a difference that already existed
    made the probe look caught. A probe whose preconditions do not hold raises instead of
    reporting. Once they hold, the flipped byte lies inside the protected header, which enters
    the Sig_structure verbatim; a separate "did the flip reach it" check could never fail and is
    therefore not made.
    """
    if len(cases_raw) < 2 or flip_case not in cases_raw:
        raise ValueError("the probe needs the flipped case and at least one other case")
    flipped_name = f"{flip_case} (flipped)"
    if flipped_name in cases_raw:
        raise ValueError(f"case name {flipped_name!r} already exists; it would be overwritten")
    raw = bytearray(cases_raw[flip_case])
    protected = zerlege(bytes(raw))["protected"]
    if not protected:
        raise ValueError(f"{flip_case} has an empty protected header; there is no byte to flip")
    before = compare_sig_structures({n: sig_structure_bytes(b) for n, b in cases_raw.items()})
    at = _last_protected_byte(bytes(raw))
    raw[at] ^= 0x01
    flipped = {name: sig_structure_bytes(b) for name, b in cases_raw.items() if name != flip_case}
    flipped[flipped_name] = sig_structure_bytes(bytes(raw))
    after = compare_sig_structures(flipped)
    return {"flipped": f"{flip_case}: byte {at} (last byte of the protected header), xor 0x01",
            "all_identical_before_flip": before["all_identical"],
            "all_identical_after_flip": after["all_identical"],
            "distinct_sha256_after_flip": len(after["distinct_sha256"]),
            "caught": before["all_identical"] and not after["all_identical"]}


#: How a case's signature is evidenced. Ed25519 is deterministic, so a signature regenerated from
#: the published seed byte for byte proves that exactly this Sig_structure was signed. D was minted
#: here with the signature TAKEN OVER from A; regenerating it would only regenerate A's, so for D
#: the evidence is a verification with the published public key, and it is named that way.
EVIDENCE = {"reproduced": "reproduced byte for byte from the published seed",
            "taken_over": "taken over from A when D was minted here, verified with the published public key"}


def pruefe(name: str, hex_bytes: str, erwartet_size: int, erwartet_sha: str, seed_hex: str,
           public_hex: str | None = None, evidence: str = "reproduced") -> dict:
    roh = bytes.fromhex(hex_bytes)
    got_sha = hashlib.sha256(roh).hexdigest()
    t = zerlege(roh)
    ss = sig_structure(t["protected"], t["payload"])
    row = {
        "name": name,
        "size_gemessen": len(roh), "size_erwartet": erwartet_size,
        "size_trifft": len(roh) == erwartet_size,
        "sha256_gemessen": got_sha, "sha256_erwartet": erwartet_sha,
        "sha256_trifft": got_sha == erwartet_sha,
        "cbor_tag": t["tag"],
        "aeusseres_array_indefinit": t["aeusseres_array_indefinit"],
        "sig_structure_laenge": len(ss),
        "sig_structure_sha256": hashlib.sha256(ss).hexdigest(),
        "signatur_laenge": len(t["signature"]),
        **tobesigned_inputs(roh),
        "signature_evidence": EVIDENCE[evidence],
    }
    if public_hex is not None:
        row["signature_verifies_with_public_key"] = _verifies(public_hex, t["signature"], ss)
    if evidence == "reproduced":
        neu = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).sign(ss)
        row["signatur_aus_seed_reproduziert"] = neu == t["signature"]
        row["signature_ok"] = row["signatur_aus_seed_reproduziert"]
    else:
        if public_hex is None:
            raise ValueError("a taken-over signature is evidenced by verification and needs the public key")
        row["signatur_aus_seed_reproduziert"] = None
        row["signature_ok"] = row["signature_verifies_with_public_key"]
    return row


def main() -> int:
    v1 = json.load(open(HIER / "data-hash-vector.json", encoding="utf-8"))
    v2 = json.load(open(HIER / "data-hash-tag-vector.json", encoding="utf-8"))
    seed = v1["test_key"]["seed_hex"]
    assert v2["test_key"]["seed_hex"] == seed, "die Vektoren nennen verschiedene Seeds"
    public = v1["test_key"]["public_key_hex"]
    assert Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes_raw().hex() \
        == public, "the published public key does not belong to the published seed"

    faelle = [
        ("V1 / A  as registered", v1["A_signed_statement_as_registered"]),
        ("V1 / B  carrying receipt", v1["B_same_statement_carrying_a_receipt"]),
    ]
    aus = [pruefe(n, d["bytes_hex"], d["size_bytes"], d["data_hash_sha256"], seed, public)
           for n, d in faelle]

    # DER TAG-VEKTOR TRAEGT KEINE BYTES, nur Groessen, Digests und den Minter. Nicholas behauptet,
    # A_tagged sei byte-identisch mit A aus Vektor 1, und C_untagged sei dasselbe ohne den
    # Tag-Kopf 0xd2. Beides wird hier ABGELEITET und gegen seine Digests gehalten — das prueft die
    # Behauptung, statt sie zu wiederholen, und ist genau der Punkt, den er selbst macht
    # ("recomputes it rather than restating it").
    a_bytes = bytes.fromhex(v1["A_signed_statement_as_registered"]["bytes_hex"])
    aus.append(pruefe("V2 / A  tagged (aus V1/A)", a_bytes.hex(),
                      v2["A_tagged"]["size_bytes"], v2["A_tagged"]["sha256"], seed, public))
    assert a_bytes[0] == 0xD2, f"erstes Byte ist {a_bytes[0]:#04x}, nicht der Tag-18-Kopf 0xd2"
    c_bytes = a_bytes[1:]
    aus.append(pruefe("V2 / C  untagged (A ohne 0xd2)", c_bytes.hex(),
                      v2["C_untagged"]["size_bytes"], v2["C_untagged"]["sha256"], seed, public))
    # D, the outer array in indefinite length, from the recorded vektor_d.json in this directory
    # (minted by mint_indefinite.py). Its expected size and digest are that record, not the list.
    vd = json.load(open(HIER / "vektor_d.json", encoding="utf-8"))["D_indefinite_array"]
    d_bytes = bytes.fromhex(vd["hex"])
    aus.append(pruefe("D  indefinite array (vektor_d.json)", d_bytes.hex(),
                      vd["size_bytes"], vd["sha256"], seed, public, evidence="taken_over"))
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
    # The inputs of ToBeSigned per case, and the two counter-probes on A: a non-empty
    # external_aad must break verification, and a detached A must need its payload supplied.
    evidence = {"A": "reproduced", "B": "reproduced", "C": "reproduced", "D": "taken_over"}
    inputs = {k: {**tobesigned_inputs(b), "signature_evidence": EVIDENCE[evidence[k]]}
              for k, b in cases_raw.items()}
    aad_probe = external_aad_probe(a_bytes, public)
    det_probe = detached_probe(a_bytes, public)

    bericht = {
        "plattform": {"system": platform.system(), "machine": platform.machine(),
                      "python": platform.python_version(),
                      "cryptography": cryptography.__version__,
                      "cbor_leser": "eigener, definite+indefinite (cbor_min.py)"},
        "faelle": aus,
        "sig_structure_comparison": comparison,
        "falling_probe": probe,
        "tobesigned_inputs": inputs,
        "external_aad_probe_on_A": aad_probe,
        "A_detached": det_probe,
    }
    print(json.dumps(bericht, indent=2))
    return exit_code(aus, comparison, probe, aad_probe, det_probe)


def exit_code(rows: list[dict], comparison: dict, probe: dict,
              aad_probe: dict | None = None, det_probe: dict | None = None) -> int:
    """0 only if every case holds, the Sig_structure bytes agree, and every probe was caught."""
    ok = all(f["size_trifft"] and f["sha256_trifft"]
             and f.get("signature_ok", f.get("signatur_aus_seed_reproduziert")) for f in rows)
    probes = [probe] + [p for p in (aad_probe, det_probe) if p is not None]
    return 0 if ok and comparison["all_identical"] and all(p["caught"] for p in probes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
