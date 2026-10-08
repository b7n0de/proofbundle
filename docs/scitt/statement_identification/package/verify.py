#!/usr/bin/env python3
"""Check this package offline: every statement, every reference, and every manifest field that states a fact about
the files. Needs cbor2 and cryptography.

The manifest fields `package`, `reference_format` and `why_these_bytes` are descriptions and are not checked; each
other field is compared with the files, and a field the checker does not know is a FAIL, so no field goes unread
in silence (Codex thread 4217204734 on pull request 298: `covered_bytes` was never read).

Usage: python3 verify.py [package directory]   (default: the directory this file is in)
Prints one line per check, OK or FAIL, then "ALL OK" or "FAILED", and exits 0 only if every check is OK.
Malformed input is a FAIL line and exit 1, never an uncaught exception. This checks this package; it is
not a general COSE validator.
"""
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ALG, CWT_CLAIMS, ISS, SUB = 1, 15, 1, 2
EDDSA = -8
REF = -70001    # the private-use header label this package uses for references
ADDED = -70002  # a private-use label for the unprotected parameter the envelope experiment adds
DIGESTS = {-16: ("SHA-256 (COSE algorithm -16)", hashlib.sha256)}   # the one digest algorithm used here
COVERS = ("ToBeSigned", "COSE_Sign1")
#: What `covered_bytes` must say for each value of the signed covered-bytes element.
COVERED_BYTES = {
    "ToBeSigned": ("the Sig_structure [\"Signature1\", body_protected, external_aad, payload] of the referenced "
                   "COSE_Sign1, encoded as RFC 9052 sections 4.4 and 9 specify; the protected value is the original "
                   "byte-string contents; external_aad is the empty byte string and the payload is embedded"),
    "COSE_Sign1": "the bytes of the whole referenced COSE_Sign1, tag and signature included",
}
#: Every field of the manifest, at each level: the ones compared with the files, and the descriptions.
FIELDS = {"top": ({"statements", "references"}, {"package", "reference_format"}),
          "statement": ({"public_key", "iss", "sub", "sha256_to_be_signed", "sha256_cose_sign1", "size_bytes"}, set()),
          "reference": ({"from", "location", "to", "digest_algorithm", "covers", "covered_bytes", "digest"},
                        {"why_these_bytes"})}

HERE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
failed = 0


class Malformed(ValueError):
    pass


#: The one form a reference's location takes in this package: the signed header, its label, the entry index.
LOCATION = re.compile(rf"\Aprotected header, label {REF}, entry (0|[1-9][0-9]*)\Z")


def no_duplicate_members(pairs: list) -> dict:
    """json.loads keeps the last of two members with one name, so a false member before a true one would be read
    as the true one; a manifest with a repeated name is malformed (Codex thread 4217984327 on pull request 298)."""
    names = [name for name, _ in pairs]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise Malformed(f"duplicate member name(s) {repeated} in one object")
    return dict(pairs)


def check(ok: bool, text: str) -> None:
    global failed
    print(("OK   " if ok else "FAIL ") + text)
    failed += not ok


def read_hex(name: str) -> bytes:
    return bytes.fromhex("".join((HERE / name).read_text(encoding="ascii").split()))


def item_end(data: bytes, pos: int, depth: int = 0) -> int:
    """Where the CBOR item at ``pos`` ends. Raises Malformed on truncation or a duplicate map key."""
    if depth > 16 or pos >= len(data):
        raise Malformed("truncated or nested too deeply")
    major, info, pos = data[pos] >> 5, data[pos] & 31, pos + 1
    if info < 24:
        arg = info
    elif info < 28:
        width = 1 << (info - 24)
        arg, pos = int.from_bytes(data[pos:pos + width], "big"), pos + width
    elif info == 31 and major in (2, 3, 4, 5):
        arg = None
    else:
        raise Malformed(f"a reserved or break head at byte {pos - 1}")
    if pos > len(data) or major in (0, 1, 7):
        if pos > len(data):
            raise Malformed("truncated")
        return pos
    if major == 6:
        return item_end(data, pos, depth + 1)
    if major in (2, 3):
        if arg is None:
            while data[pos:pos + 1] != b"\xff":
                pos = item_end(data, pos, depth + 1)
            return pos + 1
        if pos + arg > len(data):
            raise Malformed("truncated")
        return pos + arg
    seen, count = set(), 0
    while (data[pos:pos + 1] != b"\xff") if arg is None else (count < arg):
        if major == 5:
            key_end = item_end(data, pos, depth + 1)
            key = cbor2.loads(data[pos:key_end])
            if (type(key).__name__, repr(key)) in seen:
                raise Malformed(f"duplicate map key {key!r}")
            seen.add((type(key).__name__, repr(key)))
            pos = key_end
        pos, count = item_end(data, pos, depth + 1), count + 1
    return pos + (arg is None)


def open_sign1(raw: bytes):
    """-> (tagged, protected bytes, unprotected map, payload, signature, protected map). Raises Malformed."""
    end = item_end(raw, 0)
    if end != len(raw):
        raise Malformed(f"{len(raw) - end} trailing byte(s) after the item")
    item = cbor2.loads(raw)
    tagged = isinstance(item, cbor2.CBORTag)
    if tagged and item.tag != 18:
        raise Malformed(f"tag {item.tag}, not 18 (COSE_Sign1)")
    body = item.value if tagged else item
    if not (isinstance(body, (list, tuple)) and len(body) == 4):
        raise Malformed("a COSE_Sign1 is an array of four elements")
    protected, unprotected, payload, signature = body
    for value, what, kind in ((protected, "protected header", bytes), (unprotected, "unprotected header", Mapping),
                              (payload, "payload", bytes), (signature, "signature", bytes)):
        if not isinstance(value, kind):
            raise Malformed(f"the {what} is not a {'map' if kind is Mapping else 'byte string'}")
    if item_end(protected, 0) != len(protected):
        raise Malformed("trailing byte(s) in the protected header")
    header = cbor2.loads(protected)
    if not isinstance(header, Mapping):
        raise Malformed("the protected header is not a map")
    return tagged, protected, unprotected, payload, signature, header


def to_be_signed(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 sections 4.4 and 9: Sig_structure ["Signature1", protected, external_aad, payload], aad empty."""
    return cbor2.dumps(["Signature1", protected, b"", payload])


def signature_ok(key, signature: bytes, message: bytes) -> bool:
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    try:
        doc = json.loads((HERE / "references.json").read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_members)
    except Malformed as exc:
        check(False, f"references.json: {exc}")
        print(f"FAILED: {failed} check(s) failed")
        return 1
    raw, headers, tbs, keys = {}, {}, {}, {}

    # 0a. Every manifest field is one this checker compares or one it names as a description.
    for level, fields in [("top", [doc])] + [("statement", list(doc["statements"].values()))] + [
            ("reference", list(doc["references"]))]:
        checked, described = FIELDS[level]
        for i, part in enumerate(fields):
            unknown = sorted(set(part) - checked - described)
            missing = sorted(checked - set(part))
            check(not unknown and not missing,
                  f"manifest {level} {i}: every field is checked or a named description"
                  + (f" (unknown: {unknown})" if unknown else "") + (f" (missing: {missing})" if missing else ""))

    # 0. The statement files are exactly the ones the manifest lists.
    files, listed = sorted(p.name for p in HERE.glob("*.cose.hex")), sorted(doc["statements"])
    check(files == listed, f"statement files {files} are the {len(listed)} references.json lists"
          + ("" if files == listed else f" (not listed: {sorted(set(files) - set(listed))}, "
                                        f"missing: {sorted(set(listed) - set(files))})"))

    # 1. Every statement: well-formed, tag 18 and alg -8, its size, signature, digests, issuer and subject.
    for name, want in doc["statements"].items():
        try:
            raw[name] = read_hex(name)
            tagged, protected, _unprotected, payload, signature, headers[name] = open_sign1(raw[name])
        except (OSError, ValueError, TypeError, cbor2.CBORDecodeError) as exc:
            check(False, f"{name}: not a well-formed COSE_Sign1 ({type(exc).__name__}: {exc})")
            headers.pop(name, None)
            continue
        tbs[name] = to_be_signed(protected, payload)
        keys[name] = load_pem_public_key((HERE / want["public_key"]).read_bytes())
        check(tagged and headers[name].get(ALG) == EDDSA and isinstance(keys[name], Ed25519PublicKey),
              f"{name}: well-formed COSE_Sign1 (no duplicate map key, no trailing input), tag 18, alg -8 (EdDSA)")
        check(want.get("size_bytes") == len(raw[name]),
              f"{name}: size_bytes {want.get('size_bytes')} is its size, {len(raw[name])} bytes")
        check(signature_ok(keys[name], signature, tbs[name]), f"{name}: signature verifies under {want['public_key']}")
        check(sha256(tbs[name]) == want["sha256_to_be_signed"], f"{name}: SHA-256 of ToBeSigned = {sha256(tbs[name])}")
        check(sha256(raw[name]) == want["sha256_cose_sign1"],
              f"{name}: SHA-256 of the whole COSE_Sign1 = {sha256(raw[name])}")
        claims = headers[name].get(CWT_CLAIMS)
        claims = claims if isinstance(claims, Mapping) else {}
        check(claims.get(ISS) == want["iss"] and claims.get(SUB) == want["sub"],
              f"{name}: iss {claims.get(ISS)}, sub {claims.get(SUB)}")

    # 2. Every reference carried in a signed protected header is listed, and every listed one is carried.
    carried = {}
    for name, header in headers.items():
        entries = header.get(REF, [])
        for i, entry in enumerate(entries if isinstance(entries, (list, tuple)) else [entries]):
            carried[(name, i)] = entry
    # The whole location is compared, not its last number: "unsigned payload, bogus label 999, entry 0" named the
    # same slot as the true location (Codex thread 4217984308 on pull request 298).
    by_slot = {}
    for n, ref in enumerate(doc["references"]):
        form = LOCATION.match(ref["location"]) if isinstance(ref.get("location"), str) else None
        check(form is not None, f"reference {n}: location {ref.get('location')!r} is 'protected header, label {REF}, "
                                "entry <index>'")
        if form is not None:
            by_slot[(ref["from"], int(form.group(1)))] = (n, ref)
    for name, i in sorted(set(carried) - set(by_slot)):
        check(False, f"{name} carries a reference under label {REF}, entry {i}, that references.json does not "
                     "list: not listed")
    for (name, i), (n, _ref) in sorted(by_slot.items()):
        if (name, i) not in carried:
            check(False, f"reference {n}: {name} carries no reference under label {REF}, entry {i}")
    for (src, i), (n, ref) in sorted(by_slot.items(), key=lambda kv: kv[1][0]):
        entry, dst = carried.get((src, i)), ref["to"]
        if entry is None:
            continue
        if not (isinstance(entry, (list, tuple)) and len(entry) == 3 and entry[0] in DIGESTS
                and entry[1] in COVERS and isinstance(entry[2], bytes)):
            check(False, f"reference {n}: {src} carries {entry!r}, not [digest algorithm, covered bytes, digest]")
            continue
        name_of, digest_of = DIGESTS[entry[0]]
        check(list(entry) == [entry[0], ref["covers"], bytes.fromhex(ref["digest"])],
              f"reference {n}: {src} carries [{entry[0]}, {ref['covers']!r}, {ref['digest'][:16]}...] under label "
              f"{REF}, entry {i}, in its protected header")
        check(ref.get("digest_algorithm") == name_of,
              f"reference {n}: digest_algorithm {ref.get('digest_algorithm')!r} is the signed algorithm {entry[0]}")
        check(ref.get("covered_bytes") == COVERED_BYTES[entry[1]],
              f"reference {n}: covered_bytes describes the signed covered bytes {entry[1]!r}")
        if dst not in headers:
            check(False, f"reference {n}: {src} -> {dst}: the target is not a readable statement of this package")
            continue
        covered = tbs[dst] if entry[1] == "ToBeSigned" else raw[dst]
        check(digest_of(covered).digest() == entry[2],
              f"reference {n}: {src} -> {dst}: {name_of.split(' ')[0]} over its {entry[1]} matches")

    # 3. Same issuer, same subject, different statements: the subject does not select one of them.
    a, b = "01-original.cose.hex", "03-correction.cose.hex"
    if a not in headers or b not in headers:
        check(False, f"{a} and {b}: not both readable, the remaining checks cannot run")
    else:
        same = all(headers[a][CWT_CLAIMS][k] == headers[b][CWT_CLAIMS][k] for k in (ISS, SUB))
        check(same and sha256(tbs[a]) != sha256(tbs[b]), f"{a} and {b}: same iss and sub, different ToBeSigned digests")

        # 4. Two envelope changes after signing, each on its own: what stays and what changes.
        _t, protected, unprotected, payload, signature, _h = open_sign1(raw[a])
        for label, changed in (
                ("tag 18 kept, one unprotected parameter added (label -70002)",
                 cbor2.dumps(cbor2.CBORTag(18, [protected, {ADDED: "added after signing"}, payload, signature]))),
                ("tag 18 removed, nothing else changed; a generic COSE case, not an RFC 9943 Signed Statement",
                 cbor2.dumps([protected, dict(unprotected), payload, signature]))):
            _t2, p2, _u2, pl2, s2, _h2 = open_sign1(changed)
            check(signature_ok(keys[a], s2, to_be_signed(p2, pl2)) and to_be_signed(p2, pl2) == tbs[a]
                  and sha256(changed) != sha256(raw[a]),
                  f"{a} with {label} ({len(changed)} bytes): signature and ToBeSigned unchanged, "
                  f"whole-object digest changed")

    print(f"{'FAILED' if failed else 'ALL OK'}: {failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - the documented contract: a FAIL line and exit 1, never a traceback
        check(False, f"the checker stopped on malformed input: {type(exc).__name__}: {exc}")
        print(f"FAILED: {failed} check(s) failed")
        sys.exit(1)
