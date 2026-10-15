#!/usr/bin/env python3
"""A strict reader of a CCF inclusion receipt, written to the profile text after pull request 31.

Text: ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile, pull request 31, with commits eb01db3f ("Require inclusion
proofs to be valid CBOR before validation") and f6d4eb04 ("Require the vdp map to be valid CBOR and match
verifiable-proofs"). Every CBOR item it reads goes through ``proofbundle._strict_cbor``: the receipt, its protected
header, the vdp map and each proof. A duplicate map key, an encoding that is not valid under RFC 8949 Section 5.3.1
and bytes after an item are refused before any algorithm runs. A head that is not the shortest and an indefinite
length are valid CBOR and are read.

It is an inclusion reader. The whole vdp map must match ``verifiable-proofs`` before any root is computed, so each
consistency proof is held to its schema too (Section 4 of the profile at 820c5e4e), but no consistency root is computed:
``compute_roots`` needs an older root the verifier already trusts, and a receipt does not carry it.

A label is an integer or a text string (RFC 9052 Section 1.4, ``label = int / tstr``), and an integer is an integer:
a key or value 1.0 or ``true`` equals 1 in Python but is a different CBOR data item, so a header map, the vdp map, a
proof map or a key holding one is refused instead of being read as the integer.

It replaces the reference implementation of 2026-10-12 named in the pull request comment of that date, which read
with cbor2 and accepted a duplicate key in a proof and an empty consistency-proof array next to a valid inclusion
proof. The measured readings of both, and of the Go reader at e305458c, are in README.md next to this file.

The data-hash preimage of a statement replaces the unprotected header with the one byte 0xa0 in the statement's own
bytes. The profile and RFC 9943 Section 6.3 require an empty map and name no encoding; this reader fixes
a0, and the seven real receipts from microsoft/scitt-ccf-ledger 00101f76 match a0.

Usage: reader.py RECEIPT KEYS (--statement STATEMENT | --digest HEX)
KEYS is a COSE_KeySet in CBOR or a PEM certificate. Prints one line, ``PASS <root hex>`` or ``FAIL <reason>``,
and exits 0 for both; a reader that cannot run exits 2.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

from proofbundle._strict_cbor import CborInvalid, Tag, load_item_strict, loads_strict_cbor  # noqa: E402

ALGS = {-7: hashes.SHA256, -35: hashes.SHA384, -36: hashes.SHA512}
CURVES = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1}
VDS, VDP, INCLUSION, CONSISTENCY = 395, 396, -1, -2


class Fail(Exception):
    """The receipt is refused; the message is the reason printed after FAIL."""


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def strict(b: bytes, what: str):
    try:
        return loads_strict_cbor(b)
    except CborInvalid as exc:
        raise Fail(f"cbor_{what}: {exc.reason}") from exc


def _int(v) -> bool:
    return type(v) is int


def _labels(m: dict) -> bool:
    """Every key of the map is a COSE label: an int (not a bool) or a text string."""
    return all(type(k) is int or type(k) is str for k in m)


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | ai]) + n.to_bytes(width, "big")
    raise ValueError("argument does not fit in 64 bits")


def _sig_structure(protected: bytes, root: bytes) -> bytes:
    """RFC 9052 Section 4.4: ["Signature1", protected, external_aad, payload], definite lengths."""
    text = b"Signature1"
    return (_head(4, 4) + _head(3, len(text)) + text + _head(2, len(protected)) + protected + _head(2, 0)
            + _head(2, len(root)) + root)


def statement_digest(raw: bytes) -> bytes:
    """SHA-256 of the statement with its unprotected header replaced by the one byte 0xa0, in its own bytes.

    The statement must be a tagged COSE_Sign1 (tag 18), as the Go reader from the text requires too. Every other
    byte stays as it was: the tag, the array head, the protected header, the payload and the signature. Which bytes
    the unprotected header spans is read with the strict reader, never searched for."""
    top = strict(raw, "statement")
    if not (isinstance(top, Tag) and top.number == 18):
        raise Fail("statement_tag")
    body = top.value
    # COSE_Sign1 (RFC 9052 Section 4.2): a protected header in a byte string, an unprotected map, a payload that is a
    # byte string or nil, and a signature in a byte string. Every element is checked, not only the one this reader
    # replaces.
    if not (isinstance(body, list) and len(body) == 4 and isinstance(body[0], bytes) and isinstance(body[1], dict)
            and (body[2] is None or isinstance(body[2], bytes)) and isinstance(body[3], bytes)):
        raise Fail("statement_struct")
    i = _skip_head(raw, _skip_head(raw, 0))
    spans = []
    for _ in range(4):
        _value, end = load_item_strict(raw, i)
        spans.append((i, end))
        i = end
    u_start, u_end = spans[1]
    return H(raw[:u_start] + b"\xa0" + raw[u_end:])


def _skip_head(raw: bytes, i: int) -> int:
    """The offset after the head at ``i``; an indefinite head is one byte."""
    return i + 1 + {24: 1, 25: 2, 26: 4, 27: 8}.get(raw[i] & 0x1F, 0)


def read_keys(raw: bytes) -> list:
    if raw.startswith(b"-----BEGIN"):
        try:
            return [(None, x509.load_pem_x509_certificate(raw).public_key())]
        except ValueError as exc:
            raise Fail("keys") from exc
    out = []
    keyset = strict(raw, "keys")
    if not isinstance(keyset, list):
        raise Fail("keys")
    for k in keyset:
        if not (isinstance(k, dict) and _labels(k) and _int(k.get(1)) and k.get(1) == 2
                and _int(k.get(-1)) and k.get(-1) in CURVES):
            raise Fail("keys")
        x, y = k.get(-2), k.get(-3)
        n = (CURVES[k[-1]].key_size + 7) // 8
        # RFC 9053 Section 7.1.1: x and y keep their leading zero bytes, so each is exactly the byte length of the
        # curve, as r and s are in a signature. A kid is a byte string (RFC 9052 Section 7.1), like the one it meets.
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == n):
            raise Fail("keys")
        if 2 in k and not isinstance(k[2], bytes):
            raise Fail("keys")
        numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), CURVES[k[-1]]())
        try:
            public = numbers.public_key()
        except ValueError as exc:
            # A point that is not on the named curve, or coordinates out of range: the key set is refused, never an
            # exception out of verdict().
            raise Fail("keys") from exc
        out.append((k.get(2), public))
    return out


def _proof_element(el) -> bool:
    """ccf-proof-element: an array of exactly a boolean and a byte string of 32 bytes."""
    return (isinstance(el, list) and len(el) == 2 and type(el[0]) is bool and isinstance(el[1], bytes)
            and len(el[1]) == 32)


def _check_consistency(m: dict) -> None:
    """One ccf-consistency-proof against its schema, Section 4 of the profile at 820c5e4e: a closed map of exactly
    anchor (1), a byte string of 32 bytes, and path (2), a non-empty array of ccf-proof-element. The form only; no
    consistency root is computed (see the module docstring)."""
    if not all(_int(k) for k in m) or set(m) != {1, 2}:
        raise Fail("consistency_keys")
    anchor, path = m[1], m[2]
    if not (isinstance(anchor, bytes) and len(anchor) == 32):
        raise Fail("consistency_anchor")
    if not (isinstance(path, list) and path):
        raise Fail("consistency_path")
    if not all(_proof_element(el) for el in path):
        raise Fail("consistency_path_el")


def _check_vdp(unprotected: dict) -> dict:
    """The whole vdp map before any algorithm (f6d4eb04): only -1 and -2, each a non-empty array of byte strings that
    are each one valid CBOR map, and each consistency proof against its full schema. A broken entry refuses the receipt
    even if no algorithm would read it. Each inclusion proof is held to its schema in check(), before its root."""
    vdp = unprotected.get(VDP)
    if not isinstance(vdp, dict):
        raise Fail("vdp")
    if not all(_int(k) for k in vdp) or set(vdp) - {INCLUSION, CONSISTENCY}:
        raise Fail("vdp_key")
    for label in (INCLUSION, CONSISTENCY):
        if label not in vdp:
            continue
        entries = vdp[label]
        if not (isinstance(entries, list) and entries):
            raise Fail("vdp_empty")
        for p in entries:
            if not isinstance(p, bytes):
                raise Fail("vdp_type")
            m = strict(p, "proof")
            if not isinstance(m, dict):
                raise Fail("vdp_map")
            if label == CONSISTENCY:
                _check_consistency(m)
    return vdp


def check(receipt_raw: bytes, keys: list, digest: bytes) -> str:
    receipt = strict(receipt_raw, "receipt")
    if isinstance(receipt, Tag):
        if receipt.number != 18:
            raise Fail("tag")
        receipt = receipt.value
    if not (isinstance(receipt, list) and len(receipt) == 4):
        raise Fail("struct")
    protected_raw, unprotected, payload, signature = receipt
    if not (isinstance(protected_raw, bytes) and isinstance(unprotected, dict) and isinstance(signature, bytes)):
        raise Fail("struct")
    protected = strict(protected_raw, "protected")
    if not isinstance(protected, dict):
        raise Fail("protected")
    if not _labels(protected):
        raise Fail("protected_label")
    if not _labels(unprotected):
        raise Fail("unprotected_label")
    vdp = _check_vdp(unprotected)
    if not (_int(protected.get(VDS)) and protected.get(VDS) == 2):
        raise Fail("vds")
    alg = protected.get(1)
    if not (_int(alg) and alg in ALGS):
        raise Fail("alg")
    if 4 in protected and not isinstance(protected[4], bytes):
        raise Fail("kid")                 # RFC 9052 Section 3.1: the kid header parameter is a byte string
    if payload is not None:
        raise Fail("payload")
    if INCLUSION not in vdp:
        raise Fail("vdp")
    roots = set()
    for p in vdp[INCLUSION]:
        m = strict(p, "proof")
        if not all(_int(k) for k in m) or set(m) != {1, 2}:
            raise Fail("proof_keys")
        leaf, path = m[1], m[2]
        if not (isinstance(leaf, list) and len(leaf) == 3):
            raise Fail("leaf")
        its, evidence, data_hash = leaf
        if not (isinstance(its, bytes) and len(its) == 32 and isinstance(data_hash, bytes) and len(data_hash) == 32):
            raise Fail("leaf_hash")
        if not isinstance(evidence, str):
            raise Fail("evidence")
        evidence_bytes = evidence.encode("utf-8")
        if not 1 <= len(evidence_bytes) <= 1024:
            raise Fail("evidence_len")
        if not (isinstance(path, list) and path):
            raise Fail("path")
        if not all(_proof_element(el) for el in path):
            raise Fail("path_el")
        if data_hash != digest:
            raise Fail("digest_mismatch")
        h = H(its + H(evidence_bytes) + data_hash)
        for left, sibling in path:
            h = H(sibling + h) if left else H(h + sibling)
        roots.add(h)
    if len(roots) != 1:
        raise Fail("roots")
    root = roots.pop()
    tbs = _sig_structure(protected_raw, root)
    kid = protected.get(4)
    if kid is not None and any(i is not None for i, _ in keys):
        candidates = [k for i, k in keys if i is not None and i == kid]
    else:
        candidates = [k for _, k in keys]
    for k in candidates:
        # RFC 9053 Section 2.1: r and s are each written in exactly the byte length of the curve's order, so a signature
        # with leading zero bytes or of any other length is refused, not split in half.
        curve = getattr(k, "curve", None)
        if curve is None:
            continue                      # a certificate with a key that is not an EC key verifies nothing here
        n = (curve.key_size + 7) // 8
        if len(signature) != 2 * n:
            continue
        try:
            der = utils.encode_dss_signature(int.from_bytes(signature[:n], "big"), int.from_bytes(signature[n:], "big"))
            k.verify(der, tbs, ec.ECDSA(ALGS[alg]()))
            return "PASS " + root.hex()
        except Exception:  # noqa: BLE001 - a key that does not verify moves on to the next one
            continue
    raise Fail("key" if not candidates else "signature")


def verdict(receipt_raw: bytes, keys_raw: bytes, *, statement_raw: bytes | None = None,
            digest: bytes | None = None) -> str:
    """One line, PASS <root> or FAIL <reason>, never an exception for bad input."""
    try:
        keys = read_keys(keys_raw)
        d = statement_digest(statement_raw) if statement_raw is not None else digest
        if not (isinstance(d, bytes) and len(d) == 32):
            raise Fail("digest")
        return check(receipt_raw, keys, d)
    except Fail as exc:
        return f"FAIL {exc}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Strict reader of a CCF inclusion receipt after pull request 31.")
    ap.add_argument("receipt", type=Path)
    ap.add_argument("keys", type=Path)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--statement", type=Path)
    g.add_argument("--digest")
    a = ap.parse_args(argv)
    try:
        digest = bytes.fromhex(a.digest) if a.digest else None
    except ValueError:
        print("FAIL digest")
        return 0
    try:
        receipt_raw, keys_raw = a.receipt.read_bytes(), a.keys.read_bytes()
        statement_raw = a.statement.read_bytes() if a.statement else None
    except OSError as exc:
        print(f"reader.py: cannot read an input file: {exc}", file=sys.stderr)
        return 2
    line = verdict(receipt_raw, keys_raw, statement_raw=statement_raw, digest=digest)
    try:
        print(line)
    except UnicodeEncodeError:
        # A reason can quote a text key of the input; an output stream that cannot encode it gets the line as UTF-8.
        sys.stdout.flush()
        sys.stdout.buffer.write((line + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
