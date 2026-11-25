"""Third-party use case: the 716 figure statements of one publisher, and one statement it signed by mistake.

Each statement under statements/ is read with the statement-identification reader of this repository
(proofbundle.scitt_statement_id, scheme ToBeSigned, alg -16, empty external_aad) against the reference that the
publisher's list gives for its figure, and its ES256 signature is checked against the publisher's key. The signature
check is not part of that reader, which knows Ed25519 only; it runs here, separately, with ``cryptography``.

The negative case under negative/ is the version of one statement that the publisher served at 08:27:33 UTC on
2026-11-25 without its limits member. Its signature verifies under the publisher's key, and it does not match the
reference of its figure. Read against the list as it stood that morning, its digest is not on it. Read against the list
at sequence 3, its digest is on it, marked as issued in error, so a relying party that uses the list does not accept
the statement as one of the publisher.

python3 check_figure_statements.py prints one line per check and exits with 0 only if every check gives its expected
result. It needs proofbundle importable (PYTHONPATH=src from the repository root) and cryptography.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from proofbundle import scitt_statement_id as reader
from proofbundle._cbor_prescan import encode_head
from proofbundle._strict_cbor import Tag, loads_strict_cbor

HERE = Path(__file__).resolve().parent
MORNING_LIST = "lists/statement-digests-20261125T082243Z.json"
SEQUENCE_3_LIST = "lists/statement-digests-sequence-3.json"
NEGATIVE = "negative/metro-gap-fort-wayne-in-2025-20261125T082733Z.cose"
NEGATIVE_FIGURE = "metro-gap-fort-wayne-in-2025"
NEGATIVE_DIGEST = "bf059ab518eea35ffebe0bcd5da1739aa7280dcc5f7c0a74eae58057f9ed7946"


def reference(digest_hex: str) -> bytes:
    """The reference [-16, "ToBeSigned", digest] of Section 6 of the draft."""
    digest = bytes.fromhex(digest_hex)
    return (encode_head(4, 3) + bytes([0x2F]) + encode_head(3, 10) + b"ToBeSigned"
            + encode_head(2, len(digest)) + digest)


def public_key(folder: Path):
    jwk = json.loads((folder / "statement-key.json").read_text(encoding="utf-8"))["public_jwk"]
    if (jwk.get("kty"), jwk.get("crv")) != ("EC", "P-256"):
        raise ValueError("the publisher's key is not an EC P-256 key")

    def b64(text: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)), "big")
    return ec.EllipticCurvePublicNumbers(b64(jwk["x"]), b64(jwk["y"]), ec.SECP256R1()).public_key()


def es256_valid(key, statement: bytes) -> bool:
    """ES256 over the ToBeSigned of RFC 9052 Section 4.4 with an empty external_aad; r and s are 32 bytes each."""
    top = loads_strict_cbor(statement)
    if type(top) is Tag:
        top = top.value
    protected, _unprotected, payload, signature = top
    if type(payload) is not bytes or len(signature) != 64:
        return False
    tbs = (encode_head(4, 4) + encode_head(3, 10) + b"Signature1" + encode_head(2, len(protected)) + protected
           + encode_head(2, 0) + encode_head(2, len(payload)) + payload)
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        key.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def list_state(digest_list: dict, figure: str, digest_hex: str) -> str:
    """What the list says about one digest of one figure: in_force (the last entry), issued_in_error (an entry marked
    so), superseded (any other entry), or absent."""
    entries = digest_list["digests"].get(figure, [])
    for position, entry in enumerate(entries):
        if entry.get("digest") == digest_hex:
            if entry.get("issued_in_error") is True:
                return "issued_in_error"
            return "in_force" if position == len(entries) - 1 else "superseded"
    return "absent"


def check(folder: Path = HERE) -> list[tuple[str, bool, str]]:
    """(check, as expected, detail) for every check of this use case."""
    morning = json.loads((folder / MORNING_LIST).read_text(encoding="utf-8"))
    sequence_3 = json.loads((folder / SEQUENCE_3_LIST).read_text(encoding="utf-8"))
    key = public_key(folder)
    results = []
    statements = sorted((folder / "statements").glob("*.cose"))
    for path in statements:
        figure, raw = path.stem, path.read_bytes()
        expected = morning["digests"][figure][-1]["digest"]
        axes = reader.match_statement(reference(expected), raw, scheme="ToBeSigned", alg=-16, external_aad=b"")
        good = (axes["ref_usable"] is True and axes["match"] == "MATCH" and axes["is_scitt"] is True
                and es256_valid(key, raw) and list_state(sequence_3, figure, axes["digest"]) == "in_force")
        results.append((f"statement {figure}", good, axes["match"]))
    results.append(("statements counted", len(statements) == len(morning["digests"]) == 716,
                    f"{len(statements)} files, {len(morning['digests'])} figures on the list"))
    raw = (folder / NEGATIVE).read_bytes()
    in_force = morning["digests"][NEGATIVE_FIGURE][-1]["digest"]
    axes = reader.match_statement(reference(in_force), raw, scheme="ToBeSigned", alg=-16, external_aad=b"")
    results.append(("negative: its own ToBeSigned digest", axes["digest"] == NEGATIVE_DIGEST, axes["digest"]))
    results.append(("negative: NO_MATCH against the reference of its figure", axes["match"] == "NO_MATCH"
                    and axes["is_scitt"] is True, axes["match"]))
    results.append(("negative: ES256 valid under the publisher's key", es256_valid(key, raw), "verified"))
    results.append(("negative: absent from the list of that morning",
                    list_state(morning, NEGATIVE_FIGURE, NEGATIVE_DIGEST) == "absent",
                    list_state(morning, NEGATIVE_FIGURE, NEGATIVE_DIGEST)))
    state = list_state(sequence_3, NEGATIVE_FIGURE, NEGATIVE_DIGEST)
    results.append(("negative: marked issued_in_error at sequence 3, not accepted", state == "issued_in_error", state))
    return results


def main() -> int:
    results = check()
    for name, good, detail in results:
        print(f"{'OK      ' if good else 'MISMATCH'} {name}: {detail}")
    failed = sum(1 for _, good, _ in results if not good)
    print(f"{len(results) - failed} of {len(results)} checks as expected")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
