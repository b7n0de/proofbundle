"""proofbundle.checkpoint.verify_checkpoint against REAL C2SP tlog-checkpoint signed notes.

These are not proofbundle-generated notes — they are frozen snapshots of the current signed note
from two independent, currently-operating production transparency logs (see
tests/fixtures/checkpoint/PROVENANCE.json):

  * sum.golang.org — the Go module checksum database (`sumdb_latest.txt`).
  * log2025-1.rekor.sigstore.dev — a Sigstore Rekor v2 transparency log (`rekor_v2_checkpoint.txt`).

Neither test hand-types a "vkey" magic string. Each vkey is DERIVED here from independently
sourced key material and its correctness is PROVEN by the fact that it makes
`checkpoint.verify_checkpoint()` return `ok=True` against the real, live-fetched signed note:

  * the sum.golang.org vkey is read out of the vendored `gosumdb_known_keys.go` (the Go
    toolchain's OWN hardcoded trust anchor for that log, `knownGOSUMDB["sum.golang.org"]`) — used
    directly, since a C2SP vkey string IS the canonical distribution format for this key.
  * the log2025-1.rekor.sigstore.dev key is DECODED from the vendored `trusted_root.json`
    (Sigstore's public trust root) — its DER SubjectPublicKeyInfo is parsed to raw Ed25519 bytes,
    then run through `checkpoint.key_id()` / `checkpoint.vkey()` exactly as proofbundle's own
    signer would. The resulting computed key ID must equal the checkpoint's own signature-line key
    ID (`cf119915`).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

from proofbundle import checkpoint as cp

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "checkpoint"
PROVENANCE_PATH = FIXTURE_DIR / "PROVENANCE.json"

_GOSUMDB_KEY_RE = re.compile(r'"sum\.golang\.org":\s*"([^"]+)"')


def _load_provenance() -> dict:
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


def _sumdb_note() -> str:
    return (FIXTURE_DIR / "sumdb_latest.txt").read_text(encoding="utf-8")


def _sumdb_vkey() -> str:
    src = (FIXTURE_DIR / "gosumdb_known_keys.go").read_text(encoding="utf-8")
    m = _GOSUMDB_KEY_RE.search(src)
    if not m:
        raise AssertionError("could not find the sum.golang.org vkey in gosumdb_known_keys.go")
    return m.group(1)


def _rekor_note() -> str:
    return (FIXTURE_DIR / "rekor_v2_checkpoint.txt").read_text(encoding="utf-8")


def _rekor_vkey() -> tuple[str, bytes]:
    """Derive the log2025-1.rekor.sigstore.dev C2SP vkey from the Sigstore trusted_root.json.
    Returns (vkey, raw_pubkey)."""
    root = json.loads((FIXTURE_DIR / "trusted_root.json").read_text(encoding="utf-8"))
    tlog = next(t for t in root["tlogs"] if t["baseUrl"] == "https://log2025-1.rekor.sigstore.dev")
    der = base64.b64decode(tlog["publicKey"]["rawBytes"])
    pub = load_der_public_key(der)
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    keyname = "log2025-1.rekor.sigstore.dev"
    return cp.vkey(keyname, raw), raw


@unittest.skipUnless(PROVENANCE_PATH.exists(), "checkpoint fixtures not vendored (tests/fixtures/checkpoint/)")
class TestCheckpointFixtureIntegrity(unittest.TestCase):
    def test_provenance_pins_every_vendored_file(self) -> None:
        prov = _load_provenance()
        entries = {e["filename"] for e in prov["files"]}
        vendored = {p.name for p in FIXTURE_DIR.iterdir()
                   if p.is_file() and p.name != "PROVENANCE.json"}
        self.assertTrue(vendored)
        self.assertEqual(vendored, entries,
                         "every vendored file must have a PROVENANCE.json entry (and vice versa)")

    def test_fixture_sha256_matches_provenance(self) -> None:
        prov = _load_provenance()
        for entry in prov["files"]:
            actual = hashlib.sha256((FIXTURE_DIR / entry["filename"]).read_bytes()).hexdigest()
            self.assertEqual(actual, entry["sha256"],
                             f"{entry['filename']} does not match its PROVENANCE.json pin (tampered)")

    def test_tampered_fixture_is_detected(self) -> None:
        real = (FIXTURE_DIR / "sumdb_latest.txt").read_bytes()
        tampered = bytearray(real)
        tampered[0] ^= 0xFF
        prov = _load_provenance()
        pin = next(e["sha256"] for e in prov["files"] if e["filename"] == "sumdb_latest.txt")
        self.assertNotEqual(hashlib.sha256(bytes(tampered)).hexdigest(), pin,
                            "a single-byte tamper must change the SHA-256 (pin is not vacuous)")


class TestGoSumdbCheckpointKat(unittest.TestCase):
    def test_real_sumdb_note_verifies(self) -> None:
        note = _sumdb_note()
        res = cp.verify_checkpoint(note, _sumdb_vkey())
        self.assertTrue(res["ok"], "sum.golang.org checkpoint failed to verify against its own "
                                   "well-known public vkey (from the Go toolchain source)")
        self.assertEqual(res["origin"], "go.sum database tree")
        self.assertEqual(res["tree_size"], 57389448)

    def test_root_tamper_is_rejected(self) -> None:
        note = _sumdb_note()
        vk = _sumdb_vkey()
        lines = note.split("\n")
        # line index 2 is the base64 root — flip it to an all-zero root of the same length
        tampered_root_b64 = base64.b64encode(bytes(32)).decode("ascii")
        self.assertNotEqual(lines[2], tampered_root_b64)
        lines[2] = tampered_root_b64
        self.assertFalse(cp.verify_checkpoint("\n".join(lines), vk)["ok"])

    def test_foreign_key_rejected(self) -> None:
        # a real, unrelated Ed25519 checkpoint key (proofbundle's own key generator) must not
        # verify a note it never signed.
        from proofbundle.emit import _raw_pub, generate_signer
        note = _sumdb_note()
        foreign_vkey = cp.vkey("sum.golang.org", _raw_pub(generate_signer()))
        self.assertFalse(cp.verify_checkpoint(note, foreign_vkey)["ok"])


class TestRekorV2CheckpointKat(unittest.TestCase):
    def test_derived_vkey_key_id_matches_signature_line(self) -> None:
        vk, raw_pub = _rekor_vkey()
        kid = cp.key_id("log2025-1.rekor.sigstore.dev", raw_pub)
        self.assertEqual(kid.hex(), "cf119915",
                         "the C2SP key ID derived from the Sigstore trusted_root.json Ed25519 key "
                         "must equal the well-known log2025-1 checkpoint key ID")

    def test_real_rekor_v2_checkpoint_verifies(self) -> None:
        vk, _ = _rekor_vkey()
        res = cp.verify_checkpoint(_rekor_note(), vk)
        self.assertTrue(res["ok"], "log2025-1.rekor.sigstore.dev checkpoint failed to verify "
                                   "against the key derived from Sigstore's trusted_root.json")
        self.assertEqual(res["origin"], "log2025-1.rekor.sigstore.dev")
        self.assertEqual(res["tree_size"], 22578297)

    def test_size_tamper_is_rejected(self) -> None:
        vk, _ = _rekor_vkey()
        note = _rekor_note()
        lines = note.split("\n")
        lines[1] = str(int(lines[1]) + 1)
        self.assertFalse(cp.verify_checkpoint("\n".join(lines), vk)["ok"])

    def test_sumdb_key_does_not_verify_rekor_checkpoint(self) -> None:
        # cross-log negative: a real, valid vkey for a DIFFERENT log/keyname must not verify.
        self.assertFalse(cp.verify_checkpoint(_rekor_note(), _sumdb_vkey())["ok"])

    def test_rekor_key_does_not_verify_sumdb_note(self) -> None:
        vk, _ = _rekor_vkey()
        self.assertFalse(cp.verify_checkpoint(_sumdb_note(), vk)["ok"])


if __name__ == "__main__":
    unittest.main()
