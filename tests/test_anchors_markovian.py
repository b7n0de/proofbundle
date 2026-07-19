"""markovian-provenance/v1 — a third-party anchor type demonstrating register_anchor_type.

Same discipline as the built-in types: fail-closed everywhere, PENDING is a WARN (inherited from the
composed OpenTimestamps verifier), the wallet<->data binding is enforced, and a real Bitcoin-confirmed
fixture (block 956857) verifies through the generic layer. Skipped without the [anchors] extra."""
import base64
import hashlib
import json
import pathlib
import unittest

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle import anchors

_ROOT = hashlib.sha256(b"markovian-prereg-root").digest()
_SALT = "00112233445566778899aabbccddeeff"
_WALLET = "1MKVtestWa11etAAAAAAAAAAAAAAAAAAAA"
_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "markovian_anchor_confirmed.json"


def _serialize(dtf) -> bytes:
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _pending_ots(msg=_ROOT) -> bytes:
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _btc_root(msg=_ROOT, nonce=b"\x00") -> bytes:
    # Null-Op hardening (2026-07-17): the realistic upgraded proof attests sha256(msg ‖ nonce) at the end of
    # a real op chain (append a nonce, then SHA-256), so the attested block root != file_digest; confirm
    # tests supply THIS value as the relying-party header.
    return hashlib.sha256(msg + nonce).digest()


def _upgraded_ots(msg=_ROOT, height=850000) -> bytes:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    leaf = ts.ops.add(OpAppend(b"\x00")).ops.add(OpSHA256())   # real op chain, not a leaf==root Null-Op
    leaf.attestations.add(BitcoinBlockHeaderAttestation(height))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _envelope(ots: bytes, *, data_hash=_ROOT.hex(), salt=_SALT, wallet=_WALLET,
              merkle_root=None, schema="markovian-provenance/v1") -> bytes:
    if merkle_root is None:
        merkle_root = hashlib.sha256(f"{data_hash}:{salt}:{wallet}".encode()).hexdigest()
    env = {"schema": schema, "data_hash": data_hash, "salt": salt, "wallet": wallet,
           "merkle_root": merkle_root, "block_height": 77810,
           "ots": base64.b64encode(ots).decode()}
    return json.dumps(env).encode()


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestMarkovianVerifier(unittest.TestCase):
    def setUp(self):
        from proofbundle.anchors_markovian import verify_markovian
        self.verify = verify_markovian

    def test_confirmed_synthetic(self):   # WP-A1 re-pin: confirmed only against RELYING-PARTY header
        rp = {"bitcoin_block_headers": {"850000": _btc_root().hex()}}
        res = self.verify(_envelope(_upgraded_ots(height=850000)), _ROOT, frozen={}, rp_trust=rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")
        self.assertIn(_WALLET, res["detail"])          # PASS names the committing wallet

    def test_pending_is_warn_never_pass(self):
        res = self.verify(_envelope(_pending_ots()), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertTrue(res["warn"])                    # inherited from the OTS lifecycle
        self.assertEqual(res["status"], "pending")

    def test_unbound_data_hash_fails(self):
        # envelope commits to a DIFFERENT data_hash than the target canonical root
        other = hashlib.sha256(b"different").hexdigest()
        res = self.verify(_envelope(_upgraded_ots(), data_hash=other), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "unbound")

    def test_envelope_tampered_fails(self):
        # merkle_root does not equal sha256(data_hash:salt:wallet) -> inconsistent envelope
        res = self.verify(_envelope(_upgraded_ots(), merkle_root="00" * 32), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "envelope_mismatch")

    def test_wallet_swap_breaks_binding(self):
        # swapping the wallet without recomputing merkle_root is caught (the wallet is bound to the data)
        env = json.loads(_envelope(_upgraded_ots()))
        env["wallet"] = "1ATTACKERwa11etAAAAAAAAAAAAAAAAAAA"
        res = self.verify(json.dumps(env).encode(), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "envelope_mismatch")

    def test_bad_schema_fails(self):
        res = self.verify(_envelope(_upgraded_ots(), schema="not-markovian"), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "bad_schema")

    def test_malformed_fails_closed(self):
        res = self.verify(b"not json at all", _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "malformed")

    def test_upgraded_without_rp_header_is_honest_not_pass(self):   # WP-A1 re-pin
        # inherits the OTS "upgraded but needs relying-party trust material" honest report
        res = self.verify(_envelope(_upgraded_ots()), _ROOT, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "needs_rp_trust")


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestMarkovianThroughGenericLayer(unittest.TestCase):
    def setUp(self):
        from proofbundle.anchors_markovian import register
        register()   # third-party type is opt-in; register it before the generic layer will dispatch to it

    def _rp_from_fixture(self, anchor):
        # WP-A1: the relying party supplies the Bitcoin block header (from their own node). The fixture
        # carries the real block-956857 header in its frozen block; a relying party who independently
        # trusts that header passes it as rp_trust — exactly what a real verifier would do.
        headers = (anchor.get("frozen") or {}).get("bitcoinBlockHeaderMerkleRootsByHeight") or {}
        return {"bitcoin_block_headers": headers}

    def test_real_confirmed_fixture_passes(self):   # WP-A1 re-pin
        # the real fixture: our block-956857 Bitcoin-confirmed OpenTimestamps proof wrapped in a
        # markovian-provenance/v1 stamp, verified end to end through anchors.verify_anchors with the
        # relying party supplying the block header.
        anchor = json.loads(_FIXTURE.read_text())
        root = base64.b64decode(anchor["canonicalRoot"])
        res = anchors.verify_anchors([anchor], target_roots={"preRegistration": root},
                                     rp_trust=self._rp_from_fixture(anchor))
        self.assertEqual(res["status"], "PASS", res["detail"])
        self.assertTrue(res["results"][0]["ok"])
        # WP-A1 security property: the SAME fixture WITHOUT relying-party trust material does NOT confirm
        no_rp = anchors.verify_anchors([anchor], target_roots={"preRegistration": root})
        self.assertNotEqual(no_rp["status"], "PASS")
        self.assertFalse(no_rp["results"][0]["ok"])

    def test_confirmed_fixture_satisfies_require_anchor(self):   # WP-A1 re-pin
        anchor = json.loads(_FIXTURE.read_text())
        root = base64.b64decode(anchor["canonicalRoot"])
        res = anchors.verify_anchors([anchor], target_roots={"preRegistration": root},
                                     require="markovian-provenance/v1",
                                     rp_trust=self._rp_from_fixture(anchor))
        self.assertEqual(res["status"], "PASS", res["detail"])

    def test_cross_target_root_mismatch_hard_fails(self):
        # a preRegistration anchor must never validate against a different root
        anchor = json.loads(_FIXTURE.read_text())
        res = anchors.verify_anchors([anchor], target_roots={"preRegistration": b"\x00" * 32})
        self.assertEqual(res["status"], "FAIL")


# ── Cross-implementation: the upstream C2SP tlog-bitcoin-anchor corpus ────────────────────────────────
# Vendored (pure data, digest-pinned) from MarkovianProtocol/tlog-bitcoin-anchor @ aaea18d. proofbundle's
# OWN note-body canonicalization (checkpoint.py) + OpenTimestamps binding verifier (anchors_ots.py) act as
# a SECOND, independent implementation of the spec: they must reproduce the upstream expected outcomes over
# these vectors, fully offline (no calendar, no Bitcoin node). See docs/ANCHORS_MARKOVIAN.md and
# tests/fixtures/anchors/tlog_bitcoin_anchor/{MANIFEST.json,README.md}.
_TLOG_FIXDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "tlog_bitcoin_anchor"
_TLOG_KEY_NAME = "markovianprotocol.com/bitcoin-anchor"
_TLOG_SIG_TYPE = 0xFF
_TLOG_IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/ots/v1"
_TLOG_NOTE_BODY_SHA256 = "7208a041bc85370dcb295cafc1699e935a3dea2f9414278c869c848c0752852b"


def _tlog_read(name: str) -> str:
    return (_TLOG_FIXDIR / "vectors" / name).read_text()


def _tlog_expected_key_id(identifier: bytes) -> bytes:
    # spec: key ID = SHA-256(<key name> || 0x0A || 0xff || <identifier>)[:4]
    return hashlib.sha256(_TLOG_KEY_NAME.encode() + b"\x0a" + bytes([_TLOG_SIG_TYPE]) + identifier).digest()[:4]


def _tlog_known_anchor_proofs(text: str):
    """(known_ots_proofs, ignored_count) for the checkpoint's anchor lines. Data extraction only (no
    verification): a line under OUR key name is decoded to key ID || 0xff || len || identifier || ots; it is
    a KNOWN anchor iff the key ID and identifier match this spec, else it is IGNORED (unknown id / grease)."""
    sig_block = text.split("\n\n", 1)[1]
    known, ignored = [], 0
    for line in sig_block.splitlines():
        if not line.startswith(f"— {_TLOG_KEY_NAME} "):   # U+2014 EM DASH signature line under our key name
            continue
        try:
            payload = base64.b64decode(line.split(" ", 2)[2])
            kid, stype, idlen = payload[:4], payload[4], payload[5]
            ident, opaque = payload[6:6 + idlen], payload[6 + idlen:]
            if stype == _TLOG_SIG_TYPE and kid == _tlog_expected_key_id(ident) and ident == _TLOG_IDENTIFIER:
                known.append(opaque)
            else:
                ignored += 1                                   # unknown identifier / grease -> ignore
        except Exception:
            ignored += 1
    return known, ignored


def _tlog_our_note_body_root(text: str) -> bytes:
    """The checkpoint note-body root as proofbundle derives it — via the PUBLIC C2SP checkpoint API
    (parse the note, re-serialize origin/tree_size/root through checkpoint_note), then SHA-256. This is our
    canonicalization, not a raw slice of the vendored bytes, so it genuinely re-derives the committed root."""
    from proofbundle import checkpoint
    dummy = checkpoint.vkey("dummy-verifier", bytes(32))          # ok=False (no matching sig) but parses fields
    parsed = checkpoint.verify_checkpoint(text, dummy)
    note = checkpoint.checkpoint_note(parsed["origin"], parsed["tree_size"], parsed["root"])
    return hashlib.sha256(note.encode("utf-8")).digest()


class TestTlogBitcoinAnchorVectorsManifest(unittest.TestCase):
    """G1 mechanism: every vendored file is digest-pinned; a single changed byte fails this test."""

    def test_tlog_bitcoin_vectors_manifest_digests_pinned(self):
        manifest = json.loads((_TLOG_FIXDIR / "MANIFEST.json").read_text())
        for entry in manifest["files"]:
            path = _TLOG_FIXDIR / entry["path"]
            got = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(got, entry["sha256"],
                             f"vendored {entry['path']} drifted from its MANIFEST digest pin")
        up = manifest["upstream"]                               # No-Fake provenance / attribution present
        self.assertEqual(up["commit"], "aaea18da69eb76b37df6c2ea2e262d4aa99cf01f")
        self.assertEqual(up["license"], "MIT")
        self.assertEqual(manifest["committed_note_body_sha256"], _TLOG_NOTE_BODY_SHA256)


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestTlogBitcoinAnchorVectors(unittest.TestCase):
    def setUp(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        self.verify_ots = verify_opentimestamps

    def test_01_valid_binds_through_our_derivation(self):
        text = _tlog_read("01-valid.txt")
        root = _tlog_our_note_body_root(text)
        # our canonicalization reproduces the upstream committed note-body digest
        self.assertEqual(root.hex(), _TLOG_NOTE_BODY_SHA256)
        known, ignored = _tlog_known_anchor_proofs(text)
        self.assertEqual(len(known), 1)                        # one known-identifier anchor
        self.assertEqual(ignored, 1)                           # the grease line is ignored, not rejected
        # SECOND-IMPLEMENTATION check: the independently-built OTS proof commits EXACTLY our derived root
        res = self.verify_ots(known[0], root, frozen={})
        self.assertNotIn(res["status"], ("unbound", "malformed"))   # binding holds under our verifier
        # offline, with no relying-party Bitcoin header, an upgraded proof is honestly not-a-pass
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "needs_rp_trust")
        # teeth: a WRONG root is rejected as unbound — proves the binding actually checks
        self.assertEqual(self.verify_ots(known[0], b"\x00" * 32, frozen={})["status"], "unbound")

    def test_02_unknown_id_is_ignored_not_rejected(self):
        text = _tlog_read("02-unknown-id.txt")
        known, ignored = _tlog_known_anchor_proofs(text)
        self.assertEqual(len(known), 0)                        # no anchor of our identifier to verify
        self.assertEqual(ignored, 1)                           # unknown-id line ignored (forward-compat), not a rejection
        # an unknown anchor never corrupts the note body; our canonicalization still derives the same root
        self.assertEqual(_tlog_our_note_body_root(text).hex(), _TLOG_NOTE_BODY_SHA256)

    def test_03_tampered_body_fails_closed(self):
        text = _tlog_read("03-tampered-body.txt")
        root = _tlog_our_note_body_root(text)
        # the altered root-hash line makes our derived note-body root differ from the committed one
        self.assertNotEqual(root.hex(), _TLOG_NOTE_BODY_SHA256)
        known, _ = _tlog_known_anchor_proofs(text)
        self.assertEqual(len(known), 1)
        res = self.verify_ots(known[0], root, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertEqual(res["status"], "unbound")             # note body no longer binds the proof

    def test_04_tampered_proof_fails_closed(self):
        text = _tlog_read("04-tampered-proof.txt")
        root = _tlog_our_note_body_root(text)
        # the body is intact, so our derived root is the genuine committed one
        self.assertEqual(root.hex(), _TLOG_NOTE_BODY_SHA256)
        known, _ = _tlog_known_anchor_proofs(text)
        self.assertEqual(len(known), 1)
        res = self.verify_ots(known[0], root, frozen={})
        self.assertFalse(res["ok"])
        self.assertFalse(res["warn"])
        self.assertIn(res["status"], ("unbound", "malformed"))  # corrupted proof no longer commits our root


if __name__ == "__main__":
    unittest.main()
