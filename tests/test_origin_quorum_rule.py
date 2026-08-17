"""ORIGIN-QUORUM RULE — a log never votes in its own quorum.

Where this comes from: on 2026-08-16 a behaviour probe (report `20260816T0851Z`, section 8)
measured that `witness_quorum` counted a cosignature under the checked log's OWN origin name —
a self-cosigned mini-log satisfied `threshold=1` with nothing but its own signature. The C2SP
tlog-cosignature and tlog-witness specs are silent on the case (checked 2026-08-17), and the
affected log operator confirmed the intended reading in issue #7: his `/policy` declares the
quorum as `group independent-witnesses 4` with the log not a member, structural but never stated.
The rule now lives where it binds, in `checkpoint.witness_quorum`: a witness vkey whose name
equals the note's own origin line is excluded from the count — fail-closed, algorithm-agnostic,
before any signature math. His live checkpoint, self-signed under the origin name in both
Ed25519 (note signature, 0x01) and ML-DSA-44 (cosignature shape), is the vendored test vector
(`tests/fixtures/anchors/markovian_log/checkpoint_7397/`), offered by the operator for exactly
this purpose.

The probe below is the 2026-08-16 finding turned into a regression test: it MUST exclude now,
and it measures the exclusion on all three public surfaces that share `witness_quorum`
(`verify_witnessed_checkpoint`, `tlogproof.verify_tlog_proof`, `public_transparency`).
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import unittest
from unittest import mock

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import checkpoint as cp
from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    mldsa.MLDSA44PrivateKey.generate  # probe
    HAVE_MLDSA = True
except (ImportError, AttributeError):
    HAVE_MLDSA = False

TS = 1_780_000_000
ROOT = hashlib.sha256(b"leaf").digest()
ORIGIN = "meinlog.example/log"

_VECDIR = pathlib.Path(__file__).parent / "fixtures" / "anchors" / "markovian_log" / "checkpoint_7397"
_KEYFILE = (pathlib.Path(__file__).parent / "fixtures" / "anchors" / "markovian_log"
            / "proof_7271" / "keys_unabhaengig.txt")
_LIVE_ORIGIN = "markovianprotocol.com/log"


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _self_cosigned_note():
    """The 2026-08-16 probe, verbatim in structure: a log that cosigns its own checkpoint
    under its own origin name (Ed25519 — the algorithm-agnostic half runs on every build)."""
    log_key = generate_signer()
    note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
    log_vkey = cp.vkey(ORIGIN, _raw(log_key))
    self_witness = generate_signer()
    note = cp.cosign_checkpoint(note, self_witness, ORIGIN, TS)
    return note, log_vkey, self_witness


class TestOriginQuorumRegression(unittest.TestCase):
    """The measured 2026-08-16 finding, inverted into the property it violated."""

    def test_self_cosignature_under_origin_name_never_reaches_quorum(self):
        # Before the rule this returned (True, {...ok=True...}) — measured, not assumed.
        note, _, self_witness = _self_cosigned_note()
        wvkey = cp.cosign_vkey(ORIGIN, _raw(self_witness))
        ok, witnesses = cp.witness_quorum(note, [wvkey], 1)
        self.assertFalse(ok, "a log satisfied its own witness quorum with its own signature")
        (entry,) = witnesses.values()
        self.assertFalse(entry["ok"])
        self.assertIs(entry.get("origin_excluded"), True)
        self.assertIn("origin", entry["detail"])

    def test_exclusion_fires_even_though_the_signature_itself_is_valid(self):
        # The sharpest statement of the rule: verify_cosignature (a pure signature check) says
        # the self-cosignature IS cryptographically valid — and the quorum still refuses it.
        # Exclusion is about WHO speaks, not whether the bytes verify.
        note, _, self_witness = _self_cosigned_note()
        wvkey = cp.cosign_vkey(ORIGIN, _raw(self_witness))
        self.assertTrue(cp.verify_cosignature(note, wvkey)["ok"],
                        "precondition lost: the probe's self-cosignature no longer verifies, "
                        "so this test would pass for the wrong reason")
        ok, witnesses = cp.witness_quorum(note, [wvkey], 1)
        self.assertFalse(ok)
        self.assertIs(next(iter(witnesses.values())).get("origin_excluded"), True)

    def test_same_key_under_a_witness_name_still_counts(self):
        # Anti-parity: the rule must not shade into "this KEY is banned" — the same physical key
        # under a name that is not the origin verifies and counts (dedup stays key-material-based;
        # what the rule excludes is the IDENTITY claim, the origin line's own name).
        log_key = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
        w = generate_signer()
        note = cp.cosign_checkpoint(note, w, "witness.example/w", TS)
        ok, witnesses = cp.witness_quorum(note, [cp.cosign_vkey("witness.example/w", _raw(w))], 1)
        self.assertTrue(ok)
        self.assertNotIn("origin_excluded", next(iter(witnesses.values())))

    def test_real_witnesses_are_untouched_and_the_excluded_one_never_fills_a_gap(self):
        note, log_vkey, self_witness = _self_cosigned_note()
        w1, w2 = generate_signer(), generate_signer()
        note = cp.cosign_checkpoint(note, w1, "w1.example/w", TS + 1)
        note = cp.cosign_checkpoint(note, w2, "w2.example/w", TS + 2)
        roster = [cp.cosign_vkey(ORIGIN, _raw(self_witness)),
                  cp.cosign_vkey("w1.example/w", _raw(w1)),
                  cp.cosign_vkey("w2.example/w", _raw(w2))]
        met = cp.verify_witnessed_checkpoint(note, log_vkey, roster, threshold=2)
        self.assertTrue(met["ok"], "the rule over-blocked: two real witnesses no longer count")
        over = cp.verify_witnessed_checkpoint(note, log_vkey, roster, threshold=3)
        self.assertFalse(over["witnesses_ok"],
                         "threshold 3 was met — the excluded origin line counted after all")
        self.assertFalse(over["ok"])

    @unittest.skipUnless(HAVE_MLDSA, "cryptography build without ML-DSA (install proofbundle[pq])")
    def test_mldsa_self_cosignature_is_excluded_too(self):
        # The exact 2026-08-16 probe: the self-cosignature in ML-DSA-44 (the algorithm the live
        # log actually uses for its origin-name line).
        log_key = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
        pq = mldsa.MLDSA44PrivateKey.generate()
        note = cp.cosign_checkpoint_mldsa(note, pq, ORIGIN, TS)
        wvkey = cp.cosign_vkey_mldsa(ORIGIN, pq.public_key().public_bytes_raw())
        ok, witnesses = cp.witness_quorum(note, [wvkey], 1)
        self.assertFalse(ok)
        (entry,) = witnesses.values()
        self.assertIs(entry.get("origin_excluded"), True)
        self.assertEqual(entry["alg"], "ml-dsa-44")

    def test_exclusion_needs_no_pq_backend(self):
        # The rule fires BEFORE any signature math, so an ML-DSA vkey under the origin name is
        # excluded even on a build without FIPS 204 — measured by making the backend probe raise.
        log_key = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
        fake_pub = b"\x00" * 1312
        wvkey = (ORIGIN + "+" + cp.cosign_key_id_mldsa(ORIGIN, fake_pub).hex() + "+"
                 + base64.b64encode(bytes([0x06]) + fake_pub).decode())
        with mock.patch.object(cp, "_mldsa_module",
                               side_effect=AssertionError("backend must not be touched")):
            ok, witnesses = cp.witness_quorum(note, [wvkey], 1)
        self.assertFalse(ok)
        self.assertIs(next(iter(witnesses.values())).get("origin_excluded"), True)

    def test_the_comparison_is_exact(self):
        # A near-miss name is a DIFFERENT witness, not a loosened origin match: it must not be
        # excluded (and, unkeyed, it verifies nothing either). Polarity: pruefer(name) is True
        # iff a vkey under `name` gets origin_excluded — True for the origin itself, False for
        # every named loosening in the shared corpus.
        from _beinahe_treffer import pruefe_exakt  # noqa: PLC0415
        log_key = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
        probe_key = generate_signer()

        def wird_ausgeschlossen(name: str) -> bool:
            wv = cp.cosign_vkey(name, _raw(probe_key))
            _, witnesses = cp.witness_quorum(note, [wv], 1)
            return next(iter(witnesses.values())).get("origin_excluded", False) is True

        pruefe_exakt(wird_ausgeschlossen, ORIGIN, self)

    def test_unparseable_origin_named_vkey_still_raises(self):
        # Contract preservation: "an unparseable witness vkey raises" — the exclusion branch must
        # not swallow malformed input into a quiet non-count.
        note, _, _ = _self_cosigned_note()
        with self.assertRaises(BundleFormatError):
            cp.witness_quorum(note, [ORIGIN], 1)                  # a bare name is not a vkey
        with self.assertRaises(BundleFormatError):
            # a 0x01 LOG key under the origin name stays rejected as malformed for a witness
            # role (domain separation), same as everywhere else
            log_key = generate_signer()
            cp.witness_quorum(note, [cp.vkey(ORIGIN, _raw(log_key))], 1)

    def test_tlogproof_surface_inherits_the_rule(self):
        # Second public surface, through the shared helper: a tlog-proof whose roster lists an
        # origin-named witness gets no quorum from it.
        from proofbundle import emit_bundle  # noqa: PLC0415
        from proofbundle.tlogproof import tlog_proof_for_bundle, verify_tlog_proof  # noqa: PLC0415
        log_key = generate_signer()
        payload = b'{"result": 42}'
        bundle = emit_bundle(payload, log_key, prior_leaves=[b"a", b"b", b"c"])
        root = base64.b64decode(bundle["merkle"]["root_b64"])
        note = cp.sign_checkpoint(ORIGIN, bundle["merkle"]["tree_size"], root, log_key, ORIGIN)
        self_witness = generate_signer()
        note = cp.cosign_checkpoint(note, self_witness, ORIGIN, TS)
        proof = tlog_proof_for_bundle(bundle, note)
        res = verify_tlog_proof(proof, payload, cp.vkey(ORIGIN, _raw(log_key)),
                                [cp.cosign_vkey(ORIGIN, _raw(self_witness))], threshold=1)
        self.assertFalse(res["witnesses_ok"])
        self.assertFalse(res["ok"])
        self.assertTrue(res["log_ok"] and res["inclusion_ok"])    # precise verdicts: only the quorum fails
        excluded = next(iter(res["witnesses"].values()))
        self.assertIs(excluded.get("origin_excluded"), True)

    def test_public_transparency_surface_inherits_the_rule(self):
        # Third surface (experimental profile): WITNESS_QUORUM must FAIL when the only supplied
        # witness is the log itself.
        from proofbundle.public_transparency import evaluate_public_transparency  # noqa: PLC0415
        note, log_vkey, self_witness = _self_cosigned_note()
        r = evaluate_public_transparency(
            note, {"requireSignedCheckpoint": True, "witnessQuorum": {"threshold": 1}},
            log_vkey=log_vkey, witness_vkeys=[cp.cosign_vkey(ORIGIN, _raw(self_witness))])
        self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "FAIL")
        self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")


class TestLiveCheckpointVector(unittest.TestCase):
    """The operator's live checkpoint (tree 7397), self-signed under the origin name in both
    algorithms, frozen 2026-08-17 — the vector he offered for exactly this rule in issue #7."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((_VECDIR / "MANIFEST.json").read_text())
        cls.note = (_VECDIR / "checkpoint_7397.txt").read_text(encoding="utf-8")
        cls.log_vkey, cls.witness_vkeys = None, []
        for line in _KEYFILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(_LIVE_ORIGIN + "+"):
                cls.log_vkey = line
            else:
                cls.witness_vkeys.append(line)

    def test_vendored_bytes_are_digest_pinned(self):
        (entry,) = self.manifest["files"]
        raw = (_VECDIR / entry["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
        self.assertEqual(len(raw), entry["bytes"])

    def test_the_origin_name_signs_twice_note_sig_and_mldsa_cosig_shape(self):
        # The structural fact the vector exists for: the log's own name in signature position
        # under BOTH algorithms — 68-byte Ed25519 note-signature blob, 2432-byte ML-DSA-44 blob.
        blobs = []
        for line in self.note.split("\n\n", 1)[1].splitlines():
            if not line.startswith("— "):
                continue
            _, name, b64 = line.split(" ", 2)
            if name == _LIVE_ORIGIN:
                blobs.append(base64.b64decode(b64))
        self.assertEqual(sorted(len(b) for b in blobs), [68, 2432])
        declared = self.manifest["signature_lines"]["origin_name_lines"]
        by_len = {len(b): b[:4].hex() for b in blobs}
        self.assertEqual(by_len[68], declared["ed25519_note_signature_keyid"])
        self.assertEqual(by_len[2432], declared["ml_dsa_44_cosignature_shape_keyid"])

    def test_log_signature_verifies_and_quorum_is_met_without_the_origin_lines(self):
        # The carried keys verify the LIVE checkpoint: the log's note signature, and a 4-of-n
        # witness quorum from genuinely foreign witnesses — while both origin-name lines count
        # for nothing. The Ed25519 five suffice on every build; with [pq] the two ML-DSA witness
        # keys verify here too (fresh cosignatures, newer timestamps than the 7341 fixture).
        res = cp.verify_witnessed_checkpoint(self.note, self.log_vkey, self.witness_vkeys,
                                             threshold=4, expected_origin=_LIVE_ORIGIN)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["tree_size"], self.manifest["tree_size_at_retrieval"])
        n_ok = sum(1 for w in res["witnesses"].values() if w["ok"])
        self.assertEqual(n_ok, 7 if HAVE_MLDSA else 5)

    def test_a_fabricated_witness_vkey_under_the_live_origin_is_excluded(self):
        # Nobody publishes the log's own cosignature keys (by design), so the attack shape is a
        # ROSTER that lists some key under the origin name. Both algorithms, no backend needed.
        ed = generate_signer()
        ed_vkey = cp.cosign_vkey(_LIVE_ORIGIN, _raw(ed))
        fake_pub = b"\x00" * 1312
        pq_vkey = (_LIVE_ORIGIN + "+" + cp.cosign_key_id_mldsa(_LIVE_ORIGIN, fake_pub).hex() + "+"
                   + base64.b64encode(bytes([0x06]) + fake_pub).decode())
        ok, witnesses = cp.witness_quorum(self.note, [ed_vkey, pq_vkey], 1)
        self.assertFalse(ok)
        self.assertEqual(len(witnesses), 2)
        for entry in witnesses.values():
            self.assertFalse(entry["ok"])
            self.assertIs(entry.get("origin_excluded"), True)

    def test_the_logs_note_signature_key_is_never_a_witness(self):
        # The Ed25519 half of "self-signature in both algorithms" is the note signature (0x01);
        # it is excluded from witness quorums by construction — a log vkey is malformed AS a
        # witness key (domain separation), pinned here on the live vector.
        with self.assertRaises(BundleFormatError):
            cp.witness_quorum(self.note, [self.log_vkey], 1)


if __name__ == "__main__":
    unittest.main()
