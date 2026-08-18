"""ORIGIN-QUORUM RULE — a log does not vote in its own witness quorum.

Where this comes from: on 2026-08-16 a behaviour probe (report `20260816T0851Z`, section 8)
measured that `witness_quorum` counted a cosignature under the checked log's OWN origin name —
a self-cosigned mini-log satisfied `threshold=1` with nothing but its own signature. The C2SP
tlog-cosignature and tlog-witness specs are silent on the case (checked 2026-08-17), and the
affected log operator confirmed the intended reading in issue #7: his `/policy` declares the
quorum as `group independent-witnesses 4` with the log not a member, structural but never stated.

The rule lives where it binds, in `checkpoint.witness_quorum`, and after the 2026-08-17 Deep-Gate
re-gate it excludes a cosignature on EITHER of two operands the log does not choose: its key
material equals the audited log's own signing key (the robust, algorithm-agnostic test — the caller
passes it), or its name equals the origin line (exact codepoint; robust for ML-DSA-44, whose message
binds the name, defence-in-depth for Ed25519, whose cosignature/v1 message does not). The origin and every witness name must be printable-ASCII identities (`_origin_wellformed` /
`_witness_name_wellformed`), so no invisible or look-alike character can cloak the compare.
Honest limit: a separate cosign key under a non-origin alias is roster provenance, not a local check.
The operator's live checkpoint, self-signed under the origin name in both Ed25519 (note signature,
0x01) and ML-DSA-44 (cosignature shape), is the vendored test vector
(`tests/fixtures/anchors/markovian_log/checkpoint_7397/`), offered for exactly this purpose.

TestOriginQuorumRegression turns the 2026-08-16 finding into a property; TestOriginQuorumHardening
pins the 2026-08-17 re-gate findings (F-1 zero-width, F-2 key-material/relabel) on the surfaces that
share `witness_quorum` (`verify_witnessed_checkpoint`, `tlogproof.verify_tlog_proof`,
`public_transparency`).
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
        ok, witnesses = cp.witness_quorum(note, [wvkey], 1, log_key_material=None)
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
        ok, witnesses = cp.witness_quorum(note, [wvkey], 1, log_key_material=None)
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
        ok, witnesses = cp.witness_quorum(note, [cp.cosign_vkey("witness.example/w", _raw(w))], 1,
                                          log_key_material=None)
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
        ok, witnesses = cp.witness_quorum(note, [wvkey], 1, log_key_material=None)
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
            ok, witnesses = cp.witness_quorum(note, [wvkey], 1, log_key_material=None)
        self.assertFalse(ok)
        self.assertIs(next(iter(witnesses.values())).get("origin_excluded"), True)

    def test_the_comparison_is_exact(self):
        # A near-miss name is NOT the origin: it is either a DIFFERENT witness (visible near-misses:
        # prefix, suffix, uppercase, …) or a MALFORMED vkey (whitespace/zero-width near-misses, now
        # rejected at parse — the re-gate hardening). Neither is "excluded as the origin". Polarity:
        # pruefer(name) is True iff a vkey under `name` gets origin_excluded — True for the exact
        # origin only. A malformed near-miss raises rather than counting or excluding, so it maps to
        # False here (it is never accepted AS the origin), which is what the exactness property means.
        from _beinahe_treffer import pruefe_exakt  # noqa: PLC0415
        log_key = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
        probe_key = generate_signer()

        def wird_ausgeschlossen(name: str) -> bool:
            try:
                wv = cp.cosign_vkey(name, _raw(probe_key))   # malformed name now raises at BUILD too
                _, witnesses = cp.witness_quorum(note, [wv], 1, log_key_material=None)
            except BundleFormatError:
                return False    # malformed near-miss (whitespace/zero-width/empty) — never the origin
            return next(iter(witnesses.values())).get("origin_excluded", False) is True

        pruefe_exakt(wird_ausgeschlossen, ORIGIN, self)

    def test_unparseable_origin_named_vkey_still_raises(self):
        # Contract preservation: "an unparseable witness vkey raises" — the exclusion branch must
        # not swallow malformed input into a quiet non-count.
        note, _, _ = _self_cosigned_note()
        with self.assertRaises(BundleFormatError):
            cp.witness_quorum(note, [ORIGIN], 1, log_key_material=None)  # a bare name is not a vkey
        with self.assertRaises(BundleFormatError):
            # a 0x01 LOG key under the origin name stays rejected as malformed for a witness
            # role (domain separation), same as everywhere else
            log_key = generate_signer()
            cp.witness_quorum(note, [cp.vkey(ORIGIN, _raw(log_key))], 1, log_key_material=None)

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
        ok, witnesses = cp.witness_quorum(self.note, [ed_vkey, pq_vkey], 1, log_key_material=None)
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
            cp.witness_quorum(self.note, [self.log_vkey], 1, log_key_material=None)


class TestAllThreeIdentitySlotsAreHardened(unittest.TestCase):
    """Re-gate 2026-08-17: the first cut hardened origin and witness name but not the LOG KEY NAME —
    the third identity slot, encoded into the keyID. F-8 (raw UnicodeEncodeError out of the public
    verify API), F-10 (a zero-width log key name substitutes for a real one)."""

    def test_f10_zero_width_log_key_name_is_rejected(self):
        log = generate_signer()
        with self.assertRaises(BundleFormatError):
            cp.sign_checkpoint("log.example.com", 7, ROOT, log, "log​.example.com")   # ZWSP in keyname

    def test_f8_surrogate_name_never_raises_unicodeerror_from_key_helpers(self):
        log = generate_signer()
        sur = "log\ud800.example.com"          # lone surrogate — reaches name.encode("utf-8")
        for fn in (lambda: cp.key_id(sur, _raw(log)),
                   lambda: cp.vkey(sur, _raw(log)),
                   lambda: cp.cosign_key_id(sur, _raw(log)),
                   lambda: cp.cosign_vkey(sur, _raw(log)),
                   lambda: cp._parse_vkey(sur + "+deadbeef+"
                                          + base64.b64encode(bytes([1]) + _raw(log)).decode())):
            with self.subTest(fn=fn):
                with self.assertRaises(BundleFormatError):    # typed, never a raw UnicodeEncodeError
                    fn()

    def test_f8_verify_checkpoint_never_raises_unicodeerror_on_surrogate_log_vkey(self):
        log = generate_signer()
        note = cp.sign_checkpoint("log.example.com", 7, ROOT, log, "log.example.com")
        poison = "log\ud800+deadbeef+" + base64.b64encode(bytes([1]) + _raw(log)).decode()
        with self.assertRaises(BundleFormatError):            # not UnicodeEncodeError
            cp.verify_checkpoint(note, poison)

    def test_f10_invisible_log_key_name_cannot_substitute_for_a_real_one(self):
        # the trust-substitution shape: a poison vkey under a cloaked name must not verify a note the
        # real key signed, and must not let the poison identity pass as the honest one.
        log = generate_signer()
        note = cp.sign_checkpoint("log.example.com", 7, ROOT, log, "log.example.com")
        for cloaked in ("log​.example.com", "log .example.com", "log️.example.com"):
            with self.subTest(name=cloaked):
                with self.assertRaises(BundleFormatError):
                    cp.verify_checkpoint(note, cp.vkey(cloaked, _raw(log)))


class TestPublicTransparencyFailsClosedOnUnusableLogVkey(unittest.TestCase):
    """Re-gate F-9: a supplied-but-malformed log_vkey is 'not measurable', a third state — not 'no log
    context'. Reading its None as a pass silently switched off the key-material exclusion and let the
    log vote in its own quorum under an alias with errors=[]."""

    def _self_under_alias(self):
        log = generate_signer()
        origin = "log.example.com"
        note = cp.sign_checkpoint(origin, 7, ROOT, log, origin)
        note = cp.cosign_checkpoint(note, log, "independent-witness-1", TS)   # log key, alias name
        return note, log, cp.cosign_vkey("independent-witness-1", _raw(log))

    def test_malformed_log_vkey_fails_closed(self):
        from proofbundle.public_transparency import evaluate_public_transparency  # noqa: PLC0415
        note, log, alias = self._self_under_alias()
        for label, lv in (("truncated", "log.example.com+dead"),
                          ("surrogate", "log\ud800+deadbeef+"
                           + base64.b64encode(bytes([1]) + _raw(log)).decode())):
            with self.subTest(log_vkey=label):
                r = evaluate_public_transparency(note, {"witnessQuorum": {"threshold": 1}},
                                                 log_vkey=lv, witness_vkeys=[alias])
                self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "FAIL")
                self.assertEqual(r["PUBLIC_TRANSPARENCY"], "FAIL")
                self.assertTrue(r["errors"])

    def test_well_formed_log_vkey_excludes_the_self_witness(self):
        from proofbundle.public_transparency import evaluate_public_transparency  # noqa: PLC0415
        note, log, alias = self._self_under_alias()
        r = evaluate_public_transparency(note, {"witnessQuorum": {"threshold": 1}},
                                         log_vkey=cp.vkey("log.example.com", _raw(log)),
                                         witness_vkeys=[alias])
        self.assertEqual(r["statuses"]["WITNESS_QUORUM"], "FAIL")   # key-material prong excludes it


class TestCliCarriesTheExclusionReason(unittest.TestCase):
    """F-4: the CHANGELOG promises a relying party can tell 'excluded by rule' from 'signature
    invalid'. That only held in the library; verify-proof --json projected {ok, alg, timestamp} and
    dropped origin_excluded/detail — an origin-excluded witness and a bad-signature one printed
    byte-identically. This pins the reason into the machine-readable surface."""

    def test_json_witness_entry_carries_origin_excluded_and_detail(self):
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415
        from proofbundle import emit_bundle  # noqa: PLC0415
        from proofbundle.cli import main  # noqa: PLC0415
        from proofbundle.tlogproof import tlog_proof_for_bundle  # noqa: PLC0415

        log = generate_signer()
        payload = b'{"result": 1}'
        bundle = emit_bundle(payload, log, prior_leaves=[b"a", b"b", b"c"])
        root = base64.b64decode(bundle["merkle"]["root_b64"])
        note = cp.sign_checkpoint(ORIGIN, bundle["merkle"]["tree_size"], root, log, ORIGIN)
        note = cp.cosign_checkpoint(note, log, "independent.example/w", TS)   # log key under an alias
        proof = tlog_proof_for_bundle(bundle, note)
        dd = tempfile.mkdtemp()
        pf, lf = os.path.join(dd, "p.tlog-proof"), os.path.join(dd, "leaf.bin")
        pathlib.Path(pf).write_text(proof, encoding="utf-8")
        pathlib.Path(lf).write_bytes(payload)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                main(["verify-proof", pf, "--payload-file", lf,
                      "--log-vkey", cp.vkey(ORIGIN, _raw(log)),
                      "--witness-vkey", cp.cosign_vkey("independent.example/w", _raw(log)),
                      "--threshold", "1", "--json"])
            except SystemExit:
                pass
        out = json.loads(buf.getvalue())
        (w,) = out["witnesses"].values()
        self.assertFalse(w["ok"])
        self.assertIs(w.get("origin_excluded"), True)
        self.assertIn("key material", w["detail"])
        self.assertFalse(out["witnesses_ok"])


class TestOriginQuorumHardening(unittest.TestCase):
    """DEEP-GATE re-gate 2026-08-17: the name-only rule was bypassable. These pin the two operands the
    log does NOT choose — the log's key material, and a well-formed origin line — on the surfaces that
    have the log_vkey in hand (verify_witnessed_checkpoint / verify_tlog_proof). Each test names the
    finding it closes so a future weakening is caught by a failure that says why."""

    def _note_with_log_cosign(self, cosign_name, *, alg="ed25519"):
        """A note the log cosigns UNDER ``cosign_name`` with its OWN signing key (Ed25519) — the shape
        of a log trying to vote in its own quorum without an origin-named line."""
        log = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
        note = cp.cosign_checkpoint(note, log, cosign_name, TS)      # SAME key as the log signature
        return note, cp.vkey(ORIGIN, _raw(log)), cp.cosign_vkey(cosign_name, _raw(log)), log

    def test_f2_log_key_under_a_witness_alias_is_excluded(self):
        # F-2/F-2b: the log cosigns under a NON-origin alias with its own signing key. The name test
        # cannot see it (the name is not the origin); the key-material test must.
        note, log_vkey, alias_vkey, _ = self._note_with_log_cosign("independent.example/w")
        res = cp.verify_witnessed_checkpoint(note, log_vkey, [alias_vkey], threshold=1)
        self.assertFalse(res["witnesses_ok"], "the log voted in its own quorum under an alias")
        self.assertFalse(res["ok"])
        entry = next(iter(res["witnesses"].values()))
        self.assertIs(entry.get("origin_excluded"), True)
        self.assertIn("key material", entry["detail"])

    def test_f2_relabelled_ed25519_line_is_excluded(self):
        # F-2 exact: the Ed25519 cosignature/v1 message does not bind the cosigner name, so an
        # origin-named line can be relabelled under an alias WITHOUT the private key (keyID is public
        # SHA-256). The relabelled line still carries the log's key material and must not count.
        log = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
        note = cp.cosign_checkpoint(note, log, ORIGIN, TS)           # cosign under the origin name
        log_vkey = cp.vkey(ORIGIN, _raw(log))
        sig_block = note.split("\n\n", 1)[1]
        cosig = [ln for ln in sig_block.split("\n")
                 if ln.startswith("— ") and ln.split(" ", 2)[1] == ORIGIN][-1]
        blob = base64.b64decode(cosig.split(" ", 2)[2])
        alias = "independent.example/w"
        forged = cp.cosign_key_id(alias, _raw(log)) + blob[4:]       # no private key used
        logsig = [ln for ln in sig_block.split("\n")
                  if ln.startswith("— ") and ln.split(" ", 2)[1] == ORIGIN][0]
        forged_note = (note.split("\n\n", 1)[0] + "\n\n" + logsig
                       + "\n— " + alias + " " + base64.b64encode(forged).decode() + "\n")
        # precondition: the relabelled Ed25519 line really does verify (that is the whole danger)
        self.assertTrue(cp.verify_cosignature(forged_note, cp.cosign_vkey(alias, _raw(log)))["ok"])
        res = cp.verify_witnessed_checkpoint(forged_note, log_vkey,
                                             [cp.cosign_vkey(alias, _raw(log))], threshold=1)
        self.assertFalse(res["witnesses_ok"], "a relabelled log cosignature counted as a witness")
        self.assertFalse(res["ok"])

    def test_f2_inherited_by_tlogproof_surface(self):
        from proofbundle import emit_bundle  # noqa: PLC0415
        from proofbundle.tlogproof import tlog_proof_for_bundle, verify_tlog_proof  # noqa: PLC0415
        log = generate_signer()
        payload = b'{"result": 42}'
        bundle = emit_bundle(payload, log, prior_leaves=[b"a", b"b", b"c"])
        root = base64.b64decode(bundle["merkle"]["root_b64"])
        note = cp.sign_checkpoint(ORIGIN, bundle["merkle"]["tree_size"], root, log, ORIGIN)
        note = cp.cosign_checkpoint(note, log, "independent.example/w", TS)   # log key, alias name
        proof = tlog_proof_for_bundle(bundle, note)
        res = verify_tlog_proof(proof, payload, cp.vkey(ORIGIN, _raw(log)),
                                [cp.cosign_vkey("independent.example/w", _raw(log))], threshold=1)
        self.assertFalse(res["witnesses_ok"])
        self.assertFalse(res["ok"])
        self.assertTrue(res["log_ok"] and res["inclusion_ok"])       # precise verdicts

    def test_f1_zero_width_origin_is_malformed_at_verify(self):
        # F-1: an INVISIBLE (zero-width / format) character in the origin line let the log clone a
        # witness name it could then vote under. Such a note must not verify — the invisible-origin
        # guard now fires at verify time, not only at build time. Covers the four Cf classes the old
        # isspace() guard missed. Visible spaces and control chars are deliberately left to verify
        # (Go sumdb origins carry spaces; terminal neutralisation covers control chars; the
        # key-material exclusion is the robust defence for both — test_f1_visible_space below).
        log = generate_signer()
        clean = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
        for label, cloak in (("ZWSP", "\u200b"), ("ZWNJ", "\u200c"),
                             ("BOM", "\ufeff"), ("word-joiner", "\u2060")):
            cloaked = ORIGIN + cloak
            with self.subTest(cloak=label):
                with self.assertRaises(BundleFormatError):          # builder refuses to make one
                    cp.sign_checkpoint(cloaked, 7, ROOT, log, cloaked)
                forged = clean.replace(ORIGIN + "\n", cloaked + "\n", 1)   # hand-forged note
                with self.assertRaises(BundleFormatError):
                    cp.verify_checkpoint(forged, cp.vkey(cloaked, _raw(log)))

    def test_f5_origin_self_cloaking_is_the_whole_class(self):
        # Re-gate F-5, the decisive one: the cloak sits in the LOG'S OWN origin line (not the
        # witness name) — the log appends a character so origin != the (clean) witness name the
        # roster lists, and the exclusion is escaped. Each round patched one Unicode category;
        # the printable-ASCII rule closes the class. Each of these is refused as a malformed
        # origin, including a PLAIN ASCII SPACE (the earlier carve-out F-5 exploited) and a
        # Default-Ignorable letter.
        log = generate_signer()
        clean = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
        for label, suffix in (("appended-space", " "), ("hangul-filler", "\u3164"),
                              ("variation-selector", "\ufe0f"), ("combining-mark", "\u0301"),
                              ("zero-width", "\u200b"), ("nbsp", "\u00a0"),
                              ("non-ascii-letter", "\u0430")):
            with self.subTest(cloak=label):
                cloaked = ORIGIN + suffix
                with self.assertRaises(BundleFormatError):        # builder refuses it
                    cp.sign_checkpoint(cloaked, 7, ROOT, log, cloaked)
                forged = clean.replace(ORIGIN + "\n", cloaked + "\n", 1)
                with self.assertRaises(BundleFormatError):        # and verify refuses it
                    cp.verify_checkpoint(forged, cp.vkey(cloaked, _raw(log)))

    def test_f1_origin_wellformed_builder_helper(self):
        self.assertTrue(cp._origin_wellformed("markovianprotocol.com/log"))
        self.assertTrue(cp._origin_wellformed("a.b.c/d-e_f"))
        self.assertTrue(cp._origin_wellformed("go.sum database tree"))   # internal single spaces OK
        for bad in ("", "a+b", "a  b", "a\tb", "a\u200bb", "a\ufeffb",   # '+' / double / zw
                    " a", "a ", "a\u00a0b", "a\u3164b", "a\ufe0fb", "caf\u00e9/x"):  # nbsp/DI/VS/non-ascii
            self.assertFalse(cp._origin_wellformed(bad), repr(bad))

    def test_f1_nbsp_and_zero_width_in_a_witness_name_are_rejected(self):
        # Re-gate neighbour of F-1: the cloak can sit in the WITNESS NAME, not only the origin line.
        # A name carrying NBSP (Zs, isspace) or ZWSP (Cf) looks identical to the origin yet is
        # byte-different, so the name compare would miss it. _parse_witness_vkey now rejects such a
        # name (the emit path always did) — the vkey is malformed, so the line cannot count.
        log = generate_signer()
        for label, cloaked in (("NBSP", ORIGIN + " "), ("ZWSP", ORIGIN + "​"),
                               ("ideographic-space", ORIGIN + "　"), ("tab", ORIGIN + "\t")):
            with self.subTest(name=label):
                w = generate_signer()
                with self.assertRaises(BundleFormatError):
                    cp._parse_witness_vkey(cp.cosign_vkey(cloaked, _raw(w)))
                # end-to-end: a hand-forged line under such a name does not survive the quorum
                note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
                with self.assertRaises(BundleFormatError):
                    cp.witness_quorum(note, [cp.cosign_vkey(cloaked, _raw(w))], 1,
                                      log_key_material=_raw(log))

    def test_plain_space_origin_still_verifies_but_never_equals_a_witness(self):
        # The one allowed whitespace (U+0020) keeps Go sumdb-style origins verifying, and such an
        # origin can never equal a witness name (names carry no space at all), so it is never excluded
        # by the name test — measured, not assumed.
        self.assertTrue(cp._origin_wellformed("go.sum database tree"))
        self.assertTrue(cp._origin_wellformed("go.sum database"))          # no trailing/DI here -> OK
        with self.assertRaises(BundleFormatError):                           # a spaced witness name is malformed
            cp._parse_witness_vkey(cp.cosign_vkey("go.sum database tree", _raw(generate_signer())))

    def test_key_material_exclusion_needs_the_log_context(self):
        # Honest scope: the material test only fires when the caller supplies log_key_material. An explicit
        # log_key_material=None (no log context) applies the NAME test only — documented, and the public
        # surfaces always pass the material. This pins that a genuinely independent witness with a
        # DIFFERENT key is never excluded by the rule.
        log = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
        w = generate_signer()
        note = cp.cosign_checkpoint(note, w, "real.example/w", TS)
        ok, witnesses = cp.witness_quorum(note, [cp.cosign_vkey("real.example/w", _raw(w))], 1,
                                          log_key_material=_raw(log))
        self.assertTrue(ok, "an independent witness was wrongly excluded by key material")
        self.assertNotIn("origin_excluded", next(iter(witnesses.values())))

    def test_d1_log_key_material_is_a_required_keyword(self):
        # DEEP-GATE 4.0.0 D1: witness_quorum used to DEFAULT log_key_material=None, so a BARE call ran the
        # NAME test only — a log voting under an ALIAS with its own key (name != origin) was counted. The
        # material prong is the robust half; the caller must now make the choice VISIBLE (pass the log key
        # material for the full rule, or an explicit None to opt into the documented name-only mode). No
        # silent weak default. The three shipped surfaces already pass it; this pins the primitive's API.
        log = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log, ORIGIN)
        note = cp.cosign_checkpoint(note, log, "independent.example/w", TS)   # log key, alias name
        wv = cp.cosign_vkey("independent.example/w", _raw(log))
        with self.assertRaises(TypeError):
            cp.witness_quorum(note, [wv], 1)                          # no log_key_material -> required
        ok, witnesses = cp.witness_quorum(note, [wv], 1, log_key_material=_raw(log))
        self.assertFalse(ok, "the alias self-vote counted once the material was supplied")
        self.assertIs(next(iter(witnesses.values())).get("origin_excluded"), True)


if __name__ == "__main__":
    unittest.main()
