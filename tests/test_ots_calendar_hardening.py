"""OTS hardening + calendar-risk (WP-A/B/C/D) — the anchor-longevity moat, hardened against the four
adversarial questions an external audit asks about OpenTimestamps' donation-financed calendars:

  * Calendar OUTAGE — does a defunded/offline calendar remove the ability to VERIFY existing proofs?
    No: an UPGRADED proof is calendar-independent and verifies offline against a relying-party Bitcoin
    header, proven here with the socket module blocked (no network) and no calendar supplied.
  * Calendar COLLUSION / BACKDATING — can a malicious producer self-certify by bundling its own header?
    No: the pack's own bundled/frozen header is never trust (WP-A1); confirmation needs a relying-party
    header, so a bundled-header-only pack is needs_rp_trust, never a pass.
  * PENDING never PASS — a not-yet-Bitcoin-anchored proof is refused at the CLI (exit 3), never packed.
  * SINGLE POINT OF FAILURE — operator redundancy (distinct OPERATORS, not URLs) is surfaced honestly from
    what the proof carries (provenCalendars) as an embedded-but-UNVERIFIED transparency figure, NOT
    cryptographic evidence (a PendingAttestation URI is offline-constructible); producer-declared calendars
    are recorded as testimony with verified:false and never counted as redundancy (Berkeley audit
    2026-07-16, corrected 2026-07-17).

WP-D1: the confirmed/self-contained path is exercised by a SYNTHETIC, SHA-256-only fixture that
deserializes WITHOUT ripemd160 — so it runs in the 3.6.0 cleanroom pytest where the ripemd160-gated
external vector (hello-world.txt.ots) is honestly skipped.
"""
from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

from proofbundle import cli

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "ots"
_SYNTH = "synthetic-upgraded-sha256"
_ROOT = hashlib.sha256(b"ots-canonical-root").digest()


def _serialize(dtf) -> bytes:
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


def _pending_proof(msg=_ROOT, uris=("https://a.pool.opentimestamps.org",)) -> bytes:
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    for u in uris:
        ts.attestations.add(PendingAttestation(u))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _upgraded_proof(msg=_ROOT, height=800000) -> bytes:
    # Null-Op hardening (2026-07-17): attest at the END of a real op chain (append a nonce, then SHA-256)
    # below the file digest, so the attested block merkle root != file_digest — not a refused leaf==root
    # Null-Op. (The CONFIRMED-path tests in this file use the provenance-pinned synthetic FIXTURE, whose
    # relying-party header is the .block.json merkle root; this helper feeds only describe/build/uris tests.)
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    leaf = ts.ops.add(OpAppend(b"\x00")).ops.add(OpSHA256())
    leaf.attestations.add(BitcoinBlockHeaderAttestation(height))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _upgraded_proof_retaining_pending(msg=_ROOT, height=800000,
                                      uris=("https://a.pool.opentimestamps.org",
                                            "https://a.pool.eternitywall.com")) -> bytes:
    """An upgraded proof that also retains PendingAttestations on distinct operators, so the embedded
    calendar set (proof-carried operator-redundancy count) is non-empty. The Bitcoin attestation sits at the
    end of a REAL op chain (not a leaf==root Null-Op); the pending attestations are FABRICATED OFFLINE here
    from arbitrary URIs — which is precisely why the embedded count is UNVERIFIED transparency, not
    cryptographic evidence."""
    from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,
                                            PendingAttestation)
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    leaf = ts.ops.add(OpAppend(b"\x00")).ops.add(OpSHA256())
    leaf.attestations.add(BitcoinBlockHeaderAttestation(height))
    for u in uris:
        ts.attestations.add(PendingAttestation(u))
    return _serialize(DetachedTimestampFile(OpSHA256(), ts))


def _run(argv):
    """Run the CLI, return (exit_code, stdout). stderr is swallowed (errors go there)."""
    out = io.StringIO()
    err = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(argv)
    except SystemExit as exc:   # argparse errors exit(2)
        rc = exc.code if isinstance(exc.code, int) else 2
    return rc, out.getvalue()


# ── WP-B1: calendar transparency (no [anchors] extra needed for the operator heuristic) ──────────────
class TestCalendarOperatorHeuristic(unittest.TestCase):
    def test_known_operators_mapped(self):
        from proofbundle.anchors_ots import calendar_operator
        self.assertEqual(calendar_operator("https://a.pool.opentimestamps.org"), "opentimestamps")
        self.assertEqual(calendar_operator("https://b.pool.opentimestamps.org"), "opentimestamps")
        self.assertEqual(calendar_operator("https://a.pool.eternitywall.com"), "eternitywall")
        self.assertEqual(calendar_operator("https://alice.calendar.catallaxy.com"), "catallaxy")

    def test_two_urls_one_operator_is_one_point_of_failure(self):
        # the property that matters: a/b.pool.opentimestamps.org is ONE operator, not two.
        from proofbundle.anchors_ots import calendar_operators
        ops = calendar_operators(["https://a.pool.opentimestamps.org",
                                  "https://b.pool.opentimestamps.org"])
        self.assertEqual(ops, ["opentimestamps"])   # two URLs, one operator

    def test_two_operators_is_real_redundancy(self):
        from proofbundle.anchors_ots import calendar_operators
        ops = calendar_operators(["https://a.pool.opentimestamps.org",
                                  "https://a.pool.eternitywall.com"])
        self.assertEqual(ops, ["eternitywall", "opentimestamps"])

    def test_unknown_host_still_counts_as_distinct_operator(self):
        from proofbundle.anchors_ots import calendar_operator
        # a self-hosted / third-party calendar (WP-B2 own-calendar path) still counts as its own operator
        self.assertEqual(calendar_operator("https://ots.example.org"), "example.org")

    def test_garbage_never_raises(self):
        from proofbundle.anchors_ots import calendar_operator
        for bad in (None, "", 123, "not a url"):
            self.assertIsInstance(calendar_operator(bad), str)   # never raises


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestCalendarUrisFromProof(unittest.TestCase):
    def test_pending_proof_surfaces_its_calendars(self):
        from proofbundle.anchors_ots import calendar_operators, calendar_uris
        proof = _pending_proof(uris=("https://a.pool.opentimestamps.org",
                                     "https://a.pool.eternitywall.com"))
        self.assertEqual(calendar_uris(proof),
                         ["https://a.pool.eternitywall.com", "https://a.pool.opentimestamps.org"])
        self.assertEqual(calendar_operators(calendar_uris(proof)), ["eternitywall", "opentimestamps"])

    def test_upgraded_proof_has_no_calendar_dependency(self):
        from proofbundle.anchors_ots import calendar_uris
        # calendar-independence, surfaced: an upgraded proof retains no pending calendar attestation.
        self.assertEqual(calendar_uris(_upgraded_proof()), [])

    def test_malformed_proof_returns_empty_never_raises(self):
        from proofbundle.anchors_ots import calendar_uris
        self.assertEqual(calendar_uris(b"not an ots proof"), [])


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestDescribeProofLifecycle(unittest.TestCase):
    def test_states(self):
        from proofbundle.evidence_pack import describe_proof
        self.assertEqual(describe_proof(_pending_proof())["state"], "pending")
        up = describe_proof(_upgraded_proof())
        self.assertEqual(up["state"], "upgraded")
        self.assertTrue(up["selfContained"])
        self.assertEqual(up["bitcoinHeights"], [800000])
        self.assertEqual(describe_proof(b"garbage")["state"], "malformed")

    def test_pack_records_proven_operator_redundancy(self):
        # the operator-redundancy count is read from the proof's OWN retained attestations (three URLs
        # across two hostname operators) — an embedded-but-UNVERIFIED transparency figure (the URIs are
        # offline-constructible), not cryptographic evidence.
        from proofbundle.evidence_pack import build_evidence_pack
        proof = _upgraded_proof_retaining_pending(
            uris=("https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org",
                  "https://a.pool.eternitywall.com"))
        pack = build_evidence_pack(_ROOT, proof)
        self.assertEqual(len(pack["provenCalendars"]), 3)        # three URLs, proof-derived
        self.assertEqual(pack["operatorRedundancy"], 2)          # but only two INDEPENDENT operators
        self.assertEqual(pack["provenCalendarOperators"], ["eternitywall", "opentimestamps"])


# ── WP-D1: the synthetic, ripemd160-free confirmed-path fixture runs UNCONDITIONALLY ────────────────
class TestSyntheticFixtureIntegrity(unittest.TestCase):
    def test_synthetic_fixture_is_provenance_pinned(self):
        prov = json.loads((FIXTURE_DIR / "PROVENANCE.json").read_text())
        pins = {e["filename"]: e["sha256"] for e in prov["files"]}
        for name in (f"{_SYNTH}.txt", f"{_SYNTH}.txt.ots", f"{_SYNTH}.block.json"):
            self.assertIn(name, pins, f"{name} must be pinned in PROVENANCE.json")
            actual = hashlib.sha256((FIXTURE_DIR / name).read_bytes()).hexdigest()
            self.assertEqual(actual, pins[name], f"{name} does not match its provenance pin")

    def test_synthetic_fixture_marked_generated_not_external(self):
        # No-Fake: this fixture must be honestly labelled synthetic/proofbundle-generated, NOT a
        # vendored external vector (its "block" is not a real Bitcoin block).
        prov = json.loads((FIXTURE_DIR / "PROVENANCE.json").read_text())
        entry = next(e for e in prov["files"] if e["filename"] == f"{_SYNTH}.txt.ots")
        self.assertIn("synthetic", (entry.get("source_ref_or_commit", "") + entry.get("note", "")).lower())


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestSyntheticConfirmedPathNoRipemd(unittest.TestCase):
    """The WP-D1 win: a CONFIRMED/self-contained OTS proof verified offline, with NO ripemd160 skip —
    this class runs where TestOtsConfirmedPathExternalVector (hello-world) is skipped."""

    def setUp(self):
        self.target = (FIXTURE_DIR / f"{_SYNTH}.txt").read_bytes()
        self.proof = (FIXTURE_DIR / f"{_SYNTH}.txt.ots").read_bytes()
        self.block = json.loads((FIXTURE_DIR / f"{_SYNTH}.block.json").read_text())
        self.root = hashlib.sha256(self.target).digest()
        self.rp = {"bitcoin_block_headers": {str(self.block["height"]):
                                             self.block["merkle_root_internal_le_hex"]}}

    def test_confirmed_offline_against_rp_header(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(self.proof, self.root, frozen={}, rp_trust=self.rp)
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")
        self.assertEqual(res["trustedTime"], {"source": "bitcoin_block", "height": self.block["height"]})

    def test_no_rp_header_is_honest_not_pass(self):
        from proofbundle.anchors_ots import verify_opentimestamps
        res = verify_opentimestamps(self.proof, self.root, frozen={})
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "needs_rp_trust")

    def test_self_contained(self):
        from proofbundle.evidence_pack import ots_upgraded_proof_is_self_contained
        self.assertTrue(ots_upgraded_proof_is_self_contained(self.proof))


# ── Adversarial: calendar outage + collusion/backdating, at the pack level ──────────────────────────
@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestAdversarialCalendarRisk(unittest.TestCase):
    def _pack_from_synth(self, bundled_headers=None, declared=None):
        from proofbundle.evidence_pack import build_evidence_pack
        target = (FIXTURE_DIR / f"{_SYNTH}.txt").read_bytes()
        proof = (FIXTURE_DIR / f"{_SYNTH}.txt.ots").read_bytes()
        root = hashlib.sha256(target).digest()
        return build_evidence_pack(root, proof, declared_calendars=declared,
                                   bundled_headers=bundled_headers), root

    def test_calendar_outage_verify_needs_no_network_no_calendar(self):
        # OUTAGE: block the socket module; a self-contained pack must still confirm offline.
        import socket
        from proofbundle.evidence_pack import verify_evidence_pack
        pack, root = self._pack_from_synth()
        # Null-Op hardening: the fixture now attests the block merkle root at the end of a real op chain, so
        # the relying-party header is the .block.json merkle root (NOT the file digest root.hex()).
        block = json.loads((FIXTURE_DIR / f"{_SYNTH}.block.json").read_text())
        rp = {"bitcoin_block_headers": {str(block["height"]): block["merkle_root_internal_le_hex"]}}
        real = socket.socket

        def _bomb(*a, **k):
            raise AssertionError("offline verify must not open a socket")

        socket.socket = _bomb  # type: ignore[assignment]
        try:
            res = verify_evidence_pack(pack, rp_trust=rp)
        finally:
            socket.socket = real  # type: ignore[assignment]
        self.assertTrue(res["ok"], res["detail"])
        self.assertEqual(res["status"], "confirmed")

    def test_collusion_backdating_bundled_header_alone_never_confirms(self):
        # COLLUSION/BACKDATING: a producer bundles its OWN header (even the correct value). Without a
        # relying-party header it must NOT confirm — the whole WP-A1 point (no self-certification).
        from proofbundle.evidence_pack import verify_evidence_pack
        correct_root = hashlib.sha256((FIXTURE_DIR / f"{_SYNTH}.txt").read_bytes()).hexdigest()
        pack, _ = self._pack_from_synth(bundled_headers={"800000": correct_root})
        self.assertTrue(pack["bundledHeaderEvidence"])
        res = verify_evidence_pack(pack)   # no rp_trust — producer alone
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "needs_rp_trust")
        self.assertTrue(res["frozenEvidence"])   # the bundled header is reported as evidence, not trust

    def test_upgraded_no_pending_pack_proves_zero_redundancy_honestly(self):
        # No-Fake: the synthetic upgraded proof retains no pending attestation, so it PROVES no calendar
        # redundancy (0) — the honest state after upgrade, not a hidden or inflated number.
        pack, _ = self._pack_from_synth()
        self.assertEqual(pack["operatorRedundancy"], 0)
        self.assertEqual(pack["provenCalendars"], [])

    def test_declared_calendar_is_recorded_unverified_never_as_redundancy(self):
        # a producer declares one calendar; it is recorded as testimony (verified:false) and does NOT
        # become proven operator redundancy.
        pack, _ = self._pack_from_synth(declared=["https://a.pool.opentimestamps.org"])
        self.assertEqual(pack["operatorRedundancy"], 0)                        # proven, unmoved
        self.assertEqual(pack["declaredCalendars"], ["https://a.pool.opentimestamps.org"])
        self.assertFalse(pack["declaredCalendarsVerified"])


# ── CLI: the anchor group lifecycle + exit contract ─────────────────────────────────────────────────
@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestAnchorCliContract(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.synth_proof = str(FIXTURE_DIR / f"{_SYNTH}.txt.ots")
        self.synth_target = str(FIXTURE_DIR / f"{_SYNTH}.txt")
        block = json.loads((FIXTURE_DIR / f"{_SYNTH}.block.json").read_text())
        self.height = block["height"]
        self.mr = block["merkle_root_internal_le_hex"]

    def _write(self, name, data: bytes) -> str:
        p = Path(self.dir) / name
        p.write_bytes(data)
        return str(p)

    def test_upgrade_pending_refused_exit3_writes_nothing(self):
        target = b"pending target\n"
        pp = self._write("p.ots", _pending_proof(hashlib.sha256(target).digest()))
        tf = self._write("p.txt", target)
        out = str(Path(self.dir) / "should_not_exist.json")
        rc, txt = _run(["anchor", "upgrade", "--proof", pp, "--target-file", tf, "--out", out])
        self.assertEqual(rc, 3, txt)
        self.assertFalse(Path(out).exists(), "a pending proof must never write a self-contained pack")

    def test_upgrade_upgraded_writes_selfcontained_pack_exit0(self):
        out = str(Path(self.dir) / "pack.json")
        rc, txt = _run(["anchor", "upgrade", "--proof", self.synth_proof,
                        "--target-file", self.synth_target,
                        "--calendar-declared", "https://a.pool.opentimestamps.org",
                        "--calendar-declared", "https://a.pool.eternitywall.com",
                        "--out", out, "--json"])
        self.assertEqual(rc, 0, txt)
        pack = json.loads(Path(out).read_text())
        self.assertTrue(pack["selfContained"])
        # declared calendars are producer testimony (verified:false) — recorded, never proven redundancy.
        self.assertEqual(pack["operatorRedundancy"], 0)          # proven: the synth proof retains none
        self.assertEqual(len(pack["declaredCalendars"]), 2)
        self.assertFalse(pack["declaredCalendarsVerified"])

    def test_upgrade_wrong_root_is_unbound_exit2(self):
        out = str(Path(self.dir) / "nope.json")
        rc, _ = _run(["anchor", "upgrade", "--proof", self.synth_proof,
                      "--canonical-root-hex", "00" * 32, "--out", out])
        self.assertEqual(rc, 2)
        self.assertFalse(Path(out).exists())

    def test_verify_pack_confirmed_exit0(self):
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        rc, txt = _run(["anchor", "verify-pack", out, "--bitcoin-header", f"{self.height}:{self.mr}"])
        self.assertEqual(rc, 0, txt)
        self.assertIn("CONFIRMED", txt)

    def test_verify_pack_without_header_exit3(self):
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        rc, txt = _run(["anchor", "verify-pack", out])
        self.assertEqual(rc, 3, txt)   # honest not-pass: relying-party header missing

    def test_verify_pack_wrong_header_exit1(self):
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        rc, txt = _run(["anchor", "verify-pack", out, "--bitcoin-header", f"{self.height}:{'00' * 32}"])
        self.assertEqual(rc, 1, txt)   # present-and-wrong is a hard fail, never silent

    def test_verify_pack_malformed_input_exit2(self):
        bad = self._write("bad.json", b"{ not json")
        rc, _ = _run(["anchor", "verify-pack", bad])
        self.assertEqual(rc, 2)

    def test_verify_pack_recomputes_calendar_fields_from_proof_not_json(self):
        # No-Fake (2026-07-17): verify-pack must RECOMPUTE the calendar / self-contained fields from the
        # proof bytes and never echo the pack's own JSON. Build a real upgraded pack (proof retains NO
        # pending → embedded redundancy 0, self-contained True), then HAND-MANIPULATE the JSON to fabricate
        # operatorRedundancy=3 with three operators and flip selfContained=False. The authoritative report
        # must show the RECOMPUTED values (0 / [] / True), not the tampered ones — while still confirming.
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        pack = json.loads(Path(out).read_text())
        pack["operatorRedundancy"] = 3
        pack["provenCalendars"] = ["https://evil-a.example", "https://evil-b.example",
                                   "https://evil-c.example"]
        pack["provenCalendarOperators"] = ["evil-a.example", "evil-b.example", "evil-c.example"]
        pack["selfContained"] = False   # tampered — the real upgraded proof IS self-contained
        Path(out).write_text(json.dumps(pack))
        rc, txt = _run(["anchor", "verify-pack", out, "--bitcoin-header", f"{self.height}:{self.mr}",
                        "--json"])
        self.assertEqual(rc, 0, txt)   # still confirms against the relying-party header
        report = json.loads(txt)
        self.assertEqual(report["operatorRedundancy"], 0, "must recompute from proof, not echo JSON")
        self.assertEqual(report["provenCalendars"], [])
        self.assertEqual(report["provenCalendarOperators"], [])
        self.assertTrue(report["selfContained"], "self-contained recomputed from the proof bytes")
        self.assertEqual(report["status"], "confirmed")

    def test_inspect_pending_shows_operators_exit0(self):
        pp = self._write("pend.ots", _pending_proof(uris=("https://a.pool.opentimestamps.org",
                                                          "https://a.pool.eternitywall.com")))
        rc, txt = _run(["anchor", "inspect", pp])
        self.assertEqual(rc, 0)
        self.assertIn("pending", txt)
        self.assertIn("operator redundancy 2", txt)

    def test_inspect_pack_json_exit0(self):
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        rc, txt = _run(["anchor", "inspect", out, "--json"])
        self.assertEqual(rc, 0)
        info = json.loads(txt)
        self.assertEqual(info["state"], "upgraded")
        self.assertEqual(info["source"], "evidence_pack")

    def test_inspect_pack_surfaces_declared_as_unverified_never_as_redundancy(self):
        # No-Fake: an upgraded proof retains no calendars → proven operatorRedundancy 0; a producer's
        # declared calendars are surfaced SEPARATELY and flagged unverified, never counted as redundancy.
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--calendar-declared", "https://a.pool.opentimestamps.org",
              "--calendar-declared", "https://a.pool.eternitywall.com", "--out", out])
        rc, txt = _run(["anchor", "inspect", out, "--json"])
        self.assertEqual(rc, 0)
        info = json.loads(txt)
        self.assertEqual(info["operatorRedundancy"], 0)                # proven, not inflated by declared
        self.assertEqual(info["provenCalendars"], [])
        self.assertEqual(len(info["declaredCalendars"]), 2)
        self.assertFalse(info["declaredCalendarsVerified"])

    # ── WP-A1.c red-tests (2026-07-17): the 6-lens re-review's live-reproduced CRITICAL + siblings ──────
    def _write_null_op_attack_pack(self, height=400000, value_hex="aa" * 32) -> str:
        # the exact live-repro attack: a Null-Op pack where file_digest == canonicalRoot == the attested
        # value == the supplied header, with the BitcoinBlockHeaderAttestation planted DIRECTLY on the root
        # (leaf==root, no op chain). A genuine Bitcoin timestamp can never have this shape.
        import base64
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        root = bytes.fromhex(value_hex)
        ts = Timestamp(root)
        ts.attestations.add(BitcoinBlockHeaderAttestation(height))
        proof = _serialize(DetachedTimestampFile(OpSHA256(), ts))
        pack = {"type": "opentimestamps-evidence-pack", "packVersion": "v0.2",
                "canonicalRoot": base64.b64encode(root).decode(),
                "proof": base64.b64encode(proof).decode(), "selfContained": True}
        return self._write("attack_pack.json", json.dumps(pack).encode())

    def test_verify_pack_null_op_attack_never_confirms(self):
        # FIX1 red-test: the self-fabricated Null-Op pack must NOT confirm, even with the matching header a
        # producer supplies. Previously this returned ok:true / CONFIRMED / exit 0.
        pack = self._write_null_op_attack_pack()
        rc, txt = _run(["anchor", "verify-pack", pack, "--bitcoin-header", f"400000:{'aa' * 32}", "--json"])
        self.assertNotEqual(rc, 0, txt)                        # never exit 0 / CONFIRMED
        report = json.loads(txt)
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "null_op")

    def test_verify_pack_canonical_require_anchor_path_unaffected(self):
        # the canonical `verify --require-anchor` path is NOT this surface and must stay green: a genuine
        # upgraded pack still confirms via verify-pack against the fixture's relying-party header.
        out = str(Path(self.dir) / "genuine.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        rc, txt = _run(["anchor", "verify-pack", out, "--bitcoin-header", f"{self.height}:{self.mr}"])
        self.assertEqual(rc, 0, txt)
        self.assertIn("CONFIRMED", txt)

    def test_inspect_forces_declared_verified_false_even_if_pack_claims_true(self):
        # FIX3 red-test: a hand-edited pack claiming declaredCalendarsVerified:true must be shown False
        # (consistent with verify-pack). Previously inspect echoed the tampered true verbatim.
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--calendar-declared", "https://a.pool.opentimestamps.org", "--out", out])
        pack = json.loads(Path(out).read_text())
        pack["declaredCalendarsVerified"] = True   # tamper
        Path(out).write_text(json.dumps(pack))
        rc, txt = _run(["anchor", "inspect", out, "--json"])
        self.assertEqual(rc, 0, txt)
        info = json.loads(txt)
        self.assertFalse(info["declaredCalendarsVerified"])   # forced False, never mirrored

    def test_inspect_does_not_echo_raw_packSelfContained_field(self):
        # FIX4 red-test: a hand-edited pack setting selfContained:false must NOT surface a raw
        # packSelfContained; only the authoritative recomputed selfContained (True) is reported.
        out = str(Path(self.dir) / "pack.json")
        _run(["anchor", "upgrade", "--proof", self.synth_proof, "--target-file", self.synth_target,
              "--out", out])
        pack = json.loads(Path(out).read_text())
        pack["selfContained"] = False   # tamper
        Path(out).write_text(json.dumps(pack))
        rc, txt = _run(["anchor", "inspect", out, "--json"])
        self.assertEqual(rc, 0, txt)
        info = json.loads(txt)
        self.assertNotIn("packSelfContained", info)           # the raw echo field is gone
        self.assertTrue(info["selfContained"])                # recomputed from the proof bytes


# ── WP-E: the readiness-pack calendar-independence paragraph exists and stays claims-hygiene-clean ───
class TestReadinessPackCalendarIndependence(unittest.TestCase):
    REPO = Path(__file__).resolve().parents[1]

    def test_paragraph_doc_exists_with_the_four_facts(self):
        doc = self.REPO / "docs" / "readiness_pack" / "calendar_independence.md"
        self.assertTrue(doc.is_file(), "WP-E readiness-pack paragraph doc must exist")
        text = doc.read_text(encoding="utf-8").lower()
        for needle in ("calendar-independent", "donation", "bitcoin header", "rfc 3161"):
            self.assertIn(needle, text, f"WP-E paragraph must state: {needle!r}")

    def test_doc_is_claims_hygiene_clean(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "claims_hygiene_check", self.REPO / "scripts" / "claims_hygiene_check.py")
        ch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ch)
        doc = self.REPO / "docs" / "readiness_pack" / "calendar_independence.md"
        self.assertEqual(ch.scan_file(doc), [], "WP-E paragraph must carry no un-negated overclaim")


# ── No-Fake follow-up (2026-07-17): verify-pack never mirrors a hand-edited pack's trust fields ──────
# Runs WITHOUT the [anchors] extra: a bogus proof takes the safe-zeros recompute path, which is exactly
# where a hand-edited pack would otherwise have leaked its own claims into the authoritative report.
class TestVerifyPackNeverMirrorsHandEditedTrustFields(unittest.TestCase):
    def _run(self, pack: dict) -> dict:
        import argparse
        d = tempfile.mkdtemp()
        pk = Path(d) / "pack.json"
        pk.write_text(json.dumps(pack), encoding="utf-8")
        ns = argparse.Namespace(pack=str(pk), bitcoin_header=None, json=True)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli._cmd_anchor_verify_pack(ns)
        return json.loads(buf.getvalue())

    def test_declared_verified_forced_false_and_calendar_fields_recomputed(self):
        # A pack claiming declaredCalendarsVerified:true + operatorRedundancy:3 + fabricated provenCalendars
        # must NOT be echoed: declaredCalendarsVerified is forced False and the calendar figures recompute
        # to zeros from the (bogus) proof bytes — the report reflects the proof, never the JSON's claims.
        out = self._run({"type": "opentimestamps-evidence-pack", "proof": "AAAA",
                         "declaredCalendars": ["https://evil.example"], "declaredCalendarsVerified": True,
                         "operatorRedundancy": 3, "provenCalendars": ["fabricated"],
                         "provenCalendarOperators": ["evil"], "selfContained": True})
        self.assertFalse(out["declaredCalendarsVerified"], "declared is unverified by definition — never mirrored")
        self.assertEqual(out["operatorRedundancy"], 0, "operatorRedundancy must recompute, not echo the pack")
        self.assertEqual(out["provenCalendars"], [])
        self.assertEqual(out["provenCalendarOperators"], [])
        self.assertFalse(out["selfContained"])


if __name__ == "__main__":
    unittest.main()
