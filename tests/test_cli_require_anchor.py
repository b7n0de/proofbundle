"""WP4 — the ``verify --require-anchor`` relying-party gate (additive, non-breaking).

``--require-anchor`` (optionally narrowed by ``--anchor-type``) turns "this receipt carries a verifying
external time anchor" into a requirement layered OVER the crypto result, exactly like ``--policy``:
unmet → exit 3 (a policy failure, distinct from a crypto failure exit 1). It is wired to the existing
``proofbundle.anchors`` layer, never a parallel reimplementation. Without the flag the receipt's anchors
are not evaluated at all — the default behaviour is unchanged, which the last test pins explicitly.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import anchors, generate_signer
from proofbundle.cli import _verify_exit_code, main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _write(bundle) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def _plain_bundle_file() -> str:
    from proofbundle import emit_bundle
    return _write(emit_bundle(b'{"x": 1}', generate_signer()))


def _receipt_with_anchor(anchor_type: str, proof: bytes, *, prereg=b"my eval protocol\n") -> str:
    """An eval receipt that carries a preRegistration-target anchor of ``anchor_type`` over its own
    prereg root. The preRegistration root needs no RFC 8785 canonicalizer (it is the signed
    prereg_sha256), so this test file has no optional-extra dependency."""
    h = hashlib.sha256(prereg).hexdigest()
    claim, _salts = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=10, model_id="m", dataset_id="d", issuer="Lab",
        timestamp="2026-07-02T00:00:00Z", prereg_sha256=h)
    receipt = emit_eval_receipt(claim, generate_signer())
    receipt["anchors"] = [{
        "type": anchor_type, "target": "preRegistration",
        "canonicalRoot": _b64(bytes.fromhex(h)), "proof": _b64(proof), "anchoredAt": None}]
    return _write(receipt)


def _receipt_with_anchors(specs, *, prereg=b"my eval protocol\n") -> str:
    """An eval receipt carrying MULTIPLE preRegistration-target anchors — one per ``(type, proof)`` in
    ``specs`` — over its own prereg root. Mirrors ``_receipt_with_anchor`` (the signed prereg_sha256 is
    the canonical root, so no RFC 8785 canonicalizer is needed) but lets a test mix a required verifying
    anchor with an unrelated one."""
    h = hashlib.sha256(prereg).hexdigest()
    claim, _salts = build_eval_claim(
        suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=10, model_id="m", dataset_id="d", issuer="Lab",
        timestamp="2026-07-02T00:00:00Z", prereg_sha256=h)
    receipt = emit_eval_receipt(claim, generate_signer())
    receipt["anchors"] = [
        {"type": atype, "target": "preRegistration",
         "canonicalRoot": _b64(bytes.fromhex(h)), "proof": _b64(proof), "anchoredAt": None}
        for atype, proof in specs]
    return _write(receipt)


class _AnchorRegistryFixture(unittest.TestCase):
    """Register deterministic dummy verifiers (confirmed / pending) for the CLI to drive; restore after."""

    def setUp(self):
        self._saved = dict(anchors._VERIFIERS)
        anchors.register_anchor_type(   # confirmed iff proof == b"good"
            "test-confirmed",
            lambda proof, root, *, frozen, now: {"ok": proof == b"good", "detail": "dummy confirmed"})
        anchors.register_anchor_type(   # pending: not ok, but a WARN, never a hard fail
            "test-pending",
            lambda proof, root, *, frozen, now: {"ok": False, "warn": True, "status": "pending",
                                                 "detail": "dummy pending"})
        self._files: list[str] = []

    def tearDown(self):
        anchors._VERIFIERS.clear()
        anchors._VERIFIERS.update(self._saved)
        for p in self._files:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(p)

    def _track(self, path: str) -> str:
        self._files.append(path)
        return path


class TestExitCodeContract(unittest.TestCase):
    def test_pure_exit_code_with_anchor_requirement(self):
        # The anchor requirement is a third relying-party gate: crypto failure (1) dominates; an unmet
        # requirement over passing crypto is 3; a met/absent requirement does not change the 0/3 verdict.
        self.assertEqual(_verify_exit_code(True, None, None), 0)    # nothing requested
        self.assertEqual(_verify_exit_code(True, None, True), 0)    # anchor requirement met
        self.assertEqual(_verify_exit_code(True, None, False), 3)   # anchor requirement NOT met
        self.assertEqual(_verify_exit_code(True, True, False), 3)   # policy ok but anchor missing → 3
        self.assertEqual(_verify_exit_code(False, None, False), 1)  # crypto failure dominates
        # backward-compatible 2-arg calls are unchanged
        self.assertEqual(_verify_exit_code(True, False), 3)
        self.assertEqual(_verify_exit_code(True, None), 0)


class TestRequireAnchorCli(_AnchorRegistryFixture):
    def test_no_anchor_present_requirement_unmet_exit_3(self):
        path = self._track(_plain_bundle_file())
        rc, out = _run(["verify", "--require-anchor", path])
        self.assertEqual(rc, 3, out)                       # crypto OK, but the required anchor is missing
        self.assertIn("ANCHOR: REQUIRED_NOT_MET", out)
        self.assertIn("CRYPTO: OK", out)                   # crypto still passed — this is a policy-tier failure

    def test_confirmed_anchor_satisfies_requirement_exit_0(self):
        path = self._track(_receipt_with_anchor("test-confirmed", b"good"))
        rc, out = _run(["verify", "--require-anchor", path])
        self.assertEqual(rc, 0, out)
        self.assertIn("ANCHOR: OK", out)

    def test_anchor_type_narrows_requirement(self):
        path = self._track(_receipt_with_anchor("test-confirmed", b"good"))
        self.assertEqual(_run(["verify", "--anchor-type", "test-confirmed", path])[0], 0)
        # a DIFFERENT required type is not present → unmet → exit 3
        self.assertEqual(_run(["verify", "--anchor-type", "rfc3161-tsa", path])[0], 3)

    def test_required_type_verifies_despite_unrelated_broken_anchor_exit_0(self):
        # THE WP4 AGGREGATION-BUG FIX: a receipt carrying the REQUIRED verifying anchor AND an unrelated
        # broken/unregistered one must still SATISFY --anchor-type <required> (exit 0). The broken anchor
        # stays advisory — it makes the aggregate status FAIL (still reported) but must NOT fail a
        # requirement that a different anchor meets, exactly as anchors are advisory-only without the flag.
        path = self._track(_receipt_with_anchors([
            ("test-confirmed", b"good"),          # the required, VERIFYING anchor
            ("mystery/v9-unregistered", b"x"),    # unrelated + unregistered type → hard-fails on its own
        ]))
        rc, out = _run(["verify", "--anchor-type", "test-confirmed", path])
        self.assertEqual(rc, 0, out)              # requirement met → exit 0 (was exit 3 before the fix)
        self.assertIn("ANCHOR: OK", out)
        # the exit code follows the requirement, but the report stays honest: anchor_ok True while the
        # aggregate anchor_status is FAIL (the broken anchor is still surfaced in anchor_results).
        rcj, outj = _run(["verify", "--json", "--anchor-type", "test-confirmed", path])
        self.assertEqual(rcj, 0, outj)
        data = json.loads(outj)
        self.assertIs(data["anchor_ok"], True)             # requirement met
        self.assertEqual(data["anchor_status"], "FAIL")    # aggregate still FAILs (broken anchor reported)
        self.assertEqual(len(data["anchor_results"]), 2)   # both anchors surfaced, incl. the broken one

    def test_required_type_not_verifying_only_unrelated_verifies_exit_3(self):
        # Symmetric fail-closed guard: the fix keys on the REQUIRED type's own verifying instance, never
        # on "some anchor verified". An unrelated anchor that DOES verify must NOT satisfy a type-specific
        # requirement whose own anchor is broken → exit 3 (REQUIRED_NOT_MET), not a false pass.
        anchors.register_anchor_type(  # an unrelated type that always verifies
            "other-confirmed",
            lambda proof, root, *, frozen, now: {"ok": True, "detail": "unrelated ok"})
        path = self._track(_receipt_with_anchors([
            ("test-confirmed", b"bad"),           # the REQUIRED type — present but does NOT verify
            ("other-confirmed", b"whatever"),     # an unrelated anchor that DOES verify
        ]))
        rc, out = _run(["verify", "--anchor-type", "test-confirmed", path])
        self.assertEqual(rc, 3, out)              # required type has no verifying anchor → exit 3
        self.assertIn("ANCHOR: REQUIRED_NOT_MET", out)

    def test_pending_anchor_does_not_satisfy_by_default_exit_3(self):
        path = self._track(_receipt_with_anchor("test-pending", b"x"))
        self.assertEqual(_run(["verify", "--require-anchor", path])[0], 3)

    def test_pending_anchor_satisfies_with_allow_pending_exit_0(self):
        path = self._track(_receipt_with_anchor("test-pending", b"x"))
        self.assertEqual(_run(["verify", "--require-anchor", "--allow-pending", path])[0], 0)

    def test_allow_pending_without_requirement_is_malformed_exit_2(self):
        path = self._track(_plain_bundle_file())
        # a lone --allow-pending would be a silent no-op → reject loudly as malformed input (exit 2)
        self.assertEqual(_run(["verify", "--allow-pending", path])[0], 2)

    def test_crypto_failure_dominates_requirement_exit_1(self):
        from proofbundle import emit_bundle
        bundle = emit_bundle(b'{"x": 1}', generate_signer())
        bundle["payload_b64"] = "AAAA"                     # tamper: crypto now fails
        path = self._track(_write(bundle))
        rc, out = _run(["verify", "--require-anchor", path])
        self.assertEqual(rc, 1, out)                       # crypto failure (1) dominates the anchor gate
        self.assertIn("ANCHOR: NOT_EVALUATED", out)        # the requirement is not even checked

    def test_json_carries_anchor_verdict(self):
        path = self._track(_receipt_with_anchor("test-confirmed", b"good"))
        rc, out = _run(["verify", "--json", "--require-anchor", path])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIs(data["anchor_ok"], True)
        self.assertEqual(data["anchor_status"], "PASS")
        self.assertIn("anchor_results", data)

    def test_anchors_field_is_tolerated_by_plain_verify(self):
        # A receipt carrying an (experimental) anchors[] field must still verify its crypto WITHOUT the
        # flag — the field is a detached optional layer, never part of the crypto core (bundle schema).
        path = self._track(_receipt_with_anchor("test-confirmed", b"good"))
        rc, out = _run(["verify", path])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("ANCHOR:", out)                   # no anchor line without the flag

    def test_receipt_target_anchor_uses_detached_root(self):
        # The receipt-target path: the receipt root is the canonical root of the bundle WITHOUT its own
        # anchors (detached). Build a confirmed anchor over exactly that root → requirement met (0);
        # an anchor over a WRONG root fails closed (3). Needs the RFC 8785 canonicalizer.
        try:
            from proofbundle.anchors import receipt_canonical_root
            from proofbundle import emit_bundle
        except Exception:  # noqa: BLE001
            self.skipTest("anchors imports unavailable")
        base = emit_bundle(b'{"x": 1}', generate_signer())
        try:
            root = receipt_canonical_root(base)   # root of the pre-anchor bundle
        except Exception:  # noqa: BLE001 — RFC 8785 canonicalizer (the [anchors]/[eval] extra) absent
            self.skipTest("RFC 8785 canonicalizer not installed")
        good = dict(base)
        good["anchors"] = [{"type": "test-confirmed", "target": "receipt",
                            "canonicalRoot": _b64(root), "proof": _b64(b"good"), "anchoredAt": None}]
        self.assertEqual(_run(["verify", "--require-anchor", self._track(_write(good))])[0], 0)
        bad = dict(base)
        bad["anchors"] = [{"type": "test-confirmed", "target": "receipt",
                           "canonicalRoot": _b64(b"\x00" * 32), "proof": _b64(b"good"), "anchoredAt": None}]
        self.assertEqual(_run(["verify", "--require-anchor", self._track(_write(bad))])[0], 3)

    def test_default_behaviour_unchanged_without_flag(self):
        # Regression pin: a plain bundle verifies to exit 0 and emits NO anchor output when neither
        # --require-anchor nor --anchor-type is given (WP4 is strictly additive).
        path = self._track(_plain_bundle_file())
        rc, out = _run(["verify", path])
        self.assertEqual(rc, 0)
        self.assertNotIn("ANCHOR", out)


class TestRpTrustCliFlags(_AnchorRegistryFixture):
    """WP-A1: --trusted-tsa-root / --bitcoin-header supply the relying party's anchor trust material, and
    a required time anchor is UNMET (exit 3) until they do. Uses an rp_trust-aware dummy verifier so the
    plumbing is tested without the [anchors] extra."""

    def setUp(self):
        super().setUp()
        anchors.register_anchor_type(   # confirmed ONLY when the relying party supplied a bitcoin header
            "test-rp",
            lambda proof, root, *, frozen, now, rp_trust=None: (
                {"ok": True, "rp_trusted": True, "detail": "rp header supplied"}
                if (rp_trust or {}).get("bitcoin_block_headers")
                else {"ok": False, "needs_rp_trust": True, "status": "needs_rp_trust",
                      "detail": "needs a relying-party header"}))

    def test_required_anchor_unmet_without_rp_material_exit_3(self):
        path = self._track(_receipt_with_anchor("test-rp", b"whatever"))
        rc, out = _run(["verify", path, "--require-anchor"])
        self.assertEqual(rc, 3)                       # no rp_trust → unmet → exit 3
        self.assertIn("ANCHOR", out)

    def test_required_anchor_met_with_bitcoin_header_exit_0(self):
        path = self._track(_receipt_with_anchor("test-rp", b"whatever"))
        rc, out = _run(["verify", path, "--require-anchor", "--bitcoin-header", "800000:" + "aa" * 32])
        self.assertEqual(rc, 0)                       # rp header supplied → met → exit 0

    def test_malformed_bitcoin_header_is_exit_2(self):
        path = self._track(_receipt_with_anchor("test-rp", b"whatever"))
        self.assertEqual(_run(["verify", path, "--require-anchor", "--bitcoin-header", "nope"])[0], 2)
        self.assertEqual(
            _run(["verify", path, "--require-anchor", "--bitcoin-header", "800000:zz"])[0], 2)

    def test_build_rp_trust_parses_flags(self):
        import argparse

        from proofbundle.cli import _build_rp_trust
        ns = argparse.Namespace(trusted_tsa_root=None,
                                bitcoin_header=["800000:" + "ab" * 32, "800001:" + "cd" * 32])
        rp = _build_rp_trust(ns)
        self.assertEqual(rp["bitcoin_block_headers"]["800000"], "ab" * 32)
        self.assertEqual(rp["bitcoin_block_headers"]["800001"], "cd" * 32)
        # nothing supplied → None (a required anchor then stays unmet, never a silent frozen pass)
        self.assertIsNone(_build_rp_trust(argparse.Namespace(trusted_tsa_root=None, bitcoin_header=None)))


if __name__ == "__main__":
    unittest.main()
