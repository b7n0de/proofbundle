"""RT-10 / PB-2026-0718-14: the SIGNED structured findings register is fail-closed and anti-tautological.

The old audit_candidate_matrix C12.2 granted a FALSE PASS from a lexical "0 open P0/P1" substring in a
possibly-stale .md. The replacement counts from a signed, structured register. This guard proves BOTH
directions: the real committed register verifies (control), and every tampering vector (absent, byte-flip,
foreign key, empty, contradiction) is caught fail-closed — so a "0 open" claim can never be forged.

CI note: the register PRIVATE key is gitignored and absent here, so a test cannot mint a validly-signed
register with arbitrary content. The signature-path tests therefore use the committed register + tampering
(any byte change breaks the pinned-key signature), and the supersession/contradiction logic is exercised
directly on the pure ``_resolve_current`` helper (no signature needed).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class TestFindingsRegisterVerify(unittest.TestCase):
    def setUp(self):
        self.fr = _load("fr_rt10", "scripts/findings_register.py")
        self.real = REPO / "audit_artifacts" / "findings_register_361.json"

    def _run_with(self, register_obj):
        with tempfile.TemporaryDirectory() as td:
            art = Path(td) / "audit_artifacts"
            art.mkdir(parents=True)
            (art / "findings_register_361.json").write_text(json.dumps(register_obj))
            return self.fr.verify_and_count(Path(td))

    def test_control_real_register_verifies(self):
        r = self.fr.verify_and_count(REPO)
        self.assertTrue(r["ok"], r["reason"])
        self.assertEqual(r["open_ids"], [])
        self.assertGreater(r["evaluated_count"], 0)
        self.assertTrue(str(r["source_digest"]).startswith("sha256:"))

    def test_absent_register_fails(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.fr.verify_and_count(Path(td))
        self.assertFalse(r["ok"])
        self.assertEqual(r["evaluated_count"], 0)

    def test_tampered_status_fails(self):
        reg = json.loads(self.real.read_text(encoding="utf-8"))
        reg["findings"][0]["status"] = "open"  # break a closed P0 without re-signing
        r = self._run_with(reg)
        self.assertFalse(r["ok"])
        self.assertIn("signature", r["reason"].lower())

    def test_emptied_findings_fails(self):
        reg = json.loads(self.real.read_text(encoding="utf-8"))
        reg["findings"] = []  # a stale-zero analogue: no findings at all
        r = self._run_with(reg)
        self.assertFalse(r["ok"])

    def test_verify_and_count_fails_closed_on_hidden_open_p0(self):
        # RT10-REG-01 wiring: a (simulated validly-signed) register that hides an open P0 behind a dangling
        # supersession must return ok=False. The private key is gitignored (absent in CI), so bypass only the
        # signature step to exercise the anomaly-FAIL path that the live key-signed reproducer confirmed.
        reg = {
            "schema": "proofbundle.findings_register.v1", "version": "3.6.1",
            "generated_at": "2026-07-18T00:00:00Z",
            "findings": [
                {"id": "X", "severity": "P0", "status": "open", "superseded_by": "DOES_NOT_EXIST"},
                {"id": "Y", "severity": "P2", "status": "closed"},
            ],
        }
        orig = self.fr._signature_ok
        self.fr._signature_ok = lambda register: (True, "bypassed for wiring test")
        try:
            r = self._run_with(reg)
        finally:
            self.fr._signature_ok = orig
        self.assertFalse(r["ok"], "a hidden open P0 must fail closed, never PASS")

    def test_foreign_key_fails(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from proofbundle import canonical
        body = {k: v for k, v in json.loads(self.real.read_text(encoding="utf-8")).items()
                if k != "signature"}
        k = Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                          format=serialization.PublicFormat.Raw)
        forged = dict(body)
        forged["signature"] = {
            "alg": "ed25519",
            "public_key_b64": base64.b64encode(pub).decode(),
            "sig_b64": base64.b64encode(k.sign(canonical.canonicalize_statement(body))).decode(),
        }
        r = self._run_with(forged)
        self.assertFalse(r["ok"])
        self.assertIn("pinned", r["reason"].lower())


class TestResolveCurrent(unittest.TestCase):
    """Pure supersession + contradiction logic (no signature needed)."""

    def setUp(self):
        self.fr = _load("fr_rt10_b", "scripts/findings_register.py")

    def test_supersession_current_wins(self):
        findings = [
            {"id": "A", "severity": "P1", "status": "open", "superseded_by": "A2"},
            {"id": "A2", "severity": "P1", "status": "closed"},
        ]
        effective, contradictions, anomalies, superseded = self.fr._resolve_current(findings)
        self.assertNotIn("A", effective)       # superseded entry drops out (legit: A2 present)
        self.assertEqual(effective["A2"]["status"], "closed")
        self.assertEqual(contradictions, [])
        self.assertEqual(anomalies, [])
        self.assertIn("A", superseded)

    def test_contradiction_detected(self):
        findings = [
            {"id": "B", "severity": "P0", "status": "closed"},
            {"id": "B", "severity": "P0", "status": "open"},  # same id, conflicting, no supersession
        ]
        _effective, contradictions, _anomalies, _superseded = self.fr._resolve_current(findings)
        self.assertIn("B", contradictions)

    def test_dangling_supersession_is_anomaly_not_dropped(self):
        # RT10-REG-01: a dangling superseded_by (target absent) must NOT silently drop the finding.
        findings = [
            {"id": "X", "severity": "P0", "status": "open", "superseded_by": "NOPE"},
            {"id": "Y", "severity": "P2", "status": "closed"},
        ]
        effective, _c, anomalies, superseded = self.fr._resolve_current(findings)
        self.assertNotIn("X", superseded)      # not legitimately superseded
        self.assertTrue(any("X" in a for a in anomalies))

    def test_self_supersession_is_anomaly(self):
        findings = [{"id": "X", "severity": "P0", "status": "open", "superseded_by": "X"}]
        _e, _c, anomalies, superseded = self.fr._resolve_current(findings)
        self.assertNotIn("X", superseded)
        self.assertTrue(any("X" in a for a in anomalies))

    def test_non_string_id_is_anomaly(self):
        _e, _c, anomalies, _s = self.fr._resolve_current([{"id": 123, "severity": "P0", "status": "open"}])
        self.assertTrue(anomalies)

    def test_invisible_or_confusable_severity_cannot_hide_open_p0(self):
        # 6-lens gate L5-01: severity was ALLOW-by-default (anything not exactly {P0,P1} after .strip().upper()
        # was silently non-gating), and str.strip() removes neither zero-width/format chars nor confusables, so
        # an open P0 could hide behind a U+200B / fullwidth / unknown severity that renders as "P0" to a human.
        # Two defences close it: (a) NFKC + Cc/Cf folding maps an invisible/confusable severity back to its real
        # token so a hidden P0 is correctly GATED; (b) a normalized severity NOT in the known allowlist is an
        # ANOMALY (deny-by-default). Either way an open P0 can never report as 0-open.
        import json
        import tempfile
        real = Path(REPO) / "audit_artifacts" / "findings_register_361.json"
        body = {k: v for k, v in json.loads(real.read_text(encoding="utf-8")).items() if k != "signature"}
        orig = self.fr._signature_ok
        self.fr._signature_ok = lambda register: (True, "bypassed for wiring test")
        try:
            for hidden in ("P0​", "​P0", "​", "P0 ", "XYZ", "", "critical"):
                reg = dict(body)
                reg["findings"] = [{"id": "X", "severity": hidden, "status": "open"},
                                   {"id": "Y", "severity": "P2", "status": "closed"}]
                d = Path(tempfile.mkdtemp())
                (d / "audit_artifacts").mkdir()
                (d / "audit_artifacts/findings_register_361.json").write_text(json.dumps(reg))
                r = self.fr.verify_and_count(d)
                self.assertFalse(r["ok"], "an open P0 hidden behind severity %r must not report 0-open" % hidden)
        finally:
            self.fr._signature_ok = orig

    def test_unknown_severity_is_anomaly_known_is_accepted(self):
        # deny-by-default at the resolve level: a truly-unknown string severity is an anomaly; every known
        # token (incl. a value that NFKC-normalizes to a known token) is accepted.
        for unknown in ("XYZ", "", "critical", "P9"):
            _e, _c, anomalies, _s = self.fr._resolve_current(
                [{"id": "X", "severity": unknown, "status": "closed"}])
            self.assertTrue(anomalies, "severity %r must be an anomaly" % unknown)
        for known in ("P0", "P1", "P2", "P3", "INFO", "Ｐ０"):  # fullwidth -> P0
            _e, _c, anomalies, _s = self.fr._resolve_current(
                [{"id": "X", "severity": known, "status": "closed"}])
            self.assertEqual(anomalies, [], "severity %r must be accepted" % known)

    def test_supersession_cycle_is_anomaly(self):
        # 6-lens gate L5-01 (P0): a supersession RING (A->B->A, or a longer loop) makes every member point to
        # a present+different id, so without cycle detection all members drop as "legit superseded" and open
        # P0s hidden in the ring vanish (ok=True, 0 open). A cycle must be an anomaly -> fail-closed.
        ring2 = [{"id": "A", "severity": "P0", "status": "open", "superseded_by": "B"},
                 {"id": "B", "severity": "P0", "status": "open", "superseded_by": "A"}]
        _e, _c, anomalies, superseded = self.fr._resolve_current(ring2)
        self.assertTrue(any("cycle" in a for a in anomalies))
        self.assertNotIn("A", superseded)
        self.assertNotIn("B", superseded)
        ring3 = [{"id": "A", "severity": "P0", "status": "open", "superseded_by": "B"},
                 {"id": "B", "severity": "P1", "status": "open", "superseded_by": "C"},
                 {"id": "C", "severity": "P0", "status": "open", "superseded_by": "A"}]
        _e, _c, anomalies3, _s = self.fr._resolve_current(ring3)
        self.assertTrue(any("cycle" in a for a in anomalies3))
        # a LINEAR terminating chain is NOT a cycle (stays legit)
        chain = [{"id": "A", "severity": "P1", "status": "open", "superseded_by": "A2"},
                 {"id": "A2", "severity": "P1", "status": "closed"}]
        _e, _c, anomalies_ok, superseded_ok = self.fr._resolve_current(chain)
        self.assertEqual(anomalies_ok, [])
        self.assertIn("A", superseded_ok)

    def test_non_string_severity_or_status_is_anomaly(self):
        # 6-lens gate: a non-string severity (e.g. the LIST ["P0"]) would slip past the {P0,P1} test and hide
        # an open P0 (str(["P0"]).upper() != "P0"); non-string severity/status must be an anomaly -> FAIL.
        for bad in ([{"id": "X", "severity": ["P0"], "status": "open"}],
                    [{"id": "X", "severity": "P0", "status": ["open"]}],
                    [{"id": "X", "severity": 0, "status": "open"}]):
            _e, _c, anomalies, _s = self.fr._resolve_current(bad)
            self.assertTrue(anomalies, bad)


if __name__ == "__main__":
    unittest.main()
