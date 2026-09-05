"""A version-scoped signed artefact must bind its signed version to the version under test.

THE CLASS (deep gate 2026-09-05, finding L5-G6-02, P1) is the L6-01 lesson applied to the ARTEFACT
rather than to the matrix pin. C12.2 — a release-deciding check — reported PASS for 6.0.0 out of
``audit_artifacts/findings_register_361.json``, whose SIGNED ``version`` field says ``3.6.1`` and whose
``generated_at`` is 2026-07-18: seventeen findings about a release two majors back, deciding a release
today. Measured on HEAD 049b3195, all three accepted:

    register version "3.6.1"  + VERSION_UNDER_TEST 6.0.0  -> ok=True, C12.2 PASS
    register version "0.0.1"                              -> ok=True
    register with NO version field                        -> ok=True

The signature was valid in every case. That was never the question; nothing compared the two numbers.

THE PROPERTY: ``verify_and_count`` binds the register's signed ``version`` to the caller's
``expected_version`` and fails closed with ``REGISTER_VERSION_MISMATCH`` on mismatch or absence,
including a missing/malformed ``generated_at`` (freshness that cannot be measured is not freshness).
The release-deciding caller MUST pass the version; a caller that passes none is visibly unbound
(``version_bound: False``) rather than silently fine.

ANTI-PARITY: bound to the version the register actually names, the same call is ok=True. A guard that
always failed would satisfy every assertion above and be worthless.

HONEST BOUNDARY, and it is the reason C12.2 is RED on this tree: the fix makes the gate tell the truth,
it does not make the truth green. A 6.0.0 register has to be generated and SIGNED with the pinned key,
and that key is the owner's — see the lane report's open door. Producing one here would be the very act
this check exists to catch.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class RegisterVersionBinding(unittest.TestCase):
    def setUp(self):
        self.fr = _load("fr_l5g602", "scripts/findings_register.py")
        self.addCleanup(lambda: sys.modules.pop("fr_l5g602", None))
        self.real = json.loads(
            (REPO / "audit_artifacts" / "findings_register_361.json").read_text(encoding="utf-8"))

    def _repo_with(self, register: dict) -> pathlib.Path:
        d = pathlib.Path(tempfile.mkdtemp(prefix="l5g602_"))
        p = d / self.fr.REGISTER_REL
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps(register), encoding="utf-8")
        return d

    def _bypass_signature(self):
        """The register private key is gitignored and absent here, so a test cannot MINT a validly
        signed register with arbitrary content (the file says so in its own CI note). The signature
        path has its own tests; what is measured here is the BINDING, so only that one step is
        bypassed — and the real, signed register is used for the control."""
        orig = self.fr._signature_ok
        self.fr._signature_ok = lambda register: (True, "bypassed: this test measures the binding")
        self.addCleanup(lambda: setattr(self.fr, "_signature_ok", orig))

    def test_the_committed_register_does_not_decide_a_different_release(self):
        """THE FINDING, on the real committed artefact and the real version under test."""
        acm = _load("acm_l5g602", "scripts/audit_candidate_matrix.py")
        self.addCleanup(lambda: sys.modules.pop("acm_l5g602", None))
        r = self.fr.verify_and_count(REPO, expected_version=acm.VERSION_UNDER_TEST)
        if self.real.get("version") == acm.VERSION_UNDER_TEST:
            self.assertTrue(r["ok"], r["reason"])            # a 6.0.0 register exists: bound and equal
        else:
            self.assertFalse(r["ok"],
                             "a register scoped to another release still decides this one")
            self.assertIn(self.fr.CODE_REGISTER_VERSION_MISMATCH, r["reason"])
            self.assertEqual(r["register_version"], self.real.get("version"))

    def test_every_unbindable_version_fails_closed(self):
        self._bypass_signature()
        body = {k: v for k, v in self.real.items() if k != "signature"}
        shapes = {
            "foreign_version": dict(body, version="0.0.1"),
            "stale_version": dict(body, version="3.6.1"),
            "no_version": {k: v for k, v in body.items() if k != "version"},
            "non_string_version": dict(body, version=600),
            "no_generated_at": {k: v for k, v in dict(body, version="6.0.0").items()
                                if k != "generated_at"},
            "malformed_generated_at": dict(body, version="6.0.0", generated_at="yesterday"),
        }
        for label, reg in shapes.items():
            with self.subTest(shape=label):
                r = self.fr.verify_and_count(self._repo_with(reg), expected_version="6.0.0")
                self.assertFalse(r["ok"], f"{label}: accepted for a release it is not about")
                self.assertIn(self.fr.CODE_REGISTER_VERSION_MISMATCH, r["reason"])
                self.assertTrue(r["version_bound"])

    def test_ANTI_PARITY_a_matching_version_is_accepted(self):
        """Without this the guard could be a constant FAIL and every assertion above would still pass."""
        self._bypass_signature()
        body = {k: v for k, v in self.real.items() if k != "signature"}
        r = self.fr.verify_and_count(self._repo_with(dict(body, version="6.0.0")),
                                     expected_version="6.0.0")
        self.assertTrue(r["ok"], r["reason"])
        self.assertTrue(r["version_bound"])
        self.assertEqual(r["register_version"], "6.0.0")

    def test_an_unbound_caller_is_visibly_unbound(self):
        """Three states: bound-and-equal, bound-and-mismatched, never-compared. The library path may
        stay unbound; it must SAY so, so a reader cannot mistake it for a checked binding."""
        r = self.fr.verify_and_count(REPO)
        self.assertFalse(r["version_bound"])
        self.assertEqual(r["register_version"], self.real.get("version"))

    def test_the_release_deciding_caller_actually_binds(self):
        """A guard nobody calls is not a guard (the L6-01 lesson, one level down): C12.2 must PASS the
        version under test into the register verifier, not merely have the parameter available."""
        src = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
        after = src.split("def c12_2_audit_pack_zero_p0p1", 1)[-1].split("\ndef ", 1)[0]
        self.assertIn("expected_version=VERSION_UNDER_TEST", after,
                      "C12.2 calls verify_and_count without binding the version — the guard is decoration")

    def test_META_removing_the_binding_makes_a_foreign_register_pass_again(self):
        """PLANT-AND-MUST-CATCH: with the binding neutralised, the 3.6.1 register decides 6.0.0 again."""
        self._bypass_signature()
        orig = self.fr._version_binding_error
        self.fr._version_binding_error = lambda register, expected: None
        try:
            body = {k: v for k, v in self.real.items() if k != "signature"}
            r = self.fr.verify_and_count(self._repo_with(dict(body, version="3.6.1")),
                                         expected_version="6.0.0")
            self.assertTrue(r["ok"], "the pre-fix shape no longer reproduces — the meta-test is blind")
        finally:
            self.fr._version_binding_error = orig
        r2 = self.fr.verify_and_count(self._repo_with({k: v for k, v in self.real.items()
                                                       if k != "signature"}),
                                      expected_version="6.0.0")
        self.assertFalse(r2["ok"], "with the binding in place the same register must be refused")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
