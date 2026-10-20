"""Addendum R6a-1 / R6a-2 (`KRAXO-CLOUD-R6A-SIEBEN-P1-VOR-CRIT-JSON-01`, Z309 / 6.2.0).

Reviewer round 6a, two P1 false positives on the bind head, both reproduced by Cowork from the
delivered probes:

R6a-1 — `evaluate_policy(bundle, result, policy)` adopted the authentic result's ``sd-jwt-key-binding``
check and read the nonce from the PASSED bundle's ``sd_jwt_vc`` block, with no binding of that block to
the result. A copy with ONE changed character of the KB-JWT signature (same signer, same payload) kept
``policy_ok=True`` under ``require_key_binding_when_cnf_present`` + ``require_nonce``, although a fresh
``verify_bundle`` of the copy is ``ok=False`` (``sd-jwt-key-binding`` False). The fix binds the verified
``sd_jwt_vc.compact`` to the result (origin-covered) and the policy refuses a bundle whose ``sd_jwt_vc``
does not match it.

R6a-2 — the ``via_trusted`` / checkpoint root-authentication paths authenticated a pinned root without
requiring the authentic result to have proved Merkle inclusion UNDER that root. Replacing only
``merkle.root_b64`` with a foreign-but-pinned root kept ``root_authenticated=True`` under the old result,
although a fresh ``verify_bundle`` fails inclusion. The fix binds the root the result proved inclusion
under (origin-covered) and every root-authentication path requires the stated root to equal it.

RED at the bind head ``693bc3c4ee4126bcb06a9ae088cc4b23fea8dc71`` (both attacks stay positive); GREEN
after. The unchanged-bundle positive controls stay green; a fresh verify of each tampered copy is False.
"""
from __future__ import annotations

import base64
import copy
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle import emit_bundle, verify_bundle  # noqa: E402
from proofbundle.policy import evaluate_policy  # noqa: E402
from test_security_fix_620_bind_n44 import _control_bundle  # noqa: E402

_SD_POLICY = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "r6a-1",
              "sd_jwt": {"require_key_binding_when_cnf_present": True, "require_nonce": True}}


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _tamper_kb_sig(bundle: dict) -> dict:
    """Copy of bundle; in sd_jwt_vc.compact change the FIRST char of the KB-JWT (last ~ segment)
    signature part (first, not last: the last base64url char of a 64-byte sig carries pad bits, so a
    change there may decode to the same bytes). Only sd_jwt_vc.compact differs; the decoded 64
    signature bytes differ."""
    b2 = copy.deepcopy(bundle)
    compact = b2["sd_jwt_vc"]["compact"]
    head, sep, kb = compact.rpartition("~")
    h, p, s = kb.split(".")
    s2 = ("A" if s[0] != "A" else "B") + s[1:]
    assert _b64url_dec(s) != _b64url_dec(s2), "precondition: the signature bytes must differ"
    b2["sd_jwt_vc"]["compact"] = head + sep + h + "." + p + "." + s2
    return b2


def _pol_ok(out: dict):
    return out.get("policy_ok")


class R6a1TamperedSdJwtRefused(unittest.TestCase):
    """A result + a bundle copy whose KB-JWT signature was changed must not keep the key-binding/nonce
    policy positive. Repro from probe_r6a_1."""

    def test_tampered_kb_signature_is_refused_under_the_old_result(self):
        b = _control_bundle()
        r = verify_bundle(b)
        self.assertTrue(r.ok, "the control bundle verifies")
        self.assertIs(next(c.ok for c in r.checks if c.name == "sd-jwt-key-binding"), True)
        b2 = _tamper_kb_sig(b)
        attack = evaluate_policy(b2, r, _SD_POLICY)
        self.assertIsNot(_pol_ok(attack), True,
                         f"a tampered sd_jwt_vc must not keep policy_ok True (got {attack!r})")

    def test_the_unchanged_bundle_still_passes(self):
        b = _control_bundle()
        r = verify_bundle(b)
        self.assertIs(_pol_ok(evaluate_policy(b, r, _SD_POLICY)), True,
                      "the unchanged bundle + its own result stays positive (control)")

    def test_a_fresh_verify_of_the_tampered_copy_fails(self):
        b = _control_bundle()
        b2 = _tamper_kb_sig(b)
        self.assertFalse(verify_bundle(b2).ok, "a fresh verify of the tampered copy is not ok (control)")


class R6a2SwappedRootRefused(unittest.TestCase):
    """A result + a bundle copy whose merkle.root_b64 was replaced by a foreign, pinned root must not
    authenticate that root under the old result. Repro from probe_r6a_2."""

    def _pair(self):
        kA, kB = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        a = emit_bundle(b"one", kA)
        b = emit_bundle(b"two", kB)
        return a, verify_bundle(a), b

    def test_swapped_pinned_root_is_refused_under_the_old_result(self):
        a, rA, b = self._pair()
        self.assertTrue(rA.ok, "A verifies")
        root_b = b["merkle"]["root_b64"]
        a2 = copy.deepcopy(a)
        a2["merkle"]["root_b64"] = root_b
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "r6a-2",
                  "merkle": {"trusted_roots": [root_b]}}
        attack = evaluate_policy(a2, rA, policy)
        self.assertIsNot(_pol_ok(attack), True,
                         f"a swapped pinned root must not keep policy_ok True (got {attack!r})")
        self.assertIsNot(attack.get("root_authenticated"), True,
                         "root_authenticated must not be True for a root the result never proved inclusion under")

    def test_the_own_pinned_root_still_passes(self):
        a, rA, _b = self._pair()
        root_a = a["merkle"]["root_b64"]
        policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "r6a-2",
                  "merkle": {"trusted_roots": [root_a]}}
        out = evaluate_policy(a, rA, policy)
        self.assertIs(_pol_ok(out), True, "A under a pin of its own root stays positive (control)")
        self.assertIs(out.get("root_authenticated"), True)

    def test_a_fresh_verify_of_the_swapped_copy_fails(self):
        a, _rA, b = self._pair()
        a2 = copy.deepcopy(a)
        a2["merkle"]["root_b64"] = b["merkle"]["root_b64"]
        self.assertFalse(verify_bundle(a2).ok, "a fresh verify of the swapped copy fails inclusion (control)")


if __name__ == "__main__":
    unittest.main()
