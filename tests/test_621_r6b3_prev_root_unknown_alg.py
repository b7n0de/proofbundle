"""6.2.1 R6b-3 (= key identity Fund 1): an old-root pin with an unknown ``alg`` authorises no rotation.

``verify_trust_pack(prev_root_keys=...)``: an old-root pin given as a key object with an explicit ``alg`` that is
not a known trust-pack algorithm (``rsa4096``, ``hybrid-ed25519-mldsa87``, ``None``, ``""``, a number) was read
as ``ed25519``, so a valid Ed25519 signature over the classical key authorised the rotation and set ``pinned``.
Only an ABSENT ``alg`` (and the bare-string legacy form) is the documented legacy Ed25519 case.

Property: a pin whose algorithm is unknown never yields a positive trust verdict. Red at v6.2.0.
"""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack  # noqa: E402
from test_trust_pack import _NOW, _external_sign, _pack  # noqa: E402


def _rotation(entry_of):
    """A successor pack (version 4, root threshold 1) signed by its new root AND by the old root key old-0.
    ``entry_of(pub_b64)`` builds the caller's pin for old-0."""
    old_pred, old_sks = _pack("old", threshold=1, version=3)
    new_pred, new_sks = _pack("new", threshold=1, version=4)
    env = sign_trust_pack(new_pred, {"new-0": new_sks["new-0"]})
    _external_sign(env, "old-0", old_sks["old-0"])
    pin = {"old-0": entry_of(old_pred["keys"]["old-0"]["publicKey"])}
    return verify_trust_pack(env, strict=True, now=_NOW, prev_root_keys=pin, prev_root_threshold=1)


_PQ_TEST_BYTES = base64.b64encode(b"\x01" * 1952).decode("ascii")


class R6b3UnknownAlgInPrevRootKeys(unittest.TestCase):
    UNKNOWN = {
        "rsa4096": lambda pub: {"alg": "rsa4096", "publicKey": pub},
        "hybrid-ed25519-mldsa87": lambda pub: {"alg": "hybrid-ed25519-mldsa87", "publicKey": pub,
                                               "publicKeyPq": _PQ_TEST_BYTES},
        "None": lambda pub: {"alg": None, "publicKey": pub},
        "empty string": lambda pub: {"alg": "", "publicKey": pub},
        "number": lambda pub: {"alg": 7, "publicKey": pub},
    }

    def test_an_explicit_unknown_alg_does_not_authorise_the_rotation(self):
        for label, entry_of in self.UNKNOWN.items():
            with self.subTest(alg=label):
                r = _rotation(entry_of)
                self.assertIsNot(r["rotation_authorized"], True,
                                 f"alg {label}: an unknown alg must not be read as ed25519 ({r['old_root_signers']})")
                self.assertIsNot(r["pinned"], True, f"alg {label}: pinned must not be True")
                self.assertIs(r["ok"], False, f"alg {label}: ok must be False")

    def test_control_the_legacy_forms_and_explicit_ed25519_still_authorise(self):
        for label, entry_of in {"bare string": lambda pub: pub,
                                "absent alg": lambda pub: {"publicKey": pub},
                                "ed25519": lambda pub: {"alg": "ed25519", "publicKey": pub}}.items():
            with self.subTest(form=label):
                r = _rotation(entry_of)
                self.assertIs(r["rotation_authorized"], True)
                self.assertIs(r["pinned"], True)
                self.assertIs(r["ok"], True)

    def test_control_the_known_hybrid_alg_without_a_pq_signature_does_not_authorise(self):
        r = _rotation(lambda pub: {"alg": "hybrid-ed25519-mldsa65", "publicKey": pub,
                                   "publicKeyPq": _PQ_TEST_BYTES})
        self.assertIsNot(r["rotation_authorized"], True)
        self.assertIs(r["ok"], False)


if __name__ == "__main__":
    unittest.main()
