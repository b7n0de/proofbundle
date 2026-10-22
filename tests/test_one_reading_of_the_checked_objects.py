"""K3 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K3): verification and the judgement that
follows read the same values.

The core verification copies what a dict subclass stores; the pilot profile github-write/1 then read `payload`
again through the subclass's own `__getitem__`. A negatively judged, correctly signed outcome therefore appeared
as `accepted` with a matching unsigned effect digest, a signed REFUSE decision read as ALLOW, and a wrong target
behind a matching view of the scope (measured at 98b168b9 and f6ea5cc3). The Merkle accumulator had the class one
level out: `restore` normalised the inner state but read the outer envelope's signature dynamically. Both now read
each input once at their boundary, from its own storage (`proofbundle._plain_value.plain_json`), and verify and
judge only that copy. These attacks need the Python object surface; a JSON document cannot override methods.
Test keys only: the pilot's labelled vector keys, and keys generated per case.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_PILOT = REPO / "tools/pilot/github_write_profile.py"
_VECTORS = REPO / "tools/pilot/vectors.json"
_ACCUMULATOR = REPO / "tools/merkle_accumulator/accumulator.py"
_RFC8785 = importlib.util.find_spec("rfc8785") is not None


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


class View(dict):
    """A dict that stores one value and answers another for one key through its own __getitem__ and get."""

    def __init__(self, stored: dict, key: str, shown):
        super().__init__(stored)
        self._key, self._shown = key, shown

    def __getitem__(self, key):
        return self._shown if key == self._key else dict.__getitem__(self, key)

    def get(self, key, default=None):
        return self._shown if key == self._key else dict.get(self, key, default)


@unittest.skipUnless(_RFC8785, "the profile emits RFC 8785 canonical statements (the [eval] extra)")
class ThePilotProfileJudgesWhatItVerified(unittest.TestCase):

    def setUp(self):
        if not (_PILOT.is_file() and _VECTORS.is_file()):
            self.skipTest("tools/pilot is not in this tree")
        self.g = _load(_PILOT, "_k3_github_write_profile")
        self.cases = {c["case"]: c for c in json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]}
        g = self.g
        self.kw = {"gate_key": g._pub(g.test_key("gate")), "gate_id": g.GATE_ID,
                   "observer_key": g._pub(g.test_key("observer")), "observer_id": g.OBSERVER_ID}

    def _payload_of(self, statement: dict) -> str:
        return base64.b64encode(self.g.canonicalize_statement(statement)).decode()

    def test_RED_an_outcome_whose_view_shows_a_matching_unsigned_digest_is_not_accepted(self):
        """T3: the stored outcome has the bytes that differ; the view shows a statement whose effect digest is the
        approved one."""
        bad = self.cases["stored bytes differ from the approved bytes"]
        self.assertEqual(bad["expected"], self.g.NOT_ACCEPTED)
        s = self.g._statement(bad["outcome"])
        s["predicate"]["effectDigest"]["sha256"] = self.g.sha256_hex(self.g._TEXT)
        view = View(bad["outcome"], "payload", self._payload_of(s))
        r = self.g.reconcile(bad["decision"], view, bad["observed_scope"], **self.kw)
        self.assertEqual(r["verdict"], self.g.NOT_ACCEPTED, r)

    def test_RED_a_refused_decision_whose_view_shows_an_approval_is_not_accepted(self):
        """The stored decision is the signed REFUSE; the view shows the approval, and the outcome and scope are the
        ones of the approved case, bound to what the view shows."""
        refused = self.cases["refused, and an effect arrived"]
        approved = self.cases["approved and arrived as approved"]
        self.assertNotEqual(refused["decision"]["payload"], approved["decision"]["payload"])
        view = View(refused["decision"], "payload", approved["decision"]["payload"])
        r = self.g.reconcile(view, approved["outcome"], approved["observed_scope"], **self.kw)
        self.assertEqual(r["verdict"], self.g.NOT_ACCEPTED, r)

    def test_RED_a_wrong_target_behind_a_matching_view_of_the_scope_is_not_accepted(self):
        wrong = self.cases["wrong subject: arrived on another target"]
        approved = self.cases["approved and arrived as approved"]
        view = View(wrong["observed_scope"], "target", approved["observed_scope"]["target"])
        r = self.g.reconcile(wrong["decision"], wrong["outcome"], view, **self.kw)
        self.assertEqual(r["verdict"], self.g.NOT_ACCEPTED, r)

    def test_CONTROL_the_positive_vector_through_the_same_subclass_is_accepted(self):
        good = self.cases["approved and arrived as approved"]
        view = View(good["outcome"], "payload", good["outcome"]["payload"])
        r = self.g.reconcile(good["decision"], view, good["observed_scope"], **self.kw)
        self.assertEqual(r["verdict"], self.g.ACCEPTED, r)

    def test_CONTROL_the_plain_copy_of_the_view_is_not_accepted(self):
        bad = self.cases["stored bytes differ from the approved bytes"]
        r = self.g.reconcile(bad["decision"], dict(bad["outcome"]), bad["observed_scope"], **self.kw)
        self.assertEqual(r["verdict"], self.g.NOT_ACCEPTED, r)


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class TheAccumulatorRestoresWhatItVerified(unittest.TestCase):

    def setUp(self):
        if not _ACCUMULATOR.is_file():
            self.skipTest("tools/merkle_accumulator is not in this tree")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.a = _load(_ACCUMULATOR, "_k3_accumulator")
        self.state_key, event_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

        def pub(key):
            return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.state_pub, self.event_pub = pub(self.state_key), pub(event_key)
        akku = self.a.MerkleAccumulator()
        akku.append(b"leaf 0")
        self.good = akku.state(self.state_key, event_public_key=self.event_pub)

    def test_RED_a_stored_invalid_signature_behind_a_valid_view_is_refused(self):
        stored = copy.deepcopy(self.good)
        stored["signature"] = base64.b64encode(bytes(64)).decode()
        view = View(stored, "signature", self.good["signature"])
        with self.assertRaises(self.a.AccumulatorStateError):
            self.a.MerkleAccumulator.restore(view, self.state_pub, event_public_key=self.event_pub)

    def test_CONTROL_the_genuine_state_and_its_plain_copy(self):
        again = self.a.MerkleAccumulator.restore(self.good, self.state_pub, event_public_key=self.event_pub)
        self.assertEqual(again.size, 1)
        stored = copy.deepcopy(self.good)
        stored["signature"] = base64.b64encode(bytes(64)).decode()
        with self.assertRaises(self.a.AccumulatorStateError):
            self.a.MerkleAccumulator.restore(json.loads(json.dumps(stored)), self.state_pub,
                                             event_public_key=self.event_pub)


if __name__ == "__main__":
    unittest.main()
