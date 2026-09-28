"""The append-only accumulator gives the RFC 6962 values emit_bundle gives, without rebuilding the history.

tools/merkle_accumulator/accumulator.py keeps the frontier (one subtree root per set bit of the size) and,
optionally, the leaf hashes. PROPERTIES held here, against the existing merkle module as the reference:
for the same ordered leaves, the root, the new leaf's inclusion path, later inclusion proofs and
consistency proofs are byte-identical, and verify_inclusion and verify_consistency accept them, at the
sizes 0 to 3 and around every power of two up to 2^12; a bundle emitted through it is byte-identical to
emit_bundle's; a restart from a persisted state continues identically; a tampered state is refused, never
rebuilt; and one append makes at most 2 * floor(log2(n)) + 2 hash calls, counted, whatever the history.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_TOOL = REPO / "tools/merkle_accumulator/accumulator.py"
_RFC8785 = importlib.util.find_spec("rfc8785") is not None

#: Sizes 0 to 3 and 2^k - 1, 2^k, 2^k + 1 for k = 2 to 12.
_SIZES = sorted({0, 1, 2, 3} | {s for k in range(2, 13) for s in (2 ** k - 1, 2 ** k, 2 ** k + 1)})
_LEAVES = [f"leaf {i}".encode() for i in range(max(_SIZES))]


def _load():
    spec = importlib.util.spec_from_file_location("_merkle_accumulator", _TOOL)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


def _key(label: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"accumulator test: " + label.encode()).digest())


def _pub(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class TheSameValuesAsTheMerkleModule(unittest.TestCase):
    def setUp(self) -> None:
        from proofbundle import merkle
        self.m = merkle
        self.a = _load()

    def test_the_root_and_the_new_leafs_path_at_every_size(self) -> None:
        akku = self.a.MerkleAccumulator()
        self.assertEqual(akku.root(), self.m.merkle_tree_hash([]))
        for groesse in range(1, max(_SIZES) + 1):
            wurzel, pfad = akku.append(_LEAVES[groesse - 1])
            if groesse in _SIZES:
                blaetter = _LEAVES[:groesse]
                with self.subTest(size=groesse):
                    self.assertEqual(wurzel, self.m.merkle_tree_hash(blaetter))
                    self.assertEqual(akku.root(), wurzel)
                    self.assertEqual(pfad, self.m.inclusion_proof(blaetter, groesse - 1))
                    self.assertTrue(self.m.verify_inclusion(blaetter[-1], groesse - 1, groesse, pfad, wurzel))

    def test_later_inclusion_and_consistency_proofs_from_the_kept_leaf_hashes(self) -> None:
        akku = self.a.MerkleAccumulator(keep_leaf_hashes=True)
        for groesse in range(1, max(_SIZES) + 1):
            akku.append(_LEAVES[groesse - 1])
            if groesse not in _SIZES or groesse < 2:
                continue
            blaetter = _LEAVES[:groesse]
            wurzel = akku.root()
            for index in {0, groesse // 3, groesse // 2, groesse - 2}:
                with self.subTest(size=groesse, index=index):
                    pfad = akku.inclusion_proof_at(index)
                    self.assertEqual(pfad, self.m.inclusion_proof(blaetter, index))
                    self.assertTrue(self.m.verify_inclusion(blaetter[index], index, groesse, pfad, wurzel))
            for erste in {1, groesse // 2, groesse - 1, groesse}:
                with self.subTest(size=groesse, first=erste):
                    beweis = akku.consistency_proof_from(erste)
                    self.assertEqual(beweis, self.m.consistency_proof(blaetter, erste))
                    self.assertTrue(self.m.verify_consistency(erste, groesse, beweis,
                                                              self.m.merkle_tree_hash(blaetter[:erste]), wurzel))

    def test_without_kept_leaf_hashes_older_proofs_are_refused_not_guessed(self) -> None:
        akku = self.a.MerkleAccumulator()
        for blatt in _LEAVES[:5]:
            akku.append(blatt)
        with self.assertRaises(ValueError):
            akku.inclusion_proof_at(0)
        with self.assertRaises(ValueError):
            akku.consistency_proof_from(2)

    def test_the_pinned_reading_of_merkle_tree_hash(self) -> None:
        # tests/test_merkle_zwei_lesarten_vektoren.py: the argument is leaf data; reading A is the one shipped.
        eintraege = (b"entry-0: the first eval run", b"entry-1: the second eval run", b"entry-2: a run that was aborted",
                     b"entry-3: the run that was published", b"entry-4: a fifth entry, so the tree is uneven")
        self.assertEqual(self.a.MerkleAccumulator.from_leaves(list(eintraege)).root().hex(),
                         "72458930727ef63aeb4e6c92adcdc57b5e601d73a6c7415b6c00427ccc848fae")


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class TheSameBundleAsEmitBundle(unittest.TestCase):
    def test_byte_identical_bundles_and_they_verify(self) -> None:
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()
        signer = _key("emitter")
        akku = a.MerkleAccumulator()
        for groesse in range(0, 70):
            payload = f"event {groesse}".encode()
            alt = emit_bundle(payload, signer, prior_leaves=[f"event {i}".encode() for i in range(groesse)])
            neu = a.emit_bundle_incremental(payload, signer, akku)
            with self.subTest(history=groesse):
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                self.assertTrue(verify_bundle(neu).ok)
                self.assertNotIn("what_is_signed", json.dumps(neu))


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class TheRestartRule(unittest.TestCase):
    def setUp(self) -> None:
        self.a = _load()
        self.signer = _key("emitter")

    def _state_at(self, groesse: int, keep: bool = False):
        akku = self.a.MerkleAccumulator(keep_leaf_hashes=keep)
        for blatt in _LEAVES[:groesse]:
            akku.append(blatt)
        return akku, akku.state(self.signer)

    def test_a_restart_continues_exactly_as_without_one(self) -> None:
        for groesse in (0, 1, 2, 3, 7, 8, 9, 1023, 1024, 1025):
            akku, zustand = self._state_at(groesse)
            wieder = self.a.MerkleAccumulator.restore(json.loads(json.dumps(zustand)), _pub(self.signer))
            with self.subTest(size=groesse):
                for blatt in _LEAVES[groesse:groesse + 5]:
                    self.assertEqual(wieder.append(blatt), akku.append(blatt))

    def test_a_restart_with_the_kept_leaf_hashes(self) -> None:
        akku, zustand = self._state_at(37, keep=True)
        wieder = self.a.MerkleAccumulator.restore(zustand, _pub(self.signer), leaf_hashes=akku.leaf_hashes)
        self.assertEqual(wieder.consistency_proof_from(20), akku.consistency_proof_from(20))

    def test_a_tampered_state_is_refused_never_rebuilt(self) -> None:
        akku, zustand = self._state_at(37, keep=True)
        pub = _pub(self.signer)

        def geaendert(f, neu_signieren=False):
            kopie = json.loads(json.dumps(zustand))
            f(kopie["state"])
            if neu_signieren:
                import base64
                import rfc8785
                kopie["signature"] = base64.b64encode(self.signer.sign(rfc8785.dumps(kopie["state"]))).decode()
            return kopie

        faelle = {
            "a frontier root changed": geaendert(lambda s: s["frontier"][0].update(root="00" * 32)),
            "the size changed": geaendert(lambda s: s.update(tree_size=38)),
            "the root changed": geaendert(lambda s: s.update(root="11" * 32)),
            "the statement changed": geaendert(lambda s: s.update(what_is_signed="an event")),
            "re-signed with the right key, root not the fold": geaendert(lambda s: s.update(root="22" * 32), True),
            "re-signed with the right key, frontier heights wrong": geaendert(
                lambda s: s["frontier"].reverse(), True),
            "re-signed with the right key, size without its frontier": geaendert(
                lambda s: s.update(tree_size=36), True),
            "re-signed with the right key, another format": geaendert(lambda s: s.update(format="other/1"), True),
        }
        for name, kaputt in faelle.items():
            with self.subTest(case=name):
                with self.assertRaises(self.a.AccumulatorStateError):
                    self.a.MerkleAccumulator.restore(kaputt, pub)
        with self.subTest(case="signed by another key"):
            with self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(akku.state(_key("someone else")), pub)
        with self.subTest(case="leaf hashes other than the state's"):
            andere = list(akku.leaf_hashes)
            andere[3] = b"\x00" * 32
            with self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(zustand, pub, leaf_hashes=andere)
        with self.subTest(case="re-signed with the right key, the frontier of other leaves beside these hashes"):
            fremd = self.a.MerkleAccumulator.from_leaves([b"other " + b for b in _LEAVES[:37]])
            gemischt = json.loads(json.dumps(zustand))
            gemischt["state"]["frontier"] = [{"height": h, "root": r.hex()} for h, r in fremd.frontier]
            gemischt["state"]["root"] = fremd.root().hex()
            import base64
            import rfc8785
            gemischt["signature"] = base64.b64encode(self.signer.sign(rfc8785.dumps(gemischt["state"]))).decode()
            with self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(gemischt, pub, leaf_hashes=akku.leaf_hashes)

    def test_a_low_order_pinned_key_refuses_a_state_that_nobody_signed(self) -> None:
        """R = identity, S = 0 verifies for every message under the identity point, so under such a pinned
        key a state needs no private key at all (tests/test_trust_anchor_keys_refused_on_every_surface.py).
        The pinned key is checked as a trust anchor before any signature arithmetic, and the state refused."""
        import base64
        _akku, zustand = self._state_at(37)
        universell = base64.b64encode(b"\x01" + b"\x00" * 31 + b"\x00" * 32).decode()
        for name, schluessel in (("identity, canonical", b"\x01" + b"\x00" * 31),
                                 ("identity, x-sign bit set", b"\x01" + b"\x00" * 30 + b"\x80")):
            with self.subTest(key=name):
                with self.assertRaises(self.a.AccumulatorStateError):
                    self.a.MerkleAccumulator.restore(dict(zustand, signature=universell), schluessel)


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class HashWorkPerAppendDoesNotRecomputeTheHistory(unittest.TestCase):
    """Counted, not timed: the merkle module's two hash functions are wrapped for the count."""

    def _count(self, fn) -> int:
        from proofbundle import merkle
        zaehler = [0]
        alt_leaf, alt_node = merkle.leaf_hash, merkle._node_hash

        def leaf(d):
            zaehler[0] += 1
            return alt_leaf(d)

        def node(left, right):
            zaehler[0] += 1
            return alt_node(left, right)
        merkle.leaf_hash, merkle._node_hash = leaf, node
        try:
            fn()
        finally:
            merkle.leaf_hash, merkle._node_hash = alt_leaf, alt_node
        return zaehler[0]

    def test_every_append_up_to_4097_stays_within_the_logarithmic_bound(self) -> None:
        a = _load()
        akku = a.MerkleAccumulator()
        schlimmste = 0
        for groesse in range(1, 4098):
            anzahl = self._count(lambda: akku.append(_LEAVES[groesse - 1]))
            grenze = 2 * (groesse.bit_length() - 1) + 2
            self.assertLessEqual(anzahl, grenze, groesse)
            schlimmste = max(schlimmste, anzahl)
        self.assertLessEqual(schlimmste, 26)

    def test_emit_bundle_rebuilds_the_history_the_accumulator_does_not(self) -> None:
        from proofbundle.emit import emit_bundle
        a = _load()
        signer = _key("emitter")
        for groesse in (64, 1024, 4096):
            vorher = _LEAVES[:groesse]
            akku = a.MerkleAccumulator.from_leaves(vorher)
            alt = self._count(lambda: emit_bundle(b"payload", signer, prior_leaves=vorher))
            neu = self._count(lambda: a.emit_bundle_incremental(b"payload", signer, akku))
            with self.subTest(history=groesse):
                self.assertGreaterEqual(alt, 4 * groesse)
                self.assertLessEqual(neu, 2 * ((groesse + 1).bit_length() - 1) + 2)


if __name__ == "__main__":
    unittest.main()
