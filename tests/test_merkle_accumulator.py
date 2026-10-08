"""The accumulator gives the RFC 6962 values emit_bundle gives, without rebuilding the history.

tools/merkle_accumulator/accumulator.py keeps the frontier (one subtree root per set bit of the size) and,
optionally, the leaf hashes. PROPERTIES held here, against the existing merkle module as the reference:
for the same ordered leaves, the root, the new leaf's inclusion path, later inclusion proofs and
consistency proofs are byte-identical, and verify_inclusion and verify_consistency accept them, at the
sizes 0 to 3 and around every power of two up to 2^12; a bundle emitted through it is byte-identical to
emit_bundle's; a restart from a persisted state continues identically; a tampered state is refused, never
rebuilt, while an older state the same key signed is restored, as the module says; what restore reads and
what the bundle signs is one reading of what the caller passed; and one append makes at most
2 * floor(log2(n)) + 2 hash calls, counted, whatever the history.
"""
from __future__ import annotations

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


#: Throwaway seeds written out here and read from nowhere: the keys of these tests and nothing else.
#: tests/ ships in the sdist, whose guard refuses a key built from anything but a literal seed.
_EMITTER_SEED = bytes(range(32))
_OTHER_SEED = bytes(range(32, 64))


def _emitter_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_EMITTER_SEED)


def _other_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_OTHER_SEED)


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

    def test_a_proof_index_is_an_int_not_a_number_that_compares_like_one(self) -> None:
        """The range checks compare, and 0.5 and True compare like indices: inclusion_proof_at(0.5) gave the
        proof of leaf 0, consistency_proof_from(1.5) recursed without end. Anything but an int is refused
        with the ValueError the range check raises."""
        akku = self.a.MerkleAccumulator.from_leaves(_LEAVES[:3], keep_leaf_hashes=True)
        for name, aufruf in (("inclusion_proof_at(0.5)", lambda: akku.inclusion_proof_at(0.5)),
                             ("inclusion_proof_at(True)", lambda: akku.inclusion_proof_at(True)),
                             ("inclusion_proof_at('1')", lambda: akku.inclusion_proof_at("1")),
                             ("consistency_proof_from(1.5)", lambda: akku.consistency_proof_from(1.5)),
                             ("consistency_proof_from(True)", lambda: akku.consistency_proof_from(True))):
            with self.subTest(call=name):
                with self.assertRaises(ValueError):
                    aufruf()

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
        signer = _emitter_key()
        akku = a.MerkleAccumulator()
        for groesse in range(0, 70):
            payload = f"event {groesse}".encode()
            alt = emit_bundle(payload, signer, prior_leaves=[f"event {i}".encode() for i in range(groesse)])
            neu = a.emit_bundle_incremental(payload, signer, akku)
            with self.subTest(history=groesse):
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                self.assertTrue(verify_bundle(neu).ok)
                self.assertNotIn("what_is_signed", json.dumps(neu))

    def test_the_payload_is_read_once_before_the_signer_runs(self) -> None:
        """Codex thread 4217987333 on pull request 307: emit_bundle reads a bytes-like payload once before any
        code of the caller runs; the accumulator hashed the caller's buffer, and a signer that changed it before
        signing got b"b" signed beside the tree and the payload of b"a". The bundle is emit_bundle's again."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()
        echt = _emitter_key()

        class Umschreiber:
            def __init__(self, puffer):
                self.puffer = puffer

            def sign(self, data):
                self.puffer[:] = b"b"
                return echt.sign(data)

            def public_key(self):
                return echt.public_key()
        for vorher in (0, 1, 5):
            leaves = [f"event {i}".encode() for i in range(vorher)]
            p_alt, p_neu = bytearray(b"a"), bytearray(b"a")
            alt = emit_bundle(p_alt, Umschreiber(p_alt), prior_leaves=leaves)
            neu = a.emit_bundle_incremental(p_neu, Umschreiber(p_neu), a.MerkleAccumulator.from_leaves(leaves))
            with self.subTest(history=vorher):
                self.assertEqual(p_neu, b"b", "the signer ran and changed the caller's buffer")
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                self.assertTrue(verify_bundle(neu).ok)

    def test_no_value_of_the_bundle_is_read_after_the_signer_runs(self) -> None:
        """Codex thread 4218672721 on pull request 307: tree_size was read from the accumulator after the signer's
        public_key and sign had run, and a signer holding the accumulator could append before it was read. The
        bundle is emit_bundle's for the history before the call, whichever of the two appends."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()
        echt = _emitter_key()
        for methode in ("public_key", "sign"):
            for vorher in (0, 1, 5):
                leaves = [f"event {i}".encode() for i in range(vorher)]
                akku = a.MerkleAccumulator.from_leaves(leaves)

                class Anhaenger:
                    def public_key(self, m=methode, akku=akku):
                        if m == "public_key":
                            akku.append(b"extra")
                        return echt.public_key()

                    def sign(self, data, m=methode, akku=akku):
                        if m == "sign":
                            akku.append(b"extra")
                        return echt.sign(data)
                neu = a.emit_bundle_incremental(b"payload", Anhaenger(), akku)
                alt = emit_bundle(b"payload", echt, prior_leaves=leaves)
                with self.subTest(appends_in=methode, history=vorher):
                    self.assertEqual(akku.size, vorher + 2, "the signer ran and appended")
                    self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                    self.assertTrue(verify_bundle(neu).ok)

    def test_the_accumulator_cannot_be_subclassed_and_the_emitter_takes_only_it(self) -> None:
        """Codex threads 4219691072, 4220260056, 4220260071 and 4220260074 on pull request 307: a subclass of the
        caller overrode append, the size, the frontier through __getattribute__, or the append a rebuild calls, and
        each time the bundle or a restore check read the caller's answer. The class refuses to be subclassed, and
        emit_bundle_incremental refuses any object that is not exactly a MerkleAccumulator."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()
        echt = _emitter_key()
        koerper = {
            "append": {"append": lambda self, data: None},
            "size": {"size": property(lambda self: 1)},
            "__getattribute__": {"__getattribute__": lambda self, name: object.__getattribute__(self, name)},
            "root": {"root": lambda self: b"\x22" * 32},
            "_frontier_from_leaf_hashes": {"_frontier_from_leaf_hashes": staticmethod(lambda hashes: [])},
            "nothing": {},
        }
        for name, inhalt in koerper.items():
            with self.subTest(overrides=name), self.assertRaisesRegex(TypeError, "cannot be subclassed"):
                type("Abgeleitet", (a.MerkleAccumulator,), dict(inhalt))

        class Aehnlich:
            size, frontier, leaf_hashes = 0, [], None

            def append(self, data):
                return a.MerkleAccumulator().append(data)
        with self.assertRaisesRegex(TypeError, "takes a MerkleAccumulator"):
            a.emit_bundle_incremental(b"payload", echt, Aehnlich())
        # Codex thread 4220760321: a method assigned on one instance shadowed the class's; there is no instance
        # dictionary to assign it in, and a new attribute of any name is refused the same way.
        akku = a.MerkleAccumulator()
        for name, wert in (("append", lambda _: (b"\x22" * 32, [])), ("root", lambda: b"\x22" * 32),
                           ("anything", 1)):
            with self.subTest(assigns=name), self.assertRaises(AttributeError):
                setattr(akku, name, wert)
        self.assertFalse(hasattr(akku, "__dict__"))
        for vorher in (0, 1, 5):
            leaves = [f"event {i}".encode() for i in range(vorher)]
            neu = a.emit_bundle_incremental(b"payload", echt, a.MerkleAccumulator.from_leaves(leaves))
            alt = emit_bundle(b"payload", echt, prior_leaves=leaves)
            with self.subTest(control=vorher):
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                self.assertTrue(verify_bundle(neu).ok)

    def test_the_rebuild_reads_the_leaves_as_the_reference_does(self) -> None:
        """Codex thread 4219691080 on pull request 307: from_leaves iterated the caller's list through its own
        __iter__, and emit_bundle reads prior_leaves through the base type. A list subclass that yields other leaves
        than it stores gave the rebuild another tree than the reference; now both read the stored leaves."""
        from proofbundle.emit import emit_bundle
        from proofbundle.merkle import merkle_tree_hash
        a = _load()
        echt = _emitter_key()

        class Anders(list):
            def __iter__(self):
                return iter([b"x", b"y"])
        for liste in (Anders([b"a", b"b"]), Anders([bytearray(b"a"), b"b"])):
            akku = a.MerkleAccumulator.from_leaves(liste)
            with self.subTest(leaves=[type(b).__name__ for b in list.__iter__(liste)]):
                self.assertEqual(akku.root(), merkle_tree_hash([b"a", b"b"]))
                neu = a.emit_bundle_incremental(b"payload", echt, akku)
                alt = emit_bundle(b"payload", echt, prior_leaves=liste)
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))

    def test_the_signer_is_asked_in_emit_bundles_order(self) -> None:
        """Codex thread 4219203464 on pull request 307: emit_bundle signs and then reads the public key, and the
        accumulator read the key first. A signer whose public_key answers by whether it has signed yet then gave the
        two paths different keys beside one signature. The order is emit_bundle's, and the bundles are the same."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()

        class NachDerSignatur:
            def __init__(self):
                self.a, self.b, self.signiert = _emitter_key(), _other_key(), False

            def sign(self, data):
                self.signiert = True
                return self.a.sign(data)

            def public_key(self):
                return (self.a if self.signiert else self.b).public_key()
        for vorher in (0, 3):
            leaves = [f"event {i}".encode() for i in range(vorher)]
            alt = emit_bundle(b"payload", NachDerSignatur(), prior_leaves=leaves)
            neu = a.emit_bundle_incremental(b"payload", NachDerSignatur(), a.MerkleAccumulator.from_leaves(leaves))
            with self.subTest(history=vorher):
                self.assertTrue(verify_bundle(alt).ok, "control: emit_bundle's bundle verifies")
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class TheRestartRule(unittest.TestCase):
    def setUp(self) -> None:
        self.a = _load()
        self.signer = _emitter_key()

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
                self.a.MerkleAccumulator.restore(akku.state(_other_key()), pub)
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

    def test_restore_is_a_method_of_the_accumulator_alone(self) -> None:
        """The class of Codex thread 4220260056 at restore: with no subclass, restore is the accumulator's own
        classmethod, and the two re-signed tampered states it must refuse are refused through it."""
        import base64
        import rfc8785
        akku, zustand = self._state_at(37, keep=True)
        pub = _pub(self.signer)
        fremd = self.a.MerkleAccumulator.from_leaves([b"other " + b for b in _LEAVES[:37]])

        def signiert(inhalt):
            return {"state": inhalt, "signature": base64.b64encode(self.signer.sign(rfc8785.dumps(inhalt))).decode()}
        falsche_wurzel = json.loads(json.dumps(zustand["state"]))
        falsche_wurzel["root"] = "22" * 32
        fremde_front = json.loads(json.dumps(zustand["state"]))
        fremde_front["frontier"] = [{"height": h, "root": r.hex()} for h, r in fremd.frontier]
        fremde_front["root"] = fremd.root().hex()
        for name, kaputt, blaetter in (("root not the fold", signiert(falsche_wurzel), None),
                                       ("frontier of other leaves beside these hashes", signiert(fremde_front),
                                        akku.leaf_hashes)):
            with self.subTest(case=name), self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(kaputt, pub, leaf_hashes=blaetter)
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
            type("Gefaellig", (self.a.MerkleAccumulator,), {"root": lambda self: b"\x22" * 32})

    def test_a_signed_state_of_another_shape_or_spelling_is_refused_as_a_state_error(self) -> None:
        """The signature check comes first, so everything after it reads values the pinned key signed, and
        signed is not well formed: a signed [] reached `.get` and escaped as a raw AttributeError. And a
        frontier field went through int() and bytes.fromhex, which read "1", true, upper case and spaces
        as the value state() writes, so one state restored from several signed spellings. Each is refused
        as an AccumulatorStateError, the form the restart rule names."""
        import base64
        import rfc8785

        def signiert(inhalt):
            return {"state": inhalt,
                    "signature": base64.b64encode(self.signer.sign(rfc8785.dumps(inhalt))).decode()}

        pub = _pub(self.signer)
        _akku, zustand = self._state_at(3)
        self.assertEqual([e["height"] for e in zustand["state"]["frontier"]], [1, 0])
        self.a.MerkleAccumulator.restore(signiert(zustand["state"]), pub)   # re-signed as written: restored

        def feld(index, **neu):
            kopie = json.loads(json.dumps(zustand["state"]))
            kopie["frontier"][index].update(neu)
            return signiert(kopie)

        wurzel0 = zustand["state"]["frontier"][0]["root"]
        faelle = {
            "a signed empty list": signiert([]),
            "a signed string": signiert("a state"),
            "a signed number": signiert(37),
            "a signed null": signiert(None),
            "a signed list holding the state": signiert([zustand["state"]]),
            "a height as a string": feld(0, height="1"),
            "a height as true": feld(0, height=True),
            "a height as false": feld(1, height=False),
            "a root in upper case": feld(0, root=wurzel0.upper()),
            "a root with spaces": feld(0, root=" ".join(wurzel0[i:i + 2] for i in range(0, 64, 2))),
        }
        for name, kaputt in faelle.items():
            with self.subTest(case=name):
                with self.assertRaises(self.a.AccumulatorStateError):
                    self.a.MerkleAccumulator.restore(kaputt, pub)

    def test_restored_leaf_hashes_are_32_bytes_each_not_pieces_of_one_joined_string(self) -> None:
        """The state commits to its leaf hashes by the SHA-256 of their concatenation, and the frontier check
        feeds them to the unframed node hash: neither sees where one leaf hash ends and the next begins. A
        re-split of the same bytes, [h0[:1], h0[1:] + h1], keeps the count, the digest and the frontier. Each
        restored leaf hash is 32 bytes of type bytes (a bytearray could change after the check), and a
        list of them, or the state is refused."""
        from proofbundle import merkle
        akku, zustand = self._state_at(2, keep=True)
        pub = _pub(self.signer)
        h0, h1 = akku.leaf_hashes
        vorne, hinten = [h0[:1], h0[1:] + h1], [h0 + h1[:1], h1[1:]]
        # Catch proof: the re-splits pass the count, the digest and the frontier as they stand, so only a rule
        # on each leaf hash's own length can refuse them.
        for teile in (vorne, hinten):
            self.assertEqual(len(teile), 2)
            self.assertEqual(b"".join(teile), h0 + h1)
            self.assertEqual(self.a.MerkleAccumulator._frontier_from_leaf_hashes(teile), akku.frontier)
            self.assertFalse(merkle.verify_inclusion(_LEAVES[0], 0, 2, [teile[1]], akku.root()))
        faelle = {
            "re-split after byte 1": vorne,
            "re-split after byte 33": hinten,
            "hex strings": [h0.hex(), h1.hex()],
            "a bytearray": [bytearray(h0), h1],
            "a generator": (h for h in (h0, h1)),
            "one bytes object": h0 + h1,
        }
        for name, blaetter in faelle.items():
            with self.subTest(case=name):
                with self.assertRaises(self.a.AccumulatorStateError):
                    self.a.MerkleAccumulator.restore(zustand, pub, leaf_hashes=blaetter)
        with self.subTest(case="the leaf hashes as written, as a tuple"):
            wieder = self.a.MerkleAccumulator.restore(zustand, pub, leaf_hashes=(h0, h1))
            self.assertEqual(wieder.inclusion_proof_at(0), [h1])

    def test_restored_leaf_hashes_are_read_once_and_kept_as_checked(self) -> None:
        """Codex thread 4218672732 on pull request 307: the type check, the digest and the frontier each iterated the
        caller's list, and the copy kept was a fourth reading. A list subclass that yields the signed hashes three
        times and others then was restored with hashes nobody checked. The list is read once, through its base
        type's own iteration, and what is kept is what was checked."""
        akku, zustand = self._state_at(5, keep=True)
        echt = list(akku.leaf_hashes)
        fremd = [bytes([i]) * 32 for i in range(5)]

        class Wechselnd(list):
            def __init__(self, *args):
                super().__init__(*args)
                self.lesungen = 0

            def __iter__(self):
                self.lesungen += 1
                return iter(echt) if self.lesungen <= 3 else iter(fremd)
        wieder = self.a.MerkleAccumulator.restore(zustand, _pub(self.signer), leaf_hashes=Wechselnd(echt))
        self.assertEqual(wieder.leaf_hashes, echt)
        self.assertEqual(wieder.inclusion_proof_at(1), akku.inclusion_proof_at(1))

    def test_a_state_signature_is_one_snapshot_and_the_text_claims_no_more(self) -> None:
        """The boundary, measured: restore checks a state against the pinned key and against itself, and knows
        no other state. Written at size 1 and at size 2, the size-1 state restores after the size-2 one, and
        another leaf appended to it gives a second tree of size 2 beside the first. So the signed statement
        and the docstrings claim no append-only tree: the house rule (scripts/claims_hygiene_check.py) keeps
        that word for a public transparency log, and a signed statement is not prose a negation elsewhere
        in its clause may excuse, so it must not carry the word at all."""
        import re
        pub = _pub(self.signer)
        akku = self.a.MerkleAccumulator()
        akku.append(_LEAVES[0])
        eins = akku.state(self.signer)
        wurzel_zwei, _ = akku.append(_LEAVES[1])
        self.assertEqual(akku.state(self.signer)["state"]["tree_size"], 2)
        zurueck = self.a.MerkleAccumulator.restore(eins, pub)
        self.assertEqual(zurueck.size, 1)
        gabel, _ = zurueck.append(b"another second leaf")
        self.assertNotEqual(gabel, wurzel_zwei)

        spec = importlib.util.spec_from_file_location("_claims_hygiene", REPO / "scripts/claims_hygiene_check.py")
        hygiene = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hygiene)
        for name, text in (("WHAT_IS_SIGNED", self.a.WHAT_IS_SIGNED), ("the persisted state", json.dumps(eins))):
            with self.subTest(signed=name):
                self.assertIsNone(re.search(hygiene._APPEND_ONLY_PATTERN, text, re.IGNORECASE))
        for name, text in (("module", self.a.__doc__), ("class", self.a.MerkleAccumulator.__doc__),
                           ("restore", self.a.MerkleAccumulator.restore.__doc__), ("tests", __doc__)):
            with self.subTest(docstring=name):
                self.assertEqual(hygiene.scan_text(text, name), [])

    def test_restore_reads_the_state_the_signature_covers(self) -> None:
        """Codex thread 4217987333 on pull request 307, its class swept to restore: the signature was checked over
        the canonical form of the mapping, which reads what a dict stores, and the fields were then read through
        `.get` and `[]`, which a dict subclass answers itself. A subclass answering with the frontier, size and
        root of another tree, consistent among themselves, restored a state nobody signed."""
        _akku, zustand = self._state_at(37)
        fremd = self.a.MerkleAccumulator.from_leaves([b"other " + b for b in _LEAVES[:37]])
        anders = {"frontier": [{"height": h, "root": r.hex()} for h, r in fremd.frontier], "root": fremd.root().hex()}

        class ZweiLesarten(dict):
            def get(self, key, default=None):
                return anders[key] if key in anders else dict.get(self, key, default)

            def __getitem__(self, key):
                return anders[key] if key in anders else dict.__getitem__(self, key)
        wieder = self.a.MerkleAccumulator.restore(dict(zustand, state=ZweiLesarten(zustand["state"])), _pub(self.signer))
        self.assertEqual(wieder.root().hex(), zustand["state"]["root"])
        self.assertNotEqual(wieder.root(), fremd.root())

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
class _CountingHashlib:
    """A module's `hashlib` for the duration of a count: every `sha256` call is counted, every other name is the
    real module's."""

    def __init__(self, echt, zaehler) -> None:
        self._echt, self._zaehler = echt, zaehler

    def sha256(self, *args, **kwargs):
        self._zaehler[0] += 1
        return self._echt.sha256(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._echt, name)


def _count_sha256(fn, *module) -> int:
    """Every SHA-256 call the merkle module and the given modules make while `fn` runs, whichever of their
    functions makes it. Codex thread 4217987321 on pull request 307: the count wrapped the public `leaf_hash`,
    main's tree calls `_leaf_hash`, and every leaf of an emit went uncounted (127 instead of at least 256 at 64
    prior leaves). A count by the name of a function misses the next path that does not take that name."""
    from proofbundle import merkle
    zaehler = [0]
    module = (merkle, *module)
    echt = [m.hashlib for m in module]
    for m in module:
        m.hashlib = _CountingHashlib(m.hashlib, zaehler)
    try:
        fn()
    finally:
        for m, h in zip(module, echt):
            m.hashlib = h
    return zaehler[0]


class HashWorkPerAppendDoesNotRecomputeTheHistory(unittest.TestCase):
    """Counted, not timed: every SHA-256 call of the merkle module and of the accumulator, by any path."""

    def _count(self, fn, a=None) -> int:
        return _count_sha256(fn, *((a,) if a is not None else ()))

    def test_the_count_is_the_rfc_6962_count_and_follows_any_path(self) -> None:
        """The control, from arithmetic and not from the code counted: an RFC 6962 tree over n leaves hashes n
        leaves and n - 1 nodes. And a leaf path the counter has never heard of is counted all the same."""
        from proofbundle import merkle
        for n in range(1, 10):
            with self.subTest(leaves=n):
                self.assertEqual(self._count(lambda: merkle.merkle_tree_hash(_LEAVES[:n])), 2 * n - 1)
        alt = merkle._leaf_hash

        def anderer_weg(data):
            return merkle.hashlib.sha256(b"\x00" + bytes(data)).digest()
        merkle._leaf_hash = anderer_weg
        try:
            self.assertEqual(self._count(lambda: merkle.merkle_tree_hash(_LEAVES[:8])), 15)
        finally:
            merkle._leaf_hash = alt
        self.assertIs(merkle.hashlib, __import__("hashlib"), "the module's hashlib is restored")

    def test_every_append_up_to_4097_stays_within_the_logarithmic_bound(self) -> None:
        a = _load()
        akku = a.MerkleAccumulator()
        schlimmste = 0
        for groesse in range(1, 4098):
            anzahl = self._count(lambda: akku.append(_LEAVES[groesse - 1]), a)
            grenze = 2 * (groesse.bit_length() - 1) + 2
            self.assertLessEqual(anzahl, grenze, groesse)
            schlimmste = max(schlimmste, anzahl)
        self.assertLessEqual(schlimmste, 26)

    def test_emit_bundle_rebuilds_the_history_the_accumulator_does_not(self) -> None:
        from proofbundle.emit import emit_bundle
        a = _load()
        signer = _emitter_key()
        for groesse in (64, 1024, 4096):
            vorher = _LEAVES[:groesse]
            akku = a.MerkleAccumulator.from_leaves(vorher)
            alt = self._count(lambda: emit_bundle(b"payload", signer, prior_leaves=vorher))
            neu = self._count(lambda: a.emit_bundle_incremental(b"payload", signer, akku), a)
            with self.subTest(history=groesse):
                self.assertGreaterEqual(alt, 4 * groesse)
                self.assertLessEqual(neu, 2 * ((groesse + 1).bit_length() - 1) + 2)


if __name__ == "__main__":
    unittest.main()
