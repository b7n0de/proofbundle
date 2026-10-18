"""The accumulator gives the RFC 6962 values emit_bundle gives, without rebuilding the history.

tools/merkle_accumulator/accumulator.py keeps the frontier (one subtree root per set bit of the size) and,
optionally, the leaf hashes. PROPERTIES held here, against the existing merkle module as the reference:
for the same ordered leaves, the root, the new leaf's inclusion path, later inclusion proofs and
consistency proofs are byte-identical, and verify_inclusion and verify_consistency accept them, at the
sizes 0 to 3 and around every power of two up to 2^12; a bundle emitted through it is byte-identical to
emit_bundle's; a restart from a persisted state continues identically; a tampered state is refused, never
rebuilt, while an older state the same key signed is restored, as the module says; an event's signature from
emit_bundle or this tool does not restore as a state's, and a failed emission leaves the accumulator as it was;
what restore reads and what the bundle signs is one reading of what the caller passed; and one append makes at
most 2 * floor(log2(n)) + 2 hash calls, counted, whatever the history.
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
#: The key events are signed with in the restart cases; the states there are signed with the emitter key above, which
#: is a state key in those cases (A STATE KEY IS NOT THE EVENT KEY in the module docstring).
_EVENT_SEED = bytes(range(64, 96))


def _emitter_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_EMITTER_SEED)


def _other_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_OTHER_SEED)


def _event_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(_EVENT_SEED)


def _event_pub() -> bytes:
    return _pub(_event_key())


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


#: Stands for a field deleted with object.__delattr__ in the cases of a field written from outside.
_GELOESCHT = object()


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

    def test_a_field_written_from_outside_while_the_signer_runs_stops_the_write(self) -> None:
        """The write at the end goes onto exactly the state the bundle was computed from, not onto one of the same
        size. A signer that writes the frontier of another tree of the same shape with object.__setattr__, or replaces
        the kept leaf hashes with a list of the same length, leaves the size as it was and the fields fitting each
        other; the emission still writes nothing, raises RuntimeError, and the signer's write stays. A leaf hash
        appended to the list from outside breaks the fit, and the field check before the write refuses it."""
        a = _load()
        echt = _emitter_key()
        leaves = [f"event {i}".encode() for i in range(5)]
        anders = a.MerkleAccumulator.from_leaves([b"other " + b for b in leaves], keep_leaf_hashes=True)
        faelle = {
            "another frontier of the same shape": (
                lambda akku: object.__setattr__(akku, "_frontier", anders._frontier), RuntimeError),
            "another list of leaf hashes": (
                lambda akku: object.__setattr__(akku, "_leaf_hashes", anders.leaf_hashes), RuntimeError),
            "a leaf hash appended from outside": (
                lambda akku: akku._leaf_hashes.append(b"\x22" * 32), a.AccumulatorStateError),
        }
        for name, (schreiben, fehler) in faelle.items():
            akku = a.MerkleAccumulator.from_leaves(leaves, keep_leaf_hashes=True)

            class Schreibend:
                def sign(self, data, akku=akku, schreiben=schreiben):
                    schreiben(akku)
                    return echt.sign(data)

                def public_key(self):
                    return echt.public_key()
            with self.subTest(writes=name):
                with self.assertRaises(fehler):
                    a.emit_bundle_incremental(b"payload", Schreibend(), akku)
                self.assertEqual(akku._size, 5)
                self.assertNotIn(a._leaf(b"payload"), akku._leaf_hashes)

    def test_an_interrupt_at_any_line_leaves_the_state_before_a_refused_one_or_the_whole_leaf(self) -> None:
        """The boundary the module names, measured at every line it runs. An adversarial lens raised KeyboardInterrupt
        from a signal handler while emit_bundle_incremental ran; with the leaf appended before the signer, an interrupt
        between the append and the guard after it left a leaf without a bundle. Here the interrupt is raised at the
        k-th line the module runs during one call, for every k until the call returns. Before the writes at the end
        the accumulator is as it was, between two of them every operation refuses it, and only at the return, after
        the last write, is the leaf written without its bundle being returned. The tracer that ran before (a coverage
        run's) is set again afterwards."""
        import sys
        from collections import Counter
        a = _load()
        echt = _emitter_key()
        datei = str(_TOOL)
        zeilen = _TOOL.read_text(encoding="utf-8").splitlines()
        for behalten in (False, True):
            for vorher in (0, 3, 6):
                leaves = [f"event {i}".encode() for i in range(vorher)]
                ergebnisse: Counter = Counter()
                k = 0
                while True:
                    k += 1
                    akku = a.MerkleAccumulator.from_leaves(leaves, keep_leaf_hashes=behalten)
                    davor = (akku._size, akku._frontier, akku.leaf_hashes)
                    stand = {"zeilen": 0, "zeile": None}

                    def lokal(frame, event, arg, k=k, stand=stand):
                        if event == "line":
                            stand["zeilen"] += 1
                            if stand["zeilen"] == k:
                                stand["zeile"] = frame.f_lineno
                                raise KeyboardInterrupt
                        return lokal

                    def global_(frame, event, arg, lokal=lokal):
                        return lokal if frame.f_code.co_filename == datei else None
                    vorheriger = sys.gettrace()
                    sys.settrace(global_)
                    try:
                        bundle = a.emit_bundle_incremental(b"payload", echt, akku)
                    except KeyboardInterrupt:
                        bundle = None
                    finally:
                        sys.settrace(vorheriger)
                    if bundle is not None:
                        break       # the call ran fewer than k lines: every line has had its interrupt
                    if (akku._size, akku._frontier) == davor[:2] and (
                            akku._leaf_hashes is None or list(akku._leaf_hashes) == davor[2]):
                        ergebnisse["as before"] += 1
                        continue
                    try:
                        groesse = akku.size
                    except a.AccumulatorStateError:
                        ergebnisse["refused"] += 1
                        continue
                    with self.subTest(keep_leaf_hashes=behalten, history=vorher, line=stand["zeile"]):
                        self.assertEqual(zeilen[stand["zeile"] - 1].strip(), "return bundle")
                        self.assertEqual((groesse, akku.root()),
                                         (vorher + 1, a.MerkleAccumulator.from_leaves(leaves + [b"payload"]).root()))
                    ergebnisse["whole leaf, no bundle"] += 1
                with self.subTest(keep_leaf_hashes=behalten, history=vorher, counts=dict(ergebnisse)):
                    self.assertGreater(ergebnisse["as before"], 20)
                    self.assertGreaterEqual(ergebnisse["refused"], 1)
                    self.assertEqual(ergebnisse["whole leaf, no bundle"], 1)
                    self.assertEqual(sum(ergebnisse.values()), k - 1)

    def test_a_signer_that_changes_the_accumulator_gets_no_bundle_for_a_taken_position(self) -> None:
        """Codex thread 4218672721 on pull request 307: tree_size was read from the accumulator after the signer's
        public_key and sign had run, and a signer holding the accumulator could append before it was read. Since
        thread 4245187393 on pull request 340 the leaf is written only after the bundle is built, so such a signer's
        append now takes the position the bundle would name. Nothing is written, RuntimeError is raised, and the
        signer's change stays: an append, or an emission of its own, whose bundle then matches the accumulator. An
        adversarial lens found the alternative, setting everything back, withdrew the leaf of a bundle the signer
        already held, and a later bundle named the same position with another root."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()
        echt = _emitter_key()
        for art in ("append in public_key", "append in sign", "append in sign, then raises", "emission in sign",
                    "emission in sign, then raises"):
            for vorher in (0, 1, 5):
                leaves = [f"event {i}".encode() for i in range(vorher)]
                akku = a.MerkleAccumulator.from_leaves(leaves)
                gehalten = {}

                class Aendernd:
                    def public_key(self, art=art, akku=akku):
                        if art == "append in public_key":
                            akku.append(b"extra")
                        return echt.public_key()

                    def sign(self, data, art=art, akku=akku):
                        if art.startswith("append in sign"):
                            akku.append(b"extra")
                        if art.startswith("emission in sign"):
                            gehalten["innen"] = a.emit_bundle_incremental(b"extra", echt, akku)
                        if art.endswith("then raises"):
                            raise KeyError("the signer fails after its own emission")
                        return echt.sign(data)
                with self.subTest(changes=art, history=vorher):
                    with self.assertRaises(KeyError if art.endswith("then raises") else RuntimeError):
                        a.emit_bundle_incremental(b"payload", Aendernd(), akku)
                    self.assertEqual(akku.size, vorher + 1, "the signer's change stays, and nothing else")
                    self.assertEqual(akku.root(), a.MerkleAccumulator.from_leaves(leaves + [b"extra"]).root())
                    if "innen" in gehalten:
                        innen = emit_bundle(b"extra", echt, prior_leaves=leaves)
                        self.assertEqual(json.dumps(gehalten["innen"], sort_keys=True),
                                         json.dumps(innen, sort_keys=True))
                    danach = a.emit_bundle_incremental(b"payload", echt, akku)
                    alt = emit_bundle(b"payload", echt, prior_leaves=leaves + [b"extra"])
                    self.assertEqual(json.dumps(danach, sort_keys=True), json.dumps(alt, sort_keys=True))
                    self.assertTrue(verify_bundle(danach).ok)

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
        # Codex thread 4221180480: a caller assigned a list subclass to the public frontier, and the class's append
        # dispatched to its methods. The state is read-only from outside, and what is read is a copy.
        for name, wert in (("frontier", []), ("size", 3), ("leaf_hashes", [])):
            with self.subTest(assigns=name), self.assertRaises(AttributeError):
                setattr(akku, name, wert)
        akku = a.MerkleAccumulator(keep_leaf_hashes=True)
        akku.append(b"a")
        akku.frontier.append((0, b"\x22" * 32))
        akku.leaf_hashes.append(b"\x22" * 32)
        self.assertEqual((akku.size, len(akku.frontier), len(akku.leaf_hashes)), (1, 1, 1))

        class Fremd(list):
            def append(self, wert):
                super().append((0, b"\x22" * 32))
                super().append(wert)
        object.__setattr__(akku, "_frontier", Fremd(akku.frontier))
        with self.assertRaisesRegex(TypeError, "private fields"):
            a.emit_bundle_incremental(b"payload", echt, akku)
        # Codex thread 4221630977: the private slots were writable as well. No attribute can be set by assignment, and
        # a kept frontier is a tuple. A leaf hash appended to the kept list from outside leaves more leaf hashes than
        # leaves, and the emitter refuses the accumulator (thread 4222117574, THE FIELDS ARE CHECKED).
        akku = a.MerkleAccumulator(keep_leaf_hashes=True)
        for blatt in (b"a", b"b", b"c"):
            akku.append(blatt)
        for name, wert in (("_size", 5), ("_frontier", ()), ("_leaf_hashes", []), ("neu", 1)):
            with self.subTest(assigns=name), self.assertRaises(AttributeError):
                setattr(akku, name, wert)
        gehalten = akku._frontier
        self.assertIs(type(gehalten), tuple)
        akku._leaf_hashes.append(b"\x22" * 32)
        with self.assertRaises(a.AccumulatorStateError):
            a.emit_bundle_incremental(b"payload", echt, akku)
        for vorher in (0, 1, 5):
            leaves = [f"event {i}".encode() for i in range(vorher)]
            neu = a.emit_bundle_incremental(b"payload", echt, a.MerkleAccumulator.from_leaves(leaves))
            alt = emit_bundle(b"payload", echt, prior_leaves=leaves)
            with self.subTest(control=vorher):
                self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                self.assertTrue(verify_bundle(neu).ok)

    def test_a_field_written_from_outside_is_refused_by_every_operation(self) -> None:
        """Codex thread 4222117574 on pull request 307: the class's own slot writer could be called from outside, and
        a size of 5 written into an empty accumulator gave the next emission leaf_index 5 and tree_size 6 with an
        empty path; object.__setattr__ does the same, for the frontier and the leaf hashes too. Python cannot stop
        such a write, so every operation checks the fields against each other first. Each field is written here with
        object.__setattr__, in each way that breaks the fit, and every operation refuses. Leaf hashes that keep their
        number and lose their values reach only the operations that read them, the later proofs and state, which
        check them against the frontier."""
        a = _load()
        echt = _emitter_key()
        self.assertFalse(hasattr(a.MerkleAccumulator, "_setze"), "no method writes a field by a caller's name")
        for name in ("_size", "_frontier", "_leaf_hashes"):
            with self.subTest(deletes=name), self.assertRaises(AttributeError):
                delattr(a.MerkleAccumulator(), name)
        leer = a.MerkleAccumulator()
        object.__setattr__(leer, "_size", 5)
        with self.assertRaises(a.AccumulatorStateError):
            a.emit_bundle_incremental(b"payload", echt, leer)

        def h(i):
            return bytes([i]) * 32
        # (field, value, whether only the operations that read the leaf hashes can see it), on a tree of three leaves
        faelle = (("_size", 5, False), ("_size", 2, False), ("_size", 4, False), ("_size", -1, False),
                  ("_size", True, False), ("_frontier", (), False), ("_frontier", ((0, h(1)),), False),
                  ("_frontier", ((0, h(1)), (1, h(2))), False), ("_frontier", ((1, h(1)), (0, b"short")), False),
                  ("_frontier", ((1, h(1)), (0, bytearray(h(2)))), False),
                  ("_frontier", ((True, h(1)), (0, h(2))), False),
                  ("_frontier", ((1, h(1)), (0, h(2)), (0, h(3))), False),
                  ("_frontier", [(1, h(1)), (0, h(2))], False),
                  ("_leaf_hashes", [], False), ("_leaf_hashes", [h(1)] * 4, False),
                  ("_leaf_hashes", (h(1),) * 3, False),
                  ("_leaf_hashes", [h(1)] * 3, True), ("_leaf_hashes", [b"short"] * 3, True),
                  # Codex thread 4222912721: a slot deleted with object.__delattr__ is refused like one written
                  ("_size", _GELOESCHT, False), ("_frontier", _GELOESCHT, False),
                  ("_leaf_hashes", _GELOESCHT, False))

        def operationen(akku):
            return {"append": lambda: akku.append(b"d"), "root": akku.root, "size": lambda: akku.size,
                    "frontier": lambda: akku.frontier, "leaf_hashes": lambda: akku.leaf_hashes, "copy": akku.copy,
                    "state": lambda: akku.state(echt, event_public_key=_event_pub()), "inclusion_proof_at": lambda: akku.inclusion_proof_at(0),
                    "consistency_proof_from": lambda: akku.consistency_proof_from(1),
                    "emit_bundle_incremental": lambda: a.emit_bundle_incremental(b"payload", echt, akku)}
        lesen_die_blaetter = {"state", "inclusion_proof_at", "consistency_proof_from"}
        for name in operationen(a.MerkleAccumulator()):
            with self.subTest(control=name):
                operationen(a.MerkleAccumulator.from_leaves([b"a", b"b", b"c"], keep_leaf_hashes=True))[name]()
        for feld, wert, nur_blaetter in faelle:
            for name in operationen(a.MerkleAccumulator()):
                akku = a.MerkleAccumulator.from_leaves([b"a", b"b", b"c"], keep_leaf_hashes=True)
                if wert is _GELOESCHT:
                    object.__delattr__(akku, feld)
                else:
                    # a fresh list each time: an append the operation makes must not reach the next case
                    object.__setattr__(akku, feld, list(wert) if type(wert) is list else wert)
                with self.subTest(field=feld, value=repr(wert)[:40], operation=name):
                    if nur_blaetter and name not in lesen_die_blaetter:
                        operationen(akku)[name]()   # the number fits, and this operation reads no leaf hash
                    else:
                        with self.assertRaises((TypeError, a.AccumulatorStateError)):
                            operationen(akku)[name]()

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

    def test_a_failed_emission_appends_nothing(self) -> None:
        """Codex thread 4245187393 on pull request 340: the payload was appended before the signer ran, and a signer
        that raised left the accumulator one leaf larger with no bundle for that leaf; the next emission got the
        index after it and a root over the failed payload. Whatever raises in the signer, in the key's serialization or
        in the encoding of what the signer returned, the accumulator is as it was before the call, and the next emission
        is emit_bundle's. A signer that changes the accumulator and then raises is the case of the next test."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.emit import emit_bundle
        a = _load()
        echt = _emitter_key()

        class Abbruch(Exception):
            pass

        class OhneRohform:
            def public_bytes(self, *args):
                raise Abbruch("public_bytes")

        def signierer(art, akku):
            class Signierer:
                def sign(self, data):
                    if art == "sign raises":
                        raise Abbruch(art)
                    return "not bytes" if art == "sign returns a str" else echt.sign(data)

                def public_key(self):
                    if art == "public_key raises":
                        raise Abbruch(art)
                    return OhneRohform() if art == "public_bytes raises" else echt.public_key()
            return Signierer()
        for art in ("sign raises", "public_key raises", "public_bytes raises", "sign returns a str"):
            for vorher in (0, 1, 5):
                for behalten in (False, True):
                    leaves = [f"event {i}".encode() for i in range(vorher)]
                    akku = a.MerkleAccumulator.from_leaves(leaves, keep_leaf_hashes=behalten)
                    davor = (akku.size, akku.frontier, akku.leaf_hashes, akku.root())
                    with self.subTest(fails=art, history=vorher, keep_leaf_hashes=behalten):
                        with self.assertRaises((Abbruch, TypeError)):
                            a.emit_bundle_incremental(b"failed", signierer(art, akku), akku)
                        self.assertEqual((akku.size, akku.frontier, akku.leaf_hashes, akku.root()), davor)
                        neu = a.emit_bundle_incremental(b"payload", echt, akku)
                        alt = emit_bundle(b"payload", echt, prior_leaves=leaves)
                        self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))
                        self.assertTrue(verify_bundle(neu).ok)


@unittest.skipUnless(_RFC8785, "the persisted state is signed over its RFC 8785 form (the [eval] extra)")
class TheRestartRule(unittest.TestCase):
    def setUp(self) -> None:
        self.a = _load()
        self.signer = _emitter_key()

    def _state_at(self, groesse: int, keep: bool = False):
        akku = self.a.MerkleAccumulator(keep_leaf_hashes=keep)
        for blatt in _LEAVES[:groesse]:
            akku.append(blatt)
        return akku, akku.state(self.signer, event_public_key=_event_pub())

    def _signature_over(self, inhalt) -> str:
        """A state signature as state() makes one, for content changed here: over the prefix, then the RFC 8785 form."""
        import base64
        import rfc8785
        return base64.b64encode(self.signer.sign(self.a.STATE_SIGNATURE_PREFIX + rfc8785.dumps(inhalt))).decode()

    def test_a_restart_continues_exactly_as_without_one(self) -> None:
        for groesse in (0, 1, 2, 3, 7, 8, 9, 1023, 1024, 1025):
            akku, zustand = self._state_at(groesse)
            wieder = self.a.MerkleAccumulator.restore(json.loads(json.dumps(zustand)), _pub(self.signer), event_public_key=_event_pub())
            with self.subTest(size=groesse):
                for blatt in _LEAVES[groesse:groesse + 5]:
                    self.assertEqual(wieder.append(blatt), akku.append(blatt))

    def test_a_restart_with_the_kept_leaf_hashes(self) -> None:
        akku, zustand = self._state_at(37, keep=True)
        wieder = self.a.MerkleAccumulator.restore(zustand, _pub(self.signer), leaf_hashes=akku.leaf_hashes, event_public_key=_event_pub())
        self.assertEqual(wieder.consistency_proof_from(20), akku.consistency_proof_from(20))

    def test_a_tampered_state_is_refused_never_rebuilt(self) -> None:
        akku, zustand = self._state_at(37, keep=True)
        pub = _pub(self.signer)

        def geaendert(f, neu_signieren=False):
            kopie = json.loads(json.dumps(zustand))
            f(kopie["state"])
            if neu_signieren:
                kopie["signature"] = self._signature_over(kopie["state"])
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
                    self.a.MerkleAccumulator.restore(kaputt, pub, event_public_key=_event_pub())
        with self.subTest(case="signed by another key"):
            with self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(akku.state(_other_key(), event_public_key=_event_pub()), pub,
                                                 event_public_key=_event_pub())
        with self.subTest(case="leaf hashes other than the state's"):
            andere = list(akku.leaf_hashes)
            andere[3] = b"\x00" * 32
            with self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(zustand, pub, leaf_hashes=andere, event_public_key=_event_pub())
        with self.subTest(case="re-signed with the right key, the frontier of other leaves beside these hashes"):
            fremd = self.a.MerkleAccumulator.from_leaves([b"other " + b for b in _LEAVES[:37]])
            gemischt = json.loads(json.dumps(zustand))
            gemischt["state"]["frontier"] = [{"height": h, "root": r.hex()} for h, r in fremd.frontier]
            gemischt["state"]["root"] = fremd.root().hex()
            gemischt["signature"] = self._signature_over(gemischt["state"])
            with self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(gemischt, pub, leaf_hashes=akku.leaf_hashes, event_public_key=_event_pub())

    def test_restore_is_a_method_of_the_accumulator_alone(self) -> None:
        """The class of Codex thread 4220260056 at restore: with no subclass, restore is the accumulator's own
        classmethod, and the two re-signed tampered states it must refuse are refused through it."""
        akku, zustand = self._state_at(37, keep=True)
        pub = _pub(self.signer)
        fremd = self.a.MerkleAccumulator.from_leaves([b"other " + b for b in _LEAVES[:37]])

        def signiert(inhalt):
            return {"state": inhalt, "signature": self._signature_over(inhalt)}
        falsche_wurzel = json.loads(json.dumps(zustand["state"]))
        falsche_wurzel["root"] = "22" * 32
        fremde_front = json.loads(json.dumps(zustand["state"]))
        fremde_front["frontier"] = [{"height": h, "root": r.hex()} for h, r in fremd.frontier]
        fremde_front["root"] = fremd.root().hex()
        for name, kaputt, blaetter in (("root not the fold", signiert(falsche_wurzel), None),
                                       ("frontier of other leaves beside these hashes", signiert(fremde_front),
                                        akku.leaf_hashes)):
            with self.subTest(case=name), self.assertRaises(self.a.AccumulatorStateError):
                self.a.MerkleAccumulator.restore(kaputt, pub, leaf_hashes=blaetter, event_public_key=_event_pub())
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
            type("Gefaellig", (self.a.MerkleAccumulator,), {"root": lambda self: b"\x22" * 32})

    def test_a_signed_state_of_another_shape_or_spelling_is_refused_as_a_state_error(self) -> None:
        """The signature check comes first, so everything after it reads values the pinned key signed, and
        signed is not well formed: a signed [] reached `.get` and escaped as a raw AttributeError. And a
        frontier field went through int() and bytes.fromhex, which read "1", true, upper case and spaces
        as the value state() writes, so one state restored from several signed spellings. Each is refused
        as an AccumulatorStateError, the form the restart rule names."""

        def signiert(inhalt):
            return {"state": inhalt, "signature": self._signature_over(inhalt)}

        pub = _pub(self.signer)
        _akku, zustand = self._state_at(3)
        self.assertEqual([e["height"] for e in zustand["state"]["frontier"]], [1, 0])
        self.a.MerkleAccumulator.restore(signiert(zustand["state"]), pub, event_public_key=_event_pub())   # re-signed as written: restored

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
                    self.a.MerkleAccumulator.restore(kaputt, pub, event_public_key=_event_pub())

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
                    self.a.MerkleAccumulator.restore(zustand, pub, leaf_hashes=blaetter, event_public_key=_event_pub())
        with self.subTest(case="the leaf hashes as written, as a tuple"):
            wieder = self.a.MerkleAccumulator.restore(zustand, pub, leaf_hashes=(h0, h1), event_public_key=_event_pub())
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
        wieder = self.a.MerkleAccumulator.restore(zustand, _pub(self.signer), leaf_hashes=Wechselnd(echt), event_public_key=_event_pub())
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
        eins = akku.state(self.signer, event_public_key=_event_pub())
        wurzel_zwei, _ = akku.append(_LEAVES[1])
        self.assertEqual(akku.state(self.signer, event_public_key=_event_pub())["state"]["tree_size"], 2)
        zurueck = self.a.MerkleAccumulator.restore(eins, pub, event_public_key=_event_pub())
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
        wieder = self.a.MerkleAccumulator.restore(dict(zustand, state=ZweiLesarten(zustand["state"])), _pub(self.signer), event_public_key=_event_pub())
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
                    self.a.MerkleAccumulator.restore(dict(zustand, signature=universell), schluessel, event_public_key=_event_pub())

    def test_an_event_signature_is_not_a_state_signature(self) -> None:
        """Codex thread 4245187389 on pull request 340: state() signed the RFC 8785 form of the state alone, and
        emit_bundle signs the payload bytes as they are. So the RFC 8785 form of a state chosen by whoever sends
        events, sent as an event, came back with a signature restore accepted, and a frontier of the sender's choice
        was restored under the emitter's key with no state ever signed. A state is now signed with a key of its own
        over a prefix of its own: the event signature over a state's RFC 8785 form, from emit_bundle or from this
        tool, is refused under the state key, and under the event key pinned as the state key."""
        from proofbundle.canonical import canonicalize_statement
        from proofbundle.emit import emit_bundle
        ereignis = _event_key()
        gewaehlt = self.a.MerkleAccumulator.from_leaves([b"chosen " + b for b in _LEAVES[:37]])
        inhalt = gewaehlt.state(_other_key(), event_public_key=_event_pub())["state"]   # content only
        roh = canonicalize_statement(inhalt)
        for weg, bundle in (("emit_bundle", emit_bundle(roh, ereignis)),
                            ("emit_bundle_incremental",
                             self.a.emit_bundle_incremental(roh, ereignis, self.a.MerkleAccumulator()))):
            gefaelscht = {"state": inhalt, "signature": bundle["signature"]["sig_b64"]}
            for gepinnt in ("the state key", "the event key"):
                schluessel = _pub(self.signer) if gepinnt == "the state key" else _event_pub()
                with self.subTest(event_through=weg, pinned=gepinnt):
                    with self.assertRaises(self.a.AccumulatorStateError):
                        self.a.MerkleAccumulator.restore(gefaelscht, schluessel, event_public_key=_event_pub())
        with self.subTest(case="control: the same content as state() signs it with the state key"):
            wieder = self.a.MerkleAccumulator.restore(gewaehlt.state(self.signer, event_public_key=_event_pub()),
                                                      _pub(self.signer), event_public_key=_event_pub())
            self.assertEqual(wieder.root(), gewaehlt.root())

    def test_a_state_signature_covers_the_prefix_then_the_rfc_8785_form(self) -> None:
        """The bytes a state signature covers, checked with the bare Ed25519 verification and a prefix written out here
        rather than read from the module: the format name, a zero byte, then the RFC 8785 form of the state."""
        import base64
        import rfc8785
        _akku, zustand = self._state_at(5)
        praefix = b"proofbundle-merkle-accumulator-state/1\x00"
        self.assertEqual(self.a.STATE_SIGNATURE_PREFIX, praefix)
        signatur = base64.b64decode(zustand["signature"])
        self.signer.public_key().verify(signatur, praefix + rfc8785.dumps(zustand["state"]))   # raises if not

    def test_the_emitter_refuses_a_payload_that_begins_with_the_state_prefix(self) -> None:
        """The other half of the separation: through this tool one key signs events and states, so its emitter never
        signs bytes that begin with the state prefix. Such a payload is refused before the append and before the
        signer is asked, in each form the payload is read in, and the accumulator is unchanged. The prefix later than
        at the start is an event like any other."""
        import rfc8785
        from proofbundle.emit import emit_bundle
        echt = self.signer
        praefix = self.a.STATE_SIGNATURE_PREFIX
        _akku, zustand = self._state_at(5)

        class Gefragt:
            def __init__(self):
                self.anzahl = 0

            def sign(self, data):
                self.anzahl += 1
                return echt.sign(data)

            def public_key(self):
                self.anzahl += 1
                return echt.public_key()
        akku = self.a.MerkleAccumulator.from_leaves(_LEAVES[:3])
        davor = (akku.size, akku.frontier)
        for name, payload in (("a state's signed bytes", praefix + rfc8785.dumps(zustand["state"])),
                              ("the prefix alone", praefix), ("a bytearray", bytearray(praefix + b"{}")),
                              ("a memoryview", memoryview(praefix + b"{}"))):
            gefragt = Gefragt()
            with self.subTest(payload=name):
                with self.assertRaisesRegex(ValueError, "state signature prefix"):
                    self.a.emit_bundle_incremental(payload, gefragt, akku)
                self.assertEqual(gefragt.anzahl, 0)
                self.assertEqual((akku.size, akku.frontier), davor)
        with self.subTest(payload="the prefix after the first byte"):
            neu = self.a.emit_bundle_incremental(b"x" + praefix, echt, akku)
            alt = emit_bundle(b"x" + praefix, echt, prior_leaves=_LEAVES[:3])
            self.assertEqual(json.dumps(neu, sort_keys=True), json.dumps(alt, sort_keys=True))

    def test_a_state_signed_through_emit_bundle_under_the_event_key_is_refused(self) -> None:
        """Codex thread 4246051732 on pull request 340: emit_bundle, which this tool does not change, signs any
        payload, one that begins with the state prefix included, and with one key for events and states a state of the
        sender's choice restored; the module only said so. Now the state key is not the event key, checked at both
        ends. The prefixed bytes of a chosen state, sent as an event to emit_bundle under the event key, restore
        neither under the state key, where the signature does not verify, nor under the event key pinned as the state
        key, which restore refuses before any signature arithmetic."""
        from proofbundle.canonical import canonicalize_statement
        from proofbundle.emit import emit_bundle
        gewaehlt = self.a.MerkleAccumulator.from_leaves([b"chosen " + b for b in _LEAVES[:37]])
        inhalt = gewaehlt.state(_other_key(), event_public_key=_event_pub())["state"]
        bundle = emit_bundle(self.a.STATE_SIGNATURE_PREFIX + canonicalize_statement(inhalt), _event_key())
        gefaelscht = {"state": inhalt, "signature": bundle["signature"]["sig_b64"]}
        with self.assertRaisesRegex(self.a.AccumulatorStateError, "does not verify under the pinned key"):
            self.a.MerkleAccumulator.restore(gefaelscht, _pub(self.signer), event_public_key=_event_pub())
        with self.assertRaisesRegex(self.a.AccumulatorStateError, "pinned state key is the event key"):
            self.a.MerkleAccumulator.restore(gefaelscht, _event_pub(), event_public_key=_event_pub())
        self.assertIn("the state key signs states and nothing else", " ".join(self.a.__doc__.split()))

    def test_the_state_key_is_never_the_event_key(self) -> None:
        """Both ends refuse the event key as the state key, and an event key that is no sound Ed25519 key, before
        anything is signed or verified. The keys are compared as the bytes each is read as once, so a bytearray or a
        bytes subclass of the event key is the event key; a low-order, non-canonical or malformed event key is
        refused, since two such spellings could name one point."""
        akku = self.a.MerkleAccumulator.from_leaves(_LEAVES[:5])
        zustand = akku.state(self.signer, event_public_key=_event_pub())

        class Anders(bytes):
            def __eq__(self, other):
                return False

            __hash__ = bytes.__hash__
        for name, wert in (("bytes", _event_pub()), ("bytearray", bytearray(_event_pub())),
                           ("a bytes subclass that compares unequal", Anders(_event_pub()))):
            with self.subTest(state_key_given_as=name):
                with self.assertRaisesRegex(ValueError, "signed with the event key"):
                    akku.state(_event_key(), event_public_key=wert)
                with self.assertRaisesRegex(self.a.AccumulatorStateError, "pinned state key is the event key"):
                    self.a.MerkleAccumulator.restore(zustand, wert, event_public_key=_event_pub())
                with self.assertRaisesRegex(self.a.AccumulatorStateError, "pinned state key is the event key"):
                    self.a.MerkleAccumulator.restore(zustand, _event_pub(), event_public_key=wert)
        for name, schwach in (("the identity point", b"\x01" + b"\x00" * 31), ("31 bytes", b"\x02" * 31),
                              ("non-canonical, y = p", (2 ** 255 - 19).to_bytes(32, "little")), ("None", None)):
            with self.subTest(event_key=name):
                with self.assertRaisesRegex(ValueError, "not a sound 32-byte Ed25519 key"):
                    akku.state(self.signer, event_public_key=schwach)
                with self.assertRaisesRegex(self.a.AccumulatorStateError, "not a sound 32-byte Ed25519 key"):
                    self.a.MerkleAccumulator.restore(zustand, _pub(self.signer), event_public_key=schwach)
        with self.subTest(case="control: separate keys"):
            self.assertEqual(self.a.MerkleAccumulator.restore(zustand, _pub(self.signer),
                                                              event_public_key=_event_pub()).root(), akku.root())

    def test_a_state_signature_read_as_an_event_has_a_payload_that_begins_with_the_prefix(self) -> None:
        """The other direction, measured: verify_bundle, which this tool does not change, accepts a bundle built
        around a state signature, its payload the prefixed bytes the signature covers, in a tree of one leaf. What
        tells it apart is the payload's first bytes, which this tool never emits as an event, and the module names
        that as a reading rule rather than a check."""
        import base64
        import rfc8785
        from proofbundle.bundle import SCHEMA, verify_bundle
        from proofbundle.merkle import leaf_hash
        _akku, zustand = self._state_at(5)
        payload = self.a.STATE_SIGNATURE_PREFIX + rfc8785.dumps(zustand["state"])
        b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
        bundle = {"schema": SCHEMA, "payload_b64": b64(payload),
                  "signature": {"alg": "ed25519", "public_key_b64": b64(_pub(self.signer)),
                                "sig_b64": zustand["signature"]},
                  "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": 0, "tree_size": 1,
                             "inclusion_proof_b64": [], "root_b64": b64(leaf_hash(payload))}}
        self.assertTrue(verify_bundle(bundle).ok)
        self.assertTrue(base64.b64decode(bundle["payload_b64"]).startswith(self.a.STATE_SIGNATURE_PREFIX))
        self.assertIn("a payload that begins with the prefix is a state, never an event of this tool",
                      " ".join(self.a.__doc__.split()))


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
