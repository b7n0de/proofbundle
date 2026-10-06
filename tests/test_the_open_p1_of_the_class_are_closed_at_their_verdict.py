"""The gate before run 7, part four: the open P1 of the class and the findings of deep gate run 6, each measured at
the verdict it promoted.

SOURCE. Owner choice 1 of 2026-10-01 (card OA-73db31053a, the form of the owner's addendum of 2026-10-01,
18:45 UTC): the entries of RESTRISIKO_620.md that stood as open P1 with a workaround are closed in 6.2.0, each
shown closed at the final head, and the exception with a workaround of OA-ff64386f8d is lifted: a memoryview the copy cannot rebuild (V8-F2), an iterator or a generator handed in as an
argument (V10-F1), and a value of the caller's own class inside a copied container that decided
`decision.action_outcome_proven` (V8, E10). Beside them the findings of deep gate run 6 at fda55f98 that change a
verdict or a bound: a related map whose keys meet as one, read at body time (L4-620v6-T15-LIVE-RELATED-01, P1), a
relation of an evidence reference that is a list, hashed into a set (RT-04, a raw TypeError from a signed field), and a
key of shared frozensets walked once per path (L2-620v6-KEY-GRAPH-EXPONENTIAL-01, P2), with its neighbour, a shared
container copied once per path (RESTRISIKO_620.md, "A shared container is copied once per path").

EACH CASE MEASURES THE EFFECT, NOT THE MECHANISM: a sweep over every collection start of a call in which the caller's
gc callback moves its value from one state to another (`sweep` of tests/test_a_verifier_reads_a_callers_value_once.py)
must give the verdict of one of the two states or a typed refusal; a value whose own methods lie must not get the
verdict it does not store; a raw exception must not leave a surface that answers with a verdict; and the work a
reading, a key and a copy cost is COUNTED (calls of the reader), so a machine's load does not decide the bound.

MEASURED when this file was added, at fda55f98: every case but the controls is red. Each control is green at
fda55f98 and at the head that adds this file.
"""
from __future__ import annotations

import ctypes
import hashlib
import sys
import unittest
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle.errors import ProofBundleError  # noqa: E402
from _decision_result_binding import bound_decision_result  # noqa: E402  (Nachtrag 48 F1: a bound decision result)
from test_a_verifier_reads_a_callers_value_once import (  # noqa: E402
    _POLICY, _lineage_verdict, _related_full, fx, sweep)


def _oder_abgewiesen(aufruf: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """The call, with a typed refusal as an outcome of its own: a refusal of every state is no mixed verdict."""
    def lauf(wert: Any) -> Any:
        try:
            return aufruf(wert)
        except ProofBundleError as exc:
            return ("refused", type(exc).__name__)
    return lauf


def _verdikt(urteil: Callable[[Any], Any]) -> Callable[[Any], Any]:
    def lesen(aus: Any) -> Any:
        return aus if isinstance(aus, tuple) and aus[:1] == ("refused",) else urteil(aus)
    return lesen


class _Einzustand(unittest.TestCase):

    def _ein_zustand(self, name: str, aufruf, mache, aendere, urteil, *, phasen: bool = True):
        erstes, zweites, gemischt, gesamt = sweep(_oder_abgewiesen(aufruf), mache, aendere, _verdikt(urteil),
                                                  phasen=phasen)
        self.assertEqual(gemischt, [], f"{name}: a verdict neither state gives, at {len(gemischt)} of {gesamt} "
                         f"collection starts (first state {erstes!r}, second {zweites!r}): {gemischt[:4]}")
        return erstes, zweites


# ── V8-F2: a memoryview the copy cannot rebuild ──────────────────────────────────────────────────────────────────

class AMemoryviewTheCopyCannotRebuildDecidesNoVerdict(_Einzustand):
    """RESTRISIKO_620.md, V8-F2 (open P1 with a workaround until 2026-10-01): `merkle.verify_inclusion` read the proof
    first and the leaf later from two views of ctypes arrays (format ``<H``), which the copy kept as the caller's views,
    and gave True in 8 of 533 runs where each state gives False. Here: the first state holds the right sibling and a
    wrong leaf, the second the right leaf and a wrong sibling; the proof of the first beside the leaf of the second is
    the one that verifies."""

    def test_the_inclusion_of_two_views_is_judged_over_one_state(self) -> None:
        from proofbundle import merkle
        blaetter = [b"leaf-AAA", b"leaf-BBB"]
        wurzel = merkle.merkle_tree_hash(blaetter)
        geschwister = merkle.leaf_hash(blaetter[1])
        self.assertTrue(merkle.verify_inclusion(blaetter[0], 0, 2, [geschwister], wurzel))   # control
        falsches_blatt, falsches_geschwister = b"leaf-ZZZ", hashlib.sha256(b"no sibling").digest()

        def puffer(roh: bytes):
            return (ctypes.c_uint16 * (len(roh) // 2)).from_buffer_copy(roh)

        def mache():
            return (puffer(falsches_blatt), puffer(geschwister))

        def aendere(st):
            ctypes.memmove(st[0], blaetter[0], len(blaetter[0]))
            ctypes.memmove(st[1], falsches_geschwister, len(falsches_geschwister))

        def aufruf(st):
            return merkle.verify_inclusion(memoryview(st[0]), 0, 2, [memoryview(st[1])], wurzel)
        erstes, zweites = self._ein_zustand("verify_inclusion over two views in format <H", aufruf, mache, aendere,
                                            lambda v: v)
        self.assertNotIn(True, (erstes, zweites), "the case needs two states that each fail")


# ── V10-F1: an iterator or a generator handed in as an argument ─────────────────────────────────────────────────

class AnIteratorDecidesNoVerdict(_Einzustand):
    """RESTRISIKO_620.md, V10-F1 (open P1 with a workaround until 2026-10-01): an iterator over the caller's list is no
    container the reading can copy, so the body read it after the other arguments were copied.
    `evaluate_public_transparency(witness_vkeys=<iterator>)` gave PASS in 297 of 968 runs where each state fails, and
    `emit_bundle(prior_leaves=<iterator>)` signed the payload of one state over the leaves of the other in 110 of
    533."""

    def test_witness_keys_from_an_iterator(self) -> None:
        from proofbundle import checkpoint as cp
        from proofbundle.public_transparency import evaluate_public_transparency
        log = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
        zeuge = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
        notiz = cp.sign_checkpoint("example.org/log", 10, b"\x42" * 32, log, "example.org/log")
        notiz = cp.cosign_checkpoint(notiz, zeuge, "witness-1", 1700000000)
        schluessel = cp.cosign_vkey("witness-1", zeuge.public_key().public_bytes_raw())

        def aendere(st):
            st[0]["witnessQuorum"]["threshold"] = 2
            st[1].append(schluessel)
        erstes, zweites = self._ein_zustand(
            "evaluate_public_transparency, witness keys from an iterator",
            lambda st: evaluate_public_transparency(notiz, st[0], witness_vkeys=iter(st[1]))["PUBLIC_TRANSPARENCY"],
            lambda: ({"witnessQuorum": {"threshold": 1}}, []), aendere, lambda v: v)
        self.assertNotIn("PASS", (erstes, zweites), "the case needs two states that each fail")

    def test_prior_leaves_from_a_generator(self) -> None:
        from proofbundle.emit import emit_bundle
        sk = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)

        def aendere(st):
            st[0][:] = b"payload-state-1"
            st[1].clear()
            st[1].extend([b"leaf-a1", b"leaf-b1"])
        self._ein_zustand(
            "emit_bundle, prior leaves from a generator",
            lambda st: emit_bundle(st[0], sk, prior_leaves=(b for b in st[1])),
            lambda: (bytearray(b"payload-state-0"), [b"leaf-a0", b"leaf-b0"]), aendere,
            lambda b: (b["payload_b64"], b["merkle"]["root_b64"]))


# ── V8, E10: a value of the caller's class inside a copied container ────────────────────────────────────────────

class AValueOfTheCallersClassDecidesNoVerdict(unittest.TestCase):
    """RESTRISIKO_620.md, V8 E10 (named within the limit of the reading until 2026-10-01): a `str` subclass value
    whose `__ne__` depends on state gave `decision.action_outcome_proven` True in 62 of 183 runs where the states give
    None and False. The copy handed the value on, and the function compared it through the value's own `__ne__`. A
    value that stores another status than it claims shows the same class without a race."""

    def test_a_status_that_claims_to_be_executed(self) -> None:
        from proofbundle.decision import action_outcome_proven

        class _Behauptet(str):
            def __ne__(self, other):
                return False

            def __eq__(self, other):
                return True

            __hash__ = str.__hash__
        ref = {"digest": {"sha256": "a" * 64}}
        self.assertIs(action_outcome_proven({"actionOutcome": {"status": "executed", "outcomeRef": ref}}), True)
        self.assertIsNone(action_outcome_proven({"actionOutcome": {"status": "planned", "outcomeRef": ref}}))
        try:
            r = action_outcome_proven({"actionOutcome": {"status": _Behauptet("planned"), "outcomeRef": ref}})
        except ProofBundleError:
            return
        self.assertIsNone(r, "a status that stores 'planned' was judged executed through its own __ne__")

    def test_the_decision_verifier_reads_the_signed_status(self) -> None:
        """Control: the verifier parses the signed payload into plain values, so no object of the caller reaches
        the field it reports; green at fda55f98 too."""
        import json
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
        sk = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
        praedikat = json.loads((REPO / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))
        umschlag = emit_decision_receipt(praedikat, sk)
        self.assertIn(verify_decision_receipt(umschlag, sk.public_key().public_bytes_raw())["action_outcome_proven"],
                      (True, False, None))


# ── L4-620v6-T15-LIVE-RELATED-01: a related map whose keys meet as one ─────────────────────────────────────────

class _Spiegel(str):
    def __hash__(self) -> int:
        return 12345


class ARelatedMapTheCopyCannotHoldDecidesNoVerdict(_Einzustand):
    """Deep gate run 6 at fda55f98, L4 (three of three jurors P1): a related map whose keys meet as one in the copy
    stayed the caller's object, `relation._read_attached_entries` copied its entries one at a time, and a gc callback
    between two of them gave `verify_decision_receipt` ok True and safeForAutomation True at 11 of 1065 collection
    starts where both states give False. The changes are the two of the class sweep: the map emptied, and the parent
    and the retraction changed at once."""

    def _lauf(self, name: str, pruefe) -> None:
        f = fx()
        if name not in f.subject:
            self.skipTest("not shipped: examples/decision_receipt_allow.json")
        sh = f.subject[name]

        def zwei(m):
            m["8" * 64]["verified"] = False
            m["7" * 64]["relationships"] = None
        for label, aendere in (("emptied", dict.clear), ("two entries at once", zwei)):
            with self.subTest(change=label):
                erstes, zweites = self._ein_zustand(
                    f"{name}, related keyed so that two keys meet, {label}", pruefe,
                    lambda: {**_related_full(sh), "zz": {}, _Spiegel("zz"): {}}, aendere, _lineage_verdict)
                for v in (erstes, zweites):
                    if not (isinstance(v, tuple) and v[:1] == ("refused",)):
                        self.assertIs(v[0], False, "the case needs states that are each refused")

    def test_the_decision_verifier(self) -> None:
        from proofbundle.decision import verify_decision_receipt
        self._lauf("decision", lambda rel: verify_decision_receipt(fx().decision, fx().pub, related=rel,
                                                                   policy=_POLICY))

    def test_the_outcome_verifier(self) -> None:
        from proofbundle.outcome import verify_outcome_receipt
        self._lauf("outcome", lambda rel: verify_outcome_receipt(fx().outcome, fx().pub, related=rel, policy=_POLICY))


# ── RT-04: a relation of an evidence reference that is no text ──────────────────────────────────────────────────

class ARelationThatIsNoTextIsJudgedNotRaised(unittest.TestCase):
    """Deep gate run 6 at fda55f98, lens L8 and three jurors (RT-04): `evaluate_decision_policy` hashed every
    ``evidenceRefs[].relation`` into a set, and a signed relation that is a list or an object escaped as a raw
    TypeError under any policy with ``required_evidence_relations``; v6.1.0 the same. The relation comes from the
    signed payload, so JSON reaches it."""

    def test_a_list_and_an_object_as_the_relation(self) -> None:
        from proofbundle.policy import evaluate_decision_policy
        politik = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "rt04",
                   "decision_receipt": {"required_evidence_relations": ["input"]}}
        for relation in (["input"], {"a": 1}):
            with self.subTest(relation=type(relation).__name__):
                aussage = {"predicateType": "x", "predicate": {"evidenceRefs": [{"relation": relation}]}}
                try:
                    # Nachtrag 48 F1: the result must be bound to exactly this statement and signer, else the
                    # policy fails closed before the relation; a bound result reaches the relation-type check.
                    r = evaluate_decision_policy(aussage, bound_decision_result(aussage, "k"), politik,
                                                 signer_public_key_b64="k")
                except ProofBundleError:
                    continue
                except TypeError as exc:
                    self.fail(f"a raw TypeError left a surface that answers with a verdict: {exc}")
                self.assertIs(r["policy_ok"], False, "a relation that is no text satisfied a required relation")
        # control: a text relation
        aussage = {"predicateType": "x", "predicate": {"evidenceRefs": [{"relation": "input"}]}}
        self.assertIs(evaluate_decision_policy(aussage, bound_decision_result(aussage, "k"), politik,
                                               signer_public_key_b64="k")["policy_ok"], True)


# ── L2: work counted, not time ──────────────────────────────────────────────────────────────────────────────────

def _zaehle(modul: Any, name: str, aufruf: Callable[[], Any]) -> int:
    original = getattr(modul, name)
    zahl = [0]

    def zaehlend(*a, **k):
        zahl[0] += 1
        return original(*a, **k)
    setattr(modul, name, zaehlend)
    try:
        try:
            aufruf()
        except Exception:  # noqa: BLE001 - a refusal is a correct answer; the work done before it is what counts
            pass
    finally:
        setattr(modul, name, original)
    return zahl[0]


def _schluessel(ebenen: int, breite: int = 4) -> Any:
    """A key of shared frozensets: ``ebenen`` levels, each of ``breite`` frozensets of the level below."""
    f = frozenset(f"s{j}" for j in range(breite))
    for _ in range(ebenen):
        f = frozenset(((f,) * breite) + (j,) for j in range(breite))
    return f


def _geteilt(ebenen: int) -> Any:
    """A list whose two items are the same list, ``ebenen`` deep: 2 * ebenen + 1 objects, 2 ** ebenen paths."""
    wert: Any = ["leaf"]
    for _ in range(ebenen):
        wert = [wert, wert]
    return wert


class TheWorkOfAReadingIsBoundedByWhatItHolds(unittest.TestCase):
    """Deep gate run 6 at fda55f98, L2-620v6-KEY-GRAPH-EXPONENTIAL-01 (P2 by three jurors), and owner point 7 of
    2026-10-01: work and size budgets bound the reading, the processing of keys and the rebuild; the time of level 7
    alone is no bound. So the work is counted, as calls of the reader, the key rule and the copy, against the number
    of objects the value holds: a value of shared parts may cost a constant times its objects, never a factor per
    path."""

    def test_a_key_of_shared_parts_is_read_once_per_part(self) -> None:
        from proofbundle import canonical
        for ebenen in (3, 4):
            with self.subTest(levels=ebenen):
                schluessel = _schluessel(ebenen)
                teile = _teile_eines_schluessels(schluessel)
                kopie = _zaehle(canonical, "_schluessel_von", lambda: canonical._stand({schluessel: 1}))
                vergleich = _zaehle(canonical, "_typisiert",
                                    lambda: canonical._derselbe({schluessel: 1}, {schluessel: 1}))
                self.assertLessEqual(kopie, 17 * teile + 1, f"the copy: {kopie} calls for {teile} parts")
                self.assertLessEqual(vergleich, 2 * (17 * teile + 1), f"the comparison: {vergleich} calls")

    def test_the_copy_of_shared_containers_is_bounded_by_the_node_budget(self) -> None:
        """The neighbour named in RESTRISIKO_620.md ("A shared container is copied once per path", P2): a policy that
        holds a list whose two items are one list, levels deep, is copied by `_plain_for_jcs` once per place, as a
        serializer writes it, so its work doubles with each level. The bound owner point 7 asks for is a budget: the
        calls of `_plain_value` stay under the structural budget ``json_nodes`` (and a margin for the rest of the
        policy) at 10 and 14 levels, which it holds as written, and at 18 levels, which it does not (2 ** 19 values),
        the copy stops at the budget. Measured at fda55f98 with a bound of 64 calls per object: 3080 and 49160 calls;
        that bound was stricter than the owner's point and is replaced by the budget here."""
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle import canonical
        from proofbundle.policy import evaluate_decision_policy
        grenze = DEFAULT_BUDGET.json_nodes + 64
        for ebenen in (10, 14, 18):
            with self.subTest(levels=ebenen):
                politik = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "l2",
                           "decision_receipt": {"allowed_verdicts": ["ALLOW"]}, "x": _geteilt(ebenen)}
                aufrufe = _zaehle(canonical, "_plain_value", lambda: evaluate_decision_policy(
                    {"predicateType": "x", "predicate": {}}, {"ok": True}, politik, signer_public_key_b64="k"))
                self.assertLessEqual(aufrufe, grenze, f"{aufrufe} values copied for a policy of {ebenen} levels")

    def test_control_the_count_falls_for_a_reader_that_walks_every_path(self) -> None:
        from proofbundle.budget import DEFAULT_BUDGET

        def je_pfad(wert: Any) -> int:
            return 1 + sum(je_pfad(t) for t in (wert if type(wert) is list else ()))
        self.assertGreater(je_pfad(_geteilt(18)), DEFAULT_BUDGET.json_nodes + 64)

    def test_the_classes_made_for_a_callers_types_die_with_them(self) -> None:
        """Codex on pull request 311 at 4ecfb1ed (P2): the caches of the reading, keyed by the id of a caller's type,
        held the class made for each type for the life of the process, so 20000 fresh types kept 20000 stand-in classes
        and 37.1 MB after the collector ran, though each of those inputs was refused. Counted here as entries: 2000
        fresh types of the caller, as objects, as subclasses of str and as subclasses of int, passed to a public
        function, leave the caches as large as they were once the types are gone and the collector ran."""
        import gc

        from proofbundle import _membership, canonical
        caches = {"FREMDKOERPER_KLASSEN": _membership.FREMDKOERPER_KLASSEN,
                  "_FREMDKOERPER_JE_TYP": canonical._FREMDKOERPER_JE_TYP,
                  "_FREMDWERT_JE_TYP": canonical._FREMDWERT_JE_TYP,
                  "_METHODEN_JE_TYP": canonical._METHODEN_JE_TYP}

        def runde() -> None:
            for i in range(2000):
                for wert in (type(f"E{i}", (), {})(), type(f"S{i}", (str,), {})("x"), type(f"I{i}", (int,), {})(1)):
                    try:
                        canonical.canonicalize_statement({"k": wert})
                    except Exception:  # noqa: BLE001 - each of these is refused; the count is what is measured
                        pass
        def bereinigt() -> "dict[str, int]":
            # A type dies in one collection, and only its callback drops the entry that holds the class made for it;
            # that class is in a cycle of its own and goes in the next one. So collect until the counts rest.
            zahlen: dict = {}
            for _ in range(8):
                gc.collect()
                jetzt = {name: len(cache) for name, cache in caches.items()}
                if jetzt == zahlen:
                    break
                zahlen = jetzt
            return zahlen
        vorher = bereinigt()
        runde()
        nachher = bereinigt()
        for name in caches:
            self.assertLessEqual(nachher[name] - vorher[name], 16, f"{name}: {vorher[name]} -> {nachher[name]} entries")

    def test_the_copy_refuses_exactly_what_the_parse_budget_refuses(self) -> None:
        """The copy's budget is the parse budget's (`_strict_json._enforce_structural_budget`, the independent oracle
        here): a value of exactly ``json_nodes`` entries is taken by both, and one more entry is refused by both, for a
        list, a dict and a nested value. Until the review of the run 7 preparation the copy counted the root as an entry
        and refused the value of exactly ``json_nodes`` entries the parser takes."""
        from proofbundle import _strict_json, canonical
        from proofbundle.budget import DEFAULT_BUDGET
        n = DEFAULT_BUDGET.json_nodes

        def parser_nimmt(wert: Any) -> bool:
            try:
                _strict_json._enforce_structural_budget(wert, n, DEFAULT_BUDGET.json_depth, DEFAULT_BUDGET.string_len)
            except ProofBundleError:
                return False
            return True

        def kopie_nimmt(wert: Any) -> bool:
            try:
                canonical._plain_for_jcs(wert, ValueError)
            except ValueError:
                return False
            return True

        for name, bauen in (("list", lambda k: list(range(k))),
                            ("dict", lambda k: {f"k{i}": i for i in range(k)}),
                            ("nested", lambda k: {"a": [0] * (k - 2), "b": None})):
            for k, erwartet in ((n, True), (n + 1, False)):
                with self.subTest(form=name, entries=k):
                    wert = bauen(k)
                    self.assertIs(parser_nimmt(wert), erwartet, "the oracle")
                    self.assertIs(kopie_nimmt(wert), erwartet, "the copy")


def _teile_eines_schluessels(wert: Any) -> int:
    gesehen: set = set()
    stapel = [wert]
    while stapel:
        w = stapel.pop()
        if id(w) in gesehen:
            continue
        gesehen.add(id(w))
        if type(w) in (tuple, frozenset):
            stapel.extend(w)
    return len(gesehen)


if __name__ == "__main__":
    unittest.main()
