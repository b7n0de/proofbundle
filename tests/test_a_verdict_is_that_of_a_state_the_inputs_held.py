"""The gate before run 7, part three: a verdict is the verdict of a state the inputs held, through the answers of
callbacks, the copies handed to callbacks, correlated changes, ABA and switches of threads.

SOURCE. The review before run 7, section 5 and findings F1 and F3: beside single hostile arguments the gate checks
correlated changes of several arguments, the answers of callbacks, the private copies the package hands to callback
code, ABA, and switches of threads in a bounded, controlled form. A refusal and a state the inputs held are allowed
answers; a joint state the inputs never held is not. F1: the double collect (`canonical._stand`) compares two readings
by the objects they hold, so a container changed and changed back between its two reads (ABA) is not seen; an equal
content proves no joint state of mutable inputs. The owner (point 5 of 2026-10-01) keeps the double collect, never as a
full closure, asks for the sentence below wherever a joint state of mutable inputs is claimed, and asks for a targeted
ABA test up to the public verdict; a lock or switching the collector off is no closure.

THE CASES:
1. EVERY CALLBACK SITE (`_STELLEN`, one per callback parameter of the contract of part one): a lying answer promotes
   nothing, and an answer the caller changes after it returned is judged as it was when it returned.
2. A COPY HANDED TO A CALLBACK: a callback that empties and rewrites everything it was handed and every argument of
   the caller, and answers as an honest one would, gives the verdict of the honest one.
3. CORRELATED CHANGES: two arguments changed together by the caller's gc callback, at the anchor verifier (targeted)
   and over the base cases of part two (each base case with two arguments that reach its verdict); the verdict is that
   of the first or the second state, or a refusal.
4. ABA, TARGETED, UP TO THE PUBLIC VERDICT: two entries of an anchor list, changed by the caller's gc callback at the
   reads of the two collects so that each collect reads the same objects while the list never held what the copy
   holds. Measured; where it reaches the verdict, the limit must be named where the reading is described.
5. THREADS: a second thread moves the inputs between states in single steps while the call runs, under a short
   switch interval, for a bounded number of calls; every verdict must be one of the held states or a refusal.
"""
from __future__ import annotations

import base64
import collections
import copy
import dataclasses
import gc
import hashlib
import json
import sys
import threading
import unittest
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle import anchors, canonical  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402

_SIGNER = Ed25519PrivateKey.from_private_bytes(b"\x61" * 32)
_EMPFAENGER = Ed25519PrivateKey.from_private_bytes(b"\x62" * 32)
_ANDERER = Ed25519PrivateKey.from_private_bytes(b"\x63" * 32)


def _raw(k) -> bytes:
    return k.public_key().public_bytes_raw()


def _b64(k) -> str:
    return base64.b64encode(_raw(k)).decode("ascii")


_SCHLUESSEL = _raw(_EMPFAENGER)
_FREMD = _raw(_ANDERER)
_ERSATZSATZ = "does not yet prove a joint state of mutable inputs"
#: The owner's sentence of point 5 (2026-10-01), in English, for every place that claims a joint state of mutable
#: inputs. The test of section 4 looks for its middle clause, `_ERSATZSATZ`.
ERSATZ = ("The closed type boundary keeps unsupported values from being handed on as objects of the caller. It "
          "does not yet prove a joint state of mutable inputs. That needs a separate proof, in particular for ABA "
          "between two reads.")


def _verdikt(aufruf: Callable[[], Any], projektion: Callable[[Any], Any]) -> Any:
    try:
        return projektion(aufruf())
    except ProofBundleError as exc:
        return ("refused", type(exc).__name__)


def _abgewiesen(v: Any) -> bool:
    return isinstance(v, tuple) and v[:1] == ("refused",)


# ── the answers whose own methods claim what they do not store ──────────────────────────────────────────────────────

class _BehauptetWahr:
    """An answer whose own methods say True and equal to everything, and which is no bool."""

    def __bool__(self) -> bool:
        return True

    def __eq__(self, other) -> bool:
        return True

    __hash__ = object.__hash__


class _WahrZahl(int):
    def __eq__(self, other) -> bool:
        return True

    __hash__ = int.__hash__


class _RohLuegt(bytes):
    """Bytes that store one key and answer another through their own methods."""

    def __eq__(self, other) -> bool:
        return other == _SCHLUESSEL

    def __ne__(self, other) -> bool:
        return other != _SCHLUESSEL

    def __bytes__(self) -> bytes:
        return _SCHLUESSEL

    def __len__(self) -> int:
        return 32

    __hash__ = bytes.__hash__


class _PufferLuegt(bytearray):
    def __eq__(self, other) -> bool:
        return other == _SCHLUESSEL

    def __ne__(self, other) -> bool:
        return other != _SCHLUESSEL


class _ErgebnisLuegt(dict):
    """A verifier result that stores ok False and answers ok True through its own methods."""

    def get(self, k, d=None):
        return True if k == "ok" else dict.get(self, k, d)

    def __getitem__(self, k):
        return True if k == "ok" else dict.__getitem__(self, k)

    def __contains__(self, k):
        return True


class _OkText(str):
    def __eq__(self, other) -> bool:
        return other == "ok"

    __hash__ = str.__hash__


_LUEGEN: "dict[str, dict[str, Callable[[], Any]]]" = {
    "bool": {
        "an object whose __bool__ and __eq__ say True": _BehauptetWahr,
        "1": lambda: 1,
        "an int subclass equal to everything": lambda: _WahrZahl(1),
        "1.0": lambda: 1.0,
        "the text true": lambda: "true",
        "a list holding True": lambda: [True],
        "a tuple holding True": lambda: (True,),
    },
    "key": {
        "bytes that store another key and claim the key": lambda: _RohLuegt(_FREMD),
        "a bytearray that stores another key and claims the key": lambda: _PufferLuegt(_FREMD),
        "a memoryview of the key": lambda: memoryview(bytearray(_SCHLUESSEL)),
        "a memoryview of the key in format H": lambda: memoryview(bytearray(_SCHLUESSEL)).cast("H"),
        "a list holding the key": lambda: [_SCHLUESSEL],
        "the key as hex text": lambda: _SCHLUESSEL.hex(),
        "an object whose __bool__ and __eq__ say True": _BehauptetWahr,
    },
    "anchor result": {
        "a dict subclass that stores ok False and answers ok True": lambda: _ErgebnisLuegt(ok=False, warn=False),
        "ok as 1": lambda: {"ok": 1, "warn": False},
        "ok as an object whose __bool__ says True": lambda: {"ok": _BehauptetWahr(), "warn": False},
        "ok under a str subclass key": lambda: {_OkText("ok"): True, "warn": False},
        "a Mapping that is no dict": lambda: collections.UserDict(ok=True, warn=False),
        "warn as text beside ok True": lambda: {"ok": True, "warn": "false"},
    },
}


# ── the callback sites ──────────────────────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class _Stelle:
    """One callback parameter. ``bauen()`` gives ``(aufruf, objekte)``: ``aufruf(rueckruf)`` makes the call with that
    callback and returns the verdict, ``objekte`` are the caller's mutable arguments of that call. ``ja`` and ``nein``
    make the honest promoting and the honest non-promoting answer; ``gut`` says whether what a callback received is
    what an honest call hands it."""
    funktion: str
    parameter: str
    art: str
    bauen: Callable[[], "tuple[Callable[[Callable], Any], list]"]
    ja: Callable[[], Any]
    nein: Callable[[], Any]
    gut: Callable[[tuple, dict], bool]


def _ein_digest(a: tuple, k: dict) -> bool:
    d = a[0] if a else None
    return type(d) is dict and type(d.get("sha256")) is str and len(d["sha256"]) == 64


_ANKERTYP = "vortor-callback/v1"
_WURZEL = hashlib.sha256(b"vortor statement").digest()
_KOPF = {"bitcoin_block_headers": {"1": "ab" * 32}}


def _anker_eintrag(wurzel: bytes = _WURZEL) -> dict:
    return {"type": _ANKERTYP, "target": "statement", "canonicalRoot": base64.b64encode(wurzel).decode(),
            "proof": base64.b64encode(b"p").decode(), "frozen": {"marke": [1]}}


def _anker_gut(a: tuple, k: dict) -> bool:
    rp = k.get("rp_trust")
    return (k.get("frozen") == {"marke": [1]} and type(rp) is dict
            and rp.get("bitcoin_block_headers") == {"1": "ab" * 32})


def _anker_bauen():
    objekte = [[_anker_eintrag(), _anker_eintrag()], {"statement": bytearray(_WURZEL)}, copy.deepcopy(_KOPF)]

    def aufruf(rueckruf):
        anchors.register_anchor_type(_ANKERTYP, rueckruf)
        return _verdikt(lambda: anchors.verify_anchors(objekte[0], target_roots=objekte[1], rp_trust=objekte[2],
                                                       require="any"),
                        lambda r: (r["status"], r.get("require_met"),
                                   tuple((x["ok"], x["warn"]) for x in r["results"])))
    return aufruf, objekte


def _anker_rueckruf(antwort: Callable[..., Any]):
    def pruefer(proof, root, *, frozen, now, rp_trust=None):
        return antwort(proof, root, frozen=frozen, now=now, rp_trust=rp_trust)
    return pruefer


def _anker_stelle_bauen():
    """The anchor site registers a verifier; the callback is wrapped in the signature a verifier has."""
    aufruf, objekte = _anker_bauen()
    return (lambda rueckruf: aufruf(_anker_rueckruf(rueckruf))), objekte


def _folge_bauen():
    from proofbundle.renewal import build_initial_sequence, verify_sequence
    daten = ["ab" * 32]
    objekte = [build_initial_sequence(daten, hash_alg="sha256", time=1000), list(daten)]

    def aufruf(rueckruf):
        return _verdikt(lambda: verify_sequence(objekte[0], objekte[1], anchor_verifier=rueckruf),
                        lambda r: (r.ok, tuple((c.name, c.ok) for c in r.checks)))
    return aufruf, objekte


def _folge_gut(a: tuple, k: dict) -> bool:
    d = getattr(a[0], "covered_digest", None) if a else None
    return type(d) is str and len(d) == 64


def _bescheid_umschlag():
    from proofbundle.decision import emit_decision_receipt
    pred = json.loads((REPO / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))
    return emit_decision_receipt(pred, _SIGNER, strict=False)


def _bescheid_bauen(oder_raise: bool):
    def bauen():
        from proofbundle import decision
        fn = decision.verify_decision_receipt_or_raise if oder_raise else decision.verify_decision_receipt
        objekte = [_bescheid_umschlag(), bytearray(_raw(_SIGNER))]

        def aufruf(rueckruf):
            return _verdikt(lambda: fn(objekte[0], objekte[1], evidence_resolver=rueckruf),
                            lambda r: (r["ok"], tuple(sorted((k, (v or {}).get("level"))
                                                             for k, v in r["evidence_levels"].items()))))
        return aufruf, objekte
    return bauen


def _ergebnis_umschlag():
    from proofbundle.outcome import emit_outcome_receipt
    return emit_outcome_receipt(
        {"schemaVersion": "0.1.0", "outcomeId": "o-vortor", "decisionRef": {"sha256": "e" * 64},
         "executor": {"id": "executor:x", "keyId": "kid-exec"}, "requestedActionDigest": {"sha256": "b" * 64},
         "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
         "receiverRefs": [{"relation": "receiverAck", "digest": {"sha256": "d" * 64}, "receiverKeyId": "kid-recv"},
                          {"relation": "receiverAck", "digest": {"sha256": "f" * 64},
                           "receiverKeyId": "kid-other"}]}, _SIGNER)


def _paket() -> dict:
    return {"roles": {"outcomeReceivers": {"keyIds": ["kid-recv", "kid-other"]},
                      "outcomeExecutors": {"keyIds": ["kid-exec"]}},
            "keys": {"kid-recv": {"publicKey": _b64(_EMPFAENGER), "alg": "ed25519"},
                     "kid-exec": {"publicKey": _b64(_SIGNER), "alg": "ed25519"}}}


def _ergebnis_bauen(parameter: str, oder_raise: bool):
    def bauen():
        from proofbundle import outcome
        fn = outcome.verify_outcome_receipt_or_raise if oder_raise else outcome.verify_outcome_receipt
        objekte = [_ergebnis_umschlag(), bytearray(_raw(_SIGNER)), _paket()]

        def aufruf(rueckruf):
            kw = {parameter: rueckruf}
            if parameter == "receiver_attestation_resolver":
                kw["evidence_resolver"] = lambda d: True
            # N43 (security-fix 6.2.0): a trust pack confers role/receiver trust only under a relying-party
            # anchor. This site measures how a callback ANSWER is judged (a lying key must bind nothing), which
            # is downstream of the anchor, so the pack is pinned here (forwarded verdict) to exercise the
            # binding path; the anchor requirement itself is measured in test_trust_pack_pin_620_n43.py.
            return _verdikt(lambda: fn(objekte[0], objekte[1], trust_pack=objekte[2], trust_pack_pinned=True, **kw),
                            lambda r: (r["ok"], r["evidence_levels"]["effect"]["level"],
                                       (r["evidence_levels"]["receiverRefs"] or {}).get("level"),
                                       r.get("receiver_key_bound"), r.get("receiver_role_trusted")))
        return aufruf, objekte
    return bauen


def _ziffer_bauen():
    from proofbundle.assurance import classify_digest_evidence
    objekte = [{"sha256": "a" * 64}]

    def aufruf(rueckruf):
        return _verdikt(lambda: classify_digest_evidence(objekte[0], evidence_resolver=rueckruf), lambda r: r["level"])
    return aufruf, objekte


def _empfang_bauen(parameter: str):
    def bauen():
        from proofbundle.assurance import classify_receiver_corroboration
        objekte = [{"sha256": "a" * 64}, bytearray(_SCHLUESSEL)]

        def aufruf(rueckruf):
            kw = {"evidence_resolver": lambda d: True, "independent_attestation_resolver": lambda d: _SCHLUESSEL}
            kw[parameter] = rueckruf
            return _verdikt(lambda: classify_receiver_corroboration(
                objekte[0], executor_key_id="e", receiver_key_id="r", expected_receiver_public_key=objekte[1], **kw),
                lambda r: r["level"])
        return aufruf, objekte
    return bauen


_STELLEN: "list[_Stelle]" = [
    _Stelle("assurance.classify_digest_evidence", "evidence_resolver", "bool", _ziffer_bauen,
            lambda: True, lambda: False, _ein_digest),
    _Stelle("assurance.classify_receiver_corroboration", "evidence_resolver", "bool",
            _empfang_bauen("evidence_resolver"), lambda: True, lambda: False, _ein_digest),
    _Stelle("assurance.classify_receiver_corroboration", "independent_attestation_resolver", "key",
            _empfang_bauen("independent_attestation_resolver"), lambda: _SCHLUESSEL, lambda: False, _ein_digest),
    _Stelle("decision.verify_decision_receipt", "evidence_resolver", "bool", _bescheid_bauen(False),
            lambda: True, lambda: False, _ein_digest),
    _Stelle("decision.verify_decision_receipt_or_raise", "evidence_resolver", "bool", _bescheid_bauen(True),
            lambda: True, lambda: False, _ein_digest),
    _Stelle("outcome.verify_outcome_receipt", "evidence_resolver", "bool",
            _ergebnis_bauen("evidence_resolver", False), lambda: True, lambda: False, _ein_digest),
    _Stelle("outcome.verify_outcome_receipt", "receiver_attestation_resolver", "key",
            _ergebnis_bauen("receiver_attestation_resolver", False), lambda: _SCHLUESSEL, lambda: False,
            _ein_digest),
    _Stelle("outcome.verify_outcome_receipt_or_raise", "evidence_resolver", "bool",
            _ergebnis_bauen("evidence_resolver", True), lambda: True, lambda: False, _ein_digest),
    _Stelle("outcome.verify_outcome_receipt_or_raise", "receiver_attestation_resolver", "key",
            _ergebnis_bauen("receiver_attestation_resolver", True), lambda: _SCHLUESSEL, lambda: False,
            _ein_digest),
    _Stelle("renewal.verify_sequence", "anchor_verifier", "bool", _folge_bauen, lambda: True, lambda: False,
            _folge_gut),
    _Stelle("anchors.register_anchor_type", "verifier", "anchor result", _anker_stelle_bauen,
            lambda: {"ok": True, "warn": False}, lambda: {"ok": False, "warn": False}, _anker_gut),
]


def _ehrlich(stelle: _Stelle, antwort: Callable[[], Any]) -> Callable:
    """A callback that answers ``antwort()`` when it received what an honest call hands it, else the honest no."""
    def rueckruf(*a, **k):
        return antwort() if stelle.gut(a, k) else stelle.nein()
    return rueckruf


class _Registriert(unittest.TestCase):
    def setUp(self) -> None:
        gesichert = dict(anchors._VERIFIERS)
        self.addCleanup(lambda: (anchors._VERIFIERS.clear(), anchors._VERIFIERS.update(gesichert)))


def _mit_gc(cb: Callable[[str, dict], None], aufruf: Callable[[], Any]) -> Any:
    """``aufruf()`` with the caller's gc callback ``cb`` armed and a collection at nearly every allocation; every object
    that exists before the call is frozen for its length, as the sweep of the class test does (`_run`)."""
    alt = gc.get_threshold()
    gc.freeze()
    try:
        gc.callbacks.append(cb)
        gc.set_threshold(1, 1, 1)
        try:
            return aufruf()
        finally:
            gc.set_threshold(*alt)
            gc.callbacks.remove(cb)
    finally:
        gc.unfreeze()


def _kombiniert(s: _Stelle, vorher: Callable[[], Any], nachher: Callable[[], Any]) -> set:
    """The verdicts of every combination of plain answers, one per call of the callback, each ``vorher()`` or
    ``nachher()``. The number of calls is counted in a run with ``vorher``."""
    zahl = {"n": 0}

    def zaehlend(*a, **k):
        if s.gut(a, k):
            zahl["n"] += 1
        return vorher() if s.gut(a, k) else s.nein()
    aufruf, _ = s.bauen()
    aufruf(zaehlend)
    verdikte = set()
    for maske in range(1 << zahl["n"]):
        stelle = {"i": 0}

        def rueckruf(*a, maske=maske, stelle=stelle, **k):
            if not s.gut(a, k):
                return s.nein()
            i = stelle["i"]
            stelle["i"] += 1
            return nachher() if maske >> i & 1 else vorher()
        aufruf, _ = s.bauen()
        verdikte.add(aufruf(rueckruf))
    return verdikte


# ── 1. the answer of a callback ────────────────────────────────────────────────────────────────────────────────────

def _befoerdert(stellen: "list[_Stelle]") -> "tuple[list, int]":
    """(each lying answer that got the promoting verdict, how many were checked)."""
    befoerdert, geprueft = [], 0
    for s in stellen:
        aufruf, _ = s.bauen()
        ja = aufruf(_ehrlich(s, s.ja))
        for name, luege in _LUEGEN[s.art].items():
            aufruf, _ = s.bauen()
            geprueft += 1
            if aufruf(_ehrlich(s, luege)) == ja:
                befoerdert.append(f"{s.funktion}({s.parameter}) <- {name}")
    return befoerdert, geprueft


_VERAENDERLICH = {
    "key": (lambda: bytearray(_FREMD), lambda a: a.__setitem__(slice(None), _SCHLUESSEL),
            lambda: bytes(_FREMD), lambda: bytes(_SCHLUESSEL)),
    "anchor result": (lambda: {"ok": False, "warn": False}, lambda a: a.__setitem__("ok", True),
                      lambda: {"ok": False, "warn": False}, lambda: {"ok": True, "warn": False}),
}


def _zweimal_gelesen(stellen: "list[_Stelle]") -> "tuple[list, int]":
    """(each verdict outside the combinations of held answers, how many collection starts were swept)."""
    gemischt, gesamt = [], 0
    for s in stellen:
        if s.art not in _VERAENDERLICH:
            continue
        machen, umschreiben, vorher, nachher = _VERAENDERLICH[s.art]
        erwartet = _kombiniert(s, vorher, nachher)
        k = 0
        while True:
            gegeben: list = []
            zaehler = {"nach": 0, "erreicht": False}

            def rueckruf(*a, s=s, gegeben=gegeben, **kw):
                if not s.gut(a, kw):
                    return s.nein()
                antwort = machen()
                gegeben.append(antwort)
                return antwort

            def cb(phase, info, k=k, gegeben=gegeben, zaehler=zaehler):
                if phase != "start" or not gegeben:
                    return
                if zaehler["nach"] == k:
                    for antwort in gegeben:
                        umschreiben(antwort)
                    zaehler["erreicht"] = True
                zaehler["nach"] += 1
            aufruf, _ = s.bauen()
            v = _mit_gc(cb, lambda: aufruf(rueckruf))
            if not zaehler["erreicht"]:
                break
            gesamt += 1
            if v not in erwartet:
                gemischt.append(f"{s.funktion}({s.parameter}) at {k}: {v} where one of {sorted(map(str, erwartet))}")
            k += 1
    return gemischt, gesamt


class EveryCallbackSiteJudgesTheAnswerAsItStores(_Registriert):

    def test_every_callback_parameter_of_the_contract_has_a_site(self) -> None:
        import test_no_object_of_the_caller_reaches_a_body as teil1
        vertrag = {k for k, art in teil1._VERTRAG.items() if art == teil1._RUECKRUF}
        hier = {(s.funktion, s.parameter) for s in _STELLEN}
        self.assertEqual(sorted(vertrag - hier), [], "a callback parameter of the contract has no site here")
        self.assertEqual(sorted(hier - vertrag), [], "a site here is no callback parameter of the contract")

    def test_control_each_site_reaches_its_verdict_through_the_answer(self) -> None:
        gleich = []
        for s in _STELLEN:
            aufruf, _ = s.bauen()
            ja = aufruf(_ehrlich(s, s.ja))
            aufruf, _ = s.bauen()
            nein = aufruf(_ehrlich(s, s.nein))
            if ja == nein or _abgewiesen(ja):
                gleich.append(f"{s.funktion}({s.parameter}): {ja}")
        self.assertEqual(gleich, [], "a site whose verdict the answer does not reach")

    def test_a_lying_answer_promotes_nothing(self) -> None:
        befoerdert, geprueft = _befoerdert(_STELLEN)
        print(f"\nLYING ANSWERS: {geprueft} checked over {len(_STELLEN)} sites")
        self.assertEqual(befoerdert, [], f"{len(befoerdert)} lying answers got the promoting verdict")

    def test_an_answer_changed_after_it_returned_is_read_as_one_state(self) -> None:
        """The answer is a mutable object holding a non-promoting value; the caller's gc callback rewrites every answer
        given so far to the promoting value at the k-th collection start after the first return, for every k the call
        reaches. Each answer is read once, so the verdict is that of some answer held before or after the change, each
        answer on its own: the allowed verdicts are those of every combination of plain answers, one per call, each the
        value before or after (`_kombiniert`). A verdict outside them read one answer twice, in two states (the class of
        L3-620-T3-03). A change before the package read the answer is a state the answer held, not a defect. A site
        where only an exact bool decides has no such answer and is named."""
        unveraenderlich = sorted(f"{s.funktion}({s.parameter})" for s in _STELLEN if s.art not in _VERAENDERLICH)
        print(f"\nNO MUTABLE ANSWER (an exact bool decides): {unveraenderlich}")
        gemischt, gesamt = _zweimal_gelesen(_STELLEN)
        print(f"\nCHANGED AFTER RETURN: {gesamt} collection starts after a return swept")
        self.assertGreater(gesamt, 0)
        self.assertEqual(gemischt, [], f"{len(gemischt)} verdicts that read one answer in two states")


# ── 2. the copy handed to a callback ───────────────────────────────────────────────────────────────────────────────

def _verwuesten(*objekte) -> None:
    """Empties every container and overwrites every buffer it can reach, and sets every field of every dataclass object
    it can reach to None."""
    gesehen: set = set()
    stapel = list(objekte)
    while stapel:
        obj = stapel.pop()
        if id(obj) in gesehen:
            continue
        gesehen.add(id(obj))
        if type(obj) is bytearray:
            obj[:] = bytes(len(obj))
        elif isinstance(obj, dict):
            stapel.extend(dict.values(obj))
            dict.clear(obj)
        elif isinstance(obj, list):
            stapel.extend(list.__iter__(obj))
            list.clear(obj)
        elif isinstance(obj, tuple):
            stapel.extend(tuple.__iter__(obj))
        elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            for f in dataclasses.fields(obj):
                stapel.append(getattr(obj, f.name, None))
                try:
                    object.__setattr__(obj, f.name, None)
                except (AttributeError, TypeError):
                    pass


def _verwuestet(stellen: "list[_Stelle]") -> list:
    """Each site whose verdict with a devastating callback is not the honest callback's."""
    abweichend = []
    for s in stellen:
        aufruf, _ = s.bauen()
        ehrlich = aufruf(_ehrlich(s, s.ja))
        aufruf, objekte = s.bauen()

        def verwuestend(*a, s=s, objekte=objekte, **k):
            antwort = s.ja() if s.gut(a, k) else s.nein()
            _verwuesten(*a, *k.values(), *objekte)
            return antwort
        v = aufruf(verwuestend)
        if v != ehrlich:
            abweichend.append(f"{s.funktion}({s.parameter}): {v} where the honest callback gives {ehrlich}")
    return abweichend


class ACopyHandedToACallbackReachesNothingElse(_Registriert):
    """Each callback answers as the honest one, from what it received, and then empties everything it was handed and
    every argument of the caller. A site that calls its callback twice and hands both calls one copy hands the second
    what the first emptied; the verdict is then not the honest one's."""

    def test_a_devastating_callback_gives_the_verdict_of_an_honest_one(self) -> None:
        abweichend = _verwuestet(_STELLEN)
        self.assertEqual(abweichend, [], f"{len(abweichend)} sites")


# ── the gate's meta test: each check of sections 1 and 2 catches a planted defect of its class ────────────────────

def _gepflanzt(art: str, koerper: Callable[[Callable], Any]) -> _Stelle:
    """A site whose call is ``koerper(rueckruf)``, a planted body of the class a check is for."""
    def bauen():
        return (lambda rueckruf: koerper(rueckruf)), []
    ja = {"bool": lambda: True, "key": lambda: _SCHLUESSEL}[art]
    return _Stelle("planted", art, art, bauen, ja, lambda: False, _ein_digest)


def _wahrheit(rueckruf):
    """Planted: the answer judged by its truth."""
    return "promoted" if rueckruf({"sha256": "a" * 64}) else "kept"


def _zweimal(rueckruf):
    """Planted: the answer judged once, then read again after an allocation, as the role loop read it before 7409b123
    (L3-620-T3-03)."""
    antwort = rueckruf({"sha256": "a" * 64})
    leiter = type(antwort) in (bytes, bytearray) and bytes(antwort) == _SCHLUESSEL
    # A collection starts here for certain. The first version allocated 64 lists and hoped one would start it; under
    # Python 3.10.21 with cryptography 42 (the crypto-floor job at 4ecfb1ed) none did, and the control swept 0 positions.
    gc.collect(0)
    rolle = type(antwort) in (bytes, bytearray) and bytes(antwort) == _SCHLUESSEL
    return (leiter, rolle)


def _eine_kopie(rueckruf):
    """Planted: one copy handed to two calls of the callback."""
    d = {"sha256": "a" * 64}
    return (rueckruf(d) is True, rueckruf(d) is True)


class TheChecksCatchAPlantedDefectOfTheirClass(_Registriert):

    def test_a_lying_answer_promotes_at_a_body_that_reads_its_truth(self) -> None:
        befoerdert, _ = _befoerdert([_gepflanzt("bool", _wahrheit)])
        self.assertGreater(len(befoerdert), 0)

    def test_an_answer_read_twice_is_caught(self) -> None:
        gemischt, gesamt = _zweimal_gelesen([_gepflanzt("key", _zweimal)])
        self.assertGreater(gesamt, 0)
        self.assertGreater(len(gemischt), 0)

    def test_one_copy_for_two_calls_is_caught(self) -> None:
        self.assertEqual(len(_verwuestet([_gepflanzt("bool", _eine_kopie)])), 1)


# ── 3. correlated changes ──────────────────────────────────────────────────────────────────────────────────────────

def _gefegt(lauf: Callable[[Any], Any], mache: Callable[[], Any], aendere: Callable[[Any], None],
            grenze: int = 2500) -> "tuple[Any, Any, list, int, int]":
    """(verdict of the first state, of the second, the verdicts of neither, positions swept, positions in all). Every
    collection start of the call up to ``grenze`` positions; past it a stride, and the swept count says how much
    ran."""
    from test_a_verifier_reads_a_callers_value_once import _run
    erstes = lauf(mache())
    zweit = mache()
    aendere(zweit)
    zweites = lauf(zweit)
    _, n = _run(lauf, mache(), 1 << 60, aendere)
    schritt = 1 if n + 8 <= grenze else -(-(n + 8) // grenze)
    gemischt, gefegt = [], 0
    for k in range(0, n + 8, schritt):
        aus, _ = _run(lauf, mache(), k, aendere)
        gefegt += 1
        if aus != erstes and aus != zweites and not _abgewiesen(aus):
            gemischt.append((k, aus))
    return erstes, zweites, gemischt, gefegt, n + 8


def _veraenderbar(wert: Any, pfad: tuple) -> bool:
    if not pfad:
        return type(wert) is bytearray
    obj = wert
    for k in pfad[:-1]:
        if type(obj) not in (dict, list):
            return False
        obj = obj[k]
    return type(obj) in (dict, list)


def _setzen(wert: Any, pfad: tuple, neu: Any) -> None:
    if not pfad:
        wert[:] = neu
        return
    obj = wert
    for k in pfad[:-1]:
        obj = obj[k]
    obj[pfad[-1]] = neu


def _erreichende_stellen(teil2: Any, fall: Any) -> "list[tuple[str, tuple, Any]]":
    """Each place of each argument the caller can change in place (a leaf of a dict or list, a whole bytearray) whose
    change reaches the verdict: ``(argument, path, new value)``, at most four per argument, each in another
    container."""
    gefunden = []
    for p, wert in fall.argumente.items():
        if type(wert) is bytearray:
            orte = [((), bytes(wert))]
        elif type(wert) in (dict, list):
            orte = teil2._blaetter(wert)
        else:
            continue
        eltern: set = set()
        for pfad, blatt in orte:
            if not _veraenderbar(wert, pfad) or (pfad and pfad[:-1] in eltern):
                continue
            neu = (teil2._anders(blatt) or [None])[0]
            if neu is None:
                continue
            if not pfad:
                neu = bytearray(neu)
            argumente = {k: teil2._kopie(v) for k, v in fall.argumente.items()}
            argumente[p] = teil2._kopie(neu) if not pfad else teil2._ersetzt(wert, pfad, neu)
            if teil2._rufe(fall.fn, argumente) != fall.urteil:
                gefunden.append((p, pfad, neu))
                eltern.add(pfad[:-1])
                if len(eltern) >= 4:
                    break
    return gefunden


def _paar(kandidaten: list) -> "tuple[Any, str]":
    """Two places in two arguments, else two places in two containers of one argument, else None."""
    for i, a in enumerate(kandidaten):
        for b in kandidaten[i + 1:]:
            if a[0] != b[0]:
                return (a, b), "two arguments"
    for i, a in enumerate(kandidaten):
        for b in kandidaten[i + 1:]:
            if a[1][:-1] != b[1][:-1]:
                return (a, b), "two containers of one argument"
    return None, ""


class CorrelatedChangesGiveTheVerdictOfOneState(_Registriert):

    def test_the_anchor_entry_and_the_roots_changed_together(self) -> None:
        """Each state FAILs (the entry over another root than the roots name); the entry of one state beside the
        roots of the other PASSes."""
        r_a, r_b = hashlib.sha256(b"root a").digest(), hashlib.sha256(b"root b").digest()
        anchors.register_anchor_type(_ANKERTYP, lambda proof, root, *, frozen, now: {"ok": True, "warn": False})

        def mache():
            return ([_anker_eintrag(r_a)], {"statement": r_b})

        def aendere(st):
            st[0][0]["canonicalRoot"] = base64.b64encode(r_b).decode()
            st[1]["statement"] = r_a

        def lauf(st):
            return _verdikt(lambda: anchors.verify_anchors(st[0], target_roots=st[1]), lambda r: r["status"])
        self.assertEqual(lauf(([_anker_eintrag(r_a)], {"statement": r_a})), "PASS", "the mixed state must pass")
        erstes, zweites, gemischt, gefegt, alle = _gefegt(lauf, mache, aendere)
        self.assertEqual((erstes, zweites), ("FAIL", "FAIL"))
        print(f"\nCORRELATED AT verify_anchors: {gefegt} of {alle} positions swept")
        self.assertEqual(gemischt, [], f"a verdict of neither state at {len(gemischt)} of {gefegt} positions")

    def test_two_arguments_of_each_base_case_changed_together(self) -> None:
        """Over the base cases of part two: two places the caller can change in place whose change reaches the
        verdict (`_erreichende_stellen`), in two arguments or else in two containers of one argument (the form of L4),
        changed together at every collection start (past 2500 positions a stride, counted). Base cases without such a
        pair are counted, not held."""
        import test_a_verdict_surface_holds_its_verdict_at_every_argument as teil2
        faelle, _, aufraeumen = teil2._grundfaelle()
        self.addCleanup(aufraeumen)
        gemischt, ohne_paar, gestrichen, gefegt_ges, alle_ges = [], [], [], 0, 0
        arten = {"two arguments": 0, "two containers of one argument": 0}
        for fall in faelle:
            kandidaten = _erreichende_stellen(teil2, fall)
            paar, art = _paar(kandidaten)
            if paar is None:
                ohne_paar.append(fall.name)
                continue
            arten[art] += 1

            def mache(fall=fall):
                return {k: teil2._kopie(v) for k, v in fall.argumente.items()}

            def aendere(st, paar=paar):
                for p, pfad, neu in paar:
                    _setzen(st[p], pfad, neu)

            def lauf(st, fall=fall):
                return teil2._rufe(fall.fn, st)
            _, _, gem, gefegt, alle = _gefegt(lauf, mache, aendere)
            gefegt_ges += gefegt
            alle_ges += alle
            if gefegt < alle:
                gestrichen.append(f"{fall.name}: {gefegt} of {alle}")
            gemischt += [f"{fall.name} {paar[0][0]}+{paar[1][0]} at {k}: {v}" for k, v in gem[:2]]
        print(f"\nCORRELATED: {len(faelle) - len(ohne_paar)} of {len(faelle)} base cases with a pair ({arten}), "
              f"{gefegt_ges} of {alle_ges} positions swept; strided: {gestrichen}; without a pair "
              f"({len(ohne_paar)}): {ohne_paar}")
        self.assertEqual(gemischt, [], f"{len(gemischt)} verdicts of neither state")


# ── 4. ABA, targeted, up to the public verdict ─────────────────────────────────────────────────────────────────────

class ABAIsMeasuredUpToThePublicVerdict(_Registriert):
    """Two entries X and Y of one anchor list. Good is an entry over the statement's root, bad one over another root;
    the list PASSes only when both are good. The held states are (bad, good), (bad, bad) and (good, bad), each a FAIL;
    the copy (good, good) is never held.

    The reading at the call reads Y before X in each collect (`canonical._lesen_einmal` takes them from a stack, and
    `_gleich_gelesen` reads in the same order). The caller's gc callback looks at the frame the collector started in:
    when `canonical._lies` is about to read X in the first collect (its pairs not yet taken), it makes Y bad and then X
    good; when `_lies` is about to read Y in the second collect, X bad and then Y good; when it is about to read X in
    the second collect, Y bad and then X good. Each value is the same object each time, so each collect reads the same
    objects, the first one Y good and X good, which the list never held together. A step that never found its moment
    is reported as not measured, never as held."""

    def test_aba_reaches_the_public_verdict_only_where_the_limit_is_named(self) -> None:
        gut_text = base64.b64encode(_WURZEL).decode()
        schlecht_text = base64.b64encode(b"\x00" * 32).decode()
        anchors.register_anchor_type(_ANKERTYP, lambda proof, root, *, frozen, now: {"ok": True, "warn": False})
        x = {"type": _ANKERTYP, "target": "statement", "canonicalRoot": schlecht_text,
             "proof": base64.b64encode(b"p").decode()}
        y = dict(x, canonicalRoot=gut_text)
        liste = [x, y]
        ziele = {"statement": _WURZEL}

        def urteil(eintraege) -> Any:
            return _verdikt(lambda: anchors.verify_anchors(eintraege, target_roots=ziele), lambda r: r["status"])
        gehalten = {urteil([dict(x, canonicalRoot=a), dict(y, canonicalRoot=b)])
                    for a, b in ((schlecht_text, gut_text), (schlecht_text, schlecht_text), (gut_text, schlecht_text))}
        self.assertEqual(urteil([dict(x, canonicalRoot=gut_text), y]), "PASS", "the never-held state must pass")
        self.assertNotIn("PASS", gehalten)

        sammeln_1, sammeln_2, lies = (canonical._lesen_einmal.__code__, canonical._gleich_gelesen.__code__,
                                      canonical._lies.__code__)
        schritte = [(sammeln_1, x, [(y, schlecht_text), (x, gut_text)]),
                    (sammeln_2, y, [(x, schlecht_text), (y, gut_text)]),
                    (sammeln_2, x, [(y, schlecht_text), (x, gut_text)])]
        stand = {"i": 0}

        def cb(phase, info):
            if phase != "start" or stand["i"] >= len(schritte):
                return
            rahmen = sys._getframe(1)
            if rahmen.f_code is not lies or rahmen.f_back is None:
                return
            sammeln, ziel, aenderungen = schritte[stand["i"]]
            lokal = rahmen.f_locals
            if rahmen.f_back.f_code is sammeln and lokal.get("wert") is ziel and "paare" not in lokal:
                for eintrag, text in aenderungen:
                    eintrag["canonicalRoot"] = text
                stand["i"] += 1
        aus = _mit_gc(cb, lambda: urteil(liste))
        if stand["i"] < len(schritte):
            self.fail(f"NOT MEASURED: {stand['i']} of {len(schritte)} steps found their moment; verdict {aus}")
        print(f"\nABA: verdict {aus} over a list whose held states give {sorted(gehalten)}")
        if aus == "PASS":
            ohne = [str(p.relative_to(REPO)) for p in (REPO / "src" / "proofbundle" / "canonical.py",
                                                      REPO / "RESTRISIKO_620.md")
                    if _ERSATZSATZ not in " ".join(p.read_text(encoding="utf-8").split())]
            self.assertEqual(ohne, [], "ABA reaches the public verdict of verify_anchors (PASS over a list that held "
                             "no such state), and these texts describe the reading without the owner's sentence")


# ── 5. threads ─────────────────────────────────────────────────────────────────────────────────────────────────────

class AThreadThatMovesTheInputsGivesTheVerdictOfAHeldState(_Registriert):

    def test_a_thread_that_moves_two_entries_one_step_at_a_time(self) -> None:
        gut_text = base64.b64encode(_WURZEL).decode()
        schlecht_text = base64.b64encode(b"\x00" * 32).decode()
        anchors.register_anchor_type(_ANKERTYP, lambda proof, root, *, frozen, now: {"ok": True, "warn": False})
        x = {"type": _ANKERTYP, "target": "statement", "canonicalRoot": gut_text,
             "proof": base64.b64encode(b"p").decode()}
        y = dict(x, canonicalRoot=schlecht_text)
        liste = [x, y]
        # (good, bad) -> (bad, bad) -> (bad, good) -> (bad, bad) -> (good, bad): one key per step, each state FAILs.
        stopp = threading.Event()

        def wechsler():
            while not stopp.is_set():
                x["canonicalRoot"] = schlecht_text
                y["canonicalRoot"] = gut_text
                y["canonicalRoot"] = schlecht_text
                x["canonicalRoot"] = gut_text
        alt = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        t = threading.Thread(target=wechsler, daemon=True)
        t.start()
        verdikte: dict = {}
        try:
            for _ in range(1500):
                v = _verdikt(lambda: anchors.verify_anchors(liste, target_roots={"statement": _WURZEL}),
                             lambda r: r["status"])
                verdikte[str(v)] = verdikte.get(str(v), 0) + 1
        finally:
            stopp.set()
            t.join(10)
            sys.setswitchinterval(alt)
        print(f"\nTHREADS: {verdikte}")
        self.assertNotIn("PASS", verdikte, f"a state never held passed: {verdikte}")


if __name__ == "__main__":
    unittest.main()
