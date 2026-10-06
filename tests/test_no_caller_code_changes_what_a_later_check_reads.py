"""No caller code changes what a later check reads; a restricting flag restricts; a wrong container is refused.

SOURCE. The deep gate of the 6.2.0 release preparation at 7409b123 (PR 311) confirmed five P1 findings beside the
one of tests/test_the_evaluators_judge_a_policy_by_the_loaders_rule.py. They fall into three classes.

A. ONE READING BEFORE CALLER CODE, the class of PR 312, one step wider. PR 312 read every ARGUMENT once at entry.
   The property is about every VALUE a check judges: an argument, an element of one, an object the verifier hands
   to caller code, and an answer caller code returned. None of them is read after caller code could change it.
   * L1-620v2-T3-01: verify_decision_receipt read ``anchors`` (the list and each entry) and ``rp_trust`` after the
     evidence resolver ran, and verify_anchors copied each entry only when its turn came, so a registered verifier
     for one anchor rewrote the next one before it was read.
   * L3-620-T3-02: verify_sequence handed its own copy of the newest ArchiveTimeStamp to the caller's
     anchor_verifier and read ``external_token_type`` and ``hash_alg`` from that copy afterwards.
   * L3-620-T3-03: verify_outcome_receipt kept the attestation resolver's answer object and read it again after the
     resolver's next call.
B. A RESTRICTING FLAG RESTRICTS (L3-620-T2-01, a regression of PR 291). ``warn`` of a registered anchor verifier
   counted only as the exact True, so ``{"ok": True, "warn": "pending"}`` was a full anchor. With ``ok`` True a
   ``warn`` that is no bool now marks a pending anchor; with ``ok`` not True it still marks nothing, which is what
   PR 291 fixed (a ``warn`` of ``"false"`` turned a hard FAIL into a pending one).
C. A CONTAINER OF THE WRONG TYPE IS REFUSED, NEVER READ AS EMPTY (L4-620b-01). A ``related`` that is a Mapping but
   no dict (UserDict, MappingProxyType, ChainMap) was read as no attached entries, and reject_superseded did not
   see a verified retraction. The neighbour named in RESTRISIKO_620 is a falsy ``anchors`` that is no list, read
   as no anchors.

Every case was RED at 31cf5f7e (the loader-rule fix on main 52231c95) and is GREEN at the head that adds it; each
has its control beside it. The property tests at the end run each surface with callbacks that empty every
argument they can reach and compare the verdict with a run on copies and callbacks that change nothing.
"""
from __future__ import annotations

import base64
import collections
import copy
import dataclasses
import hashlib
import json
import pathlib
import types
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import anchors, dsse
from proofbundle.errors import BundleFormatError

_WURZEL = pathlib.Path(__file__).resolve().parents[1]

# Literal seeds: tests/test_sdist_ohne_signierwerkzeug.py allows `from_private_bytes` in a shipped test
# only over a seed written out in the source.
_A = Ed25519PrivateKey.from_private_bytes(b"\x41" * 32)   # signs
_P = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)   # the key a trust pack holds for a receiver
_W = Ed25519PrivateKey.from_private_bytes(b"\x43" * 32)   # the key a receiver statement is really signed by

_PROBE = "one-reading-probe/v1"
_HEADER = {"800000": "aa" * 32}
_DATEN = ["ab" * 32]


def _raw(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _b64(k) -> str:
    return base64.b64encode(_raw(k)).decode("ascii")


def _beispiel(name: str) -> dict:
    return json.loads((_WURZEL / "examples" / name).read_text(encoding="utf-8"))


def _wurzel(envelope) -> bytes:
    return anchors.statement_content_root(dsse.load_payload(envelope))


def _anker(root: bytes, typ: str = _PROBE, target: str = "statement") -> dict:
    return {"type": typ, "target": target, "canonicalRoot": base64.b64encode(root).decode("ascii"),
            "proof": base64.b64encode(b"p").decode("ascii")}


def _kante(hexd: str, relation: str = "supersedes") -> dict:
    return {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": hexd}}


class _KeinJsonWert:
    """A value no JSON document can hold."""


class _Registriert(unittest.TestCase):
    """Restores the anchor verifier registry after each case."""

    def setUp(self) -> None:
        gesichert = dict(anchors._VERIFIERS)
        self.addCleanup(lambda: (anchors._VERIFIERS.clear(), anchors._VERIFIERS.update(gesichert)))

    def _entscheidung(self, name: str = "decision_receipt_allow.json", **extra):
        from proofbundle.decision import emit_decision_receipt  # noqa: PLC0415
        praedikat = _beispiel(name)
        praedikat.update(extra)
        return praedikat, emit_decision_receipt(praedikat, _A)

    def _vertraut(self, praedikat, **abschnitt) -> dict:
        return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "one-reading",
                "decision_receipt": {"trusted_decision_makers": [
                    {"id": praedikat["decisionMaker"]["id"], "public_key_b64": _b64(_A)}], **abschnitt}}


def _rp_pruefer(proof, root, *, frozen, now, rp_trust=None):
    """Confirms only against a relying party's header, as the built-in time anchors do."""
    kopf = rp_trust.get("bitcoin_block_headers") if isinstance(rp_trust, dict) else None
    if kopf:
        return {"ok": True, "warn": False, "status": "confirmed", "rp_trusted": True, "detail": "rp header"}
    return {"ok": False, "warn": False, "status": "needs_rp_trust", "needs_rp_trust": True, "detail": "no header"}


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# A. L1-620v2-T3-01: the anchors and the relying party's trust material are read before caller code.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class TheAnchorsAreReadBeforeAnyCallback(_Registriert):

    def test_a_resolver_that_clears_the_anchor_list(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        praedikat, umschlag = self._entscheidung()
        policy = self._vertraut(praedikat)
        falsch = _anker(hashlib.sha256(b"another root").digest(), typ="chia-datalayer/v1")

        def lauf(leeren: bool) -> dict:
            anker = [dict(falsch)]

            def aufloeser(_digest) -> bool:
                if leeren:
                    anker.clear()
                return True

            return verify_decision_receipt(umschlag, _raw(_A), policy=policy, anchors=anker,
                                           evidence_resolver=aufloeser)

        kontrolle = lauf(False)
        self.assertIs(kontrolle["ok"], False)
        self.assertIs(kontrolle["anchors_ok"], False)
        r = lauf(True)
        self.assertIs(r["anchors_ok"], False, "a resolver that cleared the anchor list hid a failing anchor")
        self.assertIs(r["ok"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)

    def test_a_resolver_that_writes_the_relying_partys_header(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        anchors.register_anchor_type(_PROBE, _rp_pruefer)
        praedikat, umschlag = self._entscheidung()
        policy = self._vertraut(praedikat, require_external_anchor=True, allow_pending=False)
        anker = [_anker(_wurzel(umschlag))]

        def lauf(schreiben: bool, rp: dict) -> dict:
            def aufloeser(_digest) -> bool:
                if schreiben:
                    rp["bitcoin_block_headers"].update(_HEADER)
                return True

            return verify_decision_receipt(umschlag, _raw(_A), policy=policy, anchors=anker, rp_trust=rp,
                                           evidence_resolver=aufloeser)

        self.assertIs(lauf(False, {"bitcoin_block_headers": dict(_HEADER)})["ok"], True)   # control: header at entry
        self.assertIs(lauf(False, {"bitcoin_block_headers": {}})["ok"], False)             # control: no header
        r = lauf(True, {"bitcoin_block_headers": {}})
        self.assertIsNot(r["anchors_ok"], True, "a header the resolver wrote confirmed the anchor")
        self.assertIs(r["ok"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)

    def test_a_verifier_that_rewrites_the_next_anchor(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        _, umschlag = self._entscheidung("decision_receipt_deny.json")
        erstes = _anker(_wurzel(umschlag))
        zweites_roh = _anker(hashlib.sha256(b"another root").digest(), typ="chia-datalayer/v1")

        def lauf(umschreiben: bool) -> dict:
            zweites = dict(zweites_roh)

            def pruefer(proof, root, *, frozen, now):
                if umschreiben:
                    zweites.clear()
                    zweites.update(copy.deepcopy(erstes))
                return {"ok": True, "warn": False, "status": "confirmed", "detail": "x"}

            anchors.register_anchor_type(_PROBE, pruefer)
            return verify_decision_receipt(umschlag, _raw(_A), anchors=[dict(erstes), zweites])

        self.assertIs(lauf(False)["ok"], False)   # control
        r = lauf(True)
        self.assertIs(r["anchors_ok"], False, "a verifier rewrote the next anchor before it was read")
        self.assertIs(r["ok"], False)

    def test_verify_anchors_reads_every_entry_root_and_trust_before_the_first_verifier(self) -> None:
        wurzel = hashlib.sha256(b"statement").digest()
        fremd = hashlib.sha256(b"another root").digest()

        def lauf(form: str, schreiben: bool) -> dict:
            eins = _anker(wurzel)
            zwei = _anker(fremd) if form != "rp" else _anker(wurzel)
            ziele = {"statement": wurzel}
            rp = {"bitcoin_block_headers": {}}
            gerufen = []

            def pruefer(proof, root, *, frozen, now, rp_trust=None):
                gerufen.append(1)
                if schreiben and len(gerufen) == 1:
                    if form == "entry":
                        zwei["canonicalRoot"] = eins["canonicalRoot"]
                    elif form == "roots":
                        ziele["statement"] = fremd
                    elif form == "rp":
                        rp["bitcoin_block_headers"].update(_HEADER)
                if form == "rp":
                    return _rp_pruefer(proof, root, frozen=frozen, now=now, rp_trust=rp_trust) if len(gerufen) > 1 \
                        else {"ok": True, "warn": False, "status": "confirmed", "detail": "first"}
                return {"ok": True, "warn": False, "status": "confirmed", "detail": "x"}

            anchors.register_anchor_type(_PROBE, pruefer)
            return anchors.verify_anchors([eins, zwei], target_roots=ziele, rp_trust=rp)

        for form in ("entry", "roots", "rp"):
            with self.subTest(form=form):
                self.assertEqual(lauf(form, False)["status"], "FAIL")   # control
                r = lauf(form, True)
                self.assertEqual(r["status"], "FAIL", f"a verifier changed what the next anchor was judged by ({form})")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# A. L3-620-T3-02: verify_sequence hands caller code a copy and reads nothing from it afterwards.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class TheNewestArchiveTimeStampIsReadBeforeTheCallback(unittest.TestCase):

    def test_a_callback_that_relabels_the_hash_algorithm(self) -> None:
        from proofbundle.renewal import ArchiveTimeStamp, verify_sequence  # noqa: PLC0415
        gedeckt = hashlib.sha1("\n".join(_DATEN).encode()).hexdigest()
        folge = [[ArchiveTimeStamp("sha1", gedeckt, 1)]]

        def umbenennen(a) -> bool:
            object.__setattr__(a, "hash_alg", "sha256")
            return True

        kontrolle = verify_sequence(folge, _DATEN, anchor_verifier=lambda a: True, require_current_hash=True)
        self.assertIs(kontrolle.ok, False)
        r = verify_sequence(folge, _DATEN, anchor_verifier=umbenennen, require_current_hash=True)
        self.assertIs(r.ok, False, [(c.name, c.ok) for c in r.checks])
        self.assertIn(("renewal:current_hash", False), [(c.name, c.ok) for c in r.checks])

    def test_a_callback_that_drops_the_external_token(self) -> None:
        from proofbundle.renewal import build_initial_sequence, verify_sequence  # noqa: PLC0415
        a0 = build_initial_sequence(_DATEN, hash_alg="sha256", time=1000)[0][0]
        folge = [[dataclasses.replace(a0, external_token_type="opentimestamps", external_token=b"\x00\x01")]]

        def leeren(a) -> bool:
            object.__setattr__(a, "external_token_type", "")
            return True

        kontrolle = verify_sequence(folge, _DATEN, anchor_verifier=lambda a: True)
        self.assertIs(kontrolle.ok, False)
        r = verify_sequence(folge, _DATEN, anchor_verifier=leeren)
        self.assertIs(r.ok, False, [(c.name, c.ok) for c in r.checks])
        self.assertIn(("renewal:external_token", False), [(c.name, c.ok) for c in r.checks])

    def test_the_callback_gets_a_copy_it_cannot_reach_the_sequence_through(self) -> None:
        from proofbundle.renewal import build_initial_sequence, verify_sequence  # noqa: PLC0415
        folge = build_initial_sequence(_DATEN, hash_alg="sha256", time=1000)
        gesehen = []
        r = verify_sequence(folge, _DATEN, anchor_verifier=lambda a: gesehen.append(a) or True)
        self.assertIs(r.ok, True)   # control: the callback anchors
        self.assertIsNot(gesehen[0], folge[0][0])
        self.assertEqual(gesehen[0], folge[0][0])


class TheRegistriesAreReadBeforeTheCallback(_Registriert):
    """A verify lens on the cross-check fix at bc3d275f: module state that a verdict reads is a value it judges too.
    The registry of anchor verifiers was copied after the evidence resolver of the decision verifier had run, and
    ``HASH_REGISTRY`` was read after the anchor callback of ``verify_sequence``."""

    def test_a_resolver_that_registers_a_verifier_for_the_anchor(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        _, umschlag = self._entscheidung("decision_receipt_deny.json")
        anker = [_anker(_wurzel(umschlag), typ="probe-late/v1")]

        def lauf(registrieren: bool) -> dict:
            anchors._VERIFIERS.pop("probe-late/v1", None)

            def aufloeser(_digest) -> bool:
                if registrieren:
                    anchors.register_anchor_type(
                        "probe-late/v1", lambda proof, root, *, frozen, now: {"ok": True, "warn": False, "detail": "x"})
                return True

            return verify_decision_receipt(umschlag, _raw(_A), anchors=anker, evidence_resolver=aufloeser)

        self.assertIs(lauf(False)["anchors_ok"], False)   # control: an unknown anchor type fails
        r = lauf(True)
        self.assertIs(r["anchors_ok"], False, "a verifier the resolver registered judged the anchor")
        self.assertIs(r["ok"], False)

    def test_a_callback_that_rewrites_the_hash_registry(self) -> None:
        from proofbundle.hashalg import HASH_REGISTRY  # noqa: PLC0415
        from proofbundle.renewal import ArchiveTimeStamp, verify_sequence  # noqa: PLC0415
        gedeckt = hashlib.sha1("\n".join(_DATEN).encode()).hexdigest()
        folge = [[ArchiveTimeStamp("sha1", gedeckt, 1)]]
        echt = HASH_REGISTRY["sha1"]
        self.addCleanup(HASH_REGISTRY.__setitem__, "sha1", echt)

        def umschreiben(_a) -> bool:
            HASH_REGISTRY["sha1"] = dataclasses.replace(echt, status="current")
            return True

        kontrolle = verify_sequence(folge, _DATEN, anchor_verifier=lambda a: True, require_current_hash=True)
        self.assertIs(kontrolle.ok, False)
        r = verify_sequence(folge, _DATEN, anchor_verifier=umschreiben, require_current_hash=True)
        HASH_REGISTRY["sha1"] = echt
        self.assertIs(r.ok, False, "a callback that relabelled sha1 as current passed require_current_hash")
        self.assertIn(("renewal:current_hash", False), [(c.name, c.ok) for c in r.checks])


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# A. L3-620-T3-03: an answer of caller code is judged as it was when it was given.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class AResolverAnswerIsJudgedAsItWasGiven(unittest.TestCase):

    def test_a_key_the_next_call_rewrites(self) -> None:
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "outcomeId": "o-1", "decisionRef": {"sha256": "e" * 64},
                     "executor": {"id": "executor:x", "keyId": "kid-exec"},
                     "requestedActionDigest": {"sha256": "b" * 64}, "status": "executed",
                     "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
                     "receiverRefs": [{"relation": "receiverAck", "digest": {"sha256": "d" * 64},
                                       "receiverKeyId": "kid-recv"},
                                      {"relation": "receiverAck", "digest": {"sha256": "f" * 64},
                                       "receiverKeyId": "kid-other"}]}
        umschlag = emit_outcome_receipt(praedikat, _A)
        pack = {"roles": {"outcomeReceivers": {"keyIds": ["kid-recv"]}, "outcomeExecutors": {"keyIds": ["kid-exec"]}},
                "keys": {"kid-recv": {"publicKey": _b64(_P), "alg": "ed25519"},
                         "kid-exec": {"publicKey": _b64(_A), "alg": "ed25519"}}}

        def lauf(umschreiben: bool) -> dict:
            puffer = bytearray(_raw(_W))

            def bezeugen(d):
                if d.get("sha256") == "d" * 64:
                    return puffer
                if umschreiben:
                    puffer[:] = _raw(_P)
                return False

            # N43: the receiver-binding path this test measures runs only under a relying-party anchor; the pack
            # is pinned here (forwarded verdict) so the binding is exercised, as before.
            return verify_outcome_receipt(umschlag, _raw(_A), trust_pack=pack, trust_pack_pinned=True,
                                          evidence_resolver=lambda d: True,
                                          receiver_attestation_resolver=bezeugen)

        kontrolle = lauf(False)
        self.assertIs(kontrolle["receiver_key_bound"], False)
        r = lauf(True)
        self.assertIs(r["receiver_key_bound"], False, "a key the next call rewrote bound the receiver label")
        self.assertIn("KEY_ID_NOT_BOUND_TO_SIGNER", " ".join(r["errors"]))
        self.assertEqual(r["receiver_role_trusted"], kontrolle["receiver_role_trusted"])

    def test_the_expected_key_is_read_before_the_resolver(self) -> None:
        """The neighbour the sweep found: `assurance.classify_receiver_corroboration` (exported) read the caller's
        `expected_receiver_public_key` after it had called the caller's attestation resolver, so a resolver that
        rewrote a `bytearray` expectation to the key it returned reached INDEPENDENTLY_ATTESTED."""
        from proofbundle.assurance import EvidenceLevel, classify_receiver_corroboration  # noqa: PLC0415

        def lauf(umschreiben: bool) -> dict:
            erwartet = bytearray(_raw(_P))

            def bezeugen(_d):
                if umschreiben:
                    erwartet[:] = _raw(_W)
                return _raw(_W)

            return classify_receiver_corroboration({"sha256": "d" * 64}, evidence_resolver=lambda d: True,
                                                   independent_attestation_resolver=bezeugen,
                                                   executor_key_id="kid-exec", receiver_key_id="kid-recv",
                                                   expected_receiver_public_key=erwartet)

        self.assertIsNot(lauf(False)["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)   # control
        r = lauf(True)
        self.assertIsNot(r["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED,
                         "an expectation the resolver rewrote bound the receiver label")
        self.assertIn("KEY_ID_NOT_BOUND_TO_SIGNER", r["detail"])


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# B. L3-620-T2-01: a restricting flag restricts on any value but False.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class _Wahr:
    def __init__(self) -> None:
        self.gefragt = 0

    def __bool__(self) -> bool:
        self.gefragt += 1
        return True


class ARestrictingFlagRestricts(_Registriert):

    def setUp(self) -> None:
        super().setUp()
        self.antwort: dict = {}
        anchors.register_anchor_type(_PROBE, lambda proof, root, *, frozen, now: self.antwort)
        self.wurzel = hashlib.sha256(b"statement").digest()

    def _eins(self, antwort: dict) -> dict:
        self.antwort = antwort
        return anchors.verify_anchor(_anker(self.wurzel), target_roots={"statement": self.wurzel})

    def _gefordert(self, antwort: dict) -> dict:
        self.antwort = antwort
        return anchors.verify_anchors([_anker(self.wurzel)], target_roots={"statement": self.wurzel},
                                      require="any", allow_pending=False)

    def test_a_warn_that_is_no_bool_beside_ok_true_marks_a_pending_anchor(self) -> None:
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: PLC0415
        umschlag = emit_decision_receipt(_beispiel("decision_receipt_deny.json"), _A, strict=True)
        eigene = _wurzel(umschlag)
        for wert in ("true", "false", "pending", 1, 0, 1.0, "", None, [0], {}, _Wahr()):
            with self.subTest(warn=repr(wert)[:20]):
                antwort = {"ok": True, "warn": wert}
                self.assertIs(self._eins(antwort)["warn"], True)
                res = self._gefordert(antwort)
                self.assertIs(res["require_met"], False, "a pending anchor met a requirement for a full one")
                self.antwort = antwort
                ohne = anchors.verify_anchors([_anker(self.wurzel)], target_roots={"statement": self.wurzel})
                self.assertEqual(ohne["status"], "WARN")
                self.antwort = antwort
                r = verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=[_anker(eigene)])
                self.assertIsNot(r["anchors_ok"], True)
                if isinstance(wert, _Wahr):
                    self.assertEqual(wert.gefragt, 0, "the answer's own __bool__ ran")

    def test_control_absent_or_false_is_a_full_anchor_and_ok_not_true_stays_failed(self) -> None:
        for antwort in ({"ok": True}, {"ok": True, "warn": False}):
            with self.subTest(answer=antwort):
                self.assertIs(self._eins(antwort)["warn"], False)
                self.assertIs(self._gefordert(antwort)["require_met"], True)
        for wert in ("true", 1, _Wahr()):
            with self.subTest(ok_false_warn=repr(wert)[:20]):
                self.assertIs(self._eins({"ok": False, "warn": wert})["warn"], False)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# C. L4-620b-01: a container of the wrong type is refused, never read as empty.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class AWrongContainerIsRefusedNotReadAsEmpty(unittest.TestCase):

    _POLITIK = {"relations": {"reject_superseded": True}}

    def _flaechen(self):
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: PLC0415
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: PLC0415
        from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement  # noqa: PLC0415
        d = emit_decision_receipt({**_beispiel("decision_receipt_deny.json"), "decisionId": "c-related"}, _A,
                                  strict=True)
        o = emit_outcome_receipt({"schemaVersion": "0.1.0", "outcomeId": "o-related",
                                  "decisionRef": {"sha256": "d" * 64}, "executor": {"id": "ex"},
                                  "requestedActionDigest": {"sha256": "e" * 64}, "status": "executed",
                                  "performedAt": "2026-09-28T00:00:00Z"}, _A, strict=True)
        s = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "urn:uuid:c-related",
                                     "relationships": [_kante("c" * 64, "amends")]}, _A)
        return (("decision", d, verify_decision_receipt), ("outcome", o, verify_outcome_receipt),
                ("relation statement", s, verify_relation_statement))

    @staticmethod
    def _eintrag(umschlag) -> dict:
        return {"b" * 64: {"verified": True, "relationships": [_kante(_wurzel(umschlag).hex(), "retracts")]}}

    @staticmethod
    def _traeger(eintrag: dict):
        return (("UserDict", collections.UserDict(eintrag)), ("MappingProxyType", types.MappingProxyType(eintrag)),
                ("ChainMap", collections.ChainMap(eintrag)), ("list of pairs", list(eintrag.items())),
                ("str", "x"), ("empty list", []), ("empty tuple", ()), ("zero", 0))

    def test_related_that_is_no_dict_at_all_three_verifiers(self) -> None:
        for name, umschlag, pruefe in self._flaechen():
            eintrag = self._eintrag(umschlag)
            with self.subTest(surface=name):
                self.assertIs(pruefe(umschlag, _raw(_A))["ok"], True)                                 # control
                self.assertIs(pruefe(umschlag, _raw(_A), policy=self._POLITIK, related=eintrag)["ok"],
                              False)                                                                  # control
            for traeger, verwandt in self._traeger(eintrag):
                for politik in (self._POLITIK, None):
                    with self.subTest(surface=name, related=traeger, policy=politik is not None):
                        r = pruefe(umschlag, _raw(_A), policy=politik, related=verwandt)
                        self.assertIs(r["ok"], False, "a related of the wrong type was read as no entries")
                        self.assertIs(r["lineage_ok"], False)
                        self.assertIn("relation:related_malformed", " ".join(r["errors"]))

    def test_the_shared_engine_refuses_it_too(self) -> None:
        from proofbundle.relation import successor_warning, verify_relationship_edges  # noqa: PLC0415
        eintrag = {"b" * 64: {"verified": True, "relationships": [_kante("a" * 64, "retracts")]}}
        self.assertIsNotNone(successor_warning(None, eintrag, subject_hex="a" * 64))   # control
        for traeger, verwandt in self._traeger(eintrag):
            with self.subTest(related=traeger):
                r = verify_relationship_edges([_kante("c" * 64, "amends")], verwandt, subject_hex="a" * 64)
                self.assertEqual(r["lineage"], "FAIL")
                self.assertIsNotNone(r["supersededByAttached"])
                self.assertIsNotNone(successor_warning(None, verwandt, subject_hex="a" * 64))
        for leer in (None, {}):
            with self.subTest(related=leer):
                r = verify_relationship_edges([_kante("c" * 64, "amends")], leer, subject_hex="a" * 64)
                self.assertEqual(r["lineage"], "DECLARED_UNRESOLVED")   # control: absent stays absent

    def test_a_relations_section_that_is_no_dict(self) -> None:
        """The neighbour the sweep of this class found: the outcome and relation statement verifiers ran the
        relations gate only for a section that is a dict, and `relation.evaluate_relations_policy` read any other
        section as absent, so a policy whose `relations` is a list, a text or a number judged an attached
        retraction with no rule and gave ok True. The decision verifier refused the same policy through the
        loader's rule. `load_policy` refuses it ("relations must be a JSON object")."""
        from proofbundle.relation import CODE_LINEAGE_REQUIREMENT_FAILED, evaluate_relations_policy  # noqa: PLC0415
        for name, umschlag, pruefe in self._flaechen():
            eintrag = self._eintrag(umschlag)
            with self.subTest(surface=name):
                self.assertIs(pruefe(umschlag, _raw(_A), policy=self._POLITIK, related=eintrag)["ok"],
                              False)                                                                  # control
            for abschnitt in ([["reject_superseded", True]], "reject_superseded", 5, True, [], 0):
                with self.subTest(surface=name, relations=repr(abschnitt)):
                    r = pruefe(umschlag, _raw(_A), policy={"relations": abschnitt}, related=eintrag)
                    self.assertIs(r["ok"], False, "a relations section that is no dict was read as no rule")
                    self.assertIs(r["policy_ok"], False)
                    self.assertIn(CODE_LINEAGE_REQUIREMENT_FAILED, r.get("relations_policy_codes") or [])
        lineage = {"edges": [], "supersededByAttached": None}
        self.assertEqual(evaluate_relations_policy(None, lineage, successor_key_b64=None), [])   # control: absent
        for abschnitt in ([1], "x", 5, 0, [], _KeinJsonWert()):
            with self.subTest(section=type(abschnitt).__name__):
                codes = [v["code"] for v in evaluate_relations_policy(abschnitt, lineage, successor_key_b64=None)]
                self.assertEqual(codes, [CODE_LINEAGE_REQUIREMENT_FAILED])

    def test_anchors_that_are_falsy_and_no_list(self) -> None:
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: PLC0415
        umschlag = emit_decision_receipt(_beispiel("decision_receipt_deny.json"), _A, strict=True)
        for leer in (None, []):
            with self.subTest(anchors=leer):
                r = verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=leer)
                self.assertIs(r["ok"], True)          # control
                self.assertIsNone(r["anchors_ok"])
        self.assertEqual(anchors.verify_anchors(None, target_roots={})["status"], "SKIP")   # control
        for falsch in (0, "", {}, (), False, set(), frozenset(), 0.0):
            with self.subTest(anchors=repr(falsch)):
                r = verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=falsch)
                self.assertIs(r["anchors_ok"], False, "a falsy value that is no list was read as no anchors")
                self.assertIs(r["ok"], False)
                with self.assertRaises(BundleFormatError):
                    anchors.verify_anchors(falsch, target_roots={})


class AnEntryThatRaisesWhenReadFailsTheAnchorStep(unittest.TestCase):
    """verify_decision_receipt reads its anchors at entry, keeps what that reading raised, and raises it again at the
    anchor step (`raise _anker_fehler`), where its two arms turn it into a failed anchor verdict. Codex round two on
    PR 313 at 37fc3cac asked whether an entry whose type check raises escapes there. Measured, it does not, and no
    case held the path; this one does (owner order of 2026-09-29): ok False, anchors_ok False, no exception, and an
    exception of caller code is named by its type only, never rendered.

    Since the fix of deep gate run 6 the entry no longer reaches the body: the reading at the call
    (`canonical._ein_stand`) judges it by its type, never asks it its class, and holds it as a stand-in
    (`canonical._fremdkoerper`), which the anchor step refuses as malformed input (owner choice 8 on OA-73db31053a: the
    old expectation became the refusal). The arm for an exception of caller code stays for a registered verifier."""

    def test_an_entry_whose_type_check_raises(self) -> None:
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: PLC0415
        umschlag = emit_decision_receipt(_beispiel("decision_receipt_deny.json"), _A, strict=True)
        self.assertIs(verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=[])["ok"], True)   # control
        gerendert = []
        gefragt = []

        class _Fehler(Exception):
            def __str__(self) -> str:
                gerendert.append(1)
                return "rendered"

        def feindlich(ausnahme: BaseException):
            class _Eintrag:
                @property
                def __class__(self):
                    gefragt.append(1)
                    raise ausnahme
            return _Eintrag()

        for ausnahme in (RuntimeError("x"), _Fehler(), TypeError("x")):
            with self.subTest(error=type(ausnahme).__name__):
                r = verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=[feindlich(ausnahme)])
                self.assertIs(r["ok"], False)
                self.assertIs(r["anchors_ok"], False)
                self.assertIs(r["automation"]["safeForAutomation"], False)
                fehler = " ".join(r["errors"])
                self.assertIn("refused malformed anchor input (fail-closed)", fehler)
                self.assertIn("each anchor must be a JSON object", fehler)
        self.assertEqual(gefragt, [], "the reading or the anchor step asked an entry of the caller its class")
        self.assertEqual(gerendert, [], "the anchor step rendered an exception of caller code")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# THE PROPERTY, per surface: callbacks that empty every argument they can reach change no verdict.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


def _verwuesten(*objekte) -> None:
    """Empties every mutable container and overwrites every byte buffer it can reach, depth first."""
    for obj in objekte:
        if type(obj) is bytearray:
            obj[:] = bytes(len(obj))
        elif isinstance(obj, dict):
            werte = list(obj.values())
            obj.clear()
            _verwuesten(*werte)
        elif isinstance(obj, list):
            werte = list(obj)
            obj.clear()
            _verwuesten(*werte)


def _projektion(r: dict) -> tuple:
    felder = ("ok", "crypto_ok", "structure_ok", "policy_ok", "signer_trusted", "anchors_ok", "lineage_ok",
              "relations_policy_codes", "receiver_key_bound", "receiver_role_trusted", "executor_role_trusted")
    return (tuple(r.get(k) if not isinstance(r.get(k), list) else tuple(r.get(k)) for k in felder),
            (r.get("automation") or {}).get("safeForAutomation"), tuple(sorted(r["errors"])),
            tuple(sorted(r["warnings"])))


class ACallbackThatEmptiesEveryArgumentChangesNoVerdict(_Registriert):

    def test_decision(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        praedikat, umschlag = self._entscheidung()
        wurzel = _wurzel(umschlag).hex()

        def argumente() -> dict:
            return {"public_key": bytearray(_raw(_A)),
                    "policy": {**self._vertraut(praedikat, require_external_anchor=True),
                               "relations": {"reject_superseded": True}},
                    "anchors": [_anker(bytes.fromhex(wurzel)),
                                _anker(hashlib.sha256(b"another root").digest(), typ="chia-datalayer/v1")],
                    "rp_trust": {"bitcoin_block_headers": dict(_HEADER)},
                    "related": {"b" * 64: {"verified": True, "relationships": [_kante(wurzel, "retracts")]}}}

        for verwuesten in (False, True):
            args = argumente()

            def rueckruf(*_a, _args=args, **_k):
                if verwuesten:
                    _verwuesten(*_args.values())

            anchors.register_anchor_type(
                _PROBE, lambda proof, root, *, frozen, now, rp_trust=None, _r=rueckruf:
                    (_r(), _rp_pruefer(proof, root, frozen=frozen, now=now, rp_trust=rp_trust))[1])
            kopie = copy.deepcopy(args) if not verwuesten else args
            rest = {k: v for k, v in kopie.items() if k != "public_key"}
            r = verify_decision_receipt(umschlag, kopie["public_key"], **rest,
                                        evidence_resolver=lambda d, _r=rueckruf: (_r(), True)[1])
            if not verwuesten:
                erwartet = _projektion(r)
                self.assertIs(r["ok"], False)   # control: the second anchor and the retraction fail it
        self.assertEqual(_projektion(r), erwartet)

    def test_outcome(self) -> None:
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "outcomeId": "o-2", "decisionRef": {"sha256": "e" * 64},
                     "executor": {"id": "executor:x", "keyId": "kid-exec"},
                     "requestedActionDigest": {"sha256": "b" * 64}, "status": "executed",
                     "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
                     "receiverRefs": [{"relation": "receiverAck", "digest": {"sha256": "d" * 64},
                                       "receiverKeyId": "kid-recv"},
                                      {"relation": "receiverAck", "digest": {"sha256": "f" * 64},
                                       "receiverKeyId": "kid-recv"}]}
        umschlag = emit_outcome_receipt(praedikat, _A)
        wurzel = _wurzel(umschlag).hex()

        def argumente() -> dict:
            return {"public_key": bytearray(_raw(_A)),
                    "trust_pack": {"roles": {"outcomeReceivers": {"keyIds": ["kid-recv"]},
                                             "outcomeExecutors": {"keyIds": ["kid-exec"]}},
                                   "keys": {"kid-recv": {"publicKey": _b64(_P), "alg": "ed25519"},
                                            "kid-exec": {"publicKey": _b64(_A), "alg": "ed25519"}}},
                    "policy": {"relations": {"reject_superseded": True}},
                    "related": {"b" * 64: {"verified": True, "relationships": [_kante(wurzel, "retracts")]}},
                    "antwort": bytearray(_raw(_W))}

        for verwuesten in (False, True):
            args = copy.deepcopy(argumente())
            antwort = args.pop("antwort")

            def rueckruf(_args=args, _antwort=antwort):
                if verwuesten:
                    _verwuesten(*_args.values(), _antwort)

            def bezeugen(d, _r=rueckruf, _antwort=antwort):
                _r()
                return _antwort

            rest = {k: v for k, v in args.items() if k != "public_key"}
            # N43: pin the pack (forwarded verdict) so the receiver-binding path this test tampers with actually
            # runs; ok stays False for the retraction reason either way.
            r = verify_outcome_receipt(umschlag, args["public_key"], **rest, trust_pack_pinned=True,
                                       evidence_resolver=lambda d, _r=rueckruf: (_r(), True)[1],
                                       receiver_attestation_resolver=bezeugen)
            if not verwuesten:
                erwartet = _projektion(r)
                self.assertIs(r["ok"], False)   # control: the retraction fails it
        self.assertEqual(_projektion(r), erwartet)

    def test_verify_anchors(self) -> None:
        wurzel = hashlib.sha256(b"statement").digest()
        for verwuesten in (False, True):
            args = {"anchors": [_anker(wurzel), _anker(wurzel), _anker(hashlib.sha256(b"x").digest())],
                    "target_roots": {"statement": wurzel}, "rp_trust": {"bitcoin_block_headers": dict(_HEADER)}}

            def pruefer(proof, root, *, frozen, now, rp_trust=None, _args=args):
                antwort = _rp_pruefer(proof, root, frozen=frozen, now=now, rp_trust=rp_trust)
                if verwuesten:
                    _verwuesten(*_args.values())
                return antwort

            anchors.register_anchor_type(_PROBE, pruefer)
            r = anchors.verify_anchors(args["anchors"], target_roots=args["target_roots"], rp_trust=args["rp_trust"],
                                       require="any")
            projektion = (r["status"], r.get("require_met"), r["detail"],
                          tuple((x["ok"], x["warn"], x["detail"]) for x in r["results"]))
            if not verwuesten:
                erwartet = projektion
                self.assertEqual(r["status"], "FAIL")   # control: the third anchor stamps another root
        self.assertEqual(projektion, erwartet)

    def test_verify_sequence(self) -> None:
        from proofbundle.renewal import ArchiveTimeStamp, verify_sequence  # noqa: PLC0415
        gedeckt = hashlib.sha1("\n".join(_DATEN).encode()).hexdigest()
        for verwuesten in (False, True):
            folge = [[ArchiveTimeStamp("sha1", gedeckt, 1, external_token_type="opentimestamps",
                                       external_token=b"\x00", external_token_frozen={"a": [1]})]]
            daten = list(_DATEN)
            rp = {"bitcoin_block_headers": dict(_HEADER)}

            def rueckruf(a, _folge=folge, _daten=daten, _rp=rp):
                if verwuesten:
                    for feld in ("hash_alg", "external_token_type", "sig_alg"):
                        object.__setattr__(a, feld, "")
                    _verwuesten(a.external_token_frozen, _folge, _daten, _rp)
                return True

            r = verify_sequence(folge, daten, anchor_verifier=rueckruf, rp_trust=rp, require_current_hash=True)
            projektion = (r.ok, tuple((c.name, c.ok, c.detail) for c in r.checks))
            if not verwuesten:
                erwartet = projektion
                self.assertIs(r.ok, False)   # control: sha1 is not current, the token does not verify
        self.assertEqual(projektion, erwartet)


if __name__ == "__main__":
    unittest.main()
