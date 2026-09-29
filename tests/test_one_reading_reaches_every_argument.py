"""One reading of every argument a public verify surface judges (deep gate 6.2.0 at 2348f0a7).

SOURCE. The deep gate of the 6.2.0 release preparation (PR 311, head 2348f0a7) confirmed eight P1
findings, each by three of three blind jurors, in the class that tests/test_one_reading_at_every_surface.py
states for the whole package: a public verify surface reads the caller's object once, by what it stores,
into a plain copy, and every check uses only that copy. The sweep of that file calls each surface with
some of its arguments. The findings sit in the arguments it does not pass, and in surfaces it does not
list:

* the key a signature was checked under is read a second time for the trust pin, after caller code
  (an evidence resolver, a registered anchor verifier) could rewrite a mutable key buffer
  (decision, outcome: L1-620-T3-01);
* the claim of `verify_prereg` and `verify_evaluation_card` is read through its own `get`, and the
  stored hash is compared through the caller's `__eq__` (L1-620-T3-02, L2-620-PREREG-EVALCARD-CALLER-EQ);
* a renewal is signed over the rendering of an int subclass and judged by its stored value, `now` is
  subtracted through the caller's `__sub__`, and a remembered token digest is compared through the
  caller's `__eq__` (L2-620-RENEWAL-TIME-SIGNED-VS-JUDGED, -POLICY-NOW-INTSUB, -ROLLBACK-EQ);
* an anchor list is asked whether it is empty through its own `__bool__` (L3-620-02);
* the policy is read through its own `get` and `__getitem__` at the relations gate and at the anchor
  obligation (L4-620-01).

THE PROPERTY, unchanged: a public verify surface runs no method of the caller's objects to decide a
verdict, and it judges exactly the value it checked. Every case below was RED at 2074d814 (main, the
base of PR 311) and is GREEN at the head that adds it, with two exceptions named where they stand: the
anchor obligation of `test_a_relation_signer_pin_and_an_anchor_obligation_at_a_decision` is GREEN at
both, because `evaluate_decision_policy` judges that obligation by what the policy stores; and
`test_a_value_that_is_no_json_value_hides_no_relations_code` is GREEN at both, because it holds what
2074d814 already did and the first form of this change lost. The controls hold at both.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_WURZEL = pathlib.Path(__file__).resolve().parents[1]

# Literal seeds: tests/test_sdist_ohne_signierwerkzeug.py allows `from_private_bytes` in a shipped test
# only over a seed written out in the source.
_A = Ed25519PrivateKey.from_private_bytes(b"\x21" * 32)   # signs, is not trusted
_T = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)   # trusted, never signs


def _raw(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _b64(k) -> str:
    return base64.b64encode(_raw(k)).decode("ascii")


def _beispiel(name: str) -> dict:
    return json.loads((_WURZEL / "examples" / name).read_text(encoding="utf-8"))


def _kante(hexd: str, relation: str = "supersedes") -> dict:
    return {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": hexd}}


def _wurzel_von(envelope) -> str:
    from proofbundle import anchors, dsse  # noqa: PLC0415
    return anchors.statement_content_root(dsse.load_payload(envelope)).hex()


class _GleichAllem(str):
    """A str whose own `__eq__` and `__ne__` claim equality with every value."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# L1-620-T3-01: the key the signature was checked under is the key the trust rules judge.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class TheKeyTheSignatureWasCheckedUnderIsTheKeyTheTrustRulesJudge(unittest.TestCase):
    """PROPERTY: the trust pin and the relation-signer pin judge the key the DSSE signature was checked
    under. At 2074d814 both pins read the caller's `public_key` a second time with `base64.b64encode`,
    after the caller's evidence resolver (or a registered anchor verifier) ran, and a `bytearray` key the
    callback rewrote from the signer A to the trusted key T gave signer_trusted, policy_ok and ok True for
    a receipt T never signed."""

    def _entscheidung(self, **extra):
        from proofbundle.decision import emit_decision_receipt  # noqa: PLC0415
        praedikat = _beispiel("decision_receipt_allow.json")
        praedikat.update(extra)
        return praedikat, emit_decision_receipt(praedikat, _A)

    def _vertraut(self, praedikat) -> dict:
        policy = _beispiel("trust_policy_decision_strict.json")
        policy["decision_receipt"]["trusted_decision_makers"] = [
            {"id": praedikat["decisionMaker"]["id"], "public_key_b64": _b64(_T)}]
        return policy

    def test_the_trust_pin_of_a_decision(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        praedikat, umschlag = self._entscheidung()
        policy = self._vertraut(praedikat)
        kontrolle = verify_decision_receipt(umschlag, _raw(_A), policy=policy)
        self.assertIs(kontrolle["signer_trusted"], False)            # control: A is not trusted
        schluessel = bytearray(_raw(_A))

        def resolver(_digest):
            schluessel[:] = _raw(_T)
            return True

        r = verify_decision_receipt(umschlag, schluessel, policy=policy, evidence_resolver=resolver)
        self.assertIsNot(r["signer_trusted"], True, "the pin judged a key the signature was not checked under")
        self.assertIs(r["ok"], False)

    def test_the_trust_pin_through_a_registered_anchor_verifier(self) -> None:
        from proofbundle import anchors  # noqa: PLC0415
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        praedikat, umschlag = self._entscheidung()
        policy = self._vertraut(praedikat)
        schluessel = bytearray(_raw(_A))
        gesichert = dict(anchors._VERIFIERS)
        self.addCleanup(lambda: (anchors._VERIFIERS.clear(), anchors._VERIFIERS.update(gesichert)))

        def pruefer(proof, root, *, frozen, now):
            schluessel[:] = _raw(_T)
            return {"ok": True, "warn": False, "status": "confirmed", "detail": "rewrites the key"}

        anchors.register_anchor_type("one-reading-rewrites-the-key/v1", pruefer)
        anker = [{"type": "one-reading-rewrites-the-key/v1", "target": "statement",
                  "canonicalRoot": base64.b64encode(bytes.fromhex(_wurzel_von(umschlag))).decode(),
                  "proof": base64.b64encode(b"p").decode()}]
        r = verify_decision_receipt(umschlag, schluessel, policy=policy, anchors=anker)
        self.assertIsNot(r["signer_trusted"], True, "the pin judged a key a callback wrote after the signature check")
        self.assertIs(r["ok"], False)

    def test_the_relation_signer_pin_of_a_decision_and_an_outcome(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: PLC0415
        kante = _kante("e" * 64)
        policy = {"relations": {"relation_signer": {"supersedes": {"mode": "pinned", "keys": [_b64(_T)]}}}}
        _, d_umschlag = self._entscheidung(relationships=[kante])
        o_umschlag = emit_outcome_receipt(
            {"schemaVersion": "0.1.0", "outcomeId": "o-1", "decisionRef": {"sha256": "a" * 64},
             "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "c" * 64},
             "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
             "relationships": [kante]}, _A)
        for name, umschlag, pruefe in (("decision", d_umschlag, verify_decision_receipt),
                                       ("outcome", o_umschlag, verify_outcome_receipt)):
            with self.subTest(surface=name):
                self.assertIs(pruefe(umschlag, _raw(_A), policy=policy)["ok"], False)   # control
                schluessel = bytearray(_raw(_A))

                def resolver(_digest, schluessel=schluessel):
                    schluessel[:] = _raw(_T)
                    return True

                r = pruefe(umschlag, schluessel, policy=policy, evidence_resolver=resolver)
                self.assertIs(r["ok"], False, "the relation-signer pin judged a key a callback wrote")
                self.assertIn("RELATION_SIGNER_UNAUTHORIZED", r["relations_policy_codes"] or [])


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# L1-620-T3-02 and L2-620-PREREG-EVALCARD-CALLER-EQ: the stored hash is the hash compared.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class APreregistrationAndAnEvalCardAreJudgedByWhatTheClaimStores(unittest.TestCase):
    """PROPERTY: `verify_prereg` and `verify_evaluation_card` (both exported) compare the hash the claim
    stores with the hash of the document, by its characters. At 2074d814 the expected value was read
    through the claim's own `get` (after `isinstance`, which believes a `__class__` claim) and compared
    with `==`, which asks a `str` subclass's reflected `__eq__` first: ok True for a claim that stores the
    hash of another document."""

    def setUp(self) -> None:
        verzeichnis = tempfile.TemporaryDirectory()
        self.addCleanup(verzeichnis.cleanup)
        self.dokument = pathlib.Path(verzeichnis.name) / "protocol.txt"
        self.dokument.write_bytes(b"the real protocol\n")
        self.echt = hashlib.sha256(b"the real protocol\n").hexdigest()
        self.falsch = hashlib.sha256(b"another protocol\n").hexdigest()

    def test_both_surfaces(self) -> None:
        from proofbundle import verify_evaluation_card, verify_prereg  # noqa: PLC0415
        echt = self.echt

        class _EigenesGet(dict):
            def get(self, key, default=None):
                return echt

        class _BehauptetDict:
            __class__ = dict   # type: ignore[assignment]

            def get(self, key, default=None):
                return echt

        for pruefe, feld in ((verify_prereg, "prereg_sha256"), (verify_evaluation_card, "evaluation_card_sha256")):
            with self.subTest(surface=pruefe.__name__):
                self.assertIs(pruefe(str(self.dokument), {feld: self.echt})["ok"], True)     # control
                self.assertIs(pruefe(str(self.dokument), {feld: self.falsch})["ok"], False)  # control
                for name, anspruch in (("str subclass", {feld: _GleichAllem(self.falsch)}),
                                       ("dict subclass", _EigenesGet({feld: self.falsch})),
                                       ("class claim", _BehauptetDict())):
                    with self.subTest(carrier=name):
                        self.assertIsNot(pruefe(str(self.dokument), anspruch)["ok"], True,
                                         "ok True for a claim that stores the hash of another document")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# L2-620-RENEWAL-*: a renewal is signed and judged over the numbers and texts it stores.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class ARenewalIsJudgedByTheValuesItStores(unittest.TestCase):
    """PROPERTY: `verify_sequence` and `evaluate_renewal_policy` (both exported) judge the values an
    ArchiveTimeStamp, the policy and the relying party's arguments store, by the one rule for a number
    (an exact int) and by the characters of a text. At 2074d814 an int subclass passed `isinstance`,
    the signature was checked over its own `__format__` and the age computed from its stored value; a
    `now` answered the age through its own `__sub__`; a remembered token digest and the policy's
    strictness were compared through their own `__eq__`; an authority key was read through its own
    `__bytes__`."""

    def setUp(self) -> None:
        from proofbundle import build_initial_sequence  # noqa: PLC0415
        self.daten = ["ab" * 32]
        self.signiert = build_initial_sequence(self.daten, hash_alg="sha256", time=5, sig_alg="ed25519",
                                               signers={"ed25519": _A})

    def test_a_time_that_renders_another_number_than_it_stores(self) -> None:
        from proofbundle import RenewalPolicy, evaluate_renewal_policy, verify_sequence  # noqa: PLC0415

        class _Zeit(int):
            def __format__(self, spec):
                return "5"

            def __str__(self):
                return "5"

        politik = RenewalPolicy(max_ats_age=10, strictness="fail")
        self.assertIs(verify_sequence(self.signiert, self.daten, authority_keys={"ed25519": _raw(_A)}).ok, True)
        self.assertIs(evaluate_renewal_policy(self.signiert, policy=politik, now=1000).ok, False)   # control
        gefaelscht = [[dataclasses.replace(self.signiert[0][0], time=_Zeit(999))]]
        self.assertIsNot(verify_sequence(gefaelscht, self.daten, authority_keys={"ed25519": _raw(_A)}).ok, True,
                         "a signature over the time 5 verified an ArchiveTimeStamp that stores 999")
        self.assertIsNot(evaluate_renewal_policy(gefaelscht, policy=politik, now=1000).ok, True,
                         "an overdue ArchiveTimeStamp read as fresh")

    def test_a_clock_that_answers_its_own_arithmetic(self) -> None:
        from proofbundle import RenewalPolicy, build_initial_sequence, evaluate_renewal_policy  # noqa: PLC0415

        class _Uhr(int):
            def __sub__(self, other):
                return 0

            def __lt__(self, other):
                return False

            def __gt__(self, other):
                return False

        folge = build_initial_sequence(self.daten, hash_alg="sha256", time=1)
        politik = RenewalPolicy(max_ats_age=100, strictness="fail")
        self.assertIs(evaluate_renewal_policy(folge, policy=politik, now=1_000_000).ok, False)   # control
        self.assertIsNot(evaluate_renewal_policy(folge, policy=politik, now=_Uhr(1_000_000)).ok, True,
                         "a clock decided the age through its own subtraction")

    def test_a_strictness_that_claims_to_be_warn(self) -> None:
        from proofbundle import RenewalPolicy, build_initial_sequence, evaluate_renewal_policy  # noqa: PLC0415
        folge = build_initial_sequence(self.daten, hash_alg="sha256", time=1)
        self.assertIs(evaluate_renewal_policy(folge, policy=RenewalPolicy(max_ats_age=100, strictness="fail"),
                                              now=1_000_000).ok, False)   # control
        politik = RenewalPolicy(max_ats_age=100, strictness=_GleichAllem("fail"))
        self.assertIsNot(evaluate_renewal_policy(folge, policy=politik, now=1_000_000).ok, True,
                         "a strictness that stores 'fail' was judged as 'warn'")

    def test_a_remembered_token_digest_compared_by_its_characters(self) -> None:
        from proofbundle import build_initial_sequence, renew_timestamp, verify_sequence  # noqa: PLC0415
        from proofbundle.renewal import anchor_proof_digest  # noqa: PLC0415
        voll = renew_timestamp(build_initial_sequence(self.daten, hash_alg="sha256", time=1), time=2)
        bekannt = anchor_proof_digest(voll[-1][-1])
        gekuerzt = [[voll[0][0]]]

        def kein_rueckfall(folge, wert):
            r = verify_sequence(folge, self.daten, allow_unauthenticated_anchor=True, known_newest_token_digest=wert)
            return [c.ok for c in r.checks if c.name == "renewal:no_rollback"][0]

        self.assertIs(kein_rueckfall(voll, bekannt), True)        # control
        self.assertIs(kein_rueckfall(gekuerzt, bekannt), False)   # control
        self.assertIs(kein_rueckfall(gekuerzt, _GleichAllem(bekannt)), False,
                      "a truncated sequence passed the rollback check through the caller's own __eq__")

    def test_an_authority_key_is_read_by_the_bytes_it_stores(self) -> None:
        from proofbundle import verify_sequence  # noqa: PLC0415
        vertraut = _raw(_T)
        unterzeichner = _raw(_A)

        class _Schluessel(bytes):
            def __bytes__(self):
                return unterzeichner

        self.assertIs(verify_sequence(self.signiert, self.daten, authority_keys={"ed25519": vertraut}).ok,
                      False)   # control: T did not sign
        self.assertIsNot(verify_sequence(self.signiert, self.daten,
                                         authority_keys={"ed25519": _Schluessel(vertraut)}).ok, True,
                         "an authority key that stores T anchored a signature of A through its own __bytes__")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# L3-620-02: an anchor list is read by what it stores.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class AnAnchorListIsReadByWhatItStores(unittest.TestCase):
    """PROPERTY: `verify_decision_receipt(anchors=...)` judges the anchors the list stores. At 2074d814
    it asked the list `anchors or []`, which runs the caller's `__bool__`: a list that stores an anchor
    over another root and says it is empty hid the failing anchor, and ok went from False to True."""

    def test_a_list_that_says_it_is_empty(self) -> None:
        from proofbundle import anchors  # noqa: PLC0415
        from proofbundle.decision import emit_decision_receipt, verify_decision_receipt  # noqa: PLC0415
        gesichert = dict(anchors._VERIFIERS)
        self.addCleanup(lambda: (anchors._VERIFIERS.clear(), anchors._VERIFIERS.update(gesichert)))
        anchors.register_anchor_type("one-reading-says-empty/v1",
                                     lambda proof, root, *, frozen, now: {"ok": True, "warn": False,
                                                                          "status": "confirmed", "detail": "x"})
        umschlag = emit_decision_receipt(_beispiel("decision_receipt_deny.json"), _A, strict=True)
        falsch = {"type": "one-reading-says-empty/v1", "target": "statement",
                  "canonicalRoot": base64.b64encode(hashlib.sha256(b"another root").digest()).decode(),
                  "proof": base64.b64encode(b"p").decode()}
        aufrufe: list = []

        class _SagtLeer(list):
            def __len__(self):
                aufrufe.append("__len__")
                return 0

            def __bool__(self):
                aufrufe.append("__bool__")
                return False

        self.assertIs(verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=[falsch])["ok"], False)
        r = verify_decision_receipt(umschlag, _raw(_A), strict=True, anchors=_SagtLeer([falsch]))
        self.assertIs(r["anchors_ok"], False, "a list that said it was empty hid an anchor over another root")
        self.assertIs(r["ok"], False)
        self.assertEqual(aufrufe, [], "the anchor list's own methods ran")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# L4-620-01: the policy is read by what it stores, at every gate of all three receipt verifiers.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class _VerstecktGet(dict):
    """Stores the policy; its own `get` answers the default for every key."""

    def get(self, key, default=None):
        return default


class _TauschtAbschnitt(dict):
    """`get` answers what is stored; `policy["relations"]` answers an empty section."""

    def __getitem__(self, key):
        return {} if key == "relations" else dict.__getitem__(self, key)


class ThePolicyIsReadByWhatItStores(unittest.TestCase):
    """PROPERTY: the relations gate, the anchor obligation and the relation statement's self-assertion
    gate of `verify_decision_receipt`, `verify_outcome_receipt` and `verify_relation_statement` read the
    policy as the plain copy of what it stores. At 2074d814 each read the caller's policy through its own
    `get` and `__getitem__`, while `evaluate_decision_policy` read the same policy by what it stores: a
    policy dict subclass hid a verified attached retraction, a relation-signer pin and an anchor
    obligation, and ok and safeForAutomation came out True."""

    def setUp(self) -> None:
        from proofbundle.policy import load_policy  # noqa: PLC0415
        self.k64 = _b64(_A)
        self.policy = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "one-reading",
                                   "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": self.k64}]},
                                   "relations": {"reject_superseded": True}})

    def _ziel(self, wurzel: str, relation: str = "retracts") -> dict:
        return {"e" * 64: {"verified": True, "relationships": [_kante(wurzel, relation)], "verified_under": self.k64,
                           "subject_digest": None, "subject_digest_state": "absent"}}

    def _entscheidung(self, decision_id: str, **extra):
        from proofbundle.decision import emit_decision_receipt  # noqa: PLC0415
        praedikat = _beispiel("decision_receipt_deny.json")
        praedikat["decisionId"] = decision_id
        praedikat.update(extra)
        return emit_decision_receipt(praedikat, _A, strict=True)

    def _drei_flaechen(self):
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: PLC0415
        from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement  # noqa: PLC0415
        d = self._entscheidung("d-one-reading")
        s = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "urn:uuid:one-reading",
                                     "relationships": [_kante("c" * 64, "derivedFrom")]}, _A)
        o = emit_outcome_receipt({"schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
                                  "executor": {"id": "ex", "keyId": "kid-exec"},
                                  "requestedActionDigest": {"sha256": "1" * 64}, "effectDigest": {"sha256": "1" * 64},
                                  "status": "executed", "performedAt": "2026-07-17T00:00:00Z",
                                  "policyPurpose": "outcome"}, _A, strict=False)
        return (("decision", d, verify_decision_receipt), ("relation statement", s, verify_relation_statement),
                ("outcome", o, verify_outcome_receipt))

    def test_an_attached_retraction_at_all_three_verifiers(self) -> None:
        for name, umschlag, pruefe in self._drei_flaechen():
            ziel = self._ziel(_wurzel_von(umschlag))
            with self.subTest(surface=name):
                self.assertIs(pruefe(umschlag, _raw(_A), policy=dict(self.policy), related=ziel)["ok"], False)
                for traeger in (_VerstecktGet, _TauschtAbschnitt):
                    with self.subTest(carrier=traeger.__name__):
                        r = pruefe(umschlag, _raw(_A), policy=traeger(self.policy), related=ziel)
                        self.assertIs(r["ok"], False, "a policy read through its own methods hid a retraction")
                        self.assertIs(r["policy_ok"], False)

    def test_a_value_that_is_no_json_value_hides_no_relations_code(self) -> None:
        """The neighbour the full suite found in the first form of this change: a policy that cannot be
        copied as a whole (it holds a value that is no JSON value) skipped the relations gate, so the gate's
        own code LINEAGE_REQUIREMENT_FAILED was missing beside the generic refusal
        (tests/test_an_unreadable_attached_entry_silences_no_sibling.py, outcome). The section is read as
        the policy stores it then (`canonical._abschnitt_von`), at all three verifiers, whether the value
        sits beside the section or inside it. GREEN at 2074d814, where the gate read `policy["relations"]`."""

        class _KeinJsonWert:
            """A value no JSON document can hold."""

        abschnitt = dict(self.policy["relations"])
        for name, umschlag, pruefe in self._drei_flaechen():
            ziel = self._ziel(_wurzel_von(umschlag))
            for ort, policy in (("beside the section", {**self.policy, "x": _KeinJsonWert()}),
                                ("inside the section", {**self.policy,
                                                        "relations": {**abschnitt, "x": _KeinJsonWert()}})):
                with self.subTest(surface=name, value=ort):
                    r = pruefe(umschlag, _raw(_A), policy=policy, related=ziel)
                    self.assertIs(r["ok"], False)
                    self.assertIs(r["policy_ok"], False)
                    self.assertIn("LINEAGE_REQUIREMENT_FAILED", r.get("relations_policy_codes") or [])

    def test_a_relation_signer_pin_and_an_anchor_obligation_at_a_decision(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        from proofbundle.policy import load_policy  # noqa: PLC0415
        anderer = Ed25519PrivateKey.from_private_bytes(b"\x23" * 32)
        ziel = self._entscheidung("d-one-reading-target")
        zh = _wurzel_von(ziel)
        umschlag = self._entscheidung("d-one-reading-2", relationships=[_kante(zh, "supersedes")])
        verwandt = {zh: {"verified": True, "relationships": None, "verified_under": self.k64,
                         "subject_digest": None, "subject_digest_state": "absent"}}
        gepinnt = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "one-reading-2",
                               "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": self.k64}]},
                               "relations": {"relation_signer": {"supersedes": {"mode": "pinned",
                                                                                "keys": [_b64(anderer)]}}}})
        anker = load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "one-reading-3",
                             "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": self.k64}],
                                                  "require_external_anchor": True}})
        for name, policy, rel in (("relation signer", gepinnt, verwandt), ("anchor obligation", anker, None)):
            with self.subTest(case=name):
                self.assertIs(verify_decision_receipt(umschlag, _raw(_A), policy=dict(policy), related=rel)["ok"],
                              False)   # control
                r = verify_decision_receipt(umschlag, _raw(_A), policy=_VerstecktGet(policy), related=rel)
                self.assertIs(r["ok"], False, f"a policy read through its own get hid the {name}")

    def test_a_section_with_its_own_get_at_the_self_assertion_gate(self) -> None:
        from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement  # noqa: PLC0415
        ziel = self._entscheidung("d-one-reading-5")
        th = _wurzel_von(ziel)
        aussage = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "urn:uuid:one-reading-5",
                                           "relationships": [_kante(th, "retracts")]}, _A)
        verwandt = {th: {"verified": True, "relationships": None, "verified_under": self.k64,
                         "subject_digest": None, "subject_digest_state": "absent"}}
        self.assertIs(verify_relation_statement(aussage, _raw(_A), policy={"relations": {"reject_retracted": True}},
                                                related=verwandt)["ok"], False)   # control
        r = verify_relation_statement(aussage, _raw(_A), policy={"relations": _VerstecktGet({"reject_retracted": True})},
                                      related=verwandt)
        self.assertIs(r["ok"], False, "a section read through its own get hid reject_retracted")


if __name__ == "__main__":
    unittest.main()
