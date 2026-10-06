"""Every rule a check path lists as applied has an observable effect on that path's verdict.

SOURCE. Deep gate run 7 at 1a3cd672, L3-620v7-T18-EVALUATE-POLICY-EXPECTED-AUD-UNAPPLIED-01 (three of three jurors
P1): `policy.ANGEWANDTE_REGELN["evaluate_policy"]` lists ``sd_jwt.expected_aud``, so `_regelfehler` does not refuse
it, and the body of `evaluate_policy` never read it. A library caller who verified with `verify_bundle(bundle)` got
policy_ok True for a KB-JWT bound to another audience. The T16 contract (`test_every_rule_of_a_policy_is_handled_by_
the_command.py`) asks whether a rule is REFUSED or not; it never asked whether a rule that is not refused DOES
anything. Owner order OA-bdad1b7352 = A (2026-10-02), in English: a generator checks the observable effect of every
pair of ANGEWANDTE_REGELN.

THE PROPERTY. For every pair (check path, rule) in `ANGEWANDTE_REGELN`, there is a world and a policy in which the
rule alone turns the verdict of that path: the policy without the rule passes and with it fails (a requirement), or
the policy without it fails and with it passes (a permission or trust input). "Alone" is checked on the data: the two
policies differ in that one rule. A refusal is no effect: exit 2 at the CLI, and in the library a verdict whose text
says the policy was refused, never count as the rule's failure.

THE PAIRS come from `ANGEWANDTE_REGELN` itself, never from a copy, so a rule added to a path's contract without a
case here makes `test_every_pair_of_the_contract_has_a_case_or_a_measured_reason` red. A pair that cannot turn the
verdict on its own stands in `_OHNE_EIGENE_WIRKUNG` with its reason, and that reason is a measurement here too
(`test_a_pair_without_an_effect_of_its_own_is_subsumed_as_stated`), not a sentence.

THE SURFACES of a path are the ones that pass its name to `_regelfehler`: `verify`, `decision verify` with and
without `--anchors`, `outcome verify` and `relation-statement verify` at the CLI; `evaluate_policy`,
`evaluate_decision_policy`, `verify_decision_receipt`, `verify_outcome_receipt` and `verify_relation_statement` in
the library. The paths `outcome` and `relation_statement` are measured at both of theirs.

MEASURED when this file was added: against the code of 1a3cd672 the generator is red at exactly
``evaluate_policy x sd_jwt.expected_aud`` (the P1); every other pair turns its verdict. Against the repair it is
green.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle import anchors as _anker_modul  # noqa: E402
from proofbundle.cli import main  # noqa: E402
from proofbundle.policy import ANGEWANDTE_REGELN  # noqa: E402

_V2 = "proofbundle/trust-policy/v0.2"
_HAUPT = Ed25519PrivateKey.from_private_bytes(b"\x61" * 32)
_FREMD = Ed25519PrivateKey.from_private_bytes(b"\x62" * 32)
_VERGANGEN, _ZUKUNFT = "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"
_ALG = "jcs-sha256-v1"
#: The anchor types this file registers for the time of its class, and removes again.
_TYP_OK, _TYP_WARTET = "test-effect-confirmed", "test-effect-pending"
_TYP_VERTRAUT = {"trusted_tsa_roots": "test-effect-rp-tsa-roots", "bitcoin_block_headers": "test-effect-rp-btc",
                 "trusted_tsa_policy_oids": "test-effect-rp-tsa-oids"}


def _b64(k) -> str:
    return base64.b64encode(k.public_key().public_bytes_raw()).decode("ascii")


def _b64b(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _kante(ziel: str, relation: str) -> dict:
    return {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": _ALG, "digest": ziel}}


def _anker(typ: str, wurzel: bytes, ziel: str) -> dict:
    return {"type": typ, "target": ziel, "canonicalRoot": _b64b(wurzel), "proof": _b64b(b"good"), "anchoredAt": None}


def _bestaetigt(proof, root, *, frozen, now):
    return {"ok": proof == b"good", "detail": "confirmed (test)"}


def _wartend(proof, root, *, frozen, now):
    return {"ok": False, "warn": True, "status": "pending", "detail": "pending (test)"}


def _vertraut_von(schluessel: str):
    """An anchor that verifies only when the relying party's trust carries ``schluessel``: the observable effect of
    that trust input is that it reaches the anchor check."""
    def pruefe(proof, root, *, frozen, now, rp_trust=None):
        if (rp_trust or {}).get(schluessel):
            return {"ok": True, "rp_trusted": True, "detail": f"confirmed by {schluessel} (test)"}
        return {"ok": False, "needs_rp_trust": True, "status": "needs_rp_trust", "detail": f"needs {schluessel}"}
    return pruefe


def _politik(regeln: "dict[tuple, Any]") -> dict:
    p: dict = {"schema": _V2, "policy_id": "org/rule-effect-v1"}
    for (abschnitt, schluessel), wert in regeln.items():
        if abschnitt is None:
            p[schluessel] = wert
        else:
            p.setdefault(abschnitt, {})[schluessel] = wert
    return p


# ── the worlds ──────────────────────────────────────────────────────────────────────────────────────────────


class _Welt:
    """Every receipt a case needs, signed by `_HAUPT` unless named otherwise, written to files for the CLI."""

    def __init__(self, ordner: str) -> None:
        from proofbundle import dsse, emit_bundle
        from proofbundle import checkpoint as cp
        from proofbundle.anchors import statement_content_root
        from proofbundle.decision import emit_decision_receipt
        from proofbundle.emit import _raw_pub
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.outcome import emit_outcome_receipt
        from proofbundle.relation_statement import emit_relation_statement
        import test_kbjwt as kb
        self.d = Path(ordner)
        self.pub = _b64(_HAUPT)
        self.zaehler = 0
        self.dateien: dict = {}
        self.objekte: dict = {}

        # Eval side. b0: a plain bundle. sd: an eval receipt with an SD-JWT VC and a verified key binding (audience
        # verifier.example, nonce n-1, assurance reproduced, claim timestamp 2026-07-09). sa: a self-attested claim
        # without pre-registration.
        b0 = emit_bundle(b'{"x": 1}', _HAUPT)
        self._lege("b0", b0)
        presented, issuer, _ = kb._issue_presented()
        self.sd_pub = base64.b64encode(kb._raw_pub(issuer)).decode("ascii")
        sd = emit_eval_receipt(kb._EV_CLAIM, issuer, sd_jwt={"compact": presented, "issuer_public_key_b64": self.sd_pub})
        self._lege("sd", sd)
        jwt = presented.split("~", 1)[0].split(".")[1]
        self.vct = json.loads(base64.urlsafe_b64decode(jwt + "=" * (-len(jwt) % 4))).get("vct")
        sa_claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9", n=10,
            model_id="m", dataset_id="d", issuer="Lab", timestamp="2026-07-02T00:00:00Z",
            assurance_level="self_attested")
        self._lege("sa", emit_eval_receipt(sa_claim, _HAUPT))
        # The anchored eval receipts: a preRegistration-target anchor over the signed prereg digest.
        prereg = hashlib.sha256(b"effect protocol\n").hexdigest()
        a_claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9", n=10,
            model_id="m", dataset_id="d", issuer="Lab", timestamp="2026-07-02T00:00:00Z", prereg_sha256=prereg)
        for name, typ in (("anker_ok", _TYP_OK), ("anker_wartet", _TYP_WARTET),
                          *((f"anker_{k}", t) for k, t in _TYP_VERTRAUT.items())):
            r = emit_eval_receipt(a_claim, _HAUPT)
            r["anchors"] = [_anker(typ, bytes.fromhex(prereg), "preRegistration")]
            self._lege(name, r)
        self.b0_schema = b0["schema"]
        self.b0_root = base64.b64decode(b0["merkle"]["root_b64"])
        self.b0_hash_alg = b0["merkle"]["hash_alg"]
        cp_signer = Ed25519PrivateKey.from_private_bytes(b"\x63" * 32)
        origin = "proofbundle.example/effect-log"

        def eintrag(wurzel: bytes, groesse: int) -> dict:
            signiert = cp.sign_checkpoint(origin, groesse, wurzel, cp_signer, origin)
            return {"origin": origin, "root": _b64b(wurzel), "treeSize": groesse, "hashAlg": "sha256-rfc6962",
                    "checkpointSigner": cp.vkey(origin, _raw_pub(cp_signer)),
                    "signature": signiert.split("\n\n", 1)[1].strip().split(" ")[2]}
        self.cp_passend = eintrag(self.b0_root, b0["merkle"]["tree_size"])
        self.cp_fremd = eintrag(b"\x09" * 32, b0["merkle"]["tree_size"])

        # Decision side: the shipped DENY example and variants, each with a confirmed and a pending anchor over its
        # own content root (detached, for `--anchors` and `anchors=`).
        basis = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))

        def ohne(pfad: "tuple[str, ...]") -> dict:
            p = copy.deepcopy(basis)
            ort = p
            for teil in pfad[:-1]:
                ort = ort[teil]
            del ort[pfad[-1]]
            return p

        self.parent = emit_outcome_receipt(
            {"schemaVersion": "0.1.0", "outcomeId": "o-parent", "decisionRef": {"sha256": "e" * 64},
             "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "b" * 64},
             "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}},
            _HAUPT)
        self._lege("parent", self.parent)
        self.parent_root = statement_content_root(dsse.load_payload(self.parent)).hex()
        mit_spur = copy.deepcopy(basis)
        mit_spur["traceContext"] = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}
        roh = copy.deepcopy(basis)
        roh["privacy"]["rawInputsIncluded"] = True
        kind = copy.deepcopy(basis)
        kind["relationships"] = [_kante(self.parent_root, "derivedFrom")]
        varianten = {"d": basis, "d_ohne_digest": ohne(("policyBoundary", "policyDigest")),
                     "d_ohne_audience": ohne(("validity", "audience")), "d_ohne_nonce": ohne(("validity", "nonce")),
                     "d_ohne_not_checked": ohne(("notChecked",)),
                     "d_ohne_dcc": ohne(("decisionChangeConditions",)), "d_mit_spur": mit_spur, "d_roh": roh,
                     "d_kind": kind}
        self.wurzel: dict = {}
        for name, praed in varianten.items():
            env = emit_decision_receipt(praed, _HAUPT, strict=False)
            self._lege(name, env)
            self.wurzel[name] = hashlib.sha256(dsse.load_payload(env)).digest()
            for art, typ in (("ok", _TYP_OK), ("wartet", _TYP_WARTET)):
                self._lege(f"{name}.anker_{art}", [_anker(typ, self.wurzel[name], "statement")])
        self.d_typ = json.loads(base64.b64decode(self.objekte["d"]["payload"]))["predicateType"]

        # Lineage: an outcome and a statement that derive from the parent, a retraction of the base decision and of
        # the parent, and statements that supersede and retract the parent.
        self.wurzel["parent"] = bytes.fromhex(self.parent_root)
        o_kind = dict(json.loads(base64.b64decode(self.parent["payload"]))["predicate"], outcomeId="o-child",
                      relationships=[_kante(self.parent_root, "derivedFrom")])
        self._lege("o_kind", emit_outcome_receipt(o_kind, _HAUPT))
        stellung = {"schemaVersion": "0.1.0", "reasonCode": "withdrawal", "reason": "x",
                    "declaredAt": "2026-09-29T00:00:00Z"}

        def aussage(sid: str, ziel: str, relation: str) -> dict:
            k = dict(_kante(ziel, relation), **{k: v for k, v in stellung.items() if k != "schemaVersion"})
            return emit_relation_statement({"schemaVersion": "0.1.0", "statementId": sid, "relationships": [k]},
                                           _HAUPT)
        self._lege("s_kind", aussage("urn:uuid:effect-derived", self.parent_root, "derivedFrom"))
        self._lege("s_ersetzt", aussage("urn:uuid:effect-supersedes", self.parent_root, "supersedes"))
        self._lege("s_zieht_zurueck", aussage("urn:uuid:effect-retracts", self.parent_root, "retracts"))
        self._lege("r_d", aussage("urn:uuid:effect-retract-d", self.wurzel["d"].hex(), "retracts"))
        self._lege("r_parent", aussage("urn:uuid:effect-retract-parent", self.parent_root, "retracts"))
        self.aussage_wurzel = {n: statement_content_root(dsse.load_payload(self.objekte[n])).hex()
                               for n in ("s_kind", "s_ersetzt", "s_zieht_zurueck", "r_d", "r_parent")}

    def _lege(self, name: str, obj: Any) -> None:
        self.objekte[name] = obj
        p = self.d / f"{name}.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        self.dateien[name] = str(p)

    def politik_datei(self, politik: dict) -> str:
        self.zaehler += 1
        p = self.d / f"policy_{self.zaehler}.json"
        p.write_text(json.dumps(politik), encoding="utf-8")
        return str(p)

    def eintrag(self, wurzel_hex: str, beziehungen: "list | None" = None) -> dict:
        """A `related=` entry of the library verifiers: the attached target verified under `_HAUPT`."""
        return {"verified": True, "verified_under": self.pub, "subject_digest": None,
                "subject_digest_state": "absent", "relationships": beziehungen}


# ── the surfaces ────────────────────────────────────────────────────────────────────────────────────────────

#: A library verdict whose text holds one of these was a refusal of the policy, not a rule that failed.
_ABWEISUNG = ("this check does not apply", "rejected before evaluation", "is not a JSON object")


def _cli(argv: "list[str]") -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = main(argv)
    return {0: "PASS", 1: "FAIL", 3: "FAIL", 2: "ABGEWIESEN"}.get(rc, f"rc {rc}")


def _urteil_bib(ergebnis: dict, *, ok_feld: bool = True) -> str:
    text = json.dumps(ergebnis, default=str)
    if any(m in text for m in _ABWEISUNG):
        return "ABGEWIESEN"
    werte = [ergebnis.get("policy_ok")] + ([ergebnis.get("ok")] if ok_feld else [])
    if any(w is False for w in werte):
        return "FAIL"
    if ergebnis.get("policy_ok") is True and all(w is not False for w in werte):
        return "PASS"
    return f"kein Urteil {werte}"


class _Flaechen:
    """The surfaces of each path. `welt` names the receipt; `beilage` is what a case attaches: `--with-related` names
    for the CLI and `related=` for the library (`zu`), anchors (`anker`: "ok" or "wartet"), extra CLI flags."""

    def __init__(self, w: _Welt) -> None:
        self.w = w

    def messe(self, flaeche: str, welt: str, regeln: dict, beilage: dict) -> str:
        w = self.w
        politik = _politik(regeln)
        zu = beilage.get("zu", ())
        anker = beilage.get("anker")
        flaggen = list(beilage.get("flaggen", ()))
        mit = [x for n in zu for x in ("--with-related", w.dateien[n])]
        pol = ["--policy", w.politik_datei(politik)]
        if flaeche == "cli verify":
            return _cli(["verify", w.dateien[welt]] + flaggen + pol)
        if flaeche in ("cli decision verify", "cli decision verify --anchors"):
            a = ["--anchors", w.dateien[f"{welt}.anker_{anker or 'ok'}"]] if flaeche.endswith("--anchors") else []
            return _cli(["decision", "verify", w.dateien[welt], "--pub", w.pub] + a + mit + flaggen + pol)
        if flaeche == "cli outcome verify":
            return _cli(["outcome", "verify", w.dateien[welt], "--pub", w.pub] + mit + pol)
        if flaeche == "cli relation-statement verify":
            return _cli(["relation-statement", "verify", w.dateien[welt], "--pub", w.pub] + mit + pol)
        roh = _HAUPT.public_key().public_bytes_raw()
        related = self._related(zu)
        if flaeche == "evaluate_policy":
            from proofbundle.bundle import verify_bundle
            from proofbundle.policy import evaluate_policy
            b = w.objekte[welt]
            return _urteil_bib(evaluate_policy(b, verify_bundle(b), politik), ok_feld=False)
        if flaeche == "evaluate_decision_policy":
            from proofbundle.policy import evaluate_decision_policy
            aussage = json.loads(base64.b64decode(w.objekte[welt]["payload"]))
            status = {"ok": "PASS", "wartet": "WARN"}.get(anker or "")
            return _urteil_bib(evaluate_decision_policy(aussage, {"ok": True}, politik, signer_public_key_b64=w.pub,
                                                        anchor_status=status), ok_feld=False)
        if flaeche == "verify_decision_receipt":
            from proofbundle.decision import verify_decision_receipt
            a = w.objekte[f"{welt}.anker_{anker}"] if anker else None
            return _urteil_bib(verify_decision_receipt(w.objekte[welt], roh, policy=politik, anchors=a,
                                                       related=related))
        if flaeche == "verify_outcome_receipt":
            from proofbundle.outcome import verify_outcome_receipt
            return _urteil_bib(verify_outcome_receipt(w.objekte[welt], roh, policy=politik, related=related))
        if flaeche == "verify_relation_statement":
            from proofbundle.relation_statement import verify_relation_statement
            return _urteil_bib(verify_relation_statement(w.objekte[welt], roh, policy=politik, related=related))
        raise AssertionError(f"unknown surface {flaeche}")

    def _related(self, zu) -> "dict | None":
        """The library form of the CLI's `--with-related` files: each attached receipt keyed by its content root."""
        w = self.w
        if not zu:
            return None
        karte = {}
        for n in zu:
            if n == "parent":
                karte[w.parent_root] = w.eintrag(w.parent_root)
            else:
                praed = json.loads(base64.b64decode(w.objekte[n]["payload"]))["predicate"]
                karte[w.aussage_wurzel[n]] = w.eintrag(w.aussage_wurzel[n], praed.get("relationships"))
        return karte


_FLAECHEN = {"verify": ("cli verify",), "evaluate_policy": ("evaluate_policy",),
             "decision verify": ("cli decision verify",),
             "decision verify --anchors": ("cli decision verify --anchors",),
             "verify_decision_receipt": ("verify_decision_receipt",),
             "evaluate_decision_policy": ("evaluate_decision_policy",),
             "outcome": ("cli outcome verify", "verify_outcome_receipt"),
             "relation_statement": ("cli relation-statement verify", "verify_relation_statement")}
_FAMILIE = {"verify": "eval", "evaluate_policy": "eval", "decision verify": "decision",
            "decision verify --anchors": "decision", "verify_decision_receipt": "decision",
            "evaluate_decision_policy": "decision", "outcome": "outcome", "relation_statement": "statement"}
_ZWECK = {"eval": "eval", "decision": "decision", "outcome": "outcome", "statement": None}


# ── the cases ───────────────────────────────────────────────────────────────────────────────────────────────


class _Fall:
    """`ohne` is the policy without the rule, `wert` the rule's value, `richtung` the verdict the rule turns the
    path to ("FAIL" for a requirement, "PASS" for a permission or trust input). `erfuellt`, where given, is a value
    of the rule under which the same world passes: the control that the rule is not a failure of its own."""

    def __init__(self, welt: str, ohne: dict, wert: Any, *, richtung: str = "FAIL", beilage: "dict | None" = None,
                 erfuellt: Any = None, welt_erfuellt: "str | None" = None,
                 beilage_erfuellt: "dict | None" = None) -> None:
        self.welt, self.ohne, self.wert, self.richtung = welt, ohne, wert, richtung
        self.beilage = beilage or {}
        self.erfuellt, self.welt_erfuellt = erfuellt, welt_erfuellt
        self.beilage_erfuellt = self.beilage if beilage_erfuellt is None else beilage_erfuellt


_KEIN = object()


def _faelle(w: _Welt, pfad: str, regel: tuple) -> "list[_Fall]":
    """The cases that turn `pfad`'s verdict with `regel` alone. Empty: no case is known, which the completeness test
    reports unless the pair stands in `_OHNE_EIGENE_WIRKUNG`."""
    familie = _FAMILIE[pfad]
    a, k = regel
    if familie == "eval":
        # The passing rule beside the one measured: every bundle here is signed with ed25519, whoever signed it.
        issuer = {("signature", "allowed_algs"): ["ed25519"]}
        issuer_sd = issuer
        schema = {(None, "allowed_schema_versions"): [w.b0_schema]}
        anforderung = {**issuer, ("anchors", "require_anchor"): "any"}
        tabelle = {
            (None, "allowed_schema_versions"): [_Fall("b0", issuer, ["proofbundle/v9"], erfuellt=[w.b0_schema])],
            (None, "allowed_issuers"): [_Fall("b0", schema, [{"public_key_b64": _b64(_FREMD)}],
                                              erfuellt=[{"public_key_b64": w.pub}])],
            ("signature", "allowed_algs"): [_Fall("b0", schema, ["es256"], erfuellt=["ed25519"])],
            ("signature", "require_expected_signer"): [_Fall("b0", schema, True)],
            ("merkle", "required_hash_alg"): [_Fall("b0", issuer, "sha512-other", erfuellt=w.b0_hash_alg)],
            ("merkle", "require_authenticated_root"): [_Fall("b0", issuer, True)],
            ("merkle", "trusted_roots"): [_Fall("b0", issuer, [_b64b(b"\x07" * 32)], erfuellt=[_b64b(w.b0_root)])],
            ("merkle", "trusted_checkpoints"): [_Fall("b0", issuer, [w.cp_fremd], erfuellt=[w.cp_passend])],
            ("sd_jwt", "expected_aud"): [_Fall("sd", issuer_sd, "rp.example", erfuellt="verifier.example")],
            ("sd_jwt", "require_nonce"): [_Fall("b0", issuer, True, erfuellt=True, welt_erfuellt="sd")],
            ("sd_jwt", "max_iat_age_seconds"): [_Fall("sd", issuer_sd, 1, erfuellt=10 ** 9)],
            ("sd_jwt", "expected_vct"): [_Fall("sd", issuer_sd, "urn:other:vct", erfuellt=w.vct)],
            ("status", "reject_self_issued"): [_Fall("b0", issuer, True)],
            ("status", "allowed_status_authorities"): [_Fall("b0", issuer, ["https://status.example"])],
            ("assurance", "minimum_level"): [_Fall("sd", issuer_sd, "enclave_attested", erfuellt="self_attested")],
            ("assurance", "reject_self_attested_without_prereg"): [
                _Fall("sa", issuer, True, erfuellt=True, welt_erfuellt="sd")],
            ("anchors", "require_anchor"): [_Fall("b0", issuer, "any", erfuellt="any", welt_erfuellt="anker_ok")],
            ("anchors", "require_anchor_target"): [
                _Fall("b0", issuer, "preRegistration", erfuellt="preRegistration", welt_erfuellt="anker_ok")],
            ("anchors", "allow_pending"): [_Fall("anker_wartet", anforderung, True, richtung="PASS")],
            ("anchors", "trusted_tsa_roots"): [
                _Fall("anker_trusted_tsa_roots", anforderung, ["QUJD"], richtung="PASS")],
            ("anchors", "bitcoin_block_headers"): [
                _Fall("anker_bitcoin_block_headers", anforderung, {"850000": "ab" * 32}, richtung="PASS")],
            ("anchors", "trusted_tsa_policy_oids"): [
                _Fall("anker_trusted_tsa_policy_oids", anforderung, ["1.2.3"], richtung="PASS")],
        }
        # At the CLI the audience is bound by `verify_bundle(expected_aud=...)`: a KB-JWT for another audience fails
        # the crypto verdict (exit 1), which is the rule's effect on that path; in the library it is step 5a.
        return tabelle.get(regel, []) + _gemeinsam(regel, issuer, "b0", familie)
    if familie == "decision":
        tdm = {("decision_receipt", "trusted_decision_makers"): [{"public_key_b64": w.pub}]}
        verdikt = {("decision_receipt", "allowed_verdicts"): ["DENY"]}
        beilage = {"anker": "ok"} if pfad in ("decision verify --anchors", "verify_decision_receipt",
                                               "evaluate_decision_policy") else {}
        anforderung = {**tdm, ("decision_receipt", "require_external_anchor"): True}
        tabelle = {
            ("decision_receipt", "trusted_decision_makers"): [
                _Fall("d", verdikt, [{"public_key_b64": _b64(_FREMD)}], erfuellt=[{"public_key_b64": w.pub}],
                      beilage=beilage)],
            ("decision_receipt", "allowed_decision_types"): [
                _Fall("d", tdm, ["postHocReview"], erfuellt=["preActionAuthorization"], beilage=beilage)],
            ("decision_receipt", "allowed_verdicts"): [_Fall("d", tdm, ["ALLOW"], erfuellt=["DENY"], beilage=beilage)],
            ("decision_receipt", "required_evidence_relations"): [
                _Fall("d", tdm, ["never-present"], erfuellt=["evalResult"], beilage=beilage)],
            ("decision_receipt", "accepted_predicate_types"): [
                _Fall("d", tdm, ["https://example.org/other"], erfuellt=[w.d_typ], beilage=beilage)],
            ("decision_receipt", "require_policy_digest"): [
                _Fall("d_ohne_digest", tdm, True, erfuellt=True, welt_erfuellt="d", beilage=beilage)],
            ("decision_receipt", "require_audience"): [
                _Fall("d_ohne_audience", tdm, True, erfuellt=True, welt_erfuellt="d", beilage=beilage)],
            ("decision_receipt", "require_nonce"): [
                _Fall("d_ohne_nonce", tdm, True, erfuellt=True, welt_erfuellt="d", beilage=beilage)],
            ("decision_receipt", "require_not_checked"): [
                _Fall("d_ohne_not_checked", tdm, True, erfuellt=True, welt_erfuellt="d", beilage=beilage)],
            ("decision_receipt", "require_decision_change_conditions"): [
                _Fall("d_ohne_dcc", tdm, True, erfuellt=True, welt_erfuellt="d", beilage=beilage)],
            ("decision_receipt", "require_trace_context"): [
                _Fall("d", tdm, True, erfuellt=True, welt_erfuellt="d_mit_spur", beilage=beilage)],
            ("decision_receipt", "allow_raw_inputs"): [_Fall("d_roh", tdm, True, richtung="PASS", beilage=beilage)],
            ("decision_receipt", "require_external_anchor"): [
                _Fall("d", tdm, True, beilage=dict(beilage, anker="wartet") if beilage else {})],
            ("decision_receipt", "allow_pending"): (
                [_Fall("d", anforderung, True, richtung="PASS", beilage={"anker": "wartet"})] if beilage else []),
            ("anchors", "trusted_tsa_roots"): [],
            ("anchors", "bitcoin_block_headers"): [],
            ("anchors", "trusted_tsa_policy_oids"): [],
        }
        if pfad == "decision verify --anchors":
            # The trust inputs beside `--anchors`: an anchor of the test type that verifies only with that trust.
            for schluessel, wert in (("trusted_tsa_roots", ["QUJD"]), ("bitcoin_block_headers", {"850000": "ab" * 32}),
                                     ("trusted_tsa_policy_oids", ["1.2.3"])):
                tabelle[("anchors", schluessel)] = [
                    _Fall("d", tdm, wert, richtung="PASS", beilage={"anker": f"vertraut_{schluessel}"})]
        if pfad != "evaluate_decision_policy":
            tabelle.update(_relationen(w, "d_kind", "d", "r_d", tdm, beilage))
        return tabelle.get(regel, []) + _gemeinsam(regel, tdm, "d", familie, beilage)
    if familie == "outcome":
        basis = {("relations", "relation_signer"): {"derivedFrom": {"mode": "pinned", "keys": [w.pub]}}}
        return _relationen(w, "o_kind", "parent", "r_parent", basis, {}).get(regel, []) + \
            _gemeinsam(regel, basis, "o_kind", familie)
    basis = {("relations", "relation_signer"): {"derivedFrom": {"mode": "pinned", "keys": [w.pub]}}}
    tabelle = _relationen(w, "s_kind", None, None, basis, {})
    # The statement's own verified edge (SPEC 2.5): it supersedes or retracts the attached parent. Beside a rule
    # that passes; these statements carry no derivedFrom edge, so that pin holds without an edge to judge.
    tabelle[("relations", "reject_superseded")] = [_Fall("s_ersetzt", basis, True, beilage={"zu": ("parent",)})]
    tabelle[("relations", "reject_retracted")] = [_Fall("s_zieht_zurueck", basis, True, beilage={"zu": ("parent",)})]
    return tabelle.get(regel, []) + _gemeinsam(regel, basis, "s_kind", familie)


def _relationen(w: _Welt, kind: str, subjekt: "str | None", ruecknahme: "str | None", basis: dict,
                beilage: dict) -> dict:
    """The four relations rules of the decision and outcome paths, and three of the statement path. `kind` derives
    from the parent with a derivedFrom edge; `subjekt` is a receipt that `ruecknahme` retracts (reject_superseded)."""
    pin_fremd = {"derivedFrom": {"mode": "pinned", "keys": [_b64(_FREMD)]}}
    pin_eigen = {"derivedFrom": {"mode": "pinned", "keys": [w.pub]}}
    # The passing rule beside relation_signer: the family's own (the decision verifier gives policy_ok None, not
    # True, for a policy without a decision_receipt section) and the target pin, never the signer rule itself.
    ziel_basis = {**{r: v for r, v in basis.items() if r != ("relations", "relation_signer")},
                  ("relations", "require_relation_target"): {"derivedFrom": w.parent_root}}
    t = {
        # Declared only: the edge's target is not attached, so it does not resolve. Attached, it does.
        ("relations", "require_relation_resolution"): [
            _Fall(kind, basis, ["derivedFrom"], beilage=beilage, erfuellt=["derivedFrom"],
                  beilage_erfuellt=dict(beilage, zu=("parent",)))],
        ("relations", "relation_signer"): [
            _Fall(kind, ziel_basis, pin_fremd, erfuellt=pin_eigen, beilage=beilage)],
        ("relations", "require_relation_target"): [
            _Fall(kind, basis, {"derivedFrom": "f" * 64}, erfuellt={"derivedFrom": w.parent_root}, beilage=beilage)],
    }
    if subjekt is not None:
        t[("relations", "reject_superseded")] = [_Fall(subjekt, basis, True, beilage=dict(beilage, zu=(ruecknahme,)))]
    return t


def _gemeinsam(regel: tuple, basis: dict, welt: str, familie: str, beilage: "dict | None" = None) -> "list[_Fall]":
    zweck = _ZWECK[familie]
    tabelle = {
        (None, "valid_until"): [_Fall(welt, basis, _VERGANGEN, erfuellt=_ZUKUNFT, beilage=beilage)],
        (None, "valid_from"): [_Fall(welt, basis, _ZUKUNFT, erfuellt=_VERGANGEN, beilage=beilage)],
        (None, "policyPurpose"): [_Fall(welt, basis, "trust-pack", erfuellt=zweck if zweck else _KEIN,
                                        beilage=beilage)],
        (None, "requiresIdentityOverlay"): [_Fall(welt, basis, True, beilage=beilage)],
    }
    return tabelle.get(regel, [])


#: Pairs that cannot turn their path's verdict on their own, with the reason. Each reason is measured in
#: `test_a_pair_without_an_effect_of_its_own_is_subsumed_as_stated`.
_OHNE_EIGENE_WIRKUNG = {
    ("verify", ("sd_jwt", "require_key_binding_when_cnf_present")):
        "subsumed by the crypto verdict: every state in which the rule would fail (a KB-JWT not verified, a cnf "
        "without a KB-JWT) already fails `verify_bundle`, exit 1, with or without the rule",
    ("evaluate_policy", ("sd_jwt", "require_key_binding_when_cnf_present")):
        "subsumed by the crypto verdict for a result of `verify_bundle`; measured with a caller-built result that "
        "names no key binding check, where the rule alone fails the policy (`test_the_key_binding_rule_acts_on_a_"
        "caller_built_result`)",
    ("decision verify", ("decision_receipt", "allow_pending")):
        "without `--anchors` no anchor is checked, so `require_external_anchor` fails and the permission has nothing "
        "to relax: exit 3 with and without it (fail-closed); beside `--anchors` it is measured",
    ("verify", ("sd_jwt", "issuer_key_pin")):
        "qualifies sd_jwt.expected_vct only (Nachtrag 32, the Critical): the pin is read solely inside the "
        "expected_vct check, to decide whether the attacker-chosen SD-JWT issuer key may be trusted. Set without "
        "expected_vct it changes no verdict; beside expected_vct its effect (a wrong-key pin fails, a matching pin "
        "passes) is measured in tests/test_security_fix_620_n32.py",
    ("evaluate_policy", ("sd_jwt", "issuer_key_pin")):
        "same as the verify path: the pin is consulted only by the expected_vct check, so it flips no verdict on "
        "its own; its effect beside expected_vct is measured in tests/test_security_fix_620_n32.py",
}


# ── the tests ───────────────────────────────────────────────────────────────────────────────────────────────


class EveryAppliedRuleHasAnObservableEffect(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._gesichert = dict(_anker_modul._VERIFIERS)
        _anker_modul.register_anchor_type(_TYP_OK, _bestaetigt)
        _anker_modul.register_anchor_type(_TYP_WARTET, _wartend)
        for schluessel, typ in _TYP_VERTRAUT.items():
            _anker_modul.register_anchor_type(typ, _vertraut_von(schluessel))
        cls._td = tempfile.TemporaryDirectory(prefix="pb_rule_effect_")
        cls.w = _Welt(cls._td.name)
        for schluessel, typ in _TYP_VERTRAUT.items():
            cls.w._lege(f"d.anker_vertraut_{schluessel}", [_anker(typ, cls.w.wurzel["d"], "statement")])
        cls.f = _Flaechen(cls.w)

    @classmethod
    def tearDownClass(cls) -> None:
        _anker_modul._VERIFIERS.clear()
        _anker_modul._VERIFIERS.update(cls._gesichert)
        cls._td.cleanup()

    def _paare(self):
        for pfad in sorted(ANGEWANDTE_REGELN):
            for regel in sorted(ANGEWANDTE_REGELN[pfad], key=str):
                yield pfad, regel

    def test_every_pair_of_the_contract_has_a_case_or_a_measured_reason(self) -> None:
        ohne_fall = [f"{p}: {r}" for p, r in self._paare()
                     if not _faelle(self.w, p, r) and (p, r) not in _OHNE_EIGENE_WIRKUNG]
        self.assertEqual(ohne_fall, [], f"{len(ohne_fall)} pairs of ANGEWANDTE_REGELN have no effect case")
        fremd = [k for k in _OHNE_EIGENE_WIRKUNG if k[1] not in ANGEWANDTE_REGELN.get(k[0], ())]
        self.assertEqual(fremd, [], "a reason names a pair the contract does not hold")
        doppelt = [k for k in _OHNE_EIGENE_WIRKUNG if _faelle(self.w, *k)]
        self.assertEqual(doppelt, [], "a pair has an effect case and a reason why it has none")

    def test_the_cases_are_not_vacuous(self) -> None:
        """Every case adds exactly its rule, and the contract the generator walks is not empty or thin."""
        zahl = 0
        for pfad, regel in self._paare():
            for fall in _faelle(self.w, pfad, regel):
                zahl += 1
                self.assertNotIn(regel, fall.ohne, f"{pfad} {regel}: the policy without the rule holds it")
                self.assertIn(fall.richtung, ("FAIL", "PASS"))
        # The counts when this file was added: 152 pairs, 149 with a case, 3 with a measured reason.
        self.assertGreaterEqual(zahl, 149, "the generator walks fewer cases than when it was added")
        self.assertGreaterEqual(sum(len(v) for v in ANGEWANDTE_REGELN.values()), 152)

    def test_every_applied_rule_turns_the_verdict_of_its_path(self) -> None:
        befunde = []
        gemessen = 0
        for pfad, regel in self._paare():
            for fall in _faelle(self.w, pfad, regel):
                gegen = "PASS" if fall.richtung == "FAIL" else "FAIL"
                mit = {**fall.ohne, regel: fall.wert}
                for flaeche in _FLAECHEN[pfad]:
                    gemessen += 1
                    vorher = self.f.messe(flaeche, fall.welt, fall.ohne, fall.beilage)
                    nachher = self.f.messe(flaeche, fall.welt, mit, fall.beilage)
                    if (vorher, nachher) != (gegen, fall.richtung):
                        befunde.append(f"{flaeche} [{pfad}] {regel} in {fall.welt}: without {vorher}, with "
                                       f"{nachher}, expected {gegen} -> {fall.richtung}")
                    if fall.erfuellt is not None and fall.erfuellt is not _KEIN:
                        welt = fall.welt_erfuellt or fall.welt
                        erfuellt = self.f.messe(flaeche, welt, {**fall.ohne, regel: fall.erfuellt},
                                                fall.beilage_erfuellt)
                        if erfuellt != "PASS":
                            befunde.append(f"{flaeche} [{pfad}] {regel} = {fall.erfuellt!r} in {welt}: {erfuellt}, "
                                           "expected PASS (the control: the rule can be met)")
        self.assertGreaterEqual(gemessen, 166)
        self.assertEqual(befunde, [], f"{len(befunde)} of {gemessen} measurements:\n" + "\n".join(befunde))

    def test_a_pair_without_an_effect_of_its_own_is_subsumed_as_stated(self) -> None:
        import test_kbjwt as kb
        from proofbundle.evalclaim import emit_eval_receipt
        from proofbundle.kbjwt import split_key_binding
        w = self.w
        presented, issuer, _ = kb._issue_presented()
        pub = base64.b64encode(kb._raw_pub(issuer)).decode("ascii")
        sd_ohne_kb, _ = split_key_binding(presented)
        regel = ("sd_jwt", "require_key_binding_when_cnf_present")
        befunde = []
        for name, sd in (("KB-JWT without the issuer key", {"compact": presented}),
                         ("cnf without a KB-JWT", {"compact": sd_ohne_kb, "issuer_public_key_b64": pub})):
            w._lege("kb_fall", emit_eval_receipt(kb._EV_CLAIM, issuer, sd_jwt=sd))
            basis = {(None, "allowed_issuers"): [{"public_key_b64": pub}]}
            urteile = (_cli(["verify", w.dateien["kb_fall"], "--policy", w.politik_datei(_politik(basis))]),
                       _cli(["verify", w.dateien["kb_fall"], "--policy",
                             w.politik_datei(_politik({**basis, regel: True}))]))
            if urteile != ("FAIL", "FAIL"):
                befunde.append(f"verify, {name}: without and with the rule {urteile}, expected FAIL both (exit 1)")
        anforderung = {("decision_receipt", "trusted_decision_makers"): [{"public_key_b64": w.pub}],
                       ("decision_receipt", "require_external_anchor"): True}
        urteile = tuple(self.f.messe("cli decision verify", "d", r, {}) for r in
                        (anforderung, {**anforderung, ("decision_receipt", "allow_pending"): True}))
        if urteile != ("FAIL", "FAIL"):
            befunde.append(f"decision verify: require_external_anchor without and with allow_pending {urteile}")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_the_key_binding_rule_acts_on_a_caller_built_result(self) -> None:
        """`evaluate_policy` takes the crypto result from its caller. A result that passes but names no key binding
        check, over a bundle that carries a KB-JWT, is judged by the rule: it fails the policy, and without the rule
        the same call passes."""
        import test_kbjwt as kb
        from proofbundle.errors import Check, VerificationResult
        from proofbundle.evalclaim import emit_eval_receipt
        from proofbundle.policy import evaluate_policy
        import hashlib  # noqa: PLC0415
        presented, issuer, _ = kb._issue_presented()
        pub = base64.b64encode(kb._raw_pub(issuer)).decode("ascii")
        b = emit_eval_receipt(kb._EV_CLAIM, issuer, sd_jwt={"compact": presented})
        ergebnis = VerificationResult(checks=[Check("signature", True, "caller-built")])
        # Nachtrag 46 (F2): evaluate_policy now requires the result to be bound to the bundle it judges. This
        # caller-built result stands in for a verify_bundle result of exactly this bundle, so it carries the
        # signer and payload digest of `b`; the rule's observable effect (PASS without, FAIL with) is unchanged.
        # Nachtrag 46b: evaluate_policy also requires an authentic origin token; the stand-in stamps it over its
        # own fields, as a verify_bundle result of this bundle would carry one.
        ergebnis.verified_signer_pub = base64.b64decode(b["signature"]["public_key_b64"])
        ergebnis.verified_payload_digest = hashlib.sha256(base64.b64decode(b["payload_b64"])).hexdigest()
        ergebnis.stamp_origin()
        basis = {(None, "allowed_issuers"): [{"public_key_b64": pub}]}
        regel = ("sd_jwt", "require_key_binding_when_cnf_present")
        ohne = _urteil_bib(evaluate_policy(b, ergebnis, _politik(basis)), ok_feld=False)
        mit = _urteil_bib(evaluate_policy(b, ergebnis, _politik({**basis, regel: True})), ok_feld=False)
        self.assertEqual((ohne, mit), ("PASS", "FAIL"))

    def test_the_audience_control_passes_and_the_p1_case_fails_in_the_library(self) -> None:
        """The P1 itself, named: `evaluate_policy` over `verify_bundle(bundle)` without an audience, the KB-JWT bound
        to verifier.example. The policy's expected_aud rp.example fails it; verifier.example passes it."""
        from proofbundle.bundle import verify_bundle
        from proofbundle.policy import evaluate_policy
        b = self.w.objekte["sd"]
        basis = {(None, "allowed_issuers"): [{"public_key_b64": self.w.sd_pub}]}
        urteile = {aud: evaluate_policy(b, verify_bundle(b), _politik({**basis, ("sd_jwt", "expected_aud"): aud}))
                   for aud in ("rp.example", "verifier.example")}
        self.assertIs(urteile["rp.example"]["policy_ok"], False)
        self.assertIs(urteile["verifier.example"]["policy_ok"], True)


if __name__ == "__main__":
    unittest.main()
