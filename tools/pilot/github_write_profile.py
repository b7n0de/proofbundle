#!/usr/bin/env python3
"""The pilot profile `github-write/1`: an approved agent write, and what GitHub shows of it.

A profile over the two predicates as they ship, not a new predicate and no new field. The outbound
gate's verdict is a `decision-receipt/v0.1`; what an observer reads from the GitHub API after the write
is an `action-outcome/v0.1` bound to it. This module builds both for the pilot's vectors and decides,
for one decision and at most one outcome, whether the approved action arrived as approved.

Where each aspect lives (docs/pilot/pilot_profile.md has the full table):

  byte identity   proposedAction.parametersDigest = SHA-256 of the approved bytes;
                  outcome requestedActionDigest must equal it, outcome effectDigest = SHA-256 of the bytes
                  GitHub stores
  subject         the decision Statement's subject is derived from its predicate (checked); the outcome
                  is bound to the decision's content root (decisionRef)
  issuer role     the decision is signed by the pinned gate key and names the gate as decisionMaker; the
                  outcome is signed by the pinned observer key; executor.id is the account GitHub reports
  policy digest   policyBoundary.policyDigest (required in strict mode)
  action id,      decisionId = "<action id>#<attempt>"; the attempt nonce is validity.nonce of both
  attempt         receipts
  freshness       validity.expiresAt of the decision; the effect's performedAt (GitHub's time) must lie in
                  [decidedAt, expiresAt]
  outcome scope   actualActionDigest = SHA-256 of the RFC 8785 form of the observed scope descriptor
                  {surface, target, objectId}, which travels beside the outcome and must match it
  version signal  policyBoundary.policyEngine = PROFILE_ENGINE and bundleRevision = PROFILE_REVISION; a
                  receipt without them is not read under this profile

The answer is one of three: `accepted` (approved, arrived with the approved bytes, on the approved
surface and target, in time), `not accepted` (a check failed, or the gate refused), `unknown`
(something the answer needs is missing). Missing and unknown never become `accepted`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt

PROFILE_ENGINE = "proofbundle-pilot/github-write"
PROFILE_REVISION = "1"
SURFACES = ("github.conversationComment", "github.reviewThreadReply", "github.pullRequestBody", "git.push",
            "github.merge")
ACCEPTED, NOT_ACCEPTED, UNKNOWN = "accepted", "not accepted", "unknown"
_DECISION_ID = re.compile(r"^(?P<action>[A-Za-z0-9:._-]+)#(?P<attempt>[1-9][0-9]*)$")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scope_descriptor(surface: str, target: str, object_id: str) -> dict:
    """What the observer saw: the surface, the target URI and GitHub's id of the object."""
    return {"surface": surface, "target": target, "objectId": object_id}


def scope_digest(descriptor: dict) -> str:
    return sha256_hex(rfc8785.dumps(descriptor))


def content_root(envelope: dict) -> str:
    """SHA-256 over the exact signed payload bytes: the content root a decisionRef names."""
    return sha256_hex(base64.b64decode(envelope["payload"], validate=True))


def _statement(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"], validate=True))


def decision_predicate(*, action_id: str, attempt: int, decided_at: str, expires_at: str | None, surface: str,
                       target: str, approved: bytes, verdict: str, reasons: list, gate_id: str, agent_id: str,
                       principal_id: str, policy_digest: str, nonce: str, audience: str,
                       engine: str = PROFILE_ENGINE, revision: str = PROFILE_REVISION) -> dict:
    validity = {"audience": [audience], "nonce": nonce}
    if expires_at is not None:
        validity["expiresAt"] = expires_at
    return {
        "schemaVersion": "0.1.0", "decisionId": f"{action_id}#{attempt}", "decisionType": "preActionAuthorization",
        "decidedAt": decided_at, "decisionMaker": {"id": gate_id}, "agent": {"id": agent_id},
        "principal": {"id": principal_id},
        "proposedAction": {"actionType": surface, "target": {"name": target, "uri": target}, "method": "write",
                           "parametersDigest": {"sha256": sha256_hex(approved)}},
        "inputSnapshot": [{"name": "approved bytes", "digest": {"sha256": sha256_hex(approved)},
                           "mediaType": "text/markdown"}],
        "policyBoundary": {"policyEngine": engine, "policyId": "outbound-gate-rules",
                           "decisionPath": "outbound-gate/allow-write", "policyDigest": {"sha256": policy_digest},
                           **({"bundleRevision": revision} if revision is not None else {})},
        "evidenceRefs": [],
        "decision": {"verdict": verdict, "reasonCodes": reasons},
        "notChecked": [{"field": "content", "reason": "the gate does not judge whether the text is true",
                        "impact": "an approved text can be wrong"}],
        "decisionChangeConditions": [{"conditionType": "ruleChange",
                                      "description": "a changed closing rule for the surface"}],
        "privacy": {"rawInputsIncluded": False},
        "validity": validity,
    }


def outcome_predicate(*, outcome_id: str, decision_root: str, executor_id: str, approved: bytes,
                      performed_at: str, recorded_at: str, stored: bytes | None, scope: dict | None, nonce: str,
                      audience: str) -> dict:
    pred = {
        "schemaVersion": "0.1.0", "outcomeId": outcome_id, "decisionRef": {"sha256": decision_root},
        "executor": {"id": executor_id}, "requestedActionDigest": {"sha256": sha256_hex(approved)},
        "status": "executed", "performedAt": performed_at, "recordedAt": recorded_at,
        "limitations": ["read from the GitHub API at recordedAt; a later edit or deletion is not covered",
                        "the signer is the observer; executor.id is the account GitHub reports, not a key"],
        "validity": {"audience": [audience], "nonce": nonce},
    }
    if stored is not None:
        pred["effectDigest"] = {"sha256": sha256_hex(stored)}
    if scope is not None:
        pred["actualActionDigest"] = {"sha256": scope_digest(scope)}
    return pred


def sign_decision(predicate: dict, key: Ed25519PrivateKey) -> dict:
    return emit_decision_receipt(predicate, key, strict=True)


def sign_outcome(predicate: dict, key: Ed25519PrivateKey) -> dict:
    return emit_outcome_receipt(predicate, key, strict=True)


def _answer(verdict: str, reasons: list, checks: dict) -> dict:
    return {"verdict": verdict, "reasons": reasons, "checks": checks}


def reconcile(decision_env: dict, outcome_env: dict | None, observed_scope: dict | None, *, gate_key: bytes,
              gate_id: str, observer_key: bytes, observer_id: str) -> dict:
    """One decision and at most one outcome, read under github-write/1. Never raises on bad input."""
    checks: dict = {}
    try:
        return _reconcile(decision_env, outcome_env, observed_scope, gate_key, gate_id, observer_key,
                          observer_id, checks)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return _answer(UNKNOWN, [f"the input is not in the profile's shape ({type(exc).__name__})"], checks)


def _reconcile(decision_env, outcome_env, observed_scope, gate_key, gate_id, observer_key, observer_id,
               checks) -> dict:
    stmt = _statement(decision_env)
    pred = stmt["predicate"]
    boundary = pred.get("policyBoundary") or {}
    checks["version_signal"] = (boundary.get("policyEngine"), boundary.get("bundleRevision")) == (
        PROFILE_ENGINE, PROFILE_REVISION)
    if not checks["version_signal"]:
        return _answer(UNKNOWN, ["the decision carries no version signal of github-write/1; it is not read "
                                 "under this profile"], checks)
    d = verify_decision_receipt(decision_env, gate_key, strict=True, expected_audience=observer_id,
                                expected_nonce=(pred.get("validity") or {}).get("nonce"),
                                require_derived_subject=True)
    checks["decision_signed_by_gate_key"] = d["crypto_ok"]
    if not d["crypto_ok"]:
        return _answer(NOT_ACCEPTED, ["the decision is not signed by the pinned gate key"], checks)
    checks["decision_ok"] = d["ok"]
    if not d["ok"]:
        return _answer(NOT_ACCEPTED, ["the decision does not verify: " + "; ".join(d["errors"])], checks)
    checks["decision_maker_is_gate"] = pred["decisionMaker"]["id"] == gate_id
    if not checks["decision_maker_is_gate"]:
        return _answer(NOT_ACCEPTED, ["the decision names another decision maker than the pinned gate"], checks)
    kennung = _DECISION_ID.match(pred["decisionId"])
    checks["action_id"] = kennung.group("action") if kennung else None
    checks["attempt"] = int(kennung.group("attempt")) if kennung else None
    if not kennung:
        return _answer(UNKNOWN, ["decisionId is not <action id>#<attempt>"], checks)
    if pred["proposedAction"]["actionType"] not in SURFACES:
        return _answer(UNKNOWN, ["the approved surface is not one this profile knows"], checks)
    expires = pred["validity"].get("expiresAt")
    verdict = pred["decision"]["verdict"]
    checks["gate_verdict"] = verdict
    if outcome_env is None:
        if verdict == "ALLOW":
            return _answer(UNKNOWN, ["approved, and no effect was observed"], checks)
        return _answer(NOT_ACCEPTED, [f"the gate's verdict is {verdict}, and no effect was observed"], checks)
    o = verify_outcome_receipt(outcome_env, observer_key, strict=True, expected_decision_ref=content_root(decision_env),
                               decision_maker_id=gate_id, expected_audience=observer_id,
                               expected_nonce=pred["validity"]["nonce"], require_derived_subject=True)
    checks["outcome_signed_by_observer_key"] = o["crypto_ok"]
    if not o["crypto_ok"]:
        return _answer(NOT_ACCEPTED, ["the outcome is not signed by the pinned observer key"], checks)
    checks["outcome_bound_to_this_decision"] = o["decision_bound"]
    if o["decision_bound"] is not True:
        return _answer(NOT_ACCEPTED, ["the outcome is bound to another decision"], checks)
    checks["outcome_ok"] = o["ok"]
    if not o["ok"]:
        return _answer(NOT_ACCEPTED, ["the outcome does not verify: " + "; ".join(o["errors"])], checks)
    if verdict != "ALLOW":
        return _answer(NOT_ACCEPTED, [f"the gate's verdict is {verdict}, and an effect arrived"], checks)
    opred = _statement(outcome_env)["predicate"]
    approved = pred["proposedAction"]["parametersDigest"]["sha256"]
    checks["requested_is_approved"] = opred["requestedActionDigest"]["sha256"] == approved
    if not checks["requested_is_approved"]:
        return _answer(NOT_ACCEPTED, ["the outcome names other requested bytes than the approved ones"], checks)
    checks["execution_proven"] = o["execution_proven"]
    if o["execution_proven"] is not True or "effectDigest" not in opred:
        return _answer(UNKNOWN, ["the outcome carries no digest of the stored bytes"], checks)
    checks["bytes_identical"] = opred["effectDigest"]["sha256"] == approved
    if observed_scope is None or "actualActionDigest" not in opred:
        return _answer(UNKNOWN, ["no observed scope"], checks)
    checks["scope_matches_signed_digest"] = scope_digest(observed_scope) == opred["actualActionDigest"]["sha256"]
    if not checks["scope_matches_signed_digest"]:
        return _answer(NOT_ACCEPTED, ["the observed scope descriptor is not the one the observer signed"], checks)
    checks["surface_is_approved"] = observed_scope["surface"] == pred["proposedAction"]["actionType"]
    checks["target_is_approved"] = observed_scope["target"] == pred["proposedAction"]["target"]["uri"]
    if expires is None:
        return _answer(UNKNOWN, ["the approval states no expiry"], checks)
    checks["effect_after_approval"] = opred["performedAt"] >= pred["decidedAt"]
    checks["effect_before_expiry"] = opred["performedAt"] <= expires
    gruende = [text for ok, text in (
        (checks["bytes_identical"], "the stored bytes are not the approved bytes"),
        (checks["surface_is_approved"], "the effect arrived on another surface"),
        (checks["target_is_approved"], "the effect arrived on another target"),
        (checks["effect_after_approval"], "the effect precedes the approval"),
        (checks["effect_before_expiry"], "the approval had expired when the effect happened")) if not ok]
    if gruende:
        return _answer(NOT_ACCEPTED, gruende, checks)
    return _answer(ACCEPTED, [], checks)


# ---- the vectors ---------------------------------------------------------------------------------------

def test_key(label: str) -> Ed25519PrivateKey:
    """A key for the vectors, derived from a public label: not a secret, never a key of the pilot."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"github-write/1 vector key: " + label.encode()).digest())


def _pub(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


GATE_ID, OBSERVER_ID = "operator:outbound-gate", "operator:github-observer"
_TARGET = "https://github.com/b7n0de/proofbundle/pull/279"
_TEXT = b"Round four of five, at head 57184964.\n\nWritten by an AI session under owner review.\n"


def build_vectors() -> dict:
    gate, observer, other = test_key("gate"), test_key("observer"), test_key("someone else")
    policy = sha256_hex(b"outbound gate rules, revision 1")

    def decision(**over):
        args = dict(action_id="action-0001", attempt=1, decided_at="2026-09-27T00:40:00Z",
                    expires_at="2026-09-27T00:45:00Z", surface="github.conversationComment", target=_TARGET,
                    approved=_TEXT, verdict="ALLOW", reasons=["rules.satisfied"], gate_id=GATE_ID,
                    agent_id="agent:session-a", principal_id="operator", policy_digest=policy,
                    nonce="attempt-0001-1", audience=OBSERVER_ID)
        key = over.pop("key", gate)
        args.update(over)
        return sign_decision(decision_predicate(**args), key)

    def outcome(dec, *, key=observer, stored=_TEXT, scope=None, performed_at="2026-09-27T00:40:09Z", **over):
        scope = scope if scope is not None else scope_descriptor("github.conversationComment", _TARGET,
                                                                  "issuecomment-5851339484")
        args = dict(outcome_id="observation-0001", decision_root=content_root(dec), executor_id="github:b7n0de",
                    approved=_TEXT, performed_at=performed_at, recorded_at="2026-09-27T00:41:00Z", stored=stored,
                    scope=scope, nonce="attempt-0001-1", audience=OBSERVER_ID)
        args.update(over)
        return sign_outcome(outcome_predicate(**args), key), scope

    faelle = []

    def fall(name, erwartet, dec, out=None, scope=None, why=""):
        faelle.append({"case": name, "expected": erwartet, "why": why, "decision": dec, "outcome": out,
                       "observed_scope": scope})

    d0 = decision()
    o0, s0 = outcome(d0)
    fall("approved and arrived as approved", ACCEPTED, d0, o0, s0)
    fall("wrong issuer: decision signed by another key", NOT_ACCEPTED, decision(key=other), o0, s0,
         "a valid signature by a key that is not the gate's")
    fall("wrong issuer: another decision maker named", NOT_ACCEPTED, decision(gate_id="operator:someone-else"),
         None, None, "signed by the gate key, but naming another decision maker")
    o_fremd, s_fremd = outcome(d0, key=other)
    fall("wrong issuer: outcome signed by another key", NOT_ACCEPTED, d0, o_fremd, s_fremd)
    d_anders = decision(action_id="action-0002", nonce="attempt-0001-1")
    o_anders, s_anders = outcome(d_anders)
    fall("wrong subject: outcome bound to another decision", NOT_ACCEPTED, d0, o_anders, s_anders)
    o_ziel, s_ziel = outcome(d0, scope=scope_descriptor("github.conversationComment",
                                                        "https://github.com/b7n0de/proofbundle/pull/278",
                                                        "issuecomment-1"))
    fall("wrong subject: arrived on another target", NOT_ACCEPTED, d0, o_ziel, s_ziel)
    o_flaeche, s_flaeche = outcome(d0, scope=scope_descriptor("github.reviewThreadReply", _TARGET, "discussion_r1"))
    fall("arrived on another surface", NOT_ACCEPTED, d0, o_flaeche, s_flaeche,
         "the first reconciliation example of the pilot contract: bytes can match on the wrong surface")
    o_spaet, s_spaet = outcome(d0, performed_at="2026-09-27T00:50:00Z")
    fall("expired approval", NOT_ACCEPTED, d0, o_spaet, s_spaet, "the effect happened after validity.expiresAt")
    o_frueh, s_frueh = outcome(d0, performed_at="2026-09-27T00:39:00Z")
    fall("effect before the approval", NOT_ACCEPTED, d0, o_frueh, s_frueh)
    fall("missing effect: approved, nothing observed", UNKNOWN, d0, None, None)
    o_ohne, _ = outcome(d0, stored=None)
    fall("missing effect: outcome without a digest of the stored bytes", UNKNOWN, d0, o_ohne, s0)
    o_bytes, s_bytes = outcome(d0, stored=_TEXT + b"\n---\nan appended footer\n")
    fall("stored bytes differ from the approved bytes", NOT_ACCEPTED, d0, o_bytes, s_bytes)
    d_ref = decision(verdict="REFUSE", reasons=["rules.closingLine"])
    o_ref, s_ref = outcome(d_ref)
    fall("refused, and an effect arrived", NOT_ACCEPTED, d_ref, o_ref, s_ref)
    fall("refused, and nothing arrived", NOT_ACCEPTED, d_ref, None, None, "consistent, and still not an acceptance")
    d_defer = decision(verdict="DEFER", reasons=["rules.undecided"])
    o_defer, s_defer = outcome(d_defer)
    fall("deferred, and an effect arrived", NOT_ACCEPTED, d_defer, o_defer, s_defer)
    fall("no expiry stated", UNKNOWN, decision(expires_at=None), *outcome(decision(expires_at=None)))
    fall("no scope observed", UNKNOWN, d0, o0, None)
    fall("scope descriptor other than the signed one", NOT_ACCEPTED, d0, o0,
         scope_descriptor("github.conversationComment", _TARGET, "issuecomment-9"))
    d_alt = decision(engine="opa", revision=None)
    fall("no version signal: a decision receipt of another use", UNKNOWN, d_alt, *outcome(d_alt),
         why="the old format is not read under this profile")
    d_rev = decision(revision="2")
    fall("another revision of the profile", UNKNOWN, d_rev, *outcome(d_rev))
    manipuliert = dict(d0)
    roh = bytearray(base64.b64decode(d0["payload"]))
    roh[roh.index(b"ALLOW")] = ord("B")
    manipuliert["payload"] = base64.b64encode(bytes(roh)).decode("ascii")
    fall("tampered decision payload", NOT_ACCEPTED, manipuliert, o0, s0)
    return {"profile": f"{PROFILE_ENGINE}/{PROFILE_REVISION}", "gate_id": GATE_ID, "observer_id": OBSERVER_ID,
            "gate_public_key": _pub(gate).hex(), "observer_public_key": _pub(observer).hex(),
            "keys": "derived from public labels by test_key(); vectors only, never keys of the pilot",
            "cases": faelle}


def check_vectors(daten: dict) -> list:
    """(case, expected, got, reasons) for every vector."""
    ergebnis = []
    for fall in daten["cases"]:
        antwort = reconcile(fall["decision"], fall["outcome"], fall["observed_scope"],
                            gate_key=bytes.fromhex(daten["gate_public_key"]), gate_id=daten["gate_id"],
                            observer_key=bytes.fromhex(daten["observer_public_key"]), observer_id=daten["observer_id"])
        ergebnis.append((fall["case"], fall["expected"], antwort["verdict"], antwort["reasons"]))
    return ergebnis


def main(argv=None) -> int:
    ziel = Path(argv[0]) if argv else Path(__file__).with_name("vectors.json")
    daten = build_vectors()
    ziel.write_text(json.dumps(daten, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    fehler = 0
    for name, erwartet, bekommen, gruende in check_vectors(daten):
        fehler += erwartet != bekommen
        print(f"{'OK  ' if erwartet == bekommen else 'FAIL'} {name}: {bekommen} (expected {erwartet})"
              + (f" — {gruende[0]}" if gruende else ""))
    return 1 if fehler else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
