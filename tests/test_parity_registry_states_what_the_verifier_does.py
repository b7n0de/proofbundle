"""A shipped specification artefact states what the verifier does, measured, not what it once meant.

Release scope 6.2.0, line R1. `scripts/rust_parity_registry.json` ships in the sdist and is what a
reader building a second implementation reads. Its v0.2 entry said the verifier "deliberately does
not decide that for it (policy_decision stays None)", which reads as a neutral outcome. Measured on
2026-09-25: without a named policy `verify_agent_review_v02` returns `policy_decision: null`, the
advisory code `POLICY_NOT_EVALUATED`, and `automation.safeForAutomation: false` with that code as its
blocker. A second implementation that followed the registry could hand out the automation verdict
the reference withholds, for the same bytes.

THE PROPERTY, bound to a measurement rather than to a spelling: every registry entry that speaks of
`policy_decision` names each automation blocker the verifier ACTUALLY reports in the no-policy state,
and says the automation verdict is false. If the verifier's blocker set changes, this fails until
the registry says so; if the registry drops it, this fails too.
"""
from __future__ import annotations

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = REPO / "scripts" / "rust_parity_registry.json"
FALL = REPO / "conformance" / "agent_review" / "agent-review-v02-counter-proof-without-policy-nothing-is-decided"


def _eintraege(o, pfad=""):
    """Every (name, entry) whose value carries a `notes` string, wherever it sits in the registry."""
    if isinstance(o, dict):
        if isinstance(o.get("notes"), str):
            yield pfad, o
        for k, v in o.items():
            yield from _eintraege(v, k)


def _messung(policy_waehlen: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from proofbundle import agent_review as ar
    doc = json.loads((FALL / "predicate.json").read_text(encoding="utf-8"))
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    env = ar.emit_agent_review(doc, sk)
    policy = None if policy_waehlen == "none" else ar.load_policy()
    return ar.verify_agent_review_v02(env, sk.public_key().public_bytes_raw(),
                                      expected_subject_digest=ar._subject_digest(doc), policy=policy)


def befunde(notes: str, blocker: list[str]) -> list[str]:
    """What a `policy_decision` note fails to say about the no-policy state, given the measured blockers."""
    fehlt = [b for b in blocker if b not in notes]
    out = [f"does not name the blocker {b}" for b in fehlt]
    if "safeForAutomation is false" not in notes:
        out.append("does not say that automation.safeForAutomation is false without a policy")
    return out


def test_the_measurement_distinguishes_the_two_states():
    """PRECONDITION: without it the property below could hold against a verifier that blocks
    everything. The named default policy decides and releases automation for the same receipt."""
    if not FALL.is_dir():
        pytest.skip("the agent-review corpus case is not in this tree")
    ohne, mit = _messung("none"), _messung("default")
    assert ohne.get("policy_decision") is None, ohne.get("policy_decision")
    assert (ohne.get("automation") or {}).get("safeForAutomation") is False
    assert mit.get("policy_decision") == "accept", mit.get("policy_decision")
    assert (mit.get("automation") or {}).get("safeForAutomation") is True


def test_every_policy_decision_note_states_what_the_verifier_reports():
    if not FALL.is_dir():
        pytest.skip("the agent-review corpus case is not in this tree")
    blocker = list((_messung("none").get("automation") or {}).get("automationBlockers") or [])
    assert blocker, "the no-policy state reports no blocker -- then this case says nothing"
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    betroffen = [(name, e) for name, e in _eintraege(registry) if "policy_decision" in e["notes"]]
    assert betroffen, "no registry entry speaks of policy_decision -- then this case says nothing"
    fehler = {name: befunde(e["notes"], blocker) for name, e in betroffen}
    assert not any(fehler.values()), fehler


def test_CONTROL_the_text_before_the_fix_is_caught():
    """The counter-direction, on the wording the registry carried until 2026-09-25."""
    alt = ("a relying party decides which source its policy accepts, and this verifier deliberately "
           "does not decide that for it (policy_decision stays None).")
    assert befunde(alt, ["POLICY_NOT_EVALUATED"])
