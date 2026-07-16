"""automation_summary — a uniform, additive automation-safety verdict layered on top of any proofbundle
``verify_*`` result dict (2026-07 verify-layer hardening, Finding 01).

WURZEL: ``bundle.py::root_authenticity_summary`` already computes a ``safeForAutomation`` /
``automationBlockers`` verdict for the core evidence bundle — it exists ONLY there. The other five
receipt-chain predicates (``decision.py``, ``outcome.py``, ``trust_pack.py``, ``verification_summary.py``,
``run_ledger.py``) each compute their OWN aggregate ``ok`` using an ``is not False`` pattern over their
optional/not-applicable checks (documented, intentional: ``None`` = "not requested, passes"). That is the
RIGHT default for ``ok`` (a caller who never asked for a policy check should not be told the receipt is
somehow invalid) — but it is the WRONG bar for an AUTOMATION decision: a caller who filters on ``ok`` alone
can walk away believing a receipt was policy-authorized when ``policy_ok`` was actually ``None``
(never evaluated), because ``None is not False`` is ``True``.

``automation_summary`` does NOT change any existing ``ok`` field (additive, no breaking default flip — see
CHANGELOG "Unreleased" for the ONE deliberately-deferred breaking piece, the ``bundle.py`` CLI exit-code
default). It computes a SEPARATE, stricter verdict: ``safeForAutomation`` is true only when policy IS
``True`` (never merely "not False"), mirroring ``bundle.py``'s own ``policy_ok is True`` bar (P0-B, audit
2026-07-13). Each of the five ``verify_*`` functions stashes this at ``result["automation"]`` — the old
``result["ok"]`` field is untouched.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

__all__ = ["automation_summary", "AUTOMATION_BLOCKER_REASONS"]

# The human-legible reason for each automationBlockers enum value (mirrors bundle.py's
# AUTOMATION_BLOCKER_REASONS — kept here, next to the blocker logic, so the two can never drift apart).
AUTOMATION_BLOCKER_REASONS = {
    "CRYPTO_NOT_OK": "The cryptographic (DSSE / threshold-signature) verdict is not true",
    "STRUCTURE_NOT_OK": "The predicate structure did not fully validate",
    "POLICY_NOT_EVALUATED": "No trust policy / authorization gate was evaluated for this predicate type",
    "POLICY_FAILED": "The supplied trust policy / authorization gate was not satisfied",
    "REFERENCES_NOT_RESOLVED": "One or more referenced/bound artifacts did not resolve (see the "
                               "predicate's own *_ok / *_bound / *_intact fields for which)",
    # relation/v0.1 (EXPERIMENTAL): raised by the DECISION verify path when the trust
    # policy's relations section is violated (the outcome-path policy gate is a documented
    # follow-up — verify_outcome_receipt has no policy parameter today) (a named relation did not resolve, or an attached,
    # verified successor supersedes the receipt under rejectSuperseded). LIVE, not dormant.
    "LINEAGE_REQUIREMENT_FAILED": "The trust policy's lineage requirement was not met (relations "
                                  "section: unresolved required relation or superseded receipt)",
}


def _tri(result: Mapping[str, Any], key: Optional[str]) -> Optional[bool]:
    if key is None:
        return None
    value = result.get(key)
    return None if value is None else bool(value)


def automation_summary(result: Mapping[str, Any], *, required_checks: Mapping[str, Any]) -> dict:
    """Build a uniform automation-safety verdict from a ``verify_*`` result dict.

    ``required_checks`` maps the four canonical automation dimensions to the ACTUAL field name(s) in
    ``result`` that decide them for THIS predicate type (field names differ per ``verify_*`` function):

      ``"crypto"``     -- str, the crypto/signature verdict field (e.g. ``"crypto_ok"``,
                          ``"root_threshold_met"``).
      ``"structure"``  -- str, the structural verdict field (e.g. ``"structure_ok"``).
      ``"policy"``     -- str or ``None``. When a str, the field is treated the SAME way
                          ``bundle.py::root_authenticity_summary`` treats ``policy_ok``: safe requires the
                          field to be ``True`` EXACTLY (``is True``), never merely ``is not False`` --
                          ``None`` (not evaluated) yields ``POLICY_NOT_EVALUATED``, never a silent pass.
                          When ``None``, this predicate type carries no policy/authorization layer at all
                          -- the policy dimension is reported ``None`` (not applicable) and never blocks
                          ``safeForAutomation``.
      ``"references"`` -- a sequence of field names whose values, when EXPLICITLY ``False``, mean a
                          referenced/bound artifact did not resolve (e.g. ``decision_bound``,
                          ``evidence_bound``, ``chain_intact``). ``None`` entries (not applicable / not
                          requested) never block.

    Returns ``{"cryptoValid", "structureValid", "policyAuthorized", "referencesResolved",
    "safeForAutomation", "automationBlockers"}``. This function is PURE (no side effects on ``result``);
    the caller is responsible for stashing the return value at ``result["automation"]``.
    """
    crypto_key = required_checks.get("crypto")
    structure_key = required_checks.get("structure")
    policy_key = required_checks.get("policy")
    reference_keys: Sequence[str] = required_checks.get("references") or ()

    crypto_ok = _tri(result, crypto_key)
    structure_ok = _tri(result, structure_key)
    policy_val = result.get(policy_key) if policy_key is not None else None
    unresolved = [name for name in reference_keys if result.get(name) is False]

    blockers: list[str] = []
    if crypto_ok is not True:
        blockers.append("CRYPTO_NOT_OK")
    if structure_ok is not True:
        blockers.append("STRUCTURE_NOT_OK")
    if policy_key is not None:
        if policy_val is None:
            blockers.append("POLICY_NOT_EVALUATED")
        elif policy_val is not True:
            blockers.append("POLICY_FAILED")
    if unresolved:
        blockers.append("REFERENCES_NOT_RESOLVED")

    return {
        "cryptoValid": crypto_ok,
        "structureValid": structure_ok,
        "policyAuthorized": None if policy_key is None else (policy_val is True),
        "referencesResolved": None if not reference_keys else not unresolved,
        "safeForAutomation": not blockers,
        "automationBlockers": blockers,
    }
