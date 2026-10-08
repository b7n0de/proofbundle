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

from .errors import BundleFormatError
from .canonical import _abbild_stand, _ein_stand

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
    # relation/v0.1 3.4.0 (WP-A / WP-A2): raised on BOTH the decision and outcome verify paths.
    "RELATION_SIGNER_UNAUTHORIZED": "The successor's issuer key is not authorized by the trust "
                                    "policy's relation_signer pin (WHO may replace — set membership "
                                    "under the verifier's pins, not a proof of authority)",
    "RELATION_TARGET_MISMATCH": "A supersedes-like edge resolves to a parent NOT in the trust "
                                "policy's require_relation_target pin (WHICH parent — a valid but "
                                "wrong/decoy parent, rejected only in the policy verdict)",
}


def _tri(result: Mapping[str, Any], key: Optional[str], not_bool: list) -> Optional[bool]:
    # adversarial re-audit r5: ein Dimensions-Schluessel MUSS ein Feldname (str) sein; ein unhashbarer/nicht-str Wert
    # (list/dict) aus required_checks crasht sonst result.get(key) — fail-closed als "nicht anwendbar".
    if not isinstance(key, str):
        return None
    value = result.get(key)
    if value is None:
        return None
    # Only the exact True is True. bool(value) made "false", 1 and [0] a valid crypto/structure verdict and
    # ran the caller's __bool__; a value that is not a bool is False here and named in notBooleanInputs.
    if type(value) is not bool:
        not_bool.append(key)
        return False
    return value


@_ein_stand(required_checks=_abbild_stand, result=_abbild_stand)
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
      ``"references"`` -- a sequence of field names whose values, when not ``True``, mean a
                          referenced/bound artifact did not resolve (e.g. ``decision_bound``,
                          ``evidence_bound``, ``chain_intact``). ``None`` entries (not applicable / not
                          requested) never block.

    Every verdict read from ``result`` counts only as a bool. ``crypto`` and ``structure`` are valid
    only as the exact ``True``, a reference resolves only as ``None`` or the exact ``True``, and
    ``policy`` and ``ok`` pass only as the exact ``True``. They used to be read by their truth
    (``bool(value)``) or to block only on the exact ``False``, so ``{"crypto_ok": "false",
    "structure_ok": "false", "evidence_bound": "false"}`` read as ``cryptoValid`` true and
    ``safeForAutomation`` true. A value that is not a bool never passes, the caller's own methods on it
    never run, and the summary then carries ``notBooleanInputs``, the field names of those values
    (absent when every read value is a bool or ``None``, so the shape is unchanged for them).

    Returns ``{"cryptoValid", "structureValid", "policyAuthorized", "referencesResolved",
    "safeForAutomation", "automationBlockers"}``. This function is PURE (no side effects on ``result``);
    the caller is responsible for stashing the return value at ``result["automation"]``.

    ``result["ok"]``, when present and not ``True``, ALWAYS blocks with ``RECEIPT_NOT_OK``: a summary
    must never read safer than the verdict it summarises. An ABSENT ``ok`` never blocks — that is "not
    applicable", not "not passed". This was a per-caller correction until 02.09.2026; a deep gate
    measured that a caller could simply forget it (and that the guard watching for it checked the call's
    SPELLING, not the property).
    """
    # adversarial re-audit: both Mapping args were unguarded — a non-Mapping ``required_checks`` (None) crashed
    # ``required_checks.get(...)`` and a non-Mapping ``result`` crashed ``_tri``'s ``result.get(...)`` with a
    # raw AttributeError out of this public verdict surface. A malformed config/result is a typed
    # BundleFormatError (fail-closed), never a raw crash and never a silently-safe verdict.
    if not isinstance(required_checks, Mapping) or not isinstance(result, Mapping):
        raise BundleFormatError("automation_summary requires Mapping 'result' and 'required_checks'")
    crypto_key = required_checks.get("crypto")
    structure_key = required_checks.get("structure")
    policy_key = required_checks.get("policy")
    # adversarial re-audit round 4: the top-level Mapping args were guarded, but a truthy non-iterable
    # required_checks['references'] (int/bool/object) survived `... or ()` and crashed the iteration below.
    # A PRESENT references OF ANOTHER SHAPE IS ITSELF UNRESOLVED (verify lens on the cross-check fix at bc3d275f,
    # 2026-09-29): a text, a set, a dict, 5 or True was read as no references, and an entry that is no text
    # (b"evidence_bound", ["evidence_bound"]) was skipped, so `evidence_bound` False gave safeForAutomation True,
    # where a wrong `crypto`, `structure` or `policy` key blocks. Only an absent (None) references means none.
    # Each name is read by its characters (`_zeichen_von`): a `str` subclass names the field it holds, as a list
    # or tuple subclass is read through the base type's iteration.
    from .canonical import _folge_von, _zeichen_von  # noqa: PLC0415
    _refs = required_checks.get("references")
    _refs_folge = _folge_von(_refs) if issubclass(type(_refs), (list, tuple)) else None
    _namen = [_zeichen_von(n) for n in (_refs_folge or ())]
    refs_fremd = _refs is not None and (_refs_folge is None or any(n is None for n in _namen))
    reference_keys: Sequence[str] = [n for n in _namen if n is not None]

    not_bool: list[str] = []
    crypto_ok = _tri(result, crypto_key, not_bool)
    structure_ok = _tri(result, structure_key, not_bool)
    policy_val = result.get(policy_key) if isinstance(policy_key, str) else None  # adversarial re-audit r5: unhashable key
    if policy_val is not None and type(policy_val) is not bool:
        not_bool.append(str(policy_key))
    # A reference resolves only as None (not applicable) or the exact True; `is False` alone let "false" and 0
    # through as resolved.
    unresolved: list[str] = []
    for name in reference_keys:
        if not isinstance(name, str):
            continue
        ref_val = result.get(name)
        if ref_val is None or ref_val is True:
            continue
        unresolved.append(name)
        if type(ref_val) is not bool and name not in not_bool:
            not_bool.append(name)

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
    if unresolved or refs_fremd:
        blockers.append("REFERENCES_NOT_RESOLVED")

    # DIE ZUSAMMENFASSUNG DARF NIE NACHSICHTIGER SEIN ALS DAS URTEIL, DAS SIE ZUSAMMENFASST.
    #
    # Diese Invariante stand bis zum 02.09.2026 NICHT hier, sondern als separater Aufruf bei EINEM
    # Verbraucher (`agent_review`). Ein adversariales Tiefen-Gate hat gemessen, was das kostet: eine
    # vierte Flaeche, deren einziger Unterschied `automation_verdict.automation_summary(...)` statt
    # `automation_summary(...)` war, lieferte `ok=False, safeForAutomation=True, blockers=[]` — und
    # die Suite meldete 89 passed. Der Riegel war da, aber ein Autor konnte ihn vergessen, und der
    # Waechter darueber pruefte die SCHREIBWEISE des Aufrufs statt die Eigenschaft.
    #
    # Hier kann ihn niemand vergessen. Gemessen ueber die volle Suite: 2968 passed, kein anderes
    # Modul aendert sein Verhalten; und mit ENTFERNTEN separaten Aufrufen 0 Verstoesse bei 14 echten Aufrufstellen (hier stand '18' — das waren grep-Treffer inklusive drei Kommentarzeilen und einer def-Zeile; gemessen wurde ein VORKOMMEN statt einer EIGENSCHAFT) —
    # `ok` ist an jeder Aufrufstelle bereits endgueltig.
    #
    # DREI ZUSTAENDE, nie zwei: ein FEHLENDES `ok` (der Aufrufer fuehrt keins) blockt NICHT — das
    # ist „nicht anwendbar" und nicht dasselbe wie „nicht bestanden". Nur ein VORHANDENES `ok`, das
    # nicht `True` ist, blockt.
    #
    # Die Funktion bleibt PUR: sie LIEST `result["ok"]`, sie schreibt nichts.
    if "ok" in result:
        receipt_ok = result.get("ok")
        if receipt_ok is not True:
            blockers.append("RECEIPT_NOT_OK")
        if receipt_ok is not None and type(receipt_ok) is not bool:
            not_bool.append("ok")

    extra = {"notBooleanInputs": not_bool} if not_bool else {}
    return {
        "cryptoValid": crypto_ok,
        "structureValid": structure_ok,
        "policyAuthorized": None if policy_key is None else (policy_val is True),
        "referencesResolved": (False if refs_fremd else None if not reference_keys else not unresolved),
        "safeForAutomation": not blockers,
        "automationBlockers": blockers,
        **extra,
    }
