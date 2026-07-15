"""VerificationBudget — a centralized, additive resource-budget primitive for proofbundle's ``verify_*``
entry points (2026-07 verify-layer hardening, Finding 15b).

WURZEL: individual modules already guard SPECIFIC DoS surfaces with their own hardcoded ``_MAX_*``
constant — ``sdjwt.py``'s ``_MAX_DISCLOSURES`` (PB-2026-0715-15a), ``statuslist.py``'s
``_MAX_STATUS_LIST_BYTES``, ``hf_evals.py``'s ``_MAX_TOKEN_BYTES``, ``anchors_chia.py``'s
``_MAX_LAYERS``/``_MAX_PROOF_BYTES``. Each is real and each is a good pattern — but 11 OTHER verify
surfaces (``trust_pack``'s ``keys``/role ``keyIds`` counts, ``renewal``'s ArchiveTimeStamp chain/sequence
length, ``decision``'s ``evidenceRefs``/``inputSnapshot`` lists, ``run_ledger``'s ``runs`` list,
``verification_summary``'s ``levels`` list, DSSE envelope ``signatures`` counts, …) carry NO explicit cap
at all — an attacker-supplied envelope with e.g. a million-entry ``keys`` map or a million-ATS renewal
sequence is only bounded by whatever the underlying JSON parser / process memory allows.

This module does NOT replace the existing per-module caps (they stay; they are proven; this is additive)
— it gives every OTHER verify_* entry point the SAME kind of guard through one shared, named, testable
primitive instead of a fresh ad hoc constant each time a new gap is found. Wired concretely (this
increment, Finding 15b) into the two most concretely identified unguarded paths — ``trust_pack``'s
``keys``/role ``keyIds`` counts and ``renewal.verify_sequence``'s total ArchiveTimeStamp count — plus the
cheap, universally-safe ``input_bytes`` cap on every DSSE ``verify_*`` entry point in ``decision.py``,
``outcome.py``, ``trust_pack.py``, ``verification_summary.py`` and ``run_ledger.py`` (checked on the raw
DSSE payload bytes, BEFORE JSON parsing — mirrors the ``anchors_chia``/``hf_evals`` "cap before the
expensive work runs" pattern).

No-Fake: the defaults are DELIBERATELY generous (comfortably above any legitimate receipt/pack/sequence
observed in this repo's own examples and tests) — a budget is a DoS backstop, not a behavioural policy
knob. Raising a limit never weakens a security *check*, it only widens how much attacker-controlled input
a ``verify_*`` call is willing to walk before refusing.
"""
from __future__ import annotations

from dataclasses import dataclass

from .errors import ProofBundleError

__all__ = ["VerificationBudget", "DEFAULT_BUDGET", "BudgetExceeded"]


class BudgetExceeded(ProofBundleError):
    """A ``verify_*`` input exceeded its :class:`VerificationBudget`. Fail-closed: a ``ProofBundleError``
    subclass, so every existing ``except (ProofBundleError, ...)`` call site (CLI commands, test fuzz
    sweeps) already treats it exactly like any other malformed/over-limit input — never silently
    truncated, never silently continued."""

    def __init__(self, dimension: str, got: int, limit: int):
        self.dimension = dimension
        self.got = got
        self.limit = limit
        super().__init__(
            f"verification budget exceeded: {dimension} = {got} > limit {limit} (DoS guard, Finding 15b)")


@dataclass(frozen=True)
class VerificationBudget:
    """Generous ceilings, comfortably above legitimate use, fail-closed above them (Finding 15b). Every
    field is a COUNT/LENGTH ceiling on UNTRUSTED input, never a behavioural knob.

    * ``input_bytes``       — raw bytes of one DSSE payload / bundle / token before parsing.
    * ``json_nodes``        — combined dict-key + list-item count across one parsed JSON document
                               (a coarse proxy for "how much did the parser have to walk", independent of
                               ``json.loads``'s own C-recursion depth limit, which ``_strict_json`` already
                               maps to a clean error).
    * ``string_len``        — length of a single JSON string value.
    * ``signatures``        — DSSE / threshold-signature entries on one envelope.
    * ``merkle_path``       — RFC 6962 inclusion-proof steps (mirrors ``anchors_chia._MAX_LAYERS``, kept as
                               the SAME bar so the two never silently drift apart).
    * ``disclosures``       — SD-JWT disclosures (mirrors ``sdjwt._MAX_DISCLOSURES`` — same bar,
                               PB-2026-0715-15a).
    * ``renewal_ats_chain`` — total ArchiveTimeStamp count across a whole renewal sequence (all chains).
    * ``witnesses``         — named-key-material entries in a threshold/quorum construct: a Trust Pack's
                               ``keys`` map, or one role's ``keyIds`` list (mirrors the quorum-signer
                               concept ``checkpoint.py``'s ``witness_quorum`` already names).
    """

    input_bytes: int = 8 * 1024 * 1024
    json_nodes: int = 200_000
    string_len: int = 1_000_000
    signatures: int = 64
    merkle_path: int = 256
    disclosures: int = 256
    renewal_ats_chain: int = 10_000
    witnesses: int = 256

    def within(self, dimension: str, value: int) -> bool:
        """Non-raising: True iff ``value`` is within the named dimension's limit. Prefer this in a
        ``validate_*``-style function that REPORTS a list of errors rather than raising (mirrors the rest
        of this repo's fail-closed-but-never-crash validators)."""
        return value <= getattr(self, dimension)

    def check(self, dimension: str, value: int) -> None:
        """Raising counterpart of :meth:`within`: raises :class:`BudgetExceeded` when ``value`` exceeds the
        named dimension's limit. Prefer this at a ``verify_*`` entry point that already raises
        ``ProofBundleError`` subclasses for other malformed-input classes (decision/outcome/trust_pack/
        verification_summary/run_ledger all do, for a duplicate JSON key or a non-JSON payload)."""
        if not self.within(dimension, value):
            raise BudgetExceeded(dimension, value, getattr(self, dimension))


DEFAULT_BUDGET = VerificationBudget()
