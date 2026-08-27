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

__all__ = ["VerificationBudget", "DEFAULT_BUDGET", "BudgetExceeded", "int_magnitude_ok",
           "render_safe"]


def render_safe(value, budget: "VerificationBudget | None" = None) -> str:
    """Render ONE untrusted value for a diagnostic message without letting it raise.

    THE SECOND HALF OF THE MAGNITUDE CLASS, found by the pre-tag deep gate on 2026-08-25
    (L2-BDOS-RENEWAL-HUGEINT-01/02) — one round AFTER the first half was closed, on a neighbour
    the first sweep did not reach.

    The first half was about COMPUTE: a huge integer drives an O(bit_length) shift loop. This half
    is about RENDERING, and it is sneakier: CPython caps int->str conversion at
    ``sys.get_int_max_str_digits`` (4300 by default, CVE-2020-10735). Interpolating an untrusted
    integer into a diagnostic string therefore raises a raw ``ValueError`` — out of a surface whose
    entire contract is that it never raises. The value was never even used for a computation; it was
    used to explain WHY the input was rejected.

    WHY A RENDER HELPER AND NOT A GUARD AT EVERY SITE: a guard has to be remembered at each of the
    nine render sites in ``renewal.py`` alone, and the tenth one written next month is a new
    instance of the same class. A helper is remembered once — and the diagnostic keeps saying
    something useful about the value instead of refusing to mention it.

    Beyond the ceiling the value is described rather than printed: ``<int, 16610 bits>``. That is
    honest (it names what it is and how big) and it is exactly what a reader needs — nobody
    diagnoses anything from 5000 decimal digits.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        # A non-int normally renders via repr. But a CONTAINER holding a giant int (or any object whose
        # __repr__ interpolates one) re-raises the int->str cap from INSIDE repr() — the deep gate found a
        # never-raise surface passing a whole container field here (e.g. sig_alg=[1<<100000]). The note
        # above assumed callers pass container ELEMENTS; the never-raise surfaces pass the whole field, so
        # the contract ("without letting it raise") is enforced here — one helper, every site.
        try:
            return repr(value)
        except Exception:  # noqa: BLE001 — nested implausible int / hostile __repr__ must not escape
            return f"<unrenderable {type(value).__name__}>"
    if int_magnitude_ok(value, budget):
        return str(value)
    return f"<int, {value.bit_length()} bits>"


def int_magnitude_ok(value, budget: "VerificationBudget | None" = None) -> bool:
    """Non-raising magnitude check for ONE untrusted integer — the shared entry guard.

    Deliberately non-raising and deliberately tolerant of a non-int: the callers are surfaces with
    different contracts. ``verify_inclusion`` returns ``bool`` and never raises; ``verify_sample_opening``
    returns a verdict dict; ``bundle._require_int`` raises a typed ``BundleFormatError``. A shared guard
    that RAISED would force the first two to catch it back — and a guard whose result has to be undone at
    two of three call sites is a guard nobody will call at the fourth.

    A non-integer passes here (``True``): type-checking is the caller's job and each does it its own way.
    This function answers exactly one question, and answering only it is why it can be shared.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return True
    return value.bit_length() <= (budget or DEFAULT_BUDGET).int_bits


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
    * ``json_depth``        — maximum nesting depth of one parsed JSON document, enforced EXPLICITLY by
                               ``_strict_json`` so the bounded-depth guarantee holds interpreter-independently
                               (CPython <=3.11 raises ``RecursionError`` on deep nesting, but 3.12+ accepts
                               far deeper input without raising — relying on the exception alone left the
                               guarantee version-dependent, PB-2026-0718-11b). Sized comfortably above any
                               legitimate document (repo max observed depth = 9) yet far below CPython's own
                               ~1000-frame recursion limit, so downstream recursive walks (JCS
                               canonicalization) stay safe too.
    * ``string_len``        — length of a single JSON string value.
    * ``signatures``        — DSSE / threshold-signature entries on one envelope. Sized to admit a
                               legitimate TWO-STAGE ROTATION envelope (``trust_pack``'s rotation reuses ONE
                               ``signatures`` list for BOTH the new-root threshold AND the old-root vouch, so
                               a consortium at the ``witnesses`` ceiling per role needs up to ~2x that) while
                               still refusing an attacker-scaled million-entry list (a few-hundred Ed25519
                               verifies is microseconds; the DoS regime is orders of magnitude above).
    * ``merkle_path``       — RFC 6962 inclusion-proof steps (mirrors ``anchors_chia._MAX_LAYERS``, kept as
                               the SAME bar so the two never silently drift apart).
    * ``disclosures``       — SD-JWT disclosures (mirrors ``sdjwt._MAX_DISCLOSURES`` — same bar,
                               PB-2026-0715-15a).
    * ``renewal_ats_chain`` — total ArchiveTimeStamp count across a whole renewal sequence (all chains).
    * ``witnesses``         — named-key-material entries in a threshold/quorum construct: a Trust Pack's
                               ``keys`` map, or one role's ``keyIds`` list (mirrors the quorum-signer
                               concept ``checkpoint.py``'s ``witness_quorum`` already names).
    * ``int_bits``          — MAGNITUDE of a single untrusted integer (bit length), not a count. This is
                               the one dimension that bounds CPU rather than memory: a tree size or leaf
                               index arrives as a tiny JSON token (``2**1000000`` is seven characters of
                               source) and then drives an ``O(bit_length)`` shift loop. Every structural
                               budget above passes it — ``input_bytes``, ``json_nodes`` and ``string_len``
                               all see a scalar, and a scalar is small.

                               Found by the pre-tag deep gate on 2026-08-25 (L2-BDOS-HUGEINT, P2):
                               ``bundle._require_int`` has carried an 8192-bit ceiling since the earlier
                               L2-BDOS-01 fix, but the three EXPORTED surfaces that take their integers as
                               ARGUMENTS rather than from a dict — ``verify_inclusion``,
                               ``verify_consistency``, ``verify_sample_opening`` — never got it. Measured:
                               ``verify_inclusion(2**300000, …)`` ran 3.3 s and returned the correct
                               ``False``; at ``2**1000000`` that scales to roughly 34 s, against
                               ``verify_bundle``'s ~0.015 s on the identical magnitude. Correct verdict,
                               unbounded cost — which is precisely what a DoS looks like.

                               8192 bits is astronomically generous: a real tree size is below ``2**64``.
    """

    input_bytes: int = 8 * 1024 * 1024
    json_nodes: int = 200_000
    json_depth: int = 64
    string_len: int = 1_000_000
    signatures: int = 512
    merkle_path: int = 256
    disclosures: int = 256
    renewal_ats_chain: int = 10_000
    witnesses: int = 256
    int_bits: int = 8192

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
