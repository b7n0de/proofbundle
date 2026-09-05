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

import reprlib as _reprlib
from dataclasses import dataclass

from .errors import ProofBundleError

__all__ = ["VerificationBudget", "DEFAULT_BUDGET", "BudgetExceeded", "int_magnitude_ok",
           "render_safe", "render_keys_safe"]


class _BoundedRepr(_reprlib.Repr):
    """A ``reprlib.Repr`` that also honours the integer-magnitude budget.

    ``reprlib`` bounds DEPTH and WIDTH (a self-referential or 10,000-element container renders as a
    short elided form), but its ``repr_int`` still calls ``repr()`` on the integer and would trip the
    CVE-2020-10735 int->str cap from INSIDE the bounded walk. The magnitude rule is applied here, at
    the one place every integer passes, so a huge int nested three levels deep is described exactly
    like a top-level one.
    """

    def __init__(self, budget: "VerificationBudget | None"):
        super().__init__()
        self._budget = budget
        self.maxlevel = 4
        self.maxdict = 8
        self.maxlist = self.maxtuple = self.maxset = self.maxfrozenset = self.maxarray = 8
        self.maxstring = 256
        self.maxlong = 64
        self.maxother = 256

    def repr_int(self, x, level):  # noqa: D401 - reprlib protocol name
        if int_magnitude_ok(x, self._budget):
            return _reprlib.Repr.repr_int(self, x, level)
        return f"<int, {x.bit_length()} bits>"

    def repr_bool(self, x, level):  # a bool is an int subclass; keep it literal
        return repr(x)


# Hard ceiling on one rendered value, applied AFTER the bounded walk: no combination of the per-type
# widths above can produce an unbounded explanation.
_MAX_RENDER_CHARS = 512


def render_safe(value, budget: "VerificationBudget | None" = None, *, quote: bool = True) -> str:
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

    THE THIRD HALF, deep gate 2026-09-05 (L2-BDOS-RENDER-NEIGHBOURS-01, L3-600-01, L3-600-03): the
    rejection text of ``verify_bundle``, ``anchors.verify_anchor`` and ``hashalg.verify_dual_hash``
    rendered an enum-typed field with ``{value!r}`` directly, and ``_reject_unknown`` sorted a set of
    untrusted dict keys to name them. A huge int in ``schema``, a tuple holding one, or a mixed-type
    key set made the REJECTION fail harder than the check it explains — a raw ``ValueError`` /
    ``TypeError`` out of a typed-raise or never-raise surface. The renderer is now bounded in DEPTH
    and WIDTH too (``reprlib``), never raises for any input (a hostile ``__repr__``, a
    self-referential container, a nested huge int), and it is the ONE renderer every message site
    on those paths uses. For the ordinary cases — a string, a small int, a short tuple — the output
    is byte-identical to ``repr()`` / ``str()``, so existing message assertions keep their meaning.

    ``quote=True`` (default) is the bounded replacement for ``{value!r}``; ``quote=False`` is the
    bounded replacement for a plain ``{value}`` — a ``str`` renders as itself (clipped), everything
    else falls back to the bounded repr, because ``str()`` on a hostile object recurses exactly like
    ``repr()`` does.
    """
    try:
        if isinstance(value, bool):
            return repr(value)
        if isinstance(value, int):
            if int_magnitude_ok(value, budget):
                return str(value)
            return f"<int, {value.bit_length()} bits>"
        if not quote and isinstance(value, str):
            return _clip_render(value)
        return _clip_render(_BoundedRepr(budget).repr(value))
    except BaseException:  # noqa: BLE001 — a renderer on a never-raise path must not raise, ever
        try:
            return f"<unrenderable {type(value).__name__}>"
        except BaseException:  # noqa: BLE001 — even type(...).__name__ can be booby-trapped
            return "<unrenderable>"


def _clip_render(text: str) -> str:
    if len(text) <= _MAX_RENDER_CHARS:
        return text
    return text[: _MAX_RENDER_CHARS - 3] + "..."


def render_keys_safe(keys) -> "list[str]":
    """Name a set of UNTRUSTED dict keys in a message: rendered first, sorted second, never raising.

    ``sorted(set(obj) - allowed)`` was the shape at seven sites (bundle, anchors, decision, relation,
    policy, evalclaim, hf_evals): it orders the RAW keys, and two unknown keys of incomparable types
    (``{5: 1, "zzz": 1}``, reachable on every direct-dict surface) raise a raw ``TypeError`` before
    the typed error that was about to name them is even built (deep gate 2026-09-05, L3-600-03).
    Rendering each key first (bounded, see :func:`render_safe`) turns the ordering into a string
    sort that cannot fail, and the message still names every key.
    """
    try:
        return sorted(render_safe(k) for k in keys)
    except BaseException:  # noqa: BLE001 — a hostile __iter__/__hash__ must not escape either
        return ["<unrenderable keys>"]


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
