"""Duplicate-key-rejecting JSON parsing — the one strict parser for every verify path (WP-C1).

``json.loads`` silently keeps the LAST occurrence of a duplicated key (last-wins). On a verify
path that is a classic parser differential (Bishop Fox 2021; the exact bug class behind several
JWT/JOSE CVEs): two implementations parsing the same bytes can disagree about which ``root_b64``
or ``sig_b64`` they verified, so "cross-verifier consensus" silently stops meaning one thing.
RFC 8785 (JCS) forbids duplicate keys outright, and the DSSE statement paths already reject them
INDIRECTLY (a duplicated payload cannot be byte-equal to its own canonical re-serialization) —
but the native bundle path accepted them silently, and an explicit reject with a clear message
beats an incidental byte-mismatch everywhere.

Converted paths: the native bundle (``load_bundle``, the HF ``pb1.`` token), the DSSE statement
verifiers (eval-result / test-result / SVR / decision), the trust-policy loader, the per-sample
disclosure record, the chia-datalayer and markovian anchor envelopes, the status-list token, the
enclave EAT, and every ``json.load`` in the CLI. Emit-side inputs (a claim/predicate file the
caller authored) use it too — a duplicate key in something about to be signed is at best an
authoring bug, at worst an attempted differential.

Resolved 2026-07-12 (F12, release-audit): the SD-JWT/KB-JWT payload sites in ``sdjwt.py`` /
``kbjwt.py``, ``bundle._issuer_requires_holder_binding``, ``sdjwt_issue._jwt_payload`` and
``evalclaim.sd_jwt_hidden_count`` now parse with ``loads_strict`` too, each routed fail-closed —
a duplicate ``cnf`` is rejected, and ``_issuer_requires_holder_binding`` returns True on a duplicate
(binding REQUIRED), never the inverted "no holder binding required". Keys that differ only by Unicode normalization
(NFC/NFD) or a BOM are DISTINCT JSON keys by spec and stay distinct here — normalization games are
a downstream concern of the field validators, not of the parser.

Stdlib-only (``object_pairs_hook``), so the base install keeps rejecting duplicates without any
extra. The hook fires for every nested object (including objects inside arrays), so duplicates are
rejected at ANY depth.
"""
from __future__ import annotations

import json
from typing import Any, Union

from .errors import BundleFormatError

__all__ = ["loads_strict"]


def _reject_duplicate_keys(pairs: list) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise BundleFormatError(
                f"duplicate JSON key {key!r} — rejected fail-closed (a duplicated key parses "
                "differently across JSON implementations; parser-differential guard, WP-C1)")
        obj[key] = value
    return obj


def _enforce_structural_budget(obj: Any, json_nodes: int, json_depth: int) -> None:
    """Bounded iterative walk (crypto-review 2026-07-15; depth added PB-2026-0718-11b): refuse a PARSED
    structure that is either too WIDE (combined dict-key + list-item count exceeds ``json_nodes`` — a
    wide-but-small-bytes document that slips under the raw ``input_bytes`` cap) or too DEEP (nesting depth
    exceeds ``json_depth``). The depth bound is enforced HERE, interpreter-independently, rather than relying
    on ``json.loads`` raising ``RecursionError`` — which it does on CPython <=3.11 but NOT on 3.12+ (the C
    scanner accepts far deeper nesting without raising), so the ``RecursionError`` mapping alone left the
    bounded-depth guarantee version-dependent. Depth-first, so it aborts the moment either ceiling is
    passed and never walks the whole of an over-budget document. Over-width raises
    :class:`proofbundle.budget.BudgetExceeded`; over-depth raises :class:`BundleFormatError` with the SAME
    ``"JSON nesting is too deep"`` message + class as the ``RecursionError`` mapping, so a deep document is
    one stable malformed-input outcome on every interpreter. Both are ``ProofBundleError`` subclasses,
    fail-closed."""
    from .budget import BudgetExceeded  # noqa: PLC0415 - local import avoids an import cycle
    count = 0
    stack = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > json_depth:
            raise BundleFormatError("JSON nesting is too deep")
        if isinstance(cur, dict):
            count += len(cur)
            if count > json_nodes:
                raise BudgetExceeded("json_nodes", count, json_nodes)
            for value in cur.values():
                stack.append((value, depth + 1))
        elif isinstance(cur, list):
            count += len(cur)
            if count > json_nodes:
                raise BudgetExceeded("json_nodes", count, json_nodes)
            for value in cur:
                stack.append((value, depth + 1))


def loads_strict(text: Union[str, bytes], *, budget: Any = None) -> Any:
    """``json.loads`` that rejects duplicate object keys at any nesting depth.

    Raises :class:`BundleFormatError` for a duplicate key (fail-closed, clear message), for
    pathologically deep nesting (both the CPython ``RecursionError`` on <=3.11 AND the explicit
    ``budget.json_depth`` bound that catches the 3.12+ case where the C scanner accepts deep input without
    raising — one stable ``"JSON nesting is too deep"`` outcome on every interpreter), and maps the
    ``int``/``str`` conversion-limit ``ValueError`` from a JSON integer literal
    with more than ``sys.get_int_max_str_digits()`` digits (CWE-674 / CVE-2020-10735) to it too —
    never a raw traceback — mirroring :func:`proofbundle.bundle.load_bundle`. Ordinary JSON syntax
    errors keep raising ``ValueError`` (``json.JSONDecodeError``) so existing ``except (ValueError,
    ...)`` handling at the call sites stays correct.

    DoS backstop (Finding 15b, crypto-review 2026-07-15): this is the ONE parse chokepoint every verify
    path funnels through, so the resource caps live here rather than at each of ~10 call sites. The raw
    ``text`` is refused BEFORE parsing when it exceeds ``budget.input_bytes`` (``json.loads`` cost scales
    with input size, so an unbounded parse of a 50 MB envelope is a real pre-loop DoS the downstream
    signature/list caps cannot reach), and the PARSED structure is refused when its combined dict-key +
    list-item count exceeds ``budget.json_nodes``. Both raise :class:`proofbundle.budget.BudgetExceeded`
    (a ``ProofBundleError`` subclass, so existing ``except (ProofBundleError, ...)`` sites treat it as
    fail-closed malformed/over-limit input). ``budget`` defaults to ``DEFAULT_BUDGET``; pass a tighter one
    to test the guard."""
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
    b = budget if budget is not None else DEFAULT_BUDGET
    if len(text) > b.input_bytes:
        from .budget import BudgetExceeded  # noqa: PLC0415
        raise BudgetExceeded("input_bytes", len(text), b.input_bytes)
    try:
        obj = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        # CPython <=3.11 raises here on deep nesting; 3.12+ accepts it and the explicit depth bound in
        # _enforce_structural_budget catches it below. Both map to the SAME BundleFormatError.
        raise BundleFormatError("JSON nesting is too deep") from exc
    except ValueError as exc:
        # The int<->str conversion cap raises a plain ValueError DURING parsing (not a JSONDecodeError),
        # which a pre-auth caller without a broad `except ValueError` would surface as a raw traceback.
        # Map only that specific case; a normal JSONDecodeError keeps raising ValueError as documented.
        if "integer string conversion" in str(exc):
            raise BundleFormatError("JSON integer literal is implausibly long (fail-closed)") from exc
        raise
    _enforce_structural_budget(obj, b.json_nodes, b.json_depth)
    return obj
