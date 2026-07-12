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


def loads_strict(text: Union[str, bytes]) -> Any:
    """``json.loads`` that rejects duplicate object keys at any nesting depth.

    Raises :class:`BundleFormatError` for a duplicate key (fail-closed, clear message), maps
    ``RecursionError`` from pathologically deep nesting to the same documented malformed-input
    error, and maps the ``int``/``str`` conversion-limit ``ValueError`` from a JSON integer literal
    with more than ``sys.get_int_max_str_digits()`` digits (CWE-674 / CVE-2020-10735) to it too —
    never a raw traceback — mirroring :func:`proofbundle.bundle.load_bundle`. Ordinary JSON syntax
    errors keep raising ``ValueError`` (``json.JSONDecodeError``) so existing ``except (ValueError,
    ...)`` handling at the call sites stays correct."""
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise BundleFormatError("JSON nesting is too deep") from exc
    except ValueError as exc:
        # The int<->str conversion cap raises a plain ValueError DURING parsing (not a JSONDecodeError),
        # which a pre-auth caller without a broad `except ValueError` would surface as a raw traceback.
        # Map only that specific case; a normal JSONDecodeError keeps raising ValueError as documented.
        if "integer string conversion" in str(exc):
            raise BundleFormatError("JSON integer literal is implausibly long (fail-closed)") from exc
        raise
