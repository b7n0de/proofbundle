"""A trace record walk keeps its memory proportional to the record, before any signature is checked.

WHERE THIS COMES FROM. The deep gate of 6.4.0, iteration 1, finding C1 at 8608cb0f. `_canonicalizable`
and `_canonicalizable_value` in `proofbundle.adapters.trace_record` gave every child a fresh path
string that copied the text of all its ancestors. Measured at 8608cb0f: a record of 64301 bytes, sixty
nested members with keys of 1000 characters over a list of 2000 numbers, peaked at 120399171 bytes of
traced memory (1872 times its size), against 3 times for a flat record of the same size, and under a
600 MiB address-space limit `verify_trace_record` raised a raw MemoryError before the signature was
looked at. The structure check that calls `_canonicalizable_value` runs even when the signature fails.

THE PROPERTY. Each child of a walk costs one link, the path is rendered only for a finding and at most
`budget._PATH_TEXT_LIMIT` characters long, and one walk renders at most `_MAX_VALUE_FINDINGS` findings and
counts the rest. A short path is rendered exactly as before.
"""
from __future__ import annotations

import base64
import json
import tracemalloc

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.adapters import trace_record as tr
from proofbundle.budget import _PATH_TEXT_LIMIT

NOW = 1792000000
_PUB = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
JWK = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(_PUB).rstrip(b"=").decode("ascii")}


def _deep(keylen: int, depth: int, items: int, leaf=0) -> bytes:
    node = [leaf] * items
    for _ in range(depth):
        node = {"a" * keylen: node}
    return json.dumps(node, separators=(",", ":")).encode("ascii")


def _flat(keylen: int, count: int, items: int) -> bytes:
    node = {"a" * keylen + str(i): 0 for i in range(count)}
    node["z"] = [0] * items
    return json.dumps(node, separators=(",", ":")).encode("ascii")


def _peak(call) -> int:
    tracemalloc.start()
    try:
        call()
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return peak


def test_a_deep_record_with_long_member_names_costs_memory_in_proportion_to_its_size():
    tr.verify_trace_record(b"{}", trusted_keys=[JWK], now=NOW)   # imports and first-call costs
    deep, flat = _deep(1000, 60, 2000), _flat(1000, 60, 2000)
    peak_deep = _peak(lambda: tr.verify_trace_record(deep, trusted_keys=[JWK], now=NOW))
    peak_flat = _peak(lambda: tr.verify_trace_record(flat, trusted_keys=[JWK], now=NOW))
    # At 8608cb0f the deep record needed 1872 times its size; the flat control 3 times.
    assert peak_deep < 50 * len(deep), (peak_deep, len(deep))
    assert peak_flat < 50 * len(flat), (peak_flat, len(flat))


def test_the_open_member_walk_bounds_its_findings_and_their_path_text():
    findings = tr._Findings()
    value = json.loads(_deep(1000, 60, 2000, leaf=0.5))
    peak = _peak(lambda: tr._canonicalizable_value(value, "cnf.jwk.extra", findings))
    assert len(findings.violations) == tr._MAX_VALUE_FINDINGS + 1
    assert findings.violations[-1].startswith("cnf.jwk.extra: and 1936 more value(s)")
    shown = findings.violations[0]
    assert len(shown.split(": ", 1)[0]) <= _PATH_TEXT_LIMIT + 1 and "…" in shown
    assert peak < 50 * len(json.dumps(value))


def test_a_short_path_is_rendered_exactly_as_before():
    record = {"a": {"b": [1, {"c d": 1e300}]}}
    assert tr._canonicalizable(record, "") == (
        'a.b[1]["c d"]: the integer value 1e+300 is outside -9007199254740991..9007199254740991 '
        "(section 3.2.2)")
    findings = tr._Findings()
    tr._canonicalizable_value({"x": [0.5]}, "cnf.jwk.extra", findings)
    assert findings.violations == [
        "cnf.jwk.extra.x[0]: must be a string, boolean, null, safe integer, array or object"]


def test_the_record_root_is_named_as_before():
    assert tr._canonicalizable(1e300, "") == (
        "<record>: the integer value 1e+300 is outside -9007199254740991..9007199254740991 (section 3.2.2)")
