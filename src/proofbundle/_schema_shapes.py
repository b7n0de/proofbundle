"""The primitive shapes the published schemas share, read the way the schemas read them.

THE DEFECT CLASS, stated as the violated assumption: *a Python regular expression copied from a JSON
Schema pattern means what the pattern means.* It does not. A `pattern` in schemas/ is an ECMA-262
regular expression (JSON Schema 2020-12, core section 6.4), and two differences reach the patterns
these schemas use (measured 2026-09-26 against node 22's RegExp, with and without the `u` flag):

* `$` in Python matches before a trailing newline; in ECMA-262 without the multiline flag it matches
  only at the end of the input. `\\A..\\Z` is the Python spelling of what the schema says.
* `\\d` in a Python str pattern matches every Unicode decimal digit (Arabic-Indic, fullwidth, ...);
  in ECMA-262 it is `[0-9]`, with or without the `u` flag.

And one difference of reading rather than of regex: `sha256Digest` is `additionalProperties: false`
in all five predicate schemas, and a check that reads only the `sha256` key accepts
``{"sha256": ..., "anything": ...}``.

MEASURED at 3562dc71 before this module existed: the digest checks of decision, outcome, run_ledger,
verification_summary and trust_pack accepted a digest object with a second key; trust_pack still
anchored with `^..$`, so a signed trust pack whose `expires` ended in a newline verified ok=True;
every RFC3339 and 0.1.x pattern in eight modules took Unicode digits, so `validate_decision_predicate`
in strict mode accepted a fullwidth `decidedAt`, and on one signed relation statement whose edge
`declaredAt` used them the Python verifier said ok (exit 0) where the Rust verifier said FAIL (exit 2).

WHY ONE MODULE. The `^..$` fix of a9269f65 (2026-07-18) changed eight modules, its guard named the
modules it checked by hand, and trust_pack was on neither list, so it kept `^..$`. Every module that checks a field of these schemas now reads
these definitions, and
tests/test_every_validator_refuses_what_its_schema_refuses.py walks every regular expression literal
under src/proofbundle so that a private copy with the old reading cannot come back unnoticed.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = ["SHA256_HEX", "RFC3339_Z", "SEMVER_0_1_X", "is_sha256_digest"]

#: `sha256Digest.sha256` and every other 64-hex digest string: lowercase, exactly 64, nothing after.
SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
#: `rfc3339z`: RFC 3339 with a mandatory trailing Z, ASCII digits only.
RFC3339_Z = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z\Z")
#: `schemaVersion` of the 0.1 predicates.
SEMVER_0_1_X = re.compile(r"\A0\.1\.[0-9]+\Z")


def is_sha256_digest(obj: Any) -> bool:
    """The schemas' `sha256Digest`: an object whose ONLY key is `sha256`, holding 64 lowercase hex."""
    return (isinstance(obj, dict) and len(obj) == 1 and isinstance(obj.get("sha256"), str)
            and bool(SHA256_HEX.match(obj["sha256"])))
