"""Property-based tests (Hypothesis) for the content-root primitive (canonical.py) and the subject
binding gate (subject_binding.py) — the two pure digest-binding functions the gap survey ranked highest
for missing variation coverage.

The metamorphic relations under test:

canonical (ADR 0002 two-part rule):
  * producer == verifier: sha256(canonicalize(obj)) == statement_content_root(obj), and the bytes path
    over the canonical bytes reproduces the same root;
  * key-order invariance: two structurally-equal objects with permuted key insertion order have the SAME
    content root (RFC 8785 sorts keys).

subject_binding (O6):
  * a subject whose declared digest IS the derived predicate digest classifies DERIVED/matches;
  * ANY mutation of the predicate (so the declared digest no longer re-derives) flips to
    EXTERNAL_ATTESTED/not-matches — never silently trusted;
  * malformed subject shapes are EXTERNAL_ATTESTED, never a crash.

Needs the RFC 8785 (JCS) canonicalizer (the [eval] extra); skipped if absent, like the reference tests.
"""
from __future__ import annotations

import hashlib
import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover - dev-only dependency
    given = None

try:
    import rfc8785  # noqa: F401
    _HAS_JCS = True
except ImportError:
    _HAS_JCS = False

from proofbundle import canonical
from proofbundle.subject_binding import (
    SubjectBindingError,
    classify_subject,
    derive_subject_digest,
    require_derived_subject,
)

# JSON values RFC 8785 canonicalizes deterministically: no floats (NaN/Inf are rejected and float
# formatting is a separate concern), string keys only.
_leaves = (st.none() | st.booleans() | st.integers(min_value=-(10**12), max_value=10**12)
           | st.text(max_size=24))
_json = st.recursive(
    _leaves,
    lambda children: (st.lists(children, max_size=4)
                      | st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=4)),
    max_leaves=18,
)
_json_objects = st.dictionaries(st.text(min_size=1, max_size=10), _json, min_size=1, max_size=5)
# a predicate of literal None is indistinguishable from an ABSENT predicate to classify_subject
# (statement.get("predicate") is None), which it correctly treats as unbindable → EXTERNAL_ATTESTED. A
# real in-toto predicate is an object, never None, so the DERIVED property excludes a None predicate.
_json_predicate = _json.filter(lambda p: p is not None)


def _statement(predicate, declared=None):
    if declared is None:
        declared = derive_subject_digest(predicate)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"digest": {"sha256": declared}}],
        "predicateType": "https://proofbundle.dev/test/v1",
        "predicate": predicate,
    }


if given is not None and _HAS_JCS:

    class TestContentRootProperties(unittest.TestCase):
        @settings(max_examples=250, deadline=None)
        @given(_json_objects)
        def test_producer_equals_verifier(self, obj):
            producer = hashlib.sha256(canonical.canonicalize_statement(obj)).digest()
            root_obj = canonical.statement_content_root(obj)
            root_bytes = canonical.statement_content_root(canonical.canonicalize_statement(obj))
            self.assertEqual(producer, root_obj)
            self.assertEqual(root_obj, root_bytes)

        @settings(max_examples=250, deadline=None)
        @given(_json_objects)
        def test_key_order_invariance(self, obj):
            reordered = dict(reversed(list(obj.items())))
            self.assertEqual(canonical.statement_content_root(obj),
                             canonical.statement_content_root(reordered))

    class TestSubjectBindingProperties(unittest.TestCase):
        @settings(max_examples=250, deadline=None)
        @given(_json_predicate)
        def test_derived_subject_classifies_derived(self, predicate):
            c = classify_subject(_statement(predicate))
            self.assertEqual(c["mode"], "DERIVED")
            self.assertTrue(c["matches"])
            require_derived_subject(_statement(predicate))  # does not raise

        @settings(max_examples=250, deadline=None)
        @given(_json_objects)
        def test_mutated_predicate_flips_to_external(self, predicate):
            # bind the subject to the ORIGINAL predicate, then present a MUTATED predicate
            declared = derive_subject_digest(predicate)
            mutated = dict(predicate)
            mutated["__injected__"] = "attacker-added claim"
            c = classify_subject(_statement(mutated, declared=declared))
            self.assertEqual(c["mode"], "EXTERNAL_ATTESTED")
            self.assertFalse(c["matches"])
            with self.assertRaises(SubjectBindingError):
                require_derived_subject(_statement(mutated, declared=declared))

    class TestSubjectBindingMalformed(unittest.TestCase):
        @settings(max_examples=150, deadline=None)
        @given(st.one_of(
            st.none(), st.integers(), st.text(),
            st.fixed_dictionaries({"predicate": _json}),                       # no subject
            st.fixed_dictionaries({"subject": st.lists(_leaves, max_size=3),    # subject not [dict]
                                   "predicate": _json}),
            st.fixed_dictionaries({"subject": st.just([{"digest": {"sha256": 5}}]),  # non-str sha
                                   "predicate": _json}),
        ))
        def test_malformed_is_external_never_crash(self, statement):
            c = classify_subject(statement)
            self.assertEqual(c["mode"], "EXTERNAL_ATTESTED")
            self.assertFalse(c["matches"])


if __name__ == "__main__":
    unittest.main()
