"""S26: an absent `contentRootAlg` and a present but unusable one are not the same thing.

Deep gate run 5, finding `L1-600-CRA-01`, P3, jury 3/3. `_declared_content_root_alg` guarded with
`isinstance(alg, str) and alg`, so a PRESENT value that is not a non-empty string fell through to
the absence branch and resolved to the LEGACY algorithm with `ok=true`. An unknown STRING id
correctly failed closed one line later, which is what made the hole hard to see: the obvious case
behaved, and only the type-confused one did not.

MEASURED BEFORE THE FIX, all six resolved to legacy: `""`, `0`, `True`, `[]`, `{}`, `null`.

THE HONEST BOUNDARY. `contentRootAlg` sits INSIDE the signed payload, so this is not a signature
bypass. The damage is that the verdict describes signed content wrongly, that a receipt the
contract says to reject is accepted, and that a stricter foreign verifier rules differently on
identical bytes.

THE CLASS, which is what these cases bind: `(field ABSENT) == (resolved algorithm == LEGACY)` must
hold strictly, in both directions. The cases below therefore do not test the six reported values as
a list of special cases; they test the equivalence, and the six are the witnesses for one side of
it.
"""
from __future__ import annotations

import json
import unittest

from proofbundle import intoto

from proofbundle.intoto import (
    CONTENT_ROOT_ALG,
    LEGACY_CONTENT_ROOT_ALG,
    _declared_content_root_alg,
)

#: Values that are PRESENT and cannot name an algorithm. Not an exhaustive list of wrong types, and
#: it is not meant to be: each one is a witness that presence was read as absence.
UNUSABLE = ("", 0, True, False, [], {}, None, 1.5, b"jcs-sha256-v1")


class AbsenceAndPresenceAreDistinguished(unittest.TestCase):

    def test_absent_still_resolves_to_legacy(self):
        """The 2.0.0 receipts carry no field and must keep verifying.

        This is the case the old guard got right, and a fix that broke it would trade one defect
        for a worse one.
        """
        self.assertEqual(_declared_content_root_alg({}), LEGACY_CONTENT_ROOT_ALG)
        self.assertEqual(_declared_content_root_alg({"subject": []}), LEGACY_CONTENT_ROOT_ALG)

    def test_a_non_object_payload_still_resolves_to_legacy(self):
        """Not a Statement at all is not a declaration either; the caller rejects it one line later."""
        for nicht_objekt in (42, "x", [], None):
            with self.subTest(payload=nicht_objekt):
                self.assertEqual(_declared_content_root_alg(nicht_objekt), LEGACY_CONTENT_ROOT_ALG)

    def test_catch_present_but_unusable_never_resolves_to_legacy(self):
        """THE FINDING. Each of these is PRESENT, so none of them may read as absence."""
        for wert in UNUSABLE:
            with self.subTest(contentRootAlg=wert):
                aufgeloest = _declared_content_root_alg({"contentRootAlg": wert})
                self.assertNotEqual(
                    aufgeloest, LEGACY_CONTENT_ROOT_ALG,
                    f"a present contentRootAlg of {type(wert).__name__} resolved to legacy")

    def test_catch_present_but_unusable_is_refused_by_the_serializer(self):
        """Not resolving to legacy is only half; it must also be refused downstream.

        A sentinel that no registered algorithm matches is what makes the refusal happen, and this
        case binds that it really does not match either registered id, rather than trusting the
        name to look unregistered.
        """
        for wert in UNUSABLE:
            with self.subTest(contentRootAlg=wert):
                aufgeloest = _declared_content_root_alg({"contentRootAlg": wert})
                self.assertNotIn(aufgeloest, (CONTENT_ROOT_ALG, LEGACY_CONTENT_ROOT_ALG))

    def test_counter_direction_a_registered_id_passes_through(self):
        """Without this the rule could refuse everything and still look correct.

        A declared, registered algorithm must arrive unchanged; the registration check belongs to
        the serializer, not here.
        """
        for gueltig in (CONTENT_ROOT_ALG, LEGACY_CONTENT_ROOT_ALG):
            with self.subTest(contentRootAlg=gueltig):
                self.assertEqual(_declared_content_root_alg({"contentRootAlg": gueltig}), gueltig)

    def test_an_unknown_string_id_is_unchanged_by_this_fix(self):
        """The behaviour that was already correct stays correct: an unknown id is handed on as
        declared, and the serializer refuses it. This case exists so a later simplification cannot
        quietly fold unknown strings into the sentinel and lose the declared value from the verdict.
        """
        self.assertEqual(_declared_content_root_alg({"contentRootAlg": "not-registered-v9"}),
                         "not-registered-v9")


if __name__ == "__main__":
    unittest.main()


# ───── Codex finding on PR 254: the sentinel must not appear as a declaration ─────


class TheSentinelIsNotASignedDeclaration(unittest.TestCase):
    """The verdict was right and still described the payload wrongly.

    Codex, review of 2026-09-23: for canonical bytes of `{"contentRootAlg":null}`,
    `_content_root_binding` correctly reported ok=False and then named
    `content_root_alg="invalid-contentRootAlg"` and "unknown contentRootAlg
    'invalid-contentRootAlg'". That string appears NOWHERE in the signed payload, and the same held
    for every unusable type. The shared builder feeds all three `verify_*_dsse` surfaces, so one
    place carried the error outward three times.

    The signature boundary and the fail-closed verdict were never in question. What was wrong is
    the claim that the document declared something it did not, against this code's own promise that
    the verdict names what was found.
    """

    def _binding(self, wert):
        st = {"_type": "x", "subject": [], "predicateType": "p", "predicate": {},
              "contentRootAlg": wert}
        body = json.dumps(st, sort_keys=True, separators=(",", ":")).encode()
        return intoto._content_root_binding(st, body)

    def test_no_unusable_value_is_reported_as_a_declaration(self):
        for wert in (None, "", 0, True, [], {}):
            with self.subTest(wert=wert):
                ok, gemeldet, meldung = self._binding(wert)
                self.assertFalse(ok, "unusable stays fail-closed")
                self.assertIsNone(gemeldet,
                                  "nothing usable declared means None, not an invented name")
                self.assertNotIn("invalid-contentRootAlg", meldung,
                                 "the sentinel decides, it is not signed content")

    def test_the_message_names_what_was_actually_there(self):
        """A verdict that does not name the finding is half of the earlier mistake."""
        _, _, meldung = self._binding(0)
        self.assertIn("int", meldung, "the type found belongs in the message")
        _, _, meldung = self._binding([])
        self.assertIn("list", meldung)

    def test_counter_direction_absent_stays_legacy_and_is_reported(self):
        """WITHOUT THIS CASE a builder that ALWAYS reports None would pass, and 2.0.0 would break."""
        st = {"_type": "x", "subject": [], "predicateType": "p", "predicate": {}}
        body = json.dumps(st, sort_keys=True, separators=(",", ":")).encode()
        ok, gemeldet, _ = intoto._content_root_binding(st, body)
        self.assertTrue(ok, "a document without the field is a 2.0.0 receipt and verifies")
        self.assertEqual(gemeldet, intoto.LEGACY_CONTENT_ROOT_ALG,
                         "absent resolves to legacy, and that is what gets reported")
