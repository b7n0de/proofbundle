"""Addendum 46e (`KRAXO-CLOUD-N46E-TYPMARKE-IM-HERKUNFTSTOKEN-01`, Z309 / 6.2.0).

The process-internal origin token (:func:`proofbundle.errors._compute_origin_token` and
:func:`proofbundle.errors._origin_token`) was not type-unique: a non-bytes part ran through ``str(...)``
and bytes and str shared one presence marker, and check name / detail ran through ``str(...)`` with no
type mark. So ``b"x"`` and ``"x"``, ``Check(1, …)`` and ``Check("1", …)``, ``detail=1`` and ``"1"``,
``None`` and ``"None"`` encoded to the SAME token, contradicting the docstring's "no two distinct inputs
collide". Addendum 46e marks every part and every check name/detail by type (None / bytes / str / other);
the order, swap and separator controls stay distinct as before. Each pair is measured RED at the 46d head
8d01590ab8cff19b7ce5f3d7a8907baa90d572b1 (the pair's two tokens were equal) and GREEN at the 46e head
(they differ). Narrowing only; the token stays process-internal and is never serialised.
"""
from __future__ import annotations

import unittest

from proofbundle.errors import Check, _compute_origin_token, _origin_token

_S = b"S" * 32
_D = "payload-digest"
_R = b"R" * 32


def _ct(checks):
    return _compute_origin_token(_S, _D, _R, checks)


class EveryPartIsTypeUnique(unittest.TestCase):
    """VERTRAG 1/2/3: a part's TYPE is bound, so values that only ``str()``-print alike no longer collide.
    RED at 8d01590a (each pair equal); GREEN at head (each pair differs)."""

    def test_bytes_and_str_part_differ(self):
        self.assertNotEqual(_origin_token(b"d", (b"x",)), _origin_token(b"d", ("x",)),
                            "a bytes part and a str part of the same text must not share a token")

    def test_int_and_str_check_name_differ(self):
        self.assertNotEqual(_ct([Check(1, True, "x")]), _ct([Check("1", True, "x")]),
                            "a check named int 1 and one named str '1' must not share a token")

    def test_int_and_str_detail_differ(self):
        self.assertNotEqual(_ct([Check("n", True, 1)]), _ct([Check("n", True, "1")]),
                            "detail int 1 and detail str '1' must not share a token")

    def test_none_and_str_none_detail_differ(self):
        self.assertNotEqual(_ct([Check("n", True, None)]), _ct([Check("n", True, "None")]),
                            "detail None and detail str 'None' must not share a token")


class TheControlsStayDistinct(unittest.TestCase):
    """The order/count/separator/ok axes were already unique and must remain so (GREEN at base and head)."""

    def test_two_swapped_checks_differ(self):
        a = _ct([Check("a", True, "x"), Check("b", True, "y")])
        b = _ct([Check("b", True, "y"), Check("a", True, "x")])
        self.assertNotEqual(a, b, "swapping two distinct checks must change the token")

    def test_a_detail_with_a_separator_is_not_a_split(self):
        self.assertNotEqual(_ct([Check("n", True, "x")]), _ct([Check("n", True, "x|y")]),
                            "length prefixes mean a detail is never a separator attack")

    def test_ok_true_and_false_differ(self):
        self.assertNotEqual(_ct([Check("n", True, "x")]), _ct([Check("n", False, "x")]),
                            "ok True and ok False must differ")


class AGenuineRunStaysAuthentic(unittest.TestCase):
    """VERTRAG 4: the real producers emit str check names and str details, so the type-marking leaves a
    genuine verification run authentic — a stamped VerificationResult still validates against a recompute."""

    def test_the_real_verify_bundle_result_is_still_authentic(self):
        from proofbundle import generate_signer, verify_bundle
        from proofbundle.emit import emit_bundle
        signer = generate_signer()
        bundle = emit_bundle(b'{"n46e":"real"}', signer)
        result = verify_bundle(bundle)
        self.assertTrue(result.ok, "a genuine bundle verifies")
        self.assertTrue(result.origin_authentic(),
                        "the stamped origin token must still authenticate under the type-marked encoding")

    def test_identity_holds_for_repeated_equal_inputs(self):
        # The encoding stays deterministic: the same (state, checks) yields the same token (no accidental
        # per-call variation introduced by the type marking).
        self.assertEqual(_ct([Check("n", True, "x")]), _ct([Check("n", True, "x")]))


if __name__ == "__main__":
    unittest.main()
