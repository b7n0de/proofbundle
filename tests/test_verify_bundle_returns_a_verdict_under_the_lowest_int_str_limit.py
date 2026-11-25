"""verify_bundle(dict) returns a verdict under the lowest int-to-str limit a host can set.

`_require_int` bounds the magnitude of `merkle.leaf_index` and `merkle.tree_size` at the budget's `int_bits`
(8192 bits, up to 2,467 decimal digits), so that such a value is never rendered into a detail message and trips
CPython's int-to-str cap as a raw ValueError out of `verify_bundle(dict)`. That bound is enough under the default
limit of 4300 digits. A host may lower the limit down to `sys.int_info.str_digits_check_threshold` (640), and an
integer the bound admits can then not be written with a plain f-string.

Two messages of `verify_bundle` wrote such an integer that way (measured at bcdb8146 and at v6.6.0):

- the inclusion line. 6.6.1 built it with both integers before it knew whether the inclusion held, so every
  bundle with such an integer left `verify_bundle` as a raw ValueError where 6.6.0 returned `ok = False`. On the
  passing path 6.6.0 raised as well: the last leaf of a tree of 2**2200 + 1 entries has an audit path of one
  step, so the inclusion holds under a tree size of 663 digits.
- the `tree-size` line, in each of its three branches, whenever the caller passes `expected_tree_size`.

Both are built with the bounded renderer (`budget.render_safe`), and the inclusion line on the passing path
only. For an integer that can be written, each text is what it was.

The limit is process-wide, so each case sets it and restores the previous value.
"""
from __future__ import annotations

import base64
import hashlib
import sys

import pytest

from proofbundle.budget import int_magnitude_ok
from proofbundle.bundle import verify_bundle
from proofbundle.errors import BundleFormatError

pytestmark = pytest.mark.skipif(not hasattr(sys, "set_int_max_str_digits"),
                                reason="this interpreter has no int-to-str limit to lower")

_PAYLOAD = b"x"
_LEAF = hashlib.sha256(b"\x00" + _PAYLOAD).digest()        # the root of the tree that holds exactly this leaf
_HUGE = 10 ** 700                                           # 701 digits: under int_bits, over the lowest limit
_LAST = 2 ** 2200                                           # index of the last leaf in a tree of _LAST + 1 entries
_LEFT = bytes([7]) * 32                                     # the one step of that leaf's audit path
_ROOT_OF_LAST = hashlib.sha256(b"\x01" + _LEFT + _LEAF).digest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _bundle(leaf_index: int, tree_size: int, root: bytes, proof=()) -> dict:
    return {"schema": "proofbundle/v0.1", "payload_b64": _b64(_PAYLOAD),
            "signature": {"alg": "ed25519", "public_key_b64": _b64(bytes([9]) * 32), "sig_b64": _b64(bytes(64))},
            "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": leaf_index, "tree_size": tree_size,
                       "inclusion_proof_b64": [_b64(p) for p in proof], "root_b64": _b64(root)}}


def _detail(result, name: str) -> str:
    found = [c.detail for c in result.checks if c.name == name]
    assert len(found) == 1, (name, [c.name for c in result.checks])
    return found[0]


@pytest.fixture
def lowest_limit():
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(sys.int_info.str_digits_check_threshold)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


def test_CONTROL_the_limit_binds_and_the_integers_are_under_the_magnitude_bound(lowest_limit):
    """Without this the cases below would pass for a reason that has nothing to do with the verifier."""
    for value in (_HUGE, -_HUGE, _LAST + 1):
        assert int_magnitude_ok(value)
        with pytest.raises(ValueError):
            str(value)


_FAILING_INCLUSION = [
    ("huge tree_size, wrong root", 0, _HUGE, bytes(32)),
    ("huge tree_size, the leaf's own root", 0, _HUGE, _LEAF),
    ("huge leaf_index, tree_size 1", _HUGE, 1, _LEAF),
    ("huge leaf_index and tree_size", _HUGE - 1, _HUGE, bytes(32)),
    ("huge negative leaf_index", -_HUGE, 1, _LEAF),
]


@pytest.mark.parametrize("name,leaf_index,tree_size,root", _FAILING_INCLUSION,
                         ids=[c[0] for c in _FAILING_INCLUSION])
def test_a_failing_inclusion_with_an_unwritable_integer_gets_a_verdict(lowest_limit, name, leaf_index,
                                                                      tree_size, root):
    try:
        result = verify_bundle(_bundle(leaf_index, tree_size, root))
    except BundleFormatError:
        return                                  # a clean refusal is a verdict of form, not a raw exception
    assert result.ok is False, name
    assert _detail(result, "merkle-inclusion") == "inclusion proof failed"


def test_a_passing_inclusion_under_an_unwritable_tree_size_gets_a_verdict(lowest_limit):
    """The inclusion holds, so the line names index and tree size: the path that raised in 6.6.0 too."""
    result = verify_bundle(_bundle(_LAST, _LAST + 1, _ROOT_OF_LAST, proof=(_LEFT,)))
    assert [c.ok for c in result.checks if c.name == "merkle-inclusion"] == [True]
    assert "Merkle-consistent under the STATED root" in _detail(result, "merkle-inclusion")
    assert result.ok is False                   # the signature of this bundle is not a valid one


def test_a_passing_inclusion_under_a_bound_unwritable_tree_size_gets_a_verdict(lowest_limit):
    """The bound form of the line: the caller's expected size is the stated one, so the other label is built."""
    result = verify_bundle(_bundle(_LAST, _LAST + 1, _ROOT_OF_LAST, proof=(_LEFT,)),
                           expected_tree_size=_LAST + 1)
    assert [c.ok for c in result.checks if c.name == "merkle-inclusion"] == [True]
    assert _detail(result, "merkle-inclusion").startswith("anchored at index ")
    assert [c.ok for c in result.checks if c.name == "tree-size"] == [True]


_OUT_OF_RANGE = 2 ** 9000                                  # past int_bits: the third branch names no expectation
_TREE_SIZE_LINE = [
    ("stated size unwritable, expectation small", _bundle(0, _HUGE, bytes(32)), 5, False),
    ("stated size unwritable, expectation equal", _bundle(0, _HUGE, bytes(32)), _HUGE, True),
    ("stated size small, expectation unwritable", _bundle(0, 1, _LEAF), _HUGE, False),
    ("stated size unwritable, expectation ill-typed", _bundle(0, _HUGE, bytes(32)), True, False),
    ("stated size unwritable, expectation out of range", _bundle(0, _HUGE, bytes(32)), _OUT_OF_RANGE, False),
]


@pytest.mark.parametrize("name,bundle,expected,size_ok", _TREE_SIZE_LINE, ids=[c[0] for c in _TREE_SIZE_LINE])
def test_the_tree_size_line_with_an_unwritable_integer_gets_a_verdict(lowest_limit, name, bundle, expected,
                                                                     size_ok):
    result = verify_bundle(bundle, expected_tree_size=expected)
    assert [c.ok for c in result.checks if c.name == "tree-size"] == [size_ok], name
    assert result.ok is False


def test_CONTROL_each_text_is_unchanged_for_an_integer_that_can_be_written():
    """The renderer writes an ordinary integer as `str()` does, so no message a caller may compare moved."""
    unbound = verify_bundle(_bundle(0, 1, _LEAF))
    assert _detail(unbound, "merkle-inclusion") == (
        "anchored at stated index 0 of stated tree size 1 (Merkle-consistent under the STATED root)")
    bound = verify_bundle(_bundle(0, 1, _LEAF), expected_tree_size=1)
    assert _detail(bound, "merkle-inclusion") == (
        "anchored at index 0 of 1 (Merkle-consistent under the STATED root)")
    assert _detail(bound, "tree-size") == "tree_size 1 matches the expected size"
    other = verify_bundle(_bundle(0, 1, _LEAF), expected_tree_size=2)
    assert _detail(other, "tree-size") == "tree_size 1 != expected 2 — possible tree-size substitution"
    ill_typed = verify_bundle(_bundle(0, 1, _LEAF), expected_tree_size=True)
    assert _detail(ill_typed, "tree-size") == (
        "tree_size 1 != expected (ill-typed or out-of-range expectation) — possible tree-size substitution")


def test_CONTROL_the_ordinary_bundle_is_still_judged_under_the_lowest_limit(lowest_limit):
    result = verify_bundle(_bundle(0, 1, _LEAF), expected_tree_size=1)
    assert _detail(result, "merkle-inclusion") == (
        "anchored at index 0 of 1 (Merkle-consistent under the STATED root)")
    assert _detail(result, "tree-size") == "tree_size 1 matches the expected size"
