"""A long declared path costs the closure and the type walk no text per prefix, and its messages are cut like any other.

WHERE THIS COMES FROM. Finding F1 of the counter-reading of C1 (pull request 430, head 47fcb770, P2):
`subject_binding._declared_prefixes` kept every prefix of every declared path as a string of its own, and the walks
built the text of every node on a declared prefix, so a declared path of k names cost memory in proportion to k times
its length, and a message on a declared path named it whole, past the limit of 256 characters the CHANGELOG states for
the five walks. The callers in the package pass fixed module maps (decision.py, outcome.py), so F1 is reached only by
a direct call with a long declaration of its own.

THE PROPERTY:
* for a plain dict map the walks keep a position in the sorted declared paths, three integers, and build no path text
  until a message needs it, so a long declaration costs memory in proportion to its own size;
* a message on a declared path renders at most `budget._PATH_TEXT_LIMIT` characters of it and marks the cut with "…";
* the position keeps exactly the paths the set of `_declared_prefixes` keeps, measured against that set itself, and a
  dict subclass, which keeps the text, reports what a recursive reference walk reports.
"""
from __future__ import annotations

import json
import random
import tracemalloc

import pytest

from proofbundle.budget import _PATH_TEXT_LIMIT, DEFAULT_BUDGET
from proofbundle.subject_binding import (
    _child_text,
    _declared_prefixes,
    _item_text,
    _kept,
    nested_closure_violations,
    nested_type_violations,
)
from test_walk_paths_are_links_until_a_message_needs_them import (
    _KEYS,
    _declared,
    _reference_closure,
    _reference_types,
    _value,
)

_NAMES = 400
_NAME = "a" * 100


def _peak(call) -> int:
    tracemalloc.start()
    try:
        call()
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return peak


def _long_declaration() -> "tuple[object, str]":
    """A declared path of 400 names of 100 characters, and an input that follows it as deep as the budget allows."""
    path = ".".join([_NAME] * _NAMES)
    value: object = {"x": 1}
    for _ in range(DEFAULT_BUDGET.json_depth - 1):
        value = {_NAME: value}
    return value, path


@pytest.mark.parametrize("walk", ["closure", "type"])
def test_a_long_declared_path_costs_memory_in_proportion_to_its_size(walk):
    value, path = _long_declaration()
    if walk == "closure":
        call = lambda: nested_closure_violations(value, {path: ("x",)})  # noqa: E731
    else:
        call = lambda: nested_type_violations(value, {path: "string"})  # noqa: E731
    call()   # imports and first-call costs
    size = len(json.dumps(value)) + len(path)
    peak = _peak(call)
    # With a text per prefix the declaration alone held about 100 * 400**2 / 2 characters, 200 times its size.
    assert peak < 50 * size, (walk, peak, size)


def test_a_message_on_a_long_declared_path_is_cut_at_the_limit():
    deep = ".".join(["b" * 100] * 4)
    value: object = {"sneaky": 1}
    for _ in range(4):
        value = {"b" * 100: value}
    closure = nested_closure_violations(value, {deep: ("x",)})
    assert closure == ["b" * 100 + "." + "b" * 100 + "." + "b" * 54 + "….sneaky: undeclared nested key "
                       "(nested closure violated)"], closure
    types = nested_type_violations(value, {deep: "string"})
    assert len(types) == 1 and types[0].startswith(deep[:_PATH_TEXT_LIMIT] + "…: must be string, got "), types


def test_a_depth_message_on_a_long_declared_prefix_is_cut_at_the_limit():
    value: object = 0
    for _ in range(DEFAULT_BUDGET.json_depth + 2):
        value = {"c" * 300: value}
    declared = ".".join(["c" * 300] * (DEFAULT_BUDGET.json_depth + 3))
    depth = [m for m in nested_closure_violations(value, {declared: ()}) + nested_type_violations(
        value, {declared: "object"}) if "nesting exceeds the validation depth budget" in m]
    assert len(depth) == 2, depth
    for message in depth:
        assert message.startswith("c" * _PATH_TEXT_LIMIT + "…: "), message[:300]


class _Map(dict):
    """A dict subclass: the walks keep the text for it and look every kept prefix up with its own ``get``."""


@pytest.mark.parametrize("seed", range(0, 600, 3))
def test_a_dict_subclass_reports_what_a_recursive_walk_reports(seed):
    rng = random.Random(seed)
    value = _value(rng)
    start = rng.choice(["", "", "x"])
    allowed = {p: tuple(rng.sample(_KEYS, rng.randint(0, 3))) for p in _declared(rng, value)}
    kinds = {p: rng.choice(["string", "object", "array", ("string", "null")]) for p in _declared(rng, value)}
    assert nested_closure_violations(value, _Map(allowed), path=start) == _reference_closure(value, allowed, start)
    assert nested_closure_violations(value, allowed, path=start) == _reference_closure(value, allowed, start)
    assert nested_type_violations(value, _Map(kinds)) == _reference_types(value, kinds)
    assert nested_type_violations(value, kinds) == _reference_types(value, kinds)


_PIECES = ("a", "b", "", ".", "[]", "a.b", "b[]", "[", "]", "ab")


@pytest.mark.parametrize("seed", range(400))
def test_the_position_keeps_exactly_the_paths_the_prefix_set_keeps(seed):
    """The oracle is the set `_declared_prefixes` builds for a dict subclass, the text form it always had."""
    rng = random.Random(seed)
    paths = {"".join(rng.choice(_PIECES) for _ in range(rng.randint(0, 5))): () for _ in range(rng.randint(0, 6))}
    sorted_form, text_form = _declared_prefixes(dict(paths)), _declared_prefixes(_Map(paths))
    assert type(sorted_form) is tuple and type(text_form) is frozenset
    for _ in range(30):
        text = rng.choice(["", "", "a", "b", "x"])
        pos, kept = _kept(sorted_form, text), _kept(text_form, text)
        for _ in range(rng.randint(0, 5)):
            assert (pos is None) == (kept is None), (paths, text)
            if kept is None:
                break
            if rng.random() < 0.3:
                pos, kept = _item_text(sorted_form, pos), _item_text(text_form, kept)
                text += "[]"
            else:
                name = rng.choice(_PIECES)
                pos, kept = _child_text(sorted_form, pos, name), _child_text(text_form, kept, name)
                text = f"{text}.{name}" if text else name
        assert (pos is None) == (kept is None), (paths, text)
