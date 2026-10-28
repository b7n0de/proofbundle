"""Every walk that names a path in a message carries the path as a link and renders it only for that message.

WHERE THIS COMES FROM. The deep gate of 6.4.0, iteration 1, finding C1 at 8608cb0f
(`trace_record._canonicalizable_value`, see tests/test_trace_record_member_paths_are_built_on_demand.py), and the
three neighbours a sweep for the same assumption found at e29a2683: `_plain_value.plain_json`,
`subject_binding.nested_closure_violations` and `subject_binding.nested_type_violations`. Each gave every child a path
string that copied the text of all its ancestors. Measured with an input of 73190 bytes, fifty nested members with
names of 1000 characters over 2000 members: each peaked at about 100 MB of traced memory, 1373 to 1376 times the
input, against 3 to 5 times for a flat input of the same size.

THE PROPERTY, at every one of these walks:
* a deep input costs memory in proportion to its size, as a flat one does;
* a message renders at most `budget._PATH_TEXT_LIMIT` characters of path and marks a cut with "…";
* a message about a short path is the message the walk gave before. The closure and the type walk are compared with a
  recursive reference walk on generated inputs, and a refusal of `plain_json` with the path at which the generator
  planted the refused value.
"""
from __future__ import annotations

import json
import random
import tracemalloc

import pytest
from _lastdeckel import gedeckelt

from proofbundle._plain_value import plain_json
from proofbundle.adapters import trace_record as tr
from proofbundle.budget import _PATH_TEXT_LIMIT, DEFAULT_BUDGET, render_safe
from proofbundle.subject_binding import _has_type, nested_closure_violations, nested_type_violations

# The depth budget, capped as a test load (tests/_lastdeckel.py): the dearest level built here is a member of
# 300 characters.
_DEPTH = gedeckelt(DEFAULT_BUDGET.json_depth, bytes_je_element=400)


def _deep(keylen: int, depth: int, children: int) -> dict:
    node = {f"k{i}": 0 for i in range(children)}
    for _ in range(depth):
        node = {"a" * keylen: node}
    return node


def _flat(keylen: int, count: int, children: int) -> dict:
    node = {"a" * keylen + str(i): 0 for i in range(count)}
    node["z"] = {f"k{i}": 0 for i in range(children)}
    return node


def _peak(call) -> int:
    tracemalloc.start()
    try:
        call()
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return peak


WALKS = {
    "plain_json": lambda o: plain_json(o, what="probe", error=ValueError),
    "nested_closure_violations": lambda o: nested_closure_violations(o, {"": ("x",)}),
    "nested_type_violations": lambda o: nested_type_violations(o, {"x": "string"}),
    "trace_record._canonicalizable": lambda o: tr._canonicalizable(o, ""),
    "trace_record._canonicalizable_value": lambda o: tr._canonicalizable_value(o, "x", tr._Findings()),
}


@pytest.mark.parametrize("name", sorted(WALKS))
def test_a_deep_input_costs_memory_in_proportion_to_its_size(name):
    walk = WALKS[name]
    walk({"a": [1]})   # imports and first-call costs
    deep, flat = _deep(1000, 50, 2000), _flat(1000, 50, 2000)
    size_deep, size_flat = len(json.dumps(deep)), len(json.dumps(flat))
    peak_deep, peak_flat = _peak(lambda: walk(deep)), _peak(lambda: walk(flat))
    # At e29a2683 the three neighbours needed 1373 to 1376 times the deep input, and 3 to 5 times the flat one.
    assert peak_deep < 50 * size_deep, (name, peak_deep, size_deep)
    assert peak_flat < 50 * size_flat, (name, peak_flat, size_flat)


def _path_part(message: str, label: str, tail: str) -> str:
    assert message.startswith(label) and tail in message, message
    return message[len(label):message.index(tail)]


def test_a_refusal_below_a_long_path_names_the_path_cut_at_the_limit():
    value: object = object()
    for _ in range(50):
        value = {"a" * 1000: value}
    with pytest.raises(ValueError) as caught:
        plain_json(value, what="probe", error=ValueError)
    shown = _path_part(str(caught.value), "probe", " is of type object;")
    assert shown == "." + "a" * (_PATH_TEXT_LIMIT - 1) + "…"


def test_a_depth_message_below_a_long_undeclared_path_is_cut_at_the_limit():
    value: object = 0
    for _ in range(_DEPTH + 2):
        value = {"b" * 300: value}
    closure = nested_closure_violations(value, {"": ("x",)})
    types = nested_type_violations(value, {"x": "string"})
    depth = [m for m in closure + types if "nesting exceeds the validation depth budget" in m]
    assert len(depth) == 2, closure + types
    for message in depth:
        assert message.startswith("b" * _PATH_TEXT_LIMIT + "…: "), message[:300]


def test_a_refusal_too_deep_names_the_path_of_the_node_past_the_limit():
    value: object = 0
    for _ in range(_DEPTH):
        value = [value]
    with pytest.raises(ValueError) as caught:
        plain_json(value, what="probe", error=ValueError)
    assert str(caught.value) == f"probe{'[0]' * _DEPTH} nests deeper than {_DEPTH} levels"


# --- generated inputs against an independent reference --------------------------------------------------------------

_KEYS = ("a", "b", "a.b", "", "[]", "b[]", ".", "x")


def _tree(rng: random.Random, depth: int):
    roll = rng.random()
    if depth > 4 or roll < 0.3:
        return rng.choice([0, 1.5, "s", True, None, [], {}])
    if roll < 0.65:
        out = {}
        for _ in range(rng.randint(1, 3)):
            out[rng.choice(_KEYS)] = _tree(rng, depth + 1)
        return out
    return [_tree(rng, depth + 1) for _ in range(rng.randint(1, 3))]


def _chain(rng: random.Random, inner):
    """``inner`` below a chain of one-character members and single items that may pass the depth budget."""
    for _ in range(rng.randint(_DEPTH - 4, _DEPTH + 4)):
        inner = {"c": inner} if rng.random() < 0.6 else [inner]
    return inner


def _paths(value, path: str = "") -> list:
    out = [path]
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                out += _paths(v, f"{path}.{k}" if path else k)
    elif isinstance(value, list):
        for v in value:
            out += _paths(v, f"{path}[]")
    return out


def _value(rng: random.Random):
    value = _tree(rng, 0)
    if rng.random() < 0.3:
        value = _chain(rng, value) if rng.random() < 0.5 else {"d": _chain(rng, value), "e": _tree(rng, 2)}
    return value


def _declared(rng: random.Random, value) -> list:
    known = sorted(set(_paths(value)))
    chosen = rng.sample(known, min(len(known), rng.randint(0, 6)))
    return chosen + rng.sample(["zz", "a[].b", "x.y", "c.c.c", "[].a"], rng.randint(0, 2))


def _reference_closure(obj, allowed_map: dict, start: str) -> list:
    out: list = []

    def walk(cur, path: str, depth: int) -> None:
        if depth > _DEPTH:
            out.append(f"{path or '<root>'}: nesting exceeds the validation depth budget (nested closure fail-closed)")
            return
        if isinstance(cur, dict):
            allowed = allowed_map.get(path)
            if allowed is not None:
                for k in cur:
                    if k not in allowed:
                        out.append(f"{path or '<root>'}.{render_safe(k, quote=False)}: undeclared nested key "
                                   "(nested closure violated)")
            for k, v in cur.items():
                name = k if isinstance(k, str) else render_safe(k, quote=False)
                walk(v, f"{path}.{name}" if path else name, depth + 1)
        elif isinstance(cur, list):
            for v in cur:
                walk(v, f"{path}[]", depth + 1)

    walk(obj, start, 0)
    return out


def _reference_types(obj, type_map: dict) -> list:
    out: list = []

    def walk(cur, path: str, depth: int) -> None:
        if depth > _DEPTH:
            out.append(f"{path or '<root>'}: nesting exceeds the validation depth budget (type check fail-closed)")
            return
        want = type_map.get(path)
        if want is not None:
            kinds = (want,) if isinstance(want, str) else want
            if not any(_has_type(cur, k) for k in kinds):
                out.append(f"{path}: must be {' or '.join(kinds)}, got {render_safe(cur)}")
                return
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str):
                    walk(v, f"{path}.{k}" if path else k, depth + 1)
        elif isinstance(cur, list):
            for v in cur:
                walk(v, f"{path}[]", depth + 1)

    walk(obj, "", 0)
    return out


@pytest.mark.parametrize("seed", range(0, 1200, 3))
def test_the_closure_walk_reports_what_a_recursive_walk_reports(seed):
    rng = random.Random(seed)
    value = _value(rng)
    if isinstance(value, dict) and rng.random() < 0.3:
        value[5] = _tree(rng, 2)            # a key of a direct caller that is no text
    start = rng.choice(["", "", "x"])
    allowed_map = {p: tuple(rng.sample(_KEYS, rng.randint(0, 3))) for p in _declared(rng, value)}
    expected = _reference_closure(value, allowed_map, start)
    assert nested_closure_violations(value, allowed_map, path=start) == expected


@pytest.mark.parametrize("seed", range(1, 1200, 3))
def test_the_type_walk_reports_what_a_recursive_walk_reports(seed):
    rng = random.Random(seed)
    value = _value(rng)
    kinds = ["string", "object", "array", "boolean", "null", ("string", "null"), ("object", "array")]
    type_map = {p: rng.choice(kinds) for p in _declared(rng, value)}
    expected = _reference_types(value, type_map)
    assert nested_type_violations(value, type_map) == expected


def _plant(rng: random.Random, value, bad) -> "tuple[object, str]":
    """``value`` with ``bad`` in place of one of its leaves or as a new member, and the path of that place."""
    if isinstance(value, dict) and (not value or rng.random() < 0.4):
        key = rng.choice(_KEYS)
        value[key] = bad
        return value, f".{key}"
    if isinstance(value, list) and (not value or rng.random() < 0.4):
        value.append(bad)
        return value, f"[{len(value) - 1}]"
    if isinstance(value, dict):
        key = rng.choice(sorted(value))
        value[key], below = _plant(rng, value[key], bad)
        return value, f".{key}{below}"
    if isinstance(value, list):
        i = rng.randrange(len(value))
        value[i], below = _plant(rng, value[i], bad)
        return value, f"[{i}]{below}"
    return bad, ""


@pytest.mark.parametrize("seed", range(2, 1200, 3))
def test_a_refusal_of_plain_json_names_the_path_where_the_value_was_planted(seed):
    rng = random.Random(seed)
    value, path = _plant(rng, _tree(rng, 0), object())
    with pytest.raises(ValueError) as caught:
        plain_json(value, what="probe", error=ValueError)
    assert str(caught.value) == (f"probe{path} is of type object; a JSON value is null, a boolean, an exact int or "
                                 "float, text, a list, a tuple or a dict")
