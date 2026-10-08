"""One read of a caller's value, from its own storage, into exact built-in types.

THE CLASS (lens run 8 at fddc00f4, findings A, B and D). A producer checked a caller's value through
one read and wrote it through another. Round 8 closed that for key bytes (`signature.plain_bytes`,
`signature.plain_text`); the lens then measured the same split on every other value a producer both
checks and writes:

* A: `checkpoint.vkey` checked a name's stored text, hashed `keyname.encode()` into the key ID and
  wrote `f"{keyname}+…"`, the caller's `__format__`. A `str` subclass name wrote a whole vkey line for
  the identity point in front of the real one, and v6.0.0 and v6.1.0 accept that line.
* B: `sign_trust_pack` checked `for kid in signers` and signed `signers.items()`; the three `assemble`
  steps checked a body through `items()` or `__getitem__` and copied its storage; `instantiate_template`
  checked an overlay through `__iter__` and a policy_id through `__eq__`; `issue_sd_jwt` checked a
  status through `__contains__`. Each time the caller's class decided what the check saw.
* D: `trust_pack._read_once` read numbers through the caller's `__float__` and `__int__`, so a float
  subclass storing 1.5 whose `__float__` answers 1.0 was signed as version 1.

THE RULE. A producer reads each value it checks and writes ONCE, through the readers here, and the
check and the writer use only what they return. No method a caller's class can define runs:

* text is `str.__str__` of a `str` (subclasses included, read from storage; `signature.plain_text`);
* a number is an exact `int` (not `bool`) or an exact `float`, and nothing else: a subclass of `int` or
  `float` and a numpy scalar are refused, because their only reads are the caller's methods or a
  conversion the caller controls;
* a JSON value is copied by `plain_json`, which reads a `dict` through `dict.items` (an `OrderedDict`
  in its own order, see below), a `list` through `list.copy` and a `tuple` through `tuple.__iter__` —
  the base methods, which read the stored items of a subclass without calling its overrides — keeps
  `None`, exact `bool`, exact `int`, exact `float` and text, preserves the kind of each container, and
  refuses everything else with the caller's own typed error naming the parameter and the path.

A legitimate value is copied to an equal value of the same kinds in the same order, so every
serialiser writes the same bytes for it as before; only a value whose class answered for something
else than it holds changes its fate.

TWO READS THAT STILL RAN THE CALLER'S CODE, found when the 6.2.0 chain carried D4 (PR 300), whose
copy `canonical._plain_for_jcs` had closed both in its rounds 9 and 10, and whose tests measured them
here. ``OrderedDict.items`` hashes every key of the OrderedDict's own list to find its node, so a
``str`` subclass key ran its own ``__hash__`` and ``__eq__``, and an OrderedDict whose storage was
written past its own methods raised a raw KeyError; and a refusal named the type through
``type(x).__name__``, which runs a metaclass's ``__name__`` property and raised a raw AttributeError
for a type whose name cannot be read. An OrderedDict is now read in its own order by the reader the
JCS copy uses (`canonical._in_eigener_reihenfolge`: every key of type ``str`` itself and nothing else
in its list, or a refusal before anything is hashed), and a type is named by
`_membership.type_name`. Both copies therefore give the same answer for every OrderedDict.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any, Callable, Optional

from ._membership import type_name
from .canonical import _Abweisung, _in_eigener_reihenfolge
from .signature import plain_text

__all__ = ["plain_int", "plain_list", "plain_json"]


def plain_list(value: Any) -> "list | None":
    """The items a ``list`` or ``tuple`` holds, read once from its storage into a new exact ``list``
    (``list.copy`` and ``tuple.__iter__`` of the base types, which call no override of a subclass), or
    None for any other value. The items themselves are handed on as they are stored."""
    t = type(value)
    if issubclass(t, list):
        return list.copy(value)
    if issubclass(t, tuple):
        return list(tuple.__iter__(value))
    return None


def plain_int(value: Any) -> "int | None":
    """``value`` if it is an exact ``int`` (not a ``bool``, not a subclass), else None. An exact int
    has no method a caller can define, so the check and the writer read the same number."""
    return value if type(value) is int else None


def _depth_and_nodes(budget: Any) -> "tuple[int, int]":
    if budget is None:
        from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
        budget = DEFAULT_BUDGET
    return budget.json_depth, budget.json_nodes


def plain_json(value: Any, *, what: str, error: Callable[[str], BaseException],
               budget: Optional[Any] = None) -> Any:
    """The caller's JSON value ``value`` read ONCE from its own storage, as exact built-in types.

    ``what`` names the parameter in a refusal; ``error`` maps the refusal text to the exception the
    calling producer documents (``TrustPackError``, ``PolicyError``, ``ValueError``, ``SystemExit``…).
    Bounded like the structural budget every canonicaliser of this package applies
    (``json_depth``, counted from 1 at the root and including scalars, and ``json_nodes``, the sum of
    all container lengths): a value that nests itself or shares one container along exponentially many
    paths is refused before it is copied. Iterative, so a deep value never reaches the recursion limit."""
    max_depth, max_nodes = _depth_and_nodes(budget)
    box: list = [None]
    stack: list = [(value, box, 0, 1, "")]
    tuples: list = []                    # (parent, slot, list) to turn into tuples, deepest last
    nodes = 0
    while stack:
        cur, parent, slot, depth, path = stack.pop()
        where = f"{what}{path}"
        if depth > max_depth:
            raise error(f"{where} nests deeper than {max_depth} levels")
        t = type(cur)
        if cur is None or t is bool or t is int or t is float:
            parent[slot] = cur
            continue
        if issubclass(t, str):
            parent[slot] = str.__str__(cur)
            continue
        if issubclass(t, dict):
            items = list(dict.items(cur))
            if issubclass(t, OrderedDict):
                # its own order, read without hashing a key of the caller (see the module docstring)
                try:
                    items = _in_eigener_reihenfolge(cur, items)
                except _Abweisung as abweisung:
                    raise error(f"{where}: {abweisung.grund}") from None
            nodes += len(items)
            if nodes > max_nodes:
                raise error(f"{where} holds more than {max_nodes} entries")
            new: dict = {}
            parent[slot] = new
            pending = []
            for key, val in items:
                text = plain_text(key)
                if text is None:
                    raise error(f"{where} has a key of type {type_name(key)}; a JSON key is text")
                if text in new:
                    raise error(f"{where} names the key {text!r} twice")
                new[text] = None             # the slot, in the stored order
                pending.append((val, new, text, depth + 1, f"{path}.{text}"))
            stack.extend(reversed(pending))
            continue
        if issubclass(t, (list, tuple)):
            seq = list.copy(cur) if issubclass(t, list) else list(tuple.__iter__(cur))
            nodes += len(seq)
            if nodes > max_nodes:
                raise error(f"{where} holds more than {max_nodes} entries")
            lst: list = [None] * len(seq)
            parent[slot] = lst
            if issubclass(t, tuple):
                tuples.append((parent, slot, lst))
            stack.extend(reversed([(v, lst, i, depth + 1, f"{path}[{i}]") for i, v in enumerate(seq)]))
            continue
        if issubclass(t, (int, float)):
            base = "float" if issubclass(t, float) else "int"
            raise error(f"{where} is of type {type_name(cur)}, a subclass of {base}; a number must be an exact "
                        "int or float, so that no method of the caller's class decides its value")
        raise error(f"{where} is of type {type_name(cur)}; a JSON value is null, a boolean, an exact int or float, "
                    "text, a list, a tuple or a dict")
    for parent, slot, lst in reversed(tuples):
        parent[slot] = tuple(lst)
    return box[0]
