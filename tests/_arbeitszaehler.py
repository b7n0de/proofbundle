"""Counted work instead of measured time, for every test that judges how a cost grows with its input.

THE CLASS (Z309, 2026-10-07). A test that compares the run times of two input sizes measures the machine together
with the code. Own-process CPU time and the minimum of several runs narrow that, and they do not close it: on CI's
shared runners the time exponent of `renewal_ats_chain` in `tests/test_budget_kostenkurve.py` came out at 1.51, 1.22
and 1.24 against a bound of 1.2 on three runs of the same head, while the code was the code of a head where the same
job passed. A verdict that a second run can turn is a verdict about the run.

WHAT IS COUNTED. Two quantities, both read from the interpreter and neither from a clock:

1. Every line of Python that runs (`sys.settrace`, event "line"), in every frame the call reaches.
2. For every call of a built-in method that walks its own receiver (``WALKING_METHODS``, such as `list.count` or
   `str.find`), the length of that receiver (`sys.setprofile`, event "c_call", the method's ``__self__``). Without it
   a quadratic scan inside C stays invisible to the first count: the duplicate check of `cap1` called
   `benannt.count(x)` once per entry, one line per entry, and spent its quadratic work inside the method.

The sum is the same for one interpreter and one input however loaded the machine is, because nothing in it depends
on how fast anything ran. Measured on 2026-10-07 at the three heads before the fixes the class tests were written
against: `renewal.verify_sequence` at 917edc69 (exponent 1.992 over 250 to 2000 entries), `cap1` at c59209d9 with a
duplicate (1.996 over 2500 to 20000 units), the copy of a tuple of tuples at 8f2fa980 (1.965 over 500 to 4000);
at b1f8d355 0.997 to 1.000, 0.999 and 0.999.

WHAT IS NOT COUNTED, named rather than left out. Work inside one C call that is no method in ``WALKING_METHODS``
over its own receiver: the scanner of `json`, `hashlib`, big-int arithmetic, an operator such as ``x in a_list``,
and a method whose cost depends on its argument rather than its receiver (`str.join`, `list.insert`). A test that
uses this count names the dimensions whose work lies there. The collector is paused while counting, so a collection
cannot add lines of a callback to one count and not to another.
"""
from __future__ import annotations

import gc
import sys
from typing import Any, Callable

#: Built-in methods whose cost grows with the length of their receiver. `pop`, `append` and `insert` are not here:
#: their cost does not follow the receiver's length (or follows an argument this hook does not see), and counting
#: the receiver for them would turn a linear loop of appends into a quadratic count.
WALKING_METHODS = frozenset({
    "__contains__", "casefold", "copy", "count", "decode", "encode", "find", "index", "lower", "lstrip",
    "remove", "replace", "reverse", "rfind", "rindex", "rsplit", "rstrip", "sort", "split", "splitlines",
    "strip", "translate", "upper",
})

#: The receivers whose length is counted: the built-in sequences, sets and mappings, by exact type.
_RECEIVERS = (list, tuple, str, bytes, bytearray, set, frozenset, dict)


class _OverLimit(BaseException):
    """Raised from the tracer once the count passes its limit. A BaseException, so that a verifier that turns every
    Exception into a refusal does not swallow it and go on uncounted."""


def count_work(call: Callable[[], Any], *, accepted: tuple = (), limit: int | None = None) -> dict:
    """``{"lines": n, "walked": m, "over_limit": bool}`` for one call of `call`.

    An exception of a type in `accepted` is a result (a refusal at a budget is one), any other one is raised after the
    tracers are restored. The tracers that were set before are set again afterwards, so a coverage run keeps its own.

    `limit` ends the count at the first line after `lines + walked` has passed it, and `over_limit` says so. A test
    that only asks whether the work stays at or below some number gets the same answer without counting a quadratic
    regression to its end: at 8f2fa980 the copy of 32000 tuples is about a billion lines of Python.
    """
    counts = {"lines": 0, "walked": 0, "over_limit": False}

    def profile(frame, event, arg):
        if event == "c_call":
            receiver = getattr(arg, "__self__", None)
            if type(receiver) in _RECEIVERS and getattr(arg, "__name__", "") in WALKING_METHODS:
                counts["walked"] += len(receiver)

    def local(frame, event, arg):
        if event == "line":
            counts["lines"] += 1
            if limit is not None and counts["lines"] + counts["walked"] > limit:
                counts["over_limit"] = True
                raise _OverLimit
        return local

    def global_(frame, event, arg):
        return local

    was_enabled = gc.isenabled()
    old_trace, old_profile = sys.gettrace(), sys.getprofile()
    gc.disable()
    sys.setprofile(profile)
    sys.settrace(global_)
    try:
        call()
    except _OverLimit:
        pass
    except accepted:
        pass
    finally:
        sys.settrace(old_trace)
        sys.setprofile(old_profile)
        if was_enabled:
            gc.enable()
    return counts


def work(call: Callable[[], Any], *, accepted: tuple = (), limit: int | None = None) -> int:
    """The counted work of one call of `call`: lines of Python run plus the receivers walked (see `count_work`).

    With a `limit`, a count that passed it returns a number above the limit, which is all a bound needs."""
    counts = count_work(call, accepted=accepted, limit=limit)
    return counts["lines"] + counts["walked"]
