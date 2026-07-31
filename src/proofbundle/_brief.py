"""Bounded rendering of caller-supplied values for messages on never-raise paths.

WHY THIS MODULE EXISTS. Every public verify surface owes its caller a stable verdict rather than a raw
exception. The checks themselves honour that. The MESSAGES THAT EXPLAIN A REJECTION did not: they
interpolated the offending value directly, so rendering the explanation could fail harder than the check
that produced it. A deeply nested value handed to a relying-party expectation argument
(``expected_predicate_type``, ``require``, ``require_target``, …) made ``repr()`` recurse and raised
``RecursionError`` out of a dict-returning verify surface — a forbidden termination under the never-raise
contract, produced by the rejection path itself.

The instance is small; the CLASS is not. A structural sweep of the never-raise family (84 functions) found
23 sites in 11 functions that interpolate one of their own parameters into a message. Fixing the three that
happened to be reachable would leave twenty neighbours holding the same shape, so the fix lives here, at the
mechanism, and a guard test requires every site in the family to use it.

WHAT IT GUARANTEES. ``brief`` never raises, for any input, including values that are deeply nested,
self-referential, enormous, or whose own ``__repr__``/``__str__`` is hostile. It is bounded in depth
(``reprlib`` levels) and in output length. It is NOT a security boundary and does not sanitise: it bounds
COST, not content. Callers must still keep secrets out of messages.

WHAT IT DELIBERATELY DOES NOT CHANGE. For the ordinary cases — a string, an int, a short tuple — the output
is byte-identical to what ``{value!r}`` / ``{value}`` produced before, so existing message assertions keep
their meaning. Only the pathological input, which previously crashed, now renders as a truncated marker.
"""
from __future__ import annotations

import reprlib as _reprlib

# Depth and width bounds. `maxlevel` is what stops the recursion that caused the class; the per-type widths
# keep a wide-but-shallow value from producing a megabyte of "explanation". Chosen to leave every realistic
# argument (a URI, a small tuple of allowed values) rendered in full.
_R = _reprlib.Repr()
_R.maxlevel = 4
_R.maxdict = 8
_R.maxlist = _R.maxtuple = _R.maxset = _R.maxfrozenset = _R.maxarray = 8
_R.maxstring = 256
_R.maxlong = 64
_R.maxother = 256

# Hard ceiling on the returned text, applied after rendering, so no combination of bounds can produce an
# unbounded message.
_MAX_CHARS = 512


def _clip(text: str) -> str:
    if len(text) <= _MAX_CHARS:
        return text
    return text[: _MAX_CHARS - 3] + "..."


def brief(value: object, *, quote: bool = True) -> str:
    """Render `value` for a message, bounded and never raising.

    `quote=True` (the default) is the bounded replacement for ``{value!r}``: it quotes strings, so a
    message keeps saying whether it got ``"1"`` or ``1``. `quote=False` is the bounded replacement for a
    plain ``{value}``: a `str` renders as itself (clipped), anything else falls back to the bounded repr,
    because ``str()`` on a hostile object recurses exactly like ``repr()`` does.
    """
    if not quote and isinstance(value, str):
        return _clip(value)
    try:
        return _clip(_R.repr(value))
    except BaseException:  # noqa: BLE001 — a renderer on a never-raise path must not raise, ever.
        # Reached when a value's own __repr__ is hostile in a way reprlib's per-type handlers do not
        # intercept. Naming the type is still useful; producing it must not touch the value again.
        try:
            return f"<unrenderable {type(value).__name__}>"
        except BaseException:  # noqa: BLE001 — even type(...).__name__ can be booby-trapped.
            return "<unrenderable>"
