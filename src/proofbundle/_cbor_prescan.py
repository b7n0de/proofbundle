"""The structural pre-scan for the CBOR of the ``scitt-ccf/v1`` profile (RFC 8949), run before any decoder.

WHY IT EXISTS (ADR 0009, Decisions 8 and 13). The chosen decoder, cbor2, cannot enforce the
profile on its own. Measured on 2026-09-25 with cbor2 5.9.0 and 6.1.4
(``tools/scitt_ccf_external/reader_crosscheck.json``): both accept duplicate map keys by default,
both ignore trailing bytes in ``loads``, both accept non-shortest heads, and both interpret tags 1,
2, 28/29, 256/25 and 55799 by default without calling ``tag_hook`` (measured for tag 2). A denylist
of tags would be a list that belongs to the library. So this scan decides first, with an
ALLOWLIST, and only bytes it accepts are handed to cbor2.

WHAT IT ACCEPTS, and nothing else:

* exactly one data item that covers the whole input (no trailing bytes)
* definite lengths only, heads in their shortest form (RFC 8949 section 4.2.1)
* unsigned and negative integers, byte strings, UTF-8 text strings, arrays, maps
* the simple values false, true and null; no floats, no undefined, no other simple value
* map keys that are integers or text strings, each key once per map
* a tag only where the caller's policy allows it, by position; tag 1 must wrap an integer and
  tag 18 must wrap an array
* nesting up to ``max_depth`` and at most ``max_bytes`` of input

Every limit counts bytes of the encoded input, never characters of a decoded string.

A refusal is a ``CborRefused`` (a ``BundleFormatError``) with the offset where it was decided. It is
never a verdict about a signature; it says these bytes are not read here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .errors import BundleFormatError

#: (path, tag number) -> allowed. A path is the tuple of map keys and array indices from the root.
TagPolicy = Callable[[tuple, int], bool]


class CborRefused(BundleFormatError):
    """The pre-scan does not read these bytes. ``offset`` is where it decided."""

    def __init__(self, reason: str, offset: int):
        self.reason = reason
        self.offset = offset
        super().__init__(f"CBOR refused at offset {offset}: {reason}")


@dataclass(frozen=True)
class Tag:
    """A tag the policy allowed, with its decoded content."""

    number: int
    value: object


def no_tags(path: tuple, number: int) -> bool:
    """The default policy: no tag anywhere."""
    return False


@dataclass(frozen=True)
class Scan:
    """What the pre-scan read: the decoded value and, for a top-level array, its element spans."""

    value: object
    tagged_with: Optional[int]
    element_spans: tuple


class _Reader:
    def __init__(self, data: bytes, max_depth: int, tag_allowed: TagPolicy):
        self.b = data
        self.n = len(data)
        self.max_depth = max_depth
        self.tag_allowed = tag_allowed

    def head(self, i: int):
        if i >= self.n:
            raise CborRefused("input ends where a data item was expected", i)
        ib = self.b[i]
        mt, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            return mt, ai, i + 1
        if ai in (24, 25, 26, 27):
            width = 1 << (ai - 24)
            if i + 1 + width > self.n:
                raise CborRefused("input ends inside a head", i)
            arg = int.from_bytes(self.b[i + 1:i + 1 + width], "big")
            if mt == 7:
                raise CborRefused("float or extended simple value", i)
            smallest = 24 if ai == 24 else 1 << (8 * (width // 2))
            if arg < smallest:
                raise CborRefused("head not in its shortest form", i)
            return mt, arg, i + 1 + width
        if ai == 31:
            raise CborRefused("indefinite length", i)
        raise CborRefused(f"reserved additional information {ai}", i)

    def item(self, i: int, depth: int, path: tuple):
        if depth > self.max_depth:
            raise CborRefused(f"nesting deeper than {self.max_depth}", i)
        start = i
        mt, arg, i = self.head(i)
        if mt == 0:
            return arg, i
        if mt == 1:
            return -1 - arg, i
        if mt == 2 or mt == 3:
            if arg > self.n - i:
                raise CborRefused("string runs past the end of the input", start)
            raw = bytes(self.b[i:i + arg])
            if mt == 3:
                try:
                    return raw.decode("utf-8"), i + arg
                except UnicodeDecodeError as exc:
                    raise CborRefused("text string is not valid UTF-8", start) from exc
            return raw, i + arg
        if mt == 4:
            if arg > self.n - i:
                raise CborRefused("array declares more elements than bytes remain", start)
            out = []
            for k in range(arg):
                v, i = self.item(i, depth + 1, path + (k,))
                out.append(v)
            return out, i
        if mt == 5:
            if arg > (self.n - i) // 2:
                raise CborRefused("map declares more pairs than bytes remain", start)
            m: dict = {}
            seen: set = set()
            for _ in range(arg):
                kpos = i
                k, i = self.item(i, depth + 1, path + ("<key>",))
                if isinstance(k, bool) or not isinstance(k, (int, str)):
                    raise CborRefused("map key is neither an integer nor a text string", kpos)
                marker = (type(k), k)
                if marker in seen:
                    raise CborRefused(f"duplicate map key {k!r}", kpos)
                seen.add(marker)
                v, i = self.item(i, depth + 1, path + (k,))
                m[k] = v
            return m, i
        if mt == 6:
            if not self.tag_allowed(path, arg):
                raise CborRefused(f"tag {arg} is not allowed at {path!r}", start)
            v, i = self.item(i, depth + 1, path)
            if arg == 1 and (isinstance(v, bool) or not isinstance(v, int)):
                raise CborRefused("tag 1 must wrap an integer", start)
            if arg == 18 and not isinstance(v, list):
                raise CborRefused("tag 18 must wrap an array", start)
            return Tag(arg, v), i
        # mt == 7, simple values below 24
        if arg == 20:
            return False, i
        if arg == 21:
            return True, i
        if arg == 22:
            return None, i
        raise CborRefused(f"simple value {arg}", start)


def scan(data: bytes, *, max_bytes: int, max_depth: int = 16,
         tag_allowed: TagPolicy = no_tags) -> Scan:
    """Read exactly one CBOR data item that covers all of ``data``.

    ``element_spans`` holds the (start, end) offsets of the elements of a top-level array, looked
    through at most one tag; it is empty for any other top-level item. Offsets refer to ``data``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise CborRefused(f"input is {type(data).__name__}, not bytes", 0)
    data = bytes(data)
    if len(data) > max_bytes:
        raise CborRefused(f"input of {len(data)} bytes exceeds {max_bytes}", 0)
    r = _Reader(data, max_depth, tag_allowed)
    value, end = r.item(0, 0, ())
    if end != len(data):
        raise CborRefused(f"{len(data) - end} trailing byte(s) after the data item", end)
    tagged_with = None
    i = 0
    mt, arg, j = r.head(0)
    if mt == 6:
        tagged_with = arg
        i = j
        mt, arg, j = r.head(i)
    spans: list = []
    if mt == 4:
        pos = j
        for k in range(arg):
            _v, nxt = r.item(pos, 1, (k,))
            spans.append((pos, nxt))
            pos = nxt
    return Scan(value=value, tagged_with=tagged_with, element_spans=tuple(spans))


def encode_head(major: int, argument: int) -> bytes:
    """The shortest head for ``argument`` under ``major`` (RFC 8949 section 4.2.1)."""
    if argument < 24:
        return bytes([(major << 5) | argument])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < 1 << (8 * width):
            return bytes([(major << 5) | ai]) + argument.to_bytes(width, "big")
    raise BundleFormatError("CBOR argument does not fit in 64 bits")
