"""Strict CBOR decoding for every verify path, the CBOR counterpart of ``_strict_json``.

WHY IT EXISTS. ``cbor2.loads`` keeps the LAST value of a duplicated map key, and ``tools/scitt_ccf_datahash_vector/
cbor_min.py`` did the same. Two readers of the same bytes can then check different leaf or path values, the
parser differential that ``_strict_json`` closes for JSON. The CCF receipt profile now requires a verifier to
reject an inclusion proof that is not valid CBOR under RFC 8949 Section 5.3.1, duplicate map keys in particular
(ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile pull request 31, commits eb01db3f and f6d4eb04). This
repository applies the same rule to its readers of checked, signed or evidential bytes; the scope and the readers
outside it are named in ``tests/test_strict_decoding_guard.py``.

WHAT IT REFUSES, each with a reason and the offset where it was decided (:class:`CborInvalid`, a
``BundleFormatError``):

* input that is not well-formed (RFC 8949 Appendix C): a truncated head, string, array or map; additional
  information 28 to 30; an indefinite length on major type 0, 1 or 6; a break outside an indefinite container;
  a chunk of an indefinite string that is not a definite string of the same major type; a simple value below 32
  in the two-byte form;
* input that is not valid (RFC 8949 Section 5.3.1): a duplicate map key at any depth, a text string that is not
  valid UTF-8, and a chunk of an indefinite text string that is not valid UTF-8 on its own (Section 3.2.3: the
  bytes of one code point cannot be spread between chunks);
* bytes after the one data item (``loads_strict_cbor``), so a caller never reads a prefix;
* input over the byte, depth or width budget (the width budget counts array elements, map pairs and the chunks of
  indefinite strings; a chunk counts one level below its string, as in the two other strict readers), and a map key
  this reader cannot represent (an array, a map, a tag or a NaN as key).

WHAT IT ACCEPTS that a profile may still refuse: heads that are not in their shortest form and indefinite
lengths. Both are valid CBOR under Section 5.3.1; requiring the preferred or deterministic encoding (Section 4.2)
is a profile decision, made by the caller on top of this reader. Tags are returned as :class:`Tag` and are not
interpreted (tag validity, Section 5.3.2, belongs to the caller that knows the tag).

THE TYPES ARE FIXED. An array is a ``list``, a map is a ``dict``, a byte string is ``bytes``, a text string is
``str``, whatever library is installed. Under a tag, at any depth, cbor2 6 returns an array as a ``tuple`` and a
map as a ``frozendict``, where cbor2 5 returned a ``list`` and a ``dict``; a reader that checked
``isinstance(x, list)`` or ``isinstance(x, dict)`` behind cbor2 failed silently on the new version (measured on
2026-10-14 and 2026-10-15 with cbor2 5.9.0 and 6.1.4). Nothing here depends on cbor2.

Duplicate keys are compared as CBOR data items, not as bytes (RFC 8949 Section 5.6.1): ``0x01`` and ``0x18 0x01`` are
the same key, and so are 0.0 and -0.0; the integer 1 and the float 1.0 are not, and neither are ``true`` and 1. Two keys
that are different data items but one Python dict key (1 and 1.0, ``true`` and 1) are refused too: a dict cannot keep
both, and keeping one would be the silent merge. NaN keys are equal when their significands are; a decoded float does
not keep the significand of a half-precision NaN, so a NaN as key is refused instead of compared.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any

from .errors import BundleFormatError

__all__ = ["CborInvalid", "Tag", "Simple", "UNDEFINED", "loads_strict_cbor", "load_item_strict"]


class CborInvalid(BundleFormatError):
    """The bytes are not one valid CBOR data item. ``reason`` is the rule, ``offset`` where it was decided."""

    def __init__(self, reason: str, offset: int):
        self.reason = reason
        self.offset = offset
        super().__init__(f"CBOR refused at offset {offset}: {reason}")


@dataclass(frozen=True)
class Tag:
    """A tagged data item, not interpreted."""

    number: int
    value: Any


@dataclass(frozen=True)
class Simple:
    """A simple value other than false, true, null and undefined."""

    value: int


class _Undefined:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNDEFINED"


#: The simple value undefined (major type 7, value 23).
UNDEFINED = _Undefined()

_BREAK = object()


def _key_marker(key: Any, offset: int):
    """A hashable stand-in that is equal exactly when two keys are the same CBOR data item."""
    typ = type(key)
    if typ is bool or key is None or key is UNDEFINED:
        return ("simple", repr(key))
    if typ is int:
        return ("int", key)
    if typ is bytes:
        return ("bytes", key)
    if typ is str:
        return ("text", key)
    if typ is float:
        # Numerically equal floats are one key (RFC 8949 Section 5.6.1), so -0.0 and 0.0 are a duplicate: adding 0.0
        # turns -0.0 into 0.0 and leaves every other value as it is. A NaN key is refused, see the module docstring.
        if math.isnan(key):
            raise CborInvalid("a NaN as map key, which this reader does not represent", offset)
        return ("float", struct.pack(">d", key + 0.0))
    if typ is Simple:
        return ("simple", key.value)
    raise CborInvalid("map key is an array, a map or a tag, which this reader does not represent", offset)


class _Reader:
    def __init__(self, data: bytes, max_depth: int, max_items: int):
        self.b = data
        self.n = len(data)
        self.max_depth = max_depth
        self.max_items = max_items
        self.items = 0

    def _count(self, k: int, offset: int) -> None:
        self.items += k
        if self.items > self.max_items:
            raise CborInvalid(f"more than {self.max_items} array elements, map pairs and string chunks", offset)

    def head(self, i: int):
        """-> (major type, argument or None for an indefinite length, offset after the head)."""
        if i >= self.n:
            raise CborInvalid("input ends where a data item was expected", i)
        ib = self.b[i]
        mt, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            return mt, ai, i + 1
        if ai in (24, 25, 26, 27):
            width = 1 << (ai - 24)
            if i + 1 + width > self.n:
                raise CborInvalid("input ends inside a head", i)
            return mt, int.from_bytes(self.b[i + 1:i + 1 + width], "big"), i + 1 + width
        if ai == 31:
            if mt in (0, 1, 6):
                raise CborInvalid(f"indefinite length on major type {mt}", i)
            return mt, None, i + 1
        raise CborInvalid(f"reserved additional information {ai}", i)

    def item(self, i: int, depth: int):
        if depth > self.max_depth:
            raise CborInvalid(f"nesting deeper than {self.max_depth}", i)
        start = i
        mt, arg, i = self.head(i)
        if mt == 0:
            return arg, i
        if mt == 1:
            return -1 - arg, i
        if mt in (2, 3):
            if arg is None:
                parts = []
                while True:
                    if i >= self.n:
                        raise CborInvalid("input ends inside an indefinite string", start)
                    if self.b[i] == 0xFF:
                        i += 1
                        break
                    cpos = i
                    if depth + 1 > self.max_depth:
                        raise CborInvalid(f"nesting deeper than {self.max_depth}", cpos)
                    cmt, carg, j = self.head(i)
                    if cmt != mt or carg is None:
                        raise CborInvalid("a chunk of an indefinite string is not a definite string of its type", cpos)
                    if carg > self.n - j:
                        raise CborInvalid("string runs past the end of the input", cpos)
                    self._count(1, cpos)
                    chunk = bytes(self.b[j:j + carg])
                    if mt == 3:
                        try:
                            chunk.decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise CborInvalid("a chunk of an indefinite text string is not valid UTF-8 on its own",
                                              cpos) from exc
                    parts.append(chunk)
                    i = j + carg
                raw = b"".join(parts)
            else:
                if arg > self.n - i:
                    raise CborInvalid("string runs past the end of the input", start)
                raw = bytes(self.b[i:i + arg])
                i += arg
            if mt == 2:
                return raw, i
            try:
                return raw.decode("utf-8"), i
            except UnicodeDecodeError as exc:
                raise CborInvalid("text string is not valid UTF-8", start) from exc
        if mt == 4:
            out: list = []
            if arg is None:
                while True:
                    if i >= self.n:
                        raise CborInvalid("input ends inside an indefinite array", start)
                    if self.b[i] == 0xFF:
                        return out, i + 1
                    self._count(1, i)
                    v, i = self.item(i, depth + 1)
                    out.append(v)
            if arg > self.n - i:
                raise CborInvalid("array declares more elements than bytes remain", start)
            self._count(arg, start)
            for _ in range(arg):
                v, i = self.item(i, depth + 1)
                out.append(v)
            return out, i
        if mt == 5:
            m: dict = {}
            seen: set = set()

            def pair(i: int) -> int:
                kpos = i
                k, i = self.item(i, depth + 1)
                marker = _key_marker(k, kpos)
                if marker in seen:
                    raise CborInvalid(f"duplicate map key {k!r}", kpos)
                if k in m:
                    # Two DIFFERENT data items that Python treats as one dict key: 1 and 1.0, true and 1, 0.0 and
                    # -0.0. Keeping both is impossible in a dict and keeping one is the silent merge this reader
                    # exists to refuse, so it refuses.
                    raise CborInvalid(f"map keys {k!r} and an earlier key are distinct CBOR data items that "
                                      "collide as one dict key", kpos)
                seen.add(marker)
                v, i = self.item(i, depth + 1)
                m[k] = v
                return i

            if arg is None:
                while True:
                    if i >= self.n:
                        raise CborInvalid("input ends inside an indefinite map", start)
                    if self.b[i] == 0xFF:
                        return m, i + 1
                    self._count(1, i)
                    i = pair(i)
            if arg > (self.n - i) // 2:
                raise CborInvalid("map declares more pairs than bytes remain", start)
            self._count(arg, start)
            for _ in range(arg):
                i = pair(i)
            return m, i
        if mt == 6:
            v, i = self.item(i, depth + 1)
            return Tag(arg, v), i
        # Major type 7: simple values and floats.
        if arg is None:
            raise CborInvalid("break outside an indefinite container", start)
        ai = self.b[start] & 0x1F       # head() has read the byte at start, so it exists
        if ai < 24:
            if arg == 20:
                return False, i
            if arg == 21:
                return True, i
            if arg == 22:
                return None, i
            if arg == 23:
                return UNDEFINED, i
            return Simple(arg), i
        if ai == 24:
            if arg < 32:
                raise CborInvalid(f"simple value {arg} in the two-byte form", start)
            return Simple(arg), i
        width = {25: 2, 26: 4, 27: 8}[ai]
        raw = bytes(self.b[i - width:i])
        if width == 2:
            return struct.unpack(">e", raw)[0], i
        if width == 4:
            return struct.unpack(">f", raw)[0], i
        return struct.unpack(">d", raw)[0], i


def _budget(max_bytes, max_depth, max_items):
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
    return (DEFAULT_BUDGET.input_bytes if max_bytes is None else max_bytes,
            DEFAULT_BUDGET.json_depth if max_depth is None else max_depth,
            DEFAULT_BUDGET.json_nodes if max_items is None else max_items)


def load_item_strict(data: bytes, offset: int = 0, *, max_bytes: int | None = None,
                     max_depth: int | None = None, max_items: int | None = None) -> tuple:
    """Read ONE valid data item starting at ``offset``; -> (value, offset after it).

    For a caller that walks a sequence of items itself. Bytes after the item are the caller's to judge; a caller
    that reads one whole document uses :func:`loads_strict_cbor`, which refuses them.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CborInvalid(f"input is {type(data).__name__}, not bytes", 0)
    data = bytes(data)
    mb, md, mi = _budget(max_bytes, max_depth, max_items)
    if len(data) > mb:
        raise CborInvalid(f"input of {len(data)} bytes exceeds {mb}", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > len(data):
        raise CborInvalid("offset outside the input", 0)
    return _Reader(data, md, mi).item(offset, 0)


def loads_strict_cbor(data: bytes, *, max_bytes: int | None = None, max_depth: int | None = None,
                      max_items: int | None = None) -> Any:
    """Exactly one valid CBOR data item that covers all of ``data``, or :class:`CborInvalid`.

    Defaults come from ``DEFAULT_BUDGET``: ``input_bytes`` for the size, ``json_depth`` for the nesting and
    ``json_nodes`` for the combined number of array elements, map pairs and chunks of indefinite strings.
    """
    value, end = load_item_strict(data, 0, max_bytes=max_bytes, max_depth=max_depth, max_items=max_items)
    if end != len(data):
        raise CborInvalid(f"{len(data) - end} byte(s) after the data item", end)
    return value
