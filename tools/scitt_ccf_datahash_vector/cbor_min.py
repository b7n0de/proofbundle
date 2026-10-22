"""Ein minimaler CBOR-Leser fuer definite UND indefinite Laengen (RFC 8949).

WARUM SELBST GESCHRIEBEN. Eine Nachrechnung mit derselben Bibliothek, die den Vektor erzeugt hat,
prueft die Bibliothek nicht. Emeks Leser liest nach eigener Aussage nur definite-length CBOR — die
dritte Achse (Array-Framing) laesst sich damit gar nicht messen. Dieser Leser kann beides und
sagt, welche Form er gesehen hat.

Kein COSE-Paket, kein cbor2. Standardbibliothek, und Ed25519 aus `cryptography`.

STRICT SINCE 2026-10-14 (the strict decoding rule stated in tests/test_strict_decoding_guard.py, after pull request 31 to the CCF
receipt profile). Until then a map with a duplicate key kept the LAST value without a word, as cbor2
does; a string shorter than its head said was cut short, `0x1f` read as `None`, and a chunk of an indefinite
string could have any type. Now `lade` refuses each of these with a reason (`ValueError`), and `load_exactly_one`
also refuses bytes after the one value. It does not refuse a head that is not the shortest or an indefinite
length: both are valid CBOR under RFC 8949 Section 5.3.1, and the indefinite framing is the very axis this
reader exists to measure.
"""
from __future__ import annotations

import struct

BREAK = object()

#: The deepest nesting read. Without a bound a deep input ran into a RecursionError.
MAX_DEPTH = 64


class Unbestimmt:
    """Marker: dieser Container kam mit indefiniter Laenge."""
    __slots__ = ("wert",)

    def __init__(self, wert):
        self.wert = wert


def _kopf(b: bytes, i: int):
    if i >= len(b):
        raise ValueError(f"input ends at offset {i}, where a data item was expected")
    mt = b[i] >> 5
    ai = b[i] & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i, False
    if ai in (24, 25, 26, 27):
        width = 1 << (ai - 24)
        if i + width > len(b):
            raise ValueError(f"input ends inside the head at offset {i - 1}")
        return mt, int.from_bytes(b[i:i + width], "big"), i + width, False
    if ai == 31:
        if mt in (0, 1, 6):
            raise ValueError(f"indefinite length on major type {mt} at offset {i - 1}")
        return mt, None, i, True          # indefinit
    raise ValueError(f"reserviertes additional-info {ai} an Position {i-1}")


def _key_marker(k, pos: int):
    """Equal exactly when two keys are the same CBOR data item (1 and True are not)."""
    if isinstance(k, (bool, type(None))):
        return ("simple", repr(k))
    if isinstance(k, (int, str, bytes)):
        return (type(k).__name__, k)
    raise ValueError(f"map key at offset {pos} is not an integer, a text string or a byte string")


def _check_not_at_end(b: bytes, i: int, start: int, what: str) -> None:
    if i >= len(b):
        raise ValueError(f"input ends inside {what} that starts at offset {start}")


def lade(b: bytes, i: int = 0, _depth: int = 0):
    """One value from offset i, as (value, new offset). Bytes after the value are judged by `load_exactly_one`."""
    if _depth > MAX_DEPTH:
        raise ValueError(f"nesting deeper than {MAX_DEPTH} at offset {i}")
    start = i
    mt, arg, i, indef = _kopf(b, i)

    if mt == 0:
        return arg, i
    if mt == 1:
        return -1 - arg, i
    if mt in (2, 3):                                   # bstr / tstr
        if indef:
            teile = []
            while True:
                _check_not_at_end(b, i, start, "an indefinite string")
                if b[i] == 0xFF:
                    i += 1
                    break
                # A chunk is a DEFINITE string of the same type (RFC 8949 3.2.3), otherwise not well-formed.
                smt, _sarg, _si, sindef = _kopf(b, i)
                if smt != mt or sindef:
                    raise ValueError(f"chunk at offset {i} is not a definite string of the same type")
                st, i = lade(b, i, _depth + 1)
                teile.append(st)
            roh = b"".join(teile) if mt == 2 else "".join(teile).encode()
            return Unbestimmt(roh if mt == 2 else roh.decode()), i
        if arg > len(b) - i:
            raise ValueError(f"string at offset {start} runs past the end of the input")
        roh = bytes(b[i:i + arg])
        i += arg
        return (roh if mt == 2 else roh.decode("utf-8")), i
    if mt == 4:                                        # array
        if indef:
            aus = []
            while True:
                _check_not_at_end(b, i, start, "an indefinite array")
                if b[i] == 0xFF:
                    i += 1
                    break
                v, i = lade(b, i, _depth + 1)
                aus.append(v)
            return Unbestimmt(aus), i
        if arg > len(b) - i:
            raise ValueError(f"array at offset {start} declares more elements than bytes remain")
        aus = []
        for _ in range(arg):
            v, i = lade(b, i, _depth + 1)
            aus.append(v)
        return aus, i
    if mt == 5:                                        # map
        aus = {}
        seen = set()

        def pair(i):
            kpos = i
            k, i = lade(b, i, _depth + 1)
            marker = _key_marker(k, kpos)
            # A DUPLICATE KEY IS A REFUSAL. The last value used to win without a word (aus[k] = v), as in cbor2.
            if marker in seen or k in aus:
                raise ValueError(f"duplicate map key {k!r} at offset {kpos}")
            seen.add(marker)
            v, i = lade(b, i, _depth + 1)
            aus[k] = v
            return i

        if indef:
            while True:
                _check_not_at_end(b, i, start, "an indefinite map")
                if b[i] == 0xFF:
                    i += 1
                    break
                i = pair(i)
            return Unbestimmt(aus), i
        if arg > (len(b) - i) // 2:
            raise ValueError(f"map at offset {start} declares more pairs than bytes remain")
        for _ in range(arg):
            i = pair(i)
        return aus, i
    if mt == 6:                                        # tag
        v, i = lade(b, i, _depth + 1)
        return ("__tag__", arg, v), i
    if mt == 7:
        if indef:
            raise ValueError(f"break at offset {start} outside an indefinite container")
        if b[start] & 0x1F >= 24:
            # The two-byte form of a simple value (not well-formed below 32), or a float.
            raise ValueError(f"simple value or float at offset {start} is not supported")
        if arg == 20:
            return False, i
        if arg == 21:
            return True, i
        if arg == 22:
            return None, i
        raise ValueError(f"simple/float {arg} nicht unterstuetzt")
    raise ValueError(f"major type {mt}")


def load_exactly_one(b: bytes):
    """Exactly one value that covers all of the input. Bytes after the value are a refusal, not a rest."""
    wert, ende = lade(b, 0)
    if ende != len(b):
        raise ValueError(f"{len(b) - ende} byte(s) after the value")
    return wert


def kopf_bytes(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([(mt << 5) | n])
    if n < 0x100:
        return bytes([(mt << 5) | 24, n])
    if n < 0x10000:
        return bytes([(mt << 5) | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([(mt << 5) | 26]) + struct.pack(">I", n)
    return bytes([(mt << 5) | 27]) + struct.pack(">Q", n)


def schreibe(o) -> bytes:
    """Definite-length-Kodierung, das Noetige fuer Sig_structure."""
    if isinstance(o, bytes):
        return kopf_bytes(2, len(o)) + o
    if isinstance(o, str):
        r = o.encode("utf-8")
        return kopf_bytes(3, len(r)) + r
    if isinstance(o, list):
        return kopf_bytes(4, len(o)) + b"".join(schreibe(x) for x in o)
    if isinstance(o, int) and o >= 0:
        return kopf_bytes(0, o)
    raise TypeError(type(o))
