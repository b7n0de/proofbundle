"""Ein minimaler CBOR-Leser fuer definite UND indefinite Laengen (RFC 8949).

WARUM SELBST GESCHRIEBEN. Eine Nachrechnung mit derselben Bibliothek, die den Vektor erzeugt hat,
prueft die Bibliothek nicht. Emeks Leser liest nach eigener Aussage nur definite-length CBOR — die
dritte Achse (Array-Framing) laesst sich damit gar nicht messen. Dieser Leser kann beides und
sagt, welche Form er gesehen hat.

Kein COSE-Paket, kein cbor2. Standardbibliothek, und Ed25519 aus `cryptography`.
"""
from __future__ import annotations

import struct

BREAK = object()


class Unbestimmt:
    """Marker: dieser Container kam mit indefiniter Laenge."""
    __slots__ = ("wert",)

    def __init__(self, wert):
        self.wert = wert


def _kopf(b: bytes, i: int):
    mt = b[i] >> 5
    ai = b[i] & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i, False
    if ai == 24:
        return mt, b[i], i + 1, False
    if ai == 25:
        return mt, struct.unpack_from(">H", b, i)[0], i + 2, False
    if ai == 26:
        return mt, struct.unpack_from(">I", b, i)[0], i + 4, False
    if ai == 27:
        return mt, struct.unpack_from(">Q", b, i)[0], i + 8, False
    if ai == 31:
        return mt, None, i, True          # indefinit
    raise ValueError(f"reserviertes additional-info {ai} an Position {i-1}")


def lade(b: bytes, i: int = 0):
    """Ein Wert ab Position i. Gibt (wert, neue_position) zurueck."""
    mt, arg, i, indef = _kopf(b, i)

    if mt == 0:
        return arg, i
    if mt == 1:
        return -1 - arg, i
    if mt in (2, 3):                                   # bstr / tstr
        if indef:
            teile = []
            while True:
                if b[i] == 0xFF:
                    i += 1
                    break
                st, i = lade(b, i)
                teile.append(st)
            roh = b"".join(teile) if mt == 2 else "".join(teile).encode()
            return Unbestimmt(roh if mt == 2 else roh.decode()), i
        roh = b[i:i + arg]
        i += arg
        return (roh if mt == 2 else roh.decode("utf-8")), i
    if mt == 4:                                        # array
        if indef:
            aus = []
            while True:
                if b[i] == 0xFF:
                    i += 1
                    break
                v, i = lade(b, i)
                aus.append(v)
            return Unbestimmt(aus), i
        aus = []
        for _ in range(arg):
            v, i = lade(b, i)
            aus.append(v)
        return aus, i
    if mt == 5:                                        # map
        if indef:
            aus = {}
            while True:
                if b[i] == 0xFF:
                    i += 1
                    break
                k, i = lade(b, i)
                v, i = lade(b, i)
                aus[k] = v
            return Unbestimmt(aus), i
        aus = {}
        for _ in range(arg):
            k, i = lade(b, i)
            v, i = lade(b, i)
            aus[k] = v
        return aus, i
    if mt == 6:                                        # tag
        v, i = lade(b, i)
        return ("__tag__", arg, v), i
    if mt == 7:
        if arg == 20:
            return False, i
        if arg == 21:
            return True, i
        if arg == 22:
            return None, i
        raise ValueError(f"simple/float {arg} nicht unterstuetzt")
    raise ValueError(f"major type {mt}")


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
