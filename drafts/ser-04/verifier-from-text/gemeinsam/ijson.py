"""Strict JSON parsing (RFC 8259) with the I-JSON checks of RFC 7493 Section 2.1/2.3.

The parser keeps member order, the raw text of numbers and their IEEE 754
double value, and reports every I-JSON issue with a name, so that a caller
can decide which issues matter at which step.
"""


class JsonError(Exception):
    """Input is not a JSON text (grammar), or not one JSON text."""

    def __init__(self, kind, msg):
        super().__init__("%s: %s" % (kind, msg))
        self.kind = kind


class ResourceLimit(Exception):
    pass


MAX_DEPTH = 200
WS = " \t\n\r"


class Num:
    __slots__ = ("raw", "double")

    def __init__(self, raw):
        self.raw = raw
        self.double = float(raw)  # correctly rounded, ties to even, overflow to inf

    def __repr__(self):
        return "Num(%s)" % self.raw


class Obj:
    """Members in order; names after unescaping."""
    __slots__ = ("members",)

    def __init__(self, members):
        self.members = members

    def names(self):
        return [n for n, _ in self.members]

    def get(self, name, default=None):
        for n, v in self.members:
            if n == name:
                return v
        return default

    def as_dict(self):
        return dict(self.members)


def is_noncharacter(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


class _Parser:
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.issues = []  # (kind, detail)

    def ws(self):
        s, i = self.s, self.i
        while i < len(s) and s[i] in WS:
            i += 1
        self.i = i

    def err(self, msg):
        raise JsonError("grammar", "%s at offset %d" % (msg, self.i))

    def value(self, depth):
        if depth > MAX_DEPTH:
            raise ResourceLimit("nesting deeper than %d" % MAX_DEPTH)
        self.ws()
        if self.i >= len(self.s):
            self.err("unexpected end")
        c = self.s[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        if c in "-0123456789":
            return self.number()
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        self.err("unexpected character %r" % c)

    def obj(self, depth):
        self.i += 1
        members = []
        seen = set()
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "}":
            self.i += 1
            return Obj(members)
        while True:
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != '"':
                self.err("expected member name")
            name = self.string()
            if name in seen:
                self.issues.append(("duplicate", name))
            seen.add(name)
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != ":":
                self.err("expected ':'")
            self.i += 1
            v = self.value(depth + 1)
            members.append((name, v))
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.s) and self.s[self.i] == "}":
                self.i += 1
                return Obj(members)
            self.err("expected ',' or '}'")

    def arr(self, depth):
        self.i += 1
        out = []
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return out
            self.err("expected ',' or ']'")

    def string(self):
        s = self.s
        self.i += 1
        out = []
        while True:
            if self.i >= len(s):
                self.err("unterminated string")
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                self.i += 1
                if self.i >= len(s):
                    self.err("unterminated escape")
                e = s[self.i]
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    out.append(simple[e])
                    self.i += 1
                elif e == "u":
                    h = s[self.i + 1:self.i + 5]
                    if len(h) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in h):
                        self.err("bad \\u escape")
                    cp = int(h, 16)
                    self.i += 5
                    if 0xD800 <= cp <= 0xDBFF and s.startswith("\\u", self.i):
                        h2 = s[self.i + 2:self.i + 6]
                        if len(h2) == 4 and all(ch in "0123456789abcdefABCDEF" for ch in h2):
                            lo = int(h2, 16)
                            if 0xDC00 <= lo <= 0xDFFF:
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                                self.i += 6
                    if 0xD800 <= cp <= 0xDFFF:
                        self.issues.append(("surrogate", "U+%04X" % cp))
                        out.append("�")
                        continue
                    if is_noncharacter(cp):
                        self.issues.append(("noncharacter", "U+%04X" % cp))
                    out.append(chr(cp))
                else:
                    self.err("bad escape")
            else:
                cp = ord(c)
                if cp < 0x20:
                    self.err("control character in string")
                if 0xD800 <= cp <= 0xDFFF:
                    self.issues.append(("surrogate", "U+%04X" % cp))
                elif is_noncharacter(cp):
                    self.issues.append(("noncharacter", "U+%04X" % cp))
                out.append(c)
                self.i += 1
        return "".join(out)

    def number(self):
        s, i = self.s, self.i
        j = i
        if j < len(s) and s[j] == "-":
            j += 1
        if j < len(s) and s[j] == "0":
            j += 1
        elif j < len(s) and s[j] in "123456789":
            while j < len(s) and s[j] in "0123456789":
                j += 1
        else:
            self.err("bad number")
        if j < len(s) and s[j] == ".":
            j += 1
            k = j
            while j < len(s) and s[j] in "0123456789":
                j += 1
            if j == k:
                self.err("bad fraction")
        if j < len(s) and s[j] in "eE":
            j += 1
            if j < len(s) and s[j] in "+-":
                j += 1
            k = j
            while j < len(s) and s[j] in "0123456789":
                j += 1
            if j == k:
                self.err("bad exponent")
        self.i = j
        return Num(s[i:j])


def parse(data):
    """Parse bytes as one JSON text.

    Returns (value, issues). Raises JsonError for: 'bom', 'utf8', 'grammar',
    'trailing'. I-JSON content issues (duplicate, surrogate, noncharacter) are
    returned in issues, in the order found.
    """
    if data[:3] == b"\xef\xbb\xbf":
        raise JsonError("bom", "byte order mark")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        raise JsonError("utf8", str(e))
    p = _Parser(text)
    v = p.value(0)
    p.ws()
    if p.i != len(text):
        raise JsonError("trailing", "data after the JSON text at offset %d" % p.i)
    return v, p.issues


def to_plain(v):
    if isinstance(v, Obj):
        return {n: to_plain(x) for n, x in v.members}
    if isinstance(v, list):
        return [to_plain(x) for x in v]
    if isinstance(v, Num):
        return v.raw
    return v
