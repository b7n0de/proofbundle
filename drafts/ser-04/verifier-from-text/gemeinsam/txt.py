"""Read a draft in its TXT form: page furniture removed, original line numbers kept."""
import re

_FOOT = re.compile(r"^Gruszka\s+Expires .*\[Page \d+\]$")
_HEAD = re.compile(r"^Internet-Draft\s{2,}.*\s{2,}(January|February|March|April|May|June|July|August|September|October|November|December) \d{4}$")
_HEX = re.compile(r"^\s*([0-9a-f]{2,})\s*$")


class Draft:
    def __init__(self, path):
        raw = open(path, "rb").read()
        self.raw = raw
        text = raw.decode("utf-8")
        self.lines = text.split("\n")  # lines[i] is line i+1

    def line(self, n):
        return self.lines[n - 1]

    def body(self, a, b):
        """(line number, text) for lines a..b without page furniture or form feeds."""
        out = []
        for n in range(a, b + 1):
            t = self.lines[n - 1].replace("\f", "")
            if _FOOT.match(t.strip()) or _HEAD.match(t.strip()):
                continue
            out.append((n, t))
        return out

    def find(self, needle, start=1):
        for n in range(start, len(self.lines) + 1):
            if needle in self.lines[n - 1]:
                return n
        raise KeyError(needle)

    def hex_after(self, marker_line):
        """The hex block that starts at the first hex line after marker_line, across page breaks."""
        n = marker_line + 1
        out = []
        started = False
        while n <= len(self.lines):
            t = self.lines[n - 1].replace("\f", "")
            s = t.strip()
            if _FOOT.match(s) or _HEAD.match(s):
                n += 1
                continue
            m = _HEX.match(t)
            if m:
                out.append(m.group(1))
                started = True
            elif s == "":
                pass
            elif started:
                break
            n += 1
        return bytes.fromhex("".join(out))

    def words(self, a, b):
        """Running text of lines a..b with whitespace collapsed."""
        return " ".join(" ".join(t.split()) for _, t in self.body(a, b) if t.strip())
