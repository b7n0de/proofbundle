"""Extract every BCP 14 requirement sentence from draft-watts-agent-evidence-boundary-00.

Input is the plain-text rendering of the draft (one file, given on the command line). The file is
pinned by its SHA-256: a different copy is refused, so the line numbers in the output always refer
to the same bytes. The draft text is not stored in this repository.

Output (``requirements.json``): one entry per sentence that carries a BCP 14 key word in upper
case, with the section it stands in, the first and last line of the sentence in the pinned copy,
the key words it uses, and the sentence text with line breaks folded. The key-word paragraph of
Section 2 is skipped; the references (Sections 19 and 20) and the author's address are not read.

Usage: python extract_requirements.py <draft.txt> <out.json>
"""
from __future__ import annotations

import hashlib
import json
import re
import sys

PINNED_SHA256 = "e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d"
PINNED_LINES = 1064
DRAFT_NAME = "draft-watts-agent-evidence-boundary-00"

# Upper-case key words only (RFC 8174). Longer forms first so "MUST NOT" is one token.
KEYWORDS = ("MUST NOT", "SHALL NOT", "SHOULD NOT", "NOT RECOMMENDED", "MUST", "SHALL", "SHOULD",
            "RECOMMENDED", "REQUIRED", "MAY", "OPTIONAL")
_KW_RE = re.compile(r"\b(" + "|".join(k.replace(" ", r"\s+") for k in KEYWORDS) + r")\b")

_PAGE_FOOTER = re.compile(r"^Watts\s+Expires 16 March 2027\s+\[Page \d+\]$")
_PAGE_HEADER = re.compile(r"^Internet-Draft\s+Evidence-Bounded Agent Authorization\s+September 2026$")
_NUMBERED_HEADING = re.compile(r"^(\d+(?:\.\d+)*)\.\s+(\S.*)$")
_APPENDIX_HEADINGS = ("Appendix A.  Acknowledgements", "Author's Address")
#: The key-word paragraph of Section 2 begins with this text; it states the convention and is no requirement.
_BOILERPLATE = "The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY"


def _sections(lines):
    """Yield (line_no, section_id, title) for every heading after the table of contents."""
    in_body = False
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not in_body:
            if line == "1.  Introduction":
                in_body = True
            else:
                continue
        m = _NUMBERED_HEADING.match(line)
        if m and not line.startswith(" "):
            yield no, m.group(1), m.group(2).strip()
        elif line in _APPENDIX_HEADINGS:
            yield no, "appendix", line


def _paragraphs(lines, start, end):
    """Paragraphs of body text between two line numbers (inclusive start, exclusive end), as lists
    of (line_no, text). Page headers and footers are dropped."""
    para = []
    for no in range(start, end):
        text = lines[no - 1].rstrip("\n")
        if _PAGE_FOOTER.match(text) or _PAGE_HEADER.match(text) or text == "\f":
            continue
        if text.strip() == "":
            if para:
                yield para
                para = []
            continue
        para.append((no, text.strip()))
    if para:
        yield para


def _join_page_split(paragraphs):
    """Re-join a paragraph that a page break cut in two: the first part does not end a sentence and
    the second starts in lower case."""
    out = []
    for p in paragraphs:
        if out:
            prev_text = out[-1][-1][1]
            if not re.search(r"[.:;]$", prev_text) and p[0][1][:1].islower():
                out[-1] = out[-1] + p
                continue
        out.append(p)
    return out


def _sentences(para):
    """Split one paragraph into sentences, keeping the first and last line of each."""
    words = []
    for no, text in para:
        for k, w in enumerate(text.split()):
            if k == 0 and words and words[-1][1].endswith("-") and words[-1][0] != no:
                words[-1] = (words[-1][0], words[-1][1] + w)
                continue
            words.append((no, w))
    sents, cur = [], []
    for i, (no, w) in enumerate(words):
        cur.append((no, w))
        nxt = words[i + 1][1] if i + 1 < len(words) else ""
        ends = re.search(r"[.;:]$", w) and not re.match(r"^(e\.g\.|i\.e\.|etc\.)$", w)
        if ends and w.endswith(".") and (nxt == "" or nxt[:1].isupper() or nxt[:1] in "[(\"*"):
            sents.append(cur)
            cur = []
    if cur:
        sents.append(cur)
    return [(s[0][0], s[-1][0], " ".join(w for _, w in s)) for s in sents]


def extract(path):
    raw = open(path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED_SHA256:
        raise SystemExit(f"refused: {path} has sha256 {digest}, pinned {PINNED_SHA256}")
    lines = raw.decode("ascii").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if len(lines) != PINNED_LINES:
        raise SystemExit(f"refused: {len(lines)} lines, pinned {PINNED_LINES}")
    heads = list(_sections(lines))
    reqs = []
    counter = {}
    for idx, (hline, sid, title) in enumerate(heads):
        end = heads[idx + 1][0] if idx + 1 < len(heads) else len(lines) + 1
        if sid in ("19", "20") or sid == "appendix":
            continue
        paras = _join_page_split(list(_paragraphs(lines, hline + 1, end)))
        for para in paras:
            if " ".join(t for _, t in para).startswith(_BOILERPLATE):
                continue
            for first, last, text in _sentences(para):
                kws = [re.sub(r"\s+", " ", m.group(1)) for m in _KW_RE.finditer(text)]
                if not kws:
                    continue
                counter[sid] = counter.get(sid, 0) + 1
                reqs.append({"id": f"S{sid}-{counter[sid]}", "section": sid, "section_title": title,
                             "lines": [first, last], "keywords": kws, "text": text})
    return {"draft": DRAFT_NAME, "form": "txt", "sha256": digest, "line_count": len(lines),
            "requirement_count": len(reqs), "requirements": reqs}


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    out = extract(argv[1])
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=True)
        fh.write("\n")
    print(f"{out['requirement_count']} requirement sentences from {argv[1]}")


if __name__ == "__main__":
    main(sys.argv)
