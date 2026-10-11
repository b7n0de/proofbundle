#!/usr/bin/env python3
"""Make the XML that xml2rfc --v2v3 writes from kramdown-rfc's output into the XML that is submitted. Only the markup
changes, not the text it renders; each step answers one idnits3 code:

  1. LINE_PI: the processing instructions <?line N?>, kramdown-rfc's marks of its source lines, are removed.
  2. SUBMISSION_TYPE_UNEXPECTED: submissionType is removed from the rfc element. The Datatracker files these drafts
     with no stream; RFCXML v3 has no value for "no stream". The text that xml2rfc renders stays byte for byte.
  3. MISSING_BCP14_TAGS: each BCP 14 keyword in all capitals is wrapped in <bcp14> where it stands in the sense of
     BCP 14, in the boilerplate and in the body, outside artwork and sourcecode. The places in NOT_BCP14 keep their
     words as they are: quotations of another document and a "MAY" that states a possibility, not a permission.
     Each such place must be found exactly once, and the number of wrapped keywords must equal EXPECTED.

INVALID_REFERENCES_NAME stays: idnits3 wants "Normative References" and "Informative References" directly in <back>
for the XML, but for the text one top-level References section with numbered subsections. Taking the two sections
out of "References" (RFCXML v3 allows both forms) renumbers them in the text and gives MULTIPLE_REFERENCES_SECTION_TITLES
there; the nesting stays as kramdown-rfc writes it.

usage: v3_submission.py <file.xml>   (rewritten in place)
"""
import re
import sys

KEYWORD = re.compile(r"\b(MUST NOT|SHALL NOT|SHOULD NOT|NOT RECOMMENDED|MUST|SHALL|SHOULD|RECOMMENDED|REQUIRED|MAY|"
                     r"OPTIONAL)\b")
# docName without revision -> (the text that ends right before the keyword, whitespace collapsed; the keyword)
NOT_BCP14 = {
    "draft-gruszka-scitt-statement-identification": [
        ("Recomputing a target digest", "MAY"),             # a possibility ("may still require"), not a permission
        ("Each VDS specification applying for inclusion in this registry", "MUST"),   # quoted from RFC 9942 4.4.1
        ("and that \"Each specification", "MUST"),           # quoted from RFC 9942 4.4.1
    ],
}
EXPECTED = {
    "draft-gruszka-signed-evaluation-receipts": 27,
    "draft-gruszka-evaluation-receipt-mappings": 17,
    "draft-gruszka-scitt-statement-identification": 24,
}
OPAQUE = re.compile(r"(<!\[CDATA\[.*?\]\]>|<!--.*?-->|<\?.*?\?>|<!DOCTYPE.*?\]>|<[^>]+>)", re.S)
VERBATIM = {"artwork", "sourcecode", "bcp14"}


def tag_bcp14(xml, doc):
    """Wrap the keywords in the text between tags; returns (new xml, number wrapped, places left as they are)."""
    skip = NOT_BCP14.get(doc, [])
    found = {s: 0 for s in skip}
    stack, out, wrapped, before = [], [], 0, ""
    for i, part in enumerate(OPAQUE.split(xml)):
        if i % 2:   # a tag, a comment, a processing instruction, CDATA or the DOCTYPE
            out.append(part)
            m = re.match(r"<(/?)([A-Za-z0-9_:-]+)", part)
            if m and m.group(1):
                while stack and stack.pop() != m.group(2):
                    pass
            elif m and not part.endswith("/>"):
                stack.append(m.group(2))
            continue
        if not part or VERBATIM & set(stack) or "rfc" not in stack:
            out.append(part)
            continue
        pieces, last = [], 0
        for m in KEYWORD.finditer(part):
            prefix = re.sub(r"\s+", " ", before + part[:m.start()]).rstrip()
            hit = [s for s in skip if s[1] == m.group(1) and prefix.endswith(s[0])]
            if hit:
                found[hit[0]] += 1
                continue
            pieces += [part[last:m.start()], "<bcp14>%s</bcp14>" % m.group(1)]
            last = m.end()
            wrapped += 1
        pieces.append(part[last:])
        out.append("".join(pieces))
        before = re.sub(r"\s+", " ", before + part)[-200:]
    return "".join(out), wrapped, found


def main():
    path = sys.argv[1]
    xml = open(path, encoding="utf-8").read()
    doc = re.search(r'docName="([a-z0-9-]+?)-\d\d"', xml).group(1)
    lines_pi = len(re.findall(r"<\?line -?\d+\?>", xml))
    xml = re.sub(r"[ \t]*<\?line -?\d+\?>\n", "", xml)
    had_type = ' submissionType="IETF"' in xml
    xml = xml.replace(' submissionType="IETF"', "", 1)
    xml, wrapped, found = tag_bcp14(xml, doc)
    if any(n != 1 for n in found.values()) or wrapped != EXPECTED[doc]:
        raise SystemExit("bcp14: wrapped %d (expected %d), places left as they are %s" % (wrapped, EXPECTED[doc], found))
    if re.search(r"<\?line ", xml) or "submissionType" in xml:
        raise SystemExit("line PI or submissionType left")
    open(path, "w", encoding="utf-8").write(xml)
    print("%s: line PIs removed %d, submissionType removed %s, bcp14 %d, places left as they are %d"
          % (doc, lines_pi, had_type, wrapped, len(found)))


if __name__ == "__main__":
    main()
