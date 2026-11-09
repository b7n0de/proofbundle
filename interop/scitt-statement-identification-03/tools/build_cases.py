#!/usr/bin/env python3
"""Build the case files of this folder from the text of draft-gruszka-scitt-statement-identification-03.

Usage:
    python3 tools/build_cases.py DRAFT_TEXT OUT_DIR

DRAFT_TEXT is the plain text of the draft as the IETF archive serves it,
https://www.ietf.org/archive/id/draft-gruszka-scitt-statement-identification-03.txt, with the SHA-256 below. The
script reads every byte string from the hex of Appendix A (nothing is typed in), applies the change each case of
Appendix A.3 states to a base statement of Appendix A.1, and stops unless the result has exactly the length and the
SHA-256 the case gives. It reads the expected axes from Table 2 of Section 6 and from the measured line of each case,
and stops unless both agree. It writes cases/C1.json to cases/C14.json, base_statements.json and test_keys.json
into OUT_DIR, and prints each check it made. It uses the Python standard library and check_cases.py of this folder.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys

DRAFT_SHA256 = "9176957ab9f3a4f4daca9dde67b3bcbb812417697f20e813c3ef3102c85bd95c"
DRAFT = "draft-gruszka-scitt-statement-identification-03"
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True  # no __pycache__ beside the files of the folder
_spec = importlib.util.spec_from_file_location("check_cases", os.path.join(_HERE, os.pardir, "check_cases.py"))
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

CHECKS = []


def check(cond, what):
    if not cond:
        sys.exit("STOP: " + what)
    CHECKS.append(what)


def clean(text):
    """The draft without page breaks: footer, form feed and running header lines are dropped."""
    out = []
    for line in text.replace("\f", "\n").split("\n"):
        if re.fullmatch(r"Gruszka\s+Expires \d+ \w+ \d{4}\s+\[Page \d+\]", line.strip()):
            continue
        if re.fullmatch(r"Internet-Draft\s+Identifying SCITT Signed Statements\s+\w+ \d{4}", line.strip()):
            continue
        out.append(line.rstrip())
    return "\n".join(out)


def paragraphs(text):
    return [p for p in re.split(r"\n\s*\n", text) if p.strip()]


def is_hex_block(p):
    lines = [x.strip() for x in p.strip().split("\n")]
    return all(re.fullmatch(r"(?:[0-9a-f]{2})+", x) for x in lines)


def hex_after(paras, i):
    """The hex block that is the paragraph after paras[i]."""
    check(i + 1 < len(paras) and is_hex_block(paras[i + 1]), "a hex block follows: " + one_line(paras[i])[:60])
    return bytes.fromhex("".join(x.strip() for x in paras[i + 1].strip().split("\n")))


def one_line(p):
    return " ".join(p.split())


def section(text, start, end):
    """From the line that begins with start (the table of contents indents its lines) to the next end."""
    a = text.index("\n" + start) + 1
    b = text.index(end, a + len(start)) if end else len(text)
    return text[a:b]


def obj(data):
    return {"base64": base64.b64encode(data).decode("ascii"), "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def axes_from(words):
    """{ref_usable, match, is_scitt, sig_valid} from 'ref_usable = True, match = MATCH, ...'."""
    out = {}
    for name, value in re.findall(r"(ref_usable|match|is_scitt|sig_valid) = (\w+)", words):
        check(name not in out, "each axis is named once: " + words)
        out[name] = {"True": True, "False": False, "None": None}.get(value, value)
    return out


def table2(text):
    """Rows of Table 2 of Section 6: id -> (requirement, axes, what it shows)."""
    a = text.index("+===+===+==========+")
    body = text[a:text.index("Table 2", a)]
    rows, cur = {}, None
    for line in body.split("\n"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.strip().startswith("|") else None
        if not cells or len(cells) != 7:
            cur = None if line.strip().startswith("+") else cur
            continue
        if cells[0] and not re.fullmatch(r"C\d+", cells[0]):
            cur = None
            continue
        if cells[0]:
            cur = cells[0]
            rows[cur] = {"req": cells[1], "axes": {"ref_usable": cells[2], "match": cells[3], "is_scitt": cells[4],
                                                   "sig_valid": cells[5]}, "shows": [cells[6]]}
        elif cur:
            check(not any(cells[:6]), "a continuation row of Table 2 adds nothing to the axes")
            rows[cur]["shows"].append(cells[6])
    out = {}
    for cid, r in rows.items():
        conv = {k: {"True": True, "False": False, "None": None}.get(v, v) for k, v in r["axes"].items()}
        out[cid] = (r["req"], conv, " ".join(x for x in r["shows"] if x).replace("/ ", "/"))
    return out


class Cose:
    """A COSE_Sign1 read with check_cases.decode, with the spans of its parts."""

    def __init__(self, data):
        self.data = data
        top = cc.decode_one(data)
        check(top.kind == "tagged" and top.tag == 18, "a base statement carries tag 18")
        arr = top.value
        check(arr.kind == "array" and len(arr.value) == 4, "a base statement is an array of four")
        self.arr, self.parts = arr, arr.value

    def splice(self, index, new_encoding):
        p = self.parts[index]
        return self.data[:p.start] + new_encoding + self.data[p.end:]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    raw = open(sys.argv[1], "rb").read()
    check(hashlib.sha256(raw).hexdigest() == DRAFT_SHA256, "the draft text has the SHA-256 " + DRAFT_SHA256)
    text = clean(raw.decode("utf-8"))
    out_dir = sys.argv[2]

    # Appendix A.1: the three base statements and the reference
    a1 = section(text, "A.1.  Base statements and the reference", "A.2.  Test keys")
    paras = paragraphs(a1)
    stmts = {}
    for i, p in enumerate(paras):
        m = re.fullmatch(r"Statement (0[123]) \((.*?); (\d+) bytes; SHA-256 ([0-9a-f]{64})\):", one_line(p))
        if m:
            data = hex_after(paras, i)
            check(len(data) == int(m.group(3)), "statement %s has %s bytes" % (m.group(1), m.group(3)))
            check(hashlib.sha256(data).hexdigest() == m.group(4), "statement %s has its SHA-256" % m.group(1))
            stmts[m.group(1)] = (data, m.group(2))
    check(sorted(stmts) == ["01", "02", "03"], "Appendix A.1 gives statements 01, 02 and 03")
    ref_digest = re.search(r"Reference digest \(SHA-256 over ToBeSigned of 01\):\s+([0-9a-f]{64})", a1).group(1)
    tbs_digest = re.search(r"01 ToBeSigned SHA-256:\s+([0-9a-f]{64})", a1).group(1)

    s01 = Cose(stmts["01"][0])
    payload01 = s01.parts[2].value
    tbs01 = cc.to_be_signed(s01.parts[0].value, b"", payload01)
    check(hashlib.sha256(tbs01).hexdigest() == tbs_digest == ref_digest,
          "SHA-256 over ToBeSigned of 01 is the digest Appendix A.1 gives twice")

    refs = []
    for sid in ("02", "03"):
        s = Cose(stmts[sid][0])
        prot = s.parts[0].value
        hdr = cc.decode_one(prot)
        found = [v for k, v in hdr.value if k.kind == "int" and k.value == -70001]
        check(len(found) == 1 and found[0].kind == "array" and len(found[0].value) == 1,
              "statement %s carries one reference under label -70001" % sid)
        r = found[0].value[0]
        refs.append(prot[r.start:r.end])
    check(refs[0] == refs[1], "statements 02 and 03 carry the same reference")
    reference = refs[0]
    rv = cc.decode_one(reference).value
    check([rv[0].value, rv[1].value, rv[2].value.hex()] == [-16, "ToBeSigned", ref_digest],
          "the reference is [-16, \"ToBeSigned\", digest of A.1]")

    # Appendix A.2: the test keys
    a2 = one_line(section(text, "A.2.  Test keys", "A.3.  Cases"))
    check("PURE TEST KEYS given as fixed seeds. They MUST NOT be used for any real statement." in a2,
          "Appendix A.2 marks the keys as pure test keys")
    keys = {}
    for name in ("issuer", "auditor"):
        m = re.search(name + r": \* Ed25519 seed \(hex, 32 bytes\): ([0-9a-f]{64}) \* kid \(hex, SHA-256 of the "
                      r"SubjectPublicKeyInfo\): ([0-9a-f]{64})", a2)
        seed, kid = bytes.fromhex(m.group(1)), m.group(2)
        pub = cc.public_key_from_seed(seed)
        check(hashlib.sha256(SPKI_ED25519 + pub).hexdigest() == kid,
              "the %s kid is SHA-256 of the SubjectPublicKeyInfo of the key derived from its seed" % name)
        keys[name] = {"seed": seed, "kid": kid, "public_key": pub}
    issuer = keys["issuer"]["public_key"]
    for sid, signer in (("01", "issuer"), ("02", "auditor"), ("03", "issuer")):
        s = Cose(stmts[sid][0])
        tbs = cc.to_be_signed(s.parts[0].value, b"", s.parts[2].value)
        check(cc.ed25519_rules(keys[signer]["public_key"], s.parts[3].value, tbs),
              "statement %s verifies under the %s key" % (sid, signer))

    # Table 2 and Appendix A.3
    t2 = table2(text)
    check(sorted(t2, key=lambda c: int(c[1:])) == ["C%d" % n for n in range(1, 15)], "Table 2 has rows C1 to C14")
    a3 = section(text, "A.3.  Cases", "Acknowledgments")
    blocks = re.split(r"\nA\.3\.(\d+)\.  (C\d+) \(requirement ([^)]*)\)\n", a3)
    cases = {}
    for j in range(1, len(blocks), 4):
        num, cid, req, body = blocks[j], blocks[j + 1], blocks[j + 2], blocks[j + 3]
        check(cid == "C" + num, "A.3.%s is case %s" % (num, cid))
        flat = one_line(body)
        m = re.search(r"candidate SHA-256 \(whole COSE_Sign1\): ([0-9a-f]{64}) \((\d+) bytes\)", flat)
        measured = axes_from(re.search(r"\* measured: (.*?sig_valid = \w+)", flat).group(1))
        cases[cid] = {"req": req, "body": body, "flat": flat, "sha256": m.group(1), "length": int(m.group(2)),
                      "measured": measured, "paras": paragraphs(body)}
    check(sorted(cases, key=lambda c: int(c[1:])) == ["C%d" % n for n in range(1, 15)], "A.3 has cases C1 to C14")

    def given_hex(cid, lead):
        paras = cases[cid]["paras"]
        idx = [i for i, p in enumerate(paras) if one_line(p).endswith(lead)]
        check(len(idx) == 1, "%s gives one hex block after '%s'" % (cid, lead))
        return hex_after(paras, idx[0])

    def new_sig(cid, lead="Signature (hex):"):
        sig = given_hex(cid, lead)
        check(len(sig) == 64, cid + " gives 64 signature bytes")
        return b"\x58\x40" + sig

    c = {}
    c["C1"] = stmts["01"][0]
    c["C2"] = stmts["03"][0]
    # C3: the license value "MIT" in the payload of 01 replaced by "BSD-3-Clause", signed again
    pl = payload01
    check(pl.count(b'"license":"MIT"') == 1, "C3: the payload of 01 holds the license value \"MIT\" once")
    c3 = s01.splice(2, cc._bstr(pl.replace(b'"license":"MIT"', b'"license":"BSD-3-Clause"')))
    c["C3"] = Cose(c3).splice(3, new_sig("C3"))
    # C4: content type, header parameter 3, "application/cbor" in place of "application/json", signed again
    prot = s01.parts[0].value
    check(prot.count(b"\x03\x70application/json") == 1, "C4: the protected header of 01 holds 3: \"application/json\"")
    c4 = s01.splice(0, cc._bstr(prot.replace(b"\x03\x70application/json", b"\x03\x70application/cbor")))
    c["C4"] = Cose(c4).splice(3, new_sig("C4"))
    # C5: the unprotected header {-70002: "added after signing"} in place of the empty map
    check(s01.parts[1].kind == "map" and s01.data[s01.parts[1].start:s01.parts[1].end] == b"\xa0",
          "C5: the unprotected header of 01 is the empty map a0")
    c["C5"] = s01.splice(1, b"\xa1\x3a\x00\x01\x11\x71\x73added after signing")
    # C6, C7, C11: the signature replaced
    c["C6"] = s01.splice(3, new_sig("C6", "under the auditor key (hex):"))
    c["C7"] = s01.splice(3, new_sig("C7"))
    c["C11"] = s01.splice(3, new_sig("C11", "replaced by (hex):"))
    # C8: the payload replaced by nil and the signature replaced
    c8 = s01.splice(2, b"\xf6")
    c["C8"] = Cose(c8).splice(3, new_sig("C8", "its signature replaced by (hex):"))
    # C9: without its first byte, the tag 18
    check(s01.data[:1] == b"\xd2", "C9: the first byte of 01 is d2")
    c["C9"] = s01.data[1:]
    # C10, C13, C14: the candidate of C1
    c["C10"] = c["C13"] = c["C14"] = stmts["01"][0]
    # C12: the head of the array, the byte 84 after the tag, written as 98 04
    check(s01.data[1:2] == b"\x84", "C12: the byte after the tag of 01 is 84")
    c["C12"] = s01.data[:1] + b"\x98\x04" + s01.data[2:]
    for cid, data in c.items():
        check(len(data) == cases[cid]["length"], "%s: the candidate has %d bytes" % (cid, cases[cid]["length"]))
        check(hashlib.sha256(data).hexdigest() == cases[cid]["sha256"], cid + ": the candidate has its SHA-256")

    # The inputs that are not the base reference
    aad7 = re.search(r"external_aad \(hex, (\d+) bytes\): ([0-9a-f]+)", cases["C7"]["flat"])
    aad7_bytes = bytes.fromhex(aad7.group(2))
    check(len(aad7_bytes) == int(aad7.group(1)), "C7: external_aad has its stated length")
    ref13 = given_hex("C13", "is (46 bytes, hex):")
    ref14 = given_hex("C14", "is (47 bytes, hex):")
    check(len(ref13) == 46 and len(ref14) == 47, "C13 and C14 give references of 46 and 47 bytes")
    check(ref13 == b"\x83\x2f\x6aToBeSigned\x58\x1f" + bytes.fromhex(ref_digest)[:31],
          "C13: the reference of A.1 with the last byte of its digest removed")
    check(ref14 == b"\x83\x2f\x6aWholeBytes\x58\x20" + bytes.fromhex(ref_digest),
          "C14: the reference of A.1 with the scheme \"WholeBytes\" in place of \"ToBeSigned\"")

    # Expected axes: Table 2 and the measured line of A.3 must agree
    for cid in c:
        req, row, shows = t2[cid]
        check(row == cases[cid]["measured"], cid + ": Table 2 and the measured line of A.3 give the same four axes")
        check(req == cases[cid]["req"].split("/")[0], cid + ": Table 2 and A.3 name the same requirement")

    # Variants Appendix A.3 states in words
    flat1, flat7, flat8, flat11 = (cases[k]["flat"] for k in ("C1", "C7", "C8", "C11"))
    check("Supplied together with a detached payload, for example 32 zero bytes, the candidate gives the same four "
          "axes" in flat1, "C1 states the variant with 32 zero bytes as detached payload")
    v7 = re.search(r"the same candidate bytes under the fixed empty external_aad rule: (match = \w+, sig_valid = \w+)",
                   flat7)
    v8 = re.search(r"Supplied with the payload of statement 01 as its detached payload, the candidate gives "
                   r"(ref_usable = \w+, match = \w+, is_scitt = \w+ and sig_valid = \w+)", flat8)
    v11 = re.search(r"with rule 2 left out: the cofactorless equation gives sig_valid = (\w+), the cofactored "
                    r"equation gives sig_valid = (\w+)", flat11)
    check(bool(v7 and v8 and v11), "C7, C8 and C11 state their variants")
    variants = {
        "C1": [{"name": "with 32 zero bytes supplied as detached payload",
                "change": {"detached_payload": obj(b"\x00" * 32)}, "expected": dict(cases["C1"]["measured"])}],
        "C7": [{"name": "under the fixed empty external_aad rule", "change": {"external_aad": obj(b"")},
                "expected": axes_from(v7.group(1))}],
        "C8": [{"name": "with the payload of statement 01 supplied as detached payload",
                "change": {"detached_payload": obj(payload01)}, "expected": axes_from(v8.group(1).replace(" and ", ", "))}],
        "C11": [{"name": "with rule 2 left out and the cofactorless equation", "rules": "no-rule-2",
                 "expected": {"sig_valid": {"True": True, "False": False}[v11.group(1)]}},
                {"name": "with rule 2 left out and the cofactored equation", "rules": "no-rule-2-cofactored",
                 "expected": {"sig_valid": {"True": True, "False": False}[v11.group(2)]}}],
    }

    # The words of each case that state its candidate
    def stated(cid):
        """The prose of the case as the draft writes it: every paragraph but the bullets and the hex blocks."""
        return [one_line(p) for p in cases[cid]["paras"] if not p.strip().startswith("*") and not is_hex_block(p)]

    os.makedirs(os.path.join(out_dir, "cases"), exist_ok=True)
    for cid in sorted(c, key=lambda k: int(k[1:])):
        req, row, shows = t2[cid]
        inputs = {
            "candidate": obj(c[cid]),
            "reference": obj({"C13": ref13, "C14": ref14}.get(cid, reference)),
            "scheme": {"alg": -44 if cid == "C10" else -16, "name": "ToBeSigned"},
            "external_aad": obj(aad7_bytes if cid == "C7" else b""),
            "detached_payload": None,
            "stated_key": {"name": "issuer", "public_key": obj(issuer)},
        }
        doc = {"id": cid, "draft": DRAFT, "source": "Appendix A.3.%s, Table 2 of Section 6" % cid[1:],
               "requirement": cases[cid]["req"], "what_it_shows": shows, "derivation": stated(cid),
               "inputs": inputs, "expected": row}
        if cid in variants:
            doc["variants"] = variants[cid]
        write_json(os.path.join(out_dir, "cases", cid + ".json"), doc)
    write_json(os.path.join(out_dir, "base_statements.json"), {
        "draft": DRAFT, "source": "Appendix A.1",
        "statements": {sid: {"description": desc, "bytes": obj(data)} for sid, (data, desc) in sorted(stmts.items())},
        "reference": {"description": "[-16, \"ToBeSigned\", digest], the one reference statements 02 and 03 carry "
                                     "under COSE header label -70001; the digest is SHA-256 over the ToBeSigned of 01",
                      "bytes": obj(reference)}})
    write_json(os.path.join(out_dir, "test_keys.json"), {
        "draft": DRAFT, "source": "Appendix A.2",
        "warning": "PURE TEST KEYS given as fixed seeds. They MUST NOT be used for any real statement.",
        "keys": {name: {"ed25519_seed_hex": k["seed"].hex(), "kid_hex": k["kid"], "public_key_hex": k["public_key"].hex()}
                 for name, k in keys.items()}})
    for line in CHECKS:
        print("ok  " + line)
    print("%d checks against the text of %s" % (len(CHECKS), DRAFT))


def write_json(path, doc):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
