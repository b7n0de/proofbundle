#!/usr/bin/env python3
"""Assemble the Z156 kramdown-rfc draft from the static body and cases.json.

Substitutes @@CASES_TABLE@@ and @@CASES_APPENDIX@@ in draft_body.md with content
generated from ../examples/cases.json, so the draft's cases stay in sync with the
run set. Deterministic.
"""
import json
import textwrap

HERE = __file__.rsplit("/", 1)[0] or "."
BODY = HERE + "/draft_body.md"
CASES = HERE + "/../examples/cases.json"
OUT = HERE + "/draft-gruszka-scitt-statement-identification-01.md"

SHORT = {
    "C1": "positive control",
    "C2": "subject grouping is not single identity",
    "C3": "changed target payload",
    "C4": "changed protected header",
    "C5": "added unprotected parameter (envelope)",
    "C6": "signature replaced, same signed input",
    "C7": "non-empty external_aad",
    "C8": "detached payload not supplied",
    "C9": "tag 18 removed",
    "C10": "scheme/algorithm mismatch",
    "C11": "R of mixed order",
    "C12": "outer encoding changed, tag 18 kept",
}


#: Nachtrag 17g, N4 and N7: the case file refers to the draft from outside ("Appendix A") and states how the
#: generator derives the test seeds. Inside Appendix A the draft words this from its own position. cases.json
#: and the generator stay byte-identical; each phrase must occur exactly once, so a drift stops the build.
IN_APPENDIX = {
    "C7": [("(given in Appendix A)", "(given below)"),
           ("are reported separately in Appendix A", "are reported separately below")],
}
NOTICE_WORDING = [("derived by SHA-256 from fixed labels", "given as fixed seeds")]


def reword(text, pairs, where):
    for old, new in pairs:
        if text.count(old) != 1:
            raise SystemExit(f"{where}: expected one {old!r}")
        text = text.replace(old, new)
    return text


def wrap_hex(h, width=64):
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


#: Nachtrag 17i: the Req cell of Table 2 is the requirement up to its first slash (C9: A1), so the table fits
#: 72 columns. The heading of each case in Appendix A keeps the full requirement of cases.json.
def table(doc):
    rows = ["| ID | Req | ref_usable | match | is_scitt | sig_valid | What it shows |",
            "|----|-----|------------|-------|----------|-----------|---------------|"]
    for c in doc["cases"]:
        r = c["result"]
        rows.append(f"| {c['id']} | {c['requirement'].split('/')[0]} | {r['ref_usable']} | {r['match']} | {r['is_scitt']} | "
                    f"{r['sig_valid']} | {SHORT.get(c['id'], '')} |")
    return "\n".join(rows)


def appendix(doc):
    out = []
    s = doc["statements"]
    out.append("## Base statements and the reference")
    out.append("")
    out.append(f"All three statements share the subject `{s['01']['sub']}`. COSE header label "
               f"{doc['reference_label']} (Private Use) carries a list of references; in these examples "
               f"the list holds exactly one, `[-16, \"ToBeSigned\", digest]`, which references statement "
               f"01, and its digest is SHA-256 over the ToBeSigned of 01.")
    out.append("")
    out.append(f"* Reference digest (SHA-256 over ToBeSigned of 01): {doc['reference_to_01']['digest']}")
    out.append(f"* 01 ToBeSigned SHA-256: {s['01']['sha256_to_be_signed']}")
    for k in ("01", "02", "03"):
        out.append("")
        refs = f", refers to {s[k].get('refers_to')}" if s[k].get("refers_to") else ""
        out.append(f"Statement {k} (iss {s[k]['iss']}{refs}; {s[k]['bytes']} bytes; "
                   f"SHA-256 {s[k]['sha256_cose_sign1']}):")
        out.append("")
        out.append("~~~")
        out.append(wrap_hex(s[k]["hex"]))
        out.append("~~~")
    out.append("")
    out.append("## Test keys")
    out.append("")
    out.append(textwrap.fill(reword(doc["test_key_notice"], NOTICE_WORDING, "test_key_notice"), width=72))
    out.append("")
    for name, info in doc["test_keys"].items():
        out.append(f"{name}:")
        out.append("")
        out.append(f"* Ed25519 seed (hex, 32 bytes): {info['ed25519_seed_hex']}")
        out.append(f"* kid (hex, SHA-256 of the SubjectPublicKeyInfo): {info['kid_hex']}")
        out.append("")
    out.append("## Cases")
    out.append("")
    out.append("Each case below gives the candidate's full bytes and its SHA-256, so a reader can "
               "confirm the exact bytes the case was run on. The expected axes are in the table of "
               "Section 6; the measured axes are given here.")
    out.append("")
    for c in doc["cases"]:
        out.append(f"### {c['id']} (requirement {c['requirement']})")
        out.append("")
        out.append(textwrap.fill(reword(c["description"], IN_APPENDIX.get(c["id"], []), c["id"]), width=72))
        out.append("")
        r = c["result"]
        out.append(f"* candidate SHA-256 (whole COSE_Sign1): {c['candidate_sha256_cose_sign1']} "
                   f"({c['candidate_bytes']} bytes)")
        if c.get("aad_hex"):
            out.append(f"* external_aad (hex, {len(c['aad_hex']) // 2} bytes): {c['aad_hex']}")
        out.append(f"* measured: ref_usable = {r['ref_usable']}, match = {r['match']}, "
                   f"is_scitt = {r['is_scitt']}, sig_valid = {r['sig_valid']}")
        if c.get("empty_aad_result"):
            e = c["empty_aad_result"]
            out.append(f"* the same candidate bytes under the fixed empty external_aad rule: "
                       f"match = {e['match']}, sig_valid = {e['sig_valid']}")
        if c.get("without_rule_2"):
            w = c["without_rule_2"]
            out.append(f"* with rule 2 left out: the cofactorless equation gives sig_valid = "
                       f"{w['cofactorless']}, the cofactored equation gives sig_valid = {w['cofactored']}")
        if c.get("note"):
            out.append(f"* note: {c['note']}")
        out.append("")
        out.append("~~~")
        out.append(wrap_hex(c["candidate_hex"]))
        out.append("~~~")
        out.append("")
    return "\n".join(out)


def main():
    doc = json.load(open(CASES, encoding="utf-8"))
    body = open(BODY, encoding="utf-8").read()
    body = body.replace("@@CASES_TABLE@@", table(doc)).replace("@@CASES_APPENDIX@@", appendix(doc))
    if "@@" in body:
        raise SystemExit("unsubstituted token remains")
    open(OUT, "w", encoding="utf-8").write(body)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
