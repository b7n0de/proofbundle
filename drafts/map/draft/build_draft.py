#!/usr/bin/env python3
"""Assemble draft-gruszka-evaluation-receipt-mappings-01 from the body, mappings.json and the receipts draft.

Substitutes @@CASES_TABLE@@, @@NON_CLAIMS@@ and @@APPENDIX@@ in draft_body.md:

  * the citation cases and the examples come from ../examples/mappings.json, byte for byte;
  * the non-claims list is copied from the body of the receipts draft, word for word, and the copy is
    checked against its source.

Deterministic.
"""
import base64
import json

import cbor2

HERE = __file__.rsplit("/", 1)[0] or "."
BODY = HERE + "/draft_body.md"
MAP = HERE + "/../examples/mappings.json"
RECEIPTS_BODY = HERE + "/../../ser/draft/draft_body.md"
OUT = HERE + "/draft-gruszka-evaluation-receipt-mappings-01.md"

LABELS = {1: "1 (alg)", 4: "4 (kid)", 15: "15 (CWT Claims)", 33: "33 (x5chain)", 258: "258 (payload hash algorithm)",
          259: "259 (preimage content type)"}


def wrap_hex(h, width=64):
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def artwork(*lines):
    return ["~~~"] + list(lines) + ["~~~", ""]


#: The one cross-reference the list may carry, and how this document writes it.
NON_CLAIMS_XREF = ("{{verification}}", "Section 5 of {{RECEIPTS}}")


def non_claims():
    """The section body of 'What a Receipt Does Not Prove' in the receipts draft, word for word, with its
    one cross-reference to the receipts draft's Section 5 written as a reference into that document."""
    src = open(RECEIPTS_BODY, encoding="utf-8").read()
    start = src.index("# What a Receipt Does Not Prove {#non-claims}\n") + len("# What a Receipt Does Not Prove {#non-claims}\n")
    end = src.index("\n# ", start)
    text = src[start:end].strip("\n")
    if text not in src or text.count(NON_CLAIMS_XREF[0]) != 1:
        raise SystemExit("non-claims copy is not verbatim or does not carry its one cross-reference")
    text = text.replace(*NON_CLAIMS_XREF)
    if text.count("{{") != 1:
        raise SystemExit("non-claims copy carries another cross-reference")
    return text


def cases_table(d):
    rows = ["| Case | Candidate | Result | Verification of the candidate | What it shows |",
            "|------|-----------|--------|-------------------------------|---------------|"]
    for c in d["citation_cases"]:
        verdict = c["candidate_verdict"] + ("" if c["candidate_verdict"] == "PASS" else
                                            ", step " + str(c["candidate_step"]))
        rows.append(f"| {c['id']} | {c['candidate']} | {c['expected_match']} | {verdict} | {c['shows']} |")
    rows.append('{: #cases title="Citation cases"}')
    return "\n".join(rows)


def cite_range(ids):
    """'Cases C1 to C8' for a contiguous run of case numbers, else a list."""
    nums = [int(i[1:]) for i in ids]
    if nums == list(range(nums[0], nums[0] + len(nums))) and len(nums) > 2:
        return f"Cases {ids[0]} to {ids[-1]}"
    return "Cases " + ", ".join(ids)


def reason(c):
    r = c["reason"].replace("of the receipts draft", "of {{RECEIPTS}} Section 5")
    return r[0].upper() + r[1:]


STATUS_TITLE = '{: #status-table title="Status vectors"}'


def status_section(d):
    """One Signed Statement for each status of the checking procedure, with its candidate receipt."""
    sv = d["status_vectors"]
    rows = ["| Vector | Candidate | Status | First failing step |",
            "|--------|-----------|--------|--------------------|",
            "| M2 | P1 | accepted | (none) |"]
    for s in sv:
        step = "(none)" if s["step"] is None else str(s["step"])
        rows.append(f"| {s['id']} | {s['candidate']} | {s['expected_status']} | {step} |")
    rows.append(STATUS_TITLE)
    rows += ["", "What each vector shows:", "",
             "* M2: the statement of {{m2}}, with the receipt it was made from."]
    rows += [f"* {s['id']}: " + s["shows"].replace("of the receipts draft", "of {{RECEIPTS}} Section 5") + "."
             for s in sv]
    fpub = base64.b64decode(d["foreign_public_key_b64"])
    out = ["## Status Vectors {#status-vectors}", "",
           "Each vector is a Signed Statement presented with a candidate receipt of {{RECEIPTS}}, whose bytes "
           "are given there. The Receiver's receipt key is the issuer test key, and its one configured pair is "
           "the issuer URI of {{constants}} with the issuer test key. With M2, the vectors give one statement "
           "for each status of {{check-statement}}; S1 is the statement with alg -8 that every Receiver "
           "accepts ({{alg-choice}}).", ""] + rows + ["",
           "S4 and S5 are signed by a foreign test key whose seed is SHA-256 over the UTF-8 bytes of "
           "\"receipt-cose foreign statement key, PURE TEST KEY\"; it MUST NOT be used for anything real. "
           "Its public key (base64 and hex):", ""] + artwork(d["foreign_public_key_b64"], fpub.hex())
    for s in sv:
        out += [f"{s['id']}, {len(s['statement_hex']) // 2} bytes (hex):", ""] + artwork(wrap_hex(s["statement_hex"]))
    out += ["Vector and SHA-256 over its bytes:", ""] + artwork(*[f"{s['id']} {s['statement_sha256']}" for s in sv])
    return out


REF_CHANGE = {"R1": "(none)", "R2": "`purpose` `evaluation` added",
              "R3": "`digest_alg` `sha-256`", "R4": "`digest` in uppercase",
              "R5": "`digest` names B of P2", "R6": "(none)"}


def reference_section(d):
    """Typed digest references under the declaration of Section 5.1, one per state."""
    ref1 = json.loads(d["reference_vectors"][0]["reference_json"])
    if ref1 != {"type": d["M1_dsse"]["payloadType"], "digest_alg": "SHA-256", "digest": d["receipt_digest"]["hex"]}:
        raise SystemExit("R1 is not the reference the text describes")
    rows = ["| Vector | Change to R1 | Candidate | State | Matching rule |",
            "|--------|--------------|-----------|-------|---------------|"]
    for r in d["reference_vectors"]:
        rows.append(f"| {r['id']} | {REF_CHANGE[r['id']]} | {r['candidate']} | {r['expected_state']} "
                    f"| {r['expected_match']} |")
    rows.append('{: #reference-table title="Typed digest references"}')
    out = ["## Typed Digest References {#reference-vectors}", "",
           "Each vector is a typed digest reference under the declaration of {{typed-reference}}, written as a "
           "JSON object. R1 has exactly three members: `type`, the type; `digest_alg`, `SHA-256`; and `digest`, "
           "the receipt digest of {{p1-digests}} as 64 lowercase hexadecimal digits. Each other vector is R1 "
           "with the change in {{reference-table}}; \"names B of P2\" means SHA-256 over B of vector P2 of "
           "{{RECEIPTS}}, as 64 lowercase hexadecimal digits. The candidate is the vector of {{RECEIPTS}} named "
           "in the table. State is the state of the reference in the terms of {{CPB}} Section 8.1, and Matching "
           "rule is the result of {{matching}} for the reference's `digest_alg` and `digest`.", ""] + rows + [
           "", "What each vector shows:", ""]
    out += [f"* {r['id']}: {r['shows']}." for r in d["reference_vectors"]]
    out += ["", "The matching rule reads only the algorithm and the digest, so for R2 it gives MATCH while the "
            "reference is Unresolved.", ""]
    return out


CERT_CHANGE = {"X2": "X1 with 1 (alg) -9 in place of -7",
               "X3": "X1 without parameter 33 (x5chain)",
               "X4": "X1 with `iss` in the form of {{signed-statement}}, whose F is SHA-256 over the test leaf "
                     "certificate",
               "X5": "X1 with one more parameter, 16 (typ), the text string \"application/cose\"",
               "X6": "X1's protected header unchanged"}


def did_parts(iss):
    """F and O of a did:x509 identifier of the form did:x509:0:sha256:F::eku:O, one per line."""
    head, rest = iss.split("did:x509:0:sha256:", 1)
    f, o = rest.split("::eku:", 1)
    if head or "did:x509:0:sha256:%s::eku:%s" % (f, o) != iss:
        raise SystemExit("iss is not of the form of the certificate profile")
    return ["F " + f, "O " + o]


def certificate_section(d):
    """The certificate profile: X1 in full, X2 to X6 as a change of X1 with their own signature."""
    cp = d["certificate_profile"]
    xv = d["certificate_vectors"]
    x1 = bytes.fromhex(xv[0]["statement_hex"])
    tag = cbor2.loads(x1)
    prot = cbor2.loads(tag.value[0])
    rows = ["| Vector | Bytes | Candidate | Status | First failing step |",
            "|--------|-------|-----------|--------|--------------------|"]
    for s in xv:
        step = "(none)" if s["step"] is None else str(s["step"])
        rows.append(f"| {s['id']} | {len(s['statement_hex']) // 2} | {s['candidate']} | {s['expected_status']} "
                    f"| {step} |")
    rows.append('{: #certificate-table title="Certificate-profile vectors"}')
    out = ["## Certificate-Profile Vectors {#certificate-vectors}", "",
           "Each vector is a Signed Statement in the form of the certificate profile, or one change away from "
           "it, presented with vector P1 of {{RECEIPTS}}. The Receiver's receipt key is the issuer test key, "
           "and its one configured certificate pair is the did:x509 identifier below with the test root "
           "certificate. The test root holds an RSA-3072 key and the test leaf a P-256 key; both "
           "certificates, and the other P-256 key that signs X6, are test material made by the generator of "
           "{{examples}}, and they MUST NOT be used for anything real. The signatures use the deterministic "
           "nonce of {{RFC6979}}.", "",
           "`iss` of X1, the identifier of the configured pair, is `did:x509:0:sha256:` F `::eku:` O with F, "
           "SHA-256 over the test root certificate in base64url without padding, and O, the object identifier "
           "of code signing:", ""] + artwork(*did_parts(cp["iss"])) + [
           f"Test leaf certificate, {len(cp['leaf_certificate_hex']) // 2} bytes (hex):", ""] + artwork(
           wrap_hex(cp["leaf_certificate_hex"])) + [
           f"Test root certificate, the trust anchor of the configured pair, "
           f"{len(cp['root_certificate_hex']) // 2} bytes (hex):", ""] + artwork(
           wrap_hex(cp["root_certificate_hex"])) + [
           "SHA-256 over the test leaf and over the test root certificate:", ""] + artwork(
           cp["leaf_certificate_sha256"], cp["root_certificate_sha256"]) + [
           "kid of X1, SHA-256 over the SubjectPublicKeyInfo of the test leaf (hex):", ""] + artwork(cp["kid_hex"])
    out += ["The protected header of X1 holds these parameters, in this order:", ""]
    for k in prot:
        v = prot[k]
        if k == 15:
            out += [f"* {LABELS[k]}: a map with 1 (iss), the identifier above, and 2 (sub), the `sub` of {{{{m2}}}}"]
        elif k == 33:
            out += [f"* {LABELS[k]}: an array of the test leaf and the test root certificate"]
        elif isinstance(v, bytes):
            out += [f"* {LABELS[k]}: the kid above"]
        elif isinstance(v, str):
            out += [f"* {LABELS[k]}: the type, as a text string"]
        else:
            out += [f"* {LABELS[k]}: {v}"]
    out += ["", "The unprotected header is the empty map, and the payload is the receipt digest of "
            "{{p1-digests}}.", "",
            f"X1, {len(x1)} bytes (hex):", ""] + artwork(wrap_hex(x1.hex()))
    out += ["Each of X2 to X6 is a COSE_Sign1 with tag 18 whose protected header is the deterministic encoding "
            "of the protected header of X1 with the change below, whose unprotected header is the empty map, "
            "whose payload is that of X1, and whose signature is given below, ECDSA with SHA-256 over its own "
            "Sig_structure, under the test leaf key except for X6, which the other P-256 test key signs.", ""]
    for s in xv[1:]:
        sig = cbor2.loads(bytes.fromhex(s["statement_hex"])).value[3]
        out += [f"{s['id']}: {CERT_CHANGE[s['id']]}. Signature (hex):", ""] + artwork(wrap_hex(sig.hex()))
    out += rows + ["", "What each vector shows:", ""]
    out += [f"* {s['id']}: {s['shows']}." for s in xv]
    out += ["", "Vector and SHA-256 over its bytes:", ""] + artwork(
        *[f"{s['id']} {s['statement_sha256']}" for s in xv])
    return out


def appendix(d):
    m1, m2 = d["M1_dsse"], d["M2_scitt_hash_envelope"]
    pub = base64.b64decode(d["issuer_public_key_b64"])
    out = ["The values below are derived from vectors of {{RECEIPTS}} (P1, and the candidates named in "
           "{{cases}} and {{status-table}}) and from the issuer test key of that document, whose seed is given there; the issuer "
           "URI of the Signed Statement is a constant of this example. " + d["test_material_notice"], "",
           "## Constants {#constants}", "",
           "Type:", ""] + artwork(m1["payloadType"]) + [
           "Issuer test key, public key (base64 and hex):", ""] + artwork(d["issuer_public_key_b64"], pub.hex()) + [
           "Issuer URI of the Signed Statement (`iss`):", ""] + artwork(m2["iss"])
    out += ["## Digests of Vector P1 {#p1-digests}", "",
            f"B, {len(d['payload_B_hex']) // 2} bytes (hex):", ""] + artwork(wrap_hex(d["payload_B_hex"])) + [
            "Receipt digest, SHA-256 over B:", ""] + artwork(d["receipt_digest"]["hex"]) + [
            "SHA-256 over the receipt bytes of P1; not the receipt digest:", ""] + artwork(
            d["source"]["receipt_sha256_of_bytes"])
    c9 = [c for c in d["citation_cases"] if c["citation"]["alg"] != "sha-256"]
    if any(c["citation"]["hex"] != d["receipt_digest"]["hex"] for c in d["citation_cases"] if c not in c9):
        raise SystemExit("a sha-256 case cites something other than the receipt digest")
    out += ["## Citation Cases {#case-bytes}", "",
            "Every case cites B of P1. " + cite_range([c["id"] for c in d["citation_cases"] if c not in c9]) +
            " cite, with the algorithm sha-256, the receipt digest given in {{p1-digests}}. " +
            " ".join(f"{c['id']} cites, with the algorithm {c['citation']['alg']}, this value over the same B:"
                     for c in c9), ""]
    for c in c9:
        out += artwork(wrap_hex(c["citation"]["hex"]))
    out += ["The candidates are the vectors of {{RECEIPTS}} named in {{cases}}, whose bytes are given there. "
            "Case and SHA-256 over the candidate's receipt bytes:", ""]
    out += artwork(*[f"{c['id']} {c['candidate_receipt_sha256']}" for c in d["citation_cases"]])
    out += ["The expected results are those of {{cases}}; the reasons are:", ""]
    out += [f"* {c['id']}: {reason(c)}." for c in d["citation_cases"]]
    out += [""]
    out += ["## M1, DSSE Envelope with the Receipt's Signature {#m1}", "",
            "The envelope is a JSON object with the members payloadType, payload and signatures, serialized "
            "without insignificant whitespace and with members sorted by name. Its only signature is "
            "signature.sig of P1, unchanged; it verifies as Ed25519 over PAE(payloadType, payload) under the "
            "issuer test key.", "",
            f"PAE(type, B), {len(d['pae_hex']) // 2} bytes (hex):", ""] + artwork(wrap_hex(d["pae_hex"])) + [
            f"Envelope, {len(m1['envelope_hex']) // 2} bytes (hex):", ""] + artwork(wrap_hex(m1["envelope_hex"])) + [
            "SHA-256 over the envelope bytes; not the receipt digest:", ""] + artwork(m1["envelope_sha256"])
    tag = cbor2.loads(bytes.fromhex(m2["cose_sign1_hex"]))
    prot = cbor2.loads(tag.value[0])
    sig = tag.value[3]
    out += ["## M2, SCITT Signed Statement Citing the Receipt by Digest {#m2}", "",
            "A COSE_Sign1 with CBOR tag 18 in the form of a COSE Hash Envelope. The protected header holds "
            "these parameters, in this order:", ""]
    for k in prot:
        v = prot[k]
        if k == 15:
            out += [f"* {LABELS[k]}: a map with 1 (iss), the URI of {{{{constants}}}}, and 2 (sub), the text "
                    "string given below"]
        elif isinstance(v, bytes):
            out += [f"* {LABELS[k]}: a {len(v)}-byte string, given below"]
        elif isinstance(v, str):
            out += [f"* {LABELS[k]}: the type, as a text string"]
        else:
            out += [f"* {LABELS[k]}: {v}"]
    out += ["", "kid, the COSE Key Thumbprint (SHA-256) of the issuer test key (hex):", ""] + artwork(m2["kid_hex"]) + [
            "sub, the model commitment of B:", ""] + artwork(m2["sub"]) + [
            f"Protected header, {len(m2['protected_hex']) // 2} bytes (hex):", ""] + artwork(
            wrap_hex(m2["protected_hex"])) + [
            "The unprotected header is the empty map. The payload is the receipt digest given in "
            "{{p1-digests}}.", "",
            f"Sig_structure (ToBeSigned), {len(m2['to_be_signed_hex']) // 2} bytes (hex), with external_aad the "
            "empty byte string:", ""] + artwork(wrap_hex(m2["to_be_signed_hex"])) + [
            "Signature, Ed25519 over the Sig_structure (hex):", ""] + artwork(wrap_hex(sig.hex())) + [
            f"COSE_Sign1, {len(m2['cose_sign1_hex']) // 2} bytes (hex):", ""] + artwork(
            wrap_hex(m2["cose_sign1_hex"])) + [
            "SHA-256 over the COSE_Sign1 bytes:", ""] + artwork(m2["cose_sign1_sha256"])
    out += status_section(d)
    out += reference_section(d)
    out += certificate_section(d)
    return "\n".join(out).rstrip("\n")


def main():
    d = json.load(open(MAP, encoding="utf-8"))
    body = open(BODY, encoding="utf-8").read()
    body = (body.replace("@@CASES_TABLE@@", cases_table(d)).replace("@@NON_CLAIMS@@", non_claims())
            .replace("@@APPENDIX@@", appendix(d)))
    if "@@" in body:
        raise SystemExit("unsubstituted token remains")
    open(OUT, "w", encoding="utf-8").write(body)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
