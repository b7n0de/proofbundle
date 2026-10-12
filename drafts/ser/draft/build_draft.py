#!/usr/bin/env python3
"""Assemble draft-gruszka-signed-evaluation-receipts-02 from the body and vectors.json.

Substitutes @@VECTORS_TABLE@@ and @@VECTORS_APPENDIX@@ in draft_body.md with content generated from
../examples/vectors.json, so the draft's vectors are the run set byte for byte. Deterministic.
"""
import base64
import json
import textwrap

HERE = __file__.rsplit("/", 1)[0] or "."
BODY = HERE + "/draft_body.md"
VEC = HERE + "/../examples/vectors.json"
OUT = HERE + "/draft-gruszka-signed-evaluation-receipts-02.md"

def order(v):
    """Presentation order: positive vectors first, then negative, each by number."""
    return (v["id"][0] != "P", int(v["id"][1:]))


def md_text(s):
    """Escape the brackets of point formulas such as [S]B, which kramdown would read as link references, and the
    asterisks of products such as r*B' and k*a, two of which kramdown would read as emphasis."""
    return s.replace("[", "\\[").replace("]", "\\]").replace("*", "\\*")


def wrap_hex(h, width=64):
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def key_name(doc, b64key):
    if b64key == doc["test_keys"]["issuer"]["public_raw_b64"]:
        return "the issuer test key"
    if b64key == doc["test_keys"]["mixed_order"]["public_raw_b64"]:
        return "the mixed-order test key"
    raw = base64.b64decode(b64key)
    if raw == (1).to_bytes(32, "little"):
        return "the neutral element, canonical encoding (01 followed by 31 zero bytes)"
    if raw == (2 ** 255 - 18).to_bytes(32, "little"):
        return "the neutral element, non-canonical encoding y = p + 1 (EE, 30 bytes FF, 7F)"
    raise SystemExit("unnamed verification key " + b64key)


def table(doc):
    rows = ["| ID | Step | Expected | What it shows |", "|----|------|----------|---------------|"]
    for v in sorted(doc["vectors"], key=order):
        rows.append(f"| {v['id']} | {v['step']} | {v['expected']} | {v['requirement']} |")
    return "\n".join(rows)


def artwork(*lines):
    return ["~~~"] + list(lines) + ["~~~", ""]


def appendix(doc):
    f, out = doc["format"], []
    out += ["The vectors below are complete: a verifier needs only the bytes given here and the "
            "verification key named for each vector.", "",
            "## Constants and Test Material", "",
            "Receipt schema, also the type of {{type}}:", ""] + artwork(f["receipt_schema"]) + [
            "Payload schema:", ""] + artwork(f["payload_schema"]) + [
            "commit_alg:", ""] + artwork(f["commit_alg"]) + [
            textwrap.fill(doc["test_material_notice"], width=72, break_on_hyphens=False), ""]
    for name, label in (("issuer", "Issuer test key"), ("other", "Second test key, used only as a wrong hint")):
        k = doc["test_keys"][name]
        out += [f"{label}, Ed25519 seed (hex, 32 bytes) and public key (base64, 32 bytes):", ""]
        out += artwork(k["ed25519_seed_hex"], k["public_raw_b64"])
    m = doc["test_keys"]["mixed_order"]
    out += ["Mixed-order test key, used only by vector N61: the public point of the issuer test key plus a "
            "point of order 8. It has no RFC 8032 seed; the discrete logarithm of its prime-order part is the "
            "secret scalar of the issuer test key. The point of order 8, which vector N59 also adds to its R "
            "(hex, 32 bytes), and the public key (base64, 32 bytes):", ""]
    out += artwork(m["order8_point_hex"], m["public_raw_b64"])
    for name in ("model", "dataset"):
        s = doc["test_salts"][name]
        out += [f"The {name} commitment: salt (hex, 16 bytes), identifier, commitment:", ""]
        out += artwork(s["salt_hex"], s["identifier"], s["commit"])
    c = doc["test_criteria"]
    out += ["The example criteria set of vectors P10 and N57: its bytes (hex), and criteria_digest over them:", ""]
    out += artwork(wrap_hex(c["bytes_hex"]), c["criteria_digest"])
    out += ["## Vector Set {#vector-set}", ""]
    for v in sorted(doc["vectors"], key=order):
        out += [f"### {v['id']} ({v['requirement']}; expected {v['expected']}, step {v['step']})", "",
                textwrap.fill(md_text(v["reason"]), width=72, break_on_hyphens=False), ""]
        if v.get("note"):
            out += [textwrap.fill(md_text("Note: " + v["note"] + "."), width=72, break_on_hyphens=False), ""]
        n_b = len(v["payload_hex"]) // 2
        first = v["step"].split()[0]
        out += [f"* verification key: {key_name(doc, v['verification_key_b64'])}"]
        if not n_b:
            out += ["* payload bytes B: none, payload_b64 does not decode"]
        elif first in ("1", "2", "3"):
            # The procedure stops before it obtains B; the bytes shown are what payload_b64 carries.
            out += [f"* payload bytes carried (not B: the procedure stops at step {first} before it obtains B): "
                    f"{n_b} bytes, SHA-256 {v['payload_sha256']}"]
        else:
            out += [f"* payload bytes B: {n_b} bytes, SHA-256 {v['payload_sha256']}"]
        out += [f"* receipt bytes: {len(v['receipt_hex']) // 2} bytes, SHA-256 {v['receipt_sha256']}", ""]
        if n_b:
            label = "Payload bytes carried (hex):" if first in ("1", "2", "3") else "B (hex):"
            out += [label, ""] + artwork(wrap_hex(v["payload_hex"]))
        out += ["Receipt (hex):", ""] + artwork(wrap_hex(v["receipt_hex"]))
    return "\n".join(out).rstrip("\n")


def main():
    doc = json.load(open(VEC, encoding="utf-8"))
    body = open(BODY, encoding="utf-8").read()
    body = body.replace("@@VECTORS_TABLE@@", table(doc)).replace("@@VECTORS_APPENDIX@@", appendix(doc))
    if "@@" in body:
        raise SystemExit("unsubstituted token remains")
    open(OUT, "w", encoding="utf-8").write(body)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
