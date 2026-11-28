"""Run the SER -04 verifier on the vector file and check the file against Appendix A.

Usage: python3 -I lauf_ser.py <anlage-dir> <out-dir>
Writes ser_vektoren.json, ser_vektoren.md, ser_datei_gegen_A3.md, ser_A2_gegen_datei.md,
ser_schluessel_und_profil.md.
"""
import base64
import hashlib
import json
import os
import re
import sys

MODULE_ROOT = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, MODULE_ROOT)
from gemeinsam import ed25519 as E
from gemeinsam import ijson
from gemeinsam.txt import Draft
from ser04.pruefer_ser import TYPE, pae, step_label, verify

ANL, OUT = sys.argv[1], sys.argv[2]
D = Draft(os.path.join(ANL, "draft-gruszka-signed-evaluation-receipts-04.txt"))
VPATH = os.path.join(ANL, "test-vectors.json")
sha = lambda b: hashlib.sha256(b).hexdigest()
out = {}

# ---------- keys from the text (A.1, Section 5, file items) ----------
def next_values(start, k):
    """The next k value lines (hex or base64) after line start, skipping prose and page furniture."""
    vals = []
    for n, t in D.body(start + 1, start + 40):
        s = t.strip()
        if re.fullmatch(r"[0-9a-f]{64}|[A-Za-z0-9+/]{43}=", s):
            vals.append(s)
            if len(vals) == k:
                return vals
    raise ValueError(start)


seed_issuer, b = next_values(D.find("Issuer test key, Ed25519 seed"), 2)
seed_issuer, pub_issuer_txt = bytes.fromhex(seed_issuer), base64.b64decode(b)
seed_second, b = next_values(D.find("Second test key, used only as a wrong hint"), 2)
seed_second, pub_second_txt = bytes.fromhex(seed_second), base64.b64decode(b)
o8, b = next_values(D.find("Mixed-order test key, used only by vector N61"), 2)
order8_txt, pub_mixed_txt = bytes.fromhex(o8), base64.b64decode(b)

pub_issuer = E.public_from_seed(seed_issuer)[0]
pub_second = E.public_from_seed(seed_second)[0]
P8 = E.decode(order8_txt)
mixed = E.encode(E.add(E.decode(pub_issuer), P8))
neutral_canon = bytes([1]) + bytes(31)
neutral_ycp1 = bytes([0xEE]) + b"\xff" * 30 + bytes([0x7F])

keychecks = {
    "issuer seed -> public key equals A.1 base64": pub_issuer == pub_issuer_txt,
    "second seed -> public key equals A.1 base64": pub_second == pub_second_txt,
    "order-8 point decodes canonically": P8 is not None,
    "order-8 point has order exactly 8": P8 is not None and E.is_neutral(E.mul(8, P8)) and not E.is_neutral(E.mul(4, P8)),
    "issuer public point + order-8 point equals A.1 mixed-order key": mixed == pub_mixed_txt,
    "mixed-order key order class": E.order_class(E.decode(pub_mixed_txt)),
    "issuer key order class": E.order_class(E.decode(pub_issuer)),
    "neutral canonical encoding decodes, order class": E.order_class(E.decode(neutral_canon)),
    "y = p + 1 encoding rejected by RFC 8032 5.1.3 decoding": E.decode(neutral_ycp1) is None,
    "y = p + 1 read by a y-mod-p decoder is the neutral element": E.is_neutral(E.decode_lenient(neutral_ycp1)),
}
KEYS = {
    "the issuer test key": pub_issuer_txt,
    "the neutral element, canonical encoding (01 followed by 31 zero bytes)": neutral_canon,
    "the neutral element, non-canonical encoding y = p + 1 (EE, 30 bytes FF, 7F)": neutral_ycp1,
    "the mixed-order test key": pub_mixed_txt,
}

# ---------- Section 5: the 40 encodings a y-mod-p decoder would try ----------
enc40 = []
for y in range(E.p, E.p + 19):
    for sgn in (0, 1):
        enc40.append(((y | (sgn << 255)).to_bytes(32, "little"), "y=p+%d sign %d" % (y - E.p, sgn)))
for y in (1, E.p - 1):  # the two points with x = 0
    enc40.append(((y | (1 << 255)).to_bytes(32, "little"), "x=0 y=%s sign 1" % ("1" if y == 1 else "p-1")))
cls = {"nopoint": 0, "small": 0, "mixed": 0, "L": 0}
rejected = 0
for b, _ in enc40:
    if E.decode(b) is None:
        rejected += 1
    P = E.decode_lenient(b)
    if P is None:
        cls["nopoint"] += 1
    else:
        cls[E.order_class(P)] += 1
keychecks["Section 5: encodings considered"] = len(enc40)
keychecks["Section 5: of them rejected by rule 1 decoding"] = rejected
keychecks["Section 5: y-mod-p decoder gives no point / small / mixed / order L"] = "%d / %d / %d / %d" % (cls["nopoint"], cls["small"], cls["mixed"], cls["L"])

# ---------- the file against A.3 ----------
raw = open(VPATH, "rb").read()
a3 = D.find("A.3.  The Complete Vector Set", 1480)
size_txt = int(re.search(r"size: (\d+) bytes", D.words(a3, a3 + 10)).group(1))
sha_txt = re.search(r"SHA-256: ([0-9a-f]{64})", D.words(a3, a3 + 12)).group(1)
fchecks = []
fchecks.append(("size equals A.3", len(raw), size_txt, len(raw) == size_txt))
fchecks.append(("SHA-256 equals A.3", sha(raw), sha_txt, sha(raw) == sha_txt))
try:
    top, issues = ijson.parse(raw)
    fchecks.append(("one JSON text in UTF-8, strict parse (no BOM, no trailing data)", "issues=%s" % issues, "no issues", not issues))
except Exception as e:  # noqa
    fchecks.append(("one JSON text in UTF-8", repr(e), "parses", False))
F = json.loads(raw.decode("utf-8"))
fchecks.append(("top-level members", sorted(F.keys()), sorted(["document", "title", "note", "count", "vectors"]),
                sorted(F.keys()) == sorted(["document", "title", "note", "count", "vectors"])))
fchecks.append(("document is the name of this draft", F["document"], "draft-gruszka-signed-evaluation-receipts-04",
                F["document"] == "draft-gruszka-signed-evaluation-receipts-04"))
fchecks.append(("title and note are strings", (type(F["title"]).__name__, type(F["note"]).__name__), "str, str",
                isinstance(F["title"], str) and isinstance(F["note"], str)))
fchecks.append(("count equals number of vectors", (F["count"], len(F["vectors"])), "66, 66", F["count"] == len(F["vectors"]) == 66))

# Table 2 from the text
t2a, t2b = D.find("| ID  | Step"), D.find("Table 2", D.find("| ID  | Step"))
rows, cur = [], None
for n, t in D.body(t2a + 2, t2b - 1):
    s = t.strip()
    if not s.startswith("|"):
        continue
    cells = [c.strip() for c in s.strip("|").split("|")]
    if cells[0]:
        cur = {"id": cells[0], "step": cells[1], "expected": cells[2], "label": cells[3]}
        rows.append(cur)
    elif cur and any(cells):
        cur["step"] = (cur["step"] + " " + cells[1]).strip()
        cur["label"] = (cur["label"] + cells[3]).strip() if cells[3] else cur["label"]
for r in rows:
    r["step"] = r["step"].replace("( ", "(").replace(" )", ")").replace("(profile ", "(profile ")
T2 = {r["id"]: r for r in rows}
fchecks.append(("Table 2 rows read from the text", len(rows), 66, len(rows) == 66))
ids = [v["id"] for v in F["vectors"]]
fchecks.append(("vectors in the order of Table 2", ids == [r["id"] for r in rows], True, ids == [r["id"] for r in rows]))

struct_problems = []
for v in F["vectors"]:
    if sorted(v.keys()) != sorted(["id", "label", "expected", "step", "description", "items", "bytes"]):
        struct_problems.append((v["id"], "members %s" % sorted(v.keys())))
    t = T2.get(v["id"])
    if t is None:
        struct_problems.append((v["id"], "not in Table 2"))
    else:
        for k in ("label", "expected", "step"):
            if v[k] != t[k]:
                struct_problems.append((v["id"], "%s file=%r Table2=%r" % (k, v[k], t[k])))
    if not (isinstance(v["description"], list) and all(isinstance(x, str) for x in v["description"])):
        struct_problems.append((v["id"], "description is not an array of strings"))
    if not (isinstance(v["items"], list) and all(isinstance(x, str) for x in v["items"])):
        struct_problems.append((v["id"], "items is not an array of strings"))
    labels = []
    for b in v["bytes"]:
        if sorted(b.keys()) != sorted(["label", "length", "sha256", "hex"]):
            struct_problems.append((v["id"], "bytes members %s" % sorted(b.keys())))
        if b["label"] not in ("B", "Receipt", "Payload bytes carried"):
            struct_problems.append((v["id"], "bytes label %r" % b["label"]))
        bb = bytes.fromhex(b["hex"])
        if len(bb) != b["length"] or sha(bb) != b["sha256"]:
            struct_problems.append((v["id"], "bytes %s: length/sha256 do not match hex" % b["label"]))
        labels.append(b["label"])
        # the items must name size and SHA-256 of each byte string
        if not any(("%d bytes, SHA-256 %s" % (b["length"], b["sha256"])) in it for it in v["items"]):
            struct_problems.append((v["id"], "no item names size and SHA-256 of %s" % b["label"]))
    if not v["items"] or not v["items"][0].startswith("verification key: "):
        struct_problems.append((v["id"], "first item does not name the verification key"))
    for it in v["items"]:
        if not it.startswith("verification key: ") and not re.search(r"\d+ bytes, SHA-256 [0-9a-f]{64}$", it):
            struct_problems.append((v["id"], "item names no size and SHA-256: %r" % it))

# ---------- run every vector ----------
results = []
for v in F["vectors"]:
    keyname = v["items"][0][len("verification key: "):]
    vk = KEYS.get(keyname)
    receipt = bytes.fromhex([b for b in v["bytes"] if b["label"] == "Receipt"][0]["hex"])
    r = verify(receipt, vk)
    got = step_label(r)
    exp_res, exp_step = v["expected"], v["step"]
    same = (r["result"] == exp_res) and (got == exp_step)
    Bfile = [b for b in v["bytes"] if b["label"] == "B"]
    b_ok = None
    if Bfile:
        b_ok = r.get("B") is not None and r["B"].hex() == Bfile[0]["hex"]
    results.append({"id": v["id"], "label": v["label"], "key": keyname, "expected": exp_res, "expected_step": exp_step,
                    "result": r["result"], "step": got, "reason": r.get("reason"), "same": same,
                    "B_from_steps_1_3_equals_file_B": b_ok,
                    "table2_expected": T2[v["id"]]["expected"], "table2_step": T2[v["id"]]["step"]})

# ---------- diagnostics on profile vectors ----------
diag = {}
byid = {v["id"]: v for v in F["vectors"]}
for vid in ("N6", "N7", "N12", "N16", "N17", "N18", "N53", "N54", "N59", "N61"):
    v = byid[vid]
    rc = bytes.fromhex([b for b in v["bytes"] if b["label"] == "Receipt"][0]["hex"])
    obj = json.loads(rc)
    sigb = base64.b64decode(obj["signature"]["sig"])
    B = base64.b64decode(obj["payload_b64"])
    vk = KEYS[v["items"][0][len("verification key: "):]]
    R = sigb[:32]
    info = {"R decodes (rule 1)": E.decode(R) is not None,
            "R order class": E.order_class(E.decode(R)) if E.decode(R) else ("lenient:" + E.order_class(E.decode_lenient(R)) if E.decode_lenient(R) else "no point"),
            "S below L": int.from_bytes(sigb[32:], "little") < E.L,
            "S": int.from_bytes(sigb[32:], "little") if int.from_bytes(sigb[32:], "little") < 1000 else "large",
            "equations (no rules 1-3)": E.equations(vk, sigb, pae(TYPE, B))}
    if vid == "N7":
        info["verifies (profile) over PAE with type application/vnd.example.other+json"] = \
            E.verify_profile(vk, sigb, pae("application/vnd.example.other+json", B))
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(vk).verify(sigb, pae(TYPE, B))
        info["pyca/cryptography (installed version) verify"] = "accepted"
    except Exception as e:  # noqa
        info["pyca/cryptography (installed version) verify"] = "rejected (%s)" % type(e).__name__
    diag[vid] = info

# ---------- A.2 against the file ----------
a2 = []
heads = [n for n in range(D.find("A.2.  Vector Set", 1500), a3) if re.match(r"^A\.2\.\d+\.\s+\S+ \(", D.line(n))]
bounds = heads + [a3]
for i, h in enumerate(heads):
    m = re.match(r"^A\.2\.\d+\.\s+(\S+) \(([^;]+); expected (\S+), step (.+)\)$", D.line(h).strip())
    vid, label, exp, step = m.groups()
    blk = D.body(h + 1, bounds[i + 1] - 1)
    # paragraphs before the first item, items, then hex blocks
    paras, items, cur, mode = [], [], [], "p"
    hexes = {}
    for n, t in blk:
        s = t.strip()
        if mode in ("p", "i") and s.startswith("*  "):
            if cur:
                (paras if mode == "p" else items).append(" ".join(cur))
            cur, mode = [s[3:]], "i"
            continue
        if s and cur and cur[-1].endswith("-") and mode in ("p", "i"):
            # TXT wrapped the line after a hyphen: join without a space
            cur[-1] = cur[-1] + s
            continue
        if s in ("B (hex):", "Receipt (hex):"):
            if cur:
                (paras if mode == "p" else items).append(" ".join(cur))
            cur, mode = [], "x"
            hexes[s.split()[0]] = D.hex_after(n)
            continue
        if mode == "x":
            continue
        if s == "":
            if cur and mode == "p":
                paras.append(" ".join(cur))
                cur = []
            continue
        cur.append(s)
    if cur and mode != "x":
        (paras if mode == "p" else items).append(" ".join(cur))
    fv = byid[vid]
    def norm(x):
        return " ".join(x.split())
    row = {"id": vid, "heading_label": label == fv["label"], "heading_expected": exp == fv["expected"], "heading_step": step == fv["step"]}
    tdesc = norm(" ".join(paras))
    fdesc = norm(" ".join(fv["description"]))
    row["description_words_equal"] = tdesc == fdesc
    if tdesc != fdesc:
        row["description_text"] = tdesc
        row["description_file"] = fdesc
    row["paragraph_count_text_file"] = (len(paras), len(fv["description"]))
    titems = [norm(x) for x in items]
    fitems = [norm(x) for x in fv["items"]]
    row["items_equal"] = titems == fitems
    if titems != fitems:
        row["items_text"] = titems
        row["items_file"] = fitems
    fb = {b["label"]: bytes.fromhex(b["hex"]) for b in fv["bytes"]}
    row["receipt_bytes_equal"] = hexes.get("Receipt") == fb.get("Receipt")
    if "B" in hexes:
        row["B_hex_in_text_equals_file"] = hexes["B"] == fb.get("B")
    else:
        pb = fb.get("B", fb.get("Payload bytes carried"))
        row["B_not_in_text; file payload bytes equal B of P1"] = pb == bytes.fromhex(byid["P1"]["bytes"][0]["hex"])
    a2.append(row)

# ---------- A.1 commitments and criteria set ----------
for marker in ("The model commitment: salt", "The dataset commitment: salt"):
    n0 = D.find(marker)
    vals = [t.strip() for _, t in D.body(n0 + 1, n0 + 30) if t.strip()][:3]
    salt, ident, com = bytes.fromhex(vals[0]), vals[1], vals[2]
    keychecks["A.1 %s: sha256(salt || UTF-8 identifier) equals the commitment" % marker.split(":")[0]] = \
        ("sha256:" + sha(salt + ident.encode("utf-8"))) == com
    keychecks["A.1 %s: salt is 16 bytes" % marker.split(":")[0]] = len(salt) == 16
n0 = D.find("The example criteria set of vectors P10 and N57")
vals = []
for _, t in D.body(n0 + 1, n0 + 40):
    v = t.strip()
    if re.fullmatch(r"[0-9a-f]+", v) or v.startswith("sha256:"):
        vals.append(v)
        if v.startswith("sha256:"):
            break
crit = bytes.fromhex("".join(v for v in vals if re.fullmatch(r"[0-9a-f]+", v)))
cdig = [v for v in vals if v.startswith("sha256:")][0]
keychecks["A.1 criteria digest equals sha256 over the criteria bytes"] = ("sha256:" + sha(crit)) == cdig
p10B = json.loads(bytes.fromhex([b for b in byid["P10"]["bytes"] if b["label"] == "B"][0]["hex"]))
keychecks["P10 criteria_digest equals the A.1 criteria digest"] = p10B.get("criteria_digest") == cdig
n57B = json.loads(bytes.fromhex([b for b in byid["N57"]["bytes"] if b["label"] == "B"][0]["hex"]))
keychecks["N57 criteria_digest is the A.1 digest in uppercase hex"] = n57B.get("criteria_digest") == "sha256:" + cdig[7:].upper()

out = {"keychecks": keychecks, "file_checks": fchecks, "structure_problems": struct_problems, "results": results,
       "profile_diagnostics": diag, "A2_vs_file": a2}
json.dump(out, open(os.path.join(OUT, "ser_lauf.json"), "w"), indent=1, default=str)

same = sum(1 for r in results if r["same"])
print("SER vectors: %d run, %d same, %d different" % (len(results), same, len(results) - same))
for r in results:
    if not r["same"]:
        print("  DIFF", r)
print("file checks:")
for c in fchecks:
    print("  ", c)
print("structure problems:", struct_problems)
print("keychecks:", json.dumps(keychecks, indent=1, default=str))
print("A.2 vs file:")
for r in a2:
    print("  ", {k: v for k, v in r.items() if not k.endswith("_text") and not k.endswith("_file")})
    for k in ("description_text", "description_file", "items_text", "items_file"):
        if k in r:
            print("     ", k, r[k])
print("profile diagnostics:", json.dumps(diag, indent=1, default=str))
