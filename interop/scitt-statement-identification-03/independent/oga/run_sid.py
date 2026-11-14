#!/usr/bin/env python3
"""python3 -I run_sid.py DRAFT.txt CASES_DIR TEST_KEYS.json OUT_DIR

Step 1 (blind): rebuild each candidate from Appendix A of the draft, check it against the case file's bytes,
compute the axes of every case and variant with every 'expected' member removed, write OUT_DIR/verdicts.json.
Step 2 is compare_sid.py, run only after verdicts.json is frozen.
"""
import base64, datetime, hashlib, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sid_axes as X

DRAFT_SHA = "9176957ab9f3a4f4daca9dde67b3bcbb812417697f20e813c3ef3102c85bd95c"
draft_p, cases_d, keys_p, out_d = sys.argv[1:5]
raw = open(draft_p, "rb").read()
assert hashlib.sha256(raw).hexdigest() == DRAFT_SHA, "draft sha"
text = raw.decode("ascii")
lines = [l for l in text.split("\n") if not re.match(r"^(Gruszka\s+Expires|Internet-Draft\s+Identifying)", l)]
text = "\n".join(lines)


def hexblock(after, n_bytes=None):
    """Concatenate the hex lines that follow the first line containing `after`."""
    i = text.index(after); rest = text[i:].split("\n")[1:]
    out, started = "", False
    for l in rest:
        s = l.strip()
        if re.fullmatch(r"[0-9a-f]{2,64}", s):
            out += s; started = True
        elif started and s == "":
            if n_bytes and len(out) // 2 >= n_bytes: break
            continue
        elif started:
            break
    return bytes.fromhex(out)


st = {"01": hexblock("Statement 01 (iss", 330), "02": hexblock("Statement 02 (iss", 365),
      "03": hexblock("Statement 03 (iss", 450)}
for k, n, h in (("01", 330, "9c7253617b9fe51b"), ("02", 365, "c4758ea9ae4d8546"), ("03", 450, "f5afbb3b0c7d822b")):
    assert len(st[k]) == n and hashlib.sha256(st[k]).hexdigest().startswith(h), k


def sig_after(section):
    i = text.rindex(section)
    j = text.index("(hex):", i) + 6
    hx = [l.strip() for l in text[j:].split("\n") if re.fullmatch(r"\s*[0-9a-f]{64}\s*", l)][:2]
    assert len(hx) == 2, section
    return bytes.fromhex(hx[0] + hx[1])


def split01(b):
    """Statement 01 as (head bytes up to the array, [prot, unprot, payload, sig] raw encodings)."""
    assert b[:2] == b"\xd2\x84"
    parts, i = [], 2
    for _ in range(4):
        _, j = X._item(b, i, 0); parts.append(b[i:j]); i = j
    assert i == len(b)
    return parts


p01 = split01(st["01"])
prot01 = X.decode_one(p01[0]); pay01 = X.decode_one(p01[2])


def build(prot_enc=None, unprot_enc=None, payload_enc=None, sig=None, head=b"\xd2\x84"):
    return (head + (prot_enc or p01[0]) + (unprot_enc or p01[1]) + (payload_enc if payload_enc is not None else p01[2])
            + (X._bstr(sig) if sig is not None else p01[3]))


def tstr(s):
    b = s.encode(); n = len(b)
    return (bytes([0x60 | n]) if n < 24 else bytes([0x78, n])) + b


# C3: "MIT" -> "BSD-3-Clause" in the payload
pay3 = pay01.replace(b'"license":"MIT"', b'"license":"BSD-3-Clause"'); assert pay3 != pay01
# C4: content type -> "application/cbor", protected header in deterministic encoding (keys 1, 3, 4, 15 sorted)
m = X.decode_one(prot01)
def enc_item(v):
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        mt, n = (0, v) if v >= 0 else (1, -1 - v)
        if n < 24: return bytes([mt << 5 | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w): return bytes([mt << 5 | ai]) + n.to_bytes(w, "big")
    if isinstance(v, bytes): return X._bstr(v)
    if isinstance(v, str): return tstr(v)
    if isinstance(v, X.Map):
        enc = sorted((enc_item(k), enc_item(x)) for k, x in v.pairs)
        n = len(enc); head = bytes([0xa0 | n]) if n < 24 else bytes([0xb8, n])
        return head + b"".join(k + x for k, x in enc)
    raise TypeError(type(v))
pairs4 = [(k, ("application/cbor" if k == 3 else v)) for k, v in m.pairs]
prot4 = enc_item(X.Map(pairs4))
# C5: unprotected {-70002: "added after signing"} deterministic
unprot5 = enc_item(X.Map([(-70002, "added after signing")]))

cand = {
    "C1": st["01"], "C2": st["03"],
    "C3": build(payload_enc=X._bstr(pay3), sig=sig_after("A.3.3.  C3")),
    "C4": build(prot_enc=X._bstr(prot4), sig=sig_after("A.3.4.  C4")),
    "C5": build(unprot_enc=unprot5),
    "C6": build(sig=sig_after("A.3.6.  C6")),
    "C7": build(sig=sig_after("A.3.7.  C7")),
    "C8": build(payload_enc=b"\xf6", sig=sig_after("A.3.8.  C8")),
    "C9": st["01"][1:],
    "C10": st["01"],
    "C11": build(sig=sig_after("A.3.11.  C11")),
    "C12": b"\xd2\x98\x04" + st["01"][2:],
    "C13": st["01"], "C14": st["01"],
}
stated = {}
for cid in cand:
    sec = [m_.start() for m_ in re.finditer(r"A\.3\.\d+\.  %s \(requirement" % cid, text)][-1]
    m2 = re.search(r"candidate SHA-256 \(whole COSE_Sign1\):\s+([0-9a-f]{64})\s+\((\d+) bytes\)", text[sec:])
    stated[cid] = (m2.group(1), int(m2.group(2)))
# the reference of Appendix A.1, as carried by statement 02 under label -70001: [[-16, "ToBeSigned", digest]]
s02 = X.decode_one(st["02"]); prot02 = X.decode_one(s02.v[0])
reflist = dict((k, v) for k, v in prot02.pairs)[-70001]
ref_enc = b"\x83" + enc_item(reflist[0][0]) + tstr(reflist[0][1]) + X._bstr(reflist[0][2])
refs = {"C13": hexblock("is (46 bytes, hex):"), "C14": hexblock("is (47 bytes, hex):")}
aad7 = bytes.fromhex(re.search(r"external_aad \(hex, 17 bytes\): ([0-9a-f]{34})", text).group(1))

keys = json.load(open(keys_p))["keys"]
seed_issuer = bytes.fromhex(re.search(r"issuer:\s+\*\s+Ed25519 seed \(hex, 32 bytes\):\s+([0-9a-f]{64})", text).group(1))
seed_auditor = bytes.fromhex(re.search(r"auditor:\s+\*\s+Ed25519 seed \(hex, 32 bytes\):\s+([0-9a-f]{64})", text).group(1))
A_issuer = X.public_from_seed(seed_issuer); A_auditor = X.public_from_seed(seed_auditor)
SPKI = bytes.fromhex("302a300506032b6570032100")

checks = []
def chk(name, ok):
    checks.append((name, bool(ok)))

# self-tests of the Ed25519 arithmetic: RFC 8032 Section 7.1 TEST 1
t_sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
t_pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
t_sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
chk("RFC 8032 TEST 1 public key", X.public_from_seed(t_sk) == t_pk)
chk("RFC 8032 TEST 1 signature verifies", X.sig_rules(t_pk, t_sig, b""))
chk("RFC 8032 TEST 1 one flipped bit fails", not X.sig_rules(t_pk, t_sig[:-1] + bytes([t_sig[-1] ^ 1]), b""))
chk("issuer kid = SHA-256(SPKI)", hashlib.sha256(SPKI + A_issuer).hexdigest() == re.search(r"issuer:.*?kid \(hex, SHA-256 of the SubjectPublicKeyInfo\):\s+([0-9a-f]{64})", text, re.S).group(1))
chk("auditor kid = SHA-256(SPKI)", hashlib.sha256(SPKI + A_auditor).hexdigest() == re.search(r"auditor:.*?kid \(hex, SHA-256 of the SubjectPublicKeyInfo\):\s+([0-9a-f]{64})", text, re.S).group(1))
chk("test_keys.json issuer public key = derived", keys["issuer"]["public_key_hex"] == A_issuer.hex())
chk("test_keys.json auditor public key = derived", keys["auditor"]["public_key_hex"] == A_auditor.hex())
tbs01 = X.to_be_signed(prot01, b"", pay01)
chk("reference digest = SHA-256(ToBeSigned of 01)", hashlib.sha256(tbs01).hexdigest() == "c3f5f13764679b9f77918bb52782480bc222be5ae4bce37f51384a6b1faa9dbc")
for k, A in (("01", A_issuer), ("02", A_auditor), ("03", A_issuer)):
    s = X.decode_one(st[k]).v
    chk("statement %s signature verifies (4 rules)" % k, X.sig_rules(A, s[3], X.to_be_signed(s[0], b"", s[2])))

cases, verdicts = {}, {}
for cid in sorted(cand, key=lambda c: int(c[1:])):
    f = json.load(open(os.path.join(cases_d, cid + ".json")))
    f.pop("expected", None)
    for v in f.get("variants", []):
        v.pop("expected", None)
    inp = f["inputs"]
    b64 = lambda o: base64.b64decode(o["base64"])
    c_bytes = b64(inp["candidate"])
    chk("%s rebuilt from Appendix A: length and SHA-256 as stated" % cid,
        (hashlib.sha256(cand[cid]).hexdigest(), len(cand[cid])) == stated[cid])
    chk("%s case file candidate = rebuilt bytes" % cid, c_bytes == cand[cid])
    r_bytes = b64(inp["reference"])
    chk("%s case file reference = draft reference" % cid, r_bytes == refs.get(cid, ref_enc))
    chk("%s case file stated key = issuer key derived from seed" % cid, b64(inp["stated_key"]["public_key"]) == A_issuer)
    aad = X.NOT_SUPPLIED if inp["external_aad"] is None else b64(inp["external_aad"])
    if cid == "C7": chk("C7 case file external_aad = draft bytes", aad == aad7)
    det = X.NOT_SUPPLIED if inp["detached_payload"] is None else b64(inp["detached_payload"])
    alg, name = inp["scheme"]["alg"], inp["scheme"]["name"]
    run = lambda aad_, det_, rules="all": X.axes(cand[cid], refs.get(cid, ref_enc), alg, name, aad_, det_, A_issuer, rules)
    out = {"case": run(aad, det), "variants": []}
    for v in f.get("variants", []):
        ch = v.get("change", {})
        a2 = (X.NOT_SUPPLIED if ch["external_aad"] is None else b64(ch["external_aad"])) if "external_aad" in ch else aad
        d2 = (X.NOT_SUPPLIED if ch["detached_payload"] is None else b64(ch["detached_payload"])) if "detached_payload" in ch else det
        out["variants"].append({"name": v["name"], "axes": run(a2, d2, v.get("rules", "all"))})
    verdicts[cid] = out

os.makedirs(out_d, exist_ok=True)
doc = {"reader": "sid_axes.py (HORIZON SHIELD), written from the draft text only",
       "reader_sha256": hashlib.sha256(open(X.__file__, "rb").read()).hexdigest(),
       "runner_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
       "draft_sha256": DRAFT_SHA, "frozen_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
       "self_checks": [{"check": n, "ok": ok} for n, ok in checks], "verdicts": verdicts}
p = os.path.join(out_d, "verdicts.json")
open(p, "w").write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
print("self checks %d / %d ok" % (sum(ok for _, ok in checks), len(checks)))
for n, ok in checks:
    if not ok: print("  FAILED:", n)
for cid, o in verdicts.items():
    a = o["case"]; print("%-4s %-5s %-13s %-5s %s" % (cid, a["ref_usable"], a["match"], a["is_scitt"], a["sig_valid"]))
    for v in o["variants"]:
        a = v["axes"]; print("     + %-5s %-13s %-5s %-5s  %s" % (a["ref_usable"], a["match"], a["is_scitt"], a["sig_valid"], v["name"]))
print("verdicts.json", hashlib.sha256(open(p, "rb").read()).hexdigest(), doc["frozen_at"])
