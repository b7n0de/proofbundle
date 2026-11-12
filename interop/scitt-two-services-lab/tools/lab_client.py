#!/usr/bin/env python3
"""Client of the two-services lab. Runs on the host; our own code.

Usage: python -I -B lab_client.py <ledger|scittles> <base url> <folder -03> <statements folder> <out folder>
       [--only NAME ...]

For each statement of statements.json:
  register   POST /entries, record the answer, fetch the entry's receipt and the statement the service returns;
  reference  the reference of Section 6 of -03 (ToBeSigned, alg -16, external_aad empty) from the statement the
             service returns, computed with check_cases.py of the folder, compared with the reference of the
             submitted bytes;
  lookup     ask every retrieval path of the service with the reference, and for comparison with the SHA-256 of the
             submitted bytes.
Receipts are parsed (protected header) and not verified. The ledger's TLS certificate is not checked in the lab
(127.0.0.1).
"""
import argparse
import hashlib
import importlib.util
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("service", choices=["ledger", "scittles"])
p.add_argument("base")
p.add_argument("folder03", type=Path)
p.add_argument("statements", type=Path)
p.add_argument("out", type=Path)
p.add_argument("--only", nargs="*")
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=False)
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("cc", a.folder03 / "check_cases.py")
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)
CTX = ssl._create_unverified_context() if a.base.startswith("https") else None
OUTPUT = []


def log(*parts):
    z = " ".join(str(t) for t in parts)
    OUTPUT.append(z)
    print(z, flush=True)


def http(method, path, body=None, headers=None):
    req = urllib.request.Request(a.base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def error_text(body):
    """RFC 9290 as CBOR ({-1: title, -2: detail}) or text; otherwise the first bytes as hex."""
    try:
        item = cc.decode_one(body)
        parts = {k.value: v.value for k, v in item.value}
        return ": ".join(str(parts.get(k)) for k in (-1, -2) if k in parts) or repr(parts)[:200]
    except Exception:
        try:
            return body.decode("utf-8")[:300]
        except UnicodeDecodeError:
            return body[:40].hex()


def reference(raw):
    if raw is None:
        return None
    read = cc.read_candidate(raw)
    if read is None:
        return {"readable": False}
    tag, protected, payload, sig = read
    out = {"readable": True, "tag18": tag, "sha256_whole": hashlib.sha256(raw).hexdigest(),
           "sha256_protected": hashlib.sha256(protected).hexdigest(),
           "sha256_payload": None if payload is None else hashlib.sha256(payload).hexdigest(),
           "sha256_signature": hashlib.sha256(sig).hexdigest()}
    tbs = None if payload is None else cc.to_be_signed(protected, b"", payload)
    out["tbs_sha256"] = None if tbs is None else hashlib.sha256(tbs).hexdigest()
    item = cc.decode_one(raw)
    fields = item.value.value if tag else item.value
    out["unprotected_hex"] = raw[fields[1].start:fields[1].end].hex()
    return out


def receipt_header(raw):
    try:
        read = cc.read_candidate(raw)
        if read is None:
            return {"readable": False}
        _t, protected, _n, _s = read
        h = {k.value: v.value for k, v in cc.decode_one(protected).value}
        return {"readable": True, "alg": h.get(1), "vds_395": h.get(395), "length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}
    except Exception as e:
        return {"readable": False, "error": repr(e)[:200]}


def keep(name, raw):
    if raw:
        (a.out / name).write_bytes(raw)


meta = json.loads((a.statements / "statements.json").read_text(encoding="utf-8"))
names = [n for n in meta["statements"] if not a.only or n in a.only]
result = {"service": a.service, "base": a.base, "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "statements": {}}
st, _h, body = http("GET", "/version" if a.service == "ledger" else "/.well-known/transparency-configuration")
result["service_id"] = {"status": st, "body": body.decode("utf-8", "replace")[:300] if a.service == "ledger"
                        else body.hex()[:600]}
log("service", a.service, a.base, "id", st, result["service_id"]["body"][:120])

for name in names:
    raw = (a.statements / (name + ".cbor")).read_bytes()
    submitted = reference(raw)
    e = {"submitted": submitted}
    path = "/entries?waitForCommit=true" if a.service == "ledger" else "/entries"
    st, h, body = http("POST", path, raw, {"Content-Type": "application/cose"})
    e["registration"] = {"status": st, "content_type": h.get("Content-Type") or h.get("content-type"),
                         "location": h.get("Location") or h.get("location"), "txid": h.get("x-ms-ccf-transaction-id"),
                         "error": error_text(body) if st >= 400 else None, "length": len(body)}
    keep(name + ".registration_answer", body)
    log(name, "POST", st, e["registration"]["error"] or e["registration"]["txid"] or e["registration"]["location"])
    if st in (200, 201):
        if a.service == "ledger":
            entry_id = e["registration"]["txid"]
            paths = {"receipt": "/entries/%s" % entry_id, "statement": "/entries/%s/statement" % entry_id}
        else:
            entry_id = (e["registration"]["location"] or "").rstrip("/").rsplit("/", 1)[-1]
            paths = {"receipt": "/entries/%s" % entry_id, "statement": "/signed-statements/%s" % entry_id}
        e["service_entry_id"] = entry_id
        e["receipt_at_registration"] = receipt_header(body)
        for kind, w in paths.items():
            tries = 0
            for tries in range(1, 61):  # 302 not yet committed, 503 TransactionNotCached: the fetch is starting
                st2, _h2, b2 = http("GET", w)
                if st2 not in (302, 503):
                    break
                time.sleep(1)
            keep("%s.%s" % (name, kind), b2 if st2 == 200 else None)
            e[kind] = {"path": w, "status": st2, "tries": tries, "length": len(b2),
                       "error": error_text(b2) if st2 >= 400 else None}
            log(name, "GET", w, st2, e[kind]["error"] or len(b2))
            if kind == "statement" and st2 == 200:
                back = reference(b2)
                e["statement_returned"] = back
                equal = (back or {}).get("tbs_sha256") == (submitted or {}).get("tbs_sha256")
                e["reference_equal"] = equal
                e["bytes_equal"] = b2 == raw
                fields = ("tag18", "sha256_protected", "sha256_payload", "sha256_signature", "unprotected_hex")
                diffs = [f for f in fields if (back or {}).get(f) != (submitted or {}).get(f)]
                e["differences"] = diffs
                log(name, "reference", "equal" if equal else "DIFFERENT", (back or {}).get("tbs_sha256"),
                    "bytes equal" if b2 == raw else "bytes differ: " + ",".join(diffs))
            if kind == "receipt" and st2 == 200:
                e["receipt_header"] = receipt_header(b2)
    # does the service find the entry by the reference?
    r = (submitted or {}).get("tbs_sha256")
    w = hashlib.sha256(raw).hexdigest()
    lookups = (["/entries/%s", "/entries/%s/statement", "/operations/%s"] if a.service == "ledger"
               else ["/entries/%s", "/signed-statements/%s"])
    e["lookup"] = {}
    for key, value in (("reference_tbs", r), ("sha256_whole", w)):
        if not value:
            continue
        for pattern in lookups:
            st3, _h3, b3 = http("GET", pattern % value)
            found = st3 == 200
            e["lookup"]["%s %s" % (key, pattern)] = {"status": st3, "found": found,
                                                     "error": error_text(b3) if st3 >= 400 else None}
            log(name, "LOOKUP", key, pattern % (value[:12] + "..."), st3, "FOUND" if found else
                (error_text(b3)[:100] if st3 >= 400 else len(b3)))
    result["statements"][name] = e

result["end"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
(a.out / "result.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
(a.out / "output.txt").write_text("\n".join(OUTPUT) + "\n", encoding="utf-8")
