#!/usr/bin/env python3
"""The policy-boundary matrix over the differential corpus: one row per registered vector.

WHY. Owner order of 2026-09-27 (20:2x Berlin, addendum 20:4x): a reviewer of the corpus asked to see
two things apart, (1) which bytes the service commits to in data-hash, and (2) which semantically
awkward or conflicting COSE structures its parser and policy still accept. The rows of rounds 1 and 2
are derived here from their stored bytes alone. Round 3 is registered only after its design has been
reviewed (owner hold of 2026-09-27, 21:0x Berlin); its rows join this matrix then.

COLUMNS, the reviewer's eight:
  vector                         round and id
  protected semantics            the protected header as submitted, decoded entry by entry, in order,
                                 with every encoding that is not the preferred one named
  unprotected semantics          the unprotected header as submitted, the same way
  accepted/refused               what the service did, nothing else
  data-hash match                accepted: whether the receipt's data-hash equals the preimage rule of
                                 the first round through three encoders; refused: n/a
  committed representation       accepted: the bytes the data-hash commits to, as the rule and the
                                 returned statement show them; refused: nothing committed
  parser-visible interpretation  only what can be observed without changing the service: the error
                                 text of a refusal; otherwise NOT MEASURABLE, with the reason
  expected-policy result         the normative source per row; PENDING until the reviewed design names it
and two of ours (addendum of 20:4x), the verdict of src/proofbundle/scitt_ccf.py (scitt-ccf/v1):
  our reader, submitted          on the exact submitted bytes: the decode status and text (the column
                                 rounds 1 and 2 recorded), the statement-side status of
                                 verify_transparent_statement, and the status of verify_statement_signature
  our reader, returned           on the exact returned statement: verify_transparent_statement, status and
                                 detail as the reader gives them

ORACLES. The service's answers, the returned statements and the receipts are fixtures: the bytes recorded
by differential_corpus.py and differential_corpus_round2.py, checked against their recorded digests
before use. The preimage rule and the "own" data-hash path are our own computation (preimage_candidates.py,
candidate 4-tagged); the "cbor2" path is a foreign library re-encoding the same candidate
(`cbor2_equal`); the "EverCBOR" path is a foreign tool built by us (vendored_encoder_probe.py, CCF's
vendored encoder). The reader columns are our own reader, run here on the stored bytes. The unprotected
check (`reader_unprotected_effect`) runs the reader again on the submitted bytes with the unprotected map
replaced by an empty one, a variant derived here (the first round's candidate 11 form), to see whether
anything in that bucket changes our reader's verdict.

USAGE:
    python3 policy_matrix.py --write      # derive and write differential_corpus_round3/matrix.json and the
                                          # matrix table in differential_corpus_round3/README.md
    python3 policy_matrix.py --check      # derive and compare with the written matrix.json (exit 1 on any
                                          # difference)
Offline. Needs the [scitt] extra (cbor2) for the reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "differential_corpus_round3"
sys.path.insert(0, str(HERE))
import differential_corpus as D  # noqa: E402 - the corpus's own reader and hex files

ROUNDS = ((1, "differential_corpus"), (2, "differential_corpus_round2"))
VENDORED = HERE / "vendored_encoder_result.json"
PREIMAGE_RULE = "4-tagged"
PENDING = ("PENDING: the normative source for this row comes with the reviewed design (owner hold of "
           "2026-09-27, 21:0x Berlin); no conformance claim is made either way")
NOT_MEASURABLE_ACCEPTED = (
    "NOT MEASURABLE: the service accepted, and what it returned (the statement, the receipt) does not say "
    "which of the submitted header values its parser or policy read; the corpus queried no other read "
    "endpoint, and observing it otherwise needs a change to the service")

LABELS = {1: "alg", 2: "crit", 3: "content type", 4: "kid", 15: "CWT claims", 33: "x5chain",
          258: "payload hash alg", 259: "preimage content type", 260: "payload location", 394: "receipts"}
CWT = {1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _note(node: dict) -> str:
    framing = node.get("framing", "")
    if "NOT shortest" in framing or "indefinite" in framing:
        return f" <{framing}>"
    return ""


def value_text(node, *, cwt: bool = False) -> str:
    """A decoded item of cose_structure as short text, with every encoding that is not preferred named."""
    if not isinstance(node, dict):
        return repr(node)
    kind = node.get("type")
    if kind == "int":
        text = str(node.get("value"))
    elif kind == "tstr":
        t = node.get("text", "")
        text = repr(t if len(t) <= 60 else t[:57] + "...")
    elif kind == "bstr":
        text = f"bstr[{node.get('length')}]"
    elif kind == "array":
        text = "[" + ", ".join(value_text(i) for i in node.get("items", [])) + "]"
    elif kind == "map":
        text = "{" + map_text(node, cwt=cwt) + "}"
    else:
        text = str(kind)
    return text + _note(node)


def map_text(node: dict, *, top: bool = False, cwt: bool = False) -> str:
    parts = []
    for key, val in node.get("entries", []):
        k = key.get("value", key.get("text")) if isinstance(key, dict) else key
        names = CWT if cwt else (LABELS if top else {})
        name = names.get(k) if isinstance(k, int) and not isinstance(k, bool) else None
        shown = (repr(k) if key.get("type") == "tstr" else str(k)) + (f" {name}" if name else "")
        parts.append(f"{shown}{_note(key)}: {value_text(val, cwt=top and k == 15)}")
    return "; ".join(parts)


def header_text(node) -> str:
    if not isinstance(node, dict):
        return "(absent)"
    if node.get("type") != "map":
        return f"not a map: {node.get('type')}"
    inner = map_text(node, top=True)
    return ("{" + inner + "}" if inner else "{} (empty)") + _note(node)


def reader_on(raw: bytes, *, root: bytes, rp: dict) -> dict:
    """Our reader on one byte string: decode, statement side, statement signature, whole check."""
    from proofbundle import scitt_ccf as S
    try:
        S.decode_cose_sign1(raw, role="statement")
        decode = {"status": "read", "text": "decode_cose_sign1 reads it"}
    except S.ScittFormatError as exc:
        decode = {"status": exc.status, "text": str(exc)}
    check = S.verify_transparent_statement(raw, canonical_root=root, rp_trust=rp)
    sig_status, sig_valid = S.verify_statement_signature(raw, statement_keys=rp["scitt_statement_keys"])
    return {"decode": decode, "statement_status": check.statement_status, "status": check.status,
            "detail": check.detail, "statement_signature": {"status": sig_status, "valid": sig_valid}}


def _unprotected_emptied(raw: bytes) -> bytes:
    """The same bytes with the unprotected map replaced by an empty one (a0), every other byte kept."""
    st = D.cose_structure(raw)
    a, b = st["unprotected"]["span"]
    return raw[:a] + b"\xa0" + raw[b:]


def _load_round(number: int, name: str) -> list:
    corpus = HERE / name
    man = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    from proofbundle import scitt_ccf as S
    root = bytes.fromhex(man["target"]["receipt_canonical_root"])
    signer = [bytes.fromhex(man["signer"]["spki_hex"])]
    if "phases" in man:
        keysets = {ph["name"]: D.read_hex(corpus / ph["keyset"]) for ph in man["phases"]}
    else:
        raw = D.read_hex(corpus / "scitt-keys.hex")
        if _sha(raw) != man["service_keyset"]["sha256"]:
            raise SystemExit(f"REFUSED: {name}/scitt-keys.hex is not the recorded key set")
        keysets = {None: raw}
    vendored = {v["id"]: v for v in json.loads(VENDORED.read_text(encoding="utf-8"))["corpora"]
                .get(name, {}).get("vectors", [])}
    out = []
    for vid in man["vectors"]:
        d = corpus / "vectors" / vid
        meta = json.loads((d / "record.json").read_text(encoding="utf-8"))
        files = {}
        for fname, want in meta["files"].items():
            files[fname] = D.read_hex(d / fname)
            if _sha(files[fname]) != want["sha256"]:
                raise SystemExit(f"REFUSED: {name}/{vid}/{fname} is not the recorded bytes")
        phase = (meta.get("phase") or {}).get("name")
        rp = {"scitt_ccf_services": {"127.0.0.1:8000": S.load_cose_keyset(keysets[phase])},
              "scitt_statement_keys": signer}
        cands = d / "candidate_hashes.json"
        out.append({"round": number, "corpus": name, "id": vid, "meta": meta, "files": files, "rp": rp,
                    "root": root, "candidates": json.loads(cands.read_text(encoding="utf-8")) if cands.exists() else None,
                    "vendored": vendored.get(vid)})
    return out


def _data_hash_match(v: dict) -> dict:
    if not v["meta"]["service"]["accepted"]:
        return {"text": "n/a: refused, no receipt"}
    cand = ((v["candidates"] or {}).get("candidates") or {}).get(PREIMAGE_RULE) or {}
    own = cand.get("equals_data_hash")
    cbor2 = (own is True and cand.get("cbor2_equal") is True) if cand.get("cbor2_equal") is not None else None
    ever = (v["vendored"] or {}).get("output_sha256_equals_data_hash")
    paths = {"own": own, "cbor2": cbor2, "evercbor": ever}
    yes = [k for k, x in paths.items() if x is True]
    no = [k for k, x in paths.items() if x is False]
    missing = [k for k, x in paths.items() if x is None]
    text = ("match: " + ", ".join(yes) if yes else "") + (("; NO: " + ", ".join(no)) if no else "") + \
           (("; not recorded: " + ", ".join(missing)) if missing else "")
    return {**paths, "text": text.strip("; ")}


def _committed(v: dict, statement: dict) -> str:
    if not v["meta"]["service"]["accepted"]:
        return "nothing committed: refused, no receipt"
    facts = (v["candidates"] or {}).get("facts") or {}
    sub = D.cose_structure(v["files"]["request.hex"])
    ret = statement
    same = {k: D.contents(v["files"]["request.hex"])[i] == D.contents(v["files"]["statement.hex"])[i]
            for i, k in ((0, "protected"), (1, "payload"), (2, "signature"))}
    parts = [f"tag {ret.get('tag')}",
             "protected " + ("as submitted" if same["protected"] else "NOT as submitted") +
             f" ({sub['protected'].get('length')} bytes)",
             "unprotected emptied in the preimage",
             "payload " + ("as submitted" if same["payload"] else "NOT as submitted"),
             "signature " + ("as submitted" if same["signature"] else "NOT as submitted")]
    labels = facts.get("returned_unprotected_labels")
    if labels is None:
        labels = [e[0].get("value", e[0].get("text")) for e in ret["unprotected"].get("entries", [])]
    return ("preimage = [" + ", ".join(parts) + f"]; the returned statement's unprotected labels: {labels}")


def row(v: dict) -> dict:
    meta, files = v["meta"], v["files"]
    sub = files["request.hex"]
    st_sub = D.cose_structure(sub)
    accepted = bool(meta["service"]["accepted"])
    returned = files.get("statement.hex")
    st_ret = D.cose_structure(returned) if returned else None
    ours_sub = reader_on(sub, root=v["root"], rp=v["rp"])
    emptied = reader_on(_unprotected_emptied(sub), root=v["root"], rp=v["rp"])
    ours_ret = reader_on(returned, root=v["root"], rp=v["rp"]) if returned else None
    effect = ("none: the same statement-side status with the unprotected map emptied"
              if emptied["statement_status"] == ours_sub["statement_status"] else
              f"changes: {ours_sub['statement_status']} as submitted, {emptied['statement_status']} with the "
              "unprotected map emptied")
    error = meta["service"].get("error")
    return {
        "vector": f"r{v['round']}/{v['id']}",
        "round": v["round"], "class": meta.get("class"), "phase": (meta.get("phase") or {}).get("name"),
        "mutation": meta.get("mutation"),
        "protected_semantics": header_text((st_sub.get("protected") or {}).get("decoded")),
        "unprotected_semantics": header_text(st_sub.get("unprotected")),
        "accepted_refused": "accepted" if accepted else "refused",
        "service": {"post_status": meta["service"].get("post_status"), "txid": meta["service"].get("txid"),
                    "error": error},
        "data_hash_match": _data_hash_match(v),
        "committed_representation": _committed(v, st_ret) if accepted else "nothing committed: refused, no receipt",
        "parser_visible_interpretation": (f"error text: {error}" if not accepted and error else
                                          ("NOT MEASURABLE: refused without an error text" if not accepted
                                           else NOT_MEASURABLE_ACCEPTED)),
        "expected_policy_result": PENDING,
        "our_reader_submitted": ours_sub,
        "our_reader_returned": ours_ret,
        "reader_unprotected_effect": effect,
        "reader_against_service": _against(accepted, ours_sub),
        "files": {"corpus": v["corpus"], "vector": f"vectors/{v['id']}/",
                  "request_sha256": _sha(sub), "statement_sha256": _sha(returned) if returned else None},
    }


def _against(accepted: bool, ours_sub: dict) -> str:
    """Measured, not judged: our reader's statement-side status beside what the service did."""
    ok = ours_sub["statement_status"] == "confirmed"
    if accepted and not ok:
        return f"stricter than the service: the service accepted, our reader says {ours_sub['statement_status']}"
    if not accepted and ok:
        return "less strict than the service: the service refused, our reader's statement side is confirmed"
    return "same direction as the service"


def derive() -> dict:
    rows = []
    for number, name in ROUNDS:
        vectors = _load_round(number, name)
        control = next((v for v in vectors if v["id"] == "control"), None)
        control_dh = ((control or {}).get("candidates") or {}).get("receipt_data_hash")
        for v in vectors:
            r = row(v)
            dh = (v["candidates"] or {}).get("receipt_data_hash") if r["accepted_refused"] == "accepted" else None
            r["data_hash_match"]["receipt_data_hash"] = dh
            r["data_hash_match"]["equals_round_control"] = (dh == control_dh) if dh and control_dh else None
            rows.append(r)
    counts = {}
    for r in rows:
        key = f"r{r['round']}/{r['class']}"
        c = counts.setdefault(key, {"vectors": 0, "accepted": 0, "refused": 0})
        c["vectors"] += 1
        c["accepted" if r["accepted_refused"] == "accepted" else "refused"] += 1
    return {
        "tool": "tools/scitt_ccf_external/policy_matrix.py",
        "rounds": {"1": "differential_corpus/", "2": "differential_corpus_round2/",
                   "3": "not registered: on hold until the design is reviewed (owner hold of 2026-09-27, 21:0x Berlin)"},
        "preimage_rule": "candidate 4-tagged of preimage_candidates.py: deterministic [protected, {}, payload, "
                         "signature], tag 18, the protected header as the bytes submitted",
        "oracles": {"service answers, returned statements, receipts": "fixtures, the recorded bytes",
                    "own": "own computation (preimage_candidates.py)",
                    "cbor2": "foreign library, cbor2, re-encoding the same candidate",
                    "evercbor": "foreign tool built by us (vendored_encoder_probe.py)",
                    "our reader": "src/proofbundle/scitt_ccf.py, run on the stored bytes"},
        "counts": counts,
        "rows": rows,
    }


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _data_hash_cell(d: dict) -> str:
    same = d.get("equals_round_control")
    if same is None:
        return d["text"]
    return d["text"] + ("; the same data-hash as the round's control" if same else "; other than the round's control")


def _reader_cell(o) -> str:
    if o is None:
        return "n/a: nothing returned"
    head = f"{o['status']} (statement side {o['statement_status']}; decode {o['decode']['status']}; statement signature {o['statement_signature']['status']})"
    why = o["detail"] or (o["decode"]["text"] if o["decode"]["status"] != "read" else "")
    return head + (f": {why}" if why else "")


def table(m: dict) -> str:
    head = ("| vector | protected semantics | unprotected semantics | accepted/refused | data-hash match | "
            "committed representation | parser-visible interpretation | expected-policy result | "
            "our reader, submitted | our reader, returned |\n|" + "---|" * 10 + "\n")
    lines = []
    for r in m["rows"]:
        cells = [r["vector"], r["protected_semantics"], r["unprotected_semantics"], r["accepted_refused"],
                 _data_hash_cell(r["data_hash_match"]), r["committed_representation"], r["parser_visible_interpretation"],
                 "PENDING", _reader_cell(r["our_reader_submitted"]), _reader_cell(r["our_reader_returned"])]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return head + "\n".join(lines) + "\n"


BEGIN = "<!-- matrix table: written by policy_matrix.py --write -->"
END = "<!-- end of the matrix table -->"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    m = derive()
    text = json.dumps(m, indent=1, ensure_ascii=False) + "\n"
    target = OUT / "matrix.json"
    if args.check:
        same = target.exists() and target.read_text(encoding="utf-8") == text
        print(f"{'OK  ' if same else 'DIFF'} {target.relative_to(HERE)}: {len(m['rows'])} rows")
        return 0 if same else 1
    if args.write:
        OUT.mkdir(exist_ok=True)
        target.write_text(text, encoding="utf-8")
        readme = OUT / "README.md"
        body = readme.read_text(encoding="utf-8") if readme.exists() else ""
        if BEGIN in body and END in body:
            body = body.split(BEGIN)[0] + BEGIN + "\n\n" + table(m) + "\n" + END + body.split(END, 1)[1]
            readme.write_text(body, encoding="utf-8")
    for key, c in sorted(m["counts"].items()):
        print(f"{key:6s} vectors {c['vectors']:2d} accepted {c['accepted']:2d} refused {c['refused']:2d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
