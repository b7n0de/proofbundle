#!/usr/bin/env python3
"""Cross-check with MolTrust: the AAE conformance vectors v1.4.0 computed with the proofbundle verifier's own steps.

Usage: PYTHONPATH=<proofbundle checkout>/src python -B cross_check.py <aae-conformance-vectors checkout> <out.json>
(not -I: it would ignore PYTHONPATH and import an installed proofbundle instead of the checkout)

Written from the text alone: draft-kroehl-agentic-trust-aae-02 (Sections 2.2.2 and 3), the README, docs/CONFORMANCE.md,
vectors/enforce/README.md, schema/enforce-vector-schema.json and the vectors. The reference code of that repository
(examples/, tools/, .github/) was not read.

The proofbundle verifier of draft-gruszka-audit-decision-receipts binds a decision by decisionRef, SHA-256 over the
exact payload bytes, which must be their own RFC 8785 (JCS) serialization. Two of its steps carry over:

  JCS     the RFC 8785 canonicalizer of proofbundle (canonical.canonicalize_statement). AAE computes action_binding as
          "sha256:" || hex(SHA-256(TAG || 0x00 || JCS(A))) with TAG "aae:enforce-action:v1" (Section 2.2.2). The JCS
          octets are ours; the domain tag is AAE's and is added as the draft states it.
  exact   SHA-256 over exact octets, as decisionRef is taken. AAE's delegator_aae_hash is "sha-256:" ||
          base64url(SHA-256(parent JWS compact serialization as retrieved)) (Section 3).

This run reads the 26 enforce and 15 native vector files only; it does not read the six AAE/PSEA composition
vectors. For the files read, NOT APPLICABLE marks a check this digest-level run does not evaluate, not an AAE
rejection or a claim that decision receipts lack analogous checks. No mapping of the remaining AAE checks to the
decision-receipt procedure is implemented here.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

import proofbundle
from proofbundle.canonical import canonicalize_statement

REPO = Path(sys.argv[1])
OUT = Path(sys.argv[2])
TAG_ACTION = b"aae:enforce-action:v1\x00"
MISSING = object()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def action_binding(action):
    return "sha256:" + hashlib.sha256(TAG_ACTION + canonicalize_statement(action)).hexdigest()


def enforce(path):
    v = json.loads(path.read_text(encoding="utf-8"))
    out = {"id": v["id"], "file": path.name, "kernel": v["kernel"], "expected": v["expected"].get("verdict")
           or v["expected"].get("status") or v["expected"].get("error")}
    na = []
    if v["kernel"] != "enforce_check":
        out["action_binding"] = "NOT APPLICABLE"
        na.append("ratification (Section 6.3 of AAE) has no counterpart in the decision receipt of -05")
        out["not_applicable"] = na
        return out
    tx = v["input"].get("transaction", MISSING)
    mandate = v["input"].get("mandate", MISSING)
    if not isinstance(tx, dict):
        out["action_binding"] = "NOT APPLICABLE"
        na.append("the transaction is not an object, so there is no action to canonicalize (Section 2.2.3 step 1)")
    else:
        action = tx.get("action", None)  # an absent action canonicalizes as null (Section 2.2.3 step 1)
        ours = action_binding(action)
        out["action_binding"] = ours
        out["action_is_object"] = isinstance(action, dict)
        out["sha256_jcs_without_tag"] = hashlib.sha256(canonicalize_statement(action)).hexdigest()
        grants = mandate.get("grants") if isinstance(mandate, dict) else None
        if isinstance(grants, list):
            out["grants"] = [{"index": i, "stated": g.get("action_binding") if isinstance(g, dict) else None,
                              "equal": isinstance(g, dict) and g.get("action_binding") == ours}
                             for i, g in enumerate(grants)]
        else:
            out["grants"] = None
        trace = {t["predicate"]: t["result"] for t in v["expected"].get("trace", [])}
        if "action_binding" in trace:
            out["trace_action_binding"] = trace["action_binding"]
    na.append("verdict: grant selection by type_fields, dispositions and the constraint language of Section 2.5 "
              "are not part of the decision receipt of -05")
    na.append("core_digest: the core holds enforce_version, mandate_digest, transaction_digest, action_digest, the "
              "verdict, grant_index, the structured predicate trace without diagnostic reason text, and "
              "prev_core_digest; our decisionRef covers a decision payload with other members, so the two digests "
              "cover different field sets")
    out["not_applicable"] = na
    return out


def find(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for w in obj.values():
            r = find(w, key)
            if r is not MISSING:
                return r
    elif isinstance(obj, list):
        for w in obj:
            r = find(w, key)
            if r is not MISSING:
                return r
    return MISSING


def native(path):
    v = json.loads(path.read_text(encoding="utf-8"))
    out = {"id": v["id"], "file": path.name, "expected": v["expected"]["result"],
           "step": v["expected"]["verification_step"]}
    jws_all = [v["input"]["secured_aae"]] + list((v["input"].get("context") or {}).get("delegation_chain") or [])
    jws_all = [j if isinstance(j, str) else find(j, "secured_aae") for j in jws_all]
    by_id = {}
    for j in jws_all:
        if isinstance(j, str):
            by_id.setdefault(find(json.loads(b64url_decode(j.split(".")[1])), "id"), []).append(j)
    links = []
    for j in jws_all:
        if not isinstance(j, str):
            links.append({"result": "NOT APPLICABLE", "reason": "a chain entry is not a JWS string"})
            continue
        payload = json.loads(b64url_decode(j.split(".")[1]))
        delegation = find(payload, "delegation")
        if not isinstance(delegation, dict):
            continue  # a root AAE: no link to check
        parent_id = delegation.get("delegator_aae_id")
        parents = by_id.get(parent_id, [])
        stated = delegation.get("delegator_aae_hash", MISSING)
        if len(parents) != 1:
            links.append({"result": "NOT APPLICABLE", "reason": "the parent %r is not in the vector exactly once"
                          % (parent_id,), "parents_found": len(parents), "hash_stated": stated is not MISSING})
            continue
        ours = "sha-256:" + base64.urlsafe_b64encode(
            hashlib.sha256(parents[0].encode("ascii")).digest()).decode().rstrip("=")
        if stated is MISSING:
            links.append({"result": "NOT APPLICABLE", "reason": "delegator_aae_hash is absent (OPTIONAL, Section 3)",
                          "parent": parent_id, "computed": ours})
        else:
            links.append({"result": "equal" if stated == ours else "DIFFERENT", "parent": parent_id,
                          "stated": stated, "computed": ours})
    out["delegator_aae_hash"] = links or "NOT APPLICABLE: not a delegated AAE"
    out["not_applicable"] = [
        "Not evaluated in this digest-level run. Steps 1 to 8 and the rest of step 9 of Section 5 of AAE are "
        "outside the comparison. Only the parent-JWS hash is compared; no mapping of the other AAE checks to "
        "the decision-receipt procedure is implemented here."
    ]
    return out


print("proofbundle module", proofbundle.__file__)
result = {"repository": "https://github.com/MoltyCel/aae-conformance-vectors", "read_reference_code": False,
          "enforce": [enforce(p) for p in sorted((REPO / "vectors" / "enforce").glob("[0-9]*.json"))],
          "native": [native(p) for p in sorted((REPO / "vectors").glob("[0-9]*.json"))]}
OUT.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
for e in result["enforce"]:
    g = e.get("grants") or []
    print("%-24s %-14s %-8s binding %s grants equal %s trace %s" % (
        e["id"], e["kernel"], e["expected"], (e["action_binding"] or "")[:20],
        [x["index"] for x in g if x["equal"]], e.get("trace_action_binding", "-")))
for n in result["native"]:
    links = n["delegator_aae_hash"]
    print("%-28s %-6s step %s delegator_aae_hash %s" % (n["id"], n["expected"], n["step"],
          links if isinstance(links, str) else [x["result"] for x in links]))
