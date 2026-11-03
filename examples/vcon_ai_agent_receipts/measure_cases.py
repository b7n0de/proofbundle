"""Build the failure cases from the example and run check_example.py twice on each.

    python measure_cases.py [--proofbundle CMD] [--adrverify PATH] [--cases DIR] [--out cases.md]

Each case changes one thing in the example and, where the change would otherwise break the signature
first, signs the vCon again with the test key, so the check reaches the place the case is about. P2,
F05R and F08R use the RS256 form of the signed vCon in place of the EdDSA form. P3 and F27 check the
proposal file as well (--proposal). The receipt dec-0003 that cites the record is always the one of the
unchanged example. The cases are written
to cases/ (ignored by git); the table of results goes to cases.md. Exit 0 when every case fails at the
expected check, both runs give the same report, and the example itself passes.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_example as mk  # noqa: E402
import vcon_profile as vp  # noqa: E402

B = mk.base()
BASE = mk.files()
FORCE = {"command": "git push --force origin refs/heads/topic:refs/heads/main", "description": "Push the topic branch"}
PROPOSAL = "proposal/vcon.with-receipt-reference.unsigned.json"
OP1, OP2 = B["op1"], B["op2"]


def ev(v, op, typ):
    return next(e for e in v["events"] if e.get("operation_id") == op and e["type"] == typ)


def m_f01(v):
    t = v["attachments"][2]["content_hash"][0]
    v["attachments"][2]["content_hash"][0] = t[:-2] + ("AA" if t[-2:] != "AA" else "BB")


def m_f03(v):
    ev(v, OP1, "tool-invocation")["time"] = "2026-10-15T09:16:00.000Z"
    ev(v, OP1, "tool-result")["time"] = "2026-10-15T09:16:02.000Z"


def after_deny(v, result):
    """A tool-invocation of the disallowed merge, and the response the tool gave to it."""
    pd = ev(v, OP2, "policy-decision")
    i = v["events"].index(pd)
    common = {"time": "2026-10-15T09:05:01.000Z", "sessions": 0, "party": 1, "operation_id": OP2, "attempt": 1}
    inv = dict(common, type="tool-invocation", server=pd["server"], tool=pd["tool"], mediatype="application/json",
               encoding="json", body={"command": "gh pr merge 7 --repo acme/widgets --merge",
                                      "description": "Merge pull request 7"})
    res = dict(common, type=result, time="2026-10-15T09:05:02.000Z", mediatype="text/plain", encoding="none",
               body="Merged pull request 7." if result == "tool-result" else "merge failed")
    v["events"][i + 1:i + 1] = [inv, res]


def m_f04(v):
    after_deny(v, "tool-result")


def m_f05(v):
    v["dialog"][2]["body"] = "Approved. You may also force push."


def m_f07(v):
    env = v["attachments"][1]["body"]
    p = base64.b64decode(env["payload"])
    a1 = vp.sha256(vp.jcs(ev(v, OP1, "tool-invocation")["body"]))
    env["payload"] = base64.b64encode(p.replace(a1.encode(), vp.sha256(vp.jcs(FORCE)).encode())).decode()


def m_f09(v):
    for e in v["events"]:
        e["session"] = e.pop("sessions")


def m_f12(v):
    sid = v["sessions"][0]["agent_session_id"]
    op3 = mk.operation(sid, "toolu_example_03")
    pd = copy.deepcopy(ev(v, OP1, "policy-decision"))
    pd.update({"time": "2026-10-15T09:00:03.500Z", "operation_id": op3})
    call = copy.deepcopy(ev(v, OP1, "tool-invocation"))
    call.update({"time": "2026-10-15T09:01:00.000Z", "operation_id": op3})
    res = copy.deepcopy(ev(v, OP1, "tool-result"))
    res.update({"time": "2026-10-15T09:01:02.000Z", "operation_id": op3, "body": "Everything up-to-date"})
    v["events"] += [pd, call, res]
    env4 = mk.allow(v, sid, "dec-0004", "2026-10-15T09:01:00Z", "2026-10-15T09:06:00Z", op3, B["approval"])
    v["attachments"].append({"purpose": "decision receipt", "start": "2026-10-15T09:01:00Z", "party": 2,
                             "session": 0, "mediatype": "application/json", "filename": "dec-0004.dsse.json",
                             "encoding": "json", "body": env4})


def m_f31(v):
    s = copy.deepcopy(v["sessions"][0])
    s.update({"agent_session_id": "5e551011-0000-4000-8000-000000000009", "dialog": []})
    v["sessions"].append(s)
    pd = ev(v, OP2, "policy-decision")
    v["events"].append({"type": "tool-invocation", "time": "2026-10-15T09:05:01.000Z", "sessions": 1, "party": 1,
                        "operation_id": OP2, "attempt": 1, "server": pd["server"], "tool": pd["tool"],
                        "mediatype": "application/json", "encoding": "json",
                        "body": {"command": "gh pr merge 7 --repo acme/widgets --merge",
                                 "description": "Merge pull request 7"}})


def m_f19(v):
    ev(v, OP1, "policy-decision")["operation_id"] = mk.operation(v["sessions"][0]["agent_session_id"], "toolu_other")


def m_f22(v):
    for typ in ("tool-invocation", "tool-result"):
        ev(v, OP1, typ)["operation_id"] = mk.operation(v["sessions"][0]["agent_session_id"], "toolu_other")


def p_f27(fs):
    d = json.loads(fs[PROPOSAL])
    pds = [e for e in d["events"] if e.get("type") == "policy-decision"]
    pds[0][mk.PROPOSAL_PARAMETER]["content_hash"], pds[1][mk.PROPOSAL_PARAMETER]["content_hash"] = (
        pds[1][mk.PROPOSAL_PARAMETER]["content_hash"], pds[0][mk.PROPOSAL_PARAMETER]["content_hash"])
    fs[PROPOSAL] = vp.pretty(d)


def p_f08(fs):
    d = json.loads(fs["vcon.signed.json"])
    v = json.loads(vp.b64u_dec(d["payload"]))
    m_f05(v)
    d["payload"] = vp.b64u(vp.jcs(v))
    fs["vcon.signed.json"] = vp.pretty(d)


def p_f16(fs):
    b = bytearray(fs["vcon.cose"])
    b[-1] ^= 1
    fs["vcon.cose"] = bytes(b)


def p_f17(fs):
    _, prot_b, unprot, payload, sig, _ = vp.cose_sign1_open(fs["vcon.cose"])
    unprot[vp.TRACE_METADATA]["content-hash"] = "0" * 64
    fs["vcon.cose"] = vp.cbor_encode(vp.Tag(18, [prot_b, unprot, payload, sig]))


def p_f18(fs):
    v = copy.deepcopy(B["full"])
    m_f05(v)
    fs["vcon.cose"] = mk.sign(v)[2]


CASES = [
    ("F01", "wrong content_hash on the external DENY receipt", "A1", m_f01, None),
    ("F02", "receipt for another invocation: the arguments of the tool-invocation are another command", "R2",
     lambda v: ev(v, OP1, "tool-invocation").update({"body": dict(FORCE)}), None),
    ("F03", "approval expired at the time of the tool-invocation", "R4b", m_f03, None),
    ("F04", "DENY followed by a tool-invocation and a tool-result of the same operation", "C2", m_f04, None),
    ("F05", "vCon changed after it was cited, signed again in both forms", "Z2", m_f05, None),
    ("F06", "attachment without a matching receipt (the ALLOW receipt removed)", "C3",
     lambda v: v["attachments"].pop(1), None),
    ("F07", "payload of the inline receipt changed, old signature", "R1", m_f07, None),
    ("F08", "JWS payload changed, not signed again", "V2", None, p_f08),
    ("F09", "Event Objects with session instead of sessions", "V4", m_f09, None),
    ("F10", "content_hash without a sha512 token", "A1",
     lambda v: v["attachments"][2].update({"content_hash": [v["attachments"][2]["content_hash"][1]]}), None),
    ("F11", "approval answer contributed by the agent", "R4a", lambda v: v["dialog"][2].update({"parties": [1]}), None),
    ("F12", "two ALLOW receipts cite the same approval", "C1", m_f12, None),
    ("F13", "approvedAt is not the time of the answer", "R4a",
     lambda v: v["dialog"][2].update({"start": "2026-10-15T09:00:03.000Z"}), None),
    ("F14", "answer with a duration, approvedAt equals its start", "R4a",
     lambda v: v["dialog"][2].update({"duration": 2}), None),
    ("F15", "DENY followed by a tool-invocation that ended in tool-failure", "C2",
     lambda v: after_deny(v, "tool-failure"), None),
    ("F16", "COSE_Sign1 signature changed", "Z3", None, p_f16),
    ("F17", "trace-metadata content-hash changed (unprotected header)", "Z3", None, p_f17),
    ("F18", "COSE_Sign1 over a changed vCon, JWS unchanged", "Z3", None, p_f18),
    ("F19", "the receipt names an operation_id that no policy-decision of the session has", "R2", m_f19, None),
    ("F20", "the approved push has the policy-decision allowed instead of permission-required", "R3",
     lambda v: ev(v, OP1, "policy-decision").update({"decision": "allowed"}), None),
    ("F21", "the ALLOW receipt names a policy-decision disallowed", "R2",
     lambda v: ev(v, OP1, "policy-decision").update({"decision": "disallowed"}), None),
    ("F22", "the tool-invocation of the approved push carries another operation_id", "R2", m_f22, None),
    ("F23", "attachment on a policy-decision (Table 3: MUST NOT be present)", "V4",
     lambda v: ev(v, OP1, "policy-decision").update({"attachment": 0}), None),
    ("F24", "tool-invocation without server (6.1.8)", "V4", lambda v: ev(v, OP1, "tool-invocation").pop("server"),
     None),
    ("F25", "policy-decision with a decision outside the three values (6.1.4)", "V4",
     lambda v: ev(v, OP2, "policy-decision").update({"decision": "denied"}), None),
    ("F26", "policy-decision with policy_life once and no operation_id (6.1.2)", "V4",
     lambda v: ev(v, OP2, "policy-decision").pop("operation_id"), None),
    ("F28", "the policy-decision of the approved push comes after the approval (Figure 1)", "R4b",
     lambda v: ev(v, OP1, "policy-decision").update({"time": "2026-10-15T09:00:05.000Z"}), None),
    ("F29", "the policy-decision disallowed is not at decidedAt of the DENY receipt", "R2",
     lambda v: ev(v, OP2, "policy-decision").update({"time": "2026-10-15T09:05:02.000Z"}), None),
    ("F30", "the tool-invocation and the tool-result of the approved push are attempt 2, the decision attempt 1",
     "R2", lambda v: [ev(v, OP1, typ).update({"attempt": 2}) for typ in ("tool-invocation", "tool-result")], None),
    ("F31", "a tool-invocation of the denied merge in a second session", "C2", m_f31, None),
    ("F32", "the tool-invocation and the tool-result of the approved push name the person as party", "R2",
     lambda v: [ev(v, OP1, typ).update({"party": 0}) for typ in ("tool-invocation", "tool-result")], None),
    ("F33", "every event of both operations is attempt 2, no attempt 1 (5.1, 6.1.3)", "V4",
     lambda v: [e.update({"attempt": 2}) for e in v["events"] if "operation_id" in e], None),
    ("F34", "the tool-result of the push has encoding 7 (6.1.10)", "V4",
     lambda v: ev(v, OP1, "tool-result").update({"encoding": 7}), None),
    ("F35", "the tool-result of the push keeps encoding without body and mediatype (6.1.10)", "V4",
     lambda v: [ev(v, OP1, "tool-result").pop(k) for k in ("body", "mediatype")], None),
]
PROPOSAL_CASES = [
    ("F27", "proposal: each policy-decision references the receipt of the other decision", "E1", None, p_f27),
]
RS256_CASES = [
    ("F05R", "as F05, the vCon signed again in the RS256 form", "Z2", m_f05, None),
    ("F08R", "as F08, in the RS256 form", "V2", None, p_f08),
]


def case_files(mutate, post, rs256=False):
    fs = {k: BASE[k] for k in ("vcon.signed.json", "vcon.cose", "external/dec-0002.dsse.json",
                               "receipts/dec-0003.dsse.json", PROPOSAL)}
    if rs256:
        fs["vcon.signed.json"] = BASE["vcon.signed-rs256.json"]
    if mutate:
        v = copy.deepcopy(B["full"])
        mutate(v)
        _, fs["vcon.signed.json"], fs["vcon.cose"] = mk.sign(v)
        if rs256:
            fs["vcon.signed.json"] = mk.sign_rs256(v)
    if post:
        post(fs)
    return fs


def receipts_unchanged(fs):
    d = json.loads(fs["vcon.signed.json"])
    v = json.loads(vp.b64u_dec(d["payload"]))
    inline = [a["body"] for a in v.get("attachments", []) if a.get("purpose") == "decision receipt"
              and "body" in a]
    return inline == [B["env1"]] and fs["external/dec-0002.dsse.json"] == B["env2"]


def run(d, a, n):
    rep = d / ("report-%d.json" % n)
    cmd = [sys.executable, "-I", str(HERE / "check_example.py"), str(d), "--proofbundle", a.proofbundle,
           "--report", str(rep)] + (["--adrverify", a.adrverify] if a.adrverify else []) + a.extra
    r = subprocess.run(cmd, capture_output=True, check=False)
    b = json.loads(rep.read_bytes())
    return r.returncode, b, rep.read_bytes()


def main():
    ap = argparse.ArgumentParser(description="Run the failure cases.")
    ap.add_argument("--proofbundle", default="proofbundle")
    ap.add_argument("--adrverify")
    ap.add_argument("--cases", default=str(HERE / "cases"))
    ap.add_argument("--out", default=str(HERE / "cases.md"))
    a = ap.parse_args()
    root = Path(a.cases)
    rows, good = [], True
    plan = [("P0", "the example, unchanged", None, None, None, [], False),
            ("P1", "the example, checked with --action-bytes none", None, None, None, ["--action-bytes", "none"], False),
            ("P2", "the example in its RS256 form", None, None, None, [], True),
            ("P3", "the example with the proposal file", None, None, None, ["--proposal", PROPOSAL], False)]
    plan += [(c, t, exp, m, p, [], False) for c, t, exp, m, p in CASES]
    plan += [(c, t, exp, m, p, [], True) for c, t, exp, m, p in RS256_CASES]
    plan += [(c, t, exp, m, p, ["--proposal", PROPOSAL], False) for c, t, exp, m, p in PROPOSAL_CASES]
    for cid, title, expected, mutate, post, extra, rs256 in plan:
        d = root / cid
        fs = case_files(mutate, post, rs256)
        mk.write(d, fs)
        a.extra = extra
        (c1, b1, raw1), (c2, _b2, raw2) = run(d, a, 1), run(d, a, 2)
        got = "PASS" if b1["first_failure"] is None else "FAIL " + b1["first_failure"]["id"]
        want = "PASS" if expected is None else "FAIL " + expected
        same = raw1 == raw2
        ok = got == want and same and c1 == c2 == (0 if expected is None else 1)
        good &= ok
        where = "" if b1["first_failure"] is None else b1["first_failure"]["where"] + ", " + b1["first_failure"]["detail"]
        rows.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            cid, title, want, got, "yes" if same else "NO", "yes" if receipts_unchanged(fs) else "no",
            "yes" if ok else "NO", where.replace("|", "\\|")))
    md = ["# Cases", "",
          "Written by measure_cases.py. Each case is checked twice with check_example.py; \"same\" means the two",
          "reports are byte for byte equal. \"receipts unchanged\" means the decision receipts in the vCon and the",
          "external one are the bytes of the unchanged example, which `proofbundle decision verify` accepts there.",
          "", "| Case | Change | Expected | Result | Same | Receipts unchanged | As expected | First failure |",
          "|---|---|---|---|---|---|---|---|"] + rows
    Path(a.out).write_text("\n".join(md) + "\n", encoding="utf-8")
    print("all as expected" if good else "NOT all as expected", "(%d cases)" % len(rows))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
