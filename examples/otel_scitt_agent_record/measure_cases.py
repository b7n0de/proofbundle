"""Build the cases from the example and run check_example.py twice on each.

    python measure_cases.py [--cases DIR] [--out cases.md]

Each case changes one thing in the example. Where the change would otherwise break a signature first, the record
is signed again with the recorder's test key and anchored again with the statement signer's and the service's
test keys, so the check reaches the place the case is about. A case runs without the disclosure (the state a
reader has) or with it (the state of a dispute), as its row says. The cases are written to cases/ (ignored by
git), the table to cases.md. Exit 0 when every case ends in its expected state at its expected check and both runs
give the same report.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_example as mk  # noqa: E402
import scitt_local as sl  # noqa: E402

WRONG_SERVICE = sl.ec_key("otel scitt agent record example test key scitt-service-OTHER")
WRONG_STATEMENT = sl.ec_key("otel scitt agent record example test key statement-signer-OTHER")
WRONG_RECORDER, _ = mk.ed_key("otel scitt agent record example test key recorder-OTHER")


def rebuilt(b, statement, *, key=mk.RECORDER_SK):
    """b with another record statement, signed and anchored again."""
    b = dict(b, statement=statement)
    b["payload"], b["envelope"] = mk.sign_record(statement, key)
    b["signed_statement"], b["receipt_cose"], b["transparent"] = mk.anchor(b["payload"])
    return b


def entry(st, role):
    return next(e for e in st["predicate"]["entries"] if e["role"] == role)


def edit(b, fn, **kw):
    st = copy.deepcopy(b["statement"])
    fn(st)
    return rebuilt(b, st, **kw)


def c_unsalted_declared(b):
    def fn(st):
        run, tool = mk.span_list(b["spans"])
        e = entry(st, "action")
        e["alg"] = "sha256"
        e["fingerprint"] = "sha256:" + mk.sha256(mk.jcs(mk.selection(tool, mk.ACTION_ATTRIBUTES, parent=True)))
    return edit(b, fn)


def c_unsalted_hidden(b):
    def fn(st):
        run, tool = mk.span_list(b["spans"])
        entry(st, "action")["fingerprint"] = "sha256:" + mk.sha256(
            mk.jcs(mk.selection(tool, mk.ACTION_ATTRIBUTES, parent=True)))
    return edit(b, fn)


def c_no_receipt(b):
    return dict(b, transparent=sl.transparent(b["signed_statement"], []))


def c_receipt_removed(b):
    return dict(b, transparent=b["signed_statement"])


def c_wrong_service_key(b):
    rc = mk.ledger().register(b["signed_statement"], signing_key=WRONG_SERVICE)
    return dict(b, receipt_cose=rc, transparent=sl.transparent(b["signed_statement"], [rc]))


def c_wrong_service_key_pinned_kid(b):
    rc = mk.ledger().register(b["signed_statement"], signing_key=WRONG_SERVICE, kid=sl.kid_of(mk.SERVICE_KEY))
    return dict(b, receipt_cose=rc, transparent=sl.transparent(b["signed_statement"], [rc]))


def c_receipt_for_other_statement(b):
    rc = mk.ledger().register(b["signed_statement"], dh=hashlib.sha256(b"another statement").digest())
    return dict(b, receipt_cose=rc, transparent=sl.transparent(b["signed_statement"], [rc]))


def c_record_changed_after_anchoring(b):
    st = copy.deepcopy(b["statement"])
    st["predicate"]["conclusion"]["approvalRequired"] = False
    payload, env = mk.sign_record(st)
    return dict(b, statement=st, payload=payload, envelope=env)


def c_statement_unpinned_key(b):
    cert = sl.test_certificate(WRONG_STATEMENT, "statement-signer-OTHER", mk.LABEL_STATEMENT_ISSUER)
    st, rc, ts = mk.anchor(b["payload"], statement_key=WRONG_STATEMENT, cert=cert)
    return dict(b, signed_statement=st, receipt_cose=rc, transparent=ts)


def c_record_payload_changed(b):
    env = json.loads(b["envelope"])
    st = copy.deepcopy(b["statement"])
    st["predicate"]["conclusion"]["approvedBeforeAction"] = False
    env["payload"] = base64.b64encode(mk.jcs(st)).decode("ascii")
    return dict(b, envelope=mk.pretty(env))


def c_record_unpinned_key(b):
    return rebuilt(b, b["statement"], key=WRONG_RECORDER)


def c_conversation_id_in_clear(b):
    run, _tool = mk.span_list(b["spans"])
    return edit(b, lambda st: st["predicate"].update(
        conversationId=mk.attributes(run)["gen_ai.conversation.id"]))


def c_trace_id_in_clear(b):
    run, _tool = mk.span_list(b["spans"])
    return edit(b, lambda st: entry(st, "approval").update(
        standard=mk.APPROVAL_NOTE + "; trace " + run["traceId"]))


def c_approval_as_standard(b):
    return edit(b, lambda st: entry(st, "approval").update(
        standard="OpenTelemetry gen_ai approval span"))


def c_other_call(b):
    return edit(b, lambda st: entry(st, "approval").update(
        callRef=mk.fingerprint("call-example-other", b["salts"]["call"])))


def c_order(b):
    def fn(st):
        entry(st, "approval")["seq"], entry(st, "action")["seq"] = 3, 2
    return edit(b, fn)


def c_arguments_changed(b):
    doc = copy.deepcopy(b["spans"])
    _run, tool = mk.span_list(doc)
    for a in tool["attributes"]:
        if a["key"] == "gen_ai.tool.call.arguments":
            a["value"]["stringValue"] = mk.jcs(dict(mk.ARGUMENTS, recipient="acct-example-9999")).decode("utf-8")
    return dict(b, spans=doc)


def c_short_salt(b):
    s = dict(b["salts"], call=b["salts"]["call"][:16])
    return dict(b, salts=s)


def c_approval_deny(b):
    run, tool = mk.span_list(b["spans"])
    receipt = mk.approval_receipt(run, tool, verdict="DENY")
    st = copy.deepcopy(b["statement"])
    entry(st, "approval")["fingerprint"] = mk.fingerprint({"receiptSha256": mk.sha256(receipt)},
                                                          b["salts"]["approval"])
    return dict(rebuilt(b, st), receipt=receipt)


def c_approval_other_call(b):
    run, tool = mk.span_list(b["spans"])
    receipt = mk.approval_receipt(run, tool, call_id="call-example-other")
    st = copy.deepcopy(b["statement"])
    entry(st, "approval")["fingerprint"] = mk.fingerprint({"receiptSha256": mk.sha256(receipt)},
                                                          b["salts"]["approval"])
    return dict(rebuilt(b, st), receipt=receipt)


def c_approval_late(b):
    run, tool = mk.span_list(b["spans"])
    receipt = mk.approval_receipt(run, tool, decided="2026-11-20T10:00:05Z")
    doc = copy.deepcopy(b["spans"])
    _r, t = mk.span_list(doc)
    t["startTimeUnixNano"] = mk.nanos("2026-11-20T10:00:04Z")     # the action starts before the approval
    st = mk.record_statement(doc, receipt, b["salts"], b["rule"])
    return dict(rebuilt(b, st), receipt=receipt, spans=doc)


def c_rule_changed(b):
    return dict(b, rule=mk.pretty(dict(mk.RULE, threshold="500.00")))


def c_conclusion_false(b):
    return edit(b, lambda st: st["predicate"]["conclusion"].update(approvalRequired=False))


#: id, change, with disclosure, expected state, expected check, builder
CASES = [
    ("P0", "the example, unchanged, without the disclosure", False, "OPEN", "", lambda b: b),
    ("P1", "the example, unchanged, with the disclosure", True, "PASSED", "", lambda b: b),
    ("F01", "unsalted guessable content: the action's fingerprint is plain SHA-256 and says so", False,
     "FAILED", "K3", c_unsalted_declared),
    ("F02", "unsalted guessable content that claims sha256-salted-v1, without the disclosure", False,
     "OPEN", "", c_unsalted_hidden),
    ("F03", "as F02, with the disclosure", True, "FAILED", "D3", c_unsalted_hidden),
    ("F04", "missing receipt: the statement with an empty receipt list", False, "FAILED", "A1", c_no_receipt),
    ("F05", "missing receipt: the signed statement alone", False, "FAILED", "A1", c_receipt_removed),
    ("F06", "wrong service key: the receipt signed by another test key, kid of that key", False, "FAILED", "A1",
     c_wrong_service_key),
    ("F07", "wrong service key: the receipt signed by another test key under the pinned key's kid", False,
     "FAILED", "A1", c_wrong_service_key_pinned_kid),
    ("F08", "the receipt is for another statement (another data-hash in its leaf)", False, "FAILED", "A1",
     c_receipt_for_other_statement),
    ("F09", "the record changed and signed again after it was anchored", False, "FAILED", "A1",
     c_record_changed_after_anchoring),
    ("F10", "the statement signed by a key the reader has not pinned", False, "FAILED", "A1",
     c_statement_unpinned_key),
    ("F11", "the record's payload changed, old signature", False, "FAILED", "K1", c_record_payload_changed),
    ("F12", "the record signed by a key the reader has not pinned", False, "FAILED", "K1", c_record_unpinned_key),
    ("F13", "the conversation id in clear, as a field of its own", False, "FAILED", "K2", c_conversation_id_in_clear),
    ("F14", "the trace id in clear, inside the free text of the approval entry, without the disclosure", False,
     "OPEN", "", c_trace_id_in_clear),
    ("F14D", "as F14, with the disclosure", True, "FAILED", "D6", c_trace_id_in_clear),
    ("F15", "the approval entry presents the approval as an OpenTelemetry standard", False, "FAILED", "K3",
     c_approval_as_standard),
    ("F16", "approval and action carry different call references", False, "FAILED", "K4", c_other_call),
    ("F17", "the stated order is action before approval", False, "FAILED", "K4", c_order),
    ("F18", "the disclosed tool arguments are not the fingerprinted ones", True, "FAILED", "D3",
     c_arguments_changed),
    ("F19", "a disclosed salt of 8 bytes", True, "FAILED", "D1", c_short_salt),
    ("F20", "the disclosed approval is a DENY, the record says approved", True, "FAILED", "D5", c_approval_deny),
    ("F21", "the disclosed approval names another tool call", True, "FAILED", "D4", c_approval_other_call),
    ("F22", "the approval was decided after the action started", True, "FAILED", "D4", c_approval_late),
    ("F23", "the disclosed rule is not the one the record names", True, "FAILED", "D5", c_rule_changed),
    ("F24", "the record's conclusion is not what the rule gives", True, "FAILED", "D5", c_conclusion_false),
]


def write_case(d: Path, b):
    fs = mk.files(b)
    fs["disclosure/salts.json"] = mk.pretty({"note": "TEST SALTS", "alg": mk.COMMIT_ALG, "salts_hex": b["salts"]})
    mk.write(d, fs)


def run_check(d: Path, disclosure: bool, report: Path) -> tuple:
    cmd = [sys.executable, str(HERE / "check_example.py"), str(d), "--report", str(report)]
    if disclosure:
        cmd += ["--disclosure", str(d / "disclosure")]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, report.read_bytes()


def measure(cases_dir: Path) -> list:
    rows = []
    for cid, change, disc, want_state, want_check, fn in CASES:
        d = cases_dir / cid
        b = fn(mk.base())
        write_case(d, b)
        rc1, r1 = run_check(d, disc, d / "report-1.json")
        rc2, r2 = run_check(d, disc, d / "report-2.json")
        rep = json.loads(r1)
        first = rep["first_failure"] or {}
        rows.append({"id": cid, "change": change, "disclosure": disc, "expected": (want_state + " " + want_check).strip(),
                     "result": (rep["state"] + " " + first.get("id", "")).strip(), "exit": rc1,
                     "same": r1 == r2 and rc1 == rc2, "detail": first.get("detail", "")})
    return rows


def table(rows) -> str:
    out = ["# Cases", "",
           "Written by measure_cases.py. Each case is checked twice with check_example.py; \"same\" means the two",
           "reports and exit codes are equal. \"Disclosure\" says whether the check got the disclosure of a dispute",
           "(spans, salts, approval receipt, rule) or only the record and its Transparent Statement. OPEN exits 3,",
           "PASSED 0, FAILED 1.", "",
           "| Case | Change | Disclosure | Expected | Result | Exit | Same | As expected | First failure |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append("| %s | %s | %s | %s | %s | %d | %s | %s | %s |" % (
            r["id"], r["change"], "yes" if r["disclosure"] else "no", r["expected"], r["result"], r["exit"],
            "yes" if r["same"] else "no", "yes" if r["result"] == r["expected"] and r["same"] else "no",
            r["detail"].replace("|", "\\|")))
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the cases and write cases.md.")
    ap.add_argument("--cases", default=str(HERE / "cases"))
    ap.add_argument("--out", default=str(HERE / "cases.md"))
    a = ap.parse_args(argv)
    rows = measure(Path(a.cases))
    Path(a.out).write_text(table(rows), encoding="utf-8")
    bad = [r["id"] for r in rows if r["result"] != r["expected"] or not r["same"]]
    print("%d cases, %d not as expected%s" % (len(rows), len(bad), (": " + ", ".join(bad)) if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
