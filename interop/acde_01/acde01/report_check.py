"""Conformance checks on a report object, independent of how the report was produced.

A relying party that receives a report in this implementation's representation can run these
checks without the inputs. Each violation names the requirement sentence it comes from.
"""
from __future__ import annotations

from .profile import MIN_DISPOSITIONS, SUPPORT_MEANINGS
from .reconcile import RECEIVER_CLASSES

POSITIVE_FAILURES = ("EXPLICIT_FAILURE", "SUBSTITUTION")
#: The classes an instruction can have (S5.11-4 to S5.11-7, the ones reconcile writes). An entry of any other class
#: is none the instruction-level equation can count (CODEX-630-K10).
INSTRUCTION_CLASSES = ("with_obligations", "zero_obligations", "not_closed")


def _v(out, req, msg):
    out.append({"requirement": req, "error": msg})


def _walk(node, path="$"):
    if isinstance(node, dict):
        yield path, node
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


def check_report(report) -> list:
    out: list = []
    if not isinstance(report, dict):
        _v(out, "S6.6-4", "report is not an object")
        return out

    # Co-exposure: no structural result anywhere without claim scope and claim support (S6.6-3/4)
    for path, node in _walk(report):
        if "structural_result" in node:
            if "claim_scope" not in node or "claim_support" not in node:
                _v(out, "S6.6-3", f"{path}: structural result exposed without claim scope and "
                                  "claim-support qualification in the same result context")
            elif node.get("claim_support") not in SUPPORT_MEANINGS:
                _v(out, "S6.6-5", f"{path}: claim support {node.get('claim_support')!r} has no mapping "
                                  "to the three conceptual meanings")

    obligations = report.get("obligations")
    if not isinstance(obligations, list):
        _v(out, "S5.10-1", "no per-obligation dispositions")
        obligations = []
    for o in obligations:
        if not isinstance(o, dict) or o.get("disposition") not in MIN_DISPOSITIONS:
            _v(out, "S5.11-2", f"obligation without exactly one minimum disposition: {o!r:.120}")
        enf = (o or {}).get("enforcement") if isinstance(o, dict) else None
        if not isinstance(enf, dict) or not isinstance(o.get("control_effect"), dict):
            _v(out, "S5.6-1", "delivery, enforcement and control effect must be separate facts")
        elif enf.get("outcome") == "APPLIED" and not enf.get("records"):
            _v(out, "S5.6-3", f"{o.get('instruction_id')}/{o.get('target_id')}: APPLIED without "
                              "enforcement evidence")
        if isinstance(o, dict) and len((o.get("reduction") or {}).get("applicable") or []) > 1 \
                and not o.get("diagnostics"):
            _v(out, "S5.10-7", "several applicable diagnostics reduced without keeping them visible")

    cons = report.get("conservation") or {}
    oc = (cons.get("obligations") or {})
    counts = {d: sum(1 for o in obligations if isinstance(o, dict) and o.get("disposition") == d)
              for d in MIN_DISPOSITIONS}
    if oc.get("counts") != counts or oc.get("O") != len(obligations):
        _v(out, "S6.4-1", "published obligation counts do not equal the per-obligation dispositions")
    if oc.get("O") != sum((oc.get("counts") or {}).values()):
        _v(out, "S6.4-1", "|O| is not the sum of the disposition classes")
    o_holds = len(obligations) == sum(counts.values()) and oc.get("O") == len(obligations)
    if oc.get("holds") is not o_holds:
        _v(out, "S6.4-1", f"the report states the obligation equation holds {oc.get('holds')!r}, and its "
                          f"per-obligation dispositions give {o_holds}")

    instrs = report.get("instructions") if isinstance(report.get("instructions"), list) else []
    ic = cons.get("instructions") or {}
    # The vocabulary is closed and the equation is recomputed from the report's own entries; a boolean the report
    # states about itself is compared with that, never trusted (CODEX-630-K10: an instruction of class UNKNOWN with
    # the counts 0 + 0 left draft_equation_holds true, and the report kept PASS).
    for e in instrs:
        cls = e.get("class") if isinstance(e, dict) else None
        if cls not in INSTRUCTION_CLASSES:
            _v(out, "S6.4-3", f"instruction {e.get('instruction_id') if isinstance(e, dict) else e!r:.60}: class "
                              f"{cls!r} is none of {', '.join(INSTRUCTION_CLASSES)}, so the instruction-level "
                              "equation cannot count it")
    instrs = [e for e in instrs if isinstance(e, dict)]
    n_with = sum(1 for e in instrs if e.get("class") == "with_obligations")
    n_zero = sum(1 for e in instrs if e.get("class") == "zero_obligations")
    draft_holds = len(instrs) == n_with + n_zero
    if ic.get("draft_equation_holds") is not draft_holds:
        _v(out, "S6.4-3", f"the report states draft_equation_holds {ic.get('draft_equation_holds')!r}, and its "
                          f"instruction entries give |I| = {len(instrs)} against {n_with} + {n_zero}")
    if ic.get("I") != len(instrs) or ic.get("with_obligations") != n_with \
            or ic.get("zero_obligation_instructions") != n_zero:
        _v(out, "S5.11-7", "|I| and the with/zero instruction counts are not published consistently")
    for e in instrs:
        if e.get("class") == "zero_obligations" and not e.get("zero_obligation_condition"):
            _v(out, "S6.4-4", f"zero-obligation instruction {e.get('instruction_id')} reported without "
                              "the rule or condition that produced the empty set")

    rc = cons.get("receiver_records") or {}
    rcounts = rc.get("counts") if isinstance(rc.get("counts"), dict) else {}
    fremd = sorted(map(str, set(rcounts) - set(RECEIVER_CLASSES)))
    if fremd:
        _v(out, "S6.4-5", f"receiver-record counts name classes the profile does not have: {', '.join(fremd)}")
    r_holds = (not fremd and all(type(n) is int and n >= 0 for n in rcounts.values())
               and rc.get("R") == sum(rcounts.values()))
    if rc.get("R") != sum(n for n in rcounts.values() if type(n) is int):
        _v(out, "S6.4-5", "|R| is not matched + orphan + duplicate + invalid")
    if rc.get("holds") is not r_holds:
        _v(out, "S6.4-5", f"the report states the receiver equation holds {rc.get('holds')!r}, and its counts "
                          f"give {r_holds}")
    sub = rc.get("matched_subdivision")
    if isinstance(sub, dict) and sum(sub.values()) != rcounts.get("matched"):
        _v(out, "S6.4-7", "subdivisions of the matched class do not preserve its count")

    st = report.get("structural") or {}
    res = st.get("structural_result")
    if not isinstance(st.get("class_counts"), dict):
        _v(out, "S6.5-6", "complete class counts are not published beside the aggregate label")
    if res == "PASS":
        if any(o.get("disposition") != "CONFIRMED" for o in obligations if isinstance(o, dict)):
            _v(out, "S6.5-4", "PASS while an obligation is not CONFIRMED")
        # PASS needs each equation to hold both as the report states it and as its numbers give it (CODEX-630-K10)
        stated = (oc.get("holds"), rc.get("holds"), ic.get("draft_equation_holds")) == (True, True, True)
        if not (stated and o_holds and r_holds and draft_holds):
            _v(out, "S6.5-5", "PASS while a conservation equation fails")
        if any(e.get("class") == "not_closed" for e in instrs):
            _v(out, "S6.5-2", "PASS over a population that is not closed")
    if res == "FAIL":
        pos = st.get("positive_failing_conditions") or []
        real = [o for o in obligations if isinstance(o, dict) and o.get("disposition") in POSITIVE_FAILURES]
        if not pos or not real:
            _v(out, "S6.5-3", "FAIL without a positive failing condition (missing evidence alone)")

    if res not in ("PASS", "FAIL", "INCONCLUSIVE"):
        _v(out, "S6.5-1", f"structural result {res!r} is not one of the profile's aggregate results")
    for o in obligations:
        if not isinstance(o, dict):
            continue
        if o.get("disposition") in POSITIVE_FAILURES:
            fs = o.get("failure_scope") or {}
            if fs.get("target_id") != o.get("target_id") or fs.get("instruction_id") != o.get("instruction_id"):
                _v(out, "S6.1-2", f"{o.get('instruction_id')}/{o.get('target_id')}: failure without its own scope")
    not_closed = {e.get("instruction_id") for e in instrs if e.get("class") == "not_closed"}
    for o in obligations:
        if isinstance(o, dict) and o.get("instruction_id") in not_closed and o.get("open_scope") is not True:
            _v(out, "S5.11-12", f"{o.get('instruction_id')}/{o.get('target_id')}: per-known-target result "
                                "without an explicit open-population scope")
    for op in report.get("operations") or []:
        facts = op.get("facts") or []
        status = op.get("status") or ""
        crossed_before = any(f.get("boundary") == "provider_entry" and f.get("event") == "crossed"
                             and f.get("relation_to_activation") == "before_activation" for f in facts)
        if status.startswith("blocked") and crossed_before:
            _v(out, "S9.4-2", f"operation {op.get('operation_id')} relabelled blocked although it crossed "
                              "provider entry before activation")
        if status.startswith("blocked") and not any(f.get("event") == "refused" for f in facts):
            _v(out, "S9.4-4", f"operation {op.get('operation_id')}: blocked status without the refusal fact")
        if crossed_before and "unresolved" not in status:
            _v(out, "S9.4-5", f"operation {op.get('operation_id')}: outcome of a pre-activation crossing "
                              "reported without being left unresolved")
    for e in instrs:
        par = e.get("parent") or {}
        per = par.get("per_target")
        if not isinstance(per, dict):
            _v(out, "S6.2-1", f"parent {e.get('instruction_id')}: per-target dispositions not retained")
            continue
        if par.get("fully_confirmed_within_target_set") is True and \
                (not per or any(d != "CONFIRMED" for d in per.values())):
            _v(out, "S6.2-2", f"parent {e.get('instruction_id')} reported fully confirmed with a "
                              "non-CONFIRMED obligation")

    for c in report.get("claims") or []:
        sc = c.get("claim_scope") or {}
        # The population may be empty (it is still identified); boundaries, cutoff and fact not.
        if not isinstance(sc.get("instructions"), list):
            _v(out, "S6.6-1", f"claim {c.get('claim_id')}: claim scope does not identify the population")
        for k in ("boundaries", "cutoff", "fact"):
            if sc.get(k) in (None, [], ""):
                _v(out, "S6.6-1", f"claim {c.get('claim_id')}: claim scope lacks {k}")
        if c.get("claim_support") == "CONDITIONALLY_SUPPORTED" and not c.get("conditions"):
            _v(out, "S6.6-6", f"claim {c.get('claim_id')}: conditional support without named conditions")
        if c.get("claim_support") == "NOT_SUPPORTED" and c.get("assertable") is not False:
            _v(out, "S6.6-7", f"claim {c.get('claim_id')}: unsupported claim rendered as assertable")

    if not report.get("non_claims"):
        _v(out, "S5.13-1", "the report does not state what its results do not cover")
    return out


def check_rendering(text: str) -> list:
    """Every line of a text rendering that shows a structural result also shows claim scope and
    claim support (S6.6-3 applies to every representation, S5.13-3)."""
    out: list = []
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if "structural result" in low and ("claim scope" not in low or "claim support" not in low):
            _v(out, "S6.6-3", f"line {n}: structural result rendered without its claim context")
    return out
