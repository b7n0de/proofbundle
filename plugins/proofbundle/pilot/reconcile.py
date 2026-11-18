#!/usr/bin/env python3
"""The reconciliation of the pilot of Z405 (part 3, DECISIONS.md D57): decisions and outcomes joined, M1 to M8.

    reconcile.py --records DIR [--name NAME]

It reads the records and nothing else (contract, section 8): the decisions the gate signed, the responses the observer
kept, the outcomes it signed, and the inputs pilot_start.json keeps with their digests. It recomputes the match of the
contract, section 5, from the kept responses, so a person who was not part of the sessions gets the same classification
from the same folder (criterion 4), and it asks the profile the records keep (github-write/1) for its answer on each
decision with the outcome bound to it. It writes reconciliation/<name>.json; the same records give the same bytes.

The measures (contract, section 5), each from a closed set; `unknown` and `not measured` are values of their own:
M1 arrived, not arrived, ambiguous, not yet observed, unknown; M2 identical, different, not measured; M3 same,
different, not measured; M4 yes, no, not measured; M5 and M6 counts over the window; M7 seconds from the decision to
the first reading of its effect, or no observation; M8 the number of decisions that share the action id.

Every window's reconciliation carries one sentence under window_notes (D113, owner choice O28B-1): under the hook's
autonomous answer a write whose answer it changes can lack its receipt of Level 1, and M5 counts it where it arrives.

The key signer's journal (D65), as the key account exported it into keysigner/ of the records at the end of the window,
gives two counts of their own: signed lines without a receipt (a signature the gate key made that no receipt in
decisions/ carries) and receipts without a signed line (a receipt whose statement the key signer's journal does not
name). A signed line marked `"handedOut": false` never left the key signer and is counted apart. Either count not 0
ends the reconciliation with KEY_JOURNAL_DISAGREES, a journal the records do not keep as exported with
KEY_JOURNAL_NOT_READ; the file is written either way.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pilot_records as pr  # noqa: E402

APPROVE, ESCALATE = ("ALLOW",), ("ESCALATE", "DEFER")
NOT_MEASURED, UNKNOWN = "not measured", "unknown"
#: The exit codes of the key signer's journal (D65): a count not 0, and a journal the records do not keep as exported.
KEY_JOURNAL_DISAGREES = 3
KEY_JOURNAL_NOT_READ = 4
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
#: The name of a reconciliation, the file name it is written under.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z", re.ASCII)
#: D113 (owner choice O28B-1 of 2026-10-20: measure first, until then say so): the one sentence every
#: window's reconciliation carries about the receipts of Level 1 under the hook's autonomous answer.
LEVEL1_UNDER_AUTONOMY = ("Under the hook's autonomous answer (Claude Code, --autonomous) a GitHub write whose answer it "
                         "changes can lack its receipt of Level 1, as the signer service decides without that answer "
                         "(O28B-1); M5 counts such a write that reaches GitHub, as an effect without an approval.")


def _closing_lines(stored: bytes | None, rule: object) -> str:
    """M4: whether the stored bytes end with the closing lines the rule of the approved surface names. A surface whose
    rule is null requires none."""
    if rule is None:
        return "yes"
    if stored is None or not isinstance(rule, str):
        return NOT_MEASURED
    try:
        text = stored.decode("utf-8")
    except UnicodeDecodeError:
        return NOT_MEASURED
    return "yes" if text.rstrip().endswith(rule.rstrip()) else "no"


def _class(verdict: str, m: dict, early: bool = False) -> str:
    """The named class of one decision; a class that is no reconciliation is a mismatch with that name. An effect GitHub
    dates before the decision is no effect of that approval (contract, criterion 1)."""
    if m["M1"] == "ambiguous":
        return "ambiguous effect"
    if verdict in APPROVE:
        if m["M1"] == "arrived" and early:
            return "approved, arrived before the approval"
        if m["M1"] == "arrived":
            if m["M3"] == "different":
                return "approved, arrived on another surface"
            if m["M2"] == "different":
                return "approved, arrived with other bytes"
            if m["M4"] == "no":
                return "approved, arrived without the closing lines"
            if NOT_MEASURED in (m["M2"], m["M3"], m["M4"]):
                return "approved, arrived, form not measured"
            return "reconciled: approved and arrived as approved"
        return {"not arrived": "approved, not arrived", "not yet observed": "approved, not yet observed"} \
            .get(m["M1"], "approved, not matchable")
    if verdict in pr.REFUSED:
        return {"not arrived": "reconciled: refused and not arrived", "arrived": "refused but arrived",
                "not yet observed": "refused, not yet observed"}.get(m["M1"], "refused, not matchable")
    if verdict in ESCALATE:
        return {"not arrived": "escalated, not arrived", "arrived": "escalated, arrived without an approval of the gate",
                "not yet observed": "escalated, not yet observed"}.get(m["M1"], "escalated, not matchable")
    return f"verdict {verdict}, not read by the contract"


def key_journal_check(records: pr.Records, entries: list[dict]) -> dict:
    """The key signer's journal against the receipts (D65), matched by the sha256 of the statement each receipt carries.
    A signed line counts as handed out unless its second line says `"handedOut": false`; one without its second line is
    unconfirmed and counts as handed out."""
    receipts = {}
    for entry in entries:
        try:
            body = base64.b64decode(entry["envelope"]["payload"], validate=True)
        except (KeyError, TypeError, ValueError, binascii.Error):
            body = None
        receipts[entry["file"]] = pr.sha256_hex(body) if body is not None else None
    lines, journal_sha, why = records.key_journal()
    if lines is None:
        return {"read": False, "why": why, "signedWithoutReceipt": NOT_MEASURED,
                "receiptsWithoutSignedLine": NOT_MEASURED}
    signed, handed = {}, {}
    for line in lines:
        digest = line.get("statementSha256") if line is not None else None
        if not (isinstance(digest, str) and _SHA256.fullmatch(digest)):
            continue
        if line.get("signed") is True:
            signed[digest] = line.get("decisionId")
        elif "handedOut" in line and "signed" not in line:
            handed[digest] = handed.get(digest, True) and line["handedOut"] is True
    out = {d for d in signed if handed.get(d) is not False}
    taken = set(receipts.values())
    without_receipt = sorted(d for d in out if d not in taken)
    receipts_without = sorted(f for f, d in receipts.items() if d is None or d not in out)
    return {"read": True, "sha256": journal_sha, "lines": len(lines), "unreadableLines": lines.count(None),
            "signed": len(signed), "notHandedOut": sum(1 for d in signed if handed.get(d) is False),
            "unconfirmed": sum(1 for d in signed if d not in handed),
            "signedWithoutReceipt": len(without_receipt), "receiptsWithoutSignedLine": len(receipts_without),
            "signedWithoutReceiptLines": [{"decisionId": signed[d], "statementSha256": d} for d in without_receipt],
            "receiptsWithoutSignedLineFiles": receipts_without}


def reconcile(records: pr.Records) -> dict:
    profile = records.profile()
    rules, rules_sha = records.closing_rules()
    entries = records.decisions()
    views, unverified = {}, []
    for entry in entries:
        view = pr.decision_view(records, entry)
        if view is None:
            unverified.append(entry["file"])
        else:
            views[view["decisionId"]] = view
    runs = records.runs()
    effects = pr.effects_of_runs(runs, records.agent_of)   # a later run that lists an event again reads no second effect
    window = pr.window_of_runs(runs)
    # Without a run nothing was observed: M5 and M6 are not measured, never 0 (contract, criterion 2).
    matched = pr.match(effects, list(views.values()), records.agent_of, window) if runs else \
        {"rows": [], "M5": NOT_MEASURED, "M6": NOT_MEASURED, "actions_of_window": []}
    taken = {row["decision"]: row for row in matched["rows"] if row["decision"]}
    ambiguous = {d for row in matched["rows"] for d in row["ambiguous_with"]}
    by_root = {}
    for outcome in records.outcomes():
        by_root.setdefault(pr.outcome_root(profile, outcome), []).append(outcome)
    actions = [v["action"] for v in views.values()]
    rows = []
    for entry in entries:
        view = views.get(next((i for i, v in views.items() if v["file"] == entry["file"]), None))
        if view is None:
            answer = profile.reconcile(entry["envelope"], None, None, gate_key=records.gate_key,
                                       gate_id=records.gate_id, observer_key=records.observer_key,
                                       observer_id=records.observer_id)
            rows.append({"file": entry["file"], "receipt": "does not verify", "class": "receipt does not verify",
                         "profile": answer["verdict"], "profile_reasons": answer["reasons"]})
            continue
        row = taken.get(view["decisionId"])
        effect = row["effect"] if row else None
        covered = any(pr.instant_key(r["window"]["start"]) <= pr.instant_key(view["decidedAt"])
                      <= pr.instant_key(r["window"]["end"]) for r in runs) if pr.instant_key(view["decidedAt"]) else False
        if view["target"] is None:
            m1 = UNKNOWN
        elif view["decisionId"] in ambiguous:
            m1 = "ambiguous"
        elif effect is not None:
            m1 = "arrived"
        elif not covered:
            m1 = "not yet observed"
        else:
            m1 = "not arrived"
        arrived_approved = m1 == "arrived" and view["verdict"] in APPROVE
        stored = effect["stored"] if effect else None
        m = {"M1": m1,
             "M2": (("identical" if pr.sha256_hex(stored) == view["bytes_sha256"] else "different")
                    if arrived_approved and stored is not None and view["bytes_sha256"] else NOT_MEASURED),
             "M3": ("same" if effect["surface"] == view["surface"] else "different") if arrived_approved
             else NOT_MEASURED,
             "M4": (_closing_lines(stored, rules.get(view["surface"])) if view["closing_rules_sha256"] == rules_sha
                    else NOT_MEASURED) if arrived_approved else NOT_MEASURED,
             "M7": pr.seconds_between(view["decidedAt"], effect["observedAt"]) if effect else "no observation",
             "M8": actions.count(view["action"])}
        bound = sorted(by_root.get(view["root"], []), key=lambda o: o["file"])
        outcome = bound[0] if bound else None
        answer = profile.reconcile(view["envelope"], outcome["envelope"] if outcome else None,
                                   outcome["scope"] if outcome else None, gate_key=records.gate_key,
                                   gate_id=records.gate_id, observer_key=records.observer_key,
                                   observer_id=records.observer_id)
        early = effect is not None and None not in (pr.instant_key(effect["performedAt"]),
                                                   pr.instant_key(view["decidedAt"])) and \
            pr.instant_key(effect["performedAt"]) < pr.instant_key(view["decidedAt"])
        notes = []
        if effect is not None and outcome is None:
            notes.append("the records match an effect to this decision, and no outcome is bound to it")
        if outcome is not None and (effect is None or outcome["scope"] != profile.scope_descriptor(
                effect["surface"], effect["target"], effect["objectId"])):
            notes.append("an outcome is bound to this decision that shows no effect the records match to it")
        rows.append({"file": entry["file"], "decisionId": view["decisionId"], "action": view["action"],
                     "receipt": "verifies", "verdict": view["verdict"], "surface": view["surface"],
                     "target": view["target"], "decidedAt": view["decidedAt"], **m,
                     "class": _class(view["verdict"], m, early) if not notes else "outcome and records disagree",
                     "notes": notes, "profile": answer["verdict"], "profile_reasons": answer["reasons"],
                     "effect": {k: effect[k] for k in ("event", "type", "surface", "target", "objectId", "performedAt",
                                                       "observedAt", "response")} if effect else None,
                     "outcome": outcome["file"] if outcome else None})
    unmatched = [{k: r["effect"][k] for k in ("event", "type", "surface", "target", "performedAt", "response")}
                 for r in matched["rows"] if r["decision"] is None]
    inputs = {name: entry["sha256"] for name, entry in sorted(records.files.items())}
    for folder in ("decisions", "outcomes", "api", pr.KEY_JOURNAL_FOLDER):
        for path in sorted((records.folder / folder).rglob("*")):
            if path.is_file() or path.is_symlink():
                name = path.relative_to(records.folder).as_posix()
                inputs[name] = pr.sha256_hex(pr.file_in(records.folder, name).read_bytes())
    return {"contract": "docs/pilot/pilot_contract.md as kept", "profile": "github-write/1 as kept",
            "verification": "each decision at one second before its decidedAt, each outcome as the kept profile "
                            "verifies it (strict, the derived subject, the observer as audience, the decision's nonce)",
            "window": window, "runs": [r["run"] for r in runs], "inputs": inputs, "unverified_receipts": unverified,
            "M5": matched["M5"], "M6": matched["M6"], "unapproved_effects": unmatched, "decisions": rows,
            "window_notes": [LEVEL1_UNDER_AUTONOMY], "keyJournal": key_journal_check(records, entries)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--records", required=True, type=pathlib.Path)
    parser.add_argument("--name", default="reconciliation")
    args = parser.parse_args(argv)
    try:
        # the name becomes a file name under reconciliation/: without / and .., no write lands outside that folder
        if not _NAME.fullmatch(args.name):
            raise ValueError("a name holds letters, digits, - and _ only, a letter or a digit first")
        result = reconcile(pr.Records(args.records))
        pr.write_json(args.records / "reconciliation" / f"{args.name}.json", result)
    except (pr.RecordsError, OSError, ValueError) as exc:
        print(f"reconcile: {exc}", file=sys.stderr)
        return 1
    for row in result["decisions"]:
        print(f"{row.get('decisionId', row['file'])}: {row['class']} (profile: {row['profile']})")
    print(f"M5 {result['M5']}, M6 {result['M6']}")
    for note in result["window_notes"]:
        print(f"note: {note}")
    journal = result["keyJournal"]
    if not journal["read"]:
        print(f"key journal: not read, {journal['why']}")
        return KEY_JOURNAL_NOT_READ
    print(f"key journal: {journal['signedWithoutReceipt']} signed lines without receipt, "
          f"{journal['receiptsWithoutSignedLine']} receipts without signed line")
    if journal["signedWithoutReceipt"] or journal["receiptsWithoutSignedLine"]:
        return KEY_JOURNAL_DISAGREES
    return 0


if __name__ == "__main__":
    sys.exit(main())
