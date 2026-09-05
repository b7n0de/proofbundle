#!/usr/bin/env python3
"""Adapter: the frozen Cedulon fixture `leaked-refusal` read as a proofbundle receipt pair.

WHAT THIS IS
------------
`draft-dogru-cedulon-decision-profile-02` names D1, "an effect occurs against a refusal", as the
threat its profile exists for (section 8.1, lines 980-1001 of the -02 text). Its companion froze one
fixture for that case, `interop/mizan-ig/fixtures/leaked-refusal`, and two separately owned readers
have run it (companion `docs/EXTERNAL_REVIEW.md` "Round 10 — one fixture, two readers, 5 Sep 2026").
This script is a THIRD reader of the same frozen bytes: it translates them into our own two
predicates, `decision-receipt/v0.1` and `action-outcome/v0.1`, signs them with throwaway TEST keys
and hands the pair to our own verifier.

It measures our artefact, not theirs. Nothing here is a statement about the profile, about the
companion, or about the other readers.

FIELD MAPPING, AND WHERE EACH CELL COMES FROM
---------------------------------------------
Every mapping below is a cell of Mapping 4 Revision 3 in `docs/SCITT_CPB_MAPPING.md` at commit
`df546b0d14329afce7715525fda9dcd3a4bde5a6`; the line number of the cell is quoted at each field in
`FIELD_MAP` and repeated in the report this script writes. Where that table says NO COUNTERPART, the
adapter does NOT invent a value: it records the cell as NICHT MESSBAR in its report and leaves our
predicate without it. That is the whole point of using the table as the source: a mapping is only as
honest as its gaps.

THE ONE READING THIS ADAPTER ADDS
---------------------------------
The fixture is a channel log in the companion's example line format, not a Cedulon Decision Record.
Its decision line carries `"verdict":"silent"`, a word of that channel's own vocabulary. Reading it
as a refusal is a step this adapter takes, and it takes it on evidence rather than on taste: the
companion's own reader reports `effect-against-refusal` on exactly this row (`EXTERNAL_REVIEW.md`
Round 10, "Cedulon reader (this tree, `runFixture`): findings `[effect-against-refusal leak-1]`"),
and the fixture's directory name says the same. The step is recorded in the report as an assumption
of the adapter, at `ASSUMPTIONS` below.

TEST KEYS
---------
Two Ed25519 keys are generated at run time, one for the decision maker and one for the executor, so
that role separation is a real check and not a self-signature. They are written next to the output
with the suffix `.TESTKEY` and a header naming them as throwaway material. NEVER point this script
at a real signing key: it has no option to load one, by design.

USAGE
-----
    python3 scripts/interop/cedulon_leaked_refusal_adapter.py \
        --fixture-dir <dir with decisions.jsonl, policy.txt, sent.jsonl> \
        --out-dir <dir for the receipts, keys and report> [--verify] [--json]

Exit codes: 0 the adapter ran and wrote its artefacts · 2 the fixture bytes are not the pinned ones,
or the fixture shape is not the one this adapter reads (fail closed, nothing written).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any

_REPO = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO / "src") not in sys.path:
    sys.path.insert(0, str(_REPO / "src"))

from proofbundle import canonical  # noqa: E402
from proofbundle.decision import emit_decision_receipt  # noqa: E402
from proofbundle.emit import generate_signer  # noqa: E402
from proofbundle.outcome import emit_outcome_receipt  # noqa: E402

# --------------------------------------------------------------------------------------------
# The pinned fixture. Bytes measured by API on 2026-09-05 at commit 06c3119 of
# dogrucanemek-alt/cedulon; the same three digests stand in the companion's EXTERNAL_REVIEW.md
# Round 10 at e26f50f. A fixture that does not match these digests is not the frozen one, and this
# adapter refuses it rather than measuring something else under the same name.
# --------------------------------------------------------------------------------------------
FIXTURE_COMMIT = "06c3119badc269ef5d6d3596ea3b3d48219d6ba4"
FIXTURE_PATH = "interop/mizan-ig/fixtures/leaked-refusal"
PINNED_SHA256 = {
    "decisions.jsonl": "2db5f0a8491aa34031223d9d4e732620a1df86bb37747972fa86e9095dd48d72",
    "policy.txt": "41d79f176661c3ac24181dae71506e8d5738f0470102d9cdda1dd9222cfe0805",
    "sent.jsonl": "cfd9037ef183c04364d2c32951b108be2740d4b75bdd2f9cb83dc1ac7fd5d131",
}

MAPPING_COMMIT = "df546b0d14329afce7715525fda9dcd3a4bde5a6"
MAPPING_FILE = "docs/SCITT_CPB_MAPPING.md"

ASSUMPTIONS = [
    {
        "id": "A-verdict",
        "assumption": "the fixture's channel word 'silent' is a refusal",
        "why": (
            "the companion's own reader reports effect-against-refusal on this row "
            "(EXTERNAL_REVIEW.md Round 10 at e26f50f, lines 634-637) and the fixture is named "
            "leaked-refusal; the fixture is a channel log, not a Decision Record, so the step from "
            "'silent' to the draft's 'deny' (section 4.1) is the adapter's, not the fixture's"
        ),
        "our_field": "decision.verdict = DENY",
        "mapping_cell": f"{MAPPING_FILE}:418 (claim -70506 against decision.verdict)",
    },
    {
        "id": "A-request-bytes",
        "assumption": "the hashed request is the UTF-8 octets of the decision line's 'text' field",
        "why": (
            "-02 section 4.1 (lines 398-402) fixes the ENCODING and leaves the fields open, and "
            "requires a deployment to state what it hashes; this adapter states it here"
        ),
        "our_field": "proposedAction.parametersDigest.sha256",
        "mapping_cell": f"{MAPPING_FILE}:415 (claim -70503 against parametersDigest)",
    },
    {
        "id": "A-effect-bytes",
        "assumption": "the hashed effect is the UTF-8 octets of the sent line's 'text' field",
        "why": (
            "Table 3b calls effectHash and effectDigest the same in meaning and says neither format "
            "fixes the hashed octets, so the adapter must state them"
        ),
        "our_field": "effectDigest.sha256",
        "mapping_cell": f"{MAPPING_FILE}:436 (row effectHash against effectDigest)",
    },
]

# Cells of Mapping 4 Rev 3 that say NO COUNTERPART. The adapter reports them and maps nothing.
NICHT_MESSBAR = [
    {"claim": "effectHash (-70509) on the decision side", "cell": f"{MAPPING_FILE}:421,",
     "reason": "the decision-receipt carries no commitment to the content of the effect"},
    {"claim": "prevRecordHash (-70512), the Decider's chain", "cell": f"{MAPPING_FILE}:424,",
     "reason": "no per-decider chain on our side"},
    {"claim": "effectClass (-70513)", "cell": f"{MAPPING_FILE}:425,",
     "reason": "proposedAction.actionType classes the proposed action, not the effect on a channel"},
    {"claim": "epoch checkpoint totals per decision kind (section 4.4)", "cell": f"{MAPPING_FILE}:426,",
     "reason": "no population object on our side"},
    {"claim": "extract body: deciderId, channelId, windowStartMs, windowEndMs",
     "cell": f"{MAPPING_FILE}:434,", "reason": "no population object, no window; our receipts carry "
                                               "their population in predicate type and subject"},
    {"claim": "row effectClass", "cell": f"{MAPPING_FILE}:437,",
     "reason": "no class name on the outcome and no comparison"},
    {"claim": "row actor (optional)", "cell": f"{MAPPING_FILE}:439,",
     "reason": "no actor in this fixture's sent line; its 'to' is the recipient, not the actor, and "
               "receiverRefs[] needs a digest-bound entry this fixture does not carry"},
]


class FixtureError(Exception):
    """The fixture is not the pinned one, or not the shape this adapter reads. Fail closed."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rfc3339_from_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_fixture(fixture_dir: pathlib.Path) -> dict[str, Any]:
    """Read the three fixture files and refuse anything that is not the pinned bytes."""
    files: dict[str, bytes] = {}
    for name in PINNED_SHA256:
        p = fixture_dir / name
        if not p.is_file():
            raise FixtureError(f"fixture file missing: {p}")
        files[name] = p.read_bytes()

    digests = {name: _sha256_hex(raw) for name, raw in files.items()}
    drift = {n: (digests[n], PINNED_SHA256[n]) for n in PINNED_SHA256 if digests[n] != PINNED_SHA256[n]}
    if drift:
        lines = [f"  {n}: measured {got}, pinned {want}" for n, (got, want) in sorted(drift.items())]
        raise FixtureError(
            "these are not the pinned fixture bytes at "
            f"{FIXTURE_COMMIT[:7]}:\n" + "\n".join(lines)
        )

    dec_lines = [json.loads(x) for x in files["decisions.jsonl"].decode("utf-8").splitlines() if x.strip()]
    sent_lines = [json.loads(x) for x in files["sent.jsonl"].decode("utf-8").splitlines() if x.strip()]
    if len(dec_lines) != 1 or len(sent_lines) != 1:
        raise FixtureError(
            f"this adapter reads one decision line and one sent line; found "
            f"{len(dec_lines)} and {len(sent_lines)}"
        )
    dec, sent = dec_lines[0], sent_lines[0]
    for field, obj, where in (("id", dec, "decision line"), ("verdict", dec, "decision line"),
                              ("receivedAt", dec, "decision line"), ("text", dec, "decision line"),
                              ("id", sent, "sent line"), ("sentAt", sent, "sent line"),
                              ("text", sent, "sent line")):
        if field not in obj:
            raise FixtureError(f"{where} has no '{field}' field; the fixture shape changed")
    if dec["id"] != sent["id"]:
        raise FixtureError(
            f"decision ref {dec['id']!r} and sent ref {sent['id']!r} differ; this adapter reads the "
            "one-ref case of the frozen fixture"
        )
    if str(dec["verdict"]).lower() not in {"silent", "deny", "refuse", "defer"}:
        raise FixtureError(
            f"decision verdict {dec['verdict']!r} is not a refusal in this fixture's vocabulary; "
            "see assumption A-verdict — the adapter refuses to guess"
        )
    return {
        "files": files,
        "digests": digests,
        "decision_line": dec,
        "sent_line": sent,
        "policy_text": files["policy.txt"].decode("utf-8").strip(),
    }


def build_decision_predicate(fx: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """decisions.jsonl -> decision-receipt/v0.1. Returns the predicate and the mapping rows."""
    dec = fx["decision_line"]
    ref = str(dec["id"])
    request_bytes = str(dec["text"]).encode("utf-8")
    rows = [
        {"draft": "decider (-70501)", "fixture": "the companion's example channel bridge",
         "ours": "decisionMaker.id", "cell": f"{MAPPING_FILE}:413", "meaning": "same"},
        {"draft": "subject (-70502)", "fixture": f"from = {dec.get('from')!r}",
         "ours": "principal.id", "cell": f"{MAPPING_FILE}:414", "meaning": "similar"},
        {"draft": "requestHash (-70503)", "fixture": "sha256 of the UTF-8 octets of text",
         "ours": "proposedAction.parametersDigest.sha256", "cell": f"{MAPPING_FILE}:415,",
         "meaning": "similar; the hashed fields are open on both, so the adapter states them"},
        {"draft": "policyHash (-70504)", "fixture": "sha256 of policy.txt",
         "ours": "policyBoundary.policyDigest.sha256", "cell": f"{MAPPING_FILE}:416", "meaning": "same"},
        {"draft": "inputsHash (-70505)", "fixture": "sha256 of the raw decision line",
         "ours": "inputSnapshot[0].digest.sha256", "cell": f"{MAPPING_FILE}:417", "meaning": "similar"},
        {"draft": "decision (-70506)", "fixture": f"verdict = {dec['verdict']!r}",
         "ours": "decision.verdict = DENY", "cell": f"{MAPPING_FILE}:418",
         "meaning": "similar; see assumption A-verdict"},
        {"draft": "reasonCode (-70507)", "fixture": f"reason = {dec.get('reason')!r}",
         "ours": "decision.reasonCodes[]", "cell": f"{MAPPING_FILE}:419", "meaning": "same, a list instead of one"},
        {"draft": "ref (-70508)", "fixture": f"id = {ref!r}",
         "ours": "proposedAction.target.name / .uri", "cell": f"{MAPPING_FILE}:420",
         "meaning": "different; ours names what is acted on, not the channel reference an effect carries"},
        {"draft": "timestampMs (-70510)", "fixture": f"receivedAt = {dec['receivedAt']}",
         "ours": "decidedAt", "cell": f"{MAPPING_FILE}:422", "meaning": "same"},
        {"draft": "nonce (-70511)", "fixture": f"id = {ref!r}",
         "ours": "decisionId", "cell": f"{MAPPING_FILE}:423", "meaning": "similar"},
    ]
    pred = {
        "schemaVersion": "0.1.0",
        "decisionId": f"urn:cedulon-fixture:{FIXTURE_COMMIT[:7]}:decision:{ref}",
        "decisionType": "preActionAuthorization",
        "decidedAt": _rfc3339_from_ms(int(dec["receivedAt"])),
        "decisionMaker": {
            "id": "https://example.org/cedulon-fixture/decider/mizan-ig",
            "version": {"proofbundle": "adapter"},
        },
        "agent": {"id": "agent://cedulon-fixture/mizan-ig-bridge", "version": "0"},
        "principal": {"id": f"workload://cedulon-fixture/{dec.get('from', 'unknown')}"},
        "proposedAction": {
            "actionType": "channel.send",
            "target": {
                "name": f"cedulon-fixture:ref:{ref}",
                "uri": f"urn:cedulon-fixture:ref:{ref}",
            },
            "method": "POST",
            "parametersDigest": {"sha256": _sha256_hex(request_bytes)},
        },
        "inputSnapshot": [{
            "name": "decisions.jsonl",
            "uri": f"urn:cedulon-fixture:{FIXTURE_COMMIT[:7]}:decisions.jsonl",
            "digest": {"sha256": fx["digests"]["decisions.jsonl"]},
            "mediaType": "application/jsonl",
        }],
        "policyBoundary": {
            "policyEngine": "other",
            "policyId": f"urn:cedulon-fixture:policy:{fx['policy_text']}",
            "policyDigest": {"sha256": fx["digests"]["policy.txt"]},
            "decisionPath": "fixture.verdict",
        },
        "evidenceRefs": [],
        "decision": {
            "verdict": "DENY",
            "reasonCodes": [str(dec.get("reason", "unspecified"))],
            "humanReadableSummary": (
                "Adapter reading of a frozen third-party fixture: the channel decided "
                f"{dec['verdict']!r} on reference {ref}."
            ),
            "obligations": [],
            "allowedScope": [],
        },
        "notChecked": [{
            "field": "effectClass, effectHash, prevRecordHash, epoch totals",
            "reason": "NO COUNTERPART in decision-receipt/v0.1 (Mapping 4 Rev 3, Table 3a)",
            "impact": "the class, the committed effect content and the decider chain are outside this receipt",
        }],
        "decisionChangeConditions": [{
            "conditionType": "additionalApproval",
            "description": "not modelled by the fixture",
            "requiredEvidenceType": "approvalReceipt",
        }],
        "privacy": {
            "rawInputsIncluded": False,
            "redactionProfile": "urn:cedulon-fixture:no-redaction",
            "erased": [],
            "masked": [],
        },
    }
    return pred, rows


def build_outcome_predicate(fx: dict[str, Any], decision_root_hex: str,
                            executor_key_id: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """sent.jsonl -> action-outcome/v0.1 with execution_proven. Returns predicate and mapping rows."""
    sent = fx["sent_line"]
    ref = str(sent["id"])
    effect_bytes = str(sent["text"]).encode("utf-8")
    request_bytes = str(fx["decision_line"]["text"]).encode("utf-8")
    rows = [
        {"draft": "row ref, the match key", "fixture": f"id = {ref!r}",
         "ours": "decisionRef.sha256 (content root of the decision statement)",
         "cell": f"{MAPPING_FILE}:435",
         "meaning": "similar; theirs binds by channel reference, ours by content root, so the "
                    "fixture's ref does not travel in this field"},
        {"draft": "row effectHash", "fixture": "sha256 of the UTF-8 octets of the sent text",
         "ours": "effectDigest.sha256", "cell": f"{MAPPING_FILE}:436",
         "meaning": "same in meaning; the hashed octets are stated by the adapter"},
        {"draft": "row timestampMs", "fixture": f"sentAt = {sent['sentAt']}",
         "ours": "performedAt", "cell": f"{MAPPING_FILE}:438", "meaning": "same"},
        {"draft": "extract signed by the effect-extract root (MUST-DP-9)",
         "fixture": "no signature in the fixture; the adapter signs with a TEST key",
         "ours": "DSSE signature by the executor, role separation against the decision maker",
         "cell": f"{MAPPING_FILE}:440",
         "meaning": "similar; ours checks two identities differ when told both, theirs asks the "
                    "deployment to state its root and downgrades where they may coincide"},
        {"draft": "binding of an allow to a row with equal effectHash (section 6.1)",
         "fixture": "the row exists under a refused reference — that is D1",
         "ours": "execution_proven", "cell": f"{MAPPING_FILE}:441",
         "meaning": "similar; ours is digest presence on the executor's own record"},
    ]
    pred = {
        "schemaVersion": "0.1.0",
        "outcomeId": f"urn:cedulon-fixture:{FIXTURE_COMMIT[:7]}:outcome:{ref}",
        "decisionRef": {"sha256": decision_root_hex},
        "executor": {"id": "executor://cedulon-fixture/mizan-ig-sender", "keyId": executor_key_id},
        "requestedActionDigest": {"sha256": _sha256_hex(request_bytes)},
        "effectDigest": {"sha256": _sha256_hex(effect_bytes)},
        "status": "executed",
        "performedAt": _rfc3339_from_ms(int(sent["sentAt"])),
        "policyPurpose": "outcome",
        "limitations": [
            "adapter output over a frozen third-party fixture; the fixture carries no signature, "
            "no key and no channel identity, so identity and time are the adapter's, not the "
            "fixture's",
        ],
    }
    return pred, rows


def run(fixture_dir: pathlib.Path, out_dir: pathlib.Path) -> dict[str, Any]:
    fx = read_fixture(fixture_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Two throwaway TEST keys: a self-signed pair would make role separation meaningless.
    dm_signer = generate_signer()
    ex_signer = generate_signer()
    dm_pub = dm_signer.public_key().public_bytes_raw()
    ex_pub = ex_signer.public_key().public_bytes_raw()
    import base64
    for name, signer in (("decision_maker", dm_signer), ("executor", ex_signer)):
        p = out_dir / f"{name}.TESTKEY"
        p.write_bytes(signer.private_bytes_raw())
        (out_dir / f"{name}.TESTKEY.README").write_text(
            "THROWAWAY TEST KEY, generated by scripts/interop/cedulon_leaked_refusal_adapter.py.\n"
            "It signs adapter output over a public fixture and attests nothing. Do not reuse it.\n",
            encoding="utf-8",
        )

    dec_pred, dec_rows = build_decision_predicate(fx)
    dec_env = emit_decision_receipt(dec_pred, dm_signer, strict=True)
    dec_payload = base64.b64decode(dec_env["payload"])
    decision_root = canonical.statement_content_root(dec_payload).hex()

    out_pred, out_rows = build_outcome_predicate(fx, decision_root, base64.b64encode(ex_pub).decode())
    out_env = emit_outcome_receipt(out_pred, ex_signer, strict=True)

    (out_dir / "decision_receipt.intoto.json").write_text(
        json.dumps(dec_env, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "action_outcome.intoto.json").write_text(
        json.dumps(out_env, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "decision_maker.pub").write_text(base64.b64encode(dm_pub).decode() + "\n", encoding="utf-8")
    (out_dir / "executor.pub").write_text(base64.b64encode(ex_pub).decode() + "\n", encoding="utf-8")

    return {
        "fixture": {
            "repo": "dogrucanemek-alt/cedulon",
            "path": FIXTURE_PATH,
            "commit": FIXTURE_COMMIT,
            "files": {n: {"bytes": len(fx["files"][n]), "sha256": fx["digests"][n]}
                      for n in sorted(PINNED_SHA256)},
            "pinned_digests_match": True,
        },
        "mapping_source": {"file": MAPPING_FILE, "commit": MAPPING_COMMIT,
                           "tables": ["3a lines 411-428", "3b lines 432-441", "3c lines 445-453"]},
        "assumptions": ASSUMPTIONS,
        "nicht_messbar": NICHT_MESSBAR,
        "decision_mapping": dec_rows,
        "outcome_mapping": out_rows,
        "artefacts": {
            "decision_receipt": str(out_dir / "decision_receipt.intoto.json"),
            "action_outcome": str(out_dir / "action_outcome.intoto.json"),
            "decision_content_root": decision_root,
            "decision_maker_pub_b64": base64.b64encode(dm_pub).decode(),
            "executor_pub_b64": base64.b64encode(ex_pub).decode(),
            "decision_maker_id": dec_pred["decisionMaker"]["id"],
        },
    }


def verify_pair(report: dict[str, Any]) -> dict[str, Any]:
    """Hand the pair to our own verifier, with the decision binding and role separation pinned."""
    import base64

    from proofbundle.decision import verify_decision_receipt
    from proofbundle.outcome import verify_outcome_receipt

    art = report["artefacts"]
    dec_env = json.loads(pathlib.Path(art["decision_receipt"]).read_text(encoding="utf-8"))
    out_env = json.loads(pathlib.Path(art["action_outcome"]).read_text(encoding="utf-8"))
    dec_res = verify_decision_receipt(dec_env, base64.b64decode(art["decision_maker_pub_b64"]), strict=True)
    out_res = verify_outcome_receipt(
        out_env, base64.b64decode(art["executor_pub_b64"]), strict=True,
        expected_decision_ref=art["decision_content_root"],
        decision_maker_id=art["decision_maker_id"],
    )
    return {"decision": dec_res, "outcome": out_res}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fixture-dir", required=True, type=pathlib.Path,
                    help="directory holding decisions.jsonl, policy.txt, sent.jsonl")
    ap.add_argument("--out-dir", required=True, type=pathlib.Path,
                    help="directory for receipts, TEST keys and the report")
    ap.add_argument("--verify", action="store_true", help="run our verifier over the pair")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args(argv)

    try:
        report = run(args.fixture_dir, args.out_dir)
    except FixtureError as exc:
        print(f"FIXTURE REFUSED: {exc}", file=sys.stderr)
        return 2

    if args.verify:
        report["verification"] = verify_pair(report)

    (args.out_dir / "adapter_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        print(f"fixture {FIXTURE_COMMIT[:7]} pinned digests match: "
              f"{report['fixture']['pinned_digests_match']}")
        print(f"decision content root: {report['artefacts']['decision_content_root']}")
        print(f"NICHT MESSBAR cells (NO COUNTERPART in Mapping 4 Rev 3): {len(report['nicht_messbar'])}")
        for cell in report["nicht_messbar"]:
            print(f"  NICHT MESSBAR  {cell['claim']}  [{cell['cell']} {cell['reason']}]")
        if "verification" in report:
            v = report["verification"]
            print(f"decision verify: ok={v['decision'].get('ok')}")
            print(f"outcome  verify: ok={v['outcome'].get('ok')} "
                  f"decision_bound={v['outcome'].get('decision_bound')} "
                  f"role_separation_ok={v['outcome'].get('role_separation_ok')} "
                  f"execution_proven={v['outcome'].get('execution_proven')}")
            print("the verdict of the bound decision is DENY; the outcome path does not read it")
        print(f"report: {args.out_dir / 'adapter_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
