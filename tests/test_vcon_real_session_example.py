"""The recorded-session example under examples/vcon_ai_agent_receipts/real_session/ (part 2 of the vCon example).

A real Claude Code session behind the proofbundle guard, the two decision receipts the guard signed in it, and the vCon
make_real_session.py builds from both. The tests hold that the committed out/ is what the producer writes, that the
check passes on it, and that each of its checks fails on the one change it is about, so a passing check is not one
that cannot fail. The last test holds the observation the example exists for: the note the guard gave the agent for
the escalated call begins with NOT MEASURED, while the receipt it signed says ESCALATE.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
FOLDER = REPO / "examples" / "vcon_ai_agent_receipts" / "real_session"
#: The CLI of this tree, not whatever proofbundle the interpreter has installed: an older install does not know
#: --verification-time and exits 2, which would fail every check at K1 for a reason that is not the record.
CLI = "%s -m proofbundle.cli" % sys.executable
TREE_PATH = {"PYTHONPATH": os.pathsep.join(p for p in (str(REPO / "src"), os.environ.get("PYTHONPATH", "")) if p)}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TheRecordedSessionExample(unittest.TestCase):

    def setUp(self):
        if not (FOLDER / "check_real_session.py").is_file():
            self.skipTest("examples/vcon_ai_agent_receipts/real_session is not in this tree")
        if " " in sys.executable:
            self.skipTest("the check splits its CLI command at spaces")
        self.mk = _load("make_real_session_under_test", FOLDER / "make_real_session.py")
        self.ck = _load("check_real_session_under_test", FOLDER / "check_real_session.py")
        self.vcon = json.loads((FOLDER / "out" / "vcon.unsigned.json").read_text(encoding="utf-8"))
        self.lines = (FOLDER / "session.jsonl").read_text(encoding="utf-8").splitlines()

    def _run(self, v):
        rep = self.ck.Report()
        with mock.patch.dict(os.environ, TREE_PATH):
            try:
                self.ck.check(v, self.lines, CLI, rep)
            except self.ck.Stop:
                pass
        return rep

    def _op(self, verdict):
        rec = [a["body"] for a in self.vcon["attachments"] if a.get("purpose") == "decision receipt"]
        for env in rec:
            p = json.loads(base64.b64decode(env["payload"]))["predicate"]
            if p["decision"]["verdict"] == verdict:
                return self.mk.conv.operation_id(self.vcon["sessions"][0]["agent_session_id"],
                                                 p["traceContext"]["parentId"])
        raise KeyError(verdict)

    def _event(self, v, op, typ):
        return next(e for e in v["events"] if e.get("operation_id") == op and e["type"] == typ)

    def test_out_is_what_the_producer_writes(self):
        for rel, data in self.mk.files().items():
            with self.subTest(rel=rel):
                self.assertEqual((FOLDER / "out" / rel).read_bytes(), data)

    def test_the_committed_check_report_is_what_the_check_writes(self):
        """out/check-report.json is the verification output of both receipts as the README names it; it must be what
        the check writes on out/ today, not an older run."""
        import tempfile
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, TREE_PATH):
            rep = pathlib.Path(td) / "check-report.json"
            rc = self.ck.main([str(FOLDER / "out"), "--proofbundle", CLI, "--report", str(rep)])
            self.assertEqual(rc, 0)
            self.assertEqual(rep.read_bytes(), (FOLDER / "out" / "check-report.json").read_bytes())

    def test_the_example_passes(self):
        rep = self._run(self.vcon)
        self.assertIsNone(rep.first, rep.first)
        self.assertEqual(sorted(o["verdict"] for o in rep.observations), ["DENY", "ESCALATE"])

    def test_the_note_to_the_agent_is_not_the_verdict_it_signed(self):
        """GF-E001: the guard signed ESCALATE, and its note to the agent for the same call begins with NOT MEASURED."""
        rep = self._run(self.vcon)
        esc = [o for o in rep.observations if o["verdict"] == "ESCALATE"]
        self.assertEqual(len(esc), 1)
        self.assertTrue(esc[0]["note_to_agent_begins"].startswith("NOT MEASURED"), esc[0])

    def _fails_at(self, change, cid):
        v = copy.deepcopy(self.vcon)
        change(v)
        rep = self._run(v)
        self.assertIsNotNone(rep.first, "the change passed the check")
        self.assertEqual(rep.first["id"], cid, rep.first)

    def test_k1_a_changed_signature_fails(self):
        """Exit 1 is the verifier refusing the signature; exit 2 would be a CLI that could not read its input or its
        arguments, which is a failure of the setup and not of the receipt."""
        def change(v):
            env = v["attachments"][0]["body"]
            sig = base64.b64decode(env["signatures"][0]["sig"])
            env["signatures"][0]["sig"] = base64.b64encode(bytes([sig[0] ^ 1]) + sig[1:]).decode()
        v = copy.deepcopy(self.vcon)
        change(v)
        rep = self._run(v)
        self.assertIsNotNone(rep.first, "the changed signature passed the check")
        self.assertEqual(rep.first["id"], "K1", rep.first)
        self.assertIn("exit 1", rep.first["detail"], rep.first)

    def test_k2_another_session_fails(self):
        def change(v):
            v["sessions"][0]["agent_session_id"] = "00000000-0000-4000-8000-000000000000"
        self._fails_at(change, "K2")

    def _receipt_in_place_of_the_other(self, keep):
        def change(v):
            rec = [a for a in v["attachments"] if a.get("purpose") == "decision receipt"]
            src = next(a for a in rec if self._verdict(a) == keep)
            dst = next(a for a in rec if self._verdict(a) != keep)
            dst["body"] = copy.deepcopy(src["body"])
        return change

    @staticmethod
    def _verdict(att):
        return json.loads(base64.b64decode(att["body"]["payload"]))["predicate"]["decision"]["verdict"]

    def test_k2_the_escalate_receipt_twice_fails(self):
        """Two receipts that both verify, but both name the escalated call: the denied call is checked by none."""
        self._fails_at(self._receipt_in_place_of_the_other("ESCALATE"), "K2")

    def test_k2_the_deny_receipt_twice_fails(self):
        self._fails_at(self._receipt_in_place_of_the_other("DENY"), "K2")

    def test_k2_a_policy_decision_no_receipt_names_fails(self):
        def change(v):
            pd = copy.deepcopy(self._event(v, self._op("DENY"), "policy-decision"))
            pd["operation_id"] = "00000000-0000-8000-8000-000000000000"
            v["events"].append(pd)
        self._fails_at(change, "K2")

    def test_k2_a_tool_operation_no_receipt_names_fails(self):
        """A recorded call with no policy-decision and no receipt: its operation is named by none."""
        def change(v):
            call = copy.deepcopy(self._event(v, self._op("ESCALATE"), "tool-invocation"))
            call["operation_id"] = "00000000-0000-8000-8000-000000000001"
            call["body"] = {"command": "echo unreceipted"}
            v["events"].append(call)
        self._fails_at(change, "K2")

    def test_k4_a_tool_progress_event_of_the_denied_operation_fails(self):
        def change(v):
            pd = self._event(v, self._op("DENY"), "policy-decision")
            v["events"].append({"type": "tool-progress", "time": pd["time"], "sessions": 0, "party": pd["party"],
                                "operation_id": pd["operation_id"], "attempt": 1})
        self._fails_at(change, "K4")

    def test_the_tool_event_types_are_those_of_part_1(self):
        """The check keeps to the standard library, so it does not import ../check_example.py; its inventory of tool
        event types must still be the same set."""
        part1 = _load("check_example_under_test", FOLDER.parent / "check_example.py")
        self.assertEqual(self.ck.TOOL_TYPES, part1.TOOL_TYPES)

    @staticmethod
    def _blocks(e, typ):
        content = (e.get("message") or {}).get("content")
        return [b for b in content if isinstance(b, dict) and b.get("type") == typ] if isinstance(content, list) else []

    def _producer_refuses(self, has, change):
        """Append a changed copy of the first transcript line for which has(line) holds; the producer must refuse it and
        name the call it does not know."""
        import tempfile
        e = copy.deepcopy(next(json.loads(raw) for raw in self.lines if has(json.loads(raw))))
        change(e)
        with tempfile.TemporaryDirectory() as td:
            session = pathlib.Path(td) / "session.jsonl"
            session.write_text("\n".join(self.lines + [json.dumps(e, ensure_ascii=False)]) + "\n", encoding="utf-8")
            with mock.patch.object(self.mk, "SESSION", session):
                with self.assertRaises(ValueError) as cm:
                    self.mk.build()
        self.assertIn("toolu_unreceipted", str(cm.exception))

    def test_the_producer_refuses_a_call_no_receipt_names(self):
        """Every call of the transcript is named by one receipt, not only every receipt by one call."""
        def change(e):
            for b in self._blocks(e, "tool_use"):
                b["id"] = "toolu_unreceipted"
                b["input"] = {"command": "echo unreceipted"}
        self._producer_refuses(lambda e: self._blocks(e, "tool_use"), change)

    def test_the_producer_refuses_a_result_no_receipt_names(self):
        """A result line of a call no receipt names; the converter would drop it as a result without its call."""
        def change(e):
            for b in self._blocks(e, "tool_result"):
                b["tool_use_id"] = "toolu_unreceipted"
        self._producer_refuses(lambda e: self._blocks(e, "tool_result"), change)

    def test_the_producer_refuses_a_hook_message_for_a_call_no_receipt_names(self):
        def change(e):
            e["attachment"]["toolUseID"] = "toolu_unreceipted"
        self._producer_refuses(lambda e: isinstance((e.get("attachment") or {}).get("toolUseID"), str), change)

    def test_k2_a_note_for_an_operation_no_receipt_names_fails(self):
        """A system-event of the guard that names an operation no receipt names."""
        def change(v):
            note = copy.deepcopy(next(e for e in v["events"] if e.get("type") == "system-event"))
            note["data"]["operation_id"] = "00000000-0000-8000-8000-000000000002"
            v["events"].append(note)
        self._fails_at(change, "K2")

    def test_k3_a_verdict_other_than_escalate_or_deny_fails(self):
        """A receipt with another verdict that verifies needs the demonstration private key, which is not in the
        repository. The check is handed such a predicate after K1, and the decision of the policy-decision is null, so
        a lookup that returns nothing for the verdict would match it."""
        real = self.ck.verify

        def verify(rep, where, env, pub, cmd):
            p = real(rep, where, env, pub, cmd)
            if p["decision"]["verdict"] == "DENY":
                p = copy.deepcopy(p)
                p["decision"]["verdict"] = "ALLOW"
            return p
        v = copy.deepcopy(self.vcon)
        self._event(v, self._op("DENY"), "policy-decision")["decision"] = None
        with mock.patch.object(self.ck, "verify", verify):
            rep = self._run(v)
        self.assertIsNotNone(rep.first, "a verdict other than ESCALATE or DENY passed the check")
        self.assertEqual(rep.first["id"], "K3", rep.first)

    def test_k3_an_escalated_call_recorded_as_allowed_fails(self):
        def change(v):
            self._event(v, self._op("ESCALATE"), "policy-decision")["decision"] = "allowed"
        self._fails_at(change, "K3")

    def test_k4_another_comment_body_fails(self):
        def change(v):
            call = self._event(v, self._op("ESCALATE"), "tool-invocation")
            call["body"]["command"] = call["body"]["command"].replace("Case 1", "Case 9")
        self._fails_at(change, "K4")

    def test_k4_a_tool_event_after_the_deny_fails(self):
        def change(v):
            op = self._op("DENY")
            pd = self._event(v, op, "policy-decision")
            v["events"].append({"type": "tool-invocation", "time": pd["time"], "sessions": 0, "party": pd["party"],
                                "operation_id": op, "attempt": 1, "server": "!host", "tool": "Bash",
                                "mediatype": "application/json", "encoding": "json", "body": {"command": "true"}})
        self._fails_at(change, "K4")

    def test_k4_the_denied_arguments_as_a_json_value_fail(self):
        denied = next(b["input"] for raw in self.lines for b in (json.loads(raw).get("message") or {}).get("content") or []
                      if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("input", {}).get("command", "")
                      .startswith("git push"))

        def change(v):
            v["events"][-1].setdefault("data", {})["copy"] = dict(denied)
        self._fails_at(change, "K4")


if __name__ == "__main__":
    unittest.main()
