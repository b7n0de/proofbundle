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
