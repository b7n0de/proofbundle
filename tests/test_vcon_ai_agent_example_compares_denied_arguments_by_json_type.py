"""The vCon example converter compares the arguments of a disallowed operation by JSON type (PR 476, Codex P2 at
1e32dd75).

`examples/vcon_ai_agent_receipts/claude_jsonl_to_vcon.py` looked for copies of denied arguments with Python's `in`,
which uses `==`. Python takes `True == 1` and `False == 0`, so a denied `{"x": true}` matched a later `{"x": 1}`:
`repeats_denied` dropped an unrelated text from the dialog, and the last guard over every JSON node refused a session
in which an allowed call carried `{"x": 1}`. Both places now compare `json_key` values, which are equal exactly when
the RFC 8785 forms are equal, the form the digests of the example and `check_example.py` use: true is not 1, and 1 is
1.0. The cases below fail at 1e32dd75 and pass with the fix; the oracle test holds `json_key` against `rfc8785`
itself.

The last class holds `check_example.py` to the extensions the example uses (external review of 4b9cef80, C1): the vCon
carries Event Objects of tool-invocation and of the AI agent extension, and vCon core -05 4.1.3 requires every
extension a vCon uses to be named in `extensions`. At 4b9cef80 the checker asked for ai_agent alone, so a vCon that
named only ai_agent passed V4.
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import pathlib
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "vcon_ai_agent_receipts"
SESSION = "5e551011-0000-4000-8000-0000000000aa"


def _converter():
    spec = importlib.util.spec_from_file_location("claude_jsonl_to_vcon_under_test",
                                                  EXAMPLE / "claude_jsonl_to_vcon.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _line(n, kind, content, **more):
    return json.dumps({"type": kind, "uuid": "u%02d" % n, "parentUuid": "u%02d" % (n - 1) if n > 1 else None,
                       "sessionId": SESSION, "timestamp": "2026-11-04T07:00:%02d.000Z" % n, "isSidechain": False,
                       "message": {"role": kind, "content": content}, **more})


def _tool_use(n, call_id, args):
    return _line(n, "assistant", [{"type": "tool_use", "id": call_id, "name": "Bash", "input": args}])


def _tool_result(n, call_id, decision, text="done"):
    return _line(n, "user", [{"type": "tool_result", "tool_use_id": call_id, "content": text}],
                 permissionDecision={"decision": decision, "source": "config"})


def _session(denied_args, *after):
    """A rejected call with `denied_args`, then the given lines."""
    return [_tool_use(1, "toolu_denied", denied_args), _tool_result(2, "toolu_denied", "reject", "refused"), *after]


class TheConverterComparesDeniedArgumentsByJsonType(unittest.TestCase):

    def setUp(self):
        if not (EXAMPLE / "claude_jsonl_to_vcon.py").is_file():
            self.skipTest("examples/vcon_ai_agent_receipts/claude_jsonl_to_vcon.py is not in this tree")
        self.c = _converter()

    def _texts(self, vcon):
        return [d["body"] for d in vcon["dialog"]]

    # repeats_denied (the dialog and reasoning texts)

    def test_a_text_with_1_is_kept_after_a_denied_true(self):
        text = 'The flag is now {"x": 1}.'
        vcon, report = self.c.convert(_session({"x": True}, _line(3, "assistant", [{"type": "text", "text": text}])))
        self.assertIn(text, self._texts(vcon))
        self.assertNotIn("text that repeats the arguments of a disallowed operation", report["not_converted"])

    def test_a_text_with_0_is_kept_after_a_denied_false(self):
        text = '{"x": [0, {"y": 0}]}'
        vcon, _ = self.c.convert(_session({"x": [False, {"y": False}]},
                                          _line(3, "assistant", [{"type": "text", "text": text}])))
        self.assertIn(text, self._texts(vcon))

    def test_a_text_with_the_same_number_written_as_1_0_is_still_dropped(self):
        """1 and 1.0 are one number in RFC 8785, as in the digest; the copy stays out of the vCon."""
        vcon, report = self.c.convert(_session({"x": 1},
                                               _line(3, "assistant", [{"type": "text", "text": 'try {"x": 1.0}'}])))
        self.assertEqual(self._texts(vcon), [])
        self.assertEqual(report["not_converted"]["text that repeats the arguments of a disallowed operation"], 1)

    def test_a_text_with_the_denied_true_is_still_dropped(self):
        vcon, _ = self.c.convert(_session({"x": True},
                                          _line(3, "assistant", [{"type": "text", "text": 'again {"x": true}'}])))
        self.assertEqual(self._texts(vcon), [])

    def test_a_deeply_nested_json_text_does_not_end_the_conversion(self):
        """The old `in` stopped at the first member that differed; the key must not end the conversion either, here
        on a text whose JSON json itself can still parse."""
        deep = '{"a": ' * 600 + "1" + "}" * 600
        vcon, _ = self.c.convert(_session({"x": True}, _line(3, "assistant", [{"type": "text", "text": deep}])))
        self.assertIn(deep, self._texts(vcon))

    # the last guard over every JSON node of the vCon

    def test_an_allowed_call_with_1_after_a_denied_true_is_not_refused(self):
        vcon, _ = self.c.convert(_session({"x": True}, _tool_use(3, "toolu_allowed", {"x": 1}),
                                          _tool_result(4, "toolu_allowed", "accept")))
        bodies = [e["body"] for e in vcon["events"] if e["type"] == "tool-invocation"]
        self.assertEqual(bodies, [{"x": 1}])
        self.assertIs(type(bodies[0]["x"]), int)

    def test_the_last_guard_keys_each_object_of_the_vcon_once(self):
        """A reading of fdd0de98 (Z4, P2): the guard rebuilt the key for every nested object over its whole subtree,
        so the work grew with the square of the depth. Counted instead of timed: the strings the key encodes during
        one conversion with an allowed call 400 objects deep. At fdd0de98 they are about 80000, in one pass a few
        hundred."""
        inner = {"payload": "z" * 1000}
        for _ in range(400):
            inner = {"a": inner}
        calls = []
        real = json.dumps

        def counting(*a, **k):
            calls.append(1)
            return real(*a, **k)

        with mock.patch.object(self.c.json, "dumps", counting):
            vcon, _ = self.c.convert(_session({"x": True}, _tool_use(3, "toolu_allowed", inner),
                                              _tool_result(4, "toolu_allowed", "accept")))
        self.assertEqual(len([e for e in vcon["events"] if e["type"] == "tool-invocation"]), 1)
        self.assertLess(len(calls), 5000, "the key of the vCon objects was built %d string by string" % len(calls))

    def test_an_allowed_call_with_the_same_arguments_as_1_0_is_still_refused(self):
        with self.assertRaisesRegex(ValueError, "as a JSON value"):
            self.c.convert(_session({"x": 1}, _tool_use(3, "toolu_allowed", {"x": 1.0}),
                                    _tool_result(4, "toolu_allowed", "accept")))


class JsonKeyIsEqualityOfTheRfc8785Form(unittest.TestCase):

    VALUES = [None, True, False, 0, 1, -1, 0.0, -0.0, 1.0, 1.5, 2 ** 53 - 1, float(2 ** 53 - 1), "1", "true", "",
              [], {}, [1], [True], [1.0], [0], [False], {"x": 1}, {"x": True}, {"x": 1.0}, {"x": 0}, {"x": False},
              {"x": -0.0}, {"y": 1}, {"x": 1, "y": 2}, {"y": 2, "x": 1.0}, {"x": [1, {"b": False}]},
              {"x": [1.0, {"b": 0}]}, {"x": [True, {"b": False}]}, {"x": None}, {"x": "1"}]

    def setUp(self):
        if not (EXAMPLE / "claude_jsonl_to_vcon.py").is_file():
            self.skipTest("examples/vcon_ai_agent_receipts/claude_jsonl_to_vcon.py is not in this tree")
        try:
            import rfc8785  # noqa: PLC0415
        except ImportError:
            self.skipTest("rfc8785 is not installed")
        self.jcs = rfc8785.dumps
        self.key = _converter().json_key

    def test_two_values_have_one_key_exactly_when_their_rfc8785_forms_are_equal(self):
        pairs = 0
        for a, b in itertools.product(self.VALUES, repeat=2):
            with self.subTest(a=a, b=b):
                self.assertEqual(self.key(a) == self.key(b), self.jcs(a) == self.jcs(b))
            pairs += 1
        self.assertEqual(pairs, len(self.VALUES) ** 2)

    def test_the_case_of_the_finding_is_apart(self):
        self.assertNotEqual(self.key({"x": True}), self.key({"x": 1}))
        self.assertTrue({"x": True} == {"x": 1}, "precondition: Python's == takes True for 1")

    def test_the_key_of_a_deep_value_needs_no_recursion(self):
        """3000 levels, three times the recursion limit: building, comparing and hashing the key must not recurse.
        A key of nested tuples failed here even when built without recursion, because Python compares tuples level
        by level."""
        deep, same = [], []
        for _ in range(3000):
            deep, same = [deep, 1], [same, 1.0]
        self.assertEqual(self.key(deep), self.key(same))
        self.assertEqual(len({self.key(deep), self.key(same)}), 1)
        self.assertNotEqual(self.key(deep), self.key([[deep, 1], 1]))

    def test_a_value_outside_rfc8785_is_equal_only_to_itself(self):
        big = 2 ** 60
        self.assertEqual(self.key({"x": big}), self.key({"x": big}))
        self.assertNotEqual(self.key({"x": big}), self.key({"x": float(big)}))
        self.assertNotEqual(self.key({"x": big}), self.key({"x": big + 1}))


def _checker():
    spec = importlib.util.spec_from_file_location("check_example_under_test", EXAMPLE / "check_example.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TheCheckerNeedsBothExtensionsTheExampleUses(unittest.TestCase):

    def setUp(self):
        if not (EXAMPLE / "check_example.py").is_file():
            self.skipTest("examples/vcon_ai_agent_receipts/check_example.py is not in this tree")
        try:
            import cryptography  # noqa: F401, PLC0415
        except ImportError:
            self.skipTest("cryptography is not installed")
        self.ce = _checker()
        self.vcon = json.loads((EXAMPLE / "out" / "vcon.payload.json").read_text(encoding="utf-8"))

    def _first_failure(self, extensions):
        v = json.loads(json.dumps(self.vcon))
        v["extensions"] = extensions
        rep = self.ce.Report()
        try:
            self.ce.check_structure(rep, v)
        except self.ce.Stop:
            pass
        return rep.first

    def test_the_example_names_both_and_its_structure_passes(self):
        self.assertEqual(sorted(self.vcon["extensions"]), ["ai_agent", "tool-invocation"])
        self.assertIsNone(self._first_failure(list(self.vcon["extensions"])))

    def test_extensions_with_ai_agent_alone_fail_v4(self):
        first = self._first_failure(["ai_agent"])
        self.assertIsNotNone(first, "a vCon with tool-invocation events that names only ai_agent passed V4")
        self.assertEqual((first["id"], first["where"]), ("V4", "extensions"))

    def test_extensions_with_tool_invocation_alone_fail_v4(self):
        first = self._first_failure(["tool-invocation"])
        self.assertIsNotNone(first)
        self.assertEqual((first["id"], first["where"]), ("V4", "extensions"))


if __name__ == "__main__":
    unittest.main()
