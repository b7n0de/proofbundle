"""K5 (Codex defect search on the 6.3.0 candidate 98b168b9, CODEX-630-K5): the example checker reads its JSON
strictly at the file boundary.

`check_example.py` read `receipt.json` with `json.loads`, where the last of two members of one name wins; the
library then saw only the cleaned object and could not see the ambiguity. SPEC Section 2 refuses duplicate JSON
members in verification input. A second `"payload": ""` before the real one, or a second `"sig"` in the signature
object, passed with all five check lines `ok` (measured at 98b168b9 and f6ea5cc3, exit 0). The checker now reads
`receipt.json`, the payload and `verdict.json` with the library's strict reader, and the payload with its strict
base64 decoder. The test needs no new key and no new signature.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "verdict_contract"


class TheExampleCheckerReadsStrictJson(unittest.TestCase):

    def setUp(self):
        for needed in ("check_example.py", "out/receipt.json"):
            if not (EXAMPLE / needed).is_file():
                self.skipTest(f"examples/verdict_contract/{needed} is not in this tree")
        if shutil.which("git") is None:
            self.skipTest("the example rebuilds its toy repository with git")
        d = tempfile.mkdtemp(prefix="k5-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.out = pathlib.Path(d) / "out"
        shutil.copytree(EXAMPLE / "out", self.out, ignore=shutil.ignore_patterns("toyrepo"))

    def _check(self) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", str(EXAMPLE / "check_example.py"), str(self.out)],
                              capture_output=True, text=True, timeout=300)

    def _edit(self, old: str, new: str) -> None:
        receipt = self.out / "receipt.json"
        text = receipt.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, f"precondition: {old!r} stands once in receipt.json")
        receipt.write_text(text.replace(old, new), encoding="utf-8")

    def test_CONTROL_the_receipt_as_shipped_passes(self):
        self.assertEqual(self._check().returncode, 0)

    def test_RED_a_second_payload_member_is_refused(self):
        """T5: before the existing payload a second "payload": "" is put."""
        receipt = self.out / "receipt.json"
        receipt.write_text(receipt.read_text(encoding="utf-8").replace("{", '{"payload":"",', 1), encoding="utf-8")
        checked = self._check()
        self.assertNotEqual(checked.returncode, 0, checked.stdout)
        self.assertNotIn("Traceback", checked.stderr)

    def test_RED_a_second_member_in_the_signature_object_is_refused(self):
        self._edit('"sig": "', '"sig": "AAAA", "sig": "')
        checked = self._check()
        self.assertNotEqual(checked.returncode, 0, checked.stdout)
        self.assertNotIn("Traceback", checked.stderr)


if __name__ == "__main__":
    unittest.main()
