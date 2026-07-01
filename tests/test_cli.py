import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from make_example import build_bundle  # noqa: E402

from proofbundle.cli import main  # noqa: E402


class TestCli(unittest.TestCase):
    def _write(self, bundle) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(bundle, handle)
        handle.close()
        return handle.name

    def test_verify_ok_exit_zero(self):
        path = self._write(build_bundle())
        try:
            self.assertEqual(main(["verify", path]), 0)
            self.assertEqual(main(["verify", "--json", path]), 0)
        finally:
            os.unlink(path)

    def test_verify_tampered_exit_one(self):
        bundle = build_bundle()
        bundle["payload_b64"] = "AAAA"
        path = self._write(bundle)
        try:
            self.assertEqual(main(["verify", path]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
