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

    def test_verbose_prints_matching_roots(self):
        # issue #2: --verbose shows the recomputed root next to the stated root.
        import contextlib
        import io
        bundle = build_bundle()
        path = self._write(bundle)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(main(["verify", "--verbose", path]), 0)
            out = buf.getvalue()
            self.assertIn("stated root", out)
            self.assertIn("recomputed root", out)
            self.assertIn(bundle["merkle"]["root_b64"], out)
            stated = next(ln for ln in out.splitlines() if "stated root" in ln).split()[-1]
            recomputed = next(ln for ln in out.splitlines() if "recomputed root" in ln).split()[-1]
            self.assertEqual(stated, recomputed)
        finally:
            os.unlink(path)

    def test_verbose_shows_diverging_root_on_tamper(self):
        import contextlib
        import io
        bundle = build_bundle()
        bundle["payload_b64"] = "AAAA"                       # tamper: payload no longer anchored
        path = self._write(bundle)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(main(["verify", "--verbose", path]), 1)
            out = buf.getvalue()
            stated = next(ln for ln in out.splitlines() if "stated root" in ln).split()[-1]
            recomputed = next(ln for ln in out.splitlines() if "recomputed root" in ln).split()[-1]
            self.assertNotEqual(stated, recomputed)
        finally:
            os.unlink(path)

    def test_verbose_json_contains_roots(self):
        import contextlib
        import io
        path = self._write(build_bundle())
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(main(["verify", "--json", "--verbose", path]), 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["merkle_root"]["stated_b64"],
                             data["merkle_root"]["recomputed_b64"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
