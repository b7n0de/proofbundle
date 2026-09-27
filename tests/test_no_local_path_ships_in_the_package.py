"""No absolute path of a developer machine ships in the package.

A docstring in ``src/proofbundle/_membership.py`` named the home directory of the checkout a
measurement was taken in (it entered main after v6.1.0, so 6.2.0 would have been the first release
to ship it in the wheel). The path said nothing a reader of the package could use, and it named a
machine. This guard reads every text file under ``src/proofbundle`` and refuses a path under
``/home/<name>/`` or ``/Users/<name>/``. RED on the tree before this change, at that one line.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "proofbundle"

# A path segment that starts a path: not preceded by a word character, a dot or a dash, so that a
# prose run such as "origin/root/tree-size" is no path.
_LOCAL_PATH = re.compile(r"(?<![\w.\-/])/(?:home|Users)/[A-Za-z_][\w.\-]*/")


def local_paths(text: str) -> list:
    """Every local absolute path in ``text``, as ``(line number, match)``."""
    return [(n, m.group(0)) for n, line in enumerate(text.splitlines(), 1)
            for m in _LOCAL_PATH.finditer(line)]


class NoLocalPathShipsInThePackage(unittest.TestCase):
    def test_no_file_under_src_names_a_home_directory(self):
        found = []
        for path in sorted(SRC.rglob("*")):
            if not path.is_file() or path.suffix in {".pyc", ".so", ".pyd"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            found += [f"{path.relative_to(SRC.parent)}:{n}: {m}" for n, m in local_paths(text)]
        self.assertEqual(found, [], "a machine-local path ships in the package")

    def test_the_guard_catches_the_forms_it_names(self):
        """Catch proof: the pattern finds the line this change removed and its macOS form, and
        leaves prose with slashes alone."""
        self.assertEqual(len(local_paths("had measured ``/home/someone/proofbundle``, a checkout")), 1)
        self.assertEqual(len(local_paths("see /Users/someone/Documents/x")), 1)
        for prose in ("origin/root/tree-size are claims", "a/home/b/ is no path",
                      "https://example.org/home/x/", "C:/home"):
            self.assertEqual(local_paths(prose), [], prose)


if __name__ == "__main__":
    unittest.main()
