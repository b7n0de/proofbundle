"""No absolute path of a developer machine ships in the package.

A docstring in ``src/proofbundle/_membership.py`` named the home directory of the checkout a
measurement was taken in (it entered main after v6.1.0, so 6.2.0 would have been the first release
to ship it in the wheel). The path said nothing a reader of the package could use, and it named a
machine. This guard reads every text file under ``src/proofbundle`` and refuses a path under
``/home/<name>`` or ``/Users/<name>``, with or without a slash after the name, and also inside a
``file://`` URL. RED on the tree before this change, at that one line.

The first form wanted a slash after the name and refused any path that followed a slash, so the lens
on 8ecb6edf wrote three spellings past it: ``file:///home/<name>/x``, ``/home/<name>`` with nothing
after the name, and ``/Users/<name>`` at the end of a text.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "proofbundle"

# A path segment that starts a path: not preceded by a word character, a dot, a dash or a slash, so
# that a prose run such as "origin/root/tree-size" is no path, or preceded by `file://`, whose third
# slash starts the path. The name ends where a word character or a dash no longer follows it, so the
# name alone is a path, and so is the name before a slash, a quote, a comma or the end of the text.
_LOCAL_PATH = re.compile(r"(?:(?<![\w.\-/])|(?<=file://))/(?:home|Users)/[A-Za-z_][\w.\-]*(?![\w\-])")


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
                      "https://example.org/home/x/", "C:/home", "file://host/home/x", "/homes/x/",
                      "under /home/<name>/", "/home/"):
            self.assertEqual(local_paths(prose), [], prose)

    def test_the_guard_catches_the_three_forms_the_lens_wrote_past_it(self):
        """The lens on 8ecb6edf: a `file://` URL, a home directory named without a slash after it,
        and a macOS home directory at the end of a text. Each is one path, found once."""
        for text in ("file:///home/someone/proofbundle/x", "the checkout `/home/someone`, 47 behind",
                     "measured in /home/someone", '"/home/someone"', "see /Users/someone",
                     "see /Users/someone."):
            with self.subTest(text=text):
                self.assertEqual(len(local_paths(text)), 1, local_paths(text))


if __name__ == "__main__":
    unittest.main()
