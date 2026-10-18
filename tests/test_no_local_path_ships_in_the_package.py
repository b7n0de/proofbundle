"""No absolute path of a developer machine ships in the package.

A docstring in ``src/proofbundle/_membership.py`` named the home directory of the checkout a
measurement was taken in (it entered main after v6.1.0, so 6.2.0 would have been the first release
to ship it in the wheel). The path said nothing a reader of the package could use, and it named a
machine. This guard reads every text file under ``src/proofbundle`` and refuses a path under
``/home/<name>`` or ``/Users/<name>``, with or without a slash after the name. ``Users`` is read in
any case (``/users/<name>``), because the default macOS file system does not tell the two apart.
A slash may be written as JSON writes it, ``\\/`` (``\\/home\\/<name>``). Inside a ``file:`` URL
the path is refused when the URL names this machine: an empty host (``file:///home/<name>``) or
``localhost`` (``file://localhost/home/<name>``), which RFC 8089 reads as the same thing. RED on the
tree before this change, at that one line.

The first form wanted a slash after the name and refused any path that followed a slash, so the lens
on 8ecb6edf wrote three spellings past it: ``file:///home/<name>/x``, ``/home/<name>`` with nothing
after the name, and ``/Users/<name>`` at the end of a text. The lens on d5747000 wrote three more
(``file://localhost/home/<name>/x``, the JSON-escaped ``\\/home\\/<name>\\/x`` and a lowercase
``/users/<name>``) and two false alarms, decided below.

DECIDED, AND WHY. A request target after an HTTP method (``GET /home/index.html``) is a URL path on
a server, not a path on a machine, and is not refused. ``/home/NAME/`` IS refused: a placeholder has
the form of a path, and a form cannot tell a placeholder from a user called NAME; write a placeholder
as ``<name>``. NOT READ, and stated as limits: a ``file:`` URL that names another host
(``file://host/home/x``, a path on that host), a Windows path (a drive letter and backslashes), any
root other than ``/home`` and ``/Users`` (``/root``, ``/var/folders/...``), ``~`` and ``~name``, and
a name that starts with a digit.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "proofbundle"

#: The HTTP methods whose request target is a URL path, each a fixed-width lookbehind of its own.
_HTTP_METHODS = ("GET", "PUT", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS")

# A path segment that starts a path: not preceded by a word character, a dot, a dash, a slash or a
# backslash, so that a prose run such as "origin/root/tree-size" is no path (nor its JSON-escaped
# form), and not a request target after an HTTP method; or preceded by a `file:` URL that names this
# machine (empty host or `localhost`), whose next slash starts the path. The name ends where a word
# character or a dash no longer follows it, so the name alone is a path, and so is the name before a
# slash, a quote, a comma or the end of the text.
_LOCAL_PATH = re.compile(
    r"(?:(?<![\w.\-/\\])" + "".join(rf"(?<!\b{m} )" for m in _HTTP_METHODS)
    + r"|(?<=(?i:file)://)|(?<=(?i:file://localhost)))"
    r"/(?:home|(?i:users))/[A-Za-z_][\w.\-]*(?![\w\-])")


def local_paths(text: str) -> list:
    """Every local absolute path in ``text``, as ``(line number, match)``. JSON's escaped solidus
    (``\\/``) is read as the slash it stands for, so an escaped path is the same path."""
    return [(n, m.group(0)) for n, line in enumerate(text.splitlines(), 1)
            for m in _LOCAL_PATH.finditer(line.replace("\\/", "/"))]


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
                      "under /home/<name>/", "/home/", "origin\\/root\\/tree-size", "a\\/home\\/b\\/"):
            self.assertEqual(local_paths(prose), [], prose)

    def test_the_guard_catches_the_three_forms_the_lens_wrote_past_it(self):
        """The lens on 8ecb6edf: a `file://` URL, a home directory named without a slash after it,
        and a macOS home directory at the end of a text. Each is one path, found once."""
        for text in ("file:///home/someone/proofbundle/x", "the checkout `/home/someone`, 47 behind",
                     "measured in /home/someone", '"/home/someone"', "see /Users/someone",
                     "see /Users/someone."):
            with self.subTest(text=text):
                self.assertEqual(len(local_paths(text)), 1, local_paths(text))

    def test_the_guard_catches_the_three_forms_the_second_lens_wrote_past_it(self):
        """The lens on d5747000: `file://localhost/...`, a JSON-escaped path and a lowercase macOS
        home directory. Each is one path, found once; the pattern of d5747000 found none of them."""
        for text in ("file://localhost/home/someone/x", "FILE://LOCALHOST/home/someone/x",
                     '{"p": "\\/home\\/someone\\/proofbundle"}', "file:\\/\\/\\/home\\/someone",
                     "see /users/someone/x", "see /USERS/someone"):
            with self.subTest(text=text):
                self.assertEqual(len(local_paths(text)), 1, local_paths(text))

    def test_the_two_false_alarms_are_decided(self):
        """A request target after an HTTP method is a URL path, not a machine path; a placeholder
        in the form of a path is refused, because the form is all the guard can read."""
        for text in ("GET /home/index.html HTTP/1.1", "then POST /users/me", "DELETE /home/x"):
            with self.subTest(text=text):
                self.assertEqual(local_paths(text), [], text)
        self.assertEqual(len(local_paths("under /home/NAME/ each user")), 1)
        self.assertEqual(len(local_paths("FORGET /home/someone now")), 1)


if __name__ == "__main__":
    unittest.main()
