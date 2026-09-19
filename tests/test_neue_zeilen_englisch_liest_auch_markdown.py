"""The English gate reads Markdown too, and a fenced block is not prose.

Owner decision 2026-09-19: new and re-cast files are English, and `.md` joins this gate as the
fourth item of the 6.1.0 release step.

WHAT MADE IT NECESSARY, measured the same day: a release cut rewrote two `.md` scope files, 106
added lines, and the gate reported "0 added lines in 0 files" in GREEN. It had `*.py` written into
two separate git calls, so Markdown was never opened. A gate that answers green about a surface it
does not read is worse than one that says it cannot measure, because green is an answer and
"cannot measure" is a question.

The fenced block is the exception, and it is the one that needs a test rather than an argument. A
code fence in Markdown carries commands, output and identifiers, and those are a naming question
rather than a language one, exactly as code identifiers are in `.py`. The risk is not that the rule
is wrong, it is that the DERIVATION is: a flag flipped on every fence marker inverts the rest of the
file after one stray marker, and the report then stays green because the tool stopped looking. This
module's sibling already paid for that shape once with docstrings.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOR = REPO / "scripts" / "neue_zeilen_sind_englisch.py"

sys.path.insert(0, str(REPO / "scripts"))


def _laden():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_nze", TOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMarkdownIsRead(unittest.TestCase):

    def test_the_file_pattern_lives_in_one_place_and_names_markdown(self):
        # Two spellings of one list is how the first surface was forgotten. If a third call site
        # appears with its own literal, this fails and says so.
        quelle = TOR.read_text(encoding="utf-8")
        self.assertIn('_ENDUNGEN = ("*.py", "*.md")', quelle)
        self.assertEqual(quelle.count('"*.py"'), 1,
                         "the pattern is written somewhere other than _ENDUNGEN again")

    def test_prose_outside_a_fence_counts_and_inside_it_does_not(self):
        mod = _laden()
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = pathlib.Path(d).name
            p = pathlib.Path(d) / "probe.md"
            p.write_text(
                "# Titel\n"
                "\n"
                "Dieser Absatz ist auf Deutsch und soll gefunden werden.\n"
                "\n"
                "```bash\n"
                "# Diese deutsche Zeile steht im Zaun und zaehlt nicht\n"
                "```\n"
                "\n"
                "Auch dieser Satz steht nach dem Zaun und ist nicht Englisch.\n",
                encoding="utf-8")
            prosa = mod._md_prosazeilen(f"{rel}/probe.md")
            self.assertIsNotNone(prosa)
            self.assertIn(3, prosa, "prose before the fence must count")
            self.assertIn(9, prosa, "prose after the fence must count")
            self.assertNotIn(6, prosa, "a line inside the fence is not prose")
            self.assertNotIn(5, prosa, "the fence line itself is not prose")
            self.assertNotIn(7, prosa, "the closing fence is not prose")

    def test_a_shorter_marker_does_not_close_a_longer_fence(self):
        # CommonMark: the closer is at least as long as the opener and the same character. A
        # toggle would end the block on the first marker it meets and call the rest prose.
        mod = _laden()
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = pathlib.Path(d).name
            (pathlib.Path(d) / "probe.md").write_text(
                "````\n"
                "``` immer noch im Zaun und deutsch\n"
                "````\n"
                "Jetzt ist es wieder deutsche Prosa hier.\n",
                encoding="utf-8")
            prosa = mod._md_prosazeilen(f"{rel}/probe.md")
            self.assertNotIn(2, prosa, "a shorter marker must not close a longer fence")
            self.assertIn(4, prosa, "after the real closer the file is prose again")

    def test_a_tilde_fence_is_not_closed_by_backticks(self):
        mod = _laden()
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = pathlib.Path(d).name
            (pathlib.Path(d) / "probe.md").write_text(
                "~~~\n"
                "``` immer noch im Zaun und auf Deutsch\n"
                "~~~\n"
                "Und danach ist es wieder deutsche Prosa.\n",
                encoding="utf-8")
            prosa = mod._md_prosazeilen(f"{rel}/probe.md")
            self.assertNotIn(2, prosa, "a backtick marker must not close a tilde fence")
            self.assertIn(4, prosa)

    def test_the_gate_runs_and_reports_the_state_it_measured(self):
        # The end-to-end shape, so a refactor that breaks the CLI is not green here.
        r = subprocess.run([sys.executable, str(TOR), "--base", "origin/main", "--json"],
                           capture_output=True, text=True, cwd=str(REPO))
        self.assertIn(r.returncode, (0, 1, 2))
        self.assertIn("gemessener_stand", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
