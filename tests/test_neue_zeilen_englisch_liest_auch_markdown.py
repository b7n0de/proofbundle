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
import json
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

    def test_the_gate_runs_and_names_a_verdict_in_every_answer_shape(self):
        """The end-to-end shape, so a refactor that breaks the CLI is not green here.

        THE FIRST VERSION ASSERTED A FIELD THAT ONLY ONE ANSWER SHAPE CARRIES. It required
        `gemessener_stand`, which the gate emits when it measured something. In CI the checkout has
        no `origin/main` ref, the gate answers NOT MEASURABLE — correctly, and without that field —
        and the case went red for a reason that had nothing to do with what it was written to
        protect. Measured 2026-09-19 in the coverage job: 1 failed of 4924, and the one was this.

        It passed on a developer machine because `origin/main` exists there, so the shape it could
        not handle never appeared. A check that only ever sees one of two answer shapes is not
        strict, it is lucky.

        Both shapes are asserted now, and the second half is stronger than the original: a verdict
        is always named, and WHENEVER the gate measured, it must also say on which state. An
        honest NOT MEASURABLE is a verdict; silence is not.
        """
        r = subprocess.run([sys.executable, str(TOR), "--base", "origin/main", "--json"],
                           capture_output=True, text=True, cwd=str(REPO))
        self.assertIn(r.returncode, (0, 1, 2))
        d = json.loads(r.stdout)
        self.assertIn("urteil", d, r.stdout)
        if d["urteil"] != "NOT MEASURABLE":
            self.assertIn("gemessener_stand", d,
                          "the gate measured and did not say on which state")
        else:
            self.assertTrue(d.get("grund"),
                            "NOT MEASURABLE without a reason is a shrug, not a verdict")


class TestAVerbatimQuotationIsMarkedAndNarrow(unittest.TestCase):
    """The bracket exists because two owner instructions of 2026-09-19 met and both are right.

    New and re-cast files are English; and the 54 scope lines moving from 6.1.0 to 6.2.0 move
    unchanged, byte equality checked. A quotation that is rewritten is no longer a quotation, and
    the byte-equality check behind it would mean nothing.

    What these cases are really about is the bracket staying NARROW and FAIL-CLOSED, because an
    exemption mechanism is only as good as its edges.
    """

    def _schreibe(self, d, text):
        rel = pathlib.Path(d).name
        (pathlib.Path(d) / "probe.md").write_text(text, encoding="utf-8")
        return f"{rel}/probe.md"

    def test_marked_material_is_not_judged_and_everything_else_still_is(self):
        mod = _laden()
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = self._schreibe(d,
                "Eine deutsche Zeile vor der Klammer und sie soll gefunden werden.\n"
                "<!-- proofbundle:verbatim-quote:begin -->\n"
                "| A1 Testsammler des Mutationstors und die Zeile bleibt wie sie ist |\n"
                "<!-- proofbundle:verbatim-quote:end -->\n"
                "Eine deutsche Zeile nach der Klammer und auch diese zaehlt.\n")
            prosa = mod._md_prosazeilen(rel)
            self.assertIn(1, prosa, "prose before the bracket is still judged")
            self.assertNotIn(3, prosa, "the quoted row is not judged")
            self.assertNotIn(2, prosa, "the marker line itself is not prose")
            self.assertIn(5, prosa, "prose after the bracket is judged again")

    def test_an_opener_without_a_closer_is_not_measurable_rather_than_clean(self):
        # The defect this module already paid for once: a marker that swallows the rest of the file
        # in silence. None means not measurable, and the caller treats that as not-prose, so the
        # FILE never reads as clean on the strength of a broken bracket.
        mod = _laden()
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = self._schreibe(d,
                "<!-- proofbundle:verbatim-quote:begin -->\n"
                "Alles was hier folgt waere sonst stillschweigend ausgenommen.\n")
            self.assertIsNone(mod._md_prosazeilen(rel))

    def test_a_closer_before_its_opener_is_not_measurable(self):
        mod = _laden()
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = self._schreibe(d,
                "<!-- proofbundle:verbatim-quote:end -->\n"
                "Eine deutsche Zeile die sonst ausgenommen waere ohne je geklammert zu sein.\n"
                "<!-- proofbundle:verbatim-quote:begin -->\n")
            self.assertIsNone(mod._md_prosazeilen(rel))



class TestFencesOpenAndCloseAsCommonMarkSays(unittest.TestCase):
    """A fence opens and closes by the CommonMark rules (a review of the stack at 1ecc2aca, on main
    as well, measured 2026-09-26). Each shape below ended a block for the gate where CommonMark kept
    reading code, or opened one CommonMark never opens; either way a German paragraph after it was
    judged as code, green with exit 0."""

    G = "Eine deutsche Zeile, die nach dem Zaun als Absatz steht."
    NBSP = chr(0xA0)
    TAB = chr(9)

    def cases(self):
        """(label, text, the prose lines CommonMark renders outside a fence)."""
        return [
            ("text after the run is no closer", f"```\ncode\n``` x\n```\n{self.G}\n", {5}),
            ("a tab before a tilde run is no closer", f"~~~\ncode\n{self.TAB}~~~\n~~~\n{self.G}\n", {5}),
            ("a no-break space before a tilde run is no closer",
             f"~~~\ncode\n{self.NBSP}~~~\n~~~\n{self.G}\n", {5}),
            ("four spaces before a run is no closer", f"```\ncode\n    ```\n```\n{self.G}\n", {5}),
            ("a tab before a backtick run is no opener", f"{self.TAB}```\n\n{self.G}\n", {1, 2, 3}),
            ("a backtick in the info string is no opener", f"``` a`b\n\n{self.G}\n", {1, 2, 3}),
            ("control: spaces and a tab after a closer still close it", f"```\ncode\n```  {self.TAB}\n{self.G}\n",
             {4}),
            ("control: three spaces of indentation open and close", f"   ~~~ ok `x`\ncode\n   ~~~\n{self.G}\n",
             {4}),
            ("control: a CRLF closer closes", f"```\r\ncode\r\n```\r\n{self.G}\r\n", {4}),
        ]

    def _prose(self, mod, text):
        with tempfile.TemporaryDirectory(dir=REPO) as d:
            rel = pathlib.Path(d).name
            (pathlib.Path(d) / "probe.md").write_bytes(text.encode("utf-8"))
            return mod._md_prosazeilen(f"{rel}/probe.md")

    def test_each_shape_is_read_as_commonmark_reads_it(self):
        mod = _laden()
        for label, text, expected in self.cases():
            with self.subTest(label):
                self.assertEqual(self._prose(mod, text), expected)

    def test_markdown_it_agrees_as_an_oracle(self):
        """markdown-it-py, where it is installed, reads the same fence lines; the gate does not import it.
        Over the constructed shapes, and over every tracked .md file of this repository."""
        try:
            from markdown_it import MarkdownIt
        except ImportError:
            self.skipTest("markdown-it-py is not installed here, so the oracle is not measured")
        import re
        import subprocess as sp
        md = MarkdownIt("commonmark")

        def outside_fences(text):
            lines = re.split(r"\r\n|\r|\n", text)
            count = len(lines) - (1 if lines and lines[-1] == "" else 0)
            fence = set()
            for token in md.parse(text):
                if token.type == "fence" and token.map:
                    fence.update(range(token.map[0] + 1, token.map[1] + 1))
            return set(range(1, count + 1)) - fence

        mod = _laden()
        for label, text, _ in self.cases():
            with self.subTest(label):
                self.assertEqual(self._prose(mod, text), outside_fences(text))
        listed = sp.run(["git", "-C", str(REPO), "ls-files", "-z", "*.md"], capture_output=True)
        if listed.returncode != 0:
            self.skipTest("not a git checkout, so the tracked files are not measured")
        for name in (n for n in listed.stdout.decode("utf-8", "surrogateescape").split("\0") if n):
            path = REPO / name
            if not path.is_file():
                continue
            text = path.read_bytes().decode("utf-8", "replace")
            gate = mod._md_prosazeilen(name, lambda _, raw=path.read_bytes(): raw)
            if gate is None:
                continue
            quoted = set()
            lines = re.split(r"\r\n|\r|\n", text)
            opened = [i for i, z in enumerate(lines, 1) if z.strip() == mod._ZITAT_AUF]
            closed = [i for i, z in enumerate(lines, 1) if z.strip() == mod._ZITAT_ZU]
            for a, b in zip(opened, closed):
                quoted.update(range(a, b + 1))
            with self.subTest(name):
                self.assertEqual(gate - quoted, outside_fences(text) - quoted)

    def test_named_limit_a_fence_in_a_list_item_is_not_tracked(self):
        """CommonMark ends a fence where its list item ends; this gate does not track containers, so
        the paragraph after such an unclosed fence is still read as code. Pinned so that a change here
        is seen; none of the tracked .md files has a fence in a container (measured 2026-09-26)."""
        prose = self._prose(_laden(), f"- item\n\n  ```\n  code\n{self.G}\n")
        self.assertEqual(prose, {1, 2})


# THE MAIN BLOCK BELONGS AT THE END OF THE FILE, and this file learned why.
# It sat in the middle, because four cases were appended later. Under pytest all eight ran; run
# directly, unittest.main() executed BEFORE the class below it was defined, and reported five.
# Measured 2026-09-20: 5 against 8. A case that CANNOT run on a surface looks, on that surface,
# exactly like one that passes.
if __name__ == "__main__":
    unittest.main()
