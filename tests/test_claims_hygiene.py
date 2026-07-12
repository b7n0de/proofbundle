"""Claims-hygiene gate — the docs must not carry un-negated overclaims (six-lens review §15)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("claims_hygiene_check", REPO / "scripts" / "claims_hygiene_check.py")
ch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ch)


class TestClaimsHygiene(unittest.TestCase):
    def test_real_docs_are_clean(self):
        # The shipped docs must pass the gate — this is the tool whose product is honest scoping.
        self.assertEqual(ch.main(["--json"]), 0, "the repository docs carry an un-negated overclaim")

    def test_un_negated_forbidden_phrase_is_a_violation(self):
        with tempfile.TemporaryDirectory() as d:
            for text in ("proofbundle proves correctness of the eval.",
                         "The receipt is audit-proof.",
                         "It is quantum-safe.",
                         "This is the industry standard for receipts.",
                         "It is compliance ready today."):
                p = Path(d) / "x.md"
                p.write_text(text, encoding="utf-8")
                self.assertTrue(ch.scan_file(p), f"must flag: {text!r}")

    def test_negated_forbidden_phrase_is_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            for text in ("A receipt does not prove correctness.",
                         "proofbundle is not quantum-safe (Ed25519).",
                         "It never proves the number is true.",
                         "This is not audit-proof and makes no compliance claim."):
                p = Path(d) / "x.md"
                p.write_text(text, encoding="utf-8")
                self.assertEqual(ch.scan_file(p), [], f"negated form must be allowed: {text!r}")

    def test_code_fence_and_inline_code_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("```\nproves correctness\n```\nUse `quantum-safe` as a literal flag name.",
                         encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "code fences / inline code are not prose")


class TestGateHonesty(unittest.TestCase):
    """WP-N1 — the gate itself must be honest: a listed-but-missing doc is a FAIL, never a silent
    skip (6 of 16 default entries were silently skipped for months), and the scan set matches the
    repository exactly."""

    def test_every_default_doc_exists_and_scan_covers_all(self):
        missing = [rel for rel in ch._DEFAULT_DOCS if not (REPO / rel).is_file()]
        self.assertEqual(missing, [], "default scan set lists non-existent docs (silent-skip regression)")
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ch.main(["--json"])
        self.assertEqual(rc, 0)
        import json as _json
        out = _json.loads(buf.getvalue())
        self.assertEqual(out["scanned"], len(ch._DEFAULT_DOCS),
                         "scanned must equal the full default scan set — nothing silently skipped")
        self.assertEqual(out["missing"], [])

    def test_listed_but_missing_path_fails(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ch.main(["--json", "docs/DOES_NOT_EXIST_ANYWHERE.md"])
        self.assertEqual(rc, 1, "a listed-but-missing doc must FAIL the gate, never a silent skip")
        import json as _json
        out = _json.loads(buf.getvalue())
        self.assertEqual(out["verdict"], "FAIL")
        # missing entries carry the OSError class as a suffix, e.g. " (FileNotFoundError)"
        self.assertTrue(any(m.startswith("docs/DOES_NOT_EXIST_ANYWHERE.md") for m in out["missing"]),
                        f"missing[] must name the path: {out['missing']}")

    def test_injected_overclaim_in_every_listed_doc_fails(self):
        # WP-N1 acceptance: an injected "safe to deploy" in EVERY listed doc must be caught — proving
        # each doc is really scanned (the exact regression the silent skip hid).
        with tempfile.TemporaryDirectory() as d:
            for rel in ch._DEFAULT_DOCS:
                src = (REPO / rel).read_text(encoding="utf-8")
                p = Path(d) / Path(rel).name
                p.write_text(src + "\n\nThe model is safe to deploy.\n", encoding="utf-8")
                hits = ch.scan_file(p)
                self.assertTrue(any(v["phrase"] == "safe to deploy" for v in hits),
                                f"injected overclaim not caught in {rel}")

    def test_soft_wrapped_negation_is_exonerated(self):
        # The negation and the forbidden phrase sit on different physical lines of ONE sentence —
        # exactly docs/NON_CLAIMS.md's real layout. Must NOT flag.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("- **Safety.** A threshold is a threshold on one suite, not a statement that a\n"
                         "  model is safe to deploy.\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "a soft-wrapped in-sentence negation must exonerate")
            # counter-test: the same wrapped layout WITHOUT a negation must still flag
            p.write_text("- **Safety.** A passing threshold means that a\n  model is safe to deploy.\n",
                         encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "soft-unwrap must not swallow a real violation")

    def test_block_boundaries_still_separate_sentences(self):
        # A negation in a PREVIOUS bullet/heading must NOT exonerate the next block.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("- It does not prove truth\n- The model is safe to deploy\n", encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "a new list item is a new sentence — no cross-block exoneration")

    def test_heading_and_table_never_merge_forward(self):
        # Six-lens 2026-07-11: a heading / table row / setext underline cannot continue into prose —
        # a negation inside one must NOT exonerate the immediately following paragraph.
        cases = ("## Never a guarantee of anything\nIt produces a verified result for you.\n",
                 "| col | not applicable here |\nIt produces a verified result for you.\n",
                 "This section is never a guarantee\n=====\nIt produces a verified result for you.\n")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            for text in cases:
                p.write_text(text, encoding="utf-8")
                self.assertTrue(ch.scan_file(p), f"cross-block exoneration must not pass: {text!r}")

    def test_clause_separator_bounds_the_negation_window(self):
        # A negation in an earlier, grammatically independent clause must not exonerate a later
        # positive claim in the same (soft-unwrapped) sentence.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("A file-only proof is not producible with standard tooling — "
                         "the practical anchor is trustless.\n", encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "negation before an em-dash must not exonerate the next clause")
            p.write_text("It does not prove the anchor is trustless.\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "in-clause negation still exonerates")

    def test_content_violation_exits_one_at_main_level(self):
        # Six-lens 2026-07-11: only the missing-arm of failed=bool(violations or missing) was pinned;
        # a mutant returning 0 despite content violations survived. Pin the violations arm.
        import io
        import json as _json
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.md"
            p.write_text("The model is safe to deploy.\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ch.main(["--json", str(p)])
            self.assertEqual(rc, 1, "a content violation must exit 1")
            self.assertEqual(_json.loads(buf.getvalue())["verdict"], "FAIL")

    def test_unreadable_listed_doc_fails(self):
        # Six-lens 2026-07-11: a listed-but-UNREADABLE doc silently counted as scanned + PASS —
        # the exact silent-skip class N1 eliminates. Now it is a FAIL entry.
        import io
        import os
        from contextlib import redirect_stdout
        if os.name != "posix" or os.geteuid() == 0:
            self.skipTest("permission bits not enforceable here")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "locked.md"
            p.write_text("This is safe to deploy.\n", encoding="utf-8")
            p.chmod(0)
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = ch.main([str(p)])
            finally:
                p.chmod(0o644)
            self.assertEqual(rc, 1, "an unreadable listed doc must FAIL, never count as scanned")
            self.assertIn("MISSING", buf.getvalue())

    def test_line_numbers_stay_correct_after_soft_unwrap(self):
        # The 1:1 offset property: soft-unwrap must not shift the reported line numbers.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("First paragraph wraps over\ntwo lines without claims.\n\n"
                         "Second paragraph says the model\nis safe to deploy today.\n", encoding="utf-8")
            hits = ch.scan_file(p)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["line"], 5, "soft-unwrap must keep raw-text line numbers exact")

    def test_trustless_needs_scoping_or_negation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text("The timestamp is trustless.\n", encoding="utf-8")
            self.assertTrue(ch.scan_file(p), "positive 'trustless' must flag")
            p.write_text("The time is trust-minimized (Bitcoin PoW time).\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "the scoped wording is the allowed form")
            p.write_text("This does not make the anchor trustless.\n", encoding="utf-8")
            self.assertEqual(ch.scan_file(p), [], "negated 'trustless' is allowed")


class TestP0CAdditions(unittest.TestCase):
    """P0-C §5.2/§5.4 (Hardening 3.0.1) — the new forbidden phrasings and the per-sample /
    external-public-log context exceptions, both directions."""

    def _scan(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.md"
            p.write_text(text, encoding="utf-8")
            return [v["phrase"] for v in ch.scan_file(p)]

    def test_outer_signed_root_flagged(self):
        self.assertTrue(self._scan("The signed Merkle root proves membership."))
        self.assertTrue(self._scan("Each opening verifies against the signed root."))

    def test_per_sample_signed_root_exempt(self):
        # The samples root IS a field of the signed eval-claim payload (docs/DEMO.md audit-challenge).
        text = "## Per-sample audit\nEach opening verifies against the signed root.\n"
        self.assertEqual(self._scan(text), [], "per-sample section must exempt 'signed root'")

    def test_signed_root_exempt_only_inside_its_section(self):
        # A per-sample section must NOT exonerate a signed-root claim in a LATER, unrelated section.
        text = ("## Per-sample audit\nEverything here is per-sample.\n\n"
                "## Bundle format\nThe signed Merkle root anchors the bundle.\n")
        self.assertTrue(self._scan(text), "signed-root in a non-per-sample section must still flag")

    def test_append_only_own_output_flagged_external_log_exempt(self):
        self.assertTrue(self._scan("Our receipts form an append-only ledger."))
        exempt = "### vs Sigstore Rekor\nRekor proves public append-only existence at time T.\n"
        self.assertEqual(self._scan(exempt), [], "append-only describing an external public log is accurate")

    def test_publicly_anchored_and_score_and_secure_and_correct_and_executed(self):
        for text in ("The receipt is publicly anchored.",
                     "This gives you a verified score.",
                     "The exact score verified here is 0.9.",
                     "The benchmark is secure.",
                     "The evaluation is correct.",
                     "The action was executed by the tool."):
            self.assertTrue(self._scan(text), f"must flag: {text!r}")

    def test_regulatory_compliant_flagged_technical_compliant_clean(self):
        for text in ("It is AI Act compliant.", "A GDPR-compliant pipeline.",
                     "compliant with the EU AI Act"):
            self.assertTrue(self._scan(text), f"regulatory-compliant must flag: {text!r}")
        for text in ("The Merkle proof is RFC 9162-compliant.",
                     "a spec-compliant verifier", "C2SP-compliant checkpoint"):
            self.assertEqual(self._scan(text), [], f"technical-compliant must be clean: {text!r}")

    def test_article_12_compliant_is_an_allowed_anti_pattern_quote(self):
        # COMPLIANCE.md legitimately QUOTES this under "Anti-patterns (do not claim these)". The
        # positive Article-12 overclaim is covered by "satisfies article 12" instead.
        text = '- "proofbundle makes us Article 12 compliant" — no single artifact does'
        self.assertEqual(self._scan(text), [], "quoting 'Article 12 compliant' as an anti-pattern must not flag")

    def test_truth_as_claim_flagged_idioms_clean(self):
        for text in ("The receipt verifies the truth of the score.", "It guarantees truth.",
                     "This certifies truth."):
            self.assertTrue(self._scan(text), f"truth-as-claim must flag: {text!r}")
        for text in ("The single source of truth is pyproject.toml.",
                     "We compare against ground truth.", "To move toward truth you pre-register.",
                     "Nothing here is a claim about truth."):
            self.assertEqual(self._scan(text), [], f"truth idiom/disclaimer must be clean: {text!r}")

    def test_negated_new_phrases_allowed(self):
        for text in ("The receipts are not append-only.", "This is not publicly anchored.",
                     "It does not give a verified score.", "The benchmark is not secure by this alone."):
            self.assertEqual(self._scan(text), [], f"negated form must be allowed: {text!r}")


if __name__ == "__main__":
    unittest.main()
