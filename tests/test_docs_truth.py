"""Doc-truth guards — metrics in the docs must not be able to go stale (six-lens review F5/SH4)."""
import importlib.util
import re
import unittest
from pathlib import Path

from proofbundle import SPEC_REVISION

REPO = Path(__file__).resolve().parents[1]
_dl_spec = importlib.util.spec_from_file_location("doc_link_check", REPO / "scripts" / "doc_link_check.py")
doc_link_check = importlib.util.module_from_spec(_dl_spec)
_dl_spec.loader.exec_module(doc_link_check)

# --- Future tense about a release that is already out ------------------------------------------------
# docs/predicates/README.md said "unreleased (planned for 6.3.0)" for eval-result v0.2 after 6.3.0 and
# 6.4.0 had shipped it. A sentence that promises a version stays true only until that version exists;
# after that it reads as an open promise for something that shipped, or was skipped. The guard reads a
# future phrase followed by a version and reports it once that version is at or below the newest release.
# "since X.Y.Z", "from X.Y.Z on" and "until X.Y.Z" are history and never match.
_FUTURE_VERSION = re.compile(
    r"(?i)\b(?:planned\s+(?:for|in)|scheduled\s+(?:for|in)|targeted\s+(?:for|at)|slated\s+for|due\s+in"
    r"|coming\s+in|will\s+(?:ship|land|arrive|come|follow|appear"
    r"|be\s+(?:released|added|removed|shipped|built|fixed|available))\s+(?:in|with)"
    r"|(?:ships?|lands?)\s+in|deferred\s+to|follows?\s+in|go(?:es)?\s+to"
    r"|geplant\s+f(?:ü|ue)r|kommt\s+in|erscheint\s+in|folgt\s+in)"
    r"[\s(`\"']*(?:proofbundle\s+)?v?(\d+\.\d+\.\d+)(?![\d.]*\d)")
# A pointer to the changelog's "Unreleased" section goes stale with the next release: the entry moves
# under a version heading and the pointer names a section that no longer holds it.
_UNRELEASED_POINTER = re.compile(r"CHANGELOG(?:\.md)?`?\s*[\"“]Unreleased[\"”]")
_CHANGELOG_HEADING = re.compile(r"(?m)^## \[(\d+\.\d+\.\d+)\]")
_RECORD_NAME = re.compile(r"^(?:RESTRISIKO_(\d)(\d)(\d)(?:_.*)?|(\d+\.\d+\.\d+))\.md$")


def _vt(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def _source_version(repo: Path) -> str:
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', (repo / "pyproject.toml").read_text(encoding="utf-8"))
    return m.group(1)


def _released_versions(repo: Path) -> set:
    """The released versions, read from CHANGELOG.md, so the guard needs no git and no tags.

    The section of the source version is the release in preparation; it counts as released only when
    the clone carries its tag. Without git, or without tags, it counts as not released, which can only
    leave a sentence about that one version unreported until the next bump, never report a false one.
    """
    import subprocess
    source = _source_version(repo)
    released = {v for v in _CHANGELOG_HEADING.findall((repo / "CHANGELOG.md").read_text(encoding="utf-8"))
                if _vt(v) < _vt(source)}
    try:
        tag = subprocess.run(["git", "-C", str(repo), "tag", "-l", f"v{source}"], capture_output=True,
                             text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        tag = ""
    if tag == f"v{source}":
        released.add(source)
    return released


def _is_closed_record(rel: str, released: set) -> bool:
    """A record of a release that is out: its future sentences were true on the day it was written.

    RESTRISIKO_<xyz>*.md and docs/release_scope/<x.y.z>.md belong to the release they name. Once it
    is out they are history like CHANGELOG.md; the record of the release in preparation stays read.
    """
    parent = rel.rpartition("/")[0]
    # The records of releases sit at the root (600 and 610) or under docs/residual_risk/ (all others).
    if parent not in ("", "docs/release_scope", "docs/residual_risk"):
        return False
    m = _RECORD_NAME.match(rel.rpartition("/")[2])
    if not m:
        return False
    version = m.group(4) or f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
    return version in released


def _future_tense_scope(repo: Path, released: set) -> list:
    """The shipped and linked text: README and the other top-level documents, docs/, examples/,
    schemas/ and src/ (docstrings, comments and the CLI help all live in the .py files).

    Left out, each for its reason: CHANGELOG.md, release_notes/ and audit_artifacts/ are history and
    are not rewritten; docs/upstream/ mirrors texts of other projects; plugins/ carries its own version
    line (0.x), which this guard does not read, and so does docs/release_scope/plugin-*.md; the records
    of releases that are out (above).
    """
    out = []
    for p in sorted(repo.glob("*.md")):
        if p.name != "CHANGELOG.md" and not _is_closed_record(p.name, released):
            out.append(p)
    for top, suffixes in (("docs", (".md", ".json")), ("examples", (".md", ".json", ".py", ".txt")),
                          ("schemas", (".md", ".json")), ("src", (".py",))):
        for p in sorted((repo / top).rglob("*")):
            rel = p.relative_to(repo).as_posix()
            if (p.is_file() and p.suffix in suffixes and not rel.startswith("docs/upstream/")
                    and not rel.startswith("docs/release_scope/plugin-")
                    and "__pycache__" not in rel and not _is_closed_record(rel, released)):
                out.append(p)
    return out


def _future_tense_findings(texts, released: set) -> list:
    """Each finding as "path:line: phrase (why)". `texts` is a list of (path label, text)."""
    newest = max(_vt(v) for v in released)
    found = []
    for label, text in texts:
        for m in _FUTURE_VERSION.finditer(text):
            if _vt(m.group(1)) <= newest:
                state = "released" if m.group(1) in released else "skipped, a later release is out"
                line = text.count("\n", 0, m.start()) + 1
                found.append(f"{label}:{line}: {' '.join(m.group(0).split())!r} ({m.group(1)} {state})")
        for m in _UNRELEASED_POINTER.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            found.append(f"{label}:{line}: {m.group(0)!r} (the entry has moved under a version heading)")
    return found


class TestDocsTruth(unittest.TestCase):
    def test_readme_carries_no_hardcoded_test_count(self):
        # F5: the README stated "303 tests" while the suite had grown past it. A hardcoded count
        # goes stale on every added test. Removed (not tracked by hand) — this guard keeps it gone:
        # a "<N> tests" phrase is a stale-metric regression. docs/REVIEWERS.md joined the guard
        # after the six-lens review (2026-07-11) found it saying "683 tests" against a 693 suite.
        for rel in ("README.md", "docs/REVIEWERS.md"):
            text = (REPO / rel).read_text(encoding="utf-8")
            # ignore fenced code blocks (a CLI sample line is not a prose metric)
            prose = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
            hits = re.findall(r"\b\d+\s+(?:tests?|operators?)\b", prose, flags=re.IGNORECASE)
            self.assertEqual(hits, [], f"{rel} carries a hardcoded, stale-prone count: {hits}")

    def test_citation_version_matches_pyproject(self):
        # F6/SH4: CITATION.cff stated version 0.7.0 while pyproject shipped 1.9.1 — a stale version
        # travels into every citation. Pin them together so a release bump cannot drift them apart
        # (the RELEASE.md checklist requires bumping both).
        cff = (REPO / "CITATION.cff").read_text(encoding="utf-8")
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        cff_v = re.search(r"(?m)^version:\s*([^\s#]+)", cff)
        py_v = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        self.assertIsNotNone(cff_v, "CITATION.cff has no version")
        self.assertIsNotNone(py_v, "pyproject.toml has no version")
        self.assertEqual(cff_v.group(1).strip('"'), py_v.group(1),
                         "CITATION.cff version must equal pyproject version (bump both together)")

    def test_init_version_matches_pyproject(self):
        # 2026-07-09 release incident: `__init__.py::__version__` was bumped to 2.0.0 for the tag, but
        # `pyproject.toml::version` (the value the WHEEL is built from) was left at 2.0.0b3. The build
        # therefore produced proofbundle-2.0.0b3, `skip-existing` skipped it, and 2.0.0 never reached
        # PyPI while every other check went green. This pins the runtime `--version` string to the
        # built distribution version so that drift is a red test, not a silent failed release.
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        init_py = (REPO / "src" / "proofbundle" / "__init__.py").read_text(encoding="utf-8")
        py_v = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        init_v = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"', init_py)
        self.assertIsNotNone(py_v, "pyproject.toml has no version")
        self.assertIsNotNone(init_v, "__init__.py has no __version__")
        self.assertEqual(init_v.group(1), py_v.group(1),
                         "__init__.py __version__ must equal pyproject version (the wheel is built "
                         "from pyproject; a drift ships the wrong version to PyPI)")

    def test_spec_revision_matches_spec_md(self):
        # WP-B1 (closes #28): `proofbundle --version` reports SPEC_REVISION as the pinned SPEC.md
        # revision it implements. If the two drift apart, --version would silently lie about which
        # spec text this build actually matches — pin them together like CITATION.cff/pyproject above.
        spec_md = (REPO / "SPEC.md").read_text(encoding="utf-8")
        m = re.search(r"(?m)^Revision:\s*(\S+)", spec_md)
        self.assertIsNotNone(m, "SPEC.md has no top-of-file 'Revision:' line")
        self.assertEqual(SPEC_REVISION, m.group(1),
                         "SPEC_REVISION (src/proofbundle/__init__.py) must equal SPEC.md's Revision: line")

    def test_no_broken_internal_doc_links(self):
        # SH5: a Markdown link to a local file that 404s reads as abandonment for a tool that sells
        # reviewability. The shipped docs must have zero broken internal links.
        out = doc_link_check.check()
        self.assertGreater(out["checked"], 0, "link checker found no local links to check — is it wired up?")
        self.assertEqual(out["broken"], [], f"broken internal doc link(s): {out['broken']}")

    def test_docs_references_are_current(self):
        # WP-N2 reference hygiene, pinned so the three audited drifts cannot return:
        # (d) ValiChord moved — the old topeuph-ai URL is dead/wrong everywhere;
        # (e) SD-JWT VC is at draft-17/IESG — no doc/code comment may still cite draft-15/-16 as current
        #     (the historical CHANGELOG is exempt: it records what WAS true);
        # (f) the enclave preview install must not pin a stale beta that predates the stable release.
        for rel in ("INTEROP.md", "INTEGRATIONS.md"):
            text = (REPO / rel).read_text(encoding="utf-8")
            self.assertNotIn("topeuph-ai/ValiChord", text, f"{rel}: stale ValiChord URL")
            self.assertIn("github.com/ValiChord/ValiChord", text, f"{rel}: canonical ValiChord URL missing")
        sdjwt_issue = (REPO / "src" / "proofbundle" / "sdjwt_issue.py").read_text(encoding="utf-8")
        self.assertIn("sd-jwt-vc-17", sdjwt_issue, "sdjwt_issue.py must cite the current draft revision")
        self.assertNotIn("draft-15", sdjwt_issue)
        enclave_doc = (REPO / "docs" / "EXPERIMENTAL_ENCLAVE.md").read_text(encoding="utf-8")
        self.assertNotIn("2.0.0b1", enclave_doc, "EXPERIMENTAL_ENCLAVE.md pins a stale beta install")

    def test_no_future_tense_about_a_released_version(self):
        # "planned for 6.3.0" next to a predicate that 6.3.0 shipped (docs/predicates/README.md, read
        # after 6.4.0). The class: a future phrase about a version that is out or was skipped, and a
        # pointer to the changelog's "Unreleased" section for an entry that has since been released.
        released = _released_versions(REPO)
        self.assertGreater(len(released), 0, "no released version read from CHANGELOG.md")
        files = _future_tense_scope(REPO, released)
        self.assertGreater(len(files), 0, "the guard read no file, which is not a green result")
        texts = [(p.relative_to(REPO).as_posix(), p.read_text(encoding="utf-8", errors="replace"))
                 for p in files]
        found = _future_tense_findings(texts, released)
        self.assertEqual(found, [], "future tense about a released version:\n" + "\n".join(found))

    def test_future_tense_guard_catches_a_planted_line(self):
        # The guard proves it reads: a planted line about a released version is reported, a line about
        # the release in preparation or a later one is not, and history ("since") is never reported.
        released = {"6.2.1", "6.3.0", "6.4.0"}
        planted = [("PLANTED.md", "x\n| `p/v9` | unreleased (planned for 6.3.0) | y |\n"),
                   ("PLANTED.py", '"""Removal is scheduled\nfor 6.2.2."""\n'),
                   ("PLANTED2.md", 'see CHANGELOG.md "Unreleased" for it\n')]
        found = _future_tense_findings(planted, released)
        self.assertEqual(len(found), 3, found)
        self.assertTrue(found[0].startswith("PLANTED.md:2: "), found)
        self.assertIn("skipped", found[1])
        quiet = [("OK.md", "planned for 6.5.0, scheduled for 6.6.0, since 6.3.0, until 6.2.0, "
                           "from 6.0.0 on, planned for 6.3.0.1\n")]
        self.assertEqual(_future_tense_findings(quiet, released), [])

    def test_a_shipped_subject_profile_is_not_described_as_deferred(self):
        # Found by hand with the class above, no version in the sentence: the intoto.py module docstring
        # called full model-artifact digests deferred, while `--subject-profile public-model` writes a
        # disclosed model's real sha256 since 2.0.0. Pinned so the sentence cannot come back.
        intoto_src = (REPO / "src" / "proofbundle" / "intoto.py").read_text(encoding="utf-8")
        self.assertNotIn("Full artifact digests come only once a model artifact", intoto_src)

    def test_non_claims_covers_decision_authorization_boundary(self):
        # WP-N2(c): NON_CLAIMS.md must state the decision boundary — a verified ALLOW is a record,
        # never an authorization/bearer token — and name the replay countermeasure. The decision
        # verify CLI help carries the same sentence.
        non_claims = (REPO / "docs" / "NON_CLAIMS.md").read_text(encoding="utf-8")
        self.assertIn("not an authorization", non_claims)
        self.assertIn("bearer token", non_claims)
        self.assertIn("require_audience", non_claims)
        self.assertIn("require_nonce", non_claims)
        self.assertIn("TEE", non_claims)
        from proofbundle.cli import build_parser
        import io as _io
        from contextlib import redirect_stdout as _rs
        parser = build_parser()
        buf = _io.StringIO()
        try:
            with _rs(buf):
                parser.parse_args(["decision", "verify", "--help"])
        except SystemExit:
            pass
        # argparse wraps help text at the terminal width (COLUMNS) — normalize whitespace so this
        # assertion is width-independent (six-lens review: COLUMNS=60 broke the raw assertIn).
        normalized = " ".join(buf.getvalue().split())
        self.assertIn("NOT an authorization or bearer token", normalized)
        # Codex pre-review 6 of B4: the help said such a receipt was not checked, while the verifier fails the
        # requested binding (exit 2) since 3.1.2; the help now says what the verifier does.
        self.assertIn("and so does a receipt without a validity object", normalized)

    def test_predicates_readme_names_every_namespace_the_code_writes(self):
        # CLOUD-NEBENBEFUNDE-DOKU-660-01, finding 1: docs/predicates/README.md said every predicate lives under
        # `b7n0de.com/proofbundle/predicates/`, while eval-result is `https://b7n0de.com/attestation/...` and
        # the eval-receipt view is `https://b7n0de.com/proofbundle/eval-receipt/v0.1`. The namespaces are
        # derived from the code: every module constant named *PREDICATE_TYPE* with an https value, minus its
        # last two path segments (`<name>/v<version>`). The intro paragraph must name exactly that set, as
        # backticked `https://.../` tokens, so a namespace can neither be missing nor be claimed without code.
        pattern = re.compile(r'(?m)^(?:[A-Z][A-Z0-9_]*_)?PREDICATE_TYPE[A-Z0-9_]*\s*=\s*"(https://[^"]+)"')
        types = set()
        for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
            types.update(pattern.findall(path.read_text(encoding="utf-8")))
        from proofbundle import agent_review, decision, intoto
        anchors = {intoto.PREDICATE_TYPE, intoto.EVAL_RESULT_V02_PREDICATE_TYPE, intoto.SVR_PREDICATE_TYPE,
                   intoto.TEST_RESULT_PREDICATE_TYPE, decision.DECISION_RECEIPT_PREDICATE_TYPE,
                   agent_review.AGENT_REVIEW_PREDICATE_TYPE_V03}
        self.assertLessEqual(anchors, types, "the constant scan misses predicate types the code imports")
        namespaces = {t.rstrip("/").rsplit("/", 2)[0] + "/" for t in types}
        text = (REPO / "docs" / "predicates" / "README.md").read_text(encoding="utf-8")
        intro = text.split("\n## ", 1)[0]
        claimed = set(re.findall(r"`(https://[^`\s]+/)`", intro))
        self.assertEqual(claimed, namespaces,
                         "docs/predicates/README.md intro must name exactly the predicateType namespaces "
                         f"the code writes; code {sorted(namespaces)}, docs {sorted(claimed)}")

    def test_predicates_table_has_a_row_for_every_own_predicate_type(self):
        # CLOUD-VORLAGE-DOKU-660-01, owner question 19: the table named relation/v0.1 (the profile embedded
        # in a receipt) but not the standalone predicate relation-statement/v0.1, and called agent-review
        # v0.2 the current version while the code writes v0.3 since 6.1.0. Every predicateType the code
        # declares under the two own table prefixes gets a row; in a family, no row but the newest says
        # "the current version".
        pattern = re.compile(r'(?m)^(?:[A-Z][A-Z0-9_]*_)?PREDICATE_TYPE[A-Z0-9_]*\s*=\s*"(https://[^"]+)"')
        prefixes = ("https://b7n0de.com/proofbundle/predicates/", "https://b7n0de.com/attestation/")
        own = set()
        for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
            own.update(t[len(p):] for t in pattern.findall(path.read_text(encoding="utf-8"))
                       for p in prefixes if t.startswith(p))
        self.assertIn("agent-review/v0.3", own, "the constant scan misses a type the code declares")
        self.assertIn("eval-result/v0.2", own, "the constant scan misses a type the code declares")
        text = (REPO / "docs" / "predicates" / "README.md").read_text(encoding="utf-8")
        table = text.split("\n## Predicates", 1)[1].split("\n## ", 1)[0]
        rows = {m.group(1): m.group(2) for m in re.finditer(r"(?m)^\| `([^`]+/v\d+\.\d+)` \|(.*)$", table)}
        missing = sorted(own - set(rows))
        self.assertEqual(missing, [], f"docs/predicates/README.md has no table row for {missing}")
        for name in own:
            family, version = name.rsplit("/v", 1)
            newer = [o for o in own if o.startswith(family + "/v") and o != name
                     and tuple(map(int, o.rsplit("/v", 1)[1].split("."))) > tuple(map(int, version.split(".")))]
            if newer:
                self.assertNotIn("the current version", rows[name], f"{name} is called current, {newer} exist")

    def test_intoto_module_docstring_names_the_export_profiles_and_default(self):
        # CLOUD-NEBENBEFUNDE-DOKU-660-01, finding 2: the docstring of proofbundle.intoto described only the
        # model-id-commitment view, while `proofbundle intoto` writes eval-result with the subject profile
        # `receipt` by default. The default is read from both export functions and from the CLI help.
        import inspect
        from proofbundle import intoto
        from proofbundle.cli import build_parser
        import io as _io
        from contextlib import redirect_stdout as _rs
        defaults = {inspect.signature(fn).parameters["subject_profile"].default
                    for fn in (intoto.export_eval_result_dsse, intoto.export_eval_result_v02_dsse)}
        self.assertEqual(len(defaults), 1, f"the export functions disagree on the default profile: {defaults}")
        default = defaults.pop()
        self.assertIn(default, intoto.SUBJECT_PROFILES)
        buf = _io.StringIO()
        try:
            with _rs(buf):
                build_parser().parse_args(["intoto", "--help"])
        except SystemExit:
            pass
        self.assertIn(f"default: {default}", " ".join(buf.getvalue().split()))
        doc = " ".join((intoto.__doc__ or "").split())
        for profile in intoto.SUBJECT_PROFILES:
            self.assertIn(f"``{profile}``", doc, f"intoto docstring does not name the profile {profile}")
        self.assertIn(f"``{default}`` (the default", doc, "intoto docstring does not name the default profile")
        for ptype in intoto.EVAL_RESULT_PREDICATE_TYPES:
            self.assertIn(ptype, doc, f"intoto docstring does not name {ptype}")


class TestRecordsUnderResidualRisk(unittest.TestCase):
    """The residual-risk records moved to docs/residual_risk/.

    The future-tense guard treats a record of a release that is out as history in that folder too. The
    one link a moved record carried to a record that stayed at the root (RESTRISIKO_640.md to
    RESTRISIKO_600.md) is written from the new folder, so `test_no_broken_internal_doc_links` holds it
    with no exception in the link check.
    """

    def test_a_closed_record_under_residual_risk_is_history_and_RED_for_the_open_one(self):
        released = {"6.6.0", "6.6.1"}
        self.assertTrue(_is_closed_record("docs/residual_risk/RESTRISIKO_661.md", released))
        self.assertTrue(_is_closed_record("docs/residual_risk/RESTRISIKO_610_NACHTRAG_20260924.md",
                                          {"6.1.0"}))
        self.assertFalse(_is_closed_record("docs/residual_risk/RESTRISIKO_670.md", released),
                         "the record of the release in preparation stays read")
        self.assertFalse(_is_closed_record("docs/other/RESTRISIKO_661.md", released),
                         "only the folders of records count")


if __name__ == "__main__":
    unittest.main()
