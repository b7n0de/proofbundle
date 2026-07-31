"""Repo hygiene: what the repository SHIPS and what it CLAIMS (deep-gate lane F_repo_hygiene).

Three properties, each pinned by a computation rather than by prose:

L6-01  No built distribution artefact is tracked in the source repo, and the ignore rule that keeps
       them out is a DISCOVERY pattern, not an enumeration of the directories somebody remembered.
       (main carried dist_final/*.whl, dist_final/*.tar.gz and dist_pkgtest6/*.tar.gz — the git repo
       was a distribution channel for a clone / mirror / air-gapped `pip install dist_final/*.whl`.)

L6-02  The hermetic-cleanroom step of published-artifact-gate.yml MEASURES the property it names.
       It claimed "a bare [eval] install has no collection error" while installing the [test] extra
       first, so the named defence could not fail the gate (ledger class
       `vacuous_seam_passes_for_a_reason_other_than_the_defence_it_names`, new surface).

L2-04  merkle.verify_inclusion's trust-precondition docstring states the tree-size ambiguity as a
       number this suite RE-DERIVES, not as prose. The old wording said "adjacent size N+/-1"; the
       measured law is 2**(ceil(log2 N) - 1) falsely claimable sizes, i.e. half the enclosing perfect
       tree (between N/2 and N-1) — SPEC.md's "path-shape equivalence".

Design notes, so the guards cannot rot into decoration:
  * Every check is a plain function over data. The tests drive each function BOTH ways: over the real
    artefact (must be clean) and over the literal pre-fix artefact (must report problems). A guard
    that was never red proves nothing.
  * Each check has an anti-tautology twin that guts the detector and shows the planted violation stops
    being caught.
  * No probe mutates the working tree: the pre-fix inputs are in-memory literals, `git ls-files` and
    `git check-ignore` are read-only.
  * The docstring check is an ALLOWLIST (a parseable, re-derivable claim must be PRESENT), not a
    blocklist of known-bad phrasings — an unknown rewrite falls on the rejected side automatically.
"""
from __future__ import annotations

import math
import pathlib
import re
import shutil
import subprocess

import pytest

from proofbundle.merkle import inclusion_proof, merkle_tree_hash, verify_inclusion

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "published-artifact-gate.yml"

if not WORKFLOW.exists() or not (REPO_ROOT / ".git").exists() or shutil.which("git") is None:
    # Running from an extracted sdist / installed wheel (the sdist prunes .github and is not a git
    # checkout), or git is unavailable. These assertions are about the REPO layout — honest skip.
    pytest.skip(
        "repo-context module: asserts repo/CI layout and git state, N/A outside a git checkout",
        allow_module_level=True,
    )


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=True, capture_output=True, text=True,
    ).stdout


# --------------------------------------------------------------------------------------------------
# L6-01 — no built distribution artefact is tracked
# --------------------------------------------------------------------------------------------------

# Discovery predicates. A wheel is by construction a build output; a top-level dist* directory is a
# build-output directory; a PEP 625 style `<name>-<version>.tar.gz` basename is a source distribution.
_DIST_DIR_RE = re.compile(r"^dist([-_.].*)?/")
_SDIST_NAME_RE = re.compile(r"^[A-Za-z0-9._]+-[0-9][A-Za-z0-9._!+]*\.tar\.gz$")


def is_distribution_artefact(path: str) -> bool:
    """True iff ``path`` (repo-relative, POSIX) looks like a built distribution artefact."""
    if path.endswith(".whl"):
        return True
    if _DIST_DIR_RE.match(path):
        return True
    return bool(_SDIST_NAME_RE.match(path.rsplit("/", 1)[-1]))


def find_distribution_artefacts(tracked_paths) -> list[str]:
    """The subset of ``tracked_paths`` that are built distribution artefacts (sorted)."""
    return sorted(p for p in tracked_paths if is_distribution_artefact(p))


def tracked_paths() -> list[str]:
    return [p for p in _git("ls-files", "-z").split("\0") if p]


# The three artefacts this lane deleted from the WORKING TREE. They are still in the git index until a
# maintainer runs `git rm --cached` on them (this lane may not run git commands), so they are pinned
# here as an ENUMERATED, honest gap: a fourth artefact anywhere in the tree fails the test below, and
# each of these fails again the moment its bytes reappear on disk. Once the removal is committed the
# entries simply stop matching and should be deleted from this set.
PENDING_GIT_RM = frozenset({
    "dist_final/proofbundle-3.6.1-py3-none-any.whl",
    "dist_final/proofbundle-3.6.1.tar.gz",
    "dist_pkgtest6/proofbundle-3.6.1.tar.gz",
})


def test_no_unexpected_distribution_artefact_is_tracked():
    """Any tracked build artefact other than the three pinned pending-removal paths fails."""
    found = set(find_distribution_artefacts(tracked_paths()))
    unexpected = sorted(found - PENDING_GIT_RM)
    assert unexpected == [], (
        "built distribution artefacts are tracked in the source repo — the git repo must not be a "
        f"distribution channel: {unexpected}"
    )


def test_pending_removal_artefacts_are_gone_from_the_working_tree():
    """The pinned artefacts must not exist on disk; a restored artefact is a regression."""
    present = sorted(p for p in PENDING_GIT_RM if (REPO_ROOT / p).exists())
    assert present == [], (
        "distribution artefacts are back in the working tree (they must stay deleted; the git index "
        f"entry is removed with `git rm --cached`): {present}"
    )


def test_detector_catches_a_new_build_output_directory():
    """MUST-FAIL NEGATIVE (synthetic): the next dist_pkgtest7/ is caught without editing the detector."""
    planted = [
        "src/proofbundle/merkle.py",
        "tests/test_sdist_packaging_361.py",
        "dist_pkgtest7/proofbundle-9.9.9.tar.gz",
        "dist-rc/proofbundle-9.9.9-py3-none-any.whl",
        "somewhere/deep/proofbundle-9.9.9-py3-none-any.whl",
    ]
    assert find_distribution_artefacts(planted) == [
        "dist-rc/proofbundle-9.9.9-py3-none-any.whl",
        "dist_pkgtest7/proofbundle-9.9.9.tar.gz",
        "somewhere/deep/proofbundle-9.9.9-py3-none-any.whl",
    ]


def test_detector_does_not_fire_on_source_files():
    """Negative control: ordinary sources, docs and fixtures are not distribution artefacts."""
    assert find_distribution_artefacts([
        "src/proofbundle/merkle.py",
        "tests/test_sdist_packaging_361.py",
        "SPEC.md",
        "docs/readiness_pack/MANIFEST.sha256",
        "conformance/vectors/tree.json",
    ]) == []


def test_anti_tautology_gutted_artefact_detector_stops_catching():
    """ANTI-TAUTOLOGY TWIN: blind the predicate and the planted artefacts go unnoticed."""
    planted = ["dist_pkgtest7/proofbundle-9.9.9.tar.gz", "dist_final/x.whl"]
    assert find_distribution_artefacts(planted) == sorted(planted)  # the real detector sees them
    gutted = sorted(p for p in planted if False)  # the decoration: a predicate that never fires
    assert gutted == [], "the gutted detector must be blind — otherwise this twin proves nothing"


# --- the ignore rule, measured by EFFECT (git check-ignore), not by reading .gitignore for a string ---

def is_ignored(path: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", path],
        capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):
        pytest.fail(f"git check-ignore failed for {path!r}: rc={proc.returncode} {proc.stderr}")
    return proc.returncode == 0


# Directories nobody has created yet: the point of a discovery pattern is that they need no edit.
UNSEEN_BUILD_OUTPUTS = (
    "dist_pkgtest7/proofbundle-9.9.9.tar.gz",
    "dist_pkgtest99/proofbundle-9.9.9.tar.gz",
    "dist-nightly/proofbundle-9.9.9.tar.gz",
    "dist_final/proofbundle-9.9.9-py3-none-any.whl",
    "dist_pkgtest6/proofbundle-9.9.9.tar.gz",
    "anywhere/proofbundle-9.9.9-py3-none-any.whl",
)

NOT_BUILD_OUTPUTS = (
    "src/proofbundle/merkle.py",
    "tests/test_sdist_packaging_361.py",
    "SPEC.md",
    ".github/workflows/published-artifact-gate.yml",
)


def test_gitignore_is_a_discovery_pattern_for_unseen_build_directories():
    """MUST-FAIL NEGATIVE (effect): every unseen build-output path is ignored without a new line."""
    missed = [p for p in UNSEEN_BUILD_OUTPUTS if not is_ignored(p)]
    assert missed == [], (
        "the ignore rule is still an enumeration — these build outputs would be committable: "
        f"{missed}"
    )


def test_gitignore_does_not_swallow_sources():
    """Negative control: the discovery pattern must not hide real source files."""
    swallowed = [p for p in NOT_BUILD_OUTPUTS if is_ignored(p)]
    assert swallowed == [], f"the ignore pattern is too broad, it hides sources: {swallowed}"


# --------------------------------------------------------------------------------------------------
# L6-02 — the cleanroom step must MEASURE the bare-[eval] property it names
# --------------------------------------------------------------------------------------------------

_TEST_EXTRA_INSTALL_RE = re.compile(r"pip install .*\[test\]")
_COLLECT_ONLY_RE = re.compile(r"pytest\b.*(--co\b|--collect-only\b)")


def _ordering_problems(script: str) -> list[str]:
    """The CLASS rule: wherever a [test] extra is installed, the bare-install collection property must
    have been measured BEFORE that install, otherwise the named defence cannot fail the gate."""
    lines = [ln.strip() for ln in script.splitlines() if ln.strip()]
    collect_at = next((i for i, ln in enumerate(lines) if _COLLECT_ONLY_RE.search(ln)), None)
    extra_at = next((i for i, ln in enumerate(lines) if _TEST_EXTRA_INSTALL_RE.search(ln)), None)
    if extra_at is None:
        return []  # no [test] extra: the vacuity cannot arise here
    if collect_at is None:
        return ["no collection-only pytest run: the bare-[eval] property is never measured"]
    if collect_at > extra_at:
        return [
            "the [test] extra is installed before the collection run, so the named bare-[eval] "
            "property cannot fail this gate (vacuous seam)"
        ]
    return []


def cleanroom_step_problems(script: str) -> list[str]:
    """Problems with the shipped-test-suite cleanroom step's script.

    The named defence is "a bare [eval] install has no collection error". It is measurable only if a
    collection run happens BEFORE the [test] extra enters the venv. Allowlist shape: the measurement
    must be PRESENT and EARLIER; anything else (missing, later, absent measurement) is a problem.
    """
    problems = list(_ordering_problems(script))
    if not _TEST_EXTRA_INSTALL_RE.search(script):
        problems.append("no [test] extra install: this step no longer runs the shipped suite")
    if not _COLLECT_ONLY_RE.search(script):
        problems.append("no collection-only pytest run: the bare-[eval] property is never measured")
    return sorted(set(problems))


def jobs_installing_the_test_extra() -> dict[str, str]:
    """Every CI job (any workflow) that installs a ``[test]`` extra, mapped to its whole run script.

    DISCOVERY, not enumeration: the sweep finds the sites, so a second job with the same shape is
    covered the moment it is added rather than when somebody remembers this file.
    """
    yaml = pytest.importorskip("yaml", reason="PyYAML is a [test]-extra dependency")
    out: dict[str, str] = {}
    for wf in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            script = "\n".join(
                str(s["run"]) for s in (job.get("steps") or []) if isinstance(s, dict) and "run" in s
            )
            if _TEST_EXTRA_INSTALL_RE.search(script):
                out[f"{wf.name}::{job_id}"] = script
    return out


def cleanroom_step_script() -> str:
    yaml = pytest.importorskip("yaml", reason="PyYAML is a [test]-extra dependency")
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = doc["jobs"]["hermetic-cleanroom"]["steps"]
    hits = [s for s in steps if "shipped test suite" in str(s.get("name", "")).lower()]
    assert len(hits) == 1, f"expected exactly one shipped-test-suite step, found {len(hits)}"
    return hits[0]["run"]


# The literal pre-fix step (main HEAD 2e5807a) — the vacuous form this test must reject.
PRE_FIX_CLEANROOM_STEP = """\
/tmp/clean/bin/pip install --quiet "$(ls dist/*.tar.gz)[test]"
mkdir -p /tmp/sdisttree
tar -xzf "$(ls dist/*.tar.gz)" -C /tmp/sdisttree --strip-components=1
cd /tmp/sdisttree
test ! -e audit_artifacts/findings_register_361.json
/tmp/clean/bin/python -m pytest tests/ -q -p no:cacheprovider
"""


def test_real_cleanroom_step_measures_the_bare_eval_property():
    assert cleanroom_step_problems(cleanroom_step_script()) == []


def test_every_job_installing_the_test_extra_measures_the_bare_install_first():
    """CLASS sweep: the rule is enforced over every discovered site, not at the one known site."""
    sites = jobs_installing_the_test_extra()
    assert sites, "the sweep found no [test]-extra install at all — it would pass vacuously"
    problems = {name: _ordering_problems(script) for name, script in sites.items()}
    assert {k: v for k, v in problems.items() if v} == {}, problems


def test_pre_fix_cleanroom_step_is_rejected():
    """MUST-FAIL NEGATIVE: the shipped-at-HEAD form names a defence it cannot fail on."""
    problems = cleanroom_step_problems(PRE_FIX_CLEANROOM_STEP)
    assert problems, "the pre-fix step must be rejected, otherwise this guard is a decoration"
    assert any("never measured" in p for p in problems)


def test_reordered_step_is_rejected():
    """A collection run that happens AFTER the [test] install is still vacuous."""
    reordered = (
        '/tmp/clean/bin/pip install --quiet "$SDIST[test]"\n'
        "/tmp/clean/bin/python -m pytest tests/ --co -q\n"
        "/tmp/clean/bin/python -m pytest tests/ -q\n"
    )
    assert any("vacuous seam" in p for p in cleanroom_step_problems(reordered))


def test_anti_tautology_gutted_cleanroom_checker_stops_catching():
    """ANTI-TAUTOLOGY TWIN: blind the order check and the vacuous step passes."""
    def gutted(script: str) -> list[str]:
        return []  # the decoration: a checker that can never report a problem

    assert cleanroom_step_problems(PRE_FIX_CLEANROOM_STEP)  # the real checker catches it
    assert gutted(PRE_FIX_CLEANROOM_STEP) == []


# --------------------------------------------------------------------------------------------------
# L2-04 — the merkle trust-precondition docstring is pinned to a computed number
# --------------------------------------------------------------------------------------------------

def claimable_tree_sizes(n: int, index: int) -> list[int]:
    """Every tree size a verifier accepts for one HONEST (leaf, index, proof, root) of an n-leaf tree.

    This is the measurement behind the docstring claim: the audit path is generated once, honestly,
    for ``index`` in a tree of ``n`` leaves, and every claimed ``tree_size`` that still verifies under
    the same root is collected.
    """
    leaves = [f"leaf-{j}".encode() for j in range(n)]
    root = merkle_tree_hash(leaves)
    proof = inclusion_proof(leaves, index)
    ceiling = 4 * n + 8
    accepted = [s for s in range(1, ceiling) if verify_inclusion(leaves[index], index, s, proof, root)]
    assert accepted and accepted[-1] < ceiling - 1, "search ceiling truncated the class"
    return accepted


def max_claimable_class(n: int) -> int:
    return max(len(claimable_tree_sizes(n, i)) for i in range(n))


# Allowlist parsers: the docstring must CARRY these re-derivable claims. A rewrite that drops them
# (including a rewrite back to vague prose) fails, without this test enumerating bad phrasings.
_EXAMPLE_RE = re.compile(
    r"index\s+(\d+)\s+of\s+a\s+(\d+)-leaf\s+tree\s+verifies\s+under\s+every\s+claimed\s+size\s+in\s+"
    r"\[\s*(\d+)\s*,\s*(\d+)\s*\]",
    re.IGNORECASE,
)
_LAW_RE = re.compile(r"2\*\*\(\s*ceil\(log2 N\)\s*-\s*1\s*\)", re.IGNORECASE)


def docstring_problems(doc: str) -> list[str]:
    """Problems with a trust-precondition docstring's statement of the tree-size ambiguity."""
    problems = []
    if not _LAW_RE.search(doc or ""):
        problems.append(
            "no machine-checkable ambiguity law: the docstring must state 2**(ceil(log2 N) - 1)"
        )
    m = _EXAMPLE_RE.search(doc or "")
    if m is None:
        problems.append(
            "no re-derivable measured example of the form "
            "'index I of a N-leaf tree verifies under every claimed size in [A, B]'"
        )
        return problems
    index, n, lo, hi = (int(g) for g in m.groups())
    measured = claimable_tree_sizes(n, index)
    if measured != list(range(lo, hi + 1)):
        problems.append(
            f"the stated example [{lo}, {hi}] for index {index} of a {n}-leaf tree does not match the "
            f"measurement {measured[0]}..{measured[-1]} ({len(measured)} sizes)"
        )
    return problems


# The literal pre-fix docstring sentence (main HEAD 2e5807a) — the understating form.
PRE_FIX_DOCSTRING = (
    "This function verifies the audit path for the given (leaf_index, tree_size, root) triple; it "
    "does not independently authenticate tree_size, so a proof honestly valid for size N can also "
    "satisfy a falsely-claimed adjacent size N±1 under the same root."
)


def test_shipped_docstring_claim_is_re_derivable():
    assert docstring_problems(verify_inclusion.__doc__) == []


def test_pre_fix_docstring_is_rejected():
    """MUST-FAIL NEGATIVE: prose without a re-derivable number is rejected."""
    problems = docstring_problems(PRE_FIX_DOCSTRING)
    assert len(problems) == 2, problems
    assert any("ambiguity law" in p for p in problems)
    assert any("measured example" in p for p in problems)


def test_a_wrong_measured_example_in_the_docstring_is_caught():
    """A number that does not survive re-derivation fails, so the doc cannot drift silently."""
    doctored = (
        "constrained up to 2**(ceil(log2 N) - 1) sizes. Measured: index 4 of a 10-leaf tree verifies "
        "under every claimed size in [9, 11]."
    )
    problems = docstring_problems(doctored)
    assert any("does not match the measurement" in p for p in problems), problems


def test_anti_tautology_gutted_docstring_checker_stops_catching():
    """ANTI-TAUTOLOGY TWIN: drop the allowlist requirements and the old prose sails through."""
    def gutted(doc: str) -> list[str]:
        return []  # the decoration: no claim is required, so nothing is ever wrong

    assert docstring_problems(PRE_FIX_DOCSTRING)  # the real checker rejects it
    assert gutted(PRE_FIX_DOCSTRING) == []


def test_ambiguity_law_holds_over_a_sweep():
    """The docstring's law is not prose: the worst-case class over n = 2..40 is exactly half the
    enclosing perfect tree, i.e. between N/2 and N-1 falsely claimable sizes — never N+/-1."""
    for n in range(2, 41):
        assert max_claimable_class(n) == 2 ** (math.ceil(math.log2(n)) - 1), n
    # And the understatement is refuted by the number itself: at n=33 an honest proof is accepted for
    # 32 different claimed sizes, not 3.
    assert len(claimable_tree_sizes(33, 0)) == 32
    assert claimable_tree_sizes(33, 0) == list(range(33, 65))


def test_spec_example_matches_the_shipped_docstring_example():
    """SPEC.md's own measured example (index 4 of a 10-leaf tree -> n' in [9..16]) is the one the
    docstring now quotes, so doc and spec cannot contradict each other again."""
    spec = (REPO_ROOT / "SPEC.md").read_text(encoding="utf-8")
    assert "path-shape equivalence" in spec
    assert "n′ ∈ [9..16]" in spec or "[9..16]" in spec
    assert claimable_tree_sizes(10, 4) == list(range(9, 17))
