"""Shared pytest configuration.

PKG-2026-0718-01 (RE-GATE): the sdist ships tests/ (MANIFEST graft) so `pip install <sdist> && pytest`
is a genuinely self-testable package. A SPECIFIC SET of tests, however, assert facts about the
REPO / CI / Rust / docs LAYOUT — the contents of `.github/workflows`, the Rust verifier source under
`tools/`, `SPEC.md` / `README.md` / `CITATION.cff`, and the audit records — material the sdist
DELIBERATELY prunes (it is not a Python-package artifact; shipping the 138M Rust tree or the CI configs
in a Python sdist is a category error). Those tests are meaningless outside a git checkout, so they SKIP
when the repo-only markers are absent (i.e. when running from an extracted sdist / installed wheel),
turning 25 false runtime FAILURES into honest SKIPs — the sdist then runs clean. In a real checkout (CI)
every marker is present, NOTHING is skipped, and coverage is exactly as before (this file is a pure no-op
in the repo). This is the No-Fake honest form of "self-testable": the package-level tests run; the
repo-layout tests announce themselves as N/A rather than failing or being silently dropped.
"""
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# A git checkout always carries these; the sdist prunes/omits them (.github, the Rust tree, the spec
# source). Their ABSENCE means we are running from a distributed artifact, not the repo.
_REPO_ONLY_MARKERS = (".github", "tools", "SPEC.md")

# The exact repo-context tests (module stem :: test method) whose assertions are about the repo/CI/Rust/
# docs LAYOUT rather than the installed package. Derived from the from-sdist run: these read files the
# sdist does not (and should not) ship. Explicit + documented — a new repo-context test adds its id here.
# NOTE: test_renewal_policy::test_shipped_example_policy_loads_and_evaluates is NOT here — its example
# (docs/adr/renewal_policy.example.json) is a genuinely shipped artifact, fixed by `graft docs/adr`.
_REPO_CONTEXT_TESTS = frozenset({
    # DER RUECKFALL, GEMESSEN statt angenommen. Diese Tests erreichen das Repo NICHT ueber ein
    # Pfad-Literal im eigenen Modul (Import aus scripts/, dynamisches Laden, glob auf .github), also kann
    # die Ableitung sie nicht sehen. Ermittelt, indem die Liste im entpackten sdist GELEERT und die Suite
    # gefahren wurde: was dann faellt, gehoert hierher — und nur das.
    #
    # Eine erste Fassung dieses Fixes strich auf drei Module zusammen, weil ich die uebrigen fuer
    # redundant HIELT. Sieben Tests fielen daraufhin. Die Menge ist messbar; sie zu schaetzen war der
    # Fehler.
    #
    # test_audit_candidate_360 / test_roadmap_frontload_foundations: importieren scripts/*.py und laufen
    #   ueber DEREN Repo-Zugriffe.
    "test_audit_candidate_360::test_matrix_is_ready_and_has_33_checks",
    "test_audit_candidate_360::test_c12_2_green_on_real_repo",
    "test_audit_candidate_360::test_c1_1_green_on_real_repo",
    "test_audit_candidate_360::test_c12_2_fails_on_tampered_register",
    "test_audit_candidate_360::test_c12_2_fails_on_foreign_key_register",
    "test_roadmap_frontload_foundations::test_pack_is_grounded_in_real_artifacts",
    "test_roadmap_frontload_foundations::test_released_version_has_audit_record",
    # test_claims_hygiene: scannt die Doku ueber scripts/claims_hygiene_check, das seine Pfadmenge selbst
    #   fuehrt.
    "test_claims_hygiene::test_real_docs_are_clean",
    "test_claims_hygiene::test_every_default_doc_exists_and_scan_covers_all",
    "test_claims_hygiene::test_injected_overclaim_in_every_listed_doc_fails",
    "test_claims_hygiene::test_main_default_run_includes_cli_surface",
    "test_claims_hygiene::test_new_priority_docs_are_in_scan_set_and_clean",
    # test_rust_parity_gate: prueft den Rust-Baum ueber scripts/rust_parity_gate.
    "test_rust_parity_gate::test_real_repo_main_rs_has_the_expected_subcommands",
    "test_rust_parity_gate::test_real_repo_registry_is_honest_strict_mode_exits_0",
    # test_fork_pr_secret_isolation: glob ueber .github/workflows, kein benanntes Literal.
    "test_fork_pr_secret_isolation::test_repo_workflows_are_isolation_safe",
})


def running_in_repo_checkout() -> bool:
    """True iff the repo-only markers are present (a git checkout / CI), False from a distributed sdist."""
    return any((_REPO_ROOT / m).exists() for m in _REPO_ONLY_MARKERS)


# ── The skip set is DERIVED, not enumerated (deep gate finding L6-01, P1) ────────────────────────────
#
# The frozenset above IS the defect. Commit 2c5e7a5 already appended ids to it once, and the gate found six
# MORE tests failing from an extracted sdist at HEAD — because a list of ids cannot know about the method
# somebody adds tomorrow to a module that is already on it. The finding is explicit: appending the six is
# the instance fix and it re-opens.
#
# So the question is answered by MEASUREMENT instead: does this test module read a ROOT-relative path that
# does not exist here? If it does, we are outside a checkout and the module's assertions are about material
# the sdist deliberately prunes — an honest SKIP, never a FAIL. A method added to such a module tomorrow is
# covered the moment it is written, because nothing has to be remembered.
#
# GRANULARITY, deliberately the module. A single item's file reads cannot be attributed statically without
# guessing, and guessing here means either a false FAIL (loud, and the pressure is then to loosen the guard)
# or a false PASS. Skipping the module is the honest, conservative direction: from the sdist it announces
# N/A instead of running less than it claims. In a checkout every path exists and this whole path is a no-op.
_ROOT_NAMEN = {"REPO", "ROOT", "REPO_ROOT", "_REPO_ROOT", "PROJECT_ROOT"}


def _wurzel_relative_pfade(quelle: str) -> set[str]:
    """String literals used as ``<repo-root-ish> / "literal"`` in this module's source."""
    import ast  # noqa: PLC0415 - only needed on the from-sdist path

    try:
        baum = ast.parse(quelle)
    except SyntaxError:
        return set()

    def _ist_wurzel(knoten) -> bool:
        # REPO / "x"  ·  _REPO_ROOT / "x"  ·  (Path(__file__).resolve().parents[1]) / "x"  ·  REPO / "a" / "b"
        if isinstance(knoten, ast.Name):
            return knoten.id in _ROOT_NAMEN
        if isinstance(knoten, ast.Subscript):
            return _ist_wurzel(knoten.value)
        if isinstance(knoten, ast.Attribute):
            return knoten.attr == "parents" or _ist_wurzel(knoten.value)
        if isinstance(knoten, ast.Call):
            return _ist_wurzel(knoten.func)
        if isinstance(knoten, ast.BinOp) and isinstance(knoten.op, ast.Div):
            return _ist_wurzel(knoten.left)
        return False

    def _kette(knoten):
        """(ist_wurzelrelativ, segmente) — die GANZE Kette, nicht ihre Teile.

        Die erste Fassung sammelte jedes Segment einzeln, sodass aus
        ``parents[1] / "src" / "proofbundle"`` auch ``proofbundle`` als wurzelrelativ galt. Das liegt
        aber unter ``src/``, existiert an der Wurzel nicht, und so meldete die Ableitung 23 Module
        selbst in einem vollstaendigen Checkout. Ein zerlegter Pfad ist ein anderer Pfad.
        """
        if isinstance(knoten, ast.BinOp) and isinstance(knoten.op, ast.Div):
            links_ok, teile = _kette(knoten.left)
            if not links_ok:
                return (False, [])
            if isinstance(knoten.right, ast.Constant) and isinstance(knoten.right.value, str):
                return (True, teile + [knoten.right.value])
            return (False, [])          # ein variables Segment macht den Rest unbestimmbar
        return (_ist_wurzel(knoten), [])

    gefunden: set[str] = set()
    for x in ast.walk(baum):
        if not (isinstance(x, ast.BinOp) and isinstance(x.op, ast.Div)):
            continue
        ok, teile = _kette(x)
        if ok and teile:
            gefunden.add("/".join(teile))
    return gefunden


def modul_ist_repo_kontext(pfad: pathlib.Path, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """True iff this test module reads a root-relative path that is ABSENT here.

    Absence is the whole signal, so an unreadable module is NOT silently treated as fine: it cannot be
    shown to be package-only, and outside a checkout the safe answer is to skip it.
    """
    try:
        quelle = pfad.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return True
    # THE FULL PATH, and it has to be the full path: the sdist prunes LEAVES under shipped directories
    # too (``docs/`` is grafted but ``docs/IN_TOTO_PROFILE.md`` is pruned), so a first-segment rule misses
    # exactly the six tests this finding is about. An intermediate attempt used the first segment because
    # the full-path form flagged 23 modules even in a complete checkout — but that was never the rule's
    # fault: the path CHAINS were being decomposed (see _kette), so ``src`` / ``proofbundle`` was read as
    # a root-level ``proofbundle``. With the chain joined correctly the full-path rule is precise, and the
    # narrowing would have traded a real defect for a comfortable green.
    return any(not (wurzel / rel).exists() for rel in _wurzel_relative_pfade(quelle))


def pytest_collection_modifyitems(config, items):
    if running_in_repo_checkout():
        return  # a real checkout: run everything (the CI path — coverage unchanged, pure no-op)
    skip = pytest.mark.skip(reason="repo-context test: asserts repo/CI/Rust/docs layout not shipped in the "
                                   "sdist — N/A outside a git checkout (PKG-2026-0718-01)")
    entschieden: dict[str, bool] = {}
    for item in items:
        datei = pathlib.Path(str(getattr(item, "fspath", "")))
        stem = datei.stem
        method = getattr(item, "originalname", None) or item.name
        if stem not in entschieden:
            entschieden[stem] = modul_ist_repo_kontext(datei)
        # DERIVED first; the explicit list stays as a documented fallback for modules whose repo
        # dependency is not visible as a path literal (an env probe, a subprocess into the tree).
        if entschieden[stem] or f"{stem}::{method}" in _REPO_CONTEXT_TESTS:
            item.add_marker(skip)
