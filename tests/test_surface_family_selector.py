"""Which surfaces a class rule sweeps must be DERIVED from what is shipped, not spelled out by name.

THE CLASS. A forcing function exists so that a defect class cannot come back on a surface nobody thought
of. When such a rule picks its own population by matching NAMES, it has quietly become a blocklist of the
spellings that were known on the day it was written: it has to be COMPLETE to work, and every new naming
convention extends it. The never-raise message-rendering rule was written that way — a regex over
``verify_``/``load_``/``check_``/``decode_``/``validate_``/… — and the whole ``evaluate_`` family fell
outside it, exported ``evaluate_renewal_policy`` included, while the prose describing the rule claimed that
family was swept. The rule was not wrong about the sites it saw. It was blind, and blindness produces no
output, so nothing looked broken.

THE INVERSION. The deciding property here is PROVENANCE, not spelling: "is this surface part of the shipped
public API of the package". That is discoverable from the tree, so it is discovered:

* the population is every public top-level function and every public method of a public class in every
  public module under ``src/proofbundle`` — found by globbing and parsing, never listed here;
* a surface with NO recorded decision is COVERED. Unknown forms therefore land on the CHECKED side by
  default, which is the direction a blocklist gets wrong;
* the only thing enumerated is the set of EXCLUSIONS, each with a reason code from a closed vocabulary.
  An exclusion list has to be complete to PERMIT something, so an omission costs coverage of nothing.

WHAT THIS FILE OWES ITS READER. Three properties, each with a test: the population is really derived (a
surface that exists only at runtime in a temporary package is found without editing anything here), the
decisions are honest (a closed reason vocabulary, no stale entries), and the mechanism can go red at all
(blind the discovery and the planted surface stops being seen).
"""
from __future__ import annotations

import ast
import pathlib
import re
import textwrap
from dataclasses import dataclass

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"


@dataclass(frozen=True)
class Surface:
    """One discovered public surface: where it lives, what it is called, and the module it came from.

    ``module_functions`` carries every function AST node of the owning module (nested ones included) so a
    caller can follow one step of call closure into the private helpers this surface uses — a message built
    inside a helper is still a message on this surface's path.
    """

    module: str          # POSIX path relative to the package root; unique, unlike the bare basename
    qualname: str        # "evaluate_renewal_policy" or "RenewalPolicy.from_dict"
    node: ast.AST
    module_functions: dict

    @property
    def key(self) -> str:
        return f"{self.module}::{self.qualname}"


# ── the closed vocabulary of exclusion reasons ────────────────────────────────────────────────────────
#
# A decision may carry ONLY one of these codes. "Excluded because it looked fine" is not expressible, and a
# reader can tell from the code alone what kind of claim is being made.
REASON_CODES = {
    "OPEN_UNBOUNDED_RENDERING":
        "A confirmed violation of the never-raise message-rendering rule that is not closed yet. Pinned so "
        "the gap cannot grow silently and so a fix has to remove its line (progress stays visible). This is "
        "an admission, not an exemption: the surface is still wrong.",
}


def _module_is_public(rel: pathlib.PurePosixPath) -> bool:
    """A module is public when no path component is private. ``__init__.py`` is the package itself."""
    return all((not part.startswith("_")) or part == "__init__.py" for part in rel.parts)


def _public_defs(tree: ast.Module):
    """Public top-level functions, and public methods of public classes, as ``(qualname, node)``."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            yield node.name, node
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and not sub.name.startswith("_"):
                    yield f"{node.name}.{sub.name}", sub


def discover_public_surfaces(root: pathlib.Path = PACKAGE_ROOT) -> dict[str, Surface]:
    """Every public surface the package ships, found by walking the tree.

    Nothing about the result depends on a name pattern, so a surface named in a convention that does not
    exist yet is in scope the day it is written.
    """
    found: dict[str, Surface] = {}
    for path in sorted(root.rglob("*.py")):
        rel = pathlib.PurePosixPath(path.relative_to(root).as_posix())
        if not _module_is_public(rel):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        functions = {n.name: n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for qualname, node in _public_defs(tree):
            surface = Surface(str(rel), qualname, node, functions)
            found[surface.key] = surface
    return found


# ── the enumerated exclusions ─────────────────────────────────────────────────────────────────────────
#
# Every key below is a surface that is NOT held to the never-raise message-rendering rule right now, with
# the reason. Everything else — including everything written tomorrow — is covered by default.
#
# All current entries are OPEN_UNBOUNDED_RENDERING: real violations of the same class, made visible by the
# inversion, living in files this change does not own. They are pinned rather than hidden. `test_
# no_pinned_open_surface_is_already_fixed` fails if one of them is repaired without being unpinned, so the
# list can only shrink honestly.
#
# One entry is missing from this list for a reason worth recording. ``automation_verdict.py::
# policy_standing_errors`` did not exist when the inversion was written; it appeared during the same round,
# named in a convention no pattern here anticipates, and the derived population flagged it rendering
# ``purpose`` unbounded the moment it was saved. It was then repaired at the source, and the ratchet in
# ``test_no_pinned_open_surface_is_already_fixed`` refused to let its pin survive the repair. Both halves
# of the mechanism were exercised on live code rather than on a fixture: an unanticipated surface fell onto
# the checked side by itself, and the exclusion list could not outlive the violation it admitted.
SURFACE_DECISIONS: dict[str, str] = {
    key: "OPEN_UNBOUNDED_RENDERING" for key in (
        "adapters/eee.py::from_eee_dataset",
        "adapters/inspect_ai.py::from_inspect_ai_log",
        "adapters/lm_eval.py::from_lm_eval_results",
        "anchors_rootcommit.py::build_preimage",
        "checkpoint.py::checkpoint_note",
        "checkpoint.py::cosign_checkpoint",
        "checkpoint.py::cosign_checkpoint_mldsa",
        "checkpoint.py::cosign_vkey",
        "checkpoint.py::cosign_vkey_mldsa",
        "checkpoint.py::sign_checkpoint",
        "checkpoint.py::vkey",
        "decision.py::build_decision_statement",
        "intoto.py::resolve_subject",
        "outcome.py::build_outcome_statement",
        "policy.py::evaluate_decision_policy",
        "policy.py::explain_policy",
        "policy.py::lint_policy",
        "policy_profiles.py::instantiate_template",
        "policy_profiles.py::profile_path",
        "relation_statement.py::build_relation_statement",
        "run_ledger.py::build_run_ledger_statement",
        "statuslist.py::issue_status_list_token",
        "tlogproof.py::format_tlog_proof",
        "trust_pack.py::build_trust_pack_statement",
        "verification_summary.py::build_summary_statement",
    )
}


def covered_surfaces(root: pathlib.Path = PACKAGE_ROOT) -> dict[str, Surface]:
    """The population the never-raise message-rendering rule enforces over: everything discovered that is
    not explicitly excluded. A surface nobody has decided about is IN."""
    return {k: s for k, s in discover_public_surfaces(root).items() if k not in SURFACE_DECISIONS}


# The pattern the rule used before this file existed. Kept for exactly one purpose: to measure how much of
# the shipped surface it could never see. It is not used to select anything.
_LEGACY_NAME_PATTERN = re.compile(
    r"^(verify_|load_|check_|decode_|count_|recompute_|receipt_canonical|sd_jwt_hidden"
    r"|validate_|require_valid_|require_derived_|classify_|derive_)")


# ── 1. the population is derived ──────────────────────────────────────────────────────────────────────

def test_population_is_discovered_from_the_tree() -> None:
    """The denominator check. A rule over an empty or collapsed population passes for the wrong reason."""
    surfaces = discover_public_surfaces()
    assert len(surfaces) >= 200, f"the public surface collapsed to {len(surfaces)} — discovery is broken"
    modules = {s.module for s in surfaces.values()}
    assert len(modules) >= 30, f"only {len(modules)} modules discovered"
    # discovery reaches into subpackages, not just the top level
    assert any("/" in m for m in modules), "no subpackage module discovered — rglob is not doing its job"


def test_the_legacy_name_pattern_saw_only_a_fraction_of_it() -> None:
    """The finding, expressed as a measurement rather than as a claim: a name-keyed rule was blind to most
    of the shipped surface, and to the specific one that leaked."""
    surfaces = discover_public_surfaces()
    seen_by_name = {k for k in surfaces if _LEGACY_NAME_PATTERN.match(k.split("::")[1])}
    assert len(seen_by_name) < len(surfaces) / 2, (
        "the legacy pattern now matches most of the surface, so this measurement no longer says anything")
    assert "renewal.py::evaluate_renewal_policy" in surfaces
    assert "renewal.py::evaluate_renewal_policy" not in seen_by_name, (
        "the leaked surface is matched by name after all — re-derive the finding")
    assert "renewal.py::evaluate_renewal_policy" in covered_surfaces(), (
        "the surface the name-keyed rule missed must be covered by the derived one")


def test_unknown_surfaces_default_to_covered(tmp_path: pathlib.Path) -> None:
    """The inversion itself. A public surface that this file has never heard of — a name no pattern here
    anticipates — is in the swept population without anyone editing a list.

    This is the property a blocklist cannot have: what it does not know about, it lets through.
    """
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "brand_new_module.py").write_text(textwrap.dedent('''
        def frobnicate_the_widget(value):
            return {"ok": False, "detail": f"bad: {value}"}
    '''), encoding="utf-8")
    covered = covered_surfaces(pkg)
    assert "brand_new_module.py::frobnicate_the_widget" in covered, (
        "a brand-new public surface was not covered by default — the population is not derived")


def test_private_modules_and_names_are_out_of_scope_by_construction(tmp_path: pathlib.Path) -> None:
    """The other half of the derivation: what is not public is not a public surface. This exclusion is
    STRUCTURAL (a leading underscore is the package's own declaration), so it needs no pinned entry."""
    pkg = tmp_path / "pkg"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "_private_module.py").write_text("def public_looking(x):\n    return x\n", encoding="utf-8")
    (pkg / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "sub" / "visible.py").write_text(
        "def _helper(x):\n    return x\n\ndef exported(x):\n    return x\n", encoding="utf-8")
    keys = set(discover_public_surfaces(pkg))
    assert "sub/visible.py::exported" in keys
    assert "_private_module.py::public_looking" not in keys
    assert "sub/visible.py::_helper" not in keys


def test_surface_keys_are_path_keyed_not_basename_keyed(tmp_path: pathlib.Path) -> None:
    """Two modules can share a basename — ``__init__.py`` and ``adapters/__init__.py`` do, today. Keying a
    decision on the basename would collapse them, so one entry would silently speak for another file. That
    is the path-ambiguity shape this project has already paid for elsewhere; the key carries the path."""
    pkg = tmp_path / "pkg"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "same.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    (pkg / "sub" / "same.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    keys = set(discover_public_surfaces(pkg))
    assert keys == {"same.py::f", "sub/same.py::f"}, f"two same-named modules collapsed into {keys}"


# ── 2. the decisions are honest ───────────────────────────────────────────────────────────────────────

def test_every_decision_uses_a_declared_reason_code() -> None:
    """An exclusion may only carry a reason from the closed vocabulary, so 'excluded, no reason given' and
    'excluded, reason invented on the spot' are both unrepresentable."""
    bad = {k: v for k, v in SURFACE_DECISIONS.items() if v not in REASON_CODES}
    assert not bad, f"undeclared reason code(s): {bad}; declared: {sorted(REASON_CODES)}"


def test_no_decision_refers_to_a_surface_that_does_not_exist() -> None:
    """A decision about a deleted or renamed surface is a claim about nothing. It must be removed, or the
    exclusion list stops describing the real gap."""
    surfaces = set(discover_public_surfaces())
    stale = sorted(set(SURFACE_DECISIONS) - surfaces)
    assert not stale, (
        "these excluded surfaces no longer exist — delete their lines so the exclusion list stays true:\n  "
        + "\n  ".join(stale))


def test_the_reason_vocabulary_has_no_dead_entries() -> None:
    """A vocabulary entry nobody uses is a slot waiting to be filled with an excuse. Declare a code when a
    real decision needs it, not before."""
    used = set(SURFACE_DECISIONS.values())
    unused = sorted(set(REASON_CODES) - used)
    assert not unused, f"declared but unused reason code(s): {unused}"


# ── 3. anti-tautology: the discovery can go blind, and it shows ───────────────────────────────────────

def test_blinding_the_discovery_makes_the_planted_surface_disappear(tmp_path: pathlib.Path) -> None:
    """If ``test_unknown_surfaces_default_to_covered`` passed for a reason other than discovery working,
    breaking discovery would change nothing. It must change everything.

    The blinding is on the SAME axis the rule decides on — where the surfaces are read from — rather than
    on a side axis that would prove only that some code ran.
    """
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "brand_new_module.py").write_text(
        'def frobnicate_the_widget(value):\n    return f"bad: {value}"\n', encoding="utf-8")
    assert "brand_new_module.py::frobnicate_the_widget" in covered_surfaces(pkg), "seeing"

    empty = tmp_path / "empty"
    empty.mkdir()
    assert not covered_surfaces(empty), "blinded discovery still produced a population"


def test_an_excluded_surface_really_leaves_the_covered_population(tmp_path: pathlib.Path) -> None:
    """The exclusion mechanism has to bite in both directions, or 'excluded' is decoration."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text("def a(x):\n    return x\n\n\ndef b(x):\n    return x\n", encoding="utf-8")
    assert {"m.py::a", "m.py::b"} <= set(covered_surfaces(pkg))
    SURFACE_DECISIONS["m.py::a"] = "OPEN_UNBOUNDED_RENDERING"
    try:
        covered = set(covered_surfaces(pkg))
        assert "m.py::a" not in covered, "the exclusion did nothing"
        assert "m.py::b" in covered, "the exclusion took a neighbour with it"
    finally:
        del SURFACE_DECISIONS["m.py::a"]
