#!/usr/bin/env python3
"""Rust second-verifier parity gate (Finding 11: honesty mechanism, not a completeness mandate).

The Rust cross-implementation verifier (`tools/pb_verify_rs`, ~585 lines before this gate) covers a
small slice of the ~4000-line Python security surface (bundle/dsse/merkle/jcs/strict-parse + a partial
SD-JWT issuer-authenticity slice). `CROSS_IMPLEMENTATION_REPORT.md` used to be the only record of that
gap, hand-maintained prose that drifts the moment a new `verify_*` surface is added on the Python side
without anyone remembering to touch the Rust doc too.

This gate replaces "hope someone remembers" with a live, re-checked-every-run mechanism:

  1. AST-scan every `src/proofbundle/*.py` for a module-level `def verify_*` — the GROUND TRUTH
     inventory. This is re-discovered fresh each run; nothing here is hand-copied from the Python side.
  2. Look each one up in the declarative registry (`scripts/rust_parity_registry.json`), which says
     COVERED / PARTIAL / PENDING plus (for COVERED/PARTIAL) which Rust subcommand and which literal
     crosscheck.py call site back the claim.
  3. Cross-check every COVERED/PARTIAL claim against REAL evidence, not the registry's word for it:
     the claimed subcommand must be an actual `match` arm in `main.rs`, must appear in the BUILT
     binary's self-declared `coverage-report` (when a binary is available), and the claimed
     crosscheck.py call site must literally exist in that file. A claim that fails any of these is
     STALE_COVERED_CLAIM — a lie the gate catches, not a completeness score it trusts.
  4. A ground-truth function with no registry entry at all is UNTRACKED (a parity decision is owed,
     never silently assumed either way). A registry entry whose python_ref no longer exists (renamed /
     removed) is ORPHANED (the registry itself has drifted).

This is an HONESTY gate, not a completeness mandate: PENDING is the expected, honestly-declared state
for the large majority of the surface (see CROSS_IMPLEMENTATION_REPORT.md's own "Pending" section) and
never fails anything, in this script or in CI. Only a demonstrably FALSE claim (STALE_COVERED_CLAIM /
UNTRACKED / ORPHANED) is a registry-integrity problem, and even that only fails the process in
`--strict` mode — the CI job wired to this script (advisory, matching branch_base_check.py's own
project-style precedent) always exits 0, exactly like every other advisory check in this repo.

CLI:
  python scripts/rust_parity_gate.py [--json] [--markdown] [--strict] [--rust-bin PATH]

Exit code: 0 always, UNLESS --strict is passed and a registry-integrity problem (STALE_COVERED_CLAIM /
UNTRACKED / ORPHANED) exists, in which case exit 1. PENDING entries never cause a non-zero exit, in
any mode — an honestly-declared gap is not a failure.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"
RUST_MAIN = REPO / "tools" / "pb_verify_rs" / "src" / "main.rs"
CROSSCHECK_PY = REPO / "tools" / "pb_verify_rs" / "crosscheck.py"
REGISTRY_PATH = REPO / "scripts" / "rust_parity_registry.json"
RUST_BIN_DEBUG = REPO / "tools" / "pb_verify_rs" / "target" / "debug" / "pb_verify_rs"
RUST_BIN_RELEASE = REPO / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"

STATUS_COVERED = "COVERED"
STATUS_PARTIAL = "PARTIAL"
STATUS_PENDING = "PENDING"
_VALID_STATUSES = {STATUS_COVERED, STATUS_PARTIAL, STATUS_PENDING}
_CLAIMED_STATUSES = {STATUS_COVERED, STATUS_PARTIAL}

# Only a `match` arm whose pattern is a bare, lowercase, hyphenated-word string literal is a real
# subcommand name — this excludes CLI flags (e.g. "--expected-root", which starts with '-') and the
# `other =>` catch-all, without needing a full Rust parser.
_MATCH_ARM_RE = re.compile(r'^\s*"([a-z][a-z0-9-]*)"\s*=>', re.MULTILINE)


def discover_python_verify_functions(src_dir: Path = SRC) -> dict[str, dict]:
    """AST-scan every module-level `def verify_*` in ``src_dir`` — the ground-truth inventory this
    gate holds the registry accountable to. Returns {qualified_name: {module, function, doc}}."""
    found: dict[str, dict] = {}
    for path in sorted(src_dir.glob("*.py")):
        module = path.stem
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, OSError):
            continue
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("verify_"):
                qualified = f"proofbundle.{module}.{node.name}"
                doc = ast.get_docstring(node) or ""
                found[qualified] = {
                    "module": module,
                    "function": node.name,
                    "doc_first_line": doc.strip().split("\n")[0] if doc else "",
                }
    return found


def load_registry(path: Path = REGISTRY_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def rust_match_arms(rust_main: Path = RUST_MAIN) -> set[str]:
    """The subcommand strings main.rs's `match` actually dispatches on — independent ground truth for
    what the SOURCE implements (checked separately from the built binary's own self-report, so a
    hand-edited drift between the two is at least detectable when both are available)."""
    if not rust_main.exists():
        return set()
    return set(_MATCH_ARM_RE.findall(rust_main.read_text(encoding="utf-8")))


def rust_coverage_report(rust_bin: Optional[Path] = None) -> Optional[dict]:
    """Run the built binary's self-declared `coverage-report`. Returns None (never a fabricated empty
    dict) when no binary is available — an honest DATA_BLOCKED for that one cross-check layer, not a
    silent pass and not a failure (cargo is not assumed to be installed everywhere this gate runs)."""
    candidates = [c for c in (rust_bin, RUST_BIN_DEBUG, RUST_BIN_RELEASE) if c is not None]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            proc = subprocess.run(
                [str(candidate), "coverage-report"], capture_output=True, text=True, timeout=10
            )
        except OSError:
            continue
        if proc.returncode != 0:
            continue
        try:
            return json.loads(proc.stdout.strip())
        except ValueError:
            continue
    return None


def _crosscheck_text(crosscheck_py: Path = CROSSCHECK_PY) -> str:
    return crosscheck_py.read_text(encoding="utf-8") if crosscheck_py.exists() else ""


def evaluate(*, src_dir: Path = SRC, registry_path: Path = REGISTRY_PATH, rust_main: Path = RUST_MAIN,
             crosscheck_py: Path = CROSSCHECK_PY, rust_bin: Optional[Path] = None) -> dict:
    """The single evaluation entry point — pure function of its inputs (paths are overridable so tests
    can point it at fixture trees without touching the real repo)."""
    ground_truth = discover_python_verify_functions(src_dir)
    registry = load_registry(registry_path)
    entries = registry.get("entries", {})
    arms = rust_match_arms(rust_main)
    coverage = rust_coverage_report(rust_bin)
    cov_subcommands = set(coverage["verify_subcommands"]) if coverage else None
    crosscheck_text = _crosscheck_text(crosscheck_py)

    items: list[dict] = []
    counts = {STATUS_COVERED: 0, STATUS_PARTIAL: 0, STATUS_PENDING: 0}
    untracked: list[str] = []
    stale: list[str] = []

    for qname in sorted(ground_truth):
        entry = entries.get(qname)
        if entry is None:
            untracked.append(qname)
            items.append({
                "python_ref": qname, "status": "UNTRACKED",
                "notes": "no registry entry — new verify_* surface, a parity decision is owed",
            })
            continue

        status = entry.get("status")
        if status not in _VALID_STATUSES:
            stale.append(qname)
            items.append({
                "python_ref": qname, "status": "REGISTRY_INVALID",
                "notes": f"registry entry has an unrecognised status {status!r}",
            })
            continue

        if status not in _CLAIMED_STATUSES:
            counts[status] += 1
            items.append({"python_ref": qname, "status": status, "notes": entry.get("notes", "")})
            continue

        # COVERED / PARTIAL: verify the claim against real evidence before trusting it.
        problem = None
        for subcommand in entry.get("rust_subcommands", []):
            if subcommand not in arms:
                problem = f"claims rust_subcommand {subcommand!r} but it is not a match arm in main.rs"
                break
            if cov_subcommands is not None and subcommand not in cov_subcommands:
                problem = (f"claims rust_subcommand {subcommand!r} but the built binary's "
                           "coverage-report does not list it")
                break
        if problem is None:
            for ref in entry.get("crosscheck_refs", []):
                if ref not in crosscheck_text:
                    problem = f"claims crosscheck_ref {ref!r} but it does not appear in crosscheck.py"
                    break

        if problem is not None:
            stale.append(qname)
            items.append({"python_ref": qname, "status": "STALE_COVERED_CLAIM", "notes": problem})
            continue

        counts[status] += 1
        items.append({
            "python_ref": qname, "status": status,
            "rust_subcommands": entry.get("rust_subcommands", []),
            "crosscheck_refs": entry.get("crosscheck_refs", []),
            "notes": entry.get("notes", ""),
        })

    orphaned = sorted(qname for qname in entries if qname not in ground_truth)

    total = len(ground_truth)

    def _pct(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    registry_integrity_ok = not (untracked or orphaned or stale)
    return {
        "schema": "proofbundle.rust_parity_gate.v1",
        "total_python_verify_surfaces": total,
        "covered": counts[STATUS_COVERED], "covered_pct": _pct(counts[STATUS_COVERED]),
        "partial": counts[STATUS_PARTIAL], "partial_pct": _pct(counts[STATUS_PARTIAL]),
        "pending": counts[STATUS_PENDING], "pending_pct": _pct(counts[STATUS_PENDING]),
        "untracked": untracked,
        "orphaned": orphaned,
        "stale": stale,
        "registry_integrity_ok": registry_integrity_ok,
        "binary_available": coverage is not None,
        "items": items,
    }


def _format_human(result: dict) -> str:
    lines = [
        f"[rust-parity] {result['total_python_verify_surfaces']} Python verify_* surface(s): "
        f"{result['covered']} COVERED ({result['covered_pct']}%), "
        f"{result['partial']} PARTIAL ({result['partial_pct']}%), "
        f"{result['pending']} PENDING ({result['pending_pct']}%)"
        + ("" if result["binary_available"] else "  [rust binary not built — coverage-report "
                                                  "cross-check skipped for un-built claims]"),
    ]
    for item in result["items"]:
        status = item["status"]
        if status == STATUS_PENDING:
            lines.append(f"  Rust-Parity: PENDING {item['python_ref']} — {item['notes']}")
        elif status == STATUS_PARTIAL:
            lines.append(f"  Rust-Parity: PARTIAL {item['python_ref']} — {item['notes']}")
        elif status == "UNTRACKED":
            lines.append(f"  Rust-Parity: UNTRACKED {item['python_ref']} — {item['notes']}")
        elif status == "STALE_COVERED_CLAIM":
            lines.append(f"  Rust-Parity: STALE_COVERED_CLAIM {item['python_ref']} — {item['notes']}")
        elif status == "REGISTRY_INVALID":
            lines.append(f"  Rust-Parity: REGISTRY_INVALID {item['python_ref']} — {item['notes']}")
        # COVERED items are summarized in the header line only, to keep the PENDING/PARTIAL signal
        # (the actual honesty content) from being buried.
    if result["orphaned"]:
        lines.append(f"  Rust-Parity: ORPHANED registry entries (python_ref no longer exists): "
                     f"{', '.join(result['orphaned'])}")
    lines.append(f"  registry_integrity_ok={result['registry_integrity_ok']}")
    return "\n".join(lines)


def _format_markdown(result: dict) -> str:
    """A machine-generated replacement for CROSS_IMPLEMENTATION_REPORT.md's hand-maintained table —
    same content, regenerated from the live gate result instead of prose that can silently drift."""
    lines = [
        "| python_ref | status | rust_subcommands | notes |",
        "|---|---|---|---|",
    ]
    for item in result["items"]:
        subs = ", ".join(item.get("rust_subcommands", [])) or "—"
        notes = item.get("notes", "").replace("|", "\\|")
        lines.append(f"| `{item['python_ref']}` | {item['status']} | {subs} | {notes} |")
    return "\n".join(lines)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="print the full JSON result")
    parser.add_argument("--markdown", action="store_true",
                        help="print a Markdown table (replacement for the hand-maintained report table)")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 if UNTRACKED / ORPHANED / STALE_COVERED_CLAIM entries exist "
                             "(PENDING never fails, in any mode)")
    parser.add_argument("--rust-bin", type=Path, default=None,
                        help="path to a pb_verify_rs binary (default: auto-detect target/debug or "
                             "target/release)")
    args = parser.parse_args(argv)

    result = evaluate(rust_bin=args.rust_bin)

    if args.markdown:
        print(_format_markdown(result))
    elif args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(_format_human(result))

    if args.strict and not result["registry_integrity_ok"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
