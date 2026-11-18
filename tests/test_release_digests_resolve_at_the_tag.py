"""Every digest of the signed pre-tag receipt resolves at the tag (lesson 2 of 18 November 2026).

An outside reader asked for the audit output of 6.6.0 and found none: the receipt verified, and its
`audit_output_digest` named no tracked file until pull request 538 put the output into the tree. From
6.6.1 on the release answers this before the tag and again in the release workflow:

- release.yml runs `scripts/audit_output_aufloesbar.py --repo . --version "${GITHUB_REF_NAME#v}"`
  once, after the pre-tag gate (which recomputes the tree and the gate source) and before the build;
- the release gate of RELEASE.md, answered before the owner GO, asks for that check and for the
  outside view `scripts/verify_pre_tag_receipt.py --commit`.

The behaviour of the check itself is tested in `tests/test_audit_output_aufloesbar.py`.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RELEASE = ROOT / "RELEASE.md"
SCHRITT = 'python scripts/audit_output_aufloesbar.py --repo . --version "${GITHUB_REF_NAME#v}"'


def _run_lines(text: str) -> list[tuple[int, str]]:
    """(line number, command) of every one-line `run:` in the workflow."""
    aus = []
    for nr, zeile in enumerate(text.splitlines(), 1):
        kern = zeile.strip()
        if kern.startswith("run: ") and not kern.endswith("|"):
            aus.append((nr, kern[len("run: "):]))
    return aus


def test_the_release_workflow_asks_for_the_audit_output_once_between_gate_and_build():
    text = WORKFLOW.read_text(encoding="utf-8")
    runs = _run_lines(text)
    schritt = [nr for nr, cmd in runs if cmd == SCHRITT]
    assert len(schritt) == 1, f"release.yml runs the audit-output step {len(schritt)} times, not once"
    # Every line that names the tool, inside a multi-line `run: |` block too; comments do not count.
    genannt = [nr for nr, zeile in enumerate(text.splitlines(), 1)
               if "scripts/audit_output_aufloesbar.py" in zeile and not zeile.strip().startswith("#")]
    assert genannt == schritt, f"release.yml names the audit-output tool on lines {genannt}, only {schritt} is the step"
    tor = [nr for nr, cmd in runs if cmd.startswith("python scripts/pre_tag_audit_gate.py ")]
    assert len(tor) == 1, "release.yml no longer runs the pre-tag gate as one step"
    bau = [nr for nr, zeile in enumerate(text.splitlines(), 1) if "scripts/build_reproducible.py" in zeile]
    assert bau, "release.yml no longer builds with build_reproducible.py"
    assert tor[0] < schritt[0] < min(bau), (
        "the audit-output step must stand after the pre-tag gate and before the build: "
        f"gate {tor[0]}, step {schritt[0]}, build {min(bau)}")


def _release_gate() -> str:
    lines = RELEASE.read_text(encoding="utf-8").splitlines()
    start = [i for i, z in enumerate(lines) if z.startswith("## Release gate")]
    assert len(start) == 1, "RELEASE.md carries no single `## Release gate` section"
    rest = lines[start[0] + 1:]
    ende = next((i for i, z in enumerate(rest) if z.startswith("## ")), len(rest))
    return "\n".join(rest[:ende])


def test_the_release_gate_asks_for_both_checks_before_the_owner_go():
    gate = _release_gate()
    assert "scripts/audit_output_aufloesbar.py --repo . --version X.Y.Z" in gate, (
        "the release gate no longer asks whether the audit output is a tracked file")
    assert "scripts/verify_pre_tag_receipt.py --commit <sha> --version X.Y.Z" in gate, (
        "the release gate no longer asks for the outside view of the tree and gate digests")
