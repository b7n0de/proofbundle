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


def test_gate_step_and_build_run_in_one_job_unconditionally_and_in_that_order():
    """THE STRUCTURE, not the text (Codex on pull request 541, round lx2, P1 5). The line order above holds
    for a step that a condition skips or whose failure is allowed. Read as YAML: the step stands in the
    job of the gate and the build, between the two; neither the job, nor the gate, nor the step, nor any
    step before the build carries a condition or `continue-on-error`; and every other job of the workflow
    needs that job, so nothing is published when the step fails."""
    import yaml

    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = wf["jobs"]
    halter = [n for n, job in jobs.items() for s in job.get("steps") or [] if (s.get("run") or "").strip() == SCHRITT]
    assert len(halter) == 1, f"the audit-output step stands in {len(halter)} jobs, not one"
    name = halter[0]
    job = jobs[name]
    steps = job["steps"]
    tor = [i for i, s in enumerate(steps) if (s.get("run") or "").strip().startswith("python scripts/pre_tag_audit_gate.py ")]
    schritt = [i for i, s in enumerate(steps) if (s.get("run") or "").strip() == SCHRITT]
    bau = [i for i, s in enumerate(steps) if "scripts/build_reproducible.py" in (s.get("run") or "")]
    assert len(tor) == 1 and len(schritt) == 1 and bau, (tor, schritt, bau)
    assert tor[0] < schritt[0] < min(bau), f"gate {tor[0]}, step {schritt[0]}, build {min(bau)} in job {name}"
    assert "if" not in job and not job.get("continue-on-error", False), f"job {name} runs under a condition"
    for i, s in enumerate(steps[:min(bau)]):
        assert not s.get("continue-on-error", False), f"step {i} of {name} lets its failure through"
    for i in (tor[0], schritt[0]):
        assert "if" not in steps[i], f"step {i} of {name} runs under a condition: {steps[i]['if']!r}"
    for andere, j in jobs.items():
        if andere == name:
            continue
        needs = j.get("needs")
        needs = [needs] if isinstance(needs, str) else list(needs or [])
        assert name in needs, f"job {andere} does not need {name}, so it could run without the step"


def _release_gate() -> list[str]:
    lines = RELEASE.read_text(encoding="utf-8").splitlines()
    start = [i for i, z in enumerate(lines) if z.startswith("## Release gate")]
    assert len(start) == 1, "RELEASE.md carries no single `## Release gate` section"
    assert "before asking for the Owner-GO" in lines[start[0]], lines[start[0]]
    rest = lines[start[0] + 1:]
    ende = next((i for i, z in enumerate(rest) if z.startswith("## ")), len(rest))
    return rest[:ende]


def test_the_release_gate_asks_for_both_checks_in_one_item_before_the_owner_go():
    """ONE CHECKLIST ITEM, AND IT COMES BEFORE THE GO (Codex on pull request 541, round lx2, P1 6). The first
    form of this test found both commands anywhere in the section, so a quotation after the GO sentence
    passed. Now both stand in one `- [ ]` item of the list, and that item comes before the sentence that
    says the Owner-GO is asked for after the list is answered."""
    zeilen = _release_gate()
    punkte, aktuell = [], None
    for i, z in enumerate(zeilen):
        if z.startswith("- [ ] "):
            aktuell = [i, z]
            punkte.append(aktuell)
        elif aktuell is not None and z.startswith("      "):
            aktuell[1] += "\n" + z
        else:
            aktuell = None
    beide = [start for start, text in punkte
             if "scripts/audit_output_aufloesbar.py --repo . --version X.Y.Z" in text
             and "scripts/verify_pre_tag_receipt.py --commit <sha> --version X.Y.Z" in text]
    assert len(beide) == 1, f"{len(beide)} checklist items ask for both checks, not one"
    go = [i for i, z in enumerate(zeilen) if z.startswith("The Owner-GO is asked for after this list is answered")]
    assert len(go) == 1, "the release gate no longer says when the Owner-GO is asked for"
    assert beide[0] < go[0], "the item with both checks stands after the GO sentence"
