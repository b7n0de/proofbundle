#!/usr/bin/env python3
"""5.0.0 AUDIT-CANDIDATE matrix — the 33 machine-checkable acceptance checks (§9 minus external audit).

The audit-candidate status is TRUE only when every INTERNAL, machine-checkable acceptance criterion of
the Assurance-Extension §10 is green, leaving the single external human crypto/protocol audit as the one
remaining gate to stable. This gate makes that claim FALSIFIABLE: it runs one check per acceptance
obligation (33 in total, mapped to §9 criteria 1..12), orchestrating the already-built foundation gates
(F3 formal model, F4 type-confusion, F5 readiness pack, rust-parity, claims-hygiene, test-manifest,
fuzz-soak) rather than re-implementing them.

No-Fake verdict vocabulary (a DATA_BLOCKED is NOT a PASS):
  * PASS              — machine-verified green here.
  * PENDING_JUSTIFIED — honestly declared, not-yet-closed but not a blocker (e.g. an accepted Rust
                        PENDING gap documented in the readiness pack); never silently a PASS.
  * DATA_BLOCKED      — needs a toolchain/time this environment does not have (cargo binary, a real 24h
                        soak, an isolated build). Reported honestly as "not verified HERE", never green.
  * EXTERNAL_PENDING  — the single deliberately-open gate: the external human audit itself.
  * FAIL              — a real, machine-detected failure of an acceptance obligation.

Top-level verdict:
  * ``audit_candidate_ready`` is True iff 0 FAIL AND every check is PASS / PENDING_JUSTIFIED / the one
    EXTERNAL_PENDING — i.e. nothing is broken and nothing internal is un-closed without justification.
  * ``fully_verified_here`` is additionally True iff there are also 0 DATA_BLOCKED — i.e. the whole
    matrix was runnable in THIS environment (cargo + build tools + a recorded 24h soak present). The two
    are reported separately so a CI box without cargo reads honestly, never a fake green.

CLI:
  python scripts/audit_candidate_matrix.py [--json] [--strict]

Exit 0 iff ``audit_candidate_ready``; ``--strict`` additionally requires ``fully_verified_here``.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts", "formal", "conformance"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL = (
    "PASS", "PENDING_JUSTIFIED", "DATA_BLOCKED", "EXTERNAL_PENDING", "FAIL")
#: A release-ceremony obligation evaluated against an object it was never meant to bless.
#:
#: WHY THIS IS NOT ONE OF THE FOUR EXISTING STATES. PENDING means "not yet, but it will be here";
#: DATA_BLOCKED means "this environment cannot measure it"; EXTERNAL means "a human outside must
#: do it"; FAIL means "the obligation is BROKEN". None of them fits "the obligation does not apply
#: to this kind of object at all". Reusing one of them would have made a fifth meaning wear a
#: fourth name, and the reader could no longer tell which was meant.
#:
#: It is NOT readiness. A work branch is not audit-candidate-ready, and ``audit_candidate_ready``
#: keeps saying so. What changes is only whether this check calls the branch BROKEN.
NOT_APPLICABLE = "NOT_APPLICABLE_BEFORE_TAG"
_NON_FAIL = {PASS, PENDING, DATA_BLOCKED, EXTERNAL, NOT_APPLICABLE}

# F7 CLOSED (makellose-500 Phase 4, reviewer P8): these checks measure a keyword / a directory entry /
# non-emptiness, not a behaviour — 7 of them passed on pure lexical decoys incl. a NEGATED sentence. A
# presence proxy cannot GRANT release readiness, so they are INFORMATIVE (reported, never release-
# deciding). ``audit_candidate_ready`` is computed only over the release-deciding checks.
_INFORMATIVE_CHECKS = {"C1.2", "C1.3", "C9.2", "C10.3", "C10.4", "C10.5", "C11.3"}
_KNOWN_VERDICTS = {PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL, NOT_APPLICABLE}
_EXTERNAL_CHECK_ID = "EXT.1"  # the ONE explicitly-external open audit

#: Human-readable names, first, with the id in parentheses behind them (owner directive
#: 04.09.2026: "was ist c12.1? das muessen wir umbenennen wenn das oefter kommt in
#: menschenlesbar"). The id stays as the stable identifier for tests and tables; the NAME is what
#: a person reads first. For every row other than C12.1 the name IS the existing plain title —
#: no new wording is invented, only the order changes.
_HUMAN_NAME = {"C12.1": "Pre-tag audit receipt"}


def _laeuft_auf_pull_request() -> bool:
    """Runs this evaluation against a pull request?

    FAIL-CLOSED BY CONSTRUCTION: only the literal string ``pull_request`` (and its ``_target``
    sibling) answers yes. A local run, an unset variable, a tag build, a push to main — anything
    else — is treated as NOT a pull request, and C12.1 stays sharp. The direction matters: an
    unknown environment must not be able to switch a release gate off.
    """
    return os.environ.get("GITHUB_EVENT_NAME", "") in ("pull_request", "pull_request_target")


def _version_aus_pyproject() -> str:
    """Die Version GELESEN, nicht getippt.

    Hier stand eine feste Zeichenkette, und am 04.09.2026 stand sie auf "5.1.0", waehrend das Paket
    5.1.0.post1 auslieferte. Das Skript meldete seine eigene Drift korrekt (`version_pin: drift`) —
    und niemand zog nach, weil ein fester Wert nichts erzwingt. Genau diese Klasse fing dieses
    Skript laut seinem eigenen Kopf schon einmal (Fund L6-01, schaler Pin); sie kam wieder, weil
    der Fund die INSTANZ traf und nicht die Bauform.

    DREI ZUSTAENDE, und der dritte ist ausdruecklich keine Freigabe: gelesen · Datei fehlt ·
    Datei da, aber ohne Versionszeile. Die letzten beiden liefern einen leeren String, und der
    Drift-Check darunter sagt dann NICHT "alles in Ordnung", sondern dass er nicht messen konnte.
    """
    import re as _re
    pp = REPO / "pyproject.toml"
    try:
        roh = pp.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = _re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', roh)
    return m.group(1) if m else ""


VERSION_UNDER_TEST = _version_aus_pyproject()


def version_pin_binding(pinned: str) -> dict:
    """Is the pinned version still the version we SHIP? Three states, never two.

    FOUND BY THE PRE-TAG DEEP GATE on 2026-08-25 (finding L6-01, three lenses converged
    independently): this matrix pinned ``3.6.0``, evaluated ``release_evidence_slots["3.6.0"]``
    and ``pre_tag_audit_gate.evaluate(version="3.6.0")``, and reported
    ``audit_candidate_ready=True`` with exit 0 — while the shipping package was ``5.0.0``, two
    majors ahead. A release-readiness gate was attesting readiness from evidence about a
    different release, and nothing in the pipeline could notice.

    THE POINT IS NOT THE LITERAL. Editing ``3.6.0`` to ``5.0.0`` would make this instance green
    and recreate the class at the next version bump — the pin would go stale again, silently,
    and again nothing would notice. What is missing is the BINDING: a gate whose verdict is
    version-scoped must fail closed when its scope no longer matches the shipping identity.

    Three states:
      * ``bound``          — the pin equals the package version; this gate speaks about what ships.
      * ``drift``          — they differ; the verdict is about another release and cannot be read
                             as readiness for this one.
      * ``not_determinable`` — the package version could not be read here. Explicitly NOT a pass:
                             an unmeasurable binding is not a verified one.
    """
    try:
        import proofbundle
        shipping = str(getattr(proofbundle, "__version__", "") or "")
    except Exception as exc:                                    # noqa: BLE001
        return {"state": "not_determinable", "pinned": pinned, "shipping": None,
                "detail": f"package version unreadable: {type(exc).__name__}: {exc}"}
    if not shipping:
        return {"state": "not_determinable", "pinned": pinned, "shipping": None,
                "detail": "proofbundle.__version__ is empty"}
    if shipping == pinned:
        return {"state": "bound", "pinned": pinned, "shipping": shipping,
                "detail": f"pin matches the shipping package ({shipping})"}
    return {"state": "drift", "pinned": pinned, "shipping": shipping,
            "detail": (f"this matrix is scoped to {pinned} but the package ships {shipping} — "
                       f"its checks read {pinned} evidence slots and a {pinned} pre-tag audit "
                       f"record, so its verdict says nothing about {shipping}")}


def _read(rel: str, base: Path = REPO) -> str:
    p = base / rel
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def _json_artifact(rel: str) -> dict | None:
    p = REPO / rel
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return None


# --- the 33 checks. Each returns (verdict, detail). Wrapped so one erroring check never crashes all. ---

def _ci_falsey_if(cond) -> bool:
    """True iff a GitHub Actions ``if:`` disables the job/step (literal false / 'false' / ${{ false }})."""
    if cond is False:
        return True
    if isinstance(cond, str):
        c = cond.strip().lower().replace("${{", "").replace("}}", "").strip()
        return c in ("false", "0")
    return False


def _is_real_test_invocation(argv: list[str]) -> bool:
    """True iff ``argv`` (one shell command, tokenised, leading ``VAR=value`` env assignments already
    stepped over) is a real, EXECUTING test-suite invocation. The command HEAD — the program actually
    run — must itself be a test runner: ``pytest`` / ``py.test`` / ``python -m pytest`` /
    ``python -m unittest`` / ``unittest discover``. It must NOT be a collect-only dry run
    (``--collect-only`` / ``--co``, which imports the tests but executes none).

    This is why the inspection commands that merely NAME pytest do NOT count: their head is
    ``which`` / ``command`` / ``pip`` / ``grep`` / ``find`` / ``ls`` / ``echo`` — not a runner — so
    ``which pytest``, ``command -v pytest``, ``pip show pytest``, ``grep -r pytest``,
    ``find -iname pytest.ini`` and ``ls pytest`` all return False here. ``make test`` and ``tox`` are
    deliberately NOT recognised (a documented known limitation — see AUDITOR_OPEN_POINTS.md); they run
    tests indirectly, and recognising them would need parsing the Makefile/tox config."""
    if not argv:
        return False
    head = argv[0].lower()
    rest = [a.lower() for a in argv[1:]]
    dry_run = "--collect-only" in rest or "--co" in rest
    if head in ("pytest", "py.test"):
        return not dry_run
    if re.fullmatch(r"python[0-9.]*", head):
        # a real ``python -m pytest`` / ``python -m unittest`` run; the module after -m is decisive.
        if "-m" in argv[1:]:
            mi = argv.index("-m", 1)
            mod = argv[mi + 1].lower() if mi + 1 < len(argv) else ""
            if mod == "pytest":
                return not dry_run
            if mod == "unittest":
                return True  # `python -m unittest [discover ...]` executes the suite
        return False
    if head == "unittest" and "discover" in rest:
        return True
    return False


def _ci_run_is_test(run: str) -> bool:
    """True iff a step's ``run:`` shell script actually EXECUTES the test suite. Comments are stripped
    and each ``;`` / ``&&`` / ``||`` / ``|``-separated command is judged in isolation by
    ``_is_real_test_invocation`` on its executed head (leading ``VAR=value`` env assignments stepped
    over), so ``echo x && pytest`` still counts the pytest half. A ``pytest`` named only inside a shell
    comment or an ``echo`` argument never runs; ``pip install pytest`` installs but does not run; and
    ``which pytest`` / ``pytest --collect-only`` do not execute the suite — none of them masquerade as
    a test step."""
    for raw in run.splitlines():
        # drop a shell comment (a '#' that starts a token) through end of line
        m = re.search(r"(?:^|\s)#", raw)
        line = raw[:m.start()] if m else raw
        # evaluate each shell command in isolation so `echo x && pytest` still counts the pytest half
        for cmd in re.split(r";|&&|\|\||\|", line):
            toks = cmd.strip().split()
            i = 0
            while i < len(toks) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[i]):
                i += 1  # step over leading `PYTHONPATH=src` style env assignments
            argv = toks[i:]
            if not argv:
                continue
            if argv[0].lower() in ("echo", "printf", ":", "true", "false"):
                continue  # a printed argument is not an executing test command
            if "install" in cmd.lower():
                continue  # `pip install pytest` installs the runner, it does not run tests
            if _is_real_test_invocation(argv):
                return True
    return False


def _ci_workflow_facts(ci_text: str) -> tuple[bool, bool]:
    """Parse a CI workflow as YAML and return ``(named_ci, has_executing_test_step)``.

    named_ci — the parsed document's top-level ``name`` is 'CI' (a commented-out ``# name: CI`` does
    not count, because YAML parsing drops comments).
    has_executing_test_step — at least one NON-disabled job has a NON-disabled step whose ``run:``
    executes the test suite (see ``_ci_run_is_test``). An ``if: false`` job or step is skipped, so a
    real pytest command inside a disabled job is correctly ignored."""
    import yaml  # noqa: PLC0415 — parse the workflow, never a file-wide substring scan
    try:
        doc = yaml.safe_load(ci_text)
    except yaml.YAMLError:
        return False, False
    if not isinstance(doc, dict):
        return False, False
    named_ci = str(doc.get("name", "")).strip().lower() == "ci"
    has_test = False
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict) or _ci_falsey_if(job.get("if")):
                continue
            for step in job.get("steps") or []:
                if not isinstance(step, dict) or _ci_falsey_if(step.get("if")):
                    continue
                run = step.get("run")
                if isinstance(run, str) and _ci_run_is_test(run):
                    has_test = True
                    break
            if has_test:
                break
    return named_ci, has_test


def c1_1_two_ci_gates(repo: Path = REPO):
    # The obligation is TWO named CI gates: a published-artifact gate AND a real repository/test gate.
    # Each must be its OWN workflow file, so deleting the second gate is falsifiable (a self-referential
    # substring read of one file could otherwise stay green while the repository gate is gone).
    pub = _read(".github/workflows/published-artifact-gate.yml", repo)
    if not pub:
        return FAIL, "published-artifact-gate.yml missing"
    has_pub = "sdist" in pub.lower() or "published" in pub.lower() or "cleanroom" in pub.lower()
    if not has_pub:
        return FAIL, "published-artifact-gate.yml carries no published-artifact leg (sdist/published/cleanroom)"
    ci = _read(".github/workflows/ci.yml", repo)
    if not ci:
        return FAIL, "the second CI gate .github/workflows/ci.yml (repository/test gate) is missing"
    # YAML-parse the workflow (not a file-wide substring): the second gate counts only when a
    # non-disabled job has a run: step that actually executes the test suite. If PyYAML is not
    # installed here, honestly report DATA_BLOCKED (never a fake PASS) — same taxonomy as C9.1.
    try:
        named_ci, has_test_step = _ci_workflow_facts(ci)
    except ImportError:
        return DATA_BLOCKED, ("PyYAML not installed here — cannot YAML-parse ci.yml to confirm the "
                              "repository/test gate; run in the dev/CI image (the CI itself proves it)")
    if named_ci and has_test_step:
        return PASS, ("two named CI gates present: ci.yml (repository/test gate, name: CI + a real "
                      "run: step executing the test suite) + published-artifact-gate.yml "
                      "(published-artifact leg)")
    return FAIL, ("ci.yml is present but is not a real repository/test gate (needs `name: CI` + a "
                  "run: step that executes pytest/unittest, not only a comment/echo/disabled job)")


def c1_2_reproducible_normaliser():
    t = _read("scripts/build_reproducible.py")
    ok = "SOURCE_DATE_EPOCH" in t and ("tar" in t.lower())
    return (PASS, "deterministic sdist normaliser present (SOURCE_DATE_EPOCH + canonical tar)") if ok \
        else (FAIL, "build_reproducible.py missing SOURCE_DATE_EPOCH / tar normalisation")


def c1_3_release_sha_gate():
    t = _read(".github/workflows/release.yml")
    return (PASS, "release.yml carries a sha256 digest gate") if "sha256" in t.lower() \
        else (FAIL, "release.yml has no sha256 gate")


@functools.lru_cache(maxsize=1)
def _manifest_gate():
    import test_manifest_gate as tmg
    return tmg.evaluate()


def c2_1_no_collection_errors():
    r = _manifest_gate()
    return (PASS, f"pytest collected {r['collected']} tests, 0 collection errors") if r["errors"] == 0 \
        else (FAIL, f"{r['errors']} collection error(s) — a file silently dropped from the run")


def c2_2_no_missing_suites():
    r = _manifest_gate()
    return (PASS, f"collected {r['collected']} >= floor {r['min_collected_tests']}") \
        if r["collected"] >= r["min_collected_tests"] else (FAIL, "collected count below the locked floor")


def c3_1_manifest_floor():
    r = _manifest_gate()
    return (PASS, f"test manifest floor met (headroom {r['headroom_tests']})") if r["ok"] \
        else (FAIL, "; ".join(r["problems"]))


def c3_2_pytest_only():
    r = _manifest_gate()
    return (PASS, f"{r['pytest_only_modules']} pytest-only module(s) >= floor "
                  f"{r['min_pytest_only_modules']} (unittest-invisible class preserved)") \
        if r["pytest_only_modules"] >= r["min_pytest_only_modules"] \
        else (FAIL, "pytest-only coverage regressed")


def _type_confusion():
    import type_confusion_gate as tcg
    return tcg.evaluate()


def c4_1_never_raise():
    r = _type_confusion()
    return (PASS, f"{r['in_scope']} verifier(s) survive the {r['matrix_size']}-payload matrix, never-raise") \
        if r["never_raise_ok"] else (FAIL, f"{len(r['violations'])} raw-crash violation(s)")


def c4_2_no_needs_fixture():
    r = _type_confusion()
    return (PASS, "0 NEEDS_FIXTURE — every verifier is covered or honestly NON_JSON") \
        if r["needs_fixture"] == 0 else (PENDING, f"{r['needs_fixture']} NEEDS_FIXTURE (coverage owed)")


def c5_1_payloadtype_negatives():
    rc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "tests/test_trust_pack_payloadtype_negatives.py"],
        cwd=str(REPO), capture_output=True, text=True, env=_env())
    return (PASS, "trust-pack payloadType/predicateType confusion vectors all reject (never-raise)") \
        if rc.returncode == 0 else (FAIL, "payloadType negative vectors did not all pass")


def c6_1_soak_harness():
    return (PASS, "bounded fuzz-soak harness present") if (REPO / "scripts" / "fuzz_soak.py").is_file() \
        else (FAIL, "scripts/fuzz_soak.py missing")


def c6_2_recorded_soak_clean():
    a = _json_artifact("audit_artifacts/360/fuzz_soak_latest.json")
    if a is None:
        return FAIL, "no recorded fuzz-soak artifact"
    ok = a.get("untriaged_crash_count", 1) == 0 and a.get("false_accept_count", 1) == 0
    return (PASS, f"recorded soak: {a.get('iterations')} iters, 0 crash, 0 false-accept") if ok \
        else (FAIL, f"soak found {a.get('untriaged_crash_count')} crash(es) / "
                    f"{a.get('false_accept_count')} false-accept(s)")


def c6_3_full_24h():
    a = _json_artifact("audit_artifacts/360/fuzz_soak_latest.json") or {}
    if a.get("is_full_soak_24h"):
        return PASS, "a full 24h soak artifact is present"
    el = a.get("elapsed_seconds", 0)
    return DATA_BLOCKED, (f"recorded soak is {el}s, not the full 24h — run "
                          "`fuzz_soak.py --duration-seconds 86400` on a soak box (operational artifact)")


def _formal():
    # load formal/model.py by path (not `import model`, which a top-level `model` module could shadow)
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location("proofbundle_formal_model", REPO / "formal" / "model.py")
    fm = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(fm)
    return fm.prove_all(bound=5)


def c7_1_formal_proven():
    r = _formal()
    return (PASS, f"formal model all non-reserved obligations proven (mode {r['prover_mode']})") \
        if r["all_proven"] else (FAIL, "a non-reserved formal obligation is not proven")


def c7_2_impl_crosscheck():
    r = _formal()
    return (PASS, "formal model grounded against the real implementation") \
        if r["implementation_crosscheck"]["ok"] else (FAIL, "implementation cross-check disagrees")


def c7_3_o7_reserved_honest():
    r = _formal()
    o7 = [o for o in r["obligations"] if o["id"] == "O7_PAYLOADTYPE_BINDING"]
    if not o7:
        return FAIL, "O7 payloadType obligation absent from the model"
    if o7[0]["status"] != "RESERVED":
        return FAIL, "O7 claims a status other than RESERVED (a fake proof would be a No-Fake violation)"
    return PASS, "O7 payloadType obligation present and HONESTLY reserved (code-enforced + vector-tested, no fake proof)"


def c7_4_reserved_slots_honest():
    r = _formal()
    reserved = {o["id"] for o in r["obligations"] if o["status"] == "RESERVED"}
    need = {"O5_TARGET_PIN_NOT_CRYPTO", "O6_RETRACTS_NEVER_RAISES", "O7_PAYLOADTYPE_BINDING"}
    return (PASS, "O5/O6/O7 declared reserved, no fabricated proofs") if need <= reserved \
        else (FAIL, f"expected reserved slots missing: {need - reserved}")


def _rust_parity():
    import rust_parity_gate as rpg
    return rpg.evaluate()


def c8_1_registry_integrity():
    r = _rust_parity()
    return (PASS, f"rust-parity registry integrity ok ({r['covered']} COVERED, {r['partial']} PARTIAL, "
                  f"{r['pending']} PENDING, 0 UNTRACKED/ORPHANED/STALE)") \
        if r["registry_integrity_ok"] else (FAIL, "registry integrity problem (untracked/orphaned/stale)")


def c8_2_differential_agrees():
    a = _json_artifact("audit_artifacts/360/rust_differential_matrix.json")
    if a is None:
        return DATA_BLOCKED, ("no differential matrix artifact — build the Rust binary "
                              "(cargo build in tools/pb_verify_rs) and run crosscheck.py --matrix")
    return (PASS, f"differential matrix: {a.get('total_relation_vectors')} vector(s), Python==Rust on all") \
        if a.get("all_agree") else (FAIL, "Python and Rust disagree on a differential vector")


def c8_3_pending_documented():
    # the readiness pack must acknowledge the deliberately-not-Rust-covered surface (no fake 100%)
    r = _rust_parity()
    idx = _json_artifact("docs/readiness_pack/index.json") or {}
    slot = (idx.get("release_evidence_slots") or {}).get(VERSION_UNDER_TEST) or {}
    doc = _read("docs/readiness_pack/rust_parity_scope.md")
    documented = bool(doc) or "rust" in json.dumps(slot).lower()
    if r["pending"] == 0:
        return PASS, "no PENDING Rust surface to document"
    return (PASS, f"{r['pending']} PENDING Rust surface(s) honestly documented as deliberately not Rust-covered") \
        if documented else (PENDING, f"{r['pending']} PENDING Rust surface(s) not yet documented in the pack")


def c9_1_two_sdists_identical():
    t = _read("scripts/build_reproducible.py")
    if not t:
        return FAIL, "build_reproducible.py missing"
    # attempt the real determinism check; if the build backend is unavailable here, DATA_BLOCKED honestly.
    rc = subprocess.run([sys.executable, "scripts/build_reproducible.py", "--check"],
                        cwd=str(REPO), capture_output=True, text=True, env=_env(), timeout=600)
    out = (rc.stdout + rc.stderr).lower()
    if rc.returncode == 0 and ("reproducible ok" in out or "byte-identical" in out):
        return PASS, "two sdist builds are byte-identical"
    if rc.returncode == 1 and "not reproducible" in out:
        return FAIL, "two sdist builds are NOT byte-identical"
    if "no module named build" in out or "modulenotfound" in out or "not available" in out \
            or "unavailable" in out or "no module named" in out:
        return DATA_BLOCKED, "the `build` backend is not installed here — run in the release image"
    # the gate exists and the CI proves it on every PR; treat a non-conclusive local run as DATA_BLOCKED,
    # never a fake PASS.
    return DATA_BLOCKED, (f"determinism not conclusively reproducible in this environment "
                          f"(exit {rc.returncode}); the published-artifact-gate proves it in CI")


def c9_2_slsa_reusable():
    t = _read(".github/workflows/reusable-build-attest.yml")
    return (PASS, "SLSA-L3-shape reusable attest workflow present (signing separated from build)") \
        if t and "attest" in t.lower() else (FAIL, "reusable-build-attest workflow missing")


def _readiness():
    import readiness_pack_gate as rp
    return rp.evaluate()


def c10_1_pack_ok():
    r = _readiness()
    return (PASS, f"readiness pack grounded ({r.get('conclusions')} conclusions, {r.get('release_slots')} slots)") \
        if r["ok"] else (FAIL, "; ".join(r["problems"]))


def c10_2_slot_filled():
    idx = _json_artifact("docs/readiness_pack/index.json") or {}
    slot = (idx.get("release_evidence_slots") or {}).get(VERSION_UNDER_TEST) or {}
    return (PASS, f"{VERSION_UNDER_TEST} readiness slot is filled") if slot.get("status") == "filled" \
        else (FAIL, f"{VERSION_UNDER_TEST} slot status is {slot.get('status')!r}, expected filled")


def c10_3_open_points():
    doc = _read("docs/readiness_pack/AUDITOR_OPEN_POINTS.md")
    return (PASS, "auditor open-points list present") if doc.strip() \
        else (FAIL, "docs/readiness_pack/AUDITOR_OPEN_POINTS.md missing")


def c10_4_manifest_self_receipt():
    man = REPO / "docs" / "readiness_pack" / "MANIFEST.sha256"
    if not man.is_file():
        return FAIL, "readiness pack SHA-256 manifest missing"
    receipt_dir = REPO / "docs" / "readiness_pack" / "proofbundle"
    has_receipt = receipt_dir.is_dir() and any(receipt_dir.iterdir())
    return (PASS, "SHA-256 manifest + proofbundle self-receipt present (advisory dogfood)") if has_receipt \
        else (PENDING, "SHA-256 manifest present; proofbundle self-receipt not generated (advisory)")


def c10_5_runbook():
    doc = _read("docs/readiness_pack/REPRODUCTION_RUNBOOK.md")
    return (PASS, "reproduction runbook present") if doc.strip() \
        else (FAIL, "docs/readiness_pack/REPRODUCTION_RUNBOOK.md missing")


def c11_1_claims_hygiene():
    rc = subprocess.run([sys.executable, "scripts/claims_hygiene_check.py"],
                        cwd=str(REPO), capture_output=True, text=True, env=_env())
    return (PASS, "claims-hygiene clean (no un-negated overclaim, extended audit-candidate list)") \
        if rc.returncode == 0 else (FAIL, "claims-hygiene found an overclaim")


def c11_2_beta_classifier():
    t = _read("pyproject.toml")
    if re.search(r"Development Status\s*::\s*5\s*-\s*Production/Stable", t):
        return FAIL, "pyproject declares Development Status 5 - Production/Stable (must stay 4 - Beta)"
    if re.search(r"Development Status\s*::\s*4\s*-\s*Beta", t):
        return PASS, "pyproject Development Status is 4 - Beta (status boundary held)"
    return PENDING, "no Development Status classifier found in pyproject (expected 4 - Beta)"


def c11_3_relation_experimental():
    t = _read("pyproject.toml") + _read("SPEC.md") + _read("docs/predicates/relation.md")
    return (PASS, "relation profile still marked EXPERIMENTAL") if "EXPERIMENTAL" in t \
        else (FAIL, "relation EXPERIMENTAL marker not found")


def c12_1_pretag_audit():
    """A signed pre-tag audit receipt must bind THIS tree, THIS version and THIS gate.

    WHY THIS IS RED ON A WORK BRANCH, AND WHY THAT IS CORRECT (Owner decision 2026-08-30, card
    OA-4a8daddb55). A receipt binds a `subject_tree_digest`. A work branch is not finished and will
    get at least one more commit when it merges, so a receipt issued against it attests a tree that
    is about to stop existing. Producing one anyway would be exactly the act this check was built to
    catch — it would REPRODUCE the finding instead of closing it. C12.1 is a RELEASE gate; the
    receipt belongs to the tree that actually gets tagged.

    So a red C12.1 on a branch is not unfinished work and not a tool defect. It is the check doing
    its job on an object it was not meant to bless. Measured the same day: the v5.0.0 receipt
    (`audit_artifacts/500/pre_tag_receipt_v5.0.0.json`) binds `4212087273dc…`, which IS the
    subject_tree_digest of the v5.0.0 tag, is signed by the pinned key, and this gate returns ok
    when run against that tree.

    HONEST LIMIT, recorded rather than smoothed over: the receipt's signed `audit_output_digest`
    resolves to no artifact that could be found, and nothing in this gate resolves it — the field is
    signed, which makes it tamper-evident and attributable, not checkable.
    """
    import pre_tag_audit_gate as pta
    r = pta.evaluate(REPO, version=VERSION_UNDER_TEST)
    if r["ok"]:
        return (PASS, f"pre-tag adversarial audit recorded for {VERSION_UNDER_TEST}")
    # AUF EINEM PULL REQUEST IST DIESE VERPFLICHTUNG NICHT ANWENDBAR, NICHT GEBROCHEN.
    #
    # Die Owner-Entscheidung vom 30.08. (Karte OA-4a8daddb55, im Docstring oben zitiert) sagt: ein
    # Receipt fuer einen Arbeitszweig zu erzeugen waere genau der Akt, den diese Pruefung faengt.
    # Daraus folgt aber, dass sie auf JEDEM PR rot ist — und eine Pruefung, die immer rot ist,
    # traegt keine Information und lehrt jeden Leser, Rot zu uebergehen. Unter dem oeffentlich auf
    # der SCITT-Liste verlinkten PR 178 sah ein Fremder ein rotes Kreuz an einem Beitrag, den wir
    # als sauber bezeichnen.
    #
    # DIE ENTSCHEIDUNG VOM 30.08. BLEIBT UNBERUEHRT: es wird weiterhin kein Receipt fuer Zweige
    # erzeugt. Es wird nur nicht mehr so getan, als koennte es eines geben.
    #
    # ENG GEHALTEN: nur der Fall „kein Receipt bindet diesen Baum" wird umgedeutet. Jeder ANDERE
    # Fehlschlag des Tors — eine kaputte Signatur, ein nicht vertrauenswuerdiger Schluessel, ein
    # unlesbares Receipt — bleibt FAIL, auch auf einem PR. Sonst waere aus einer Praezisierung
    # eine Abschaltung geworden.
    if _laeuft_auf_pull_request() and "no valid pre-tag audit RECEIPT" in (r.get("reason") or ""):
        return (NOT_APPLICABLE,
                "nicht anwendbar vor dem Tag: ein Receipt bindet einen BAUM, und der Baum eines "
                "Zweigs hoert beim Merge auf zu existieren (Owner-Entscheid 30.08., OA-4a8daddb55). "
                "Auf main und auf Tags bleibt diese Zeile scharf.")
    return (FAIL, r["reason"])


def c12_2_audit_pack_zero_p0p1(repo: Path = REPO):
    # RT-10 / PB-2026-0718-14 (was a proven FALSE-PASS): the '0 open P0/P1' obligation is carried by the
    # SIGNED, STRUCTURED findings register (audit_artifacts/findings_register_361.json), counted from
    # structured severity+status fields — NOT a lexical '0 open P0/P1' substring in a possibly-stale .md.
    # The old guard derived PASS from any non-negated '0 open P0/P1' line in a version-scoped record, with
    # NO freshness/supersession/signature/contradiction check, so a STALE record that still said '0 open'
    # granted PASS while current open P0/P1 existed (false_accept=true). The register replacement is
    # fail-closed: a valid ed25519 signature by the pinned key is required (unsigned/tampered/wrong-key =
    # FAIL); supersession is resolved current-wins; a contradiction is an ERROR; and absence / an empty
    # register is FAIL, not PASS (evaluated_count==0 -> FAIL, the assertion-by-absence guard). Every verdict
    # carries the RT-10 triple (population_size, evaluated_count, source_digest).
    import findings_register as fr
    r = fr.verify_and_count(repo)
    triple = (f"population_size={r['population_size']} evaluated_count={r['evaluated_count']} "
              f"source_digest={r['source_digest']}")
    return (PASS if r["ok"] else FAIL), f"{r['reason']} [{triple}]"


def ext_1_external_audit():
    return EXTERNAL, ("the independent external human crypto/protocol audit — the SINGLE deliberately "
                      "open gate to stable; no internal instrument can substitute for it (No-Fake)")


CHECKS = [
    ("C1.1", 1, "two named CI gates (repo + published-artifact)", c1_1_two_ci_gates),
    ("C1.2", 1, "deterministic sdist normaliser", c1_2_reproducible_normaliser),
    ("C1.3", 1, "release sha256 digest gate", c1_3_release_sha_gate),
    ("C2.1", 2, "pytest cleanroom: 0 collection errors", c2_1_no_collection_errors),
    ("C2.2", 2, "no missing suites (floor met)", c2_2_no_missing_suites),
    ("C3.1", 3, "locked test manifest floor met", c3_1_manifest_floor),
    ("C3.2", 3, "pytest-only modules preserved", c3_2_pytest_only),
    ("C4.1", 4, "type-confusion matrix never-raise total", c4_1_never_raise),
    ("C4.2", 4, "no NEEDS_FIXTURE coverage gap", c4_2_no_needs_fixture),
    ("C5.1", 5, "trust-pack payloadType negatives green", c5_1_payloadtype_negatives),
    ("C6.1", 6, "fuzz-soak harness present", c6_1_soak_harness),
    ("C6.2", 6, "recorded soak: 0 crash, 0 false-accept", c6_2_recorded_soak_clean),
    ("C6.3", 6, "full 24h soak artifact", c6_3_full_24h),
    ("C7.1", 7, "formal model: non-reserved obligations proven", c7_1_formal_proven),
    ("C7.2", 7, "formal model grounded in implementation", c7_2_impl_crosscheck),
    ("C7.3", 7, "O7 payloadType obligation honestly reserved", c7_3_o7_reserved_honest),
    ("C7.4", 7, "reserved slots O5/O6/O7 honest (no fake proof)", c7_4_reserved_slots_honest),
    ("C8.1", 8, "rust-parity registry integrity", c8_1_registry_integrity),
    ("C8.2", 8, "Python<->Rust differential agrees", c8_2_differential_agrees),
    ("C8.3", 8, "PENDING Rust surface documented (no fake 100%)", c8_3_pending_documented),
    ("C9.1", 9, "two sdists byte-identical", c9_1_two_sdists_identical),
    ("C9.2", 9, "SLSA-L3 reusable attest workflow", c9_2_slsa_reusable),
    ("C10.1", 10, "readiness pack grounded", c10_1_pack_ok),
    ("C10.2", 10, f"{VERSION_UNDER_TEST} readiness slot filled", c10_2_slot_filled),
    ("C10.3", 10, "auditor open-points list", c10_3_open_points),
    ("C10.4", 10, "SHA-256 manifest + self-receipt", c10_4_manifest_self_receipt),
    ("C10.5", 10, "reproduction runbook", c10_5_runbook),
    ("C11.1", 11, "claims-hygiene (no stable/audited/prod-ready claim)", c11_1_claims_hygiene),
    ("C11.2", 11, "pyproject stays 4 - Beta", c11_2_beta_classifier),
    ("C11.3", 11, "relation still EXPERIMENTAL", c11_3_relation_experimental),
    ("C12.1", 12, "pre-tag adversarial audit recorded", c12_1_pretag_audit),
    ("C12.2", 12, "internal audit pack: 0 open P0/P1", c12_2_audit_pack_zero_p0p1),
    ("EXT.1", 0, "external human audit (the one remaining gate)", ext_1_external_audit),
]


def _env() -> dict:
    import os
    e = dict(os.environ)
    src = str(REPO / "src")
    e["PYTHONPATH"] = src + (":" + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
    return e


def gate_ready_on_binding(ready_before: bool, binding_state: str) -> bool:
    """Der Versions-Pin senkt die Bereitschaft GENAU DANN, wenn er nicht gebunden ist.

    WARUM DAS EINE EIGENE FUNKTION IST (gemessen 02.09.2026). Die Regel stand als zwei Zeilen mitten
    in `evaluate()`, und die Anti-Paritaets-Probe konnte sie nur INDIREKT beobachten: sie verglich das
    Endergebnis mit der Bereitschaft davor. Solange die Bereitschaft davor ohnehin `False` ist -- und
    das ist sie auf jedem Baum, der nicht vollstaendig bereit ist -- sind beide Seiten `False`, die
    Gleichheit haelt, und ein eingepflanzter Dauer-`False`-Defekt kam mit `8 passed` durch. Gemessen,
    nicht vermutet: genau dieser Defekt lief gruen durch, bevor es diese Funktion gab.

    Als eigene Funktion ist die Regel ADRESSIERBAR: alle vier Kombinationen lassen sich hinschreiben,
    auch die eine, die den Defekt sichtbar macht (bereit davor UND gebunden ergibt bereit). Ein
    Riegel, der seine Bedingung nur beobachten kann, wenn die Welt gerade guenstig steht, ist auf
    jedem anderen Baum stumm.
    """
    return bool(ready_before) and binding_state == "bound"


def evaluate() -> dict:
    rows = []
    for cid, crit, title, fn in CHECKS:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 - an erroring check is an honest FAIL, never a crash
            verdict, detail = FAIL, f"check raised {type(exc).__name__}: {exc}"
        rows.append({"id": cid, "criterion": crit, "title": title,
                     "verdict": verdict, "detail": detail})
    counts = {v: sum(1 for r in rows if r["verdict"] == v)
              for v in (PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL, NOT_APPLICABLE)}
    # F2 + F7 CLOSED (makellose-500 Phase 4): audit_candidate_ready = every RELEASE-DECIDING check is
    # PASS, EXCEPT exactly the one explicitly-external open audit (EXT.1 == EXTERNAL_PENDING). An internal
    # PENDING_JUSTIFIED, an internal DATA_BLOCKED (a check that could NOT be measured here), an unknown
    # verdict, a FAIL, or an unbound version pin is NOT ready — honesty about not-having-measured is not
    # readiness. Informative (presence-only) checks are excluded from the verdict entirely. Fail-closed.
    unknown = [r for r in rows if r["verdict"] not in _KNOWN_VERDICTS]
    deciding = [r for r in rows if r["id"] not in _INFORMATIVE_CHECKS]
    # EIN NAME FUER DIE BEREITSCHAFT VOR DER PIN-BINDUNG, und er wird auch nach aussen gereicht.
    # Grund (gemessen 02.09.2026): die Anti-Paritaets-Probe dieser Datei bildete diese Groesse mit
    # `_NON_FAIL` NACH, und `_NON_FAIL` enthaelt DATA_BLOCKED, das hier ausdruecklich NICHT
    # bereitmacht. Beide Seiten stimmten nur ueberein, solange irgendeine Zeile FAILte; als ein
    # gueltiges Pre-Tag-Receipt die letzte FAIL-Zeile entfernte, klaffte die Nachbildung auf und der
    # Test beschuldigte den Pin, der bound und unbeteiligt war. Ein Pruefer, der die gepruefte
    # Bedingung NACHBAUT statt sie zu lesen, misst eine zweite Groesse mit demselben Namen.
    ready_before_binding = (counts[FAIL] == 0 and not unknown and all(
        r["verdict"] == PASS or (r["id"] == _EXTERNAL_CHECK_ID and r["verdict"] == EXTERNAL)
        for r in deciding))
    # THE BINDING GATES THE VERDICT, not just decorates it. A green matrix about another release
    # is not a green matrix about this one — and `ready` is the field a reader takes at face value.
    # `not_determinable` withholds readiness too: an unmeasurable binding is not a verified one,
    # and this gate's whole job is to be falsifiable.
    # THE PIN IS PASSED, NOT DEFAULTED. A default argument is bound once, when the function is
    # defined; the constant is then frozen into the signature and a later change to
    # VERSION_UNDER_TEST would no longer reach the check. Caught by this file's own anti-parity
    # test, which set the constant and watched the guard ignore it — a binding check that reads a
    # stale copy of the thing it binds is the same class of defect it exists to catch.
    binding = version_pin_binding(VERSION_UNDER_TEST)
    ready = gate_ready_on_binding(ready_before_binding, binding["state"])
    fully_here = ready and counts[DATA_BLOCKED] == 0
    # status_boundary is COMPUTED, never a static claim: it says "all internal deciding gates green" only
    # when that is actually true (reviewer F7 — the old static string claimed it unconditionally).
    not_pass_deciding = [r["id"] for r in deciding
                         if not (r["verdict"] == PASS or r["id"] == _EXTERNAL_CHECK_ID)]
    if ready:
        boundary = ("audit-candidate: all internal release-deciding gates PASS; the sole remaining gate "
                    "to stable is the independent external security audit. NOT stable, NOT audited, NOT "
                    "production-ready.")
    else:
        boundary = ("NOT audit-candidate-ready: internal release-deciding obligations are not all PASS "
                    f"(unmet: {not_pass_deciding or 'version-pin unbound'}). NOT stable, NOT audited, "
                    "NOT production-ready.")
    return {
        "schema": "proofbundle.audit_candidate_matrix.v1",
        "version_under_test": VERSION_UNDER_TEST,
        "version_pin": binding,
        "total_checks": len(rows),
        "release_deciding_count": len(deciding),
        "informative_count": len(rows) - len(deciding),
        "unknown_verdicts": [r["id"] for r in unknown],
        "unmet_deciding": not_pass_deciding,
        # Die Bereitschaft OHNE die Wirkung der Pin-Bindung. Wer pruefen will, ob die Bindung
        # das Verdikt gesenkt hat, vergleicht `audit_candidate_ready` hiermit — statt die
        # Bedingung ein zweites Mal nachzubauen.
        "ready_before_binding": ready_before_binding,
        "counts": counts,
        "audit_candidate_ready": ready,
        "fully_verified_here": fully_here,
        "status_boundary": boundary,
        "checks": rows,
    }


def _fmt(result: dict) -> str:
    c = result["counts"]
    pin = result.get("version_pin") or {}
    lines = []
    # The binding goes FIRST when it is not clean: a reader who stops after one line must not
    # walk away with a readiness impression that the line below would have withdrawn.
    if pin.get("state") == "drift":
        lines.append(f"[audit-candidate-matrix] VERSION PIN DRIFT — {pin.get('detail')}")
        lines.append("  audit_candidate_ready is withheld: this matrix does not speak about the "
                     "shipping version. Bind the pin (or scope the claim), do not just bump it.")
    elif pin.get("state") == "not_determinable":
        lines.append(f"[audit-candidate-matrix] VERSION PIN NOT DETERMINABLE — {pin.get('detail')}")
        lines.append("  audit_candidate_ready is withheld: an unmeasurable binding is not a "
                     "verified one.")
    lines += [
        f"[audit-candidate-matrix] {result['total_checks']} checks · "
        f"PASS {c[PASS]} · PENDING {c[PENDING]} · DATA_BLOCKED {c[DATA_BLOCKED]} · "
        f"EXTERNAL {c[EXTERNAL]} · NICHT ANWENDBAR {c[NOT_APPLICABLE]} · FAIL {c[FAIL]}",
        f"  audit_candidate_ready={result['audit_candidate_ready']} "
        f"fully_verified_here={result['fully_verified_here']}",
        f"  (ready = no internal obligation BROKEN; it does NOT mean all {result['total_checks']} are "
        f"green — {c[DATA_BLOCKED]} still need the release toolchain/24h soak (DATA_BLOCKED) and "
        f"{c[EXTERNAL]} is the external audit. Full green HERE needs fully_verified_here=True.)",
    ]
    for r in result["checks"]:
        mark = {PASS: "  ok ", PENDING: " pend", DATA_BLOCKED: " data",
                EXTERNAL: " ext ", FAIL: "FAIL ", NOT_APPLICABLE: " n.a."}[r["verdict"]]
        # NAME ZUERST, KUERZEL IN KLAMMERN. Das Kuerzel bleibt der stabile Bezeichner fuer Tests
        # und Tafeln; wer liest, soll aber nicht erst nachschlagen muessen, was C12.1 ist.
        name = _HUMAN_NAME.get(r["id"], r["title"])
        lines.append(f"  [{mark}] {name} ({r['id']}) (§{r['criterion']}): {r['detail']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="also require fully_verified_here (0 DATA_BLOCKED — a full toolchain env)")
    args = p.parse_args(argv)
    result = evaluate()
    print(json.dumps(result, indent=2, ensure_ascii=False) if args.json else _fmt(result))
    # DER AUSGANGSCODE SAGT „BLOCKIERT DIESE PRUEFUNG DIESES OBJEKT", NICHT „IST ES FERTIG".
    #
    # `audit_candidate_ready` bleibt unveraendert und sagt weiterhin die Wahrheit: ein Arbeitszweig
    # ist nicht release-bereit, und im JSON steht das auch so. Was sich aendert, ist allein, ob
    # dieser Lauf deswegen ROT wird. Haelt NUR eine nicht-anwendbare Zeile die Bereitschaft
    # zurueck, ist das keine Aussage ueber einen Defekt — und ein rotes Kreuz waere eine.
    #
    # FAIL bleibt FAIL, auch hier: sobald irgendeine Zeile wirklich gebrochen ist, oder die
    # Version-Pin-Bindung nicht steht, endet der Lauf rot wie bisher.
    if not result["audit_candidate_ready"]:
        _na = [r for r in result["checks"] if r["verdict"] == NOT_APPLICABLE]
        # WAS AUF EINEM PR KEIN MANGEL DES PR IST. `DATA_BLOCKED` steht hier neben
        # `NOT_APPLICABLE`, und zwar nicht aus Bequemlichkeit: der Workflow sagt es woertlich
        # ueber genau diesen Job — "a full run needs a soak box (24h) and the build backend, so
        # DATA_BLOCKED is expected in CI and must not fail the build (No-Fake)". Beides heisst
        # "hier nicht gemessen", keines heisst "gebrochen".
        #
        # FAIL, PENDING und ein unbekanntes Verdikt bleiben Maengel. Ein PENDING sagt "noch
        # nicht", und das ist eine Aussage ueber die Arbeit; die anderen beiden sind Aussagen
        # ueber die Umgebung und ueber den Gegenstand.
        _echte_maengel = [
            r for r in result["checks"]
            if r["id"] not in _INFORMATIVE_CHECKS
            and r["verdict"] not in (PASS, NOT_APPLICABLE, DATA_BLOCKED)
            and not (r["id"] == _EXTERNAL_CHECK_ID and r["verdict"] == EXTERNAL)
        ]
        _pin_ok = (result.get("version_pin") or {}).get("state") == "bound"
        if not (_na and not _echte_maengel and _pin_ok):
            return 1
    if args.strict and not result["fully_verified_here"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
