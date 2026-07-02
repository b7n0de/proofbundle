"""pytest plugin — opt-in auto-emit of a signed receipt of the test run (v1.0).

Registered via the ``pytest11`` entry-point, so pytest loads it automatically at startup. It emits a signed
proofbundle receipt of the run ONLY when the user opts in — the ``--proofbundle`` flag or ``PROOFBUNDLE_EMIT=1``
— never on a normal run, never failing the run. This module must import cheaply (it loads at every pytest
startup), so the crypto is imported lazily inside the terminal-summary hook, not at module top.

Counts come from ``terminalreporter.stats`` (the canonical count source): a dict outcome→list. Only the
pass/fail outcomes (passed/failed/error) form the denominator; skipped/xfailed/xpassed are recorded in
provenance. ``error`` (collect/setup/teardown failures) is kept separate from ``failed`` (call-phase).
"""
from __future__ import annotations


def pytest_addoption(parser):
    group = parser.getgroup("proofbundle", "proofbundle signed test-run receipt")
    group.addoption("--proofbundle", action="store_true", dest="proofbundle", default=False,
                    help="emit a signed proofbundle receipt of the test run (also enabled by PROOFBUNDLE_EMIT=1)")


def _fmt(x: float) -> str:
    return format(x, ".6f").rstrip("0").rstrip(".") or "0"


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    flag = bool(config.getoption("proofbundle", default=False))
    from ._integration import emit_enabled  # noqa: PLC0415
    if not emit_enabled(flag):
        return
    try:
        from datetime import datetime, timezone  # noqa: PLC0415

        from ._integration import emit_claim_receipt, emit_config  # noqa: PLC0415
        from .evalclaim import build_eval_claim  # noqa: PLC0415

        stats = terminalreporter.stats
        counts = {k: len(stats.get(k, [])) for k in
                  ("passed", "failed", "error", "skipped", "xfailed", "xpassed")}

        # Count UNIQUE tests by node id, not the sum of reports: a single test can produce both a call-phase
        # report (passed/failed) AND a separate setup/teardown 'error' report, so summing over-counts. A test
        # is a clean pass only if it passed AND has no failure/error report; ran = distinct nodes with an
        # outcome. This keeps the signed pass_rate + n honest for fixture-teardown-erroring suites.
        def _ids(key):
            return {getattr(r, "nodeid", id(r)) for r in stats.get(key, [])}
        passed_ids, failed_ids, error_ids = _ids("passed"), _ids("failed"), _ids("error")
        ran_ids = passed_ids | failed_ids | error_ids
        clean_passed = passed_ids - failed_ids - error_ids
        ran = len(ran_ids)
        if ran == 0:
            print("[proofbundle] no pass/fail tests to attest — receipt skipped")
            return
        pass_rate = len(clean_passed) / ran

        cfg = emit_config()
        rootname = getattr(getattr(config, "rootpath", None), "name", None) or "pytest"
        provenance = {"harness": "pytest", "exit_status": int(exitstatus), "tests_ran": ran,
                      "tests_passed": len(clean_passed), **{f"n_{k}": v for k, v in counts.items()}}
        claim, _ = build_eval_claim(
            suite="pytest", suite_version=str(getattr(__import__("pytest"), "__version__", "unknown")),
            metric=cfg["metric"] or "pass_rate", comparator=cfg["comparator"], threshold=cfg["threshold"],
            score=_fmt(pass_rate), n=ran, model_id=str(getattr(config, "rootpath", rootname)),
            dataset_id="pytest-suite", issuer="", timestamp=datetime.now(timezone.utc).isoformat(),
            provenance=provenance)
        emit_claim_receipt(claim, "proofbundle_pytest_receipt.json")
    except Exception as e:  # noqa: BLE001 — an integration must never fail the host test run
        print(f"[proofbundle] pytest receipt emission skipped ({type(e).__name__}: {e})")
