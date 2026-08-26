"""Gate-3 qualification (makellose-500 Phase 4, reviewer F2/F7): audit_candidate_ready is granted ONLY
when every RELEASE-DECIDING check is PASS except the one explicitly-external open audit. An internal
PENDING_JUSTIFIED / DATA_BLOCKED / unknown verdict, a FAIL, or an unbound version pin withholds it; the
presence-only (lexical) checks are informative and cannot grant it.

Generator-hardened: the ready property is exercised by mutating exactly one verdict of an otherwise-
ready synthetic matrix, with a positive control (all-PASS + external => ready) so the guard is not a
constant reject."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_candidate_matrix as acm  # noqa: E402

PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL = acm.PASS, acm.PENDING, acm.DATA_BLOCKED, acm.EXTERNAL, acm.FAIL


def _run(monkeypatch, checks, pin_state="bound"):
    reg = [(cid, 1, cid, (lambda v=v: (v, "synthetic"))) for cid, v in checks]
    monkeypatch.setattr(acm, "CHECKS", reg)
    monkeypatch.setattr(acm, "version_pin_binding", lambda _v: {"state": pin_state, "detail": "test"})
    return acm.evaluate()


class TestReadyLogic:
    def test_positive_control_all_pass_plus_external_is_ready(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("C4.1", PASS), ("EXT.1", EXTERNAL)])
        assert r["audit_candidate_ready"] is True

    def test_P7_internal_pending_justified_is_not_ready(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("C7.3", PENDING), ("EXT.1", EXTERNAL)])
        assert r["audit_candidate_ready"] is False
        assert "C7.3" in r["unmet_deciding"]

    def test_P7_internal_data_blocked_is_not_ready(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("C6.3", DATA_BLOCKED), ("EXT.1", EXTERNAL)])
        assert r["audit_candidate_ready"] is False

    def test_unknown_verdict_is_not_ready(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("C3.1", "WEIRD_STATE"), ("EXT.1", EXTERNAL)])
        assert r["audit_candidate_ready"] is False
        assert "C3.1" in r["unknown_verdicts"]

    def test_a_fail_is_not_ready(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("C4.1", FAIL), ("EXT.1", EXTERNAL)])
        assert r["audit_candidate_ready"] is False

    def test_P8_lexical_decoys_are_informative_not_deciding(self, monkeypatch):
        # every lexical check PASSes on a decoy, but a single DATA_BLOCKED deciding check still withholds.
        checks = [(cid, PASS) for cid in acm._INFORMATIVE_CHECKS] + [("C6.3", DATA_BLOCKED), ("EXT.1", EXTERNAL)]
        r = _run(monkeypatch, checks)
        assert r["audit_candidate_ready"] is False
        assert r["informative_count"] == len(acm._INFORMATIVE_CHECKS)

    def test_unbound_version_pin_is_not_ready(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("EXT.1", EXTERNAL)], pin_state="drift")
        assert r["audit_candidate_ready"] is False

    def test_status_boundary_is_computed_not_a_static_all_green_claim(self, monkeypatch):
        r = _run(monkeypatch, [("C2.1", PASS), ("C7.3", PENDING), ("EXT.1", EXTERNAL)])
        assert "all internal" not in r["status_boundary"].lower() or "NOT audit-candidate-ready" in r["status_boundary"]
        assert r["audit_candidate_ready"] is False
