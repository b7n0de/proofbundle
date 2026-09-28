"""A full eval claim with chosen always-open values, for tests that issue an SD-JWT from it.

WHY THIS EXISTS. Until 6.2.0 these tests handed `issue_sd_jwt` a dict of the five always-open fields
(passed, threshold, comparator, suite, issuer). Since then `issue_sd_jwt` refuses every claim that
`decode_eval_claim` refuses, and such a dict is one: it lacks nine required fields. An SD-JWT is a
view of a signed eval claim (sdjwt_issue.py, module docstring), so the fixture is a whole claim whose
always-open values are the ones the test needs. Where a test already holds the bundle's own signed
claim, it issues from that instead and does not need this module.
"""
from proofbundle.evalclaim import build_eval_claim


def full_eval_claim(issuer: str, *, suite: str = "demo-suite", threshold: str = "0.80") -> dict:
    """A claim `decode_eval_claim` accepts, with passed=True, comparator ">=" and the given values.

    The score 0.9 lies at or above every threshold these tests use, so `passed` is True, which is
    the always-open value every caller of this helper had written by hand.
    """
    claim, _ = build_eval_claim(
        suite=suite, suite_version="1", metric="acc", comparator=">=", threshold=threshold,
        score="0.9", n=100, model_id="m", dataset_id="d", issuer=issuer,
        timestamp="2026-07-09T10:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    assert claim["passed"] is True, "the helper promises passed=True; the score no longer clears the bar"
    return claim
