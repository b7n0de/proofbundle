"""PROBE, NOT A TEST OF THE PACKAGE. Do not merge.

One deliberately red leg of the five-version matrix (Python 3.11 only), to measure what
`needs.test.result` carries into the collector job `all-checks-passed` when a single leg of a
`fail-fast: false` matrix fails. GitHub's documentation does not say; a reviewer (lens B,
2026-09-17) named this the one open assumption of the collector, and the ruleset must not be
switched on an assumption. The pull request carrying this file is closed after the measurement.
"""
import sys


def test_probe_one_red_leg_on_python_311():
    assert sys.version_info[:2] != (3, 11), "PROBE: this leg is red on purpose (3.11 only)"
