"""The upstream fetcher in tools/scitt_ccf_datahash_vector: the digest is the pin, a source is transport.

Measured 2026-09-25: the pinned commit answers HTTP 404, the author's site serves the same bytes.
These cases replace the network with a stub opener and check the three outcomes the fetcher
promises: an unreachable source moves on, a source with different bytes stops everything, and no
reachable source is NOT MEASURABLE rather than a verdict.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import pathlib
import sys
import urllib.error

import pytest

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "scitt_ccf_datahash_vector"


def _load():
    spec = importlib.util.spec_from_file_location("_fetch_under_test",
                                                  TOOL / "fetch_upstream_vectors.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


F = _load()
GOOD = b'{"vector": "stand-in"}'
SOURCES = (("first", "https://first.invalid"), ("second", "https://second.invalid"))


def _opener(by_host: dict):
    """Stub for urlopen: per host either bytes to serve or an exception to raise."""
    seen = []

    def opener(req, timeout=None):  # noqa: ARG001
        seen.append((req.full_url, req.get_header("User-agent")))
        outcome = by_host[req.full_url.split("/")[2]]
        if isinstance(outcome, BaseException):
            raise outcome
        return io.BytesIO(outcome)

    opener.seen = seen
    return opener


def _404(host):
    return urllib.error.HTTPError(f"https://{host}/x", 404, "Not Found", {}, None)


def test_an_unreachable_source_moves_on_to_the_next():
    op = _opener({"first.invalid": _404("first.invalid"), "second.invalid": GOOD})
    raw, label, unreachable = F.fetch_one("v.json", len(GOOD), hashlib.sha256(GOOD).hexdigest(),
                                          sources=SOURCES, opener=op)
    assert raw == GOOD and label == "second"
    assert len(unreachable) == 1 and "404" in unreachable[0]
    assert all(ua == F.USER_AGENT for _url, ua in op.seen)


def test_a_reachable_source_with_other_bytes_stops_everything():
    op = _opener({"first.invalid": b"tampered", "second.invalid": GOOD})
    with pytest.raises(ValueError, match="MISMATCH"):
        F.fetch_one("v.json", len(GOOD), hashlib.sha256(GOOD).hexdigest(),
                    sources=SOURCES, opener=op)
    assert len(op.seen) == 1, "after a mismatch no further source may be asked"


def test_no_reachable_source_is_not_measurable_and_not_a_verdict():
    op = _opener({"first.invalid": _404("first.invalid"), "second.invalid": OSError("down")})
    raw, label, unreachable = F.fetch_one("v.json", len(GOOD), hashlib.sha256(GOOD).hexdigest(),
                                          sources=SOURCES, opener=op)
    assert raw is None and label is None and len(unreachable) == 2
