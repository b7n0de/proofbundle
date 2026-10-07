"""The work count of `tests/_arbeitszaehler.py` is what the cost tests judge since Z309, so it is tested itself.

Four properties, each one a way the count could fail without anybody seeing it: it has to see quadratic work in Python
and inside a walking built-in method, it must not see a linear loop as more than linear, it has to give the same number
for the same call however loaded the machine is, and it has to hand the tracers of a coverage run back unchanged.
"""
from __future__ import annotations

import gc
import math
import sys
import threading

import pytest

from _arbeitszaehler import WALKING_METHODS, count_work, work


def _exponent(sizes, build):
    """The median log slope of the counted work over a doubling series."""
    points = [(n, work(build(n))) for n in sizes]
    slopes = sorted(math.log(k1 / k0) / math.log(n1 / n0) for (n0, k0), (n1, k1) in zip(points, points[1:]))
    return slopes[len(slopes) // 2]


def _nested(n):
    def f():
        s = 0
        for i in range(n):
            for j in range(n):
                s += 1
    return f


def _appends(n):
    def f():
        out = []
        for i in range(n):
            out.append(i)
    return f


def test_a_quadratic_loop_in_python_counts_quadratic():
    assert _exponent((100, 200, 400, 800), _nested) > 1.9


def test_a_quadratic_walk_inside_list_count_counts_quadratic():
    """One line per element, and a full walk of the list inside each `count`. Without the receiver this case is
    linear, which is exactly how the duplicate scan of cap1 hid."""
    def build(n):
        xs = list(range(n))
        return lambda: [xs.count(x) for x in xs]
    assert _exponent((100, 200, 400, 800), build) > 1.9
    xs = list(range(500))
    assert count_work(lambda: xs.count(1))["walked"] == 500


@pytest.mark.parametrize("call, expected", [
    (lambda s: s.find("z"), 1000),
    (lambda s: s.encode(), 1000),
    (lambda s: s.split(","), 1000),
])
def test_a_walking_str_method_counts_its_receiver(call, expected):
    s = "a" * 1000
    assert count_work(lambda: call(s))["walked"] == expected


def test_appending_is_not_counted_as_a_walk():
    """`append` costs the same however long the list is. Counting the receiver for it would turn every linear loop of
    appends into a quadratic count and make the bound meaningless."""
    assert "append" not in WALKING_METHODS and "pop" not in WALKING_METHODS and "insert" not in WALKING_METHODS
    assert count_work(_appends(2000))["walked"] == 0
    assert _exponent((500, 1000, 2000, 4000), _appends) < 1.05


def test_the_same_call_counts_the_same_with_and_without_a_busy_thread():
    """The point of the count. A thread that keeps the interpreter busy slows the call down and changes nothing in the
    number."""
    data = [str(i) for i in range(3000)]

    def call():
        return sorted(set(x.strip() for x in data if "1" in x))
    call()
    quiet = [count_work(call), count_work(call)]
    stop = threading.Event()

    def burn():
        x = 0
        while not stop.is_set():
            x += 1
    busy = threading.Thread(target=burn, daemon=True)
    busy.start()
    try:
        loaded = count_work(call)
    finally:
        stop.set()
        busy.join()
    assert quiet[0] == quiet[1] == loaded, (quiet, loaded)
    assert loaded["lines"] > 3000


def test_the_tracers_of_the_caller_are_handed_back():
    """A coverage run keeps its tracer in `sys.gettrace()`. The count replaces it for the call and must set it again,
    or coverage loses every line after the first counted call."""
    def tracer(frame, event, arg):
        return None

    def profiler(frame, event, arg):
        return None
    old_trace, old_profile = sys.gettrace(), sys.getprofile()
    sys.settrace(tracer)
    sys.setprofile(profiler)
    try:
        count_work(_appends(10))
        with pytest.raises(KeyError):
            count_work(lambda: {}["missing"])
        after = (sys.gettrace(), sys.getprofile())
    finally:
        sys.settrace(old_trace)
        sys.setprofile(old_profile)
    assert after == (tracer, profiler)


def test_a_limit_ends_the_count_past_it_and_says_so():
    """The limit gives the answer to "at or below N?" without counting a regression to its end. It must stop early,
    say that it stopped, report a number above the limit, and hand the tracers back as any other count does."""
    big = _nested(3000)                      # nine million iterations, far beyond the limit
    old_trace = sys.gettrace()
    counts = count_work(big, limit=10_000)
    assert counts["over_limit"] is True
    assert 10_000 < counts["lines"] + counts["walked"] < 10_100, counts
    assert sys.gettrace() is old_trace
    assert work(big, limit=10_000) > 10_000
    small = count_work(_appends(100), limit=10_000)
    assert small["over_limit"] is False and small["lines"] < 10_000
    assert count_work(_appends(100), limit=None)["lines"] == small["lines"]


def test_a_limit_is_not_swallowed_by_a_broad_except():
    """A verifier that turns every Exception into a refusal must not catch the stop and run on uncounted."""
    def guarded():
        try:
            _nested(3000)()
        except Exception:                    # noqa: BLE001 - the case under test
            return "refused"
    counts = count_work(guarded, limit=5_000)
    assert counts["over_limit"] is True and counts["lines"] < 5_100, counts


def test_an_accepted_refusal_is_a_result_and_any_other_error_is_raised():
    def refuse():
        for _ in range(5):
            pass
        raise ValueError("over the budget")
    counts = count_work(refuse, accepted=(ValueError,))
    assert counts["lines"] >= 5
    with pytest.raises(ValueError):
        count_work(refuse)


@pytest.mark.parametrize("enabled", [True, False])
def test_the_collector_is_paused_while_counting_and_restored_after(enabled):
    seen = []
    was = gc.isenabled()
    (gc.enable if enabled else gc.disable)()
    try:
        count_work(lambda: seen.append(gc.isenabled()))
        after = gc.isenabled()
    finally:
        (gc.enable if was else gc.disable)()
    assert seen == [False]
    assert after is enabled
