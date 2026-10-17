"""Z43: the top-level help is grouped, names each command once, and says how to update.

The grouped list lives in `cli._COMMAND_GROUPS`, not in argparse, so it can drift from the parser in
two ways: a new command without a line, or a line whose command is gone. Both are caught here. The
maturity marker of each short line is held against the command's own long help, because a short line
that drops "(experimental)" tells a reader more than the command promises.
"""
from __future__ import annotations

import argparse
import contextlib
import io

import pytest

from proofbundle import cli


def _sub_action(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))


def _table() -> dict:
    return {name: text for _titel, zeilen in cli._COMMAND_GROUPS for name, text in zeilen}


def test_every_registered_command_has_exactly_one_line():
    registered = set(_sub_action(cli.build_parser()).choices)
    names = [name for _titel, zeilen in cli._COMMAND_GROUPS for name, _text in zeilen]
    assert len(names) == len(set(names)), "a command is listed twice"
    assert set(names) == registered, (
        f"missing from the grouped list: {sorted(registered - set(names))}; "
        f"listed but not registered: {sorted(set(names) - registered)}")


def test_maturity_marker_follows_the_long_help():
    long_help = {ca.dest: (ca.help or "") for ca in _sub_action(cli.build_parser())._choices_actions}
    for name, text in _table().items():
        lang = long_help[name].upper()
        for word in ("EXPERIMENTAL", "PROPOSED"):
            assert (word in lang) == (f"({word.lower()})" in text), (
                f"{name}: long help {'says' if word in lang else 'does not say'} {word}, "
                f"the short line {text!r} disagrees")


def _help() -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit) as ctx:
        cli.main(["--help"])
    assert ctx.value.code == 0
    return buf.getvalue()


def test_the_rendered_help_is_grouped_and_lists_each_command_once():
    h = _help()
    assert "<command> ..." in h.splitlines()[0]
    assert "{verify," not in h, "the flat brace list is back"
    assert "positional arguments" not in h
    for titel, zeilen in cli._COMMAND_GROUPS:
        assert f"\n  {titel}\n" in h
        for name, _text in zeilen:
            assert sum(1 for z in h.splitlines() if z.split()[:1] == [name]) == 1, name


#: WHERE EACH COMMAND BELONGS, as a LITERAL, not derived from `cli._COMMAND_GROUPS`.
#: The first attempt at this test built the expectation AND the measurement from the same table; a
#: mutant that moved `policy` from "Verify" to "Try it" moved both sides with it and stayed green
#: (measured 2026-09-22, after a review lens had found exactly this class in four places). A
#: grouping is a STATEMENT to the reader; whoever changes it changes these lines with it, and that
#: is the intent, not the burden.
EXPECTED_GROUP = {
    "verify": "Verify",
    "verify-proof": "Verify",
    "verify-opening": "Verify",
    "verify-enclave": "Verify",
    "policy": "Verify",
    "emit": "Emit and commit",
    "emit-eval": "Emit and commit",
    "show-eval": "Emit and commit",
    "prereg": "Emit and commit",
    "evalcard": "Emit and commit",
    "hf-token": "Emit and commit",
    "audit-challenge": "Emit and commit",
    "decision": "Statements over a receipt",
    "outcome": "Statements over a receipt",
    "relation-statement": "Statements over a receipt",
    "anchor": "Time anchors",
    "intoto": "Export to other formats",
    "svr": "Export to other formats",
    "demo": "Try it",
}
#: The order INSIDE a group as well, as a literal. The docstring of this file gives the grouping as
#: a statement to the reader, and a statement includes its order. Measured on 2026-09-22: a mutant
#: that swapped the five entries under "Verify" survived all nine tests, because membership and the
#: order of the headings were checked and the order below them was not. The same class as the other
#: findings of that day, a hardening at ONE place with the neighbouring place left open.
EXPECTED_ORDER_PER_GROUP = {
    "Verify": ["verify", "verify-proof", "verify-opening", "verify-enclave", "policy"],
    "Emit and commit": ["emit", "emit-eval", "show-eval", "prereg", "evalcard", "hf-token",
                        "audit-challenge"],
    "Statements over a receipt": ["decision", "outcome", "relation-statement"],
    "Time anchors": ["anchor"],
    "Export to other formats": ["intoto", "svr"],
    "Try it": ["demo"],
}
#: The order of the headings, also as a literal.
EXPECTED_HEADING_ORDER = ["Verify", "Emit and commit", "Statements over a receipt", "Time anchors",
                         "Export to other formats", "Try it"]


def test_the_table_groups_each_command_where_it_belongs():
    ist = {name: t for t, zeilen in cli._COMMAND_GROUPS for name, _ in zeilen}
    assert ist == EXPECTED_GROUP


def test_the_order_inside_each_group_is_the_declared_one():
    ist = {t: [n for n, _ in zeilen] for t, zeilen in cli._COMMAND_GROUPS}
    assert ist == EXPECTED_ORDER_PER_GROUP


def test_the_rendered_help_keeps_the_order_inside_each_group():
    h = _help().splitlines()
    aktuell, gesehen = None, {t: [] for t in EXPECTED_ORDER_PER_GROUP}
    for zeile in h:
        nackt = zeile.strip()
        if nackt in gesehen:
            aktuell = nackt
            continue
        wort = zeile.split()[:1]
        if aktuell and wort and zeile.startswith("    ") and wort[0] in EXPECTED_GROUP:
            if wort[0] not in gesehen[aktuell]:
                gesehen[aktuell].append(wort[0])
    assert gesehen == EXPECTED_ORDER_PER_GROUP


def test_each_command_is_RENDERED_under_its_own_heading():
    h = _help().splitlines()
    aktuell = None
    gesehen: dict[str, str] = {}
    for zeile in h:
        nackt = zeile.strip()
        if nackt in EXPECTED_HEADING_ORDER:
            aktuell = nackt
            continue
        wort = zeile.split()[:1]
        if aktuell and wort and zeile.startswith("    ") and wort[0] in EXPECTED_GROUP:
            gesehen.setdefault(wort[0], aktuell)
    assert gesehen == EXPECTED_GROUP, (
        "rendered under the wrong heading: "
        f"{ {k: (gesehen.get(k), v) for k, v in EXPECTED_GROUP.items() if gesehen.get(k) != v} }")


def test_the_groups_are_rendered_in_the_declared_order():
    h = _help()
    stellen = [h.index(f"\n  {t}\n") for t in EXPECTED_HEADING_ORDER]
    assert stellen == sorted(stellen), "the headings are not in the expected order"
    assert [t for t, _ in cli._COMMAND_GROUPS] == EXPECTED_HEADING_ORDER


def test_the_short_line_is_written_out_not_cut():
    # The draft's first rendering cut "pb1." to "pb1" when shortening the long help.
    assert "pb1. token" in _table()["hf-token"]


def test_help_and_version_both_say_how_to_update():
    assert cli.UPDATE_HINT in _help()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), pytest.raises(SystemExit):
        cli.main(["--version"])
    lines = buf.getvalue().rstrip("\n").splitlines()
    assert lines[-1] == cli.UPDATE_HINT
    assert lines[0].startswith("proofbundle ")


def test_a_missing_or_unknown_command_still_names_the_choices():
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as ctx:
        cli.main(["no-such-command"])
    assert ctx.value.code == 2
    assert "invalid choice" in err.getvalue() and "'verify'" in err.getvalue()
