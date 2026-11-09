"""B23: no command-line option of the package may be reached by an abbreviation.

argparse resolves a unique prefix of a long option to that option unless the parser is built with
``allow_abbrev=False``, and a subparser made by ``add_parser`` does not inherit the setting from its
parent. Measured on 6.5.0: ``proofbundle outcome verify ... --decision X`` was read as
``--decision-maker-id X``, so a word the caller did not write could steer a check. Since 6.6.0 ``--decision`` is an
option of its own, and ``--decision-m X`` was read as ``--decision-maker-id X`` at main c7f272b0 in the same way.

The cases are generated from the parser tree of ``proofbundle.cli.build_parser`` and from the
syntax tree of every module under ``src/``, so a parser added later without the setting fails here.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import io
import pathlib
import subprocess
import sys

import pytest

from proofbundle import cli

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"


def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()):
    yield path, parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield from _walk(sub, path + (name,))


def _value(action: argparse.Action) -> str:
    """A valid value that differs from the option's default, so a control cannot pass when the option is ignored."""
    if action.choices:
        other = [c for c in action.choices if c != action.default]
        return str((other or list(action.choices))[0])
    if action.type is int:
        return "2" if action.default == 1 else "1"
    return "y" if action.default == "x" else "x"


def _values(action: argparse.Action) -> list[str]:
    nargs = action.nargs
    if nargs == 0:
        return []
    if isinstance(nargs, int):
        return [_value(action)] * nargs
    return [_value(action)]


def _base_argv(parser: argparse.ArgumentParser, skip: argparse.Action | None = None) -> list[str]:
    """Positionals and required options, so the parser reaches the option under test."""
    argv: list[str] = []
    for action in parser._actions:
        if action is skip:
            continue
        if isinstance(action, argparse._SubParsersAction):
            name, sub = next(iter(action.choices.items()))
            argv += [name] + _base_argv(sub)
        elif not action.option_strings and action.nargs not in ("?", "*"):
            argv += _values(action)
        elif action.option_strings and action.required:
            argv += [action.option_strings[0]] + _values(action)
    return argv


def _abbreviation(option: str, longs: set[str]) -> str | None:
    """The shortest proper prefix argparse would have resolved to ``option`` alone, else a prefix
    shared with another option (ambiguous), else None when the option has no proper prefix."""
    for end in range(3, len(option)):
        prefix = option[:end]
        if prefix not in longs and [o for o in longs if o.startswith(prefix)] == [option]:
            return prefix
    prefix = option[:-1]
    if len(prefix) > 2 and prefix not in longs:
        return prefix
    return None


def _long_options():
    """(path, option, every long option of that parser) for each long option of the parser tree."""
    out = []
    for path, parser in _walk(cli.build_parser()):
        longs = {s for a in parser._actions for s in a.option_strings if s.startswith("--")}
        for action in parser._actions:
            for option in action.option_strings:
                if option.startswith("--"):
                    out.append((path, option, longs))
    return out


LONG_OPTIONS = _long_options()
# One abbreviation for each long option that has a proper prefix; a control for every long option, with or without.
CASES = [pytest.param(path, option, _abbreviation(option, longs), id=" ".join(path + (option,)))
         for path, option, longs in LONG_OPTIONS if _abbreviation(option, longs) is not None]
CONTROLS = [pytest.param(path, option, id=" ".join(path + (option,))) for path, option, _ in LONG_OPTIONS]


def _leaf(path: tuple[str, ...]) -> argparse.ArgumentParser:
    return dict(_walk(cli.build_parser()))[path]


def _argv(path: tuple[str, ...], parser: argparse.ArgumentParser, words: list[str],
          skip: argparse.Action | None = None) -> list[str]:
    """The option words go before a subcommand, so the parser under test reads them, and after
    the arguments of a leaf parser."""
    base = _base_argv(parser, skip)
    if any(isinstance(a, argparse._SubParsersAction) for a in parser._actions):
        return list(path) + words + base
    return list(path) + base + words


def _parse(argv: list[str]):
    out, err = io.StringIO(), io.StringIO()
    code = None
    ns = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            ns = cli.build_parser().parse_args(argv)
        except SystemExit as exc:
            code = exc.code
    return code, ns, err.getvalue()


def test_every_parser_in_the_tree_refuses_abbreviations():
    walked = list(_walk(cli.build_parser()))
    assert len(walked) > 1
    lax = [" ".join(path) or "proofbundle" for path, p in walked if p.allow_abbrev is not False]
    assert lax == []


def _parser_calls_without_allow_abbrev_false() -> tuple[int, list[str]]:
    seen, lax = 0, []
    for module in sorted(SRC.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"), str(module))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name not in ("ArgumentParser", "add_parser"):
                continue
            seen += 1
            ok = any(k.arg == "allow_abbrev" and isinstance(k.value, ast.Constant)
                     and k.value.value is False for k in node.keywords)
            if not ok:
                lax.append(f"{module.relative_to(SRC)}:{node.lineno}")
    return seen, lax


def test_every_parser_constructed_under_src_sets_allow_abbrev_false():
    seen, lax = _parser_calls_without_allow_abbrev_false()
    assert seen > 0, "no parser found under src/, the check measured nothing"
    assert lax == []


def test_the_cases_cover_the_parser_tree():
    assert len(CASES) > 100
    assert {c.values[0] for c in CASES} >= {path for path, _ in _walk(cli.build_parser())}
    # every long option has a control, also the ones without a proper prefix such as verify-opening --n
    assert len(CONTROLS) == len(LONG_OPTIONS) > len(CASES)
    assert ("verify-opening", "--n") in {(c.values[0][0] if c.values[0] else "", c.values[1]) for c in CONTROLS}


@pytest.mark.parametrize("path,option,abbrev", CASES)
def test_an_abbreviated_option_is_refused(path, option, abbrev):
    leaf = _leaf(path)
    action = leaf._option_string_actions[option]
    argv = _argv(path, leaf, [abbrev] + _values(action))
    code, ns, err = _parse(argv)
    assert code == 2, f"{argv!r} was accepted as {ns!r}"
    assert abbrev in err


@pytest.mark.parametrize("path,option", CONTROLS)
def test_the_full_option_still_applies(path, option):
    leaf = _leaf(path)
    action = leaf._option_string_actions[option]
    argv = _argv(path, leaf, [option] + _values(action), skip=action)
    code, ns, err = _parse(argv)
    if isinstance(action, (argparse._HelpAction, cli._VersionAction)):
        assert code == 0
        return
    assert code is None, err
    got = getattr(ns, action.dest)
    if isinstance(action, argparse._StoreTrueAction):
        assert got is True
    elif isinstance(action, argparse._AppendAction):
        assert got == [action.type(v) if action.type else v for v in _values(action)]
    else:
        want = _values(action)[0]
        assert got == (action.type(want) if action.type else want)


def test_the_measured_case_in_a_real_process(tmp_path):
    """The case of the finding: ``--decision-m`` must not become ``--decision-maker-id``."""
    receipt = tmp_path / "r.json"
    receipt.write_text("{}", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "proofbundle.cli", "outcome", "verify", str(receipt),
         "--pub", str(tmp_path / "k.pub"), "--decision-m", "dm-1"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2
    assert "unrecognized arguments: --decision-m dm-1" in proc.stderr
