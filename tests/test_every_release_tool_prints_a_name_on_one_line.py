"""Every release tool prints a name on one line, and with one reading.

7056ebf6 fixed the version gate: a tracked file named `docs/z<LF>  - README.md:1: fake finding.md`
split one printed problem into two items, one blaming README.md. A review lens, run 10 at 50f3ef33
(2026-09-26), found the class standing in the other four release tools: the mutant guard's findings,
the language gate's text form, the digest resolver's reason and the receipt verifier's `receipt=` and
reason each printed a name with a line break raw, so a file name could write a line that reads like
a verdict. Each case below was reproduced there. The same quoting function, `_pfad`, now stands in
each of the five tools, and a test holds the five copies identical, since the guard and the version
gate run on a bare interpreter where one tool does not import another.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("scripts/mutant_signature_guard.py", "scripts/neue_zeilen_sind_englisch.py",
         "scripts/audit_output_aufloesbar.py", "scripts/verify_pre_tag_receipt.py",
         "scripts/check_version_and_changelog.py")
#: A name that writes a line of its own when printed raw, shaped like one of the guard's findings.
NAME = "z\n  ok.py:1: fake verdict"
GERMAN = "Diese Zeile ist deutsch und die Pruefung muss sie sehen.\n"


def _function_source(path: Path, name: str) -> str | None:
    text = path.read_text(encoding="utf-8")
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    return None


def _guard_module():
    spec = importlib.util.spec_from_file_location("_one_line_guard", ROOT / TOOLS[0])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_five_tools_carry_one_and_the_same_quoting_function():
    sources = {tool: _function_source(ROOT / tool, "_pfad") for tool in TOOLS}
    assert all(sources.values()), [tool for tool, source in sources.items() if not source]
    assert len(set(sources.values())) == 1, "the five copies of `_pfad` differ"


def test_the_two_tools_that_quote_a_line_of_a_file_carry_the_same_excerpt_function():
    sources = {_function_source(ROOT / tool, "_auszug") for tool in TOOLS[:2]}
    assert None not in sources and len(sources) == 1


def test_the_five_tools_carry_one_and_the_same_function_for_an_unexpected_exception():
    """Each tool ends a run on an exception no branch names in its own verdict for what it did not judge
    (a review lens, 2026-09-27 at 53676296: exit 1, the code of a finding, in the guard and the gate)."""
    sources = {tool: _function_source(ROOT / tool, "_unerwartet") for tool in TOOLS}
    assert all(sources.values()), [tool for tool, source in sources.items() if not source]
    assert len(set(sources.values())) == 1, "the five copies of `_unerwartet` differ"


def test_an_unexpected_exception_is_one_line_even_when_its_message_cannot_be_printed():
    """`str()` of an exception that carries an int past the digit limit raises in turn."""
    unerwartet = _guard_module()._unerwartet
    for message in (int("f" * 3600, 16), "a\nb\u2028c"):
        try:
            raise ValueError(message)
        except ValueError as exc:
            line = unerwartet(exc)
        assert line.splitlines() == [line], line
        assert line.startswith("an unexpected exception at test_every_release_tool_prints_a_name_on_one_line.py:")
    assert line.endswith('"ValueError: a\\nb\\u2028c"'), line


@pytest.mark.parametrize("name,printed", [
    ("docs/a.md", "docs/a.md"),
    ("docs/pr\u00fcfung.md", "docs/pr\u00fcfung.md"),
    ('a"b.py', '"a\\"b.py"'),
    ("a\\b.py", '"a\\\\b.py"'),
    ("z\n  - README.md:1: x", '"z\\n  - README.md:1: x"'),
    ("a\u2028b.md", '"a\\u2028b.md"'),
    ("\udcff.py", '"\\udcff.py"'),
], ids=["plain", "non-ascii", "quote", "backslash", "newline", "line-separator", "not-utf8"])
def test_the_quoting_function_writes_one_line_with_one_reading(name, printed):
    pfad = _guard_module()._pfad
    assert pfad(name) == printed
    assert pfad(name).splitlines() == [pfad(name)]
    if printed != name:
        assert ast.literal_eval(printed) == name            # one reading: the quoted form reads back


def _git(repo: Path, *args: str, **kw) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True, **kw).stdout.strip()


def _run(tool: str, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(ROOT / tool), *args], cwd=str(cwd),
                          capture_output=True, text=True, timeout=300)


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "r"
    (r / "src" / "proofbundle").mkdir(parents=True)
    (r / "docs").mkdir()
    (r / "src" / "proofbundle" / "g.py").write_text("x = 0\n", encoding="utf-8")
    (r / "docs" / "a.md").write_text("# T\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _no_forged_line(stdout: str) -> None:
    assert not any(line.startswith("  ok.py:1: fake verdict") for line in stdout.splitlines()), stdout


def test_the_guard_prints_a_finding_under_such_a_name_on_one_line(repo):
    (repo / "src" / "proofbundle" / f"{NAME}.py").write_text("if False:\n    pass\n", encoding="utf-8")
    _git(repo, "add", "-A")
    r = _run(TOOLS[0], "--staged", cwd=repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert '  "src/proofbundle/z\\n  ok.py:1: fake verdict.py":1: trivial-truth branch' in r.stdout, r.stdout
    _no_forged_line(r.stdout)


def test_the_language_gate_prints_a_finding_under_such_a_name_on_one_line(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "docs" / f"{NAME}.md").write_text(GERMAN, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a German line under such a name")
    r = _run(TOOLS[1], "--base", base, cwd=repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert '  "docs/z\\n  ok.py:1: fake verdict.md":1  [' in r.stdout, r.stdout
    _no_forged_line(r.stdout)


def test_the_resolver_names_a_match_under_such_a_name_on_one_line(repo, tmp_path):
    (repo / "docs" / f"{NAME}.md").write_text(GERMAN, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a record under such a name")
    receipt = tmp_path / "q.json"
    receipt.write_text(json.dumps({"audit_output_digest": hashlib.sha256(GERMAN.encode()).hexdigest()}),
                       encoding="utf-8")
    r = _run(TOOLS[2], "--receipt", str(receipt), "--repo", str(repo), cwd=repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(r.stdout.splitlines()) == 1, r.stdout
    assert '"docs/z\\n  ok.py:1: fake verdict.md"' in r.stdout, r.stdout


def test_the_receipt_verifier_names_a_candidate_under_such_a_name_on_one_line(repo):
    gate = ROOT / "scripts" / "pre_tag_audit_gate.py"
    if not gate.is_file():
        pytest.skip("the gate is not here (sdist without repo context)")
    (repo / "scripts").mkdir()
    (repo / "scripts" / "pre_tag_audit_gate.py").write_bytes(gate.read_bytes())
    (repo / "audit_artifacts" / "610").mkdir(parents=True)
    (repo / "audit_artifacts" / "610" / f"{NAME}.json").write_text("[1]", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a candidate under such a name")
    r = _run(TOOLS[3], "--repo", str(repo), "--commit", _git(repo, "rev-parse", "HEAD"), "--version", "6.1.0",
             cwd=repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert 'receipt="audit_artifacts/610/z\\n  ok.py:1: fake verdict.json"' in r.stdout, r.stdout
    assert '  "audit_artifacts/610/z\\n  ok.py:1: fake verdict.json": the committed receipt' in r.stdout, r.stdout
    _no_forged_line(r.stdout)


def test_the_version_gate_prints_a_tag_name_on_one_line(tmp_path):
    """The sweep of the class in the fifth tool, beyond the path 7056ebf6 quoted: a tag name may hold a
    U+2028, which git allows and a reader that splits lines ends a line at."""
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "HEAD"], capture_output=True)
    if archive.returncode != 0:
        pytest.skip("NOT MEASURABLE here: this tree is not a git checkout")
    t = tmp_path / "tree"
    t.mkdir()
    subprocess.run(["tar", "-x", "-C", str(t)], input=archive.stdout, check=True)
    _git(t, "init", "-q")
    _git(t, "add", "-A")
    _git(t, "commit", "-q", "-m", "the tree")
    _git(t, "tag", "review\u2028OK")
    r = _run(TOOLS[4], "--repo", str(t), cwd=t)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "\u2028" not in r.stdout, r.stdout
    assert '(latest reachable tag: "review\\u2028OK")' in r.stdout, r.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
