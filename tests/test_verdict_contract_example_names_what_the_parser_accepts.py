"""631 part 2, P2 group 3 of CODEX-DEFEKTSUCHE-630-KANDIDAT-01 (at 98b168b9): the example says what its parser accepts.

examples/verdict_contract/verdict_contract.py is vendored unchanged from tonydzi/verdict-contract, and the signed
record of the example names its sha256, so this repository does not change it. Its PROMPT_RULE asks for the bare
line `===VERDICT=== <value>` with "No backticks, no bold, no brackets, nothing else on that line", while its marker
pattern and `_REST_DECOR` read decoration (lines 60, 75 and 80). Measured at 063b4e22 with the body of
measure_cases.py: `APPROVE.`, `APPROVE:`, `` `APPROVE` ``, `**APPROVE**`, `**===VERDICT=== APPROVE**`, a quoted
`> ===VERDICT=== APPROVE`, `# ...`, `- ...`, `approve`, `== VERDICT == APPROVE`, `===verdict=== APPROVE`,
`===VERDICT===APPROVE` and `===VERDICT=== :APPROVE` as the last line each gave APPROVE, exit 0, and the example's
README did not say so. The README now carries a table of what the parser reads; this file holds the table to the
vendored bytes, so the description cannot drift from the parser in either direction.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "verdict_contract"
SECTION = "## What the parser accepts"
BARE = "===VERDICT=== APPROVE"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_vc_names_{name}", EXAMPLE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VC = _load("verdict_contract")


def _body() -> str:
    sys.path.insert(0, str(EXAMPLE))
    try:
        return _load("measure_cases").BODY.decode("utf-8")
    finally:
        sys.path.remove(str(EXAMPLE))


def _table() -> list[tuple[str, str]]:
    text = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    assert text.count(SECTION) == 1, f"the README has no section {SECTION!r}"
    section = text.split(SECTION, 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| `([^`]+)` \| (APPROVE|REQUEST_CHANGES|AMBIGUOUS) \|$", section, re.MULTILINE)


def test_the_readme_table_is_what_the_vendored_parser_reads():
    rows = _table()
    assert len(rows) >= 8, rows
    body = _body()
    got = [(line, VC.find_verdict(body + line + "\n")) for line, _ in rows]
    assert got == rows


def test_the_table_names_a_decorated_approve_the_rule_forbids():
    decorated = [line for line, verdict in _table() if verdict == "APPROVE" and line != BARE]
    assert any("*" in line for line in decorated) and any(line.startswith(">") for line in decorated), decorated
    assert "No backticks, no bold" in VC.PROMPT_RULE and "===VERDICT=== <value>" in VC.PROMPT_RULE


def test_control_the_parser_is_the_vendored_one_the_record_names():
    digest = hashlib.sha256((EXAMPLE / "verdict_contract.py").read_bytes()).hexdigest()
    record = json.loads((EXAMPLE / "out" / "verdict.json").read_text(encoding="utf-8"))
    assert record["parser"]["sha256"] == digest
    assert f"sha256 `{digest}`" in (EXAMPLE / "README.md").read_text(encoding="utf-8")
