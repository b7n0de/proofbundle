"""The guard of Nachtrag 6 to FIX-18 part B, point 1: a plugin test hands no process and not the gate the caller's
environment (tests/_plugin_env.py).

Measured at ac0e8a72 and at the naive merge 814c341a: 31 failing cases printed the whole environment as a dict, a
GITHUB_TOKEN among it, because the tests built the environment of the gate and of git as dict(os.environ, ...). The
property held here has two halves. In the source: no plugin test file uses os.environ as a whole, its copy, its items
or values, or a mapping built from it; reading, setting or taking out one name and walking the names stay allowed.
At run time: a plugin test module runs without the caller's names, so a process it starts without env= inherits none
of them. Exceptions are named below with their reason, and a named exception that no longer stands is a finding."""
from __future__ import annotations

import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import _plugin_env
from _plugin_env import FIXED, PYTEST_OWN, is_plugin_test, plugin_env

TESTS = pathlib.Path(__file__).resolve().parent
#: (file, source of the statement, reason). Each must still stand, word for word.
EXCEPTIONS = (
    ("test_plugin_gate_runde9.py", "saved = dict(os.environ)",
     "keeps the withheld environment of this module to put it back after an in-process run of the gate replaced "
     "os.environ with an environment made by plugin_env(); the copy reaches no process"),
    ("test_plugin_run_evidence.py", "saved = dict(os.environ)",
     "keeps the withheld environment of this module to put it back after an in-process run of the gate replaced "
     "os.environ with an environment made by plugin_env(); the copy reaches no process"),
    ("_plugin_env.py", "for name in os.environ:\n        if name.startswith(CASE_PREFIXES):\n"
                       "            env[name] = os.environ[name]",
     "plugin_env() copies the GIT_ and PROOFBUNDLE_ values the case set; with the caller's names withheld, no other "
     "value is left to copy"),
)
#: Methods of os.environ that read, set or take out one name, clear it, or fill it.
_ONE_NAME = {"get", "pop", "setdefault", "clear", "update", "keys", "__contains__"}
#: Texts that name the plugin: a test file carrying one is a plugin test.
_PLUGIN_MARKERS = ("plugins/proofbundle", '"plugins"', "proofbundle_gate", "import test_plugin_",
                   "from test_plugin_", "import test_claude_code_plugin", "import test_codex_plugin")


def _is_environ(node: ast.AST, from_os: set[str]) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in ("environ", "environb"):
        value = node.value
        return (isinstance(value, ast.Name) and value.id == "os") or (
            isinstance(value, ast.Attribute) and value.attr == "os")
    return isinstance(node, ast.Name) and node.id in from_os


def _reads_by_name(body: list[ast.AST], names: set[str], from_os: set[str]) -> bool:
    """Whether `body` reads os.environ[<a name of `names`>]: a walk over the names that copies the values."""
    for node in (n for b in body for n in ast.walk(b)):
        if isinstance(node, ast.Subscript) and _is_environ(node.value, from_os):
            if any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node.slice)):
                return True
    return False


def whole_environment_uses(source: str) -> list[tuple[int, str]]:
    """Each place `source` uses the environment as a whole: (line, statement source)."""
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    from_os = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
               and node.module == "os" for alias in node.names if alias.name in ("environ", "environb")}
    found = []
    for node in ast.walk(tree):
        if not _is_environ(node, from_os) or isinstance(parents.get(node), ast.ImportFrom):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.attr in _ONE_NAME:
            continue
        if isinstance(parent, ast.Subscript) and parent.value is node:
            continue
        if isinstance(parent, ast.Compare) and node in parent.comparators and all(
                isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops):
            continue
        if isinstance(parent, ast.comprehension) and parent.iter is node:
            owner = parents[parent]
            targets = {n.id for n in ast.walk(parent.target) if isinstance(n, ast.Name)}
            if isinstance(owner, (ast.ListComp, ast.SetComp, ast.GeneratorExp)) and not _reads_by_name(
                    [owner.elt], targets, from_os):
                continue
        if isinstance(parent, ast.For) and parent.iter is node:
            targets = {n.id for n in ast.walk(parent.target) if isinstance(n, ast.Name)}
            if not _reads_by_name(parent.body, targets, from_os):
                continue
        statement = node
        while not isinstance(statement, ast.stmt):
            statement = parents[statement]
        found.append((node.lineno, ast.get_source_segment(source, statement) or ""))
    return found


def _plugin_test_files() -> list[pathlib.Path]:
    return sorted(p for p in TESTS.glob("test_*.py") if is_plugin_test(p))


def _named(file: str, statement: str) -> bool:
    return any(file == f and statement.strip() == s for f, s, _ in EXCEPTIONS)


# --- the source ------------------------------------------------------------------------------------------------------

def test_no_plugin_test_hands_on_the_environment_as_a_whole():
    files = _plugin_test_files()
    assert len(files) >= 150, len(files)
    found = [f"{p.name}:{line}: {text.splitlines()[0]}" for p in files
             for line, text in whole_environment_uses(p.read_text(encoding="utf-8")) if not _named(p.name, text)]
    assert found == [], "\n".join(found)


def test_each_named_exception_still_stands_and_says_why():
    for file, statement, reason in EXCEPTIONS:
        uses = [text.strip() for _, text in whole_environment_uses((TESTS / file).read_text(encoding="utf-8"))]
        assert statement in uses, (file, statement)
        assert len(reason) > 40, (file, reason)


def test_the_helper_hands_on_no_environment_as_a_whole():
    found = whole_environment_uses((TESTS / "_plugin_env.py").read_text(encoding="utf-8"))
    assert [text for _, text in found if not _named("_plugin_env.py", text)] == []


# Planted counter-probes: each form once, each found once; the allowed forms found never.
PLANTED = {
    "dict": "subprocess.run(cmd, env=dict(os.environ))",
    "dict_with_values": "env = dict(os.environ, PATH='x')",
    "copy": "env = os.environ.copy()",
    "bare_keyword": "subprocess.run(cmd, env=os.environ)",
    "unpacked": "env = {**os.environ, 'A': 'b'}",
    "items": "env = {k: v for k, v in os.environ.items() if k != 'A'}",
    "values": "x = list(os.environ.values())",
    "assigned": "env = os.environ",
    "returned": "def f():\n    return os.environ",
    "in_process": "gate.decide('git status', '.', 1.0, 'claude', dict(os.environ))",
    "module_alias": "env = dict(n2c.os.environ, GIT_TRACE='1')",
    "from_import": "from os import environ\nenv = dict(environ)",
    "environb": "env = dict(os.environb)",
    "dict_by_name": "env = {k: os.environ[k] for k in os.environ}",
    "loop_by_name": "env = {}\nfor k in os.environ:\n    env[k] = os.environ[k]",
    "list_of_values": "vals = [os.environ[k] for k in os.environ]",
}
ALLOWED = ("x = os.environ.get('A')\ny = os.environ['B']\nos.environ['C'] = 'd'\nz = 'E' in os.environ\n"
           "for k in [k for k in os.environ if k.startswith('GIT_')]:\n    monkeypatch.delenv(k)\n"
           "os.environ.pop('F', None)\nfrom os import environ\nw = environ.get('G')\n")


@pytest.mark.parametrize("form", sorted(PLANTED))
def test_a_planted_whole_environment_use_is_found(form):
    found = whole_environment_uses("import os, subprocess\n" + PLANTED[form])
    assert len(found) == 1, (form, found)


def test_the_allowed_one_name_forms_are_not_found():
    assert whole_environment_uses("import os\n" + ALLOWED) == []


def test_every_test_file_that_names_the_plugin_is_a_plugin_test():
    named = [p.name for p in sorted(TESTS.glob("test_*.py"))
             if any(m in p.read_text(encoding="utf-8") for m in _PLUGIN_MARKERS)]
    assert len(named) >= 150, len(named)
    assert [n for n in named if not is_plugin_test(TESTS / n)] == []
    for stem in _plugin_env.NOT_PLUGIN:
        text = (TESTS / f"{stem}.py").read_text(encoding="utf-8")
        assert not any(m in text for m in _PLUGIN_MARKERS), stem


def test_conftest_brings_the_fixture_to_every_module():
    tree = ast.parse((TESTS / "conftest.py").read_text(encoding="utf-8"))
    imported = {(n.module, a.name) for n in tree.body if isinstance(n, ast.ImportFrom) for a in n.names}
    assert ("_plugin_env", "withhold_caller_environment") in imported


# --- the run ---------------------------------------------------------------------------------------------------------

def test_this_plugin_test_runs_without_the_callers_names():
    names = [n for n in os.environ]
    assert set(names) <= set(FIXED) | {PYTEST_OWN}, sorted(set(names) - set(FIXED) - {PYTEST_OWN})


def test_the_helper_keeps_the_fixed_list_and_what_the_case_set(monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", "/gate")
    monkeypatch.setenv("GITHUB_TOKEN", "planted")
    env = plugin_env(PATH="/bin", GIT_DIR="d", PROOFBUNDLE_GATE_DIR=None)
    assert env["PATH"] == "/bin" and env["GIT_DIR"] == "d" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert "PROOFBUNDLE_GATE_DIR" not in env and "GITHUB_TOKEN" not in env and PYTEST_OWN not in env
    assert set(env) <= set(FIXED) | {"GIT_CONFIG_GLOBAL", "GIT_DIR"}
    assert "GIT_CONFIG_GLOBAL" not in plugin_env(without=("GIT_CONFIG",))
    with pytest.raises(TypeError):
        plugin_env(without="GIT_")


_PLANTED_MODULE = '''
import json, os, pathlib, subprocess, sys
import pytest
from _plugin_env import plugin_env

OUT = pathlib.Path(__file__).with_suffix(".json")
CHILD = "import json, os, sys; print(json.dumps(sorted(os.environ)))"


@pytest.fixture(scope="module")
def module_names():
    return sorted(os.environ)


def test_child(module_names, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    child = json.loads(subprocess.run([sys.executable, "-I", "-c", CHILD], capture_output=True, text=True,
                                      check=True).stdout)
    try:
        helper = sorted(plugin_env())
    except RuntimeError:
        helper = None
    OUT.write_text(json.dumps({"child": child, "module": module_names, "helper": helper}))
'''


def _planted_run(tmp_path: pathlib.Path, planted: dict) -> tuple[subprocess.CompletedProcess, dict, dict]:
    """A pytest run whose caller sets `planted`, with this helper and fixture, a plugin module and a module of another
    name; what each module's child process, module fixture and plugin_env() saw (names only)."""
    tests = tmp_path / "tests"
    tests.mkdir()
    shutil.copy(TESTS / "_plugin_env.py", tests / "_plugin_env.py")
    (tests / "conftest.py").write_text("from _plugin_env import withhold_caller_environment  # noqa: F401\n",
                                       encoding="utf-8")
    (tests / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    for name in ("test_plugin_planted.py", "test_other_planted.py"):
        (tests / name).write_text(_PLANTED_MODULE, encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tests),
                           str(tests)], capture_output=True, text=True, timeout=300, check=False,
                          cwd=tmp_path, env=plugin_env(**planted))
    assert proc.returncode == 0, proc.stdout[-2000:]
    plugin = json.loads((tests / "test_plugin_planted.json").read_text(encoding="utf-8"))
    other = json.loads((tests / "test_other_planted.json").read_text(encoding="utf-8"))
    return proc, plugin, other


def test_a_planted_caller_value_reaches_no_process_of_a_plugin_test(tmp_path):
    """Counter-probe: a pytest run whose caller sets a token, an askpass program and a GIT_ value. The plugin module's
    child process, its module fixture and plugin_env() see none of them; a module of another name sees them all,
    which shows the planting reached the run."""
    planted = {"GITHUB_TOKEN": "PLANTED-N6P1", "GH_TOKEN": "PLANTED-N6P1", "GIT_ASKPASS": "/planted/askpass",
               "SSH_ASKPASS": "/planted/askpass", "GIT_CONFIG_COUNT": "0"}
    proc, plugin, other = _planted_run(tmp_path, planted)
    assert "PLANTED-N6P1" not in proc.stdout + proc.stderr
    for names in (plugin["child"], plugin["module"], plugin["helper"]):
        assert not set(names) & set(planted), names
    assert set(plugin["module"] + plugin["helper"]) <= set(FIXED) | {PYTEST_OWN, "GIT_CONFIG_GLOBAL"}, plugin
    # The child may carry three names the run makes itself, measured: LC_CTYPE from Python's locale coercion (PEP 538)
    # in the child, COLUMNS and LINES from GNU readline, which pytest loads and which sets them in the C environment.
    made = {"LC_CTYPE", "COLUMNS", "LINES"}
    assert set(plugin["child"]) <= set(FIXED) | {PYTEST_OWN, "GIT_CONFIG_GLOBAL"} | made, plugin
    assert set(planted) <= set(other["child"]) and set(planted) <= set(other["module"]), other
    assert other["helper"] is None


def test_uv_offline_and_its_cache_pass_and_a_proxy_or_certificate_path_does_not(tmp_path):
    """Owner answer of Nachtrag 8: UV_OFFLINE and UV_CACHE_DIR carry no secret, so the caller's values reach a plugin
    module's child process, its module fixture and plugin_env(); a proxy name, a certificate path and any other uv
    name do not. A module of another name sees them all."""
    passed = {"UV_OFFLINE": "1", "UV_CACHE_DIR": str(tmp_path / "uv-cache")}
    withheld = {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
                "HTTP_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9",
                "SSL_CERT_FILE": "/planted/ca.pem", "REQUESTS_CA_BUNDLE": "/planted/ca.pem",
                "UV_INDEX_URL": "https://planted.invalid/simple"}
    _proc, plugin, other = _planted_run(tmp_path, {**passed, **withheld})
    for names in (plugin["child"], plugin["module"], plugin["helper"]):
        assert set(passed) <= set(names), names
        assert not set(withheld) & set(names), names
    assert set(passed) | set(withheld) <= set(other["child"]), other
