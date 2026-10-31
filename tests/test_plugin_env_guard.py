"""The guard of follow-up note 6 to review fix 18 part B, point 1: a plugin test hands no process and not the gate the caller's
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
from _gate_answer import skip_where_the_gate_is_not_shipped
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
    ("test_integration_docs_name_only_defaults_the_code_has.py",
     'ohne = {k: v for k, v in os.environ.items() if not k.startswith("PROOFBUNDLE_")}',
     "_measured_defaults reads the emission config in-process with every PROOFBUNDLE_ name taken out; the copy goes "
     "only to mock.patch.dict for one call of emit_config() and reaches no process"),
    ("test_integration_docs_name_only_defaults_the_code_has.py",
     "with mock.patch.dict(os.environ, ohne, clear=True):\n        cfg = emit_config()",
     "replaces os.environ in-process for one call of emit_config() and puts it back; no process is started"
     ""),
    ("_plugin_env.py", "for name in os.environ:\n        if name.startswith(CASE_PREFIXES):\n"
                       "            env[name] = os.environ[name]",
     "plugin_env() copies the GIT_ and PROOFBUNDLE_ values the case set; with the caller's names withheld, no other "
     "value is left to copy"),
)
#: Methods of os.environ that read, set or take out one name, clear it, or fill it.
_ONE_NAME = {"get", "pop", "setdefault", "clear", "update", "keys", "__contains__"}
#: Texts that name the plugin: a test file carrying one is a plugin test (the one list, in tests/_plugin_env.py).
_PLUGIN_MARKERS = _plugin_env.MARKERS


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


def _touches_the_plugin(path: pathlib.Path) -> bool:
    """Whether a test module touches the plugin, read from its syntax tree and not from the marker texts of
    _plugin_env: a string constant that is the plugins directory, a path in it or one of its two manifest folders, or
    an import of a plugin test module or of a module of the plugin. Quotes, implicit concatenation and line breaks do
    not change a constant, so a spelling the marker list does not know is still read here."""
    stems = {p.stem for p in (TESTS.parent / "plugins" / "proofbundle").rglob("*.py")}
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if value == "plugins" or any(t in value for t in ("plugins/proofbundle", ".claude-plugin", ".codex-plugin")):
                return True
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        if any(n.split(".")[0].startswith(_plugin_env.PLUGIN_PREFIXES) or n.split(".")[0] in stems for n in names):
            return True
    return False


def test_every_test_module_that_touches_the_plugin_is_a_plugin_test():
    """The lens on the cut of pull request 403 (finding 3): the selection reads texts, and a text is a spelling, so
    it can only fail open, and this guard read the same list. Here the guard reads the syntax tree; measured over the
    821 modules of the tree, 286 touch the plugin, each is selected, and none that touches it is left out."""
    touching = [p for p in sorted(TESTS.glob("test_*.py")) if _touches_the_plugin(p)]
    assert len(touching) >= 150, len(touching)
    assert [p.name for p in touching if not is_plugin_test(p)] == []


def test_the_guard_reads_a_spelling_the_marker_list_does_not_know(tmp_path):
    """Gate meta test: a module the selection catches by a word of its name that names the plugins directory as two
    implicitly joined strings carries no marker text, so the selection misses it; the syntax tree still reads the
    directory, and so the guard above would be red for it. A module of the library stays untouched."""
    hidden = tmp_path / "test_release_gate_planted.py"
    hidden.write_text('import pathlib\nP = pathlib.Path("plug" "ins") / "proof" "bundle"\n', encoding="utf-8")
    library = tmp_path / "test_core_layer_gate_planted.py"
    library.write_text("import os\nENV = dict(os.environ)\nWORD = 'plugin'\n", encoding="utf-8")
    hook = tmp_path / "test_codex_planted.py"
    hook.write_text("import pin_state_schleuse\n", encoding="utf-8")
    assert (is_plugin_test(hidden), _touches_the_plugin(hidden)) == (False, True)
    assert (is_plugin_test(library), _touches_the_plugin(library)) == (False, False)
    # the names of the plugin's modules come from plugins/, which a distribution without the plugin lacks
    skip_where_the_gate_is_not_shipped(TESTS.parent / "plugins" / "proofbundle" / "hooks" / "pin_state_schleuse.py",
                                       TESTS.parent)
    assert (is_plugin_test(hook), _touches_the_plugin(hook)) == (True, True)


def test_a_test_of_the_library_named_after_one_of_its_gates_is_no_plugin_test(tmp_path):
    """The cut of pull request 403, finding 3: the selection by name took main's tests named after one of the library's
    own gates for plugin tests, so they ran without their caller's environment and this guard read their source;
    test_core_layer_gate_judges_every_binding.py, which main added after the plugin branch, builds an environment from
    os.environ and turned the guard red. A name the selection catches without a plugin prefix is a plugin test only
    with a text that names the plugin."""
    library = tmp_path / "test_core_layer_gate_planted.py"
    library.write_text("import os\nENV = dict(os.environ)\n", encoding="utf-8")
    naming = tmp_path / "test_release_gate_planted.py"
    naming.write_text("import test_plugin_gate_n2c_push_done as n2c\n", encoding="utf-8")
    prefixed = tmp_path / "test_plugin_planted.py"
    prefixed.write_text("", encoding="utf-8")
    assert (is_plugin_test(library), is_plugin_test(naming), is_plugin_test(prefixed)) == (False, True, True)
    of_main = [TESTS / f"{stem}.py" for stem in ("test_core_layer_gate_judges_every_binding", "test_pr_form_gate")]
    assert any(p.exists() for p in of_main)
    assert [p.name for p in of_main if p.exists() and is_plugin_test(p)] == []


def test_conftest_brings_the_fixture_to_every_module():
    tree = ast.parse((TESTS / "conftest.py").read_text(encoding="utf-8"))
    # the import may stand in a try at the top whose one handler lets only the missing _plugin_env itself pass (finding
    # 1 of the cut of pull request 403: tests of the library copy conftest.py alone into a throwaway tree)
    tries = [n for n in tree.body if isinstance(n, ast.Try)]
    top = tree.body + [b for t in tries for b in t.body]
    imported = {(n.module, a.name) for n in top if isinstance(n, ast.ImportFrom) for a in n.names}
    assert ("_plugin_env", "withhold_caller_environment") in imported
    for t in tries:
        if any(isinstance(b, ast.ImportFrom) and b.module == "_plugin_env" for b in t.body):
            (handler,) = t.handlers
            assert ast.unparse(handler.type) == "ModuleNotFoundError", ast.unparse(handler)
            assert "exc.name != '_plugin_env'" in ast.unparse(handler) and "raise" in ast.unparse(handler)


@pytest.mark.parametrize("plugin_env_source, stops", [
    (None, False),
    ("import a_module_that_is_not_there_403\n", True),
    ("from _plugin_env_twin_403 import withhold_caller_environment\n", True),
])
def test_conftest_lets_only_the_missing_plugin_env_itself_pass(tmp_path, plugin_env_source, stops):
    """The lens on finding 1, run and not only read: conftest.py in a throwaway checkout without _plugin_env.py
    collects and runs, and a _plugin_env.py whose own import fails still stops the collection, with that module named.
    A handler that let every missing module pass would make the last two cases collect."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tmp_path / "SPEC.md").write_text("a checkout marker of conftest.py\n", encoding="utf-8")
    shutil.copy(TESTS / "conftest.py", tests / "conftest.py")
    if plugin_env_source is not None:
        (tests / "_plugin_env.py").write_text(plugin_env_source, encoding="utf-8")
    (tests / "test_one_planted.py").write_text("def test_one():\n    pass\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tmp_path),
                           str(tests)], capture_output=True, text=True, timeout=300, check=False, cwd=tmp_path,
                          env=plugin_env())
    out = proc.stdout + proc.stderr
    if stops:
        assert proc.returncode not in (0, 1), out[-2000:]
        assert plugin_env_source.split()[1] in out, out[-2000:]
    else:
        assert proc.returncode == 0 and "1 passed" in out, out[-2000:]


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
    """Owner answer of follow-up note 8: UV_OFFLINE and UV_CACHE_DIR carry no secret, so the caller's values reach a plugin
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


_IMPORTING_MODULE = '''
import json, pathlib, subprocess, sys

OUT = pathlib.Path(__file__).with_suffix(".json")


def test_child():
    import proofbundle
    child = subprocess.run([sys.executable, "-c", "import proofbundle; print(proofbundle.__file__)"],
                           capture_output=True, text=True, check=True).stdout.strip()
    OUT.write_text(json.dumps({"child": child, "self": proofbundle.__file__}))
'''


def test_a_child_of_a_plugin_test_imports_the_proofbundle_the_test_imports(tmp_path):
    """The witness runs pytest with -o pythonpath=src: src/ stands on sys.path of the test process only, and a child it
    starts without PYTHONPATH imported the proofbundle its interpreter has installed (measured on the witness of 31
    October 2026: 6.0.0, without proofbundle._plain_value, and 13 cases of the pilot went red). Here a run whose caller
    puts a decoy proofbundle on PYTHONPATH and this tree's src/ on pythonpath: the plugin module's child imports the
    package its test imports, a module of another name keeps the caller's PYTHONPATH and reads the decoy, which shows
    the decoy reached the run. Red at e4b614b0, where the plugin module's child read the decoy too."""
    import proofbundle  # noqa: PLC0415 - the package this run imports, whose src/ the inner run gets
    src = pathlib.Path(proofbundle.__file__).resolve().parent.parent
    decoy = tmp_path / "decoy"
    (decoy / "proofbundle").mkdir(parents=True)
    (decoy / "proofbundle" / "__init__.py").write_text("DECOY = True\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    shutil.copy(TESTS / "_plugin_env.py", tests / "_plugin_env.py")
    (tests / "conftest.py").write_text("from _plugin_env import withhold_caller_environment  # noqa: F401\n",
                                       encoding="utf-8")
    (tests / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    for name in ("test_plugin_planted.py", "test_other_planted.py"):
        (tests / name).write_text(_IMPORTING_MODULE, encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", str(tests),
                           "-o", f"pythonpath={src}", str(tests)], capture_output=True, text=True, timeout=300,
                          check=False, cwd=tmp_path, env=plugin_env(PYTHONPATH=str(decoy)))
    assert proc.returncode == 0, proc.stdout[-2000:]
    plugin = json.loads((tests / "test_plugin_planted.json").read_text(encoding="utf-8"))
    other = json.loads((tests / "test_other_planted.json").read_text(encoding="utf-8"))
    for seen in (plugin, other):
        assert pathlib.Path(seen["self"]).resolve().parent.parent == src, seen
    assert pathlib.Path(plugin["child"]).resolve() == pathlib.Path(plugin["self"]).resolve(), plugin
    assert pathlib.Path(other["child"]).resolve().parent.parent == decoy.resolve(), other
