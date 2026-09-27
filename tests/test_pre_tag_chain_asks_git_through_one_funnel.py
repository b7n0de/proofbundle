"""Every git call of the pre-tag receipt chain goes through a funnel, and the funnel gives one
answer whatever the environment and the configuration say.

Two generators instead of point fixtures, because the point fixtures of the previous round each
closed one instance and the next lens found the neighbour:

  the call sites   derived from the syntax tree of every file the chain loads (the producer, the
                   release gate, the third-party verifier, and whatever they import or load by
                   path, down to the package modules). Any call that can start a process must sit
                   in the funnel `pre_tag_receipt_lib.git_run`, in its copy `_git` in the
                   third-party verifier, or be the one call that starts the audit program, which is
                   not a question to git. A new git call anywhere else in the chain fails here
                   without anyone having to remember to add a case. The verifier's copy exists
                   because its cleanliness check must not run on the library it checks; the two
                   are held equal in allowlist, pinned options and built environment.
  the answers      one fixture repository, five answers computed through the chain's own
                   functions (tree digest, trust anchor, the producer's tree measurement, the gate
                   source digest, the verifier's cleanliness listing), first on a clean baseline and
                   then under each environment name and configuration key of a sweep: the names
                   and keys of the findings of this round (excludes file, replacement switch, work
                   tree, pathspec and trace names) and of the Codex finding on the
                   verifier, the 22 settings the lens found without effect on `4e67ba25`, and the
                   rest of git's repository-local names. Every answer must equal the baseline. For
                   the settings that ARE live, a plain `git` call in the same fixture shows that the
                   setting changes git's answer there, so equality means the funnel held, not that
                   the fixture measured nothing. A setting whose attack does not exist on the git
                   under test is reported as a skipped subtest that names the version and the
                   reason, and only where the reason is measured; it is never counted as passed.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

#: The entry points of the chain. Everything they load is derived below, not listed.
_ENTRIES = ("scripts/pre_tag_receipt.py", "scripts/pre_tag_audit_gate.py",
            "scripts/verify_pre_tag_receipt.py")
#: The places that may start git: the library's funnel, and the verifier's copy of it (which
#: must run on the verifier's own file, see its comment). And the one place that may start the
#: audit program.
_FUNNELS = (("scripts/pre_tag_receipt_lib.py", "git_run"), ("scripts/verify_pre_tag_receipt.py", "_git"))
_FUNNEL = _FUNNELS[0]
_AUDIT_RUN = ("scripts/pre_tag_receipt.py", "_audit_ausfuehren")
#: A file the chain loads for data only: which file loads it, under which name, and the only
#: attributes read from it. Its functions (three of which run git) are never called by the chain.
_DATA_ONLY = {"scripts/sign_readiness_artifact.py":
              ("scripts/pre_tag_receipt_lib.py", "_mod", {"MUTABLE_EVIDENCE_RELS"})}

_SUBPROCESS_STARTERS = {"run", "Popen", "call", "check_call", "check_output", "getoutput",
                        "getstatusoutput"}
_OS_STARTERS = {"system", "popen", "fork", "forkpty"}
_OS_PREFIXES = ("exec", "spawn", "posix_spawn")


def _module_files(rel: str, node: ast.AST) -> list[str]:
    """The repository files an import statement or a by-path load in `rel` refers to."""
    if isinstance(node, ast.Import):
        mods = [a.name for a in node.names]
    elif isinstance(node, ast.ImportFrom):
        if node.level:
            base = pathlib.PurePosixPath(rel).parent
            for _ in range(node.level - 1):
                base = base.parent
            mod = ".".join(base.parts) + (f".{node.module}" if node.module else "")
        else:
            mod = node.module or ""
        mods = [mod] + [f"{mod}.{a.name}" for a in node.names]
    elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
          and node.value.endswith(".py") and "/" not in node.value and " " not in node.value):
        mods = [f"scripts.{node.value[:-3]}"]          # `Path(__file__).parent / "<name>.py"`
    else:
        return []
    found = []
    for mod in mods:
        parts = mod.removeprefix("src.").split(".")
        candidates = ["src/" + "/".join(parts) + ".py", "src/" + "/".join(parts) + "/__init__.py"]
        if len(parts) == 1 or parts[0] == "scripts":
            candidates.append(f"scripts/{parts[-1]}.py")
        # importing `a.b` runs `a/__init__.py` first
        for i in range(1, len(parts)):
            candidates.append("src/" + "/".join(parts[:i]) + "/__init__.py")
        found += [c for c in candidates if (REPO / c).is_file()]
    return found


def _chain_files() -> dict[str, ast.Module]:
    todo, seen = list(_ENTRIES), {}
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        seen[rel] = ast.parse((REPO / rel).read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(seen[rel]):
            todo += _module_files(rel, node)
    return seen


def _parents(tree: ast.AST) -> dict:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _enclosing_functions(node: ast.AST, parents: dict) -> list[str]:
    names = []
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
    return names


def _process_calls(tree: ast.Module) -> list[ast.Call]:
    """Every call in `tree` that can start a process, whatever name the module was bound to."""
    sp_mods, sp_funcs, os_mods, os_funcs, others = {"subprocess"}, set(), {"os"}, set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "subprocess":
                    sp_mods.add(a.asname or a.name)
                elif a.name == "os":
                    os_mods.add(a.asname or a.name)
                elif a.name in ("asyncio", "pty"):
                    others.add(a.asname or a.name)
        elif isinstance(node, ast.ImportFrom) and node.module in ("subprocess", "os", "pty",
                                                                  "asyncio"):
            for a in node.names:
                (sp_funcs if node.module == "subprocess" else os_funcs).add(a.asname or a.name)
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            owner, attr = f.value.id, f.attr
            if ((owner in sp_mods and attr in _SUBPROCESS_STARTERS)
                    or (owner in os_mods and (attr in _OS_STARTERS or attr.startswith(_OS_PREFIXES)))
                    or (owner in others and ("subprocess" in attr or attr == "spawn"))):
                calls.append(node)
        elif isinstance(f, ast.Name) and (f.id in sp_funcs & _SUBPROCESS_STARTERS
                                          or f.id in os_funcs):
            calls.append(node)
    return calls


class EveryGitCallGoesThroughTheFunnel(unittest.TestCase):

    def setUp(self):
        for rel in (*_ENTRIES, _FUNNEL[0]):
            if not (REPO / rel).is_file():
                self.skipTest(f"{rel} is not in this tree (a distributed artefact prunes scripts/)")
        self.files = _chain_files()

    def test_the_derivation_reaches_what_the_chain_loads(self):
        """Anti-vacuity: a derivation that found only the entry points would pass everything."""
        for rel in ("scripts/pre_tag_receipt_lib.py", "scripts/sign_readiness_artifact.py",
                    "src/proofbundle/signature.py", "src/proofbundle/_wire_b64.py",
                    "src/proofbundle/__init__.py"):
            self.assertIn(rel, self.files)

    def test_no_process_starts_outside_the_funnel_and_the_audit_run(self):
        """[RED] on `4e67ba25`: the verifier's `_git`, the producer's `_git_bytes` and two
        functions of the library called `subprocess.run` themselves."""
        outside = []
        for rel, tree in self.files.items():
            parents = _parents(tree)
            for call in _process_calls(tree):
                where = _enclosing_functions(call, parents)
                if rel in _DATA_ONLY and where:
                    continue                  # held by the data-only case below
                allowed = [(f, n) for f, n in (*_FUNNELS, _AUDIT_RUN) if f == rel and n in where]
                if not allowed:
                    outside.append(f"{rel}:{call.lineno} in {'.'.join(reversed(where)) or '<module>'}")
        self.assertEqual(outside, [], "a call that can start a process sits outside the funnel")

    def test_no_argument_list_names_git_outside_the_funnel(self):
        """The second reading of the same property: an argument vector that starts with `git`
        is built nowhere else, so no call can hand one to a process starter indirectly."""
        outside = []
        for rel, tree in self.files.items():
            parents = _parents(tree)
            for node in ast.walk(tree):
                if (isinstance(node, (ast.List, ast.Tuple)) and node.elts
                        and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "git"):
                    where = _enclosing_functions(node, parents)
                    if rel in _DATA_ONLY and where:
                        continue
                    if not any(rel == f and n in where for f, n in _FUNNELS):
                        outside.append(f"{rel}:{node.lineno}")
        self.assertEqual(outside, [])

    def test_each_funnel_passes_its_own_environment_and_pinned_options(self):
        for (rel, name), options in zip(_FUNNELS, ("GIT_PINNED_OPTIONS", "_GIT_PINNED_OPTIONS")):
            with self.subTest(funnel=f"{rel}:{name}"):
                tree = self.files[rel]
                parents = _parents(tree)
                runs = [c for c in _process_calls(tree) if name in _enclosing_functions(c, parents)]
                self.assertEqual(len(runs), 1, "the funnel starts git in exactly one place")
                keywords = {k.arg for k in runs[0].keywords}
                self.assertIn("env", keywords, "the funnel hands git an environment it built")
                argv = runs[0].args[0]
                self.assertIsInstance(argv, ast.List)
                self.assertIsInstance(argv.elts[1], ast.Starred)
                self.assertEqual(ast.unparse(argv.elts[1].value), options,
                                 "the pinned configuration comes right after `git`")

    def test_the_verifier_funnel_runs_on_the_verifiers_own_code(self):
        """The verifier's `_git` may not reach the library (or anything loaded from the checkout)
        at all: no name of the module it calls into is used inside it."""
        tree = self.files["scripts/verify_pre_tag_receipt.py"]
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_git")
        used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        self.assertFalse(used & {"_lib", "_gate", "lib", "gate"}, used)

    def test_a_file_loaded_for_data_runs_nothing_when_loaded(self):
        for rel, (loader, name, attributes) in _DATA_ONLY.items():
            with self.subTest(file=rel):
                self.assertIn(rel, self.files)
                tree = self.files[rel]
                parents = _parents(tree)
                at_load = [c.lineno for c in _process_calls(tree)
                           if not _enclosing_functions(c, parents)]
                self.assertEqual(at_load, [], "the module starts a process when it is loaded")
                used = {n.attr for n in ast.walk(self.files[loader])
                        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                        and n.value.id == name}
                self.assertEqual(used, attributes,
                                 f"{loader} reads more than data from {rel}: {sorted(used)}")


class TheFunnelBuildsTheEnvironment(unittest.TestCase):
    """The allowlist as a property: whatever the process holds, git gets the named few. And the
    verifier's copy of the funnel builds the same environment and pins the same options."""

    def setUp(self):
        self.mods = {}
        for rel in (_FUNNELS[0][0], _FUNNELS[1][0]):
            if not (REPO / rel).is_file():
                self.skipTest(f"{rel} is not in this tree")
            spec = importlib.util.spec_from_file_location(f"_funnel_env_{len(self.mods)}", REPO / rel)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.mods[rel] = mod
        self.lib = self.mods[_FUNNELS[0][0]]
        self.verifier = self.mods[_FUNNELS[1][0]]

    def test_the_two_funnels_are_one_in_allowlist_options_and_environment(self):
        """Derived from both modules, not typed here: the verifier carries a copy because it may
        not run the library's code for its cleanliness check, and a copy that drifted would make
        the verifier ask git under other terms than the producer and the gate."""
        self.assertEqual(self.verifier._GIT_INHERITED, self.lib._GIT_INHERITED)
        self.assertEqual(self.verifier._GIT_PINNED_OPTIONS, self.lib.GIT_PINNED_OPTIONS)
        root = pathlib.Path(tempfile.gettempdir()).resolve() / "a-repository"
        polluted = {"GIT_DIR": "/x", "GIT_TRACE": "1", "HOME": "/h", "SYSTEMROOT": "C:\\W",
                    "PATH": os.environ.get("PATH", "/usr/bin")}
        with mock.patch.dict(os.environ, polluted):
            self.assertEqual(self.verifier._git_environment(root), self.lib.git_environment(root))

    def test_no_inherited_name_but_the_allowlist_reaches_git(self):
        oracle = subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True,
                                text=True).stdout.split()
        self.assertIn("GIT_DIR", oracle, f"git gave no usable list: {oracle}")
        polluted = {n: "/polluted" for n in oracle}
        polluted.update({n: "1" for n in (
            "GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_LITERAL_PATHSPECS", "GIT_TRACE",
            "GIT_TRACE2_EVENT", "GIT_EXEC_PATH", "GIT_ATTR_SOURCE", "GIT_CEILING_DIRECTORIES",
            "GIT_TEST_ASSUME_DIFFERENT_OWNER", "HOME", "XDG_CONFIG_HOME", "LANGUAGE", "PAGER",
            "GIT_PAGER", "SOME_UNRELATED_NAME")})
        root = pathlib.Path(tempfile.gettempdir()).resolve() / "a-repository"
        pinned = {"LC_ALL": "C", "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
                  "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
                  "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                  "GIT_WORK_TREE": str(root), "GIT_CEILING_DIRECTORIES": str(root.parent)}
        for label, build in (("library", self.lib.git_environment),
                             ("verifier", self.verifier._git_environment)):
            with self.subTest(funnel=label):
                with mock.patch.dict(os.environ, polluted):
                    got = build(root)
                self.assertEqual({k: v for k, v in got.items() if k not in ("PATH", "SYSTEMROOT")},
                                 pinned)
                self.assertEqual(got.get("PATH"), os.environ.get("PATH"))


# ── the sweep ────────────────────────────────────────────────────────────────────────────────

#: Runs in a child: loads the tree's own producer, library and verifier by path, and prints the
#: chain's answers and a plain git probe for the baseline and for every lever of the plan.
_DRIVER = r'''
import importlib.util, json, os, pathlib, shutil, subprocess, sys
scripts, repo, plan_file = (pathlib.Path(a) for a in sys.argv[1:4])
def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, scripts / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
producer = load("_sweep_producer", "pre_tag_receipt.py")
lib = load("_sweep_lib", "pre_tag_receipt_lib.py")
verifier = load("_sweep_verifier", "verify_pre_tag_receipt.py")
# THE PLAIN PROBE READS NO SYSTEM FILE OF THE MACHINE THAT RUNS THE SUITE (the chain reads none
# either). Loading the producer above removed every GIT_ name from this process, the one the
# fixture set included, so it is set again here; a row that wants a system file sets its own.
os.environ["GIT_CONFIG_SYSTEM"] = os.devnull
plan = json.loads(plan_file.read_text(encoding="utf-8"))
def safe(f):
    try:
        return f()
    except SystemExit as e:
        return "refused: " + str(e)
    except Exception as e:
        return f"{type(e).__name__}: {e}"
def listing():
    rc, out, _err = verifier._git(repo, "status", "--porcelain", "--untracked-files=all",
                                  "--", "scripts", "src")
    return [rc, out.decode("utf-8", "replace")]
def answers():
    return {"digest": safe(lambda: lib.subject_tree_digest(repo)),
            "anchor": safe(lambda: lib.load_trusted_pubkeys(repo)),
            "tree": safe(lambda: producer._baumzustand_oder_stop(repo, "measured")),
            "gate_source": safe(lambda: producer._gate_source_digest(repo)),
            "verifier_listing": safe(listing)}
def plain():
    out = []
    for args, stdin in ((["status", "--porcelain", "--untracked-files=all"], None),
                        (["ls-tree", "HEAD", "--", "a.txt", "scripts/pre_tag_audit_gate.py"], None),
                        (["rev-parse", "--show-toplevel"], None),
                        (["check-ignore", "-v", "-z", "--no-index", "--stdin"], b"x.log\0")):
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, input=stdin)
        out.append([r.returncode, r.stdout.decode("utf-8", "replace")])
    return out
# A plain `git status` may refresh and rewrite the index (measured: under GIT_WORK_TREE on a clone
# it stored the clone's stat data), so every row starts from the same index.
index = repo / ".git" / "index"
saved_index = index.read_bytes()
results = {"baseline": {"answers": answers(), "plain": plain()}}
index.write_bytes(saved_index)
for lever in plan:
    saved_env, saved_files = dict(os.environ), {}
    marker = pathlib.Path(lever["marker"]) if lever.get("marker") else None
    try:
        for k, v in lever.get("env", {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for path, text in lever.get("append", {}).items():
            p = pathlib.Path(path)
            saved_files[p] = p.read_bytes() if p.exists() else None
            p.write_bytes((saved_files[p] or b"") + text.encode())
        a = answers()
        after_chain = marker.exists() if marker else None
        pl = plain()
        after_plain = marker.exists() if marker else None
        results[lever["label"]] = {"answers": a, "plain": pl, "marker_after_chain": after_chain,
                                   "marker_after_plain": after_plain}
    finally:
        os.environ.clear()
        os.environ.update(saved_env)
        for p, old in saved_files.items():
            if old is None:
                p.unlink()
            else:
                p.write_bytes(old)
        if marker and marker.exists():
            marker.unlink()
        index.write_bytes(saved_index)
print(json.dumps(results))
'''


def _git(cwd, *args, env) -> str:
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                        "-c", "commit.gpgsign=false", *args],
                       cwd=str(cwd), capture_output=True, env=env)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed in {cwd}: {r.stderr.decode()}")
    return r.stdout.decode().strip()


def _git_version() -> tuple[int, int, int]:
    """The version of the `git` on PATH, which the driver's plain probe runs as well."""
    out = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    found = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    if not found:
        raise AssertionError(f"git gave no version: {out!r}")
    return tuple(int(x) for x in found.groups())


class TheFunnelGivesOneAnswer(unittest.TestCase):
    """The sweep. One child process computes every answer, so the cost is one interpreter."""

    #: Settings that change a plain git's answer in this fixture, each named for the finding it
    #: stands for. For these the probe must differ from the baseline (the setting is live).
    LIVE = ("excludes: core.excludesFile in .git/config", "excludes: core.excludesFile in ~/.gitconfig",
            "excludes: core.excludesFile in $XDG_CONFIG_HOME/git/config", "excludes: includeIf in ~/.gitconfig",
            "excludes: $XDG_CONFIG_HOME/git/ignore", "excludes: core.excludesFile through [include]",
            "replacement: core.useReplaceRefs=true in .git/config", "work tree: core.worktree in .git/config",
            "environment: GIT_ICASE_PATHSPECS=1", "environment: GIT_GLOB_PATHSPECS=1", "environment: GIT_TRACE=/dev/stdout",
            "environment: GIT_TRACE_SETUP=/dev/stdout", "environment: GIT_TRACE2_EVENT=/dev/stdout",
            "environment: GIT_LITERAL_PATHSPECS=1", "verifier: GIT_WORK_TREE on a clean clone",
            "GIT_DIR of a clean clone", "another owner (GIT_TEST_ASSUME_DIFFERENT_OWNER=1)",
            "config core.checkStat = minimal", "other GIT_NO_REPLACE_OBJECTS removed")

    #: Live settings whose ATTACK exists only before a git version: the first version without it,
    #: the row that stands for the same property on every version (it must be live wherever this
    #: one is not, or the fixture measured nothing), and why the attack is gone.
    #:
    #: The replacement key: on git before 2.42.0, `GIT_NO_REPLACE_OBJECTS` and `core.useReplaceRefs`
    #: wrote one global and the configuration, read later, won (measured on 2.34.1: with the key set
    #: to true, `GIT_NO_REPLACE_OBJECTS=1 git show` and `git --no-replace-objects show` both read
    #: the replacement). git 2.42.0 made the switch final (RelNotes: "Introduce a mechanism to
    #: disable replace refs globally and per repository", merge 9c7d1b057f ds/disable-replace-refs):
    #: the switch disables replacement for the whole process, and the key can only turn it off
    #: (`replace_refs_enabled` in replace-object.c). Measured on 2.55.0: under the switch, with the
    #: key set to true, git reads the raw object. A replacement is still followed BY DEFAULT on
    #: every version, which the row "other GIT_NO_REPLACE_OBJECTS removed" measures.
    VERSION_BOUND = {
        "replacement: core.useReplaceRefs=true in .git/config": (
            (2, 42, 0), "other GIT_NO_REPLACE_OBJECTS removed",
            "since git 2.42.0 (ds/disable-replace-refs, merge 9c7d1b057f) GIT_NO_REPLACE_OBJECTS "
            "disables replacement for the whole process and core.useReplaceRefs can only turn it "
            "off, so the key cannot switch replacement back on under the switch"),
    }

    def setUp(self):
        for rel in (*_ENTRIES, _FUNNEL[0], "scripts/sign_readiness_artifact.py"):
            if not (REPO / rel).is_file():
                self.skipTest(f"{rel} is not in this tree (a distributed artefact prunes scripts/)")
        d = tempfile.mkdtemp(prefix="pre-tag-sweep-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.base = pathlib.Path(d)

    def _fixture(self):
        b = self.base
        home0 = b / "home0"
        (home0 / ".xdg").mkdir(parents=True)
        # NO SYSTEM FILE OF THIS MACHINE (2026-09-27, measured on CI run 36319775855): GitHub's
        # runner image appends `[safe] directory = *` to /etc/gitconfig, so under
        # `GIT_TEST_ASSUME_DIFFERENT_OWNER=1` a plain git there answered as usual and the owner row
        # measured nothing. Reproduced with a git 2.55.0 whose system file carries those two lines;
        # the same git without them refuses the repository. The chain reads no system file (its
        # funnel sets GIT_CONFIG_NOSYSTEM), and the fixture and the probe must not read one either.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("GIT_") and k not in ("HOME", "XDG_CONFIG_HOME")}
        env.update(HOME=str(home0), XDG_CONFIG_HOME=str(home0 / ".xdg"),
                   GIT_CONFIG_SYSTEM=os.devnull, PYTHONDONTWRITEBYTECODE="1")
        repo = b / "repo"
        repo.mkdir()
        files = {"a.txt": "eins\n", "café.txt": "quoted\n", ".gitignore": "*.log\n",
                 "logs/.gitignore": "*\n!.gitignore\n", "scripts/pre_tag_audit_gate.py": "# gate\n",
                 "src/x.py": "X = 1\n", "audit_artifacts/pre_tag_trusted_pubkeys.txt": "KEY\n",
                 "run.sh": "#!/bin/sh\n"}
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8")
        # Owner read and execute and nothing else: git records 100755 from the owner's execute bit
        # and reads the file to hash it; no group or other bit is part of what is measured.
        os.chmod(repo / "run.sh", 0o500)
        # an old mtime, recorded in the index at `add`: the same-size rewrite below restores it
        old = 1_577_836_800
        os.utime(repo / "src" / "x.py", (old, old))
        _git(repo, "init", "-q", env=env)
        _git(repo, "add", "-A", env=env)
        _git(repo, "commit", "-qm", "base", env=env)
        base_commit = _git(repo, "rev-parse", "HEAD", env=env)
        clone = b / "clone"
        _git(b, "clone", "-q", str(repo), str(clone), env=env)
        # a second clone whose head TRACKS the planted files: under its GIT_DIR a plain status of
        # the fixture no longer lists them
        tracking = b / "tracking_clone"
        _git(b, "clone", "-q", str(repo), str(tracking), env=env)
        (tracking / "evil.py").write_text("PLANTED = True\n", encoding="utf-8")
        (tracking / "src" / "evil2.py").write_text("PLANTED = True\n", encoding="utf-8")
        _git(tracking, "add", "-A", env=env)
        _git(tracking, "commit", "-qm", "tracks the planted files", env=env)
        (repo / "a.txt").write_text("zwei\n", encoding="utf-8")
        _git(repo, "commit", "-qam", "second", env=env)
        second = _git(repo, "rev-parse", "HEAD", env=env)
        _git(repo, "reset", "-q", "--hard", base_commit, env=env)
        _git(repo, "replace", base_commit, second, env=env)
        # dirt the chain must see: an untracked file at the root, one under src/, and two files
        # the tree's own rules ignore
        (repo / "evil.py").write_text("PLANTED = True\n", encoding="utf-8")
        (repo / "src" / "evil2.py").write_text("PLANTED = True\n", encoding="utf-8")
        (repo / "x.log").write_text("log\n", encoding="utf-8")
        (repo / "logs" / "y.txt").write_text("log\n", encoding="utf-8")
        # a tracked file rewritten with the same size, through a new inode, and its old mtime put
        # back: a status that compares only mtime, size and mode takes it for unchanged
        fresh = repo / "src" / "x.py.new"
        fresh.write_text("X = 2\n", encoding="utf-8")
        os.replace(fresh, repo / "src" / "x.py")
        os.utime(repo / "src" / "x.py", (old, old))
        other = b / "other"
        other.mkdir()
        (other / ".gitignore").write_text("*\n", encoding="utf-8")
        marker = b / "fsmonitor-ran"
        hook = b / "fsmonitor-hook"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
        # Owner read and execute: git starts the hook by path (execute) and the shell reads the
        # script (read). The row asserts that the hook really ran under a plain git.
        os.chmod(hook, 0o500)
        homes = {}
        for name, text in (("excludes", "[core]\n\texcludesFile = logs/.gitignore\n"),
                           ("harmless", "[core]\n\tworktree = /nonexistent\n\tabbrev = 5\n"
                                        "\tquotePath = false\n[color]\n\tui = always\n")):
            h = b / f"home_{name}"
            h.mkdir()
            (h / ".gitconfig").write_text(text, encoding="utf-8")
            homes[name] = h
        inc = b / "included.conf"
        inc.write_text("[core]\n\texcludesFile = logs/.gitignore\n", encoding="utf-8")
        h = b / "home_includeif"
        h.mkdir()
        (h / ".gitconfig").write_text(f'[includeIf "gitdir:{repo}/.git"]\n\tpath = {inc}\n',
                                      encoding="utf-8")
        homes["includeif"] = h
        xdg_config, xdg_ignore = b / "xdg_config", b / "xdg_ignore"
        (xdg_config / "git").mkdir(parents=True)
        (xdg_config / "git" / "config").write_text("[core]\n\texcludesFile = logs/.gitignore\n",
                                                   encoding="utf-8")
        (xdg_ignore / "git").mkdir(parents=True)
        (xdg_ignore / "git" / "ignore").write_text("evil.py\nevil2.py\n", encoding="utf-8")
        cfg = str(repo / ".git" / "config")
        levers = [
            {"label": "excludes: core.excludesFile in .git/config",
             "append": {cfg: "[core]\n\texcludesFile = logs/.gitignore\n"}},
            {"label": "excludes: core.excludesFile in ~/.gitconfig", "env": {"HOME": str(homes["excludes"])}},
            {"label": "excludes: core.excludesFile in $XDG_CONFIG_HOME/git/config",
             "env": {"XDG_CONFIG_HOME": str(xdg_config)}},
            {"label": "excludes: includeIf in ~/.gitconfig", "env": {"HOME": str(homes["includeif"])}},
            {"label": "excludes: $XDG_CONFIG_HOME/git/ignore", "env": {"XDG_CONFIG_HOME": str(xdg_ignore)}},
            {"label": "excludes: core.excludesFile through [include]",
             "append": {cfg: f"[include]\n\tpath = {inc}\n"}},
            {"label": "replacement: core.useReplaceRefs=true in .git/config",
             "append": {cfg: "[core]\n\tuseReplaceRefs = true\n"}},
            {"label": "work tree: core.worktree in .git/config",
             "append": {cfg: f"[core]\n\tworktree = {other}\n"}},
            {"label": "environment: GIT_ICASE_PATHSPECS=1", "env": {"GIT_ICASE_PATHSPECS": "1"}},
            {"label": "environment: GIT_GLOB_PATHSPECS=1", "env": {"GIT_GLOB_PATHSPECS": "1"}},
            {"label": "environment: GIT_TRACE=/dev/stdout", "env": {"GIT_TRACE": "/dev/stdout"}},
            {"label": "environment: GIT_TRACE_SETUP=/dev/stdout", "env": {"GIT_TRACE_SETUP": "/dev/stdout"}},
            {"label": "environment: GIT_TRACE2_EVENT=/dev/stdout", "env": {"GIT_TRACE2_EVENT": "/dev/stdout"}},
            {"label": "environment: GIT_LITERAL_PATHSPECS=1", "env": {"GIT_LITERAL_PATHSPECS": "1"}},
            {"label": "verifier: GIT_WORK_TREE on a clean clone", "env": {"GIT_WORK_TREE": str(clone)}},
            {"label": "GIT_DIR of a clean clone", "env": {"GIT_DIR": str(tracking / ".git")}},
            {"label": "another owner (GIT_TEST_ASSUME_DIFFERENT_OWNER=1)",
             "env": {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}},
            {"label": "core.fsmonitor hook in .git/config", "marker": str(marker),
             "append": {cfg: f"[core]\n\tfsmonitor = {hook}\n"}},
        ]
        # the 22 settings the lens measured without effect on `4e67ba25`
        harmless_env = {
            "GIT_EXEC_PATH": "/nonexistent", "GIT_NOGLOB_PATHSPECS": "1", "GIT_TRACE": "1",
            "GIT_REF_PARANOIA": "1", "GIT_DEFAULT_HASH": "sha256", "GIT_TEST_FSMONITOR": str(hook),
            "GIT_QUARANTINE_PATH": "/nonexistent", "GIT_ATTR_SOURCE": "HEAD",
            "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "1", "GIT_PAGER": "cat",
            "PAGER": "cat", "LC_ALL": "C.UTF-8", "LANG": "de_DE.UTF-8", "GIT_INDEX_VERSION": "4",
            "GIT_NAMESPACE": "elsewhere", "GIT_COMMON_DIR": str(clone / ".git"),
            "GIT_CONFIG_PARAMETERS": "'core.excludesfile'='logs/.gitignore'"}
        levers += [{"label": f"without effect before: {k}={v}", "env": {k: v}} for k, v in harmless_env.items()]
        levers += [{"label": "without effect before: HOME with core.worktree, abbrev, quotePath, color",
                    "env": {"HOME": str(homes["harmless"])}},
                   {"label": "without effect before: GIT_WORK_TREE", "env": {"GIT_WORK_TREE": str(other)}},
                   {"label": "without effect before: GIT_DIR", "env": {"GIT_DIR": str(other)}}]
        # the rest of git's repository-local names and the configuration selectors
        rest_env = {
            "GIT_INDEX_FILE": "/nonexistent/index", "GIT_OBJECT_DIRECTORY": "/nonexistent",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(clone / ".git" / "objects"),
            "GIT_CEILING_DIRECTORIES": str(repo), "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
            "GIT_CONFIG": str(homes["excludes"] / ".gitconfig"),
            "GIT_CONFIG_GLOBAL": str(homes["excludes"] / ".gitconfig"),
            "GIT_CONFIG_SYSTEM": str(homes["excludes"] / ".gitconfig"),
            "GIT_REPLACE_REF_BASE": "refs/elsewhere/", "GIT_GRAFT_FILE": "/nonexistent",
            "GIT_SHALLOW_FILE": "/nonexistent", "GIT_IMPLICIT_WORK_TREE": "0",
            "GIT_PREFIX": "src/", "GIT_INTERNAL_SUPER_PREFIX": "sub/"}
        levers += [{"label": f"other {k}", "env": {k: v}} for k, v in rest_env.items()]
        levers += [
            {"label": "other GIT_CONFIG_COUNT/KEY/VALUE",
             "env": {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.excludesFile",
                     "GIT_CONFIG_VALUE_0": "logs/.gitignore"}},
            {"label": "other GIT_CONFIG_NOSYSTEM removed, system file set",
             "env": {"GIT_CONFIG_NOSYSTEM": None,
                     "GIT_CONFIG_SYSTEM": str(homes["excludes"] / ".gitconfig")}},
            {"label": "other GIT_NO_REPLACE_OBJECTS removed", "env": {"GIT_NO_REPLACE_OBJECTS": None}},
        ]
        for key_value in ("core.quotePath = false", "core.ignoreCase = true", "core.fileMode = false",
                          "core.untrackedCache = true", "core.checkStat = minimal",
                          "core.trustctime = false", "core.commitGraph = true", "core.bare = true",
                          "core.sparseCheckout = true", "core.abbrev = 5",
                          f"core.attributesFile = {inc}", "status.showUntrackedFiles = no",
                          "status.branch = true", "color.ui = always",
                          "diff.ignoreSubmodules = all", "safe.directory = *"):
            section, _, rest = key_value.partition(".")
            levers.append({"label": f"config {key_value}",
                           "append": {cfg: f"[{section}]\n\t{rest}\n"}})
        return repo, levers, env

    def test_every_answer_equals_the_clean_baseline(self):
        """[RED] on `4e67ba25` for the excludes, replacement, work-tree and environment settings,
        and for the verifier's listing under `GIT_WORK_TREE`/`GIT_DIR`; every one of those gives
        the baseline answer here. The replacement key was red there with git before 2.42.0 only
        (see `VERSION_BOUND`); on a later git that row is a skipped subtest naming the version."""
        repo, levers, env = self._fixture()
        plan = self.base / "plan.json"
        plan.write_text(json.dumps(levers), encoding="utf-8")
        r = subprocess.run([sys.executable, "-B", "-c", _DRIVER, str(SCRIPTS), str(repo), str(plan)],
                           capture_output=True, text=True, timeout=900, env=env)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        results = json.loads(r.stdout.strip().splitlines()[-1])
        baseline = results.pop("baseline")
        # the baseline itself measured something: the planted dirt is seen, the ignored files are not
        self.assertIn("?? evil.py", baseline["answers"]["tree"])
        self.assertIn("?? src/evil2.py", baseline["answers"]["tree"])
        self.assertNotIn("x.log", baseline["answers"]["tree"])
        self.assertIn("M src/x.py", baseline["answers"]["tree"])
        # ... and it read the objects HEAD names, not their replacement: `refs/replace/` maps base
        # to second, whose `a.txt` differs from the checkout. Without this line every row is
        # compared with a baseline that may already follow the replacement, and a funnel without
        # its replacement pins passed the whole sweep (measured 2026-09-27 on a scratch copy, on
        # git 2.34.1 and 2.55.0).
        self.assertNotIn("M a.txt", baseline["answers"]["tree"])
        self.assertEqual(baseline["answers"]["verifier_listing"],
                         [0, " M src/x.py\n?? src/evil2.py\n"])
        self.assertEqual(baseline["answers"]["anchor"], ["KEY"])
        self.assertRegex(baseline["answers"]["digest"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(len(results), len(levers))
        for label, got in results.items():
            with self.subTest(setting=label):
                self.assertEqual(got["answers"], baseline["answers"],
                                 f"{label} changed what the chain was told")
                if label in self.VERSION_BOUND and got["plain"] == baseline["plain"]:
                    first, witness, why = self.VERSION_BOUND[label]
                    version = _git_version()
                    shown = ".".join(map(str, version))
                    self.assertGreaterEqual(
                        version, first, f"{label} does not change a plain git's answer on git "
                        f"{shown}, a version on which it should: this row measures nothing")
                    self.assertNotEqual(
                        results[witness]["plain"], baseline["plain"],
                        f"{witness} does not change a plain git's answer either: the fixture "
                        "measures nothing about this property")
                    self.skipTest(f"the attack of this row does not exist on git {shown}: {why}. "
                                  f"The property is measured on this git by the row {witness!r}.")
                if label in self.LIVE:
                    self.assertNotEqual(got["plain"], baseline["plain"],
                                        f"{label} does not change a plain git's answer here, so "
                                        "this row measures nothing")
                if got["marker_after_chain"] is not None:
                    self.assertFalse(got["marker_after_chain"], "a configured hook ran")
                    self.assertTrue(got["marker_after_plain"], "precondition: the hook is live")
        self.assertTrue(set(self.LIVE) <= set(results), set(self.LIVE) - set(results))


if __name__ == "__main__":
    unittest.main()
