"""Every git call in scripts/ and tools/ that lists paths reads them with -z, or stands below with the
reason it may read the quoted form.

THE CLASS, found three times on 2026-09-26: a path git lists is read in its quoted display form. The
mutant guard read `+++ "b/src/proofbundle/pr\\303\\274fung.py"` as a path and let a mutant through; the
same day the version gate, the digest-resolvability check, the third-party receipt verifier and the
language gate did the same with `ls-files`, `ls-tree` and a diff header (the cases are in
tests/test_git_paths_are_read_as_git_names_them.py and below). A list of the places fixed is the
instance; this sweep is the class. A new git call that lists paths either reads them with -z or is
named here with its reason.

WHAT COUNTS AS A LISTING: `ls-files`, `ls-tree`, `check-ignore` and `status` always; `diff`, `show`,
`log` and their plumbing forms with a name switch (`--name-only`, `--name-status`, `--raw`,
`--numstat`, `--stat`, `--summary`); `grep` with `-l`/`-L` and their long forms. A patch is a listing
too, through its headers, and has a rule of its own: a function that reads a `+++` header decodes it
with the mutant guard's `_git_path`.

THE READING IS STATIC and sees what a call spells literally: the subcommand and the switches as string
constants. A call that builds its arguments at run time is not seen, which is the limit of this sweep,
not a claim that no such call exists. tests/ is not swept; it is not tooling that judges a tree.
"""
from __future__ import annotations

import ast
import functools
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_ALWAYS = {"ls-files", "ls-tree", "check-ignore", "status"}
_NAME_SWITCHES = {"--name-only", "--name-status", "--raw", "--numstat", "--stat", "--summary"}
_WITH = {"diff": _NAME_SWITCHES, "show": _NAME_SWITCHES, "log": _NAME_SWITCHES,
         "diff-tree": _NAME_SWITCHES, "diff-index": _NAME_SWITCHES, "diff-files": _NAME_SWITCHES,
         "whatchanged": _NAME_SWITCHES,
         "grep": {"-l", "-L", "--name-only", "--files-with-matches", "--files-without-match"}}

#: (file, enclosing function, subcommand) -> why the quoted form may stand there. Each reason is
#: about what the caller does with the names, and the premise a reason rests on is bound by a case
#: below where it can be.
QUOTED_FORM_ALLOWED = {
    ("scripts/pre_tag_receipt_lib.py", "subject_tree_digest", "ls-tree"):
        "hashes the listing and opens no name; the quoted form is an injective encoding, so the "
        "digest stays well defined. The exclusion set is quote-free (bound below), and a receipt "
        "under a quoted name falls outside the ASCII receipt pattern, so it stays in the digest and "
        "cannot bind itself: a refusal, never a pass. The grammar is a signed quantity shared with "
        "sign_readiness_artifact.tree_digest; changing it is a change of the receipt format.",
    ("scripts/sign_readiness_artifact.py", "tree_digest", "ls-tree"):
        "the same digest as pre_tag_receipt_lib.subject_tree_digest, recomputed by the gate; see there.",
    ("scripts/audit_candidate_matrix.py", "_evidenz_relation_erlaubt", "diff"):
        "compares the names against the mutable evidence set, which is quote-free (bound below); a "
        "quoted name can only fall outside that set, and outside is a refusal, never a pass.",
    ("scripts/mutation_check.py", "_worktree_status", "status"):
        "the output is compared as a whole, before against after; no name is read from it.",
    ("scripts/render_site_data.py", "_source_time", "status"):
        "only whether the output is empty is read.",
    ("scripts/verify_pre_tag_receipt.py", "_measure", "status"):
        "the entries are counted and the first is shown; the quoted form keeps one entry per line, "
        "so the count holds.",
}


def _swept_files() -> list[Path]:
    files = sorted((ROOT / "scripts").rglob("*.py")) + sorted((ROOT / "tools").rglob("*.py"))
    return [p for p in files if "target" not in p.relative_to(ROOT).parts]


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _enclosing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return "<module>"


def _literal_args(call: ast.Call) -> list[str]:
    out: list[str] = []
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            out.append(arg.value)
        elif isinstance(arg, (ast.List, ast.Tuple)):
            out += [e.value for e in arg.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return out


@functools.cache
def _listings_without_nul() -> dict[tuple[str, str, str], list[int]]:
    found: dict[tuple[str, str, str], list[int]] = {}
    for path in _swept_files():
        rel = path.relative_to(ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        parents = None
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            args = _literal_args(call)
            sub = next((a for a in args if a in _ALWAYS or a in _WITH), None)
            if sub is None or "-z" in args:
                continue
            if sub in _WITH and not set(args) & _WITH[sub]:
                continue
            if "git" not in args and "git" not in ast.unparse(call.func).lower():
                continue
            parents = parents or _parents(tree)
            key = (rel, _enclosing_function(call, parents), sub)
            found.setdefault(key, []).append(call.lineno)
    return found


def test_every_listing_reads_with_nul_or_is_named_with_its_reason():
    unnamed = {k: v for k, v in _listings_without_nul().items() if k not in QUOTED_FORM_ALLOWED}
    assert not unnamed, (
        "git calls that list paths without -z and are not named in QUOTED_FORM_ALLOWED: "
        + "; ".join(f"{f}:{lines} in {fn} ({sub})" for (f, fn, sub), lines in sorted(unnamed.items()))
        + ". Without -z git quotes a name outside ASCII, and the quoted string opens no file. Read "
          "with -z (and as bytes, decoded with os.fsdecode), or name the call with the reason the "
          "quoted form cannot change a verdict there.")


def test_every_named_exception_still_names_a_call():
    """A reason for a call that no longer exists is a permission waiting for the next call there."""
    stale = sorted(set(QUOTED_FORM_ALLOWED) - set(_listings_without_nul()))
    assert not stale, f"QUOTED_FORM_ALLOWED names calls that no longer read the quoted form: {stale}"


def test_every_patch_header_reader_decodes_the_path():
    """A function that reads a `+++` header CALLS the mutant guard's `_git_path`. Holding the name is
    not enough: a first version of this rule asked only for the name, and a planted reader that
    loaded the decoder and then sliced the header itself (`zeile[6:]`) passed it."""
    missing = []
    for path in _swept_files():
        rel = path.relative_to(ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            strings = [n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
            if not any(s.startswith("+++") for s in strings):
                continue
            called = {n.func.id for n in ast.walk(fn)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            if "_git_path" not in called:
                missing.append(f"{rel}:{fn.lineno} {fn.name}")
    assert not missing, f"diff-header readers that take the quoted form as the path: {missing}"


def test_the_evidence_set_the_exceptions_rest_on_is_quote_free():
    """Three reasons above rest on this: a path git never quotes matches in either form."""
    tree = ast.parse((ROOT / "scripts" / "sign_readiness_artifact.py").read_text(encoding="utf-8"))
    value = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "MUTABLE_EVIDENCE_RELS" for t in n.targets))
    rels = ast.literal_eval(value)
    assert rels, "MUTABLE_EVIDENCE_RELS is empty, and the reasons above would rest on nothing"
    quoted = [r for r in rels if any(not (0x20 < ord(c) < 0x7F) or c in '"\\' for c in r)]
    assert not quoted, f"these evidence paths would be quoted by git: {quoted}"


# -- the language gate, whose script the package does not ship ----------------------------------

def _language_gate():
    spec = importlib.util.spec_from_file_location("_nul_language_gate",
                                                  ROOT / "scripts" / "neue_zeilen_sind_englisch.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    empty = tmp_path / "empty-gitconfig"
    empty.write_text("", encoding="utf-8")
    for key, value in {"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}.items():
        monkeypatch.setenv(key, value)
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    (r / "m.py").write_text("x = 1\n", encoding="utf-8")
    for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "base")):
        subprocess.run(["git", "-C", str(r), *args], check=True, capture_output=True)
    return r


def _commit(r: Path, files: dict[str, str]) -> str:
    base = subprocess.run(["git", "-C", str(r), "rev-parse", "HEAD"], check=True, capture_output=True,
                          text=True).stdout.strip()
    for rel, text in files.items():
        (r / rel).write_text(text, encoding="utf-8")
    for args in (("add", "-A"), ("commit", "-q", "-m", "change")):
        subprocess.run(["git", "-C", str(r), *args], check=True, capture_output=True)
    return base


GERMAN = "Diese Zeile ist deutsch und die Pruefung muss sie sehen.\n"


@pytest.mark.parametrize("neighbour", ["docs/a.md", "docs/z.md"])
def test_the_language_gate_reads_a_diff_header_git_quotes(repo, neighbour):
    """Measured before the fix: after `docs/a.md` the German line was reported as `docs/a.md:1`;
    before `docs/z.md` the verdict was green over one added line."""
    gate = _language_gate()
    base = _commit(repo, {"docs/prüfung.md": GERMAN, neighbour: "An English line.\n"})
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    result = gate.pruefe(base)
    assert result["urteil"] == "ROT", result
    assert [(b["datei"], b["zeile"]) for b in result["befunde"]] == [("docs/prüfung.md", 1)], result


def test_the_language_gate_reads_an_untracked_file_git_quotes(repo):
    """Measured before the fix: NOT MEASURABLE, because the quoted name opened no file."""
    gate = _language_gate()
    base = _commit(repo, {"docs/a.md": "An English line.\n"})
    (repo / "neu_prüfung.py").write_text("# das ist eine neue deutsche Datei und sie ist ungetrackt\n",
                                             encoding="utf-8")
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    lines, state = gate._neue_zeilen(base, arbeitsbaum=True)
    assert state == "measured", state
    assert "neu_prüfung.py" in lines, sorted(lines)


def test_the_language_gate_lists_untracked_names_as_bytes(repo):
    """A name that is not UTF-8 is a name, not a decoder error."""
    gate = _language_gate()
    _commit(repo, {"docs/a.md": "An English line.\n"})
    try:
        fd = os.open(os.fsencode(repo) + b"/\xff.md", os.O_WRONLY | os.O_CREAT, 0o644)
    except OSError as exc:
        pytest.skip(f"this file system refuses a name that is not UTF-8: {exc}")
    os.write(fd, b"An English line.\n")
    os.close(fd)
    gate.REPO, gate.REPO_HERKUNFT = repo, "vorgabe"
    rc, names = gate._git_namen("ls-files", "--others", "--exclude-standard", "-z")
    assert rc == 0 and os.fsdecode(b"\xff.md") in names, names


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
