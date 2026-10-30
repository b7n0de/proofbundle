"""Three P1 findings of the reading of bundle G-2 (slice 02b-gate-core), line 3, each held by a case that fails on the
code as read.

- Part 7, D104: GNU rm takes any unambiguous abbreviation of a long option, so `rm --rec <dir>` deletes recursively,
  and the gate saw a recursive rm only in the exact spelling `--recursive`.
- Part 8, D119: the shell joins quoted and unquoted parts of a word, so `s''udo` runs sudo, and the door check split
  the line at the quotes and saw `s` and `udo`.
- Part 9: the key signer read the private key file through a plain open, so a symbolic link or a file that other
  accounts may read or write was taken as the key.
- Part 10: the secrets hook normalised `..` away before it walked the links, so `<link>/../config` with the link into
  a folder of keys read `.ssh/config` while the check looked at `<folder>/config` (owner answer A on OA-0e0ebea093).
- Codex on PR 441, P1: a word the shell expands as a pattern (`*`, `?`, `[`) named no path the gate could tell, and
  the guards read that as nothing to check, so `cat .ss[h]/config` read a key file without a decision (D102) and
  `rm -r /sr[v]/x` deleted outside the work folder (D104).
- hermetic-cleanroom on PR 441: MANIFEST.in prunes plugins/, and four modules that import the gate when they load
  ended as collection errors in the extracted sdist. tests/_gate_answer.py now skips such a module where a
  distribution leaves the gate out, and nowhere else.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"
SIGNER = ROOT / "plugins" / "proofbundle" / "pilot" / "key_signer.py"
SECRETS = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_secrets.py"


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load(GATE, "proofbundle_gate_under_test")


@pytest.mark.parametrize("option", ["--recursive"[:n] for n in range(3, len("--recursive") + 1)])
def test_every_abbreviation_of_recursive_is_a_recursive_rm(gate, option):
    assert gate._rm_targets(["rm", option, "/somewhere/else"]) == [2]


@pytest.mark.parametrize("option", ["--force", "--dir", "--verbose", "--one-file-system", "--preserve-root"])
def test_control_other_long_options_do_not_recurse(gate, option):
    assert gate._rm_targets(["rm", option, "/somewhere/else"]) is None


def test_gnu_rm_does_recurse_with_an_abbreviation(tmp_path):
    """The premise of the case above, measured on the rm of this machine; only GNU rm is asked."""
    version = subprocess.run(["rm", "--version"], capture_output=True, text=True)
    if version.returncode != 0 or "GNU coreutils" not in version.stdout:
        pytest.skip("not GNU rm; the abbreviation rule is GNU getopt_long's")
    target = tmp_path / "target" / "below"
    target.mkdir(parents=True)
    (target / "file").write_text("x", encoding="utf-8")
    assert subprocess.run(["rm", "--rec", str(tmp_path / "target")]).returncode == 0
    assert not (tmp_path / "target").exists()


@pytest.mark.parametrize("spelling", ["s''udo", 's""udo', "\\sudo", "su\\do", "'sudo'", '"sudo"', "s'u'do", "/usr/bin/s''udo"])
def test_a_root_program_spelled_with_quotes_or_backslashes_is_the_door_root(gate, spelling):
    assert gate._release_door_words(f"{spelling} -n true") == "root"


@pytest.mark.parametrize("line", ["pseudo -n true", "git status", "gh pr view 41"])
def test_control_a_line_without_a_root_program_names_no_root_door(gate, line):
    assert gate._release_door_words(line) != "root"


@pytest.fixture()
def signer():
    pytest.importorskip("cryptography")
    return _load(SIGNER, "key_signer_under_test")


def _key_file(tmp_path: pathlib.Path, mode: int) -> pathlib.Path:
    key = tmp_path / "key"
    key.write_text("11" * 32 + "\n", encoding="ascii")
    os.chmod(key, mode)
    return key


def test_control_a_private_key_file_of_mode_600_is_read(signer, tmp_path):
    assert signer.private_key({"key_file": str(_key_file(tmp_path, 0o600))}) is not None


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620, 0o602])
def test_a_key_file_other_accounts_may_read_or_write_is_refused(signer, tmp_path, mode):
    with pytest.raises((ValueError, OSError)):
        signer.private_key({"key_file": str(_key_file(tmp_path, mode))})


def test_a_key_file_reached_through_a_symbolic_link_is_refused(signer, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(_key_file(tmp_path, 0o600))
    with pytest.raises((ValueError, OSError)):
        signer.private_key({"key_file": str(link)})


def test_a_key_path_that_is_a_folder_is_refused(signer, tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir(mode=0o700)
    with pytest.raises((ValueError, OSError)):
        signer.private_key({"key_file": str(folder)})


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
def test_a_key_path_that_is_a_fifo_is_refused_without_blocking(signer, tmp_path):
    """A plain open of a FIFO with no writer blocks (the class of R18-2), so the read runs in a process of its own
    under a time limit: a refusal ends it at once, a block ends it at the limit and fails the case."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    probe = ("import importlib.util, sys\n"
             "s = importlib.util.spec_from_file_location('k', sys.argv[1]); m = importlib.util.module_from_spec(s)\n"
             "s.loader.exec_module(m)\n"
             "try:\n    m.private_key({'key_file': sys.argv[2]})\nexcept (ValueError, OSError):\n    sys.exit(3)\n"
             "sys.exit(0)\n")
    try:
        r = subprocess.run([sys.executable, "-c", probe, str(SIGNER), str(fifo)], capture_output=True, timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail("reading a FIFO as the key file blocked")
    assert r.returncode == 3, r.stderr


@pytest.fixture(scope="module")
def secrets():
    return _load(SECRETS, "proofbundle_secrets_under_test")


def _tree(tmp_path: pathlib.Path) -> pathlib.Path:
    """<tmp>/.ssh/child/, <tmp>/.ssh/config, <tmp>/other/, and the links alias -> .ssh/child, plain -> other."""
    (tmp_path / ".ssh" / "child").mkdir(parents=True)
    (tmp_path / ".ssh" / "config").write_text("Host x\n", encoding="utf-8")
    (tmp_path / "other").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / ".ssh" / "child")
    (tmp_path / "plain").symlink_to(tmp_path / "other")
    return tmp_path


def test_a_link_followed_by_dotdot_into_a_folder_of_keys_is_found(secrets, tmp_path):
    root = _tree(tmp_path)
    path = f"{root}/alias/../config"
    assert os.path.realpath(path) == str(root / ".ssh" / "config")
    assert secrets.secret_problem(path, "/", str(root / "home")) is not None


def test_a_relative_link_and_dotdot_from_cwd_is_found(secrets, tmp_path):
    root = _tree(tmp_path)
    assert secrets.secret_problem("alias/../config", str(root), str(root / "home")) is not None


def test_control_a_link_and_dotdot_outside_any_folder_of_keys_stays_free(secrets, tmp_path):
    root = _tree(tmp_path)
    (root / "x").write_text("x", encoding="utf-8")
    assert secrets.secret_problem(f"{root}/plain/../x", "/", str(root / "home")) is None
    assert secrets.secret_problem(f"{root}/other/../x", "/", str(root / "home")) is None


def test_control_the_direct_paths_keep_their_answer(secrets, tmp_path):
    root = _tree(tmp_path)
    assert secrets.secret_problem(f"{root}/.ssh/config", "/", str(root / "home")) is not None
    assert secrets.secret_problem(f"{root}/alias/key", "/", str(root / "home")) is not None
    assert secrets.secret_problem(f"{root}/other/notes.txt", "/", str(root / "home")) is None


# --- Codex on PR 441: a pattern the shell expands ---------------------------------------------------------------------

STORE = ".net" + "rc"   # the name of a credential store, joined so that no tool of the house reads it as a path


def _ask_gate(command: str, cwd: pathlib.Path, home: pathlib.Path):
    """The gate's answer to a Bash call, from the hook itself as a process: deny, ask or None."""
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
             "cwd": str(cwd), "session_id": "g2-pattern"}
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home)}
    r = subprocess.run([sys.executable, "-I", str(GATE)], input=json.dumps(event), capture_output=True, text=True,
                       timeout=60, env=env, cwd=str(cwd))
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


@pytest.fixture()
def home(tmp_path):
    """A home with stand-ins of a folder of keys and two credential stores, and a repository as the work folder."""
    h = tmp_path / "home"
    (h / ".ssh").mkdir(parents=True)
    (h / ".ssh" / "config").write_text("Host stand-in\n", encoding="utf-8")
    (h / STORE).write_text("machine stand-in\n", encoding="utf-8")
    (h / ".aws").mkdir()
    (h / ".aws" / "credentials").write_text("[stand-in]\n", encoding="utf-8")
    (h / "repo" / "build" / "x").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(h / "repo")], check=True)
    return h


@pytest.mark.parametrize("command", [
    "cat .ss[h]/config", "cat .ss?/config", "cat .s*h/config", "cat ~/.ss[h]/config", "cat {.ss[h],x}/config",
    "cat < .ss[h]/config", f"cat {STORE[:-1]}[{STORE[-1]}]", "cat ~/.aws/*", "cat ~/.aw?/credentials",
    "cat .*/config", "grep -r x .s[s]h",
])
def test_a_pattern_that_may_name_a_key_path_is_denied(home, command):
    assert _ask_gate(command, home, home) == "deny"


@pytest.mark.parametrize("command", ["cat .ssh/config", f"cat {STORE}", "cat ~/.aws/credentials"])
def test_control_the_written_key_paths_are_denied(home, command):
    assert _ask_gate(command, home, home) == "deny"


@pytest.mark.parametrize("command", ["cat README.m[d]", "cat *.txt", "cat *", "grep -r x *", "ls .ss[h]",
                                     "cat repo/[a-z]*.py"])
def test_control_a_pattern_that_names_no_key_path_is_not_denied(home, command):
    assert _ask_gate(command, home, home) != "deny"


@pytest.mark.parametrize("command", ["rm -r /sr[v]/stand-in/x", "rm -r /s?v/stand-in/x", "rm -r ~/[a-z]*/x"])
def test_a_recursive_delete_through_a_pattern_outside_the_work_folder_is_denied(home, command):
    assert _ask_gate(command, home / "repo", home) == "deny"


@pytest.mark.parametrize("command", ["rm -r bui[l]d/x", "rm -r ./b*/x"])
def test_control_a_recursive_delete_through_a_pattern_inside_the_work_folder_is_not_denied(home, command):
    assert _ask_gate(command, home / "repo", home) != "deny"


def test_control_the_written_delete_outside_is_denied(home):
    assert _ask_gate("rm -r /srv/stand-in/x", home / "repo", home) == "deny"


@pytest.mark.parametrize("command", ["echo x >> /sr[v]/stand-in/x", "echo x | tee -a /s?v/stand-in/x"])
def test_an_append_through_a_pattern_outside_the_work_folder_is_denied(home, command):
    assert _ask_gate(command, home / "repo", home) == "deny"


@pytest.mark.parametrize("command", ["echo x >> bui[l]d/x/log", "echo x | tee -a ./b*/x/log"])
def test_control_an_append_through_a_pattern_inside_the_work_folder_is_not_denied(home, command):
    assert _ask_gate(command, home / "repo", home) != "deny"


@pytest.mark.parametrize("command", ["echo x >> /srv/stand-in/x", "echo x | tee -a /srv/stand-in/x"])
def test_control_the_written_append_outside_is_denied(home, command):
    assert _ask_gate(command, home / "repo", home) == "deny"


# --- Re-reading of the fixes at 21fead88, line 3: shell forms the fixes did not model -----------------------------------

@pytest.mark.parametrize("command", [
    "cat .ss[[:alpha:]]/config", "cat .ss[[=h=]]/config", "cat id_r[[:lower:]]a", "cat private-??.[p]em",
])
def test_a_pattern_form_the_first_fix_did_not_model_is_denied(home, command):
    (home / "private-ab.pem").write_text("stand-in\n", encoding="utf-8")
    assert _ask_gate(command, home, home) == "deny"


@pytest.mark.parametrize("command", ["cat .ss[!x]/config", "cat ~/.ss[^x]/config", "cat id_r[a-z]a",
                                     "cat *.[Pp][Ee][Mm]"])
def test_control_a_pattern_form_the_first_fix_modelled_stays_denied(home, command):
    assert _ask_gate(command, home, home) == "deny"


@pytest.mark.parametrize("command", ["cat [[:upper:]]*.md", "cat notes-[0-9].txt", "cat *.pub", "cat [!.]*.json"])
def test_control_a_pattern_form_that_names_no_key_path_is_not_denied(home, command):
    assert _ask_gate(command, home, home) != "deny"


@pytest.mark.parametrize("command", ["wc -l repo/test_*", "cat notes*", "grep -r x repo/build*"])
def test_a_pattern_that_ends_with_a_run_is_not_read_as_a_key_ending(home, command):
    """It may end in `.pem` as `*` alone may; counting it would deny every `wc -l tests/test_*`."""
    assert _ask_gate(command, home, home) != "deny"


@pytest.mark.parametrize("command", ["cat id*", "cat ~/.ss*/config"])
def test_control_a_pattern_that_ends_with_a_run_still_counts_by_names(home, command):
    assert _ask_gate(command, home, home) == "deny"


@pytest.mark.parametrize("line", ["s$''udo -n true", "$'\\x73udo' -n true", "$'\\163udo' -n true", 's$""udo -n true',
                                  "x=sudo; $x -n true", "s${E}udo -n true", "`printf s`udo -n true",
                                  "$(printf s)udo -n true"])
def test_a_root_program_the_shell_assembles_is_the_door_root(gate, line):
    assert gate._release_door_words(line) == "root"


@pytest.mark.parametrize("line", ["echo $HOME", "ls $HOME/x", '"$HOME"/bin/tool --flag', "git status",
                                  "printf '%s' $'\\x41'"])
def test_control_a_line_whose_program_names_no_root_is_no_root_door(gate, line):
    assert gate._release_door_words(line) != "root"


# --- Third reading at 097cedad, line 3: the steps of bash's word formation for a program word ---------------------------

ROOT_FORMS = ["s\\\nu\\\ndo -n true", "{s,x}udo -n true", "su{d,}o -n true", "eval \"$(printf 's%s' udo)\" -n true",
              "bash -c \"$(printf s)udo -n true\"", "/usr/bin/su[d]o -n true", "/usr/bin/s?do -n true"]


@pytest.mark.parametrize("line", ROOT_FORMS)
def test_every_step_of_word_formation_that_makes_a_root_program_is_the_door_root(gate, line):
    assert gate._release_door_words(line) == "root"


@pytest.mark.parametrize("line", ["echo a\\\nb", "ls {a,b}.txt", "cat *.md", "eval echo hi", "bash -c 'echo hi'",
                                  "printf '%s' 'a\\b'", "/usr/bin/[a-c]at x"])
def test_control_word_formation_without_a_root_program_is_no_root_door(gate, line):
    assert gate._release_door_words(line) != "root"


NEIGHBOUR_FORMS = [("SUDO -n true", "root"), ("printf 'su%s' do | sh", "root"), ("bash <(printf 's%s' udo)", "root"),
                   ("/usr/bin/gp[g] --sign f", "signatur")]


@pytest.mark.parametrize("line,door", NEIGHBOUR_FORMS)
def test_the_neighbours_kraxo_measured_are_their_doors(gate, line, door):
    """A name in other case (a file system without case, as on macOS, finds the program), text a shell reads from a
    pipe or a process substitution, and the same class at the door of a signer. An alias the line itself defines is
    no neighbour: measured, neither `bash -c` nor `zsh -f -c` expands it in the same line."""
    assert gate._release_door_words(line) == door


@pytest.mark.parametrize("line", ["cat x | grep y", "printf hi | wc -l", "Git status", "export LANG=C",
                                  "bash script.sh", "x=ls; echo $x | sort"])
def test_control_neighbour_shapes_without_a_door_are_no_door(gate, line):
    assert gate._release_door_words(line) is None


# --- Fourth reading at de05121d, line 3: the escapes of $'…' are not rebuilt; with a backslash it is not resolved ------

@pytest.mark.parametrize("line", ["$'\\0163udo' -n true", "eval $'\\0163udo'", '$"x" -n true'])
def test_ansi_c_or_locale_quoting_the_gate_does_not_resolve_holds_the_release_back(gate, line):
    """`$'…'` with a backslash and `$"…"` with text count as not resolved: bash 5.1.16 and zsh 5.8.1 read `\\0163` as
    `\\016` and `3` (measured), another shell may not, and a message catalog may translate `$"…"`."""
    assert gate._release_door_words(line) == "root"


@pytest.mark.parametrize("line", ["printf '%s' $'\\x41'", "printf $'a\\nb'", 'echo $"hello"', "echo $''"])
def test_control_quoting_the_gate_does_not_resolve_outside_a_program_word_is_no_door(gate, line):
    assert gate._release_door_words(line) is None


@pytest.mark.parametrize("line", ROOT_FORMS[:5] + ["printf 'su%s' do | sh", "bash <(printf 's%s' udo)"])
def test_bash_runs_sudo_for_the_forms_above(line, tmp_path):
    """The premise, measured on bash with a stand-in in place of the program: an exported function and a script of the
    same name first on PATH, so that no form reaches the real program, also not in a child shell; the path forms need
    a file and are measured in the probe of the third reading."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash")
    stand_in = tmp_path / "bin" / "sudo"
    stand_in.parent.mkdir()
    stand_in.write_text("#!/bin/sh\nprintf 'SUDO\\n'\n", encoding="utf-8")
    stand_in.chmod(0o755)
    script = "sudo() { printf 'SUDO\\n'; }\nexport -f sudo\n" + line
    env = {"PATH": f"{stand_in.parent}:/usr/bin:/bin", "HOME": str(tmp_path)}
    r = subprocess.run([bash, "--norc", "--noprofile", "-c", script], capture_output=True, text=True, timeout=20,
                       cwd=str(tmp_path), env=env)
    assert r.stdout.startswith("SUDO"), (r.stdout, r.stderr)




# hermetic-cleanroom on PR 441: a module that imports the gate when it loads, in a tree without the gate. Skipped only
# where the tree is a distribution (positive evidence) whose MANIFEST.in does not ship the gate.

def _planted_tree(tmp_path: pathlib.Path, *, manifest: str, pkg_info: bool, git: bool) -> tuple:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "proofbundle"\n', encoding="utf-8")
    (root / "MANIFEST.in").write_text(manifest, encoding="utf-8")
    if pkg_info:
        (root / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: proofbundle\n", encoding="utf-8")
    if git:
        (root / ".git").mkdir()
    return root, root / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"


def _skip_reason(gate: pathlib.Path, root: pathlib.Path) -> str | None:
    from _gate_answer import skip_where_the_gate_is_not_shipped  # noqa: PLC0415
    try:
        skip_where_the_gate_is_not_shipped(gate, root)
    except pytest.skip.Exception as exc:
        return exc.msg
    return None


def test_a_distribution_that_prunes_plugins_skips_a_module_that_imports_the_gate(tmp_path):
    root, gate = _planted_tree(tmp_path, manifest="graft src\nprune plugins\n", pkg_info=True, git=False)
    why = _skip_reason(gate, root)
    assert why is not None and why.startswith("NOT MEASURED"), why
    assert "plugins/proofbundle/hooks/proofbundle_gate.py" in why


@pytest.mark.parametrize("case", ["promised", "checkout", "neither", "both", "shipped"])
def test_control_anywhere_else_the_import_of_the_gate_stays_loud(tmp_path, case):
    """A distribution that promises plugins/, a checkout, a tree that shows neither or both kinds, and a distribution
    that carries the gate: no skip, so a missing gate is an import error there."""
    root, gate = _planted_tree(tmp_path, manifest="graft plugins\n" if case == "promised" else "prune plugins\n",
                               pkg_info=case in ("promised", "both", "shipped"), git=case in ("checkout", "both"))
    if case == "shipped":
        gate.parent.mkdir(parents=True)
        gate.write_text("", encoding="utf-8")
    assert _skip_reason(gate, root) is None
