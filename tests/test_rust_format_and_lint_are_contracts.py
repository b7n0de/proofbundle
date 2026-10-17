"""The pinned Rust toolchain as a CONTRACT: both guards, their form and their run.

WHY THIS FILE EXISTS. On 2026-09-15 `cargo fmt --check` was red in the Rust tree: 36 hits under the
pinned toolchain. The fix went through PR 211 and landed as `8d20eec`, and the measurement for it was
honest, only NOT attestable. The closing receipt of this house asks for a catch proof in the form of
a pytest node, and a cargo measurement had none. The application came back refused, and the lesson
then stood in the findings book instead of in the tree: a measurement without a node cannot be
promised.

THE FORM IS READ FROM THE PARSED YAML, NOT FROM THE TEXT, and that is the core of the second
version. The first searched substrings in the raw text of `ci.yml`. An executing cross-read on
2026-09-16 found four ways to satisfy the promise without keeping it: a bare COMMENT
`# working-directory: tools/pb_verify_rs` satisfied the directory check; an appended `|| true`
neutralised the exit code while `-D warnings` still stood there; and `text.index(line)` always found
the FIRST occurrence of a line, so a harmless decoy job further up lent its compliance to the real,
broken step further down. All four disappear when steps are read as OBJECTS instead of as lines.

THE VERSION IS CHECKED FOR EQUALITY, not for a substring. `"1.95.0" in "rustc 1.95.0-ROGUE-FORK ..."`
is true, and the same cross-read demonstrated exactly that.

THE RUN MUST ALSO REALLY HAPPEN IN CI. The first version ran only when `tools/pb_verify_rs/target`
existed, and measured, NO job that runs this file with pytest builds the Rust tree. The hit rate in
the real pipeline was zero, and a case that never measures looks like care. The `rust-parity` job
builds the tree and runs this file explicitly since then; the case below pins exactly that.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUST = REPO / "tools" / "pb_verify_rs"
PIN = RUST / "rust-toolchain.toml"
CI = REPO / ".github" / "workflows" / "ci.yml"

#: `channel = "1.95.0"`, deliberately a regex and not tomllib: the package is also tested on 3.10,
#: and tomllib does not exist there.
_CHANNEL = re.compile(r'^\s*channel\s*=\s*"([^"]+)"\s*$', re.M)
#: `rustc 1.95.0 (59807616e 2026-04-14)`, the version as its OWN field, not as a substring.
_RUSTC = re.compile(r"^rustc\s+(\S+)")
#: `components = ["rustfmt", "clippy"]`, the FIELD, not the file text. The head of the pin names
#: both tools in a comment; a `"clippy" in text` is therefore true even when the list no longer holds
#: it. That is exactly how the first attempt at this case survived the planted defect, the same class
#: this whole second version stands against, inside the fix against it.
_COMPONENTS = re.compile(r"^\s*components\s*=\s*\[([^\]]*)\]", re.M)
#: What swallows an exit code. `cmd || true`, `cmd || :`, `cmd ; true`, `set +e`.
_SWALLOWED = re.compile(r"\|\|\s*(true|:)\s*$|;\s*true\s*$|\bset\s+\+e\b", re.M)


def _pinned_channel() -> str:
    if not PIN.is_file():
        pytest.skip(f"{PIN} is not here")
    m = _CHANNEL.search(PIN.read_text(encoding="utf-8"))
    if not m:
        pytest.fail(f"{PIN} names no `channel`, so the measurement is not pinned")
    return m.group(1)


def _run(*command: str, cwd: Path = RUST) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)


def _steps_with(command_part: str) -> list[tuple[str, dict, dict, dict]]:
    """Every step whose `run` contains the command part, as (job_id, job, step, workflow).

    AS OBJECTS, NOT AS LINES. A step is a dictionary with `run`, `working-directory` and its job; a
    comment is no longer there in the parsed tree, and two lines with the same text in two jobs are
    two different objects. That is exactly where the first version failed.
    """
    yaml = pytest.importorskip("yaml", reason="PyYAML is missing, the form of ci.yml is NOT MEASURABLE")
    if not CI.is_file():
        pytest.skip(".github/workflows/ci.yml is not here")
    wf = yaml.safe_load(CI.read_text(encoding="utf-8")) or {}
    out = []
    for job_id, job in (wf.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            if isinstance(step, dict) and command_part in str(step.get("run") or ""):
                out.append((job_id, job or {}, step, wf))
    return out


def _working_directory(step: dict, job: dict, wf: dict) -> str | None:
    """The EFFECTIVE working directory of a step, in the precedence of GitHub Actions."""
    for level in (step, job, wf):
        wd = level.get("working-directory")
        if wd:
            return str(wd)
        default = ((level.get("defaults") or {}).get("run") or {}).get("working-directory")
        if default:
            return str(default)
    return None


def _runs_in_the_directory_of_the_pin(step: dict, job: dict, wf: dict) -> bool:
    """Does this step land in `tools/pb_verify_rs`? rustup selects the toolchain by it."""
    wd = _working_directory(step, job, wf)
    if wd and wd.strip().strip("./") == "tools/pb_verify_rs":
        return True
    return bool(re.search(r"cd\s+tools/pb_verify_rs\s*&&", str(step.get("run") or "")))


def test_the_toolchain_is_pinned_to_an_exact_version_and_names_both_tools():
    """A channel like `stable` is not a pin but a moving surface.

    AND THE COMPONENTS BELONG TO IT: if the file does not name `clippy`, a fresh runner does not
    install it at all, and the clippy step would break, while locally everything stays green because
    the component has long been there. A mutant that took `clippy` out of the list survived the first
    version."""
    channel = _pinned_channel()
    assert re.fullmatch(r"\d+\.\d+\.\d+", channel), (
        f"channel = {channel!r} is not an exact version. rustfmt and clippy judge by version; a "
        "moving channel makes the same source look different tomorrow, and exactly this drift has "
        "turned the gate red once before.")
    m = _COMPONENTS.search(PIN.read_text(encoding="utf-8"))
    assert m, f"{PIN} names no `components` field"
    named = {w.strip().strip('\'"') for w in m.group(1).split(",") if w.strip()}
    for tool in ("rustfmt", "clippy"):
        assert tool in named, (
            f"the pin does not list {tool!r} in `components` (read: {sorted(named)}), so a fresh "
            "runner does not install it, and its step breaks for a reason this file claims to "
            "prevent")


@pytest.mark.parametrize("command,flag", [("cargo fmt", "--check"), ("cargo clippy", "-D warnings")])
def test_each_guard_runs_in_the_directory_of_the_pin_and_keeps_its_exit_code(command, flag):
    """The form, from the PARSED workflow. Three promises per step.

    (1) It lands in `tools/pb_verify_rs`, because rustup selects the toolchain by working directory,
    through `working-directory` on step, job or workflow level or through a `cd ... &&`. (2) It carries
    its flag: `--check` checks instead of formatting, `-D warnings` turns a warning into an error.
    (3) Its exit code is not swallowed; an appended `|| true` turns both other promises into
    decoration."""
    steps = _steps_with(command)
    assert steps, f"no step in CI runs `{command}`"
    for job_id, job, step, wf in steps:
        where = f"job {job_id!r}, step {step.get('name') or step.get('run')!r}"
        assert _runs_in_the_directory_of_the_pin(step, job, wf), (
            f"{where} does not land in tools/pb_verify_rs. rustup selects the toolchain by working "
            "directory; without it the step measures under any version, and green or red would be "
            "chance.")
        run = str(step.get("run") or "")
        assert flag in run, f"{where} does not carry {flag!r}: {run!r}"
        assert not _SWALLOWED.search(run), (
            f"{where} swallows its exit code ({run!r}). With `|| true` at the end, {flag!r} is an "
            "opinion, not a promise.")


def test_the_rust_job_runs_this_file():
    """THE CASE THAT MAKES THIS FILE TAKE EFFECT AT ALL.

    The run case below needs a built Rust tree. Measured 2026-09-16: NO job that runs pytest on this
    file builds it; `test` and `coverage` build no Rust, `rust-parity` and `audit-candidate-matrix`
    run no pytest. The hit rate in the real pipeline was therefore ZERO, and a case that never
    measures looks like care. Found by an executing cross-read, not by reading.

    The `rust-parity` job builds the tree anyway; since then it runs this file explicitly, and this
    case holds that."""
    yaml = pytest.importorskip("yaml", reason="PyYAML is missing, the form of ci.yml is NOT MEASURABLE")
    if not CI.is_file():
        pytest.skip(".github/workflows/ci.yml is not here")
    wf = yaml.safe_load(CI.read_text(encoding="utf-8")) or {}
    my_file = Path(__file__).name
    builds, runs = set(), set()
    for job_id, job in (wf.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            run = str((step or {}).get("run") or "")
            if "cargo build" in run:
                builds.add(job_id)
            if my_file in run:
                runs.add(job_id)
    both = builds & runs
    assert both, (
        f"no job builds the Rust tree AND runs {my_file}: builds {sorted(builds)}, runs "
        f"{sorted(runs)}. Without an overlap the run case skips itself in the whole pipeline and "
        "never measures anything.")


def _pinned_surface_or_skip(channel: str) -> str:
    """Is the pinned toolchain running here? Otherwise a SKIP that says WHY nothing was measured."""
    if not RUST.is_dir():
        pytest.skip("tools/pb_verify_rs is not here (package run instead of a checkout)")
    if shutil.which("cargo") is None:
        pytest.skip("NOT MEASURED: no `cargo` on PATH, and that is not a passed run")
    # A REDIRECTED TOOL IS NOT A PINNED SURFACE. `RUSTFMT` binds a foreign program while
    # `rustc --version` still reports the pin; a cross-read brought a REAL formatting error past this
    # case that way.
    for var in ("RUSTFMT", "RUSTC", "CARGO"):
        if os.environ.get(var):
            pytest.skip(f"NOT MEASURED: ${var} redirects the tool ({os.environ[var]!r}), so what "
                        "runs is not the pinned toolchain")
    rustc = _run("rustc", "--version")
    if rustc.returncode != 0:
        pytest.skip(f"NOT MEASURED: `rustc --version` ended with {rustc.returncode}: "
                    f"{(rustc.stderr or rustc.stdout).strip()[:160]}")
    m = _RUSTC.match(rustc.stdout.strip())
    measured = m.group(1) if m else rustc.stdout.strip()
    # EQUALITY, NOT A SUBSTRING: `"1.95.0" in "rustc 1.95.0-ROGUE-FORK ..."` is true.
    if measured != channel:
        pytest.skip(f"NOT MEASURED on the pinned surface: the pin names {channel}, here runs "
                    f"{measured!r}")
    return rustc.stdout.strip()


def test_the_rust_tree_is_formatted_under_the_pinned_toolchain():
    """THE ACTUAL NODE for the formatting. It measures what the CI step measures."""
    toolchain = _pinned_surface_or_skip(_pinned_channel())
    ver = _run("cargo", "fmt", "--version")
    component = ver.stdout.strip() if ver.returncode == 0 else "(rustfmt version not measurable)"
    r = _run("cargo", "fmt", "--check")
    assert r.returncode == 0, (
        f"`cargo fmt --check` under {toolchain} / {component} ended with {r.returncode}. That is the "
        f"same command the CI step runs.\n--- stdout ---\n{r.stdout[:4000]}\n"
        f"--- stderr ---\n{r.stderr[:1000]}")


def test_the_linter_is_green_where_the_tree_already_stands():
    """The linter run. It pulls NO full compilation into the suite.

    Measured: 3.5 s on a built tree, minutes on a cold one. It therefore runs only where the tree
    stands, and that this is really the case in CI is held by `test_the_rust_job_runs_this_file`."""
    toolchain = _pinned_surface_or_skip(_pinned_channel())
    if not (RUST / "target").is_dir():
        pytest.skip("NOT MEASURED: the Rust tree is not built here; a full compilation does not "
                    "belong in this suite, it runs in the Rust job")
    r = _run("cargo", "clippy", "--all-targets", "--", "-D", "warnings")
    assert r.returncode == 0, (
        f"`cargo clippy --all-targets -- -D warnings` under {toolchain} ended with "
        f"{r.returncode}. That is the same command the CI step runs.\n"
        f"--- stderr ---\n{r.stderr[-4000:]}")
