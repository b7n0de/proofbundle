"""One way for a test to get the Rust second verifier, `pb_verify_rs`.

WHY THIS MODULE EXISTS (owner note of 2026-09-28 on Z281). Five test modules built the binary
themselves when cargo was present, and about eleven others only looked for it and skipped when it
was absent, most of them at collection time. Which tests ran therefore depended on the order: in a
serial run an early module built the binary and the later checkers found it, but a checker decided at
collection had already skipped, and under pytest-xdist any checker could run before any builder.
Measured on 0ace3039 with four workers: three tests skipped in one run and passed in the next two.

Every test that needs the binary asks this module, at run time:

- PINNED: `PROOFBUNDLE_PB_VERIFY_RS` names a built binary; it is used as given and nothing is built.
  CI builds once in a step before the tests and pins the result.
- BUILT: otherwise, when `tools/pb_verify_rs` and cargo are present, `cargo build --release` runs once
  per process under an exclusive file lock, so parallel workers wait for each other instead of racing;
  after the first build cargo's own check is a no-op.
- ABSENT: otherwise there is no binary, and `binary_or_skip` skips with the reason, unless
  `PROOFBUNDLE_REQUIRE_PB_VERIFY_RS=1`, which CI sets. Then a missing binary fails the test: a skip
  there would be a green check over an empty set.

`binary_or_skip` raises `unittest.SkipTest`, which pytest and unittest both report as a skip, so a
`TestCase` run by `unittest discover` and a pytest function use the same call.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
RUST_DIR = REPO / "tools" / "pb_verify_rs"
RELEASE_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"
PINNED_ENV = "PROOFBUNDLE_PB_VERIFY_RS"
REQUIRED_ENV = "PROOFBUNDLE_REQUIRE_PB_VERIFY_RS"
LOCK_FILE = RUST_DIR / "target" / ".pb_verify_rs-build.lock"

_CACHE: dict = {}


def required() -> bool:
    """Whether a missing binary fails the test instead of skipping it."""
    return os.environ.get(REQUIRED_ENV, "").strip() == "1"


def _lock(handle) -> None:
    try:
        import fcntl  # noqa: PLC0415
    except ImportError:  # pragma: no cover - no POSIX locks on this platform, cargo's own lock remains
        return
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _build() -> "tuple[pathlib.Path | None, str]":
    if not (RUST_DIR / "Cargo.toml").is_file():
        return None, f"{RUST_DIR} is absent (an unpacked sdist carries no Rust sources)"
    if shutil.which("cargo") is None:
        return None, "cargo is not on PATH"
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_FILE, "a+", encoding="utf-8") as handle:
        _lock(handle)
        done = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                              capture_output=True, text=True, timeout=1800)
    if done.returncode != 0 or not RELEASE_BIN.is_file():
        tail = (done.stderr or done.stdout).strip().splitlines()[-3:]
        return None, f"cargo build --release failed with exit {done.returncode}: {' | '.join(tail)}"
    return RELEASE_BIN, ""


def locate() -> "tuple[pathlib.Path | None, str]":
    """(binary, reason when absent). Resolved once per process."""
    if "result" not in _CACHE:
        pinned = os.environ.get(PINNED_ENV, "").strip()
        if pinned:
            path = pathlib.Path(pinned)
            _CACHE["result"] = ((path, "") if path.is_file()
                                else (None, f"{PINNED_ENV}={pinned} names no file"))
        else:
            _CACHE["result"] = _build()
    return _CACHE["result"]


def binary() -> "pathlib.Path | None":
    return locate()[0]


def binary_or_skip() -> pathlib.Path:
    """The binary, or a skip naming why it is absent; a failure instead when CI requires it."""
    path, why = locate()
    if path is not None:
        return path
    message = f"pb_verify_rs is not available: {why}"
    if required():
        raise AssertionError(f"{message}; {REQUIRED_ENV}=1 requires it, a skip here would pass an "
                             "empty set")
    raise unittest.SkipTest(f"{message} (NOT MEASURED, never green)")
