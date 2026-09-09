#!/usr/bin/env bash
# Setup phase for the Codex environment: everything that needs the network happens HERE.
#
# WHY THIS FILE EXISTS. The agent phase of that environment has no network (AGENTS.md, Boundaries).
# Anything not installed during setup is simply missing later, and the failure then looks like a
# broken test rather than a missing dependency. This script is the one place that may reach out,
# so it installs the Python package with its test extras AND builds the Rust second verifier.
#
# WHY THE RUST BUILD BELONGS HERE. Without `pb_verify_rs` the differential tests do not fail — they
# SKIP, and a skip reads like "not needed" rather than "not measured". A review agent then sees a
# green run over a smaller surface than it believes. Building it in the setup phase removes that
# silent gap.
#
# FAIL LOUD. Every step is checked and the script exits non-zero on the first failure. A setup that
# half-succeeds is worse than one that stops: it hands the agent phase an environment nobody
# described.
set -euo pipefail

WURZEL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${WURZEL}"

echo "== proofbundle setup, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "-- repository: ${WURZEL}"
echo "-- commit:     $(git rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"

echo "== python package with test extras"
python -m pip install --upgrade pip
python -m pip install -e ".[dev,pq,anchors,eval]" pytest hypothesis

echo "== rust second verifier (release)"
if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is not on PATH — the differential tests would SKIP silently, which this setup exists to prevent" >&2
    exit 1
fi
cargo build --release --manifest-path tools/pb_verify_rs/Cargo.toml

BINARY="${WURZEL}/tools/pb_verify_rs/target/release/pb_verify_rs"
if [[ ! -x "${BINARY}" ]]; then
    echo "the build reported success but ${BINARY} is not executable" >&2
    exit 1
fi

echo "== versions, measured not assumed"
echo "-- python:       $(python --version 2>&1)"
echo "-- pytest:       $(python -m pytest --version 2>&1 | head -1)"
echo "-- hypothesis:   $(python -c 'import hypothesis; print(hypothesis.__version__)' 2>&1)"
echo "-- cargo:        $(cargo --version 2>&1)"
echo "-- pb_verify_rs: $("${BINARY}" --version 2>&1 | head -1 || echo 'no --version, binary present')"
echo "-- binary bytes: $(stat -c%s "${BINARY}")"

echo "== collection check, so a missing dependency shows up NOW and not in the agent phase"
python -m pytest --collect-only -q 2>&1 | tail -1

echo "== setup complete"
