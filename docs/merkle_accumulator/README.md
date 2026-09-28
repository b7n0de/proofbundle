# The incremental Merkle accumulator, before and after

`emit_bundle` (`src/proofbundle/emit.py`) rebuilds the whole tree for every event: with n prior leaves it
hashes the n + 1 leaves and every interior node again, for the root and for the new leaf's inclusion path.
[`tools/merkle_accumulator/accumulator.py`](../../tools/merkle_accumulator/accumulator.py) keeps the
frontier instead, one subtree root per set bit of the size, and gives the same root and path, byte for
byte, from it. This page records what that changes, measured with the runtime baseline harness
([`benchmarks/runtime_baseline/run.py`](../../benchmarks/runtime_baseline/run.py)), which measures the
accumulator whenever the tool is present. Nothing here is compared with a target.

The three runs are under [`runs/`](runs/), each with every sample (`raw.json`, nanoseconds) and the
percentiles (`summary.json`). The tables are written from them by
[`render_runs.py`](../../tools/merkle_accumulator/render_runs.py); `tests/test_merkle_accumulator_runs.py`
holds the tables to the files and each summary to its samples.

## What is measured

For n = 0 and every power of two up to 16384 prior leaves, each size on its own, 200 samples after 20
untimed warm-up calls, nearest-rank percentiles:

- **emit_bundle**: one emit with `prior_leaves` of n entries, the tree rebuilt;
- **through the accumulator**: `emit_bundle_incremental` on an accumulator that already holds the n
  leaves (a fresh copy per sample, made outside the timed call), which appends and signs;
- **append alone**: the root and the new leaf's path from the frontier, without the signature.

The SHA-256 calls of one emit and of one append are counted by wrapping the merkle module's leaf and node
hash, not timed. The runs were taken one after another at one commit, each started with the one-minute
load average below 0.5, on the machine the runtime baseline names.

## The runs

<!-- runs: written by render_runs.py -->

| run | commit measured | measured at (end) | load average at start (1, 5, 15 min) | at end | tree clean |
|---|---|---|---|---|---|
| 2026-09-28-cloud-vm-run1 | `35563abb` | 2026-09-28T00:50:56Z | 0.19, 0.55, 1.53 | 0.62, 0.61, 1.51 | yes |
| 2026-09-28-cloud-vm-run2 | `35563abb` | 2026-09-28T00:52:04Z | 0.47, 0.58, 1.47 | 0.82, 0.66, 1.45 | yes |
| 2026-09-28-cloud-vm-run3 | `35563abb` | 2026-09-28T00:53:21Z | 0.46, 0.58, 1.40 | 0.72, 0.64, 1.38 | yes |

<!-- end of runs -->

## The growing history

Microseconds, except the counts.

<!-- history: written by render_runs.py -->

| prior leaves n | SHA-256 calls, emit_bundle | SHA-256 calls, append | emit_bundle p50, runs 1 to 3 | through the accumulator p50, runs 1 to 3 | append alone p50, run 1 |
|---|---|---|---|---|---|
| 0 | 1 | 1 | 43.8 / 43.9 / 44.5 | 44.9 / 45.1 / 45.2 | 1.3 |
| 1 | 4 | 2 | 47.0 / 47.0 / 47.6 | 46.2 / 46.4 / 45.8 | 2.1 |
| 2 | 8 | 2 | 50.5 / 49.8 / 50.8 | 46.0 / 46.3 / 46.0 | 2.0 |
| 4 | 16 | 2 | 54.8 / 55.5 / 56.5 | 45.9 / 46.2 / 46.1 | 2.0 |
| 8 | 32 | 2 | 93.8 / 67.6 / 68.5 | 46.4 / 46.5 / 46.3 | 2.0 |
| 16 | 64 | 2 | 117.1 / 95.7 / 89.5 | 46.3 / 46.2 / 45.8 | 2.0 |
| 32 | 128 | 2 | 158.5 / 138.1 / 133.5 | 46.0 / 46.1 / 46.0 | 2.0 |
| 64 | 256 | 2 | 246.8 / 226.0 / 226.2 | 46.1 / 46.3 / 46.0 | 2.0 |
| 128 | 512 | 2 | 413.3 / 414.5 / 414.3 | 46.0 / 46.2 / 46.0 | 2.0 |
| 256 | 1024 | 2 | 769.3 / 772.8 / 769.4 | 46.1 / 46.3 / 46.1 | 2.0 |
| 512 | 2048 | 2 | 1488.8 / 1489.5 / 1485.1 | 46.1 / 46.3 / 46.0 | 2.0 |
| 1024 | 4096 | 2 | 2937.1 / 2924.6 / 2920.9 | 46.1 / 46.6 / 46.3 | 2.0 |
| 2048 | 8192 | 2 | 5920.0 / 5834.5 / 5796.2 | 44.8 / 46.5 / 46.1 | 1.9 |
| 4096 | 16384 | 2 | 11795.7 / 11624.6 / 11657.0 | 44.5 / 46.3 / 46.0 | 1.9 |
| 8192 | 32768 | 2 | 23963.2 / 23240.6 / 23409.8 | 44.6 / 46.5 / 46.3 | 2.0 |
| 16384 | 65536 | 2 | 47412.9 / 47128.3 / 46736.5 | 45.5 / 46.6 / 46.0 | 2.0 |

<!-- end of history -->

## What the tables show

- With n prior leaves emit_bundle makes 4n SHA-256 calls (1 with none); an append makes 1 with none and 2
  at every size measured here.
- Through the accumulator the p50 of an emit is between 44.5 and 46.6 microseconds at every n in all three
  runs. emit_bundle's p50 grows from 43.8 at n = 0 to 47412.9 at n = 16384 (run 1). At n = 0 the
  accumulator's path is the slower of the two in all three runs.

## Not measured

- **The sizes where an append carries.** Every size here is a power of two, and at a power of two an
  append makes one leaf hash and one node hash, whatever the size. The accumulator's own bound is
  1 + 2 · floor(log2(size)) + 1 calls, reached near sizes of the form 2^k − 1, where the new leaf merges a
  run of subtrees. There the calls are counted by `tests/test_merkle_accumulator.py` (at most 26 up to
  4097 leaves), and the time is not measured.
- Building the accumulator from a long history, restoring a persisted state, and the later proofs that need
  the kept leaf hashes (O(n) each).
- Memory: the frontier is at most one 32-byte root per set bit of the size; the optional leaf hashes are
  32 bytes per leaf. Not measured as process memory.
- Any other machine, and the ledger process that ran in a container during the runs (not measured).
