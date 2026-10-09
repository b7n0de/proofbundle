# Runtime baseline

What one receipt costs, stage by stage, on the machine the numbers were taken on, and what the growing
history costs an emit. Nothing here is compared with a target: the numbers describe one machine on one
day, and a later change is measured against them, not judged by them.

The harness is [`run.py`](run.py); the three runs it wrote are under [`results/`](results/), each with
every sample in `raw.json` (nanoseconds, in the order taken) and the percentiles in `summary.json`. The
tables below are written from those files by [`render.py`](render.py); `tests/test_runtime_baseline.py`
holds the tables to the files and each summary to its samples.

## What is measured

One call per sample, timed with `time.perf_counter_ns`, after 20 untimed warm-up calls; 200 samples per
case. Percentiles are nearest rank: the p-th percentile is the ceil(p/100 · N)-th smallest sample.

| stage | the call |
|---|---|
| capture | `build_eval_claim` from fixed inputs: salted commitments, the verdict computed |
| canonicalize | the RFC 8785 bytes of that claim, the payload that gets signed |
| hash_sha256 | SHA-256 of the payload |
| hash_leaf | the RFC 6962 leaf hash of the payload |
| sign | Ed25519 over the payload |
| emit_empty_history | `emit_bundle` with no history: signature, root and inclusion path of a one-leaf tree |
| durable_write | the bundle as JSON to a file: write, flush, fsync, rename, fsync of the directory |
| policy | `evaluate_policy` over a verified bundle, with a policy that passes |
| verify | `verify_bundle`, the full offline check: signature, leaf, inclusion path, root |

The growing history: `emit_bundle` with `prior_leaves` of n entries, for n = 0 and every power of two up
to 16384, each size measured on its own. For each n the SHA-256 calls of one emit are counted (by wrapping
the merkle module's leaf and node hash, not timed), and the Merkle part (root and inclusion path over the
n + 1 leaves) and the signature are timed apart. `emit_bundle` rebuilds the whole tree on every call
(`src/proofbundle/emit.py`: `list(prior_leaves) + [payload]`, then `merkle_tree_hash` and `inclusion_proof`
over it).

The three runs were taken one after another at the same commit, each started only when the one-minute load
average of the machine was below 0.5.

## The machine and the runs

<!-- machine: written by render.py -->

| what | value |
|---|---|
| commit measured | `f10092c232ec4ff9c059f0b84ce59e4dd9a3b9e6` |
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz, 4 logical CPUs, x86_64 |
| memory | 16481900 kB total |
| operating system | Ubuntu 24.04.4 LTS, kernel 6.18.44-fc-v42 |
| Python | CPython 3.11.15 |
| dependencies | cffi 2.1.1, cryptography 50.0.1, rfc8785 0.1.4 |
| disk of the durable write | ext4 on /dev/vda, mounted at `/` |
| samples per case | 200 after 20 untimed warm-up calls |
| payload | 514 bytes, sha256 `3ff1f789d6f2f4096261cf285fa397d34e8ef40a012d2f3749b2c82016322a28` |

| run | measured at (end) | load average at start (1, 5, 15 min) | at end | tree clean |
|---|---|---|---|---|
| 2026-09-28-cloud-vm-run1 | 2026-09-28T00:43:58Z | 0.30, 1.16, 2.19 | 0.67, 1.13, 2.14 | yes |
| 2026-09-28-cloud-vm-run2 | 2026-09-28T00:45:01Z | 0.48, 1.06, 2.09 | 0.74, 1.05, 2.04 | yes |
| 2026-09-28-cloud-vm-run3 | 2026-09-28T00:46:08Z | 0.48, 0.97, 1.99 | 0.76, 0.97, 1.94 | yes |

<!-- end of machine -->

## Stages

Microseconds.

<!-- stages: written by render.py -->

| stage | p50, runs 1 to 3 | p95, run 1 | p99, runs 1 to 3 | max, run 1 |
|---|---|---|---|---|
| capture | 7.3 / 7.3 / 7.2 | 12.3 | 20.6 / 15.0 / 23.0 | 48.9 |
| canonicalize | 20.4 / 20.3 / 20.5 | 26.1 | 58.4 / 42.0 / 50.7 | 88.3 |
| hash_sha256 | 0.9 / 0.9 / 0.9 | 1.1 | 3.8 / 1.4 / 1.2 | 13.8 |
| hash_leaf | 0.9 / 1.0 / 0.9 | 1.0 | 1.3 / 1.9 / 1.3 | 5.7 |
| sign | 37.3 / 37.2 / 37.3 | 53.9 | 69.8 / 58.1 / 63.3 | 75.2 |
| emit_empty_history | 61.5 / 43.9 / 44.2 | 77.1 | 87.8 / 68.2 / 86.2 | 101.9 |
| durable_write | 345.9 / 277.5 / 363.8 | 491.7 | 605.3 / 430.6 / 563.6 | 666.0 |
| policy | 220.2 / 218.1 / 218.8 | 336.6 | 399.1 / 291.3 / 316.5 | 474.2 |
| verify | 160.0 / 155.5 / 156.5 | 224.1 | 248.4 / 220.8 / 250.1 | 259.4 |

<!-- end of stages -->

## The growing history

Microseconds, except the count.

<!-- history: written by render.py -->

| prior leaves n | SHA-256 calls per emit | emit p50, runs 1 to 3 | emit p99, run 1 | Merkle part p50, run 1 | signature p50, run 1 |
|---|---|---|---|---|---|
| 0 | 1 | 51.1 / 44.0 / 43.9 | 93.5 | 1.2 | 37.4 |
| 1 | 4 | 53.0 / 47.4 / 47.1 | 93.1 | 3.4 | 37.3 |
| 2 | 8 | 62.6 / 49.9 / 50.3 | 107.7 | 6.2 | 37.4 |
| 4 | 16 | 57.3 / 55.7 / 56.1 | 101.6 | 11.8 | 48.2 |
| 8 | 32 | 67.4 / 66.6 / 67.1 | 102.4 | 22.7 | 37.1 |
| 16 | 64 | 90.5 / 88.2 / 88.7 | 143.8 | 44.9 | 38.4 |
| 32 | 128 | 139.5 / 130.6 / 133.3 | 256.4 | 89.4 | 37.4 |
| 64 | 256 | 232.1 / 219.0 / 223.0 | 428.7 | 178.8 | 38.7 |
| 128 | 512 | 437.2 / 402.8 / 420.0 | 962.0 | 375.3 | 37.9 |
| 256 | 1024 | 793.1 / 765.6 / 790.6 | 963.4 | 735.2 | 36.8 |
| 512 | 2048 | 1521.4 / 1485.4 / 1501.5 | 2173.6 | 1466.4 | 37.2 |
| 1024 | 4096 | 3034.8 / 2905.7 / 2992.7 | 4451.5 | 2954.6 | 37.2 |
| 2048 | 8192 | 5910.2 / 5846.1 / 5951.1 | 7340.4 | 5841.4 | 37.4 |
| 4096 | 16384 | 11932.5 / 11690.6 / 11657.8 | 16352.4 | 11690.6 | 36.8 |
| 8192 | 32768 | 24077.2 / 23626.2 / 23680.5 | 45431.7 | 23711.9 | 37.5 |
| 16384 | 65536 | 47184.2 / 46477.3 / 47196.6 | 62415.3 | 47131.8 | 36.8 |

<!-- end of history -->

## What the tables show

Read off the tables above; each line names where it comes from.

- An emit makes 1 SHA-256 call with no history and 4n calls with n prior leaves, at every size measured
  (the count column; the same in all three runs).
- The signature's p50 is between 36.8 and 38.7 microseconds at every n except n = 4, where it is 48.2
  (run 1). The Merkle part is below it at n = 8 and above it from n = 16 on; at n = 16384 it is 47131.8 of
  the emit's 47184.2 (run 1).
- The p50 of most stages differs by a few percent between the runs. Two differ more: the empty-history
  emit, where run 1 is higher than runs 2 and 3, and the durable write, whose fsync varies from run to
  run. What else ran on the machine during each run was not recorded, so the cause is not known.

## Not measured

- Any other machine. This is a virtual machine of a cloud provider; its neighbours are not visible from
  inside. A local ledger process (in a container) was running during the runs; its CPU share during the
  runs was not measured.
- The command-line process: interpreter start and imports are not in any stage.
- A verify with a long inclusion path, a policy with more rules, or any write other than one fsync'd file.
- The incremental accumulator. The harness measures it when `tools/merkle_accumulator/accumulator.py` is
  present; it is not on this branch.

## Retaken runs

A first set of three runs at `a986c7f1` is not kept. Its runs 2 and 3 recorded the tree as not clean: the
check asked `git status` over all of `benchmarks/`, so run 1's result files counted as a changed tree,
although the code was the same. The check now leaves out `results/` and still reports any other change
under `src/`, `benchmarks/` and `tools/` (`f10092c2`), and all three runs were retaken at that commit.

## Rerun

```
PYTHONPATH=src python benchmarks/runtime_baseline/run.py --out benchmarks/runtime_baseline/results/<name>
python benchmarks/runtime_baseline/render.py
```
