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
| commit measured | `9b7beab975cb94283b0ecc000a104384c7c3ad44` |
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz, 4 logical CPUs, x86_64 |
| memory | 16479424 kB total |
| operating system | Ubuntu 24.04.4 LTS, kernel 6.18.44-fc-v114 |
| Python | CPython 3.11.15 |
| dependencies | cffi 2.1.1, cryptography 50.0.1, rfc8785 0.1.4 |
| disk of the durable write | ext4 on /dev/vda, mounted at `/` |
| samples per case | 200 after 20 untimed warm-up calls |
| payload | 514 bytes, sha256 `3ff1f789d6f2f4096261cf285fa397d34e8ef40a012d2f3749b2c82016322a28` |

| run | measured at (end) | load average at start (1, 5, 15 min) | at end | tree clean |
|---|---|---|---|---|
| 2026-10-11-cloud-vm-run1 | 2026-10-11T13:32:47Z | 0.17, 0.12, 0.05 | 0.70, 0.28, 0.11 | yes |
| 2026-10-11-cloud-vm-run2 | 2026-10-11T13:34:15Z | 0.49, 0.27, 0.11 | 0.80, 0.40, 0.16 | yes |
| 2026-10-11-cloud-vm-run3 | 2026-10-11T13:35:39Z | 0.48, 0.36, 0.16 | 0.80, 0.47, 0.21 | yes |

<!-- end of machine -->

## Stages

Microseconds.

<!-- stages: written by render.py -->

| stage | p50, runs 1 to 3 | p95, run 1 | p99, runs 1 to 3 | max, run 1 |
|---|---|---|---|---|
| capture | 43.9 / 38.5 / 63.5 | 83.5 | 99.5 / 71.3 / 99.5 | 117.0 |
| canonicalize | 19.4 / 19.4 / 35.2 | 38.3 | 56.2 / 51.4 / 59.8 | 78.1 |
| hash_sha256 | 0.7 / 0.8 / 1.2 | 0.8 | 0.9 / 1.1 / 1.5 | 0.9 |
| hash_leaf | 1.4 / 1.6 / 2.8 | 2.6 | 3.7 / 1.8 / 3.2 | 17.9 |
| sign | 31.9 / 35.7 / 57.6 | 46.9 | 62.0 / 72.1 / 88.3 | 87.2 |
| emit_empty_history | 69.4 / 69.1 / 104.5 | 90.1 | 106.1 / 97.2 / 147.2 | 117.5 |
| durable_write | 761.2 / 1065.7 / 528.9 | 1230.4 | 1578.7 / 2652.5 / 1131.9 | 2390.0 |
| policy | 481.2 / 814.0 / 425.1 | 620.1 | 664.4 / 963.5 / 802.8 | 730.1 |
| verify | 239.2 / 226.9 / 222.9 | 293.9 | 355.1 / 434.2 / 404.5 | 377.3 |

<!-- end of stages -->

## The growing history

Microseconds, except the count.

<!-- history: written by render.py -->

| prior leaves n | SHA-256 calls per emit | emit p50, runs 1 to 3 | emit p99, run 1 | Merkle part p50, run 1 | signature p50, run 1 |
|---|---|---|---|---|---|
| 0 | 1 | 73.0 / 71.1 / 76.1 | 114.6 | 24.1 | 35.4 |
| 1 | 4 | 80.5 / 82.7 / 81.4 | 123.9 | 29.8 | 34.5 |
| 2 | 8 | 85.7 / 85.9 / 86.1 | 146.4 | 35.0 | 31.8 |
| 4 | 16 | 90.5 / 95.5 / 92.1 | 129.8 | 42.6 | 31.8 |
| 8 | 32 | 98.4 / 109.3 / 109.0 | 169.6 | 61.7 | 35.6 |
| 16 | 64 | 134.6 / 127.2 / 224.8 | 224.8 | 81.1 | 36.2 |
| 32 | 128 | 189.0 / 194.4 / 313.1 | 275.1 | 142.2 | 35.5 |
| 64 | 256 | 289.4 / 295.2 / 277.9 | 460.8 | 251.1 | 36.6 |
| 128 | 512 | 536.7 / 527.7 / 494.7 | 1085.9 | 484.1 | 34.4 |
| 256 | 1024 | 961.4 / 986.0 / 944.9 | 1627.9 | 921.5 | 35.6 |
| 512 | 2048 | 1897.0 / 2037.1 / 1831.1 | 3728.4 | 1806.8 | 34.4 |
| 1024 | 4096 | 3606.2 / 3800.2 / 3471.7 | 6291.3 | 4697.3 | 51.8 |
| 2048 | 8192 | 7148.7 / 10915.6 / 6958.9 | 14689.8 | 7479.5 | 35.1 |
| 4096 | 16384 | 14595.0 / 14754.1 / 14334.2 | 26384.2 | 15274.2 | 34.4 |
| 8192 | 32768 | 29277.4 / 29369.9 / 27739.0 | 61848.6 | 29395.5 | 34.9 |
| 16384 | 65536 | 55979.9 / 59030.9 / 57902.0 | 115261.0 | 59995.6 | 32.2 |

<!-- end of history -->

## What the tables show

Read off the tables above; each line names where it comes from.

- An emit makes 1 SHA-256 call with no history and 4n calls with n prior leaves, at every size measured
  (the count column; the same in all three runs).
- The signature's p50 is between 31.8 and 51.8 microseconds in run 1, the highest at n = 1024, and between
  31.3 and 54.6 over all three runs. The Merkle part is below it at n = 0 and n = 1 and above it from n = 2
  on, in all three runs. At n = 16384 the Merkle part's p50 is 59995.6 and the emit's 55979.9 (run 1): each
  p50 is the median of its own samples, so the p50 of a part can exceed the p50 of the whole.
- The p50 of a stage differs between the runs by up to a factor of 2.01, for the durable write; for verify
  by 1.07, for every other stage by 1.51 to 1.91. Run 3 is the highest in capture, canonicalize, both hashes,
  the signature and the empty-history emit, run 2 in the durable write and the policy. What else ran in the
  machine during the runs was not recorded, so the cause of that spread is not known.

## Not measured

- Any other machine. This is a virtual machine of a cloud provider; its neighbours are not visible from
  inside, and what else ran in it during the runs was not recorded.
- The command-line process: interpreter start and imports are not in any stage.
- A verify with a long inclusion path, a policy with more rules, or any write other than one fsync'd file.
- The incremental accumulator. The harness measures it when `tools/merkle_accumulator/accumulator.py` is
  present; it is not on this branch.

## Retaken runs

A first set of three runs at `a986c7f1` is not kept. Its runs 2 and 3 recorded the tree as not clean: the
check asked `git status` over all of `benchmarks/`, so run 1's result files counted as a changed tree,
although the code was the same. The check now leaves out `results/` and still reports any other change
under `src/`, `benchmarks/` and `tools/` (`f10092c2`), and three runs were taken again at that commit.

Those three runs at `f10092c2` are not kept either. The harness changed after them (`851fca4a`: the hash
counter follows the path the tree takes, and the durable write fsyncs the directory), and
`tests/test_runtime_baseline.py` holds the runs to the harness this page carries. The runs above were taken at
`9b7beab9`, where `run.py` is the same as at `851fca4a`, on a virtual machine of the same kind: the same CPU
model and the same Python build, each run started below a one-minute load of 0.5. Three things differ from
the runs at `f10092c2` at once: the code (289 commits, 67 files under `src/`), the kernel (`6.18.44-fc-v42`
then, `6.18.44-fc-v114` now) and the machine instance with its neighbours. Taking the median of the three
runs' p50, six of the nine stages are higher now and canonicalize, hash_sha256 and sign lower, and the emit
over a growing history is higher at all 16 sizes. Which of the three changes carries which difference is not
measured separately.

## Rerun

```
PYTHONPATH=src python benchmarks/runtime_baseline/run.py --out benchmarks/runtime_baseline/results/<name>
python benchmarks/runtime_baseline/render.py
```
