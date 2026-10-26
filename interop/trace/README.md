# Comparison of `proofbundle verify-trace` with the TRACE reference

This directory compares proofbundle's TRACE v0.2 Trust Record verifier
(`proofbundle.adapters.trace_record`, CLI `proofbundle verify-trace`) with the TRACE reference
library, case by case. It does not belong to the verifier: nothing here is imported by the
library, and the verifier and its tests import nothing of the reference.

## What is pinned

`pins.json` names every input by commit and digest:

- agentrust-io/trace-tests at `109fb54278cca5be649a878e2bfb54311a6bf386`
- agentrust-io/trace-spec at `a131c6400eaa95007b16b84a96331ccf37a93b73` (main, 2026-10-16), and
  the tag `v0.11.0` at `7d8df347ada4ce84356640c9252ea2cc1d467b58`
- agentrust-trace 0.11.0 from PyPI, wheel SHA-256
  `7de621eaf795449e365d04967a82a551a18d75c99d248b4a0923f6d593bdb09e`

`pins.json` also holds the SHA-256 of each of the 52 vector files the comparison reads.
`compare.py` refuses a checkout at another commit, and it refuses any file whose bytes differ
from its pin.

## What is not copied

The trace-tests vectors are Apache-2.0. The trace-spec vectors are material of the TRACE project.
Neither is stored in this repository. The comparison reads them from checkouts at the pinned
commits. Its output carries the exact bytes of every divergent case, so `compare.py` writes it
only outside the repository. The counter-cases in `counter_cases.py` are built here from fixed
seeds, and they are MIT like the rest of the repository.

## Running it

```
git clone https://github.com/agentrust-io/trace-tests && git -C trace-tests checkout 109fb54278cca5be649a878e2bfb54311a6bf386
git clone https://github.com/agentrust-io/trace-spec  && git -C trace-spec  checkout a131c6400eaa95007b16b84a96331ccf37a93b73
python -m venv ref && ref/bin/pip install --require-hashes --no-deps -r interop/trace/reference-requirements.txt
python interop/trace/compare.py --trace-tests trace-tests --trace-spec trace-spec \
    --reference-python ref/bin/python --out ../trace-comparison
```

The reference runs in its own interpreter (`reference_driver.py`, started with `python -I`). Its
input path is stated there: the reference has no byte-level API, so the record bytes are parsed
with `json.loads`, as a caller would, and the parsed object is handed on.

## Reading the table

Each row gives the expectation, the reference verdict, the proofbundle verdict, and whether each
pair agrees. The expectation is the full-verification verdict that the cited section requires.
A row says `n/a` where no normative text decides the case, and where the reference has no path
for the input (the compact JWS form). A divergence is reported, never reconciled.
