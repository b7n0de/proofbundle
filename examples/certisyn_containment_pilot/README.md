# Certisyn containment pilot, checked with proofbundle

`pack/` is the containment pilot pack of Certisyn-Inc/certisyn-drafts, pull request 12, commit
`8c01cd7a543d9e7359238958355d491f7923cf58`, directory `interop/containment-pilot/`, copied byte for byte. Its
`FORMAT.md` specifies the record, the seal and the verification procedure. proofbundle reads the format with
`proofbundle.containment`, which runs the seven steps of section 6 of `FORMAT.md` in their order.

## Run

From a checkout of this branch, with Python 3.10 or later and proofbundle's two dependencies (`cryptography`,
`rfc8785`):

    PYTHONPATH=src python examples/certisyn_containment_pilot/verify_all.py

The script needs no network. It prints `expected_output.txt` byte for byte and exits 0;
`tests/test_certisyn_containment_reader.py` compares the two. Measured on Linux with CPython 3.10, 3.12 and 3.14.

## What it does

1. It checks every line of `pack/MANIFEST.sha256`.
2. It reads the trusted key from `pack/KEY.json` with `load_trusted_key` and stops unless its SHA-256 is the one
   pinned in the script, the key agreed before the pilot. The key printed inside a seal is never used.
3. It submits each of the thirteen vectors as `pack/run-all.mjs` submits them: the record and the seal of the vector,
   or of its `record` field, with the input file of its `input` field or of its own id where `pack/inputs/` has one.
4. For each vector it prints the outcome and every failed step with its reason, then the outcome against
   `pack/expected.json`.

## Limits

- Integrity only, as `FORMAT.md` section 7 says: an accepted pair is the record that the holder of the pinned key
  sealed. Whether its result is right is a separate question.
- `pack/README.md` withdraws an earlier sealed record by a note. The format carries no withdrawal, so a reader cannot
  see one; that record is not in `pack/` and is not run here.
- `pack/verify.mjs` and `pack/run-all.mjs` are kept unchanged and are not run by proofbundle.

## License

`pack/` is Apache-2.0, as its `README.md` states; the license text is `LICENSE.author`, the provenance is in `NOTICE`
and `PROVENANCE.json`. The files beside `pack/` are proofbundle's, under its MIT license.
