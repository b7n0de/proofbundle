# Go reader of the CCF receipt profile, written from the text

`main.go` is a CCF receipt reader written in Go by an AI coding agent (OpenAI Codex) from the supplied profile text incorporating pull request 31 at `d04ddffe` (ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile#31). It uses the Go standard library only. Alongside that text, the agent received one test receipt, its Transparent Statement and the service's public certificate. The agent's report records no access to proofbundle's code, the reference reader, or the section 4 vectors in `../section4_vectors` and their generator. The Go build and the runs on these fifteen vectors were performed separately afterwards.

`main.go` is byte-identical to the agent output identified in its report. SHA-256 `248b684ab61ff2e45b5655b11a3274a76690626cb8a5f800243d76f59cf67540`.

## Build

```
go build -trimpath -o ccfverify .
```

Go 1.22 or newer. Measured with Go 1.24.7 on linux/amd64.

## Run on the fifteen section 4 vectors

```
python3 run_section4.py ./ccfverify ../section4_vectors
```

`run_section4.py` (Python 3, standard library only) writes, for each `S4-*.json`, the receipt bytes and a COSE_KeySet holding the vector's public key, then calls

```
./ccfverify -consistency receipt.cose -older-root <older_root_hex> -keys keys.cbor
```

For these fifteen vectors, the reader prints one line, `verdict=PASS newer_root=<hex>` or `verdict=FAIL reason=<reason>`. At a resource limit it prints `resource_limit` instead. Its exit status is 0 for all three results. The script prints the table below; the last three columns are the results recorded in each vector. It prints results rather than checking that all fifteen vectors were run or that their results match this table.

## Results, measured on 2026-10-12

| vector | title | Go reader | reading A | reading B size-free | reading B size-aware |
|---|---|---|---|---|---|
| S4-01 | Canonical proof 19 to 24, control | verdict=PASS | accept | passes_size_free_checks B1 to B13 hold | accept B1 to B14 hold |
| S4-02 | Canonical proof 22 to 24, control | verdict=PASS | accept | passes_size_free_checks B1 to B13 hold | accept B1 to B14 hold |
| S4-03 | A second proof with one anchor bit flipped | verdict=FAIL reason=root_mismatch | accept | reject B8 | reject B8 |
| S4-04 | Two valid proofs to the same newer root, control for multiple proofs | verdict=PASS | accept | passes_size_free_checks B1 to B13 hold | accept B1 to B14 hold |
| S4-05 | A second proof whose older and newer roots are both other roots | verdict=FAIL reason=root_mismatch | accept | reject B8 | reject B8 |
| S4-06 | Mixed: a valid consistency proof and an inclusion proof to another root | verdict=FAIL reason=root_mismatch | accept | reject B9 | reject B9 |
| S4-07 | Mixed: a valid consistency proof and a valid inclusion proof to the same root, control | verdict=PASS | accept | passes_size_free_checks B1 to B13 hold | accept B1 to B14 hold |
| S4-08 | Unchanged tree: m = n, left siblings only | verdict=PASS | accept | reject B10 | reject B10 |
| S4-09 | Deeper anchor: the first sibling is a left one | verdict=PASS | accept | reject B11 | reject B11 |
| S4-10 | Tiago Pinto's N1 = HASH(R_6 \|\| HASH(d[6])), signed as the root of 7 leaves | verdict=PASS | accept | passes_size_free_checks B1 to B13 hold | reject B14 |
| S4-11 | Empty consistency-proof array | verdict=FAIL reason=proof | reject | reject B4 | reject B4 |
| S4-12 | A vdp key other than -1 and -2 | verdict=FAIL reason=proof | accept | reject B3 | reject B3 |
| S4-13 | One tag flipped, negative control | verdict=FAIL reason=older_root_mismatch | reject | reject B11 | reject B11 |
| S4-14 | One signature byte flipped, negative control | verdict=FAIL reason=signature | reject | reject B13 | reject B13 |
| S4-15 | The older root matches no proof | verdict=FAIL reason=older_root_mismatch | reject | reject B12 | reject B12 |

The reader agrees with reading A on 11 of 15 vectors and with reading B, size-free, on 13 of 15. It rejects S4-03, S4-05 and S4-06 because it requires every proof in the receipt to give the same newer root, and S4-12 because it treats the `vdp` map as closed. It accepts S4-08 and S4-09.

## What the reader checks for a consistency receipt

`consistencyRoots` (lines 254 to 260 of `main.go`) folds a left sibling into both the older and the newer root and a right sibling into the newer root only. `verify` (lines 376 to 400) accepts when the older root of at least one consistency proof equals `-older-root`, every proof gives the same newer root, and the receipt's signature verifies over that root. It checks neither 0 < m < n nor the position of the anchor, and it does not require a right sibling in the path. That is why S4-08, whose path has left siblings only (m = n), and S4-09, whose anchor sits deeper, pass. A PASS from this reader is therefore not a result of conformance with section 4.

## Licence

Original code in this folder is provided under the repository's MIT licence.

Created with AI assistance. Reviewed and published by me.
