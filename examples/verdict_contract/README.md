# A reviewer reply bound by its exact bytes

A worked example for [tonydzi/verdict-contract#1](https://github.com/tonydzi/verdict-contract/issues/1). One reviewer reply is kept as raw bytes, parsed with `verdict_contract.find_verdict`, and recorded in a signed agent-review receipt that can be checked offline.

## Files

| File | What it is |
|---|---|
| `verdict_contract.py` | The parser, vendored unchanged from tonydzi/verdict-contract at commit `73561ee356fc01d6c976a93fb9110d2df2a2df4e`, sha256 `ff5884d5be7520e08054b484456ce0c38fe4fdf99818fed3925b925bc3309a8f`. MIT, the licence text is in `LICENSE.verdict_contract`. |
| `reply.txt` | The reviewer reply, written for this example. |
| `make_example.py` | The producer side. It hashes the reply bytes, runs `find_verdict`, writes `out/verdict.json` and a signed receipt that binds it. |
| `check_example.py` | The offline check of `out/`. |
| `toy_repo.py` | Rebuilds the toy pull request the receipt points at, byte for byte. |
| `measure_cases.py` | Runs the byte-binding cases: LF against CRLF, a blank line and spaces at the end, a sentinel in a fence, two sentinels, a quoted REQUEST_CHANGES. |
| `out/` | The receipt, its public key, the record, the reply and the pull request body, as produced. |

## Check it offline

```
pip install proofbundle
cd examples/verdict_contract
python check_example.py out
```

The files in `out/` were produced and checked with proofbundle 6.2.1. The check exits 0 only when the receipt verifies against the pinned public key and against the pull request context the checker computes itself, `verdict.json` is the record the receipt binds, `reply.txt` and `verdict_contract.py` are the bytes the record names, and `find_verdict` on the reply gives the recorded verdict. The verdict is printed and is not the exit status.

## Byte binding

The reply is hashed before anything decodes it, and `find_verdict` runs on the strict UTF-8 decoding of the same bytes with no newline translation. A reply normalized before hashing, for example CRLF turned into LF or trailing spaces and blank lines stripped, does not match its own receipt.

## What the receipt does not show

The receipt is a self-declaration. It does not show that a review ran in CI, that the reply was produced from that diff, or that the review was right. The pull request is a toy one, its identifiers are example values, and the receipt is signed with an example key whose private half is not in this repository.

`make_example.py --key <path>` reads the key at that path when it exists and otherwise generates a fresh one there, so a rerun signs with a new key. `check_example.py` needs only the public key in `out/`. `measure_cases.py` writes `cases/` and the checker rebuilds `out/toyrepo/`; git ignores both.

This directory is not part of the sdist, see `MANIFEST.in`.
