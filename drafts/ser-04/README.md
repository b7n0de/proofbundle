# SER -04: a verifier written from the text, and its result on each vector

This folder holds draft-gruszka-signed-evaluation-receipts-04 as filed, the vector file its Appendix A.3 names, and a
verifier written from the text of the draft alone. It also holds that verifier's result on each of the 66 vectors,
with the first failing step, and a challenge set for a second implementation.

## What is here

| Path | What it is | SHA-256 |
| --- | --- | --- |
| `draft-gruszka-signed-evaluation-receipts-04.xml` | the draft as filed at ietf.org, 152816 bytes | `f2a7e569af4456d296f44f1f79d27f80d5a3b572e41831f923816fdfcda0081b` |
| `draft-gruszka-signed-evaluation-receipts-04.txt` | its text form, 109277 bytes | `d60c3dd95aefb8019a5f1c0ce041d8c4eb1d4571302766944bfbc92b91c1e358` |
| `test-vectors.json` | the file of Appendix A.3, 232309 bytes, as published at `https://signed-evidence.org/eval-receipt/v1/test-vectors.json` | `710cb8abab7ca51cf61b85c5610018f9a153add4c3db4f71b2d597e57b1671d1` |
| `verifier-from-text/` | the verifier written from the text, and its run script | per file below |
| `results/` | the recorded run: `ser_lauf.json`, `ser_lauf.txt`, and `results.md` with one row per vector | |
| `author-checker/ser_verify.py` | the checker the drafting session wrote with the -04 text | `7550f262b1330d2407efde3052b6e20aca10f014eda01c31925e34f6431291e4` |
| `challenge-set/` | a fresh challenge set for a second implementation, see its README | |

The verifier, file by file:

| File | SHA-256 |
| --- | --- |
| `verifier-from-text/ser04/pruefer_ser.py` | `3e6b49be8802c7bbb5f171ae24dcf55e9b76a6e9e026f6eb25bb0309e34f3fdd` |
| `verifier-from-text/ser04/lauf_ser.py` | `de3089339b3e1cfff00b2a6341bf629058a98f099c116a9039ac1e4e151716f0` |
| `verifier-from-text/gemeinsam/b64.py` | `006417a93b3405ee8e5dabe4afeed1e7e62ad098a28769ed9e7795412d2ef4b7` |
| `verifier-from-text/gemeinsam/ed25519.py` | `52fa04f01fa2fcf26f84ce072a851b381520b47cfb62ac43aa020ce9b666276b` |
| `verifier-from-text/gemeinsam/ijson.py` | `dfc2c5dc79335863790c4b5f2129b56bb077d11d726b042a29ba7bdf57e7955e` |
| `verifier-from-text/gemeinsam/jcs.py` | `5414fd3961ed91d3be731286ec33bc8001e76f220afb59dac4b974ad7c235e78` |
| `verifier-from-text/gemeinsam/txt.py` | `751e976a2e7791cdf8dca3132d9e47ae0f51d17fb6ce064bdff939fce268852b` |
| `verifier-from-text/ser04/__init__.py`, `verifier-from-text/gemeinsam/__init__.py` | empty files |

The verifier files and `author-checker/ser_verify.py` are kept byte for byte as they were delivered, so that each
SHA-256 above names the code that ran. For that reason `verifier-from-text/ruff.toml` waives two lint rules for
`lauf_ser.py` (E402, E731) and `author-checker/ruff.toml` waives one for `ser_verify.py` (E702). Every other file is
linted as in the rest of the repository.

## The verifier is written from the draft alone

`verifier-from-text/ser04/pruefer_ser.py` implements the eleven steps of Section 5, with the verification profile, from
the -04 text. It uses the Python standard library and the modules in `verifier-from-text/gemeinsam/`. It contains no
proofbundle code and imports nothing from proofbundle.

The run script `lauf_ser.py` reads the keys from Appendix A.1 of the text. It checks the vector file against the size
and SHA-256 of Appendix A.3 and the ten vectors of Appendix A.2 against the file. It then runs every vector and writes
`ser_lauf.json` and `ser_lauf.txt`. For ten profile vectors it also records what an installed pyca/cryptography says
about the signature. That entry is a diagnostic: it depends on the installed version, and it is not part of the result.

To run it, from this folder, with Python 3:

```
python3 -I -B verifier-from-text/ser04/lauf_ser.py . <output folder>
```

`tests/test_ser04_verifier_from_text.py` runs this call in CI. It holds each of the 66 results to the result and first
failing step in the vector file. It renders `results/results.md` again from a fresh run and compares. Its first case,
the control, changes one byte of the signature of P1, which the file expects to pass, and requires the comparison to
name P1. A comparison that cannot fail would measure nothing.

## What the result shows

For each of the 66 vectors, the verifier gives the result and first failing step that the vector file states: 10 PASS
and 56 FAIL. The file has the size and SHA-256 of Appendix A.3 and parses strictly as one JSON text. Its vectors stand
in the order of Table 2, and the ten vectors of Appendix A.2 match their entries in the file. The keys of Appendix A.1
agree with their seeds, and the mixed-order key is the issuer key plus the point of order 8 the text gives.

The run reports one structure note. The item of N24 for the payload bytes reads "payload bytes B: none, payload_b64
does not decode" and gives no size or SHA-256, which the run script's structure check expects of every item. N24 is the
vector whose payload_b64 does not decode, so it has no payload bytes to describe.

## What the result does not show

It does not show that the text is unambiguous. The verifier and the vector file can share a reading of the text that
another reader would not take.

It is not an independent implementation. The verifier is a second implementation by us, the authors of the draft,
written in a separate session from the -04 text. The checker in `author-checker/` is ours as well. Agreement between
them is agreement inside one project.

It says nothing about receipts outside the 66 vectors. The vectors and their expected results are public, so a
verifier can reach 66 of 66 without implementing the text.

It does not fix resource limits. Section 8 defines no universal limit and asks implementations for documented ones;
the nesting limit of 200 in `verifier-from-text/gemeinsam/ijson.py` is the verifier's own choice.

## An independent implementation

We look for one through https://proofbundle.dev/verifier-2/. It is written by someone outside this project, from the
published text alone. A submission then answers a fresh challenge set from `challenge-set/` that has never been
published, and the comparison reads its answers without running its code.
