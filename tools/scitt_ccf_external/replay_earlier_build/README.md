# Replay of nine vectors on an earlier CCF build

Rounds 1 to 3 registered their vectors on scitt-ccf-ledger `00101f76` with CCF 7.0.17. This package replays nine of
them on an earlier build, to see whether CCF's change of its CBOR implementation in 7.0.15 moves any outcome or any
data-hash. Everything a run needs is here, and the expected outcome of each vector is fixed in `predictions.json`,
committed in its own commit before any registration. Nothing here was registered yet.

| file | |
|---|---|
| `vectors.json`, `vectors/<name>/request.hex` | the nine request bodies, byte for byte as stored, with digest and origin |
| `build_choice.json` | the earlier build, why, its pins, the fallback, the 7.0.15 changelog entries, the expected configuration deltas |
| `predictions.json` | per vector: registered or refused, the refusal stage and text, the expected data-hash after C(n) |
| `replay_run.py` | registers the nine on a running ledger with round 3's `register` and writes one row per vector |
| `oracle.py` | the independent oracle: C(n) from the request bytes, the receipt's data-hash and signature, the returned statement minus 394 |

## THE NINE VECTORS

The eight-vector core and the ES256 statement with a protected x5chain from PR 299 as a positive control:

| name | origin | bytes |
|---|---|---|
| `r3-control` | `differential_corpus_round3/vectors/control` | 1150 |
| `r3-r-a10-cwt-claims-unprotected` | `differential_corpus_round3/vectors/r-a10-cwt-claims-unprotected` | 1173 |
| `r3-m-u15` | `differential_corpus_round3/vectors/m-u15` | 1150 |
| `r2-g03-alg-1-byte-argument` | `differential_corpus_round2/vectors/g03-alg-1-byte-argument` | 1151 |
| `r3-x-pa-ub-sig-a` | `differential_corpus_round3/vectors/x-pa-ub-sig-a` | 2023 |
| `r3-x-pa-ub-sig-b` | `differential_corpus_round3/vectors/x-pa-ub-sig-b` | 2023 |
| `r3-x-pb-ua-sig-a` | `differential_corpus_round3/vectors/x-pb-ua-sig-a` | 2023 |
| `r3-x-pb-ua-sig-b` | `differential_corpus_round3/vectors/x-pb-ua-sig-b` | 2023 |
| `pr299-es256-protected-x5chain` | `producer_crosscheck.json` at `60ad9595`, `/statements/es256/statement_hex` | 1149 |

The corpus files are frozen at `c5ff0a72` (`../CORPUS_FREEZE_rounds_1_to_3.sha256`). The signer certificates of
rounds 2 and 3 have expired since; the ledger resolves the did:x509 issuer with `true /* Do not validate time */` in
both commits named below, so that does not change an outcome.

## THE BUILD

`build_choice.json` holds the reasons. In short: no scitt-ccf-ledger commit pins CCF 7.0.14, so the build takes
`5a973bb3`, the last ledger commit before CCF's API breaks of 7.0.15 and 7.0.16, whose registration code equals
`00101f76`'s, and sets CCF 7.0.14 as a build argument.

    git clone https://github.com/microsoft/scitt-ccf-ledger && cd scitt-ccf-ledger
    git checkout 5a973bb3af8a0c506923c501d4e2aeb508867105
    docker build -f docker/Dockerfile \
        --build-arg CCF_VERSION=7.0.14 \
        --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
        --build-arg SCITT_VERSION_OVERRIDE=5a973bb \
        -t scitt:replay-5a973bb3-ccf-7.0.14 .
    docker image inspect --format '{{.Id}}' scitt:replay-5a973bb3-ccf-7.0.14
    docker run --rm --entrypoint cat scitt:replay-5a973bb3-ccf-7.0.14 /opt/scitt/share/build-inputs.json

The build inputs must name `reproduce.json` SHA-256 `1022713e535bae1fe24f8c0a89acbcb538f57dc1e5dd8e08fccb90cd171057c4`,
the RPM SHA-256 `5939a48f33de90d26e35aa2197cd50539c05b3a7dcd949a9f8aac2395d36bc10` and the tdnf snapshot
`1788790797`. If the sandbox needs its proxy CA trusted in the base stage, as in rounds 1 to 3, record the patch and
its SHA-256. If the build fails, record the reason and build the fallback, the same commit with its own CCF 7.0.10
(no `CCF_VERSION` argument), and record that the fallback ran.

## START

One node, virtual mode, as in rounds 1 to 3:

    DOCKER_TAG=scitt:replay-5a973bb3-ccf-7.0.14 ./docker/run-dev.sh
    scitt governance local_development ...      # as in rounds 1 to 3, the repository's own command

Then apply the configuration of `build_choice.json` (`configuration.target`): unauthenticated registration allowed,
the policy "any statement with a CWT issuer". `replay_run.py` reads `/configuration` back and records its digest;
round 3's was `6593529c...`, whether the replay's equals it is measured, not assumed.

## REGISTER AND RECORD

From `tools/scitt_ccf_external/replay_earlier_build/`, with the repository's `src` on the path (round 3's `register`
uses the corpus readers):

    git log --diff-filter=A --format='%H %cI' -- predictions.json   # the predictions' commit, older than the run
    PYTHONPATH=../../../src python3 replay_run.py --url https://127.0.0.1:8000 --service-cert CERT \
        --service-commit 5a973bb3af8a0c506923c501d4e2aeb508867105 --image-id IMAGE_ID \
        --label ccf-7.0.14

It refuses to register without `predictions.json`. Per vector it writes `runs/<label>/<name>/` with `request.hex`,
`receipt.hex` and `statement.hex` where the service returned them, and `row.json`; `runs/<label>/rows.json` holds all
nine. The columns of a row:

| column | |
|---|---|
| `request_sha256` | SHA-256 of the exact request body |
| `service_commit`, `image_id` | the ledger commit and the image digest |
| `ccf_version` | from `/node/version` |
| `configuration_sha256` | SHA-256 of `/configuration` as served |
| `predicted` | from `predictions.json` |
| `measured_outcome` | registered, refused, timeout, unfinished or receipt_unverified |
| `refusal_stage`, `raw_service_error`, `api_status` | for a refusal: where it ended and the service's raw error |
| `returned_statement_sha256` | SHA-256 of the statement the service returned |
| `receipt_data_hash` | the receipt's data-hash, where a receipt exists |
| `rebuilt_cn_sha256` | SHA-256 of C(n), rebuilt by the oracle from the request alone |
| `data_hash_match`, `receipt_signature_valid`, `rebuilt_equals_returned_minus_394` | the oracle's comparisons |

A refused row has no receipt: its data-hash fields stay null, never a commitment result.

## THE ORACLE ON ITS OWN

    python3 oracle.py --request runs/LABEL/NAME/request.hex --receipt runs/LABEL/NAME/receipt.hex \
        --returned runs/LABEL/NAME/statement.hex --keyset runs/LABEL/scitt-keys.hex

It needs Python's standard library and `cryptography`, and nothing from proofbundle. It gives no verdict on the
statement's or the receipt's shape. `tests/test_scitt_ccf_replay_oracle.py` runs it over the 62 accepted rows of
rounds 1 to 3, where it rebuilds every data-hash.

## DRIFT CONTROL

If it costs little, register the nine in the same session on the original build, `00101f76` with CCF 7.0.17 (its own
Dockerfile, no build argument), with `--label ccf-7.0.17-control`, and say whether it ran.

## LIMITS

One node, virtual mode, no TEE, one earlier build. A difference between the runs points to CCF between 7.0.14 and
7.0.17, because the ledger's registration code is the same; it does not say which change caused it.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
