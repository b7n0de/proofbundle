# proofbundle's in-toto export, read by foreign tools

The in-toto export of 6.1.0 was handed to five foreign readers: the in-toto attestation bindings for Go
and Python, two DSSE verifiers, cosign and GUAC. Every signature of the export verified under a
foreign DSSE verifier that accepts an envelope without keyid. No foreign reader took the export as it
is written: the top-level `contentRootAlg` field stops cosign and the strict parse of both bindings,
the missing DSSE keyid stops securesystemslib and GUAC, and GUAC has no parser for any of the three
predicate types. Every finding below is a finding about what a tool does with the bytes, measured,
not an error of the tool or of the export; which side the in-toto specification backs is said per
finding.

## SOURCES

- in-toto attestation framework: https://github.com/in-toto/attestation, tag `v1.2.0`, commit `df02077bf97218a8860a5c534eff1f1381f56984`, retrieved 2026-09-26
- the rules cited below are from that commit: `spec/v1/README.md` (Parsing rules) and `spec/v1/envelope.md`
- in-toto attestation Go binding: module `github.com/in-toto/attestation` `v1.2.0`, the same commit, `go.sum` `h1:aPRUZ3azbqD7yEBD5fP3TD8Dszf+YHo284SOcpahjQk=`
- DSSE, Go: module `github.com/secure-systems-lab/go-securesystemslib` `v0.11.1`, commit `662f0f738ddc65cf9543c3e90114bd6d95a7e361`, `go.sum` `h1:ayahDPjfSIqKegyt5YVGEvQ7SAi72GHXTy+b2YjUd5w=`
- the Go probe is built with go1.25.0 and `google.golang.org/protobuf` `v1.36.11`
- in-toto attestation Python binding: https://pypi.org/project/in-toto-attestation/0.9.3/, wheel sha256 `1f44d3f3bded1ed551e260c5e9f834ee05de03f1d2f360bada5a172c11d748ff`, retrieved 2026-09-26
- commit NOT MEASURABLE: PyPI carries none and the repository has no tag for the Python version 0.9.3
- DSSE, Python: https://pypi.org/project/securesystemslib/1.5.1/ with the `crypto` extra, tag `v1.5.1`, commit `15064ca640222edba024af9f13191fa5dbad3825`, with protobuf 7.36.2 and cryptography 50.0.1, retrieved 2026-09-26
- cosign: https://github.com/sigstore/cosign/releases/tag/v3.1.3, `cosign-linux-amd64`, commit `11926fa5bbbbde47e88fc006b625a17769b743b2`
- cosign binary sha256 `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`, equal to the release's `cosign_checksums.txt`, retrieved 2026-09-26
- GUAC: https://github.com/guacsec/guac/releases/tag/v1.1.0, commit `a399a54801bfbffc36bc8748dd97d2d2b3bea378`, retrieved 2026-09-26
- `guacone-linux-amd64` sha256 `fb929dfb5a96dc3e5d8c6af52806f565c465662e5de3af42926b886bac1675d2`
- `guacgql-linux-amd64` sha256 `afd3231a3fa65933385a7f03caeee11e83120bee095ba23a06e6635242fed534`
- both equal to the release's `guac_checksums.txt`
- registry and image, helpers only: `crane` and `registry` of `github.com/google/go-containerregistry` `v0.22.1`, `go install`, retrieved 2026-09-26
- source lines cited for cosign and GUAC are from the tagged commits above

## WHAT WAS MEASURED

- one eval receipt, exported by proofbundle at the commit this directory was committed on
- eval-result/v0.1 by `proofbundle intoto`, once per subject profile: receipt, public-model, release-gate
- test-result/v0.1 by `intoto.export_intoto_dsse`, the only way it is exported
- svr/v0.1 by `intoto.export_svr_dsse`, the function behind `proofbundle svr`, with a fixed `timeCreated`
- test-result and svr take no subject profile; their subject is always the receipt binder
- so four cells of the three-by-three matrix do not exist, and they are not built by hand
- six controls, made by the same export functions and never counted as the export:
- the five cells in the export's legacy content-root mode, which signs the same statement without `contentRootAlg`
- the eval-result receipt cell with a DSSE keyid, in the form go-securesystemslib derives (the key's OpenSSH SHA256 fingerprint)
- one GUAC control, built by `run.py`: a SLSA provenance v1 statement over the test image under the same key and keyid

## RESULTS

Measured 2026-09-26 by `run.py`. "yes" means the tool accepted, "no" means it refused; the cause is
the finding named in brackets. `results/results.json` holds every tool's own last line.

| cell | Go DSSE | Go Statement, strict | Go Statement, lenient + Validate | Python DSSE | Python Statement, strict | Python Statement, lenient + validate | cosign verify-attestation | cosign verify-blob-attestation | GUAC |
|---|---|---|---|---|---|---|---|---|---|
| eval-result, receipt | yes | no [F1] | yes | no [F3] | no [F1] | yes | no [F1] | no [F1] | not ingested [F3] |
| eval-result, public-model | yes | no [F1] | yes | no [F3] | no [F1] | yes | no [F1] | no [F1] | not ingested [F3] |
| eval-result, release-gate | yes | no [F1] | yes | no [F3] | no [F1] | yes | no [F1] | no [F1] | not ingested [F3] |
| test-result, receipt | yes | no [F1] | yes | no [F3] | no [F1] | yes | not attached [F2] | no [F2] | not ingested [F3] |
| svr, receipt | yes | no [F1] | yes | no [F3] | no [F1] | yes | no [F1] | no [F1] | not ingested [F3] |
| test-result and svr, public-model and release-gate | not applicable | | | | | | | | |
| control: legacy eval-result, receipt | yes | yes | yes | no [F3] | yes | yes | no, subject is not the image [F5] | yes | not ingested [F3] |
| control: legacy eval-result, public-model | yes | yes | yes | no [F3] | yes | yes | no, subject is not the image [F5] | yes | not ingested [F3] |
| control: legacy eval-result, release-gate | yes | yes | yes | no [F3] | yes | yes | yes | yes | not ingested [F3] |
| control: legacy test-result, receipt | yes | yes | yes | no [F3] | yes | yes | not attached [F2] | no [F2] | not ingested [F3] |
| control: legacy svr, receipt | yes | yes | yes | no [F3] | yes | yes | no, subject is not the image [F5] | yes | not ingested [F3] |
| control: keyid, eval-result, receipt | yes | no [F1] | yes | yes | no [F1] | yes | no [F1] | no [F1] | signature verified, not ingested [F4] |
| GUAC control: SLSA provenance v1 | | | | | | | | | ingested: 1 HasSLSA, 2 artifacts, 2 IsOccurrence |

## FINDINGS

F1, the top-level `contentRootAlg`.
- measured: every export carries it; the in-toto Statement protobuf has no such field
- `protojson.Unmarshal` (Go) and `json_format.Parse` (Python), called with their defaults, refuse the statement
- with DiscardUnknown (Go) or ignore_unknown_fields (Python) both parse it and `Validate` passes
- cosign 3.1.3 parses with the strict default (`pkg/cosign/attestation/attestation.go`, `Statement.UnmarshalJSON`)
- its fallback accepts only a predicate that is a string, so it says `could not parse predicate with type map[string]interface {}`
- the legacy controls, the same statements without the field, pass both strict parses and both cosign commands where the subject matches
- judgement: the in-toto rules are on the export's side
- `spec/v1/README.md`: "Consumers MUST ignore unrecognized fields", and "Producers MAY add extension fields to any JSON object"
- the tools refuse a conforming statement, and every cosign user is one of those tools

F2, the test-result payloadType.
- measured: `export_intoto_dsse` signs with `application/vnd.in-toto.test-result+json`
- cosign refuses the envelope when attaching and when verifying a blob: `invalid payloadType ... Expected application/vnd.in-toto+json`
- the legacy control fails the same way, so the cause is the payloadType, not F1
- judgement: `spec/v1/envelope.md` allows it: "MUST be set to `application/vnd.in-toto.<predicate>+json` or to `application/vnd.in-toto+json`"
- cosign takes only the second form

F3, the missing DSSE keyid.
- measured: `proofbundle intoto`, `export_intoto_dsse` and `export_svr_dsse` write no keyid
- securesystemslib 1.5.1: `Envelope.from_dict` raises `KeyError: 'keyid'`
- its own `verify` docstring says that requiring a keyid "is not DSSE spec compliant (Issue #416)"
- GUAC 1.1.0 looks up the verification key by the signature's keyid (`pkg/ingestor/verifier/sigstore_verifier/sigstore_verifier.go`)
- it stops at `failed to find key from key providers`, before it reads the statement
- go-securesystemslib accepts a signature without keyid; the keyid control passes securesystemslib
- judgement: `spec/v1/envelope.md` says "A `keyid` (or equivalent) SHOULD be included for each signing key used"
- on this point the export is below a SHOULD of in-toto; the DSSE protocol itself calls keyid optional

F4, GUAC has no parser for these predicates.
- measured: with the keyid control, GUAC verifies the signature and then stops at `no document parser registered for type: ITE6`
- nothing of the attestation reaches the graph: 0 artifacts, 0 HasSLSA, 0 HasMetadata, 0 CertifyGood, 0 IsOccurrence
- GUAC 1.1.0 classifies every in-toto statement whose predicateType it does not know as ITE6 (`pkg/handler/processor/guesser/type_ite6.go`) and registers no parser for that type
- the SLSA control, under the same key and keyid, is ingested, so the key, the keyid form and the server work
- judgement: none against the export; GUAC ingests the predicate types it models, and these three are not among them

F5, cosign verify-attestation needs the subject to be the image.
- measured: cosign attaches any of these attestations to an image, and then verifies only one whose subject digest is that image's digest
- otherwise `no matching subject digest found`
- of the three subject profiles only release-gate can name an image; receipt and public-model are checked with `verify-blob-attestation` against the subject's own bytes (`receipt_binder.json`, `public_model.txt`)
- judgement: none against the export; it is what release-gate is for

## FILES

| file | what |
|---|---|
| `make_inputs.py` | the receipt, the five exports and the six controls; the test key, salts and SVR time are fixed, so a re-run writes the same bytes |
| `run.py` | the measurement: registry, image, inputs, both probes, cosign, GUAC; writes `results/results.json` |
| `probe_python.py` | the Python probe, run in its own environment with in-toto-attestation and securesystemslib |
| `go/` | the Go probe, `main.go`, `go.mod`, `go.sum` |
| `inputs/` | what `make_inputs.py` wrote in the committed run; `inputs.json` names every file and the subjects |
| `results/results.json` | every row, the tools' last lines, the GUAC graph deltas, the tool versions |

## RUN

```
cd tools/intoto_external/go && go build -o /tmp/z225probe .
python3 -m venv /tmp/z225py && /tmp/z225py/bin/pip install in-toto-attestation==0.9.3 "securesystemslib[crypto]==1.5.1"
# cosign, guacone-linux-amd64, guacgql-linux-amd64 from the releases above, crane and registry by
# go install github.com/google/go-containerregistry/cmd/{crane,registry}@v0.22.1, all in one directory
PYTHONPATH=src python3 tools/intoto_external/run.py --go-probe /tmp/z225probe --py /tmp/z225py/bin/python --bin DIR
```

The run needs the network only to fetch the tools; the measurement itself runs on localhost.

## THE KEY

`inputs/test_key.pub.b64` is an Ed25519 test key; its seed is the SHA-256 of a label printed in
`make_inputs.py`. It signs test inputs and nothing else, and nothing trusts it.

## NOT MEASURED

- a second in-toto-attestation Python version, and any cosign or GUAC version but the one named
- cosign with a transparency log or keyless signing: `--insecure-ignore-tlog` was set, since the export has neither
- GUAC with any backend but the in-memory keyvalue store
- GUAC's own processor for DSSE without a verifier key: the file collector always verifies

Measurement, not certification.
