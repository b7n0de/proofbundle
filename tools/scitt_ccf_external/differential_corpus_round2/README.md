# Differential corpus, second round: four classes on a local scitt-ccf-ledger

Twenty-nine statements were registered on a local scitt-ccf-ledger in virtual mode: a control, four
classes against it, and the control's bytes again in two later phases. The service accepted 19 and
refused 10. The data-hash preimage identified in the first round holds for all 19 accepted vectors.
That preimage is tag 18, a definite four-element array, the element contents with preferred heads,
and an empty unprotected map. It holds even where the protected header is not core deterministic,
because the service keeps the protected header byte for byte.

## PINS

Every `vectors/<id>/record.json` pins the service and verifier at the moment that vector was
registered.
- service: https://github.com/microsoft/scitt-ccf-ledger
- service commit: `00101f769d872711356e080fbb089ac48589c60a`
- image id: `sha256:1bdd60edc1b8cfc1fb02ed516b5a5ea60d75a3ca4b5d59f128e3c61e23680380`, the image of the first round
- CCF: `ccf-7.0.17` (`/node/version`)
- mode: virtual, one node, attestation format `Insecure_Virtual`
- configuration (`/configuration`), per phase:
  - initial: the first round's policy
  - after the change: a policy that also refuses the issuer `did:example:blocked`
- verifier: https://github.com/b7n0de/proofbundle at `43a89623f371902f78e29e9290181841566f34c2`, tree clean
  apart from this run's own output directory (`tree_clean_excludes`)
- the verifier pin's `tool` field names `differential_corpus.py`: this run reuses that file's pin
  function. The tool that ran is `differential_corpus_round2.py`, at the pinned commit.
- libraries: CPython 3.11.15, cbor2 6.1.4, cryptography 50.0.1
- measured: 2026-09-26

## THE CLASSES

Each vector carries a valid signature. A vector whose protected header changes is signed again over
its own protected bytes. A vector that changes only the unprotected map keeps the control's signature.

| class | what changes against the control | vectors | accepted | refused |
|---|---|---|---|---|
| g | semantically equivalent protected-header encodings and orderings | 9 | 8 | 1 |
| h | duplicate map keys, and labels in both buckets, equal and conflicting | 9 | 5 | 4 |
| i | crit: parameters the service knows, against unknown ones | 8 | 3 | 5 |
| j | none: the control's bytes again, after a configuration change and after a restart | 2 | 2 | 0 |

## EVERY VECTOR

| id | mutation | service | data-hash | v1 reader, submitted / returned |
|---|---|---|---|---|
| g01-keys-descending | the protected labels in descending order; signed again | accepted | other than the control | read / confirmed |
| g02-cwt-claims-keys-reversed | the CWT claims map (15) with its keys 2 before 1; signed again | accepted | other than the control | read / confirmed |
| g03-alg-1-byte-argument | alg -7 as 38 06, a 1-byte argument; signed again | accepted | other than the control | malformed / malformed |
| g04-alg-2-byte-argument | alg -7 as 39 00 06, a 2-byte argument; signed again | accepted | other than the control | malformed / malformed |
| g05-label-1-byte-argument | the label 1 as 18 01, a 1-byte argument; signed again | accepted | other than the control | malformed / malformed |
| g06-map-count-1-byte-argument | the protected map head b8 05, a 1-byte count; signed again | accepted | other than the control | malformed / malformed |
| g07-text-2-byte-length | the content type text of 259 with a 2-byte length argument; signed again | accepted | other than the control | malformed / malformed |
| g08-x5chain-array-1-byte-count | the x5chain array head 98 02, a 1-byte count; signed again | accepted | other than the control | malformed / malformed |
| g09-map-indefinite | the protected map with an indefinite length (bf ... ff); signed again | refused | no receipt | malformed / n/a |
| h01-protected-duplicate-alg-equal | alg (1) twice in the protected map, -7 both times, the two entries adjacent; signed again | refused | no receipt | malformed / n/a |
| h02-protected-duplicate-alg-conflicting | alg (1) twice in the protected map, -7 then -35, the two entries adjacent; signed again | refused | no receipt | malformed / n/a |
| h03-unprotected-duplicate-equal | label 99 twice in the unprotected map, equal; the control's signature | refused | no receipt | malformed / n/a |
| h04-unprotected-duplicate-conflicting | label 99 twice in the unprotected map, conflicting; the control's signature | refused | no receipt | malformed / n/a |
| h05-alg-both-buckets-equal | alg (1) also in the unprotected bucket, equal; the control's signature | accepted | same as the control | malformed / confirmed |
| h06-alg-both-buckets-conflicting | alg (1) also in the unprotected bucket, -35; the control's signature | accepted | same as the control | malformed / confirmed |
| h07-payload-hash-alg-both-buckets-conflicting | the payload hash algorithm (258) also in the unprotected bucket, -43; the control's signature | accepted | same as the control | malformed / confirmed |
| h08-cwt-claims-both-buckets-equal | CWT claims (15) also in the unprotected bucket, equal; the control's signature | accepted | same as the control | malformed / confirmed |
| h09-x5chain-both-buckets-conflicting | x5chain (33) also in the unprotected bucket, the end-entity certificate alone; the control's signature | accepted | same as the control | malformed / confirmed |
| i01-crit-x5chain | crit [33], x5chain; signed again | accepted | other than the control | read / outside_profile |
| i02-crit-cwt-claims | crit [15], CWT claims; signed again | accepted | other than the control | read / outside_profile |
| i03-crit-cwt-claims-and-x5chain | crit [15, 33]; signed again | accepted | other than the control | read / outside_profile |
| i04-crit-unknown-int-present | crit [99], label 99 present; signed again | refused | no receipt | read / n/a |
| i05-crit-unknown-int-absent | crit [99], label 99 absent; signed again | refused | no receipt | read / n/a |
| i06-crit-unknown-text-present | crit ["x"], label "x" present; signed again | refused | no receipt | read / n/a |
| i07-crit-registered-not-listed | crit [259], a registered label the service does not list; signed again | refused | no receipt | read / n/a |
| i08-crit-empty | crit [], an empty array; signed again | refused | no receipt | read / n/a |
| j01-after-configuration-change | the control's bytes registered again, after-configuration-change: the policy script replaced through a governance proposal by one that also refuses the issuer did:example:blocked | accepted | same as the control | read / confirmed |
| j02-after-restart | the control's bytes registered again, after-restart: the node stopped; a plain restart of the node refused (PID file my_node.pid already exists, exit 103); the service recovered from its ledger in a new node (command Recover, transition_service_to_open, one recovery share), with a new service identity | accepted | same as the control | read / confirmed |

## WHAT THE MEASUREMENT SHOWS

- g: the service accepted 8 of 9 and returned each protected header byte for byte.
- g: none of those 8 protected headers is core deterministic, and for each of them the preimage
  rule over the returned elements holds. The hashed bytes therefore contain the protected header as
  sent, not a normalized form of it.
- g: all 8 also have a data-hash other than the control's. Their signatures differ too, so that
  alone decides nothing.
- g: the indefinite-length protected map (g09) was refused.
- h, two buckets: all five accepted vectors, equal or conflicting, have the control's data-hash.
  The unprotected value is dropped before hashing, as in the first round.
- h, duplicates in the protected map: refused with a duplicate-label error.
- h, duplicates in the unprotected map: refused, and the service names a signature failure. The
  signature and the protected header of both vectors are the control's.
- i: crit naming x5chain (33), CWT claims (15) or both was accepted. Every other crit was refused
  with the messages the service source names: scitt-ccf-ledger `app/src/verifier.h`,
  `throw_if_invalid_crit_for_x509`, at the pinned commit. The v1 reader returns `outside_profile`
  for the three accepted ones.
- j: the control's bytes have the control's data-hash after a configuration change and after a
  recovery. Each was measured under a new transaction id, and each receipt verifies under the key
  set the service served in that phase.
- After the recovery, the key set holds two keys, the previous one and the new one.

The preimage table of this round is in `preimage_summary.json`, per vector in
`vectors/<id>/candidate_hashes.json`:

- Candidates 3-tagged and 4-tagged match 19 of 19, and are the same bytes in every one.
- Every other candidate matches fewer.
- The protected header is core deterministic in 11 of the 19.
- The data-hash readers agree in 19 of 19.

## THE PHASES OF CLASS j

- initial: a fresh single-node network on the image, opened with `scitt governance local_development`.
- after-configuration-change: the policy script was replaced through a governance proposal
  (`scitt governance propose_configuration`), accepted by the one member.
- after-restart:
  - The node was stopped. Starting the same node again was refused: cchost exited with code 103,
    "PID file my_node.pid already exists".
  - The service was then recovered from its ledger by a new node: command `Recover`, then the
    proposal `transition_service_to_open` with the previous and the next service identity, then
    one recovery share.
  - `recovery_count` is 1, and the service identity changed.

## ADMISSIBILITY (`admissibility.json`)

The refusals, as this service returned them. A refusal is what this service did with the bytes; it is
not judged SCITT-invalid here. Every one came with HTTP 400 and `InvalidInput`.

| id | service error |
|---|---|
| g09-map-indefinite | `Signature verification failed` |
| h01-protected-duplicate-alg-equal | `Failed to decode protected header: QCBOR_ERR_DUPLICATE_LABEL` |
| h02-protected-duplicate-alg-conflicting | `Failed to decode protected header: QCBOR_ERR_DUPLICATE_LABEL` |
| h03-unprotected-duplicate-equal | `Signature verification failed` |
| h04-unprotected-duplicate-conflicting | `Signature verification failed` |
| i04-crit-unknown-int-present | `x509 signed statement crit value 99 is not allowed` |
| i05-crit-unknown-int-absent | `x509 signed statement crit value 99 is not allowed` |
| i06-crit-unknown-text-present | `x509 signed statement crit values must be integers` |
| i07-crit-registered-not-listed | `x509 signed statement crit value 259 is not allowed` |
| i08-crit-empty | `Cannot have crit array of length 0 in COSE protected header.` |

## STORED FORM AND DERIVED VIEWS

- stored as in the first round:
  - `vectors/<id>/request.hex`, `receipt.hex` and `statement.hex`, as hex text
  - `vectors/<id>/record.json`, which adds the phase
  - `scitt-keys.<phase>.hex`, the key set served in each phase
  - `manifest.json`
- derived by `python3 ../differential_corpus_round2.py derive --write`, checked by `--check` and by
  `tests/test_scitt_ccf_differential_corpus_round2.py`: `summary.json`, `admissibility.json`
- derived by `python3 ../preimage_candidates.py --corpus differential_corpus_round2 --write`:
  `vectors/<id>/candidate_hashes.json`, `preimage_summary.json`

- Stored: 123 text files, 353362 bytes; the largest is `summary.json`, 20427 bytes.

## NOT MEASURED, NOT MEASURABLE

- A software-version boundary is NOT MEASURABLE here. The one service image in this environment is
  the first round's. Building another would need the network, which the agent phase does not have.
- A first run of this round at 22:28Z was discarded, and nothing of it is stored.
  - Reason: its pins recorded the tree as not clean, and the only untracked path was that run's
    own output directory.
  - Its 29 outcomes, accepted or refused, and its service errors were the same as those of this run.
- Only one node, in virtual mode. A production service is NOT MEASURED.
- The service source was read, not run. The crit messages match it; the reason behind the
  signature error on the unprotected duplicates was NOT MEASURED.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
