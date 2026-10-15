# CCF inclusion receipts after pull request 31: a strict reader, probes and vectors

This directory holds a reader of CCF inclusion receipts written to the CCF receipt profile as changed by
ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile pull request 31, the receipts it was measured against, and the
measured results of three readers on them.

## What this is

`reader.py` reads a CCF inclusion receipt and prints one line, `PASS <root hex>` or `FAIL <reason>`. Every CBOR item
it reads, the receipt, its protected header, the `vdp` map and each proof, goes through
`src/proofbundle/_strict_cbor.py`. It follows these requirements of pull request 31, quoted from its head commit
`820c5e4ebbd7d88d815ae7f2f538f40e2ac1767e` (2026-10-14):

> After decoding each `ccf-inclusion-proof` byte string, the Verifier MUST validate that the decoded value is well
> constructed with regard to the schema defined in {{ccf-inclusion-proof-cddl}}, including {{ccf-leaf-cddl}} for the
> leaf, and MUST reject the proof before `compute_root` is called if any check fails. In particular:
>
> * the byte string is valid CBOR ({{Section 5.3.1 of RFC8949}}), in particular the map has no duplicate keys;

> A Verifier MUST reject a receipt whose `vdp` map is not valid CBOR ({{Section 5.3.1 of RFC8949}}) or does not match
> `verifiable-proofs` in {{unprotected-header-map-cddl}}, before applying either verification algorithm.

> `data-hash` is the hash of the bytes of the Signed Statement as registered: the `COSE_Sign1` encoding with CBOR tag
> 18 retained ({{Section 6.1 of -scitt-architecture}}) and an empty unprotected header map ({{Section 6.3 of
> -scitt-architecture}}), other elements as submitted.

The first two passages came in with commits `eb01db3fa913b748186af97d8b7cd41ed444c3f4` and
`f6d4eb0417d970b8f1c9b407eda8304eb48f7697`. Commit `820c5e4e` reworded the first from "check the decoded value
against the CDDL of" to the wording quoted above, which states the check in terms of the schema of the figures.

The profile and RFC 9943 Section 6.3 require the empty unprotected header map in the data-hash preimage and name no
encoding for it. This reader writes it as the one byte `a0`. The seven receipts from microsoft/scitt-ccf-ledger at
`00101f76` match a preimage with `a0`; that was measured on 2026-10-12 and is not repeated here.

A valid CBOR encoding that is not the shortest one, such as a head that is not the shortest or an indefinite length,
is read, because RFC 8949 Section 5.3.1 does not make it invalid. A code point spread between two chunks of an
indefinite text string is refused, because RFC 8949 Section 3.2.3 makes the string invalid.

A label is an integer or a text string (RFC 9052 Section 1.4), and an integer is an integer. In Python, `1.0 == 1` and
`True == 1` with the same hash, so a reader that looks labels up as Python values reads a proof map with the key 1.0
as one with the key 1. This reader refuses a header map, the `vdp` map, a proof map or a key whose labels are other
data items, and an algorithm, a VDS or a key type given as a float. A key set whose point is not on its curve, whose
coordinate is not exactly the byte length of the curve (RFC 9053 Section 7.1.1), or whose kid is not a byte string is
a `FAIL keys` line, not an error. A receipt whose kid is not a byte string (RFC 9052 Section 3.1), in the protected or
in the unprotected header, is `FAIL kid`; a content type that is neither an unsigned integer nor a text string, and an
IV or Partial IV that is not a byte string, is `FAIL header_type` in either header. The unprotected kid is not signed,
so it never selects a key; only its type is checked. A label in both the protected and the unprotected header is `FAIL label_in_both_headers`: RFC 9052 Section 3 says an
application SHOULD verify that no label occurs in both, and this reader does. A signature is r and s, each in exactly
the byte length of the curve (RFC 9053 Section 2.1); a signature of another length, such as one with a zero byte in
front of r and s, is refused.

## What it is not

- It does not claim conformance to the profile, and it is not a COSE library.
- The verdicts below hold for these receipts and these named versions only.
- A `PASS` says that the inclusion proofs of the receipt verify under the named key for the named data hash. It does
  not say that the statement is true or that the ledger is honest.
- It is an inclusion reader. Consistency proofs under the `vdp` label -2 are checked for their form only, against their
  schema in Section 4 of the profile: a closed map of exactly an `anchor` of 32 bytes and a non-empty `path` of
  elements that are each a boolean and a hash of 32 bytes. They are not computed, because that needs an older root the
  verifier already trusts, and a `PASS` says nothing about them.

## The probes, `probes/`

24 receipts. The bytes were generated separately and are taken unchanged. Only the file names are English.
`index.json` carries, per probe:
- the original file name and its sha256, so each file can be checked against the generator's manifest;
- the verdict the generator expected (`expected_by_generator`, where `OPEN` means it left the verdict open);
- the verdict a strict reader is expected to give (`expected_strict`).

The generator itself is not in this tree. All probes share one data hash, `b111c6e1…`, and the test key in
`probes/keys.cbor`.

## The vectors, `vectors/`

42 receipts written by `make_vectors.py`, with the same test key except two that use the P-256 and P-521 test keys in
`vectors/keys_p256_p521.cbor`. The probes repeat a duplicate key with the same
value, so a reader that keeps the first value and one that keeps the last agree there. These vectors make them
disagree, add the cases of `f6d4eb04` and of the empty map, and add one receipt for each requirement that no probe
exercises:

| vectors | what they hold |
|---|---|
| `dup_leaf_first`, `dup_leaf_last`, `dup_path_first`, `dup_path_last` | one proof whose map carries key 1 (`leaf`) or key 2 (`path`) twice, with two different values; the receipt is signed for the reading named in the file (`first` or `last`) |
| `dup_twin` | the same receipt with one leaf and one path, as the control |
| `vdp_empty_consistency`, `vdp_duplicate_key`, `vdp_unknown_key` | a valid inclusion proof next to an empty `consistency-proof` array, a duplicate key in the `vdp` map, and a `vdp` key other than -1 and -2 |
| `vdp_twin` | the control for the three `vdp` cases |
| `empty_map_a0`, `empty_map_b8_00`, `empty_map_bf_ff` | one statement (`statement.cose`) whose unprotected header is not empty, and three receipts whose data hash is the SHA-256 of that statement with the header replaced by `a0`, by `b8 00` or by `bf ff` |
| `label_leaf_float_1_0`, `label_leaf_true`, `label_path_float_2_0`, `label_vdp_float_minus_1_0`, `label_unprotected_float_396_0` | a key that equals an integer label in Python but is another data item (1.0, `true`, 2.0, -1.0, 396.0), in the proof map, the `vdp` map or the unprotected header. Only the unprotected part changes, so the signature stays valid and anyone can write such a receipt without the key |
| `label_protected_alg_true`, `label_protected_vds_float`, `label_protected_alg_value_float` | the same in the protected header (the label of `alg` as `true`, VDS 2 as 2.0, `alg` -35 as -35.0), signed with the test key |
| `evidence_chunks_split_inside_a_code_point`, `evidence_chunks_split_at_code_points` | the evidence as an indefinite text string in two chunks, cut inside the first `ü` and at a code point |
| `evidence_512_two_byte_characters`, `evidence_513_two_byte_characters` | 1024 and 1026 bytes of evidence in 512 and 513 characters, so the bytes are counted and not the characters |
| `evidence_as_byte_string`, `its_33` | the evidence as a byte string, and an `internal-transaction-hash` of 33 bytes |
| `form_tag_17`, `form_five_elements`, `form_unprotected_not_a_map`, `form_protected_not_a_map`, `form_vdp_without_inclusion`, `form_vdp_missing`, `form_proof_not_a_map`, `form_leaf_of_two`, `form_leaf_of_four`, `form_leaf_a_map` | a receipt, a header, a `vdp` map, a proof or a leaf of another form |
| `form_protected_header_over_255_bytes`, `evidence_1_byte` | valid receipts at a length boundary: a protected header whose byte string head takes two bytes, and evidence of one byte |
| `roots_differ_signed_for_the_second` | two inclusion proofs with different roots, signed for the second, so a reader that keeps the last root it computed would verify the signature |
| `signature_padded` | the receipt of `vdp_twin` with a zero byte in front of r and of s |
| `curve_p256_es256`, `curve_p521_es512` | valid receipts under ES256 with P-256 and ES512 with P-521 |

`vectors.json` names, per vector, the data hash, the statement where there is one, the verdict expected from a
strict reader and the whole line it must print (`strict_line`). For the `dup_*` vectors it also names the verdicts of
a first-wins and of a last-wins reader. The expected lines follow from the text of pull request 31 and RFC 9052, not
from a run of this reader.

## What was measured, 2026-10-15

The three readers:
- **This reader:** `reader.py`, CPython 3.10.12, `cryptography` 50.0.2, no cbor2. The 36 receipts of the first run
  and the 30 vectors added later the same day were run again together; the Go reader and the earlier reference gave
  the same results on the 36 as in the first run.
- **The Go reader:** `tools/scitt_ccf_external/section4_reader_go/main.go` at commit `e305458c` (sha256 `248b684a…`).
  It is on the branch `claude/scitt-section4-vectors`, not on main. Built with Go 1.27.2 linux/amd64, called as
  `ccfverify -receipt R -keys K` with `-digest HEX` or `-statement S`.
- **The earlier reference:** the reference implementation of 2026-10-12 named in the pull request comment of that date.
  It is not in this tree; its sha256 is `0fcb793a…`. It decodes with cbor2 and was run once with cbor2 5.9.0 and once
  with 6.1.4, with `cryptography` 50.0.2. Its command line takes a statement file. For the receipts with a fixed data
  hash, its verification function was called with that hash directly.

| receipt | expected, strict | this reader | Go reader `e305458c` | earlier reference, cbor2 5.9.0 | earlier reference, cbor2 6.1.4 |
|---|---|---|---|---|---|
| baseline | PASS | PASS | PASS | PASS | FAIL struct |
| bool_as_1 | FAIL | FAIL path_el | FAIL proof | FAIL path_el | FAIL struct |
| bytes_after_the_proof | FAIL | FAIL cbor_proof: 1 byte(s) after the data item | FAIL cbor | FAIL proof_decode | FAIL struct |
| duplicate_key_2 | FAIL | FAIL cbor_proof: duplicate map key 2 | FAIL proof | PASS | FAIL struct |
| evidence_0 | FAIL | FAIL evidence_len | FAIL proof | FAIL evidence_len | FAIL struct |
| evidence_1024 | PASS | PASS | PASS | PASS | FAIL struct |
| evidence_1025 | FAIL | FAIL evidence_len | FAIL proof | FAIL evidence_len | FAIL struct |
| evidence_invalid_utf8 | FAIL | FAIL cbor_proof: text string is not valid UTF-8 | FAIL cbor | FAIL proof_decode | FAIL struct |
| extra_key_in_proof | FAIL | FAIL proof_keys | FAIL proof | FAIL proof_keys | FAIL struct |
| foreign_kid | FAIL | FAIL key | FAIL key | FAIL key | FAIL struct |
| foreign_label_unprotected | PASS | PASS | PASS | PASS | FAIL struct |
| hash_33 | FAIL | FAIL path_el | FAIL proof | FAIL path_el | FAIL struct |
| path_element_of_three | FAIL | FAIL path_el | FAIL proof | FAIL path_el | FAIL struct |
| path_empty | FAIL | FAIL path | FAIL proof | FAIL path | FAIL struct |
| path_indefinite | PASS | PASS | PASS | PASS | FAIL struct |
| path_length_not_shortest | PASS | PASS | PASS | PASS | FAIL struct |
| payload_instead_of_nil | FAIL | FAIL payload | FAIL header | FAIL payload | FAIL struct |
| plus_empty_consistency_array | FAIL | FAIL vdp_empty | FAIL proof | PASS | FAIL struct |
| tag_around_hash | FAIL | FAIL path_el | FAIL proof | FAIL path_el | FAIL struct |
| two_proofs_different_roots | FAIL | FAIL roots | FAIL root_mismatch | FAIL roots | FAIL struct |
| two_proofs_same_root | PASS | PASS | PASS | PASS | FAIL struct |
| vds_3 | FAIL | FAIL vds | FAIL header | FAIL vds | FAIL struct |
| vds_missing | FAIL | FAIL vds | FAIL header | FAIL vds | FAIL struct |
| without_tag18 | PASS | PASS | PASS | PASS | PASS |
| dup_leaf_first | FAIL | FAIL cbor_proof: duplicate map key 1 | FAIL proof | FAIL signature | FAIL struct |
| dup_leaf_last | FAIL | FAIL cbor_proof: duplicate map key 1 | FAIL proof | PASS | FAIL struct |
| dup_path_first | FAIL | FAIL cbor_proof: duplicate map key 2 | FAIL proof | FAIL signature | FAIL struct |
| dup_path_last | FAIL | FAIL cbor_proof: duplicate map key 2 | FAIL proof | PASS | FAIL struct |
| dup_twin | PASS | PASS | PASS | PASS | FAIL struct |
| empty_map_a0 | PASS | PASS | PASS | PASS | FAIL struct |
| empty_map_b8_00 | FAIL | FAIL digest_mismatch | FAIL digest_mismatch | FAIL digest_mismatch | FAIL struct |
| empty_map_bf_ff | FAIL | FAIL digest_mismatch | FAIL digest_mismatch | FAIL digest_mismatch | FAIL struct |
| vdp_duplicate_key | FAIL | FAIL cbor_receipt: duplicate map key -1 | FAIL proof | PASS | FAIL struct |
| vdp_empty_consistency | FAIL | FAIL vdp_empty | FAIL proof | PASS | FAIL struct |
| vdp_twin | PASS | PASS | PASS | PASS | FAIL struct |
| vdp_unknown_key | FAIL | FAIL vdp_key | FAIL proof | PASS | FAIL struct |
| evidence_512_two_byte_characters | PASS | PASS | PASS | PASS | FAIL struct |
| evidence_513_two_byte_characters | FAIL | FAIL evidence_len | FAIL proof | FAIL evidence_len | FAIL struct |
| evidence_as_byte_string | FAIL | FAIL evidence | FAIL proof | FAIL evidence | FAIL struct |
| evidence_chunks_split_at_code_points | PASS | PASS | PASS | PASS | FAIL struct |
| evidence_chunks_split_inside_a_code_point | FAIL | FAIL cbor_proof: a chunk of an indefinite text string is not valid UTF-8 on its own | FAIL cbor | FAIL proof_decode | FAIL struct |
| form_five_elements | FAIL | FAIL struct | FAIL cbor | FAIL struct | FAIL struct |
| form_proof_not_a_map | FAIL | FAIL vdp_map | FAIL proof | FAIL proof_keys | FAIL struct |
| form_protected_not_a_map | FAIL | FAIL protected | FAIL header | FAIL vds | FAIL struct |
| form_tag_17 | FAIL | FAIL tag | FAIL cbor | FAIL tag | FAIL tag |
| form_unprotected_not_a_map | FAIL | FAIL struct | FAIL cbor | FAIL struct | FAIL struct |
| form_vdp_without_inclusion | FAIL | FAIL consistency_keys | FAIL proof | FAIL vdp | FAIL struct |
| its_33 | FAIL | FAIL leaf_hash | FAIL proof | FAIL leaf_hash | FAIL struct |
| label_leaf_float_1_0 | FAIL | FAIL proof_keys | FAIL proof | PASS | FAIL struct |
| label_leaf_true | FAIL | FAIL proof_keys | FAIL proof | PASS | FAIL struct |
| label_path_float_2_0 | FAIL | FAIL proof_keys | FAIL proof | PASS | FAIL struct |
| label_protected_alg_true | FAIL | FAIL protected_label | FAIL header | PASS | FAIL struct |
| label_protected_alg_value_float | FAIL | FAIL alg | FAIL header | PASS | FAIL struct |
| label_protected_vds_float | FAIL | FAIL vds | FAIL header | FAIL vds | FAIL struct |
| label_unprotected_float_396_0 | FAIL | FAIL unprotected_label | FAIL header | PASS | FAIL struct |
| label_vdp_float_minus_1_0 | FAIL | FAIL vdp_key | FAIL proof | PASS | FAIL struct |
| curve_p256_es256 | PASS | PASS | PASS | PASS | FAIL struct |
| curve_p521_es512 | PASS | PASS | PASS | PASS | FAIL struct |
| evidence_1_byte | PASS | PASS | PASS | PASS | FAIL struct |
| form_leaf_a_map | FAIL | FAIL leaf | FAIL proof | FAIL leaf | FAIL struct |
| form_leaf_of_four | FAIL | FAIL leaf | FAIL proof | FAIL leaf | FAIL struct |
| form_leaf_of_two | FAIL | FAIL leaf | FAIL proof | FAIL leaf | FAIL struct |
| form_protected_header_over_255_bytes | PASS | PASS | PASS | PASS | FAIL struct |
| form_vdp_missing | FAIL | FAIL vdp | FAIL header | FAIL vdp | FAIL struct |
| roots_differ_signed_for_the_second | FAIL | FAIL roots | FAIL root_mismatch | FAIL roots | FAIL struct |
| signature_padded | FAIL | FAIL signature | FAIL signature | PASS | FAIL struct |

The `expected, strict` column gives the verdict a strict reader is expected to give. For
`plus_empty_consistency_array` the generator had left the verdict open; the strict reading follows `f6d4eb04`. Where
the readers name reasons differently, the table shows each reader's own word.

Counted from the table:
- **This reader and the Go reader:** the same verdict on all 66 receipts.
- **The earlier reference with cbor2 5.9.0:** a different verdict on 15 of them. It accepts:
  - `duplicate_key_2`;
  - `dup_leaf_last` and `dup_path_last`, where the last value of the duplicate key wins;
  - `plus_empty_consistency_array`, `vdp_empty_consistency`, `vdp_duplicate_key` and `vdp_unknown_key`;
  - the seven `label_*` vectors other than `label_protected_vds_float`, where it reads a float or `true` as the
    integer label or value;
  - `signature_padded`, whose r and s it reads at any length.

  On `dup_leaf_first` and `dup_path_first` it fails on the signature, because it keeps the last value.
- **The earlier reference with cbor2 6.1.4:** `FAIL struct` on 64 of 66. Under a tag, at any depth, cbor2 6 returns
  an array as a tuple and a map as a frozendict, where cbor2 5.9.0 returns a list and a dict. The reference tests for
  a list. `form_tag_17` fails on its tag first, and only `without_tag18`, which has no tag, passes.

## Reproducing

From the repository root:

    PYTHONPATH=src python3 tools/scitt_ccf_external/pr31_strict_reader/reader.py \
        tools/scitt_ccf_external/pr31_strict_reader/probes/baseline.cose \
        tools/scitt_ccf_external/pr31_strict_reader/probes/keys.cbor \
        --digest b111c6e1d318f203063e5c16bab43c108326af0aa2f7b65760c95547a43dbe52
    python3 tools/scitt_ccf_external/pr31_strict_reader/make_vectors.py   # writes vectors/ again, byte for byte

`make_vectors.py` needs only the standard library and `cryptography` 43 or later, the first release with
deterministic ECDSA. The package itself declares 42 as its floor. Its signatures are deterministic (RFC 6979), so
a second run writes the same bytes. `tests/test_pr31_strict_reader.py` runs this reader on all 66 receipts. It holds
the verdict of each probe, the whole line of each vector and the reasons of five probes, it checks that
`make_vectors.py` writes the files in `vectors/` byte for byte, and it runs `reader.py` as a script as shown above.

## Limitations

- Readers beyond the three named above are not measured.
- The seven receipts from microsoft/scitt-ccf-ledger are not part of this run.
- The Go reader's reasons are coarser than this reader's (`proof` for most failures inside a proof), so only its
  verdicts are compared, not its reasons.

---

Created with AI assistance. Reviewed and published by me.
