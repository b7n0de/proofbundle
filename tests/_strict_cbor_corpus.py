"""One corpus for every strict CBOR reader of this repository (the strict decoding rule stated in
test_strict_decoding_guard.py).

Every reader that decodes checked, signed or evidential CBOR runs against the SAME cases, so two strict readers
cannot drift apart without one of them turning red: ``proofbundle._strict_cbor``, ``cbor_min`` of the data-hash
vector tool and the checker of the statement identification package.

``VALID`` holds valid CBOR under RFC 8949 Section 5.3.1 with the value it decodes to; every reader must accept
it. Two of them are not in the preferred encoding (a head that is not the shortest, an indefinite length): both
are valid, and a reader that refuses them is stricter than the rule, which is a profile's decision, not this
corpus's. ``INVALID`` holds input that is not one valid data item; every reader must refuse it.
"""

#: name -> (hex, the value it decodes to, as plain Python: dict, list, bytes, str, int, bool, None)
VALID = {
    "empty_map_a0": ("a0", {}),
    "empty_map_b8_00_not_shortest_head": ("b800", {}),
    "empty_map_bf_ff_indefinite": ("bfff", {}),
    "map_two_keys": ("a2014161024162", {1: b"a", 2: b"b"}),
    "map_nested": ("a101a1024161", {1: {2: b"a"}}),
    "map_text_keys": ("a2616b01616c02", {"k": 1, "l": 2}),
    "array_indefinite": ("9f0102ff", [1, 2]),
    "text_indefinite": ("7f61616162ff", "ab"),
    "text_indefinite_chunks_at_code_points": ("7f62c3bc62c3bcff", "\u00fc\u00fc"),
    "bytes_indefinite": ("5f41614162ff", b"ab"),
    "head_not_shortest": ("1801", 1),
    "negative": ("20", -1),
    "simple_values": ("83f4f5f6", [False, True, None]),
    "map_false_and_true_keys": ("a2f401f502", {False: 1, True: 2}),
    "map_bytes_key": ("a1410100", {b"\x01": 0}),
    "map_indefinite": ("bf0102ff", {1: 2}),
    "bytes_indefinite_chunks_not_utf8": ("5f41ff42ffffff", b"\xff\xff\xff"),
}

#: name -> hex
INVALID = {
    "duplicate_key": "a2014161014162",
    "duplicate_key_nested": "a101a2016161016162",
    "duplicate_key_head_not_shortest": "a201416118014162",
    "duplicate_key_indefinite_map": "bf014161014162ff",
    "duplicate_text_key": "a2616b01616b02",
    "duplicate_bytes_key": "a2416b01416b02",
    "duplicate_key_in_array": "81a2014161014162",
    "bytes_after_the_value": "a1014161" + "00",
    "text_not_utf8": "62c328",
    "text_surrogate_in_utf8": "63eda080",
    # RFC 8949 Section 3.2.3: every chunk of an indefinite text string is itself valid, so the bytes of one code
    # point cannot be spread between chunks, although their concatenation would be valid UTF-8.
    "text_chunks_split_inside_a_code_point": "7f61c361bcff",
    "text_chunks_split_three_ways": "7f61e2618261acff",
    # Distinct data items that are one Python dict key: a reader that builds a dict keeps one of them in silence.
    "keys_1_and_1_0_collide": "a201416af93c00416b",
    "keys_true_and_1_collide": "a2f5416a01416b",
    # RFC 8949 Section 5.6.1: -0.0 is equal to 0.0, so these are one key twice.
    "duplicate_key_0_0_and_minus_0_0": "a2f90000416af98000416b",
    "indefinite_length_major_0": "1f",
    "indefinite_length_major_1": "3f",
    "indefinite_length_major_6": "df00",
    "break_alone": "ff",
    "additional_info_28": "1c",
    # RFC 8949 Appendix F.1: additional information 28 to 30 is reserved on every major type.
    "additional_info_28_major_1": "3c",
    "additional_info_29_major_2": "5d",
    "additional_info_30_major_3": "7e",
    "additional_info_28_major_4": "9c",
    "additional_info_29_major_5": "bd",
    "additional_info_30_major_6": "de",
    "additional_info_28_major_7": "fc",
    "simple_value_two_byte_below_32": "f814",
    "simple_value_two_byte_31": "f81f",
    "string_too_short": "4561",
    "array_too_short": "830102",
    "map_too_short": "a201",
    "head_too_short": "19ff",
    "chunk_of_wrong_type": "7f4161ff",
    "indefinite_without_break": "9f01",
    "indefinite_map_without_break": "bf01",
    "indefinite_map_cut_at_its_head": "bf",
    "empty_input": "",
    "too_deep": "81" * 70 + "00",
    "too_deep_indefinite_arrays": "9f" * 70 + "00" + "ff" * 70,
    "too_deep_map_values": "a100" * 70 + "00",
    "too_deep_tags": "c1" * 70 + "00",
}
