"""RFC 8785 key order by UTF-16 code unit, held in Python and in the Rust second verifier alike.

RFC 8785 section 3.2.3 sorts the members of an object by the UTF-16 code units of their names.
U+1F600 is the surrogate pair D83D DE00 in UTF-16, and D83D is below E000, so U+1F600 sorts before
U+E000; by code point the order is the reverse. Measured on 19cadafc: `canonicalize_statement` and
`pb_verify_rs content-root` both sort by code unit and give the same root.

The expected bytes below are written out by hand from the RFC, not computed by either
implementation, so the three-way check (RFC, Python, Rust) cannot agree with itself by
construction. Every JCS writer of the package is held to the same pair.
"""
from __future__ import annotations

import hashlib
import json
import subprocess

E000 = ""
GRIN = "\U0001f600"

STATEMENT = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
    "predicateType": "https://example.org/p",
    "predicate": {E000: 1, GRIN: 2},
}

# RFC 8785 section 3.2.3 by hand: U+1F600 (F0 9F 98 80) precedes U+E000 (EE 80 80).
EXPECTED = (
    b'{"_type":"https://in-toto.io/Statement/v1",'
    b'"predicate":{"\xf0\x9f\x98\x80":2,"\xee\x80\x80":1},'
    b'"predicateType":"https://example.org/p",'
    b'"subject":[{"digest":{"sha256":"' + b"0" * 64 + b'"},"name":"x"}]}'
)
EXPECTED_PAIR = b'{"\xf0\x9f\x98\x80":2,"\xee\x80\x80":1}'


def test_the_two_orders_differ_for_this_pair():
    # The pair discriminates: code-unit and code-point order disagree on it.
    assert sorted([E000, GRIN]) == [E000, GRIN]
    assert sorted([E000, GRIN], key=lambda k: k.encode("utf-16-be")) == [GRIN, E000]


def test_python_canonical_bytes_match_the_rfc():
    from proofbundle.canonical import canonicalize_statement, statement_content_root

    assert canonicalize_statement(STATEMENT) == EXPECTED
    assert statement_content_root(STATEMENT) == hashlib.sha256(EXPECTED).digest()


def test_every_python_jcs_writer_orders_by_code_unit():
    from proofbundle import evalclaim
    from proofbundle.adapters import _provenance, trace_record

    pair = {E000: 1, GRIN: 2}
    assert evalclaim.canonicalize(pair) == EXPECTED_PAIR
    assert trace_record._jcs(pair) == EXPECTED_PAIR
    tag, _, digest = _provenance.config_hash(pair).partition(":")
    assert tag == "sha256-jcs"
    assert digest == hashlib.sha256(_provenance._CONFIG_DOMAIN + EXPECTED_PAIR).hexdigest()


def test_rust_content_root_matches_the_rfc_and_python(pb_verify_rs, tmp_path):
    path = tmp_path / "statement.json"
    # Literal characters, not \u escapes: the order is under test, not the escape reading.
    path.write_bytes(json.dumps(STATEMENT, ensure_ascii=False).encode("utf-8"))
    done = subprocess.run([str(pb_verify_rs), "content-root", str(path)],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == hashlib.sha256(EXPECTED).hexdigest()
