"""The structure check of a trace record builds a path text only where a message needs one.

WHERE THIS COMES FROM. The deep gate of 6.5.0, iteration 1, the trace record finding (tag note of v6.5.0,
"Known limitations of this release"): 3 percent more input gave 108 times the traced memory, and under a
600 MiB address-space limit `verify_trace_record` raised an uncaught MemoryError on a 649,293-byte input
before any signature was checked. The fix of 6.4.0 had turned the two value walks (`_canonicalizable`,
`_canonicalizable_value`) into walks over links; the structure check (`_check_structure` and every
reader it calls) still gave each member a fresh path string that copied the text of all its ancestors.
Under `appraisal.platform_measurement.layers` the ancestor text holds a member name the record chooses,
so one layer with a long name and many members cost members times that name, and the paths of the
members the schema does not name were kept in the findings and in `unknown_fields`.

THE CLASS. A walk's cost per node was assumed to be constant because the schema's depth is fixed, but a
node's path text costs the length of all its ancestors' names, which the input chooses; built for every
node, the walk costs nodes times path length instead of nodes.

THE PROPERTY. Each member of the structure check costs one link; the text is rendered only for a finding
or an unknown member, at most `budget._PATH_TEXT_LIMIT` characters long. A path within that limit is
rendered exactly as before (`test_every_message_of_the_corpus_is_unchanged`).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import textwrap
import tracemalloc
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.adapters import trace_record as tr

NOW = 1792000000
ED = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
GOLDEN = Path(__file__).parent / "fixtures" / "trace_record_messages_v6_5_0.json"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


JWK = {"kty": "OKP", "crv": "Ed25519", "x": _b64(ED.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw))}


def _record(**changes) -> dict:
    rec = {
        "eat_profile": tr.TRACE_PROFILE_V0_2,
        "iat": NOW - 60,
        "subject": "spiffe://trust.example.org/agent/payments/prod",
        "model": {"provider": "example-provider", "model_id": "example-model", "version": "20251001",
                  "weights_digest": "sha256:" + "a3" * 32},
        "runtime": {"platform": "software-only", "measurement": "sha384:" + "c9" * 48,
                    "nonce": "challenge-1"},
        "policy": {"bundle_hash": "sha256:" + "b2" * 32, "enforcement_mode": "enforce", "version": "1.2.0"},
        "data_class": "confidential",
        "tool_transcript": {"hash": "sha256:" + "d4" * 32, "call_count": 3,
                            "transcript_uri": "https://registry.example.org/transcript/1"},
        "build_provenance": {"slsa_level": 2, "builder": "https://builder.example.org",
                             "digest": "sha256:" + "e5" * 32},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "transparency": "https://registry.example.org/claim/1",
        "cnf": {"jwk": copy.deepcopy(JWK)},
    }
    rec.update(changes)
    return rec


def _jcs(value) -> bytes:
    """RFC 8785 bytes, or a stand-in for a record that has none (the reader refuses it before the signature)."""
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, ValueError):
        return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _embedded(rec: dict) -> bytes:
    body = {k: v for k, v in rec.items() if k != "signature"}
    return json.dumps(dict(body, signature=_b64(ED.sign(_jcs(body)))),
                      ensure_ascii=False).encode("utf-8")


def _jws(rec: dict) -> bytes:
    h = _b64(b'{"alg":"EdDSA"}')
    p = _b64(_jcs(rec))
    return (h + "." + p + "." + _b64(ED.sign((h + "." + p).encode("ascii")))).encode("ascii")


def _set(rec: dict, path: tuple, value) -> dict:
    rec = copy.deepcopy(rec)
    node = rec
    for step in path[:-1]:
        node = node[step]
    if value is _DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return rec


_DELETE = object()

#: Every object position of the schema a record reaches, with a valid value to mutate from.
_FULL = _record(
    delegation={"parent_record_hash": "sha256:" + "11" * 32, "credential_id": "cred-1"},
    origin={"kind": "self", "producer": "p", "source_event_id": "e", "ingested_at": 1700000001},
    references=[{"rel": "r", "id": "i", "resolver": "x", "retention": "P1D", "digest": "sha256:" + "22" * 32}],
    reproducibility={"function": "f", "code_identity": "sha256:" + "33" * 32, "code_resolver": "c",
                     "input_closure": [{"id": "a", "digest": "sha256:" + "44" * 32, "resolver": "r"}],
                     "transcript_digest": "sha256:" + "55" * 32},
    appraisal={"status": "affirming", "verifier": "https://verifier.example.org",
               "policy_ref": "https://p.example.org", "timestamp": 1, "provenance_depth_verified": "builder",
               "method": "re-execution",
               "re_execution": {"outcome": "reproduced", "observed_digest": "sha256:" + "66" * 32},
               "platform_measurement": {"measurement": "sha384:" + "c9" * 48,
                                        "layers": {"firmware": {"outcome": "established"}}}},
)

_POSITIONS = [
    (), ("model",), ("runtime",), ("policy",), ("tool_transcript",), ("build_provenance",), ("appraisal",),
    ("cnf",), ("cnf", "jwk"), ("delegation",), ("origin",), ("references", 0), ("reproducibility",),
    ("reproducibility", "input_closure", 0), ("appraisal", "re_execution"),
    ("appraisal", "platform_measurement"), ("appraisal", "platform_measurement", "layers"),
    ("appraisal", "platform_measurement", "layers", "firmware"),
]
_BAD_VALUES = (None, True, 7, 1.5, "x", "", [], {}, [1], {"q": 1})


def _corpus() -> list:
    """(name, wire bytes) for the error cases the structure check names, signed and unsigned."""
    cases = [("valid", _FULL)]
    for pos in _POSITIONS:
        node = _FULL
        for step in pos:
            node = node[step]
        where = ".".join(map(str, pos)) or "<record>"
        cases.append((f"{where} unknown member", _set(_FULL, pos + ("zz_unknown",), 1)))
        cases.append((f"{where} unknown member with quote", _set(_FULL, pos + ('a "b"é\x01',), 1)))
        if type(node) is dict:
            for name in node:
                cases.append((f"{where}.{name} removed", _set(_FULL, pos + (name,), _DELETE)))
                for i, bad in enumerate(_BAD_VALUES):
                    cases.append((f"{where}.{name} bad {i}", _set(_FULL, pos + (name,), bad)))
    cases += [
        ("layers empty", _set(_FULL, ("appraisal", "platform_measurement", "layers"), {})),
        ("layer name long", _set(_FULL, ("appraisal", "platform_measurement", "layers"),
                                 {"L" * 200: {"outcome": "nope", "x": 1, "reason": "layer-not-measured"}})),
        ("tpm2 layer names", _set(_set(_FULL, ("runtime", "platform"), "tpm2"),
                                  ("appraisal", "platform_measurement", "layers"),
                                  {"pcr:7": {"outcome": "established"}, "bios": {"outcome": "established"},
                                   "pcr:24": {"outcome": "not-established"}})),
        ("measurement differs", _set(_FULL, ("appraisal", "platform_measurement", "measurement"),
                                     "sha384:" + "ab" * 48)),
        ("origin forces software-only", _set(_set(_FULL, ("origin", "kind"), "log-import"),
                                             ("runtime", "platform"), "tpm2")),
        ("diverged without digest", _set(_FULL, ("appraisal", "re_execution"), {"outcome": "diverged"})),
        ("not-attempted without reason", _set(_FULL, ("appraisal", "re_execution"),
                                              {"outcome": "not-attempted"})),
        ("re_execution without method", _set(_FULL, ("appraisal", "method"), _DELETE)),
        ("status none with measurement", _set(_FULL, ("appraisal", "status"), "none")),
        ("jwk open member values", _set(_FULL, ("cnf", "jwk", "ext"),
                                        {"a b": [0.5, {"c": 1e300}], "d": 9007199254740993})),
        ("jwk EC without y", _set(_FULL, ("cnf", "jwk"), {"kty": "EC", "crv": "P-256", "x": "AA", "d": "x"})),
        ("jwk RSA", _set(_FULL, ("cnf", "jwk"), {"kty": "RSA"})),
        ("references many", _set(_FULL, ("references",), [{}, 1, {"rel": 1}, {"rel": "r", "id": "i",
                                                                              "resolver": "x", "u": 1}])),
        ("many unknown top members", dict(_FULL, **{f"u{i}": i for i in range(9)})),
        ("record is a list", [1]),
    ]
    out = []
    for name, rec in cases:
        if type(rec) is dict:
            out.append((name + " / embedded", _embedded(rec)))
            out.append((name + " / jws", _jws(rec)))
            out.append((name + " / unsigned", json.dumps(rec).encode("utf-8")))
        else:
            out.append((name, json.dumps(rec).encode("utf-8")))
    return out


def _verdict_text(raw: bytes) -> str:
    """The SHA-256 (first 24 hex digits) of the whole verdict: every check with its message in order,
    unknown_fields, the exit code."""
    v = tr.verify_trace_record(raw, trusted_keys=[JWK], now=NOW)
    text = json.dumps(dict(v.as_dict(), exit_code=tr.exit_code(v)), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def test_every_message_of_the_corpus_is_unchanged():
    """Messages, the order of the findings, unknown_fields and exit codes as v6.5.0 (ac4129f7) gave them.
    The fixture was written by this file's `_write_golden` at ac4129f7, before the fix."""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    corpus = _corpus()
    assert [n for n, _ in corpus] == list(golden), "the corpus changed; the fixture no longer pins it"
    differ = [n for n, raw in corpus if _verdict_text(raw) != golden[n]]
    assert not differ, differ[:5]
    assert len(golden) > 500


def _write_golden() -> None:   # pragma: no cover - run by hand at the commit the fixture pins
    GOLDEN.write_text(json.dumps({n: _verdict_text(raw) for n, raw in _corpus()}, indent=0,
                                 ensure_ascii=True) + "\n", encoding="utf-8")


def _wide_layer(name_len: int, members: int) -> bytes:
    layer = {"outcome": "established", **{f"m{i}": 0 for i in range(members)}}
    rec = _record(appraisal={"status": "affirming", "verifier": "https://verifier.example.org",
                             "platform_measurement": {"measurement": "sha384:" + "c9" * 48,
                                                      "layers": {"L" * name_len: layer}}})
    return json.dumps(rec, separators=(",", ":")).encode("ascii")


def _deep_open_member(key_len: int, depth: int, items: int) -> bytes:
    node: object = [0.5] * items
    for _ in range(depth):
        node = {"k" * key_len: node}
    rec = _record(cnf={"jwk": dict(JWK, ext=node)})
    return json.dumps(rec, separators=(",", ":")).encode("ascii")


def _nodes(raw: bytes) -> int:
    """Members and items of the parsed record, the count a walk over it cannot do with less."""
    count, stack = 0, [json.loads(raw)]
    while stack:
        cur = stack.pop()
        if type(cur) is dict:
            count += len(cur)
            stack.extend(cur.values())
        elif type(cur) is list:
            count += len(cur)
            stack.extend(cur)
    return count


def _built_path_text(raw: bytes, monkeypatch) -> int:
    """The total length of every path text `_member_path` built during one verification."""
    built = [0]
    original = tr._member_path

    def counting(base, key):
        text = original(base, key)
        built[0] += len(text)
        return text

    monkeypatch.setattr(tr, "_member_path", counting)
    try:
        tr.verify_trace_record(raw, trusted_keys=[JWK], now=NOW)
    finally:
        monkeypatch.setattr(tr, "_member_path", original)
    return built[0]


@pytest.mark.parametrize("make", [
    lambda: _wide_layer(20_000, 200),
    lambda: _wide_layer(2_000, 2_000),
    # Depth near the parser's bound of 64 levels: the open member sits three levels down.
    lambda: _deep_open_member(1_000, 60, 2_000),
], ids=["long-layer-name", "many-layer-members", "deep-open-member"])
def test_the_path_text_a_verification_builds_grows_with_the_input_not_with_its_paths(make, monkeypatch):
    from proofbundle.budget import _PATH_TEXT_LIMIT
    raw = make()
    built = _built_path_text(raw, monkeypatch)
    # A constant per node, whatever the names above it: one bounded text per finding or unknown member,
    # and its rendering joins a handful of steps of at most the limit each. At ac4129f7 the long layer
    # name cost 4,049,173 characters for 239 nodes (23,100 bytes), and 2,000 members below a name of
    # 2,000 characters cost 4,091,573 characters.
    assert built <= 4 * _PATH_TEXT_LIMIT * _nodes(raw), (built, _nodes(raw))


def _peak(raw: bytes) -> int:
    tr.verify_trace_record(b"{}", trusted_keys=[JWK], now=NOW)
    tracemalloc.start()
    try:
        tr.verify_trace_record(raw, trusted_keys=[JWK], now=NOW)
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return peak


def test_traced_memory_of_a_long_layer_name_stays_in_proportion_to_its_size():
    raw = _wide_layer(20_000, 200)
    peak = _peak(raw)
    # At ac4129f7: 23,100 bytes peaked at about 8.3 MB (about 360 times).
    assert peak < 50 * len(raw), (peak, len(raw))


def test_the_cost_of_a_member_does_not_grow_with_the_length_of_the_name_above_it():
    """The same 2,000 unknown members below a layer name of 2,000 and of 20,000 characters, both over
    the path limit: each member's text is cut at the limit, so ten times the name is not ten times the
    memory. A name within the limit is named in full, so the control is a name over it."""
    near, far = _wide_layer(2_000, 2_000), _wide_layer(20_000, 2_000)
    peak_near, peak_far = _peak(near), _peak(far)
    # At ac4129f7 the name of 2,000 characters alone peaked at 8,815,040 bytes for 22,300 bytes.
    assert peak_far < 1.5 * peak_near + 50 * (len(far) - len(near)), (peak_far, peak_near)


def test_unknown_members_below_a_long_name_are_named_within_the_path_limit():
    from proofbundle.budget import _PATH_TEXT_LIMIT
    v = tr.verify_trace_record(_wide_layer(5_000, 10), trusted_keys=[JWK], now=NOW)
    assert tr.exit_code(v) == 1
    assert len(v.unknown_fields) == 10
    for path, permitted in v.unknown_fields:
        assert permitted is False and len(path) <= _PATH_TEXT_LIMIT + 1 and path.endswith("…")
        assert path.startswith("appraisal.platform_measurement.layers.LLLL")


_CHILD = textwrap.dedent("""
    import json, resource, sys
    limit = int(sys.argv[2]) * 1024 * 1024
    from proofbundle.adapters import trace_record as tr
    raw = open(sys.argv[1], "rb").read()
    jwk = json.loads(sys.argv[3])
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    try:
        v = tr.verify_trace_record(raw, trusted_keys=[jwk], now=1792000000)
    except MemoryError:
        print("MemoryError")
        sys.exit(70)
    print("exit", tr.exit_code(v))
""")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is enforced as measured on Linux")
def test_a_wide_layer_under_a_600_mib_address_space_ends_in_a_verdict(tmp_path):
    """Run in a child process with RLIMIT_AS and a timeout, never in the process of the suite."""
    raw = _wide_layer(200_000, 3_000)        # 233,931 bytes
    path = tmp_path / "record.json"
    path.write_bytes(raw)
    env = dict(os.environ, PYTHONHASHSEED="0")
    done = subprocess.run([sys.executable, "-c", _CHILD, str(path), "600", json.dumps(JWK)],
                          capture_output=True, text=True, timeout=120, env=env)
    # At ac4129f7 the child printed MemoryError and exited 70.
    assert done.returncode == 0, (done.returncode, done.stdout[-300:], done.stderr[-300:])
    assert done.stdout.strip() == "exit 1"
