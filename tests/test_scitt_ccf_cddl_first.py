"""The CDDL pass of the scitt-ccf/v1 reader: every shape before any status (Nachtrag 4).

Five Codex rounds on pull request 278 each found another place of one class: an early return before
the shape was checked in full. The reader now runs one pass over the statement, label 394, every
receipt and every proof family, against the -05 CDDL and the RFC 9995 parameter types, before any
status logic, and sets readable there only.

Two things are pinned here.

REGRESSION. Every finding of the five rounds is a case, and so is each sibling Codex named with it.
Each case names its expected status and readable value, and the words of the rule that refuses it.

MUTANTS. Every rule of every table of the pass is taken away, one at a time, and the whole case list
runs again. Some regression case must break: its status, readable value or the words of its refusal
are no longer the expected ones. A rule whose removal breaks no case is a rule no test holds, and the
test fails for it. The tables are replaced on the module for the
duration of one run, so no production code carries a switch for this.

Needs the [scitt] extra. The statement and receipt builders are those of test_scitt_ccf_profile.py
and test_scitt_ccf_consistency.py, loaded from their files.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

HERE = Path(__file__).resolve().parent


def _load(name: str, file: str):
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / file)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _p():
    return _load("_scitt_cddl_first_profile_builders", "test_scitt_ccf_profile.py")


def _c():
    return _load("_scitt_cddl_first_consistency_builders", "test_scitt_ccf_consistency.py")


def _s():
    from proofbundle import scitt_ccf  # noqa: PLC0415
    return scitt_ccf


# ------------------------------------------------------------------------------------------------
# Builders: one change against the control per case
# ------------------------------------------------------------------------------------------------
def _stmt(**prot):
    """The control statement, with protected labels added or replaced (None removes one)."""
    P = _p()
    base = {1: -7, 258: -16, 259: "application/json", 15: {1: "did:example:signer"}}
    for k, v in prot.items():
        label = int(k[1:]) if k.startswith("L") else k
        if v is None:
            base.pop(label, None)
        else:
            base[label] = v
    return P.Stmt(prot_map=base)


def _ts(st=None, receipts=None, unprot=None, **rcpt):
    """A Transparent Statement: the statement and one receipt of the control, one thing changed."""
    P = _p()
    st = st or _stmt()
    if receipts is None:
        receipts = [P.Rcpt(data_hash=P.dh_of(st), **rcpt).build()]
    return ("transparent", P.transparent(st, receipts, unprot))


def _ts_raw(st, unprot):
    """A statement with exactly this unprotected map, label 394 included or left out."""
    P = _p()
    return ("transparent", b"\xd2\x84" + P.enc(st.protected()) + P.enc(unprot) + P.enc(st.payload)
            + P.enc(st.signature()))


def _proof(leaf=None, path=None, extra=None):
    """An inclusion proof of the control receipt's leaf and path, with one part replaced."""
    P = _p()
    st = _stmt()
    itx = hashlib.sha256(b"itx").digest()
    ev = "ce:2.57:" + "8c" * 32
    dh = P.dh_of(st)
    good_path = [[i % 2 == 0, hashlib.sha256(bytes([i])).digest()] for i in range(4)]
    m = {1: leaf if leaf is not None else [itx, ev, dh], 2: path if path is not None else good_path}
    m.update(extra or {})
    return P.enc(m)


def _cons(vdp=None, proofs=None, **kw):
    """A consistency receipt of the control, one thing changed."""
    C = _c()
    return ("consistency", C.receipt(proofs, vdp=vdp, **kw))


def _anchor(anchor):
    C = _c()
    _a, path = C.TREE.proof(13, 24)
    return C._cbor2().dumps({1: anchor, 2: [[left, h] for left, h in path]})


def _good_cons_proof():
    C = _c()
    return C.enc_proof(*C.TREE.proof(13, 24))


# ------------------------------------------------------------------------------------------------
# The cases: (id, build, expected status, expected readable, words of the refusal or None)
# ------------------------------------------------------------------------------------------------
def _cases():
    P = _p()
    st = _stmt()
    dh = P.dh_of(st)
    rc = P.Rcpt(data_hash=dh).build()
    other = P.Rcpt(data_hash=hashlib.sha256(b"another statement").digest()).build()
    return [
        # controls: they must confirm, or nothing below means anything
        ("control transparent statement", lambda: _ts(), "confirmed", True, None),
        ("control consistency receipt", lambda: _cons(), "confirmed", True, None),
        # R1, PR 278 thread 4110616327: proofs parsed before the profile, and its sibling in _verify_consistency
        ("R1 junk inclusion proof under an unsupported alg",
         lambda: _ts(alg=-8, proofs_override=[b"junk"]), "malformed", False, "does not decode"),
        ("R1 sibling: junk consistency proof under an unsupported alg",
         lambda: _cons(proofs=[b"junk"], signed=_c().sign_over(_c().TREE.root(24), prot={
             1: -8, 4: _c().kid_of(_c().SERVICE_KEY), 395: 2, 15: {1: _c().ISSUER}})),
         "malformed", False, "does not decode"),
        # R1, thread 4110616328: missing trust is never an unbound receipt; sibling: no consistency
        # status before the signature claims a valid signature
        ("R1 receipt of another statement without a service key",
         lambda: ("transparent-rp", P.transparent(st, [other]), {"scitt_statement_keys": [P.spki(P.STMT_KEY)]}),
         "needs_rp_trust", True, None),
        ("R1 sibling: older root mismatch without a service key",
         lambda: ("consistency-rp", _c().receipt(), {}), "consistency_older_root_mismatch", True, None),
        # R2, thread 4110716823: receipts refused before parsing are never readable; sibling: over the limit
        ("R2 no label 394", lambda: _ts_raw(st, {}), "malformed", False, "no receipt under label 394"),
        ("R2 label 394 empty", lambda: _ts(receipts=[]), "malformed", False, "no receipt under label 394"),
        ("R2 sibling: more than MAX_RECEIPTS receipts",
         lambda: _ts(receipts=[rc] * (_s().MAX_RECEIPTS + 1)), "malformed", False, "more than"),
        # R3, thread 4110785175: every vdp family parsed; siblings: unknown labels, another root
        ("R3 junk consistency proof beside the inclusion proof",
         lambda: _ts(consistency=[b"junk"]), "malformed", False, "does not decode"),
        ("R3 sibling: a vdp label other than -1 and -2",
         lambda: _ts(vdp_extra={-3: [b"junk"]}), "malformed", False, "-05 defines -1 and -2 only"),
        ("R3 sibling: a consistency proof to another root",
         lambda: _ts(consistency="other_root"), "root_mismatch", True, None),
        # R4, thread 4110836223: an empty family; sibling: the -1 arm
        ("R4 an empty -2 beside the inclusion proof",
         lambda: _ts(consistency=[]), "malformed", False, "an empty consistency-proof array"),
        ("R4 sibling: an empty -1", lambda: _ts(proofs_override=[]), "malformed", False,
         "an empty inclusion-proof array"),
        # R5, thread 4110907849: the RFC 9995 parameter types; sibling: both labels
        ("R5 259 of []", lambda: _ts(st=_stmt(L259=[])), "malformed", False, "259"),
        ("R5 sibling: 260 of 0", lambda: _ts(st=_stmt(L260=0)), "malformed", False, "260"),
        # PR 279 round one, thread 4111060383: a claim type in the unprotected CWT claims too;
        # siblings: iat, and the consistency verifier. The control keeps its placement status.
        ("PR 279 R1 control: well-typed CWT claims, unprotected",
         lambda: ("transparent", _p().transparent(st, [_receipt_unprot({15: {1: _p().ISSUER, 6: 1790000000}})])),
         "outside_profile", True, "no CWT issuer in its protected header"),
        ("PR 279 R1 receipt CWT issuer an int, unprotected",
         lambda: ("transparent", _p().transparent(st, [_receipt_unprot({15: {1: 5}})])),
         "malformed", False, "CWT claim 1 in the unprotected"),
        ("PR 279 R1 sibling: receipt CWT iat text, unprotected",
         lambda: ("transparent", _p().transparent(st, [_receipt_unprot({15: {1: _p().ISSUER, 6: "now"}})])),
         "malformed", False, "CWT claim 6 in the unprotected"),
        ("PR 279 R1 sibling: consistency receipt CWT issuer an int, unprotected",
         lambda: _cons(signed=_signed_without_cwt(), unprot_extra={15: {1: 5}}),
         "malformed", False, "CWT claim 1 in the unprotected"),
        # every other rule of the pass, one case each
        ("statement alg a bool", lambda: _ts(st=_stmt(L1=True)), "malformed", False, "label 1 in the protected"),
        ("statement crit empty", lambda: _ts(st=_stmt(L2=[])), "malformed", False, "label 2 in the protected"),
        ("statement content type a bstr", lambda: _ts(st=_stmt(L3=b"x")), "malformed", False,
         "label 3 in the protected"),
        ("statement kid text", lambda: _ts(st=_stmt(L4="kid")), "malformed", False, "label 4 in the protected"),
        ("statement CWT claims an array", lambda: _ts(st=_stmt(L15=[1])), "malformed", False,
         "label 15 in the protected"),
        ("statement x5chain an int, unprotected",
         lambda: _ts_raw(_p().Stmt(x5chain=None), {33: 5, 394: [rc]}), "malformed", False,
         "label 33 in the unprotected"),
        ("258 text", lambda: _ts(st=_stmt(L258="sha-256")), "malformed", False, "label 258"),
        ("a receipt that is not bytes", lambda: _ts(receipts=[5]), "malformed", False, "a receipt is a byte string"),
        ("receipt alg a bool", lambda: _ts(extra_prot={1: True}), "malformed", False, "label 1 in the protected"),
        ("receipt alg text", lambda: _ts(extra_prot={1: "ES384"}), "malformed", False, "-05 CDDL"),
        ("receipt crit empty", lambda: _ts(extra_prot={2: []}), "malformed", False, "label 2 in the protected"),
        ("receipt content type a bstr", lambda: _ts(extra_prot={3: b"x"}), "malformed", False,
         "label 3 in the protected"),
        ("receipt kid text", lambda: _ts(kid="kid"), "malformed", False, "label 4 in the protected"),
        ("receipt CWT claims an array", lambda: _ts(extra_prot={15: [1]}), "malformed", False,
         "label 15 in the protected"),
        ("receipt CWT issuer an int", lambda: _ts(extra_prot={15: {1: 5}}), "malformed", False, "CWT claim 1"),
        ("receipt CWT iat text", lambda: _ts(extra_prot={15: {1: _p().ISSUER, 6: "now"}}), "malformed", False,
         "CWT claim 6"),
        ("receipt vds text", lambda: _ts(vds="2"), "malformed", False, "label 395"),
        ("vdp an array", lambda: ("transparent", _p().transparent(st, [_receipt_with_vdp([1])])),
         "malformed", False, "vdp (396) is not a map"),
        ("vdp empty", lambda: ("transparent", _p().transparent(st, [_receipt_with_vdp({})])),
         "malformed", False, "neither -1 nor -2"),
        ("-1 not an array", lambda: _ts(proofs_override=b"junk"), "malformed", False,
         "inclusion proofs (-1) are not an array"),
        ("-1 over the limit", lambda: _ts(n_proofs=_s().MAX_INCLUSION_PROOFS + 1), "malformed", False,
         "more than"),
        ("-2 not an array", lambda: _ts(consistency=b"junk"), "malformed", False,
         "consistency proofs (-2) are not an array"),
        ("-2 over the limit", lambda: _ts(consistency=[_same_root_cons()] * (_s().MAX_CONSISTENCY_PROOFS + 1)),
         "malformed", False, "more than"),
        ("a proof that is not bytes", lambda: _ts(proofs_override=[5]), "malformed", False,
         "a proof is not a byte string"),
        ("a proof with a third key", lambda: _ts(proofs_override=[_proof(extra={3: 0})]), "malformed", False,
         "a proof is exactly"),
        ("a proof with an empty path", lambda: _ts(proofs_override=[_proof(path=[])]), "malformed", False,
         "a path has 1 to"),
        ("a path element with an int tag",
         lambda: _ts(proofs_override=[_proof(path=[[1, hashlib.sha256(bytes([0])).digest()]]
                                                   + [[i % 2 == 0, hashlib.sha256(bytes([i])).digest()]
                                                      for i in range(1, 4)])]),
         "malformed", False, "a path element is"),
        ("a leaf of two components", lambda: _ts(proofs_override=[_proof(leaf=[b"\x00" * 32, "ce"])]),
         "malformed", False, "three components"),
        ("an internal-transaction-hash of 31 bytes",
         lambda: _ts(proofs_override=[_proof(leaf=[b"\x00" * 31, "ce", _p().dh_of(_stmt())])]),
         "malformed", False, "internal-transaction-hash"),
        ("an empty internal-evidence",
         lambda: _ts(proofs_override=[_proof(leaf=[hashlib.sha256(b"itx").digest(), "", _p().dh_of(_stmt())])]),
         "malformed", False, "internal-evidence"),
        ("a data-hash of 31 bytes",
         lambda: _ts(proofs_override=[_proof(leaf=[hashlib.sha256(b"itx").digest(), "ce", b"\x00" * 31])]),
         "malformed", False, "data-hash"),
        ("an anchor of 31 bytes", lambda: _cons(proofs=[_anchor(b"\x00" * 31)]), "malformed", False, "the anchor"),
    ]


def _receipt_unprot(extra):
    """The control receipt without protected CWT claims, these labels added to its unprotected
    header. The signature covers the protected header and the root, so it still verifies."""
    P = _p()
    st = _stmt()
    import cbor2  # noqa: PLC0415
    prot, unprot, payload, sig = cbor2.loads(P.Rcpt(data_hash=P.dh_of(st), drop_prot=(15,)).build()).value
    return b"\xd2" + cbor2.dumps([prot, {**unprot, **extra}, payload, sig])


def _signed_without_cwt():
    """The consistency control's protected header and signature, without protected CWT claims."""
    C = _c()
    return C.sign_over(C.TREE.root(24), prot={1: -35, 4: C.kid_of(C.SERVICE_KEY), 395: 2,
                                                 "ccf.v1": {"txid": "2.24"}})


def _receipt_with_vdp(vdp):
    """The control receipt re-signed with this value under label 396."""
    P = _p()
    st = _stmt()
    rc = P.Rcpt(data_hash=P.dh_of(st), vdp_extra={})
    raw = rc.build()
    import cbor2  # noqa: PLC0415
    tag = cbor2.loads(raw)
    prot, _unprot, payload, sig = tag.value
    return b"\xd2" + cbor2.dumps([prot, {396: vdp}, payload, sig])


def _same_root_cons():
    P = _p()
    st = _stmt()
    raw = P.Rcpt(data_hash=P.dh_of(st), consistency="same_root").build()
    import cbor2  # noqa: PLC0415
    return cbor2.loads(raw).value[1][396][-2][0]


_BUILT: dict = {}


def _built(case_id, build):
    if case_id not in _BUILT:
        _BUILT[case_id] = build()
    return _BUILT[case_id]


def _outcome(built) -> tuple:
    """What a case produces: status, readable, and the refusal or receipt statuses."""
    S = _s()
    P, C = _p(), _c()
    kind = built[0]
    if kind in ("transparent", "transparent-rp"):
        rp = built[2] if kind == "transparent-rp" else P.trust()
        r = S.verify_transparent_statement(built[1], canonical_root=P.ROOT, rp_trust=rp)
        return (r.status, r.readable, r.detail, tuple((c.status, c.readable, c.detail) for c in r.receipts))
    rp = built[2] if kind == "consistency-rp" else None
    older = C.TREE.root(12) if kind == "consistency-rp" else None
    c = C.check(built[1], older=older, rp=rp)
    return (c.status, c.readable, c.detail, c.signature_valid)


def _all_rules():
    S = _s()
    tables = ("_STATEMENT_RULES", "_TRANSPARENT_RULES", "_RECEIPT_BYTES_RULES", "_RECEIPT_RULES",
              "_CCF_RULES", "_PROOF_RULES", "_LEAF_RULES", "_ANCHOR_RULES")
    return [(t, r.name) for t in tables for r in getattr(S, t)]


# ------------------------------------------------------------------------------------------------
# Regression
# ------------------------------------------------------------------------------------------------
N_CASES = 52


def _holds(case) -> tuple:
    """Run one case: (whether it gives its expected status, readable value and refusal, the outcome)."""
    case_id, build, status, readable, words = case
    out = _outcome(_built(case_id, build))
    ok = (out[0], out[1]) == (status, readable)
    if ok and words is not None:
        refusal = out[2] + " ".join(d for _s, _r, d in out[3]) if isinstance(out[3], tuple) else out[2]
        ok = words in refusal
    return ok, out


@pytest.mark.parametrize("index", range(N_CASES))
def test_regression_case(index):
    cases = _cases()
    assert len(cases) == N_CASES, len(cases)       # the parametrize range must track the list
    case_id = cases[index][0]
    ok, out = _holds(cases[index])
    assert ok, (case_id, out)
    if case_id.startswith("R1 receipt of another statement"):
        r = out[3][0]
        assert r[0] == "needs_rp_trust"
    if case_id.startswith("R1 sibling: older root"):
        assert out[3] is None                       # no status before the signature claims one


def _readable_writes(fn) -> list:
    """Every place a function gives readable a value: (line, kind, source of the value)."""
    import ast  # noqa: PLC0415
    import inspect  # noqa: PLC0415
    import textwrap  # noqa: PLC0415
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "readable":
            out.append((node.value.lineno, "keyword", ast.unparse(node.value)))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (isinstance(target, ast.Name) and target.id == "readable") or \
                        (isinstance(target, ast.Attribute) and target.attr == "readable"):
                    out.append((node.lineno, "assign", ast.unparse(node.value)))
    return out


def test_readable_is_set_in_the_cddl_pass_only():
    """readable is decided in the pass: _validate_receipt computes it, the transparent verifier
    decides it once before its status logic, and every other function only carries it on."""
    import inspect  # noqa: PLC0415
    S = _s()
    assert [k for _l, k, _v in _readable_writes(S._validate_receipt)] == ["keyword"]
    for fn in (S._receipt_status, S._verify_consistency):
        assert {v for _l, _k, v in _readable_writes(fn)} == {"v.readable"}, fn.__name__
    for fn in (S._statement_profile, S._statement_signature, S._receipt_outside, S._receipt_crit, S._receipt):
        assert _readable_writes(fn) == [], fn.__name__
    writes = _readable_writes(S._verify_transparent_statement)
    decided = [line for line, kind, _v in writes if kind == "assign"]
    assert len(decided) == 1 and {v for _l, k, v in writes if k == "keyword"} == {"readable"}
    lines = inspect.getsource(S._verify_transparent_statement).splitlines()
    status_logic = next(i for i, text in enumerate(lines, 1) if "# THE STATUS LOGIC" in text)
    assert decided[0] < status_logic


# ------------------------------------------------------------------------------------------------
# Mutants: every rule must hold some case
# ------------------------------------------------------------------------------------------------
def _broken() -> list:
    """The regression cases that do not hold under the tables as they stand."""
    return [case[0] for case in _cases() if not _holds(case)[0]]


@pytest.mark.parametrize("table, rule", _all_rules() if importlib.util.find_spec("cbor2") else [])
def test_every_rule_of_the_cddl_pass_breaks_a_regression_case(table, rule, monkeypatch):
    S = _s()
    assert _broken() == []                          # the unmutated pass holds every case
    monkeypatch.setattr(S, table, tuple(r for r in getattr(S, table) if r.name != rule))
    assert _broken(), f"removing {rule!r} from {table} breaks no regression case: no test holds this rule"


def test_the_mutant_harness_flags_a_rule_no_case_holds(monkeypatch):
    """Positive control: a rule that refuses nothing is added to a table and then taken away. No case
    may break, so the harness above would name it; a harness that always passed would prove nothing."""
    S = _s()
    idle = S._Rule("idle rule of the positive control", lambda _subject: None)
    monkeypatch.setattr(S, "_STATEMENT_RULES", S._STATEMENT_RULES + (idle,))
    assert _broken() == []
    monkeypatch.setattr(S, "_STATEMENT_RULES", tuple(r for r in S._STATEMENT_RULES if r is not idle))
    assert _broken() == []
