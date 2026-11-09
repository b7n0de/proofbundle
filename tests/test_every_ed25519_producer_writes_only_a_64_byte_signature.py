"""Every producer of an Ed25519 signature writes only a signer's output of 64 bytes.

THE CLASS, found by Codex in pre-reviews 5 and 6 of the class fix after 6.5.0: a producer asked its signer and wrote
what came back, unchecked, into something its own verifier reads under a budget or as one segment. A signer of
another kind that returned 750,001 bytes gave a bundle (`emit_bundle`), a DSSE envelope (`dsse.sign_envelope`) or a
Trust Pack (`sign_trust_pack`) that the verifier refuses at `string_len`, and 6,500,000 bytes gave a status list token
past the segment bound. The sweep over every `.sign(` of the package found twelve calls, ten of them Ed25519 sites
(pre-review 7 counted them by AST). Each now reads the output once through `signature._ed25519_signatur_von` and
refuses, with the error it already uses, anything that is not 64 bytes.

THE GENERATOR, not a fixture per site: every producer below runs against the same odd outputs, and the same
controls must hold for each. A signer of another kind that returns the real signature in any buffer a producer took
before, as bytes, a ``bytearray``, a ``memoryview``, a view that is not contiguous or an ``array.array``, writes
exactly what the real key writes (pre-review 6: the SD-JWT producers refused a view while the emitter took it;
pre-review 7: renewal took a strided view and every site an array, and the first reader refused both).

THE LIST, per call and not per file (pre-review 7): every `.sign(` call of the package is read by AST, and each one
outside the two ML-DSA sites must be the one argument of `_ed25519_signatur_von`. Its function must be listed, with
exactly as many calls as it has. A missing reader in a file that has other readers, a second unread call inside a
listed function and a new unlisted producer each fail `test_the_list_binds_every_ed25519_signing_call_to_the_reader`;
the mutation controls below show it on the real sources. A reference to `.sign` that is not called on the spot (an
alias such as ``weiter = signer.sign``, or ``getattr(signer, "sign")``) is refused anywhere in the package (pre-review
8: a second signature through an alias passed the list and every generated case).

THE COUNT, behind equal outputs (pre-review 8): a signer that returns the real signature on its first call and 750,001
bytes on every later one must be asked exactly once, and the producer must write what the real key writes. A second
signing call hidden behind an equal first output fails here even where the list cannot see it.

THE LENGTH, an expectation the producer cannot move (pre-review 9): equal outputs of two runs of the same producer say
nothing when both runs write the same extra signature, for example through the ML-DSA helper with a second signer of
its own. With the fixed inputs below, each producer's output has one length, measured over five key pairs before this
test was written; the test holds every run, with the real key and with the counting signer, to that number. And the
two ML-DSA helpers, which sign outside the Ed25519 rule, may be referred to only where they are today: one import in
renewal.py and one call in renewal._sign_ats_content.

OUT OF THIS CLASS, named: `checkpoint.cosign_checkpoint_mldsa` and `pqsig.sign_mldsa` sign with ML-DSA, whose signature has
another length; they do not write an Ed25519 signature.
"""
from __future__ import annotations

import ast
import base64
import json
from array import array
from collections import Counter
from pathlib import Path

import pytest

from proofbundle import checkpoint as cp
from proofbundle import dsse
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
from proofbundle.renewal import RenewalError, _sign_ats_content
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.statuslist import issue_status_list_token
from proofbundle.trust_pack import TrustPackError, sign_trust_pack

SRC = Path(__file__).resolve().parents[1] / "src" / "proofbundle"
KEY = generate_signer()
HOLDER = generate_signer()


class _Signer:
    """A signer of another kind: it names the real key and returns ``ausgabe(real signature)``."""

    def __init__(self, ausgabe=lambda s: s):
        self.ausgabe = ausgabe

    def sign(self, data):
        return self.ausgabe(KEY.sign(data))

    def public_key(self):
        return KEY.public_key()


def _note():
    return cp.sign_checkpoint("example.org/log", 3, bytes(range(32)), KEY, "example.org/log")


def _pack_predicate():
    return {"schemaVersion": "0.1.0", "trustPackId": "tp-sig", "version": 1, "expires": "2027-01-01T00:00:00Z",
            "prevVersionDigest": {"sha256": "a" * 64},
            "roles": {"root": {"keyIds": ["k-0"], "threshold": 1}},
            "keys": {"k-0": {"publicKey": base64.b64encode(KEY.public_key().public_bytes_raw()).decode(),
                             "scheme": "ed25519"}},
            "nonClaims": ["signer output test pack"]}


def _claim():
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
                                threshold="0.65", score="0.92", n=500, model_id="acme/model-x",
                                dataset_id="acme/set", issuer=issuer_fingerprint(KEY),
                                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


def _holder_raw():
    return HOLDER.public_key().public_bytes_raw()


class _HolderSigner(_Signer):
    def sign(self, data):
        return self.ausgabe(HOLDER.sign(data))

    def public_key(self):
        return HOLDER.public_key()


#: name -> (producer of the output from a signer, error the producer refuses with, file:function of the site)
PRODUCERS = {
    "emit_bundle": (lambda s: emit_bundle(b"payload", s), BundleFormatError, "emit.py:emit_bundle"),
    "dsse.sign_envelope": (lambda s: dsse.sign_envelope(b"body", s, payload_type="application/vnd.test"),
                           BundleFormatError, "dsse.py:sign_envelope"),
    "sign_checkpoint": (lambda s: cp.sign_checkpoint("example.org/log", 3, bytes(range(32)), s, "example.org/log"),
                        BundleFormatError, "checkpoint.py:sign_checkpoint"),
    "cosign_checkpoint": (lambda s: cp.cosign_checkpoint(_note(), s, "witness.example", 1_780_000_000),
                          BundleFormatError, "checkpoint.py:cosign_checkpoint"),
    "issue_status_list_token": (lambda s: issue_status_list_token([0, 1], uri="https://example.org/sl", signer=s,
                                                                  iat=1_780_000_000),
                                BundleFormatError, "statuslist.py:issue_status_list_token"),
    "issue_enclave_attestation": (lambda s: issue_enclave_attestation(enclave_binding_for(emit_bundle(b"e", KEY)), s,
                                                                      profile="p", tier="affirming", exp=200),
                                  BundleFormatError, "experimental/enclave.py:issue_enclave_attestation"),
    "renewal ed25519": (lambda s: _sign_ats_content(b"content", "ed25519", {"ed25519": s}), RenewalError,
                        "renewal.py:_sign_ats_content"),
    "sign_trust_pack": (lambda s: sign_trust_pack(_pack_predicate(), {"k-0": s}), TrustPackError,
                        "trust_pack.py:sign_trust_pack"),
    "issue_sd_jwt": (lambda s: issue_sd_jwt(_claim(), s, root_b64="cm9vdA==", holder_public_key=_holder_raw()),
                     ValueError, "sdjwt_issue.py:issue_sd_jwt"),
}

#: The holder signs over the issuer's compact serialization; its signer is the holder's key.
HOLDER_PRODUCER = (lambda s: present_with_key_binding(
    issue_sd_jwt(_claim(), KEY, root_b64="cm9vdA==", holder_public_key=_holder_raw()), s, iat=1792000000,
    aud="https://rp.example", nonce="n1"), ValueError, "sdjwt_issue.py:present_with_key_binding")

def _gestaffelt(s):
    """``s`` as a view that is not contiguous: every second byte of a buffer twice as long."""
    speicher = bytearray(2 * len(s))
    speicher[::2] = s
    return memoryview(speicher)[::2]


def _freigegeben(s):
    sicht = memoryview(bytes(s))
    sicht.release()
    return sicht


class _NurBytes:
    """An object that exports no buffer and only answers ``bytes()`` (the first reader's ``bytes(...)`` ran it)."""

    def __init__(self, s):
        self.s = s

    def __bytes__(self):
        return bytes(self.s)


ODD = {
    "750,001 bytes": lambda s: b"s" * 750_001,
    "65 bytes": lambda s: s + b"\x00",
    "63 bytes": lambda s: s[:63],
    "a str of 64 characters": lambda s: "s" * 64,
    "an int": lambda s: 64,
    "a strided view of 65 bytes": lambda s: _gestaffelt(s + b"\x00"),
    "an array of 63 bytes": lambda s: array("B", s[:63]),
    "a released view": _freigegeben,
    "a list of the 64 byte values": lambda s: list(s),
    "an object with only __bytes__": _NurBytes,
}

#: The real signature in every buffer a producer took before the reader (pre-review 7).
ECHTE_FORMEN = {
    "bytes": lambda s: s,
    "bytearray": bytearray,
    "memoryview": memoryview,
    "a strided view": _gestaffelt,
    "an array of bytes": lambda s: array("B", s),
    "an array of 32 two-byte items": lambda s: array("H", s),
}


def _faelle():
    for name, (erzeuge, fehler, _ort) in PRODUCERS.items():
        yield name, erzeuge, fehler, _Signer
    yield "present_with_key_binding", HOLDER_PRODUCER[0], HOLDER_PRODUCER[1], _HolderSigner


FAELLE = list(_faelle())


@pytest.mark.parametrize("odd", sorted(ODD))
@pytest.mark.parametrize("name,erzeuge,fehler,signer_typ", FAELLE, ids=[f[0] for f in FAELLE])
def test_an_output_that_is_no_64_byte_signature_is_refused(name, erzeuge, fehler, signer_typ, odd):
    with pytest.raises(fehler, match="no 64-byte Ed25519 signature"):
        erzeuge(signer_typ(ODD[odd]))


@pytest.mark.parametrize("form", sorted(ECHTE_FORMEN))
@pytest.mark.parametrize("name,erzeuge,fehler,signer_typ", FAELLE, ids=[f[0] for f in FAELLE])
def test_control_the_real_signature_in_any_buffer_writes_what_the_real_key_writes(name, erzeuge, fehler, signer_typ,
                                                                                  form):
    assert erzeuge(signer_typ(ECHTE_FORMEN[form])) == erzeuge(HOLDER if signer_typ is _HolderSigner else KEY)


#: The two ML-DSA sites: one `.sign(` call each, outside the Ed25519 rule (their signature has another length).
AUSSERHALB = {"checkpoint.py:cosign_checkpoint_mldsa": 1, "pqsig.py:sign_mldsa": 1}
LESER = "_ed25519_signatur_von"


def _quellen():
    return {p.relative_to(SRC).as_posix(): p.read_text(encoding="utf-8") for p in sorted(SRC.rglob("*.py"))}


def _funktion_von(knoten, eltern):
    oben = knoten
    while oben in eltern:
        oben = eltern[oben]
        if isinstance(oben, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return oben.name
    return None


def _sign_aufrufe(datei, text):
    """Every `.sign(` call of a source by AST, as ("file:innermost function", read by the reader)."""
    baum = ast.parse(text)
    eltern = {kind: knoten for knoten in ast.walk(baum) for kind in ast.iter_child_nodes(knoten)}
    for k in ast.walk(baum):
        if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr == "sign"):
            continue
        e = eltern.get(k)
        gelesen = (isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == LESER
                   and len(e.args) == 1 and e.args[0] is k and not e.keywords)
        yield f"{datei}:{_funktion_von(k, eltern)}", gelesen


def _sign_ohne_aufruf(datei, text):
    """Every reference to `.sign` that is not the callee of a call on the spot, and every getattr(x, "sign")."""
    baum = ast.parse(text)
    eltern = {kind: knoten for knoten in ast.walk(baum) for kind in ast.iter_child_nodes(knoten)}
    ziele = {id(k.func) for k in ast.walk(baum) if isinstance(k, ast.Call)}
    for k in ast.walk(baum):
        alias = isinstance(k, ast.Attribute) and k.attr == "sign" and id(k) not in ziele
        dynamisch = (isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id == "getattr"
                     and len(k.args) >= 2 and isinstance(k.args[1], ast.Constant) and k.args[1].value == "sign")
        if alias or dynamisch:
            yield f"{datei}:{_funktion_von(k, eltern)}"


def _befund(quellen):
    """What breaks the rule, per call: unread Ed25519 calls, unlisted functions, and counts off the list."""
    gelistet = {ort for _e, _f, ort in PRODUCERS.values()} | {HOLDER_PRODUCER[2]}
    erwartet = Counter({ort: 1 for ort in gelistet}) + Counter(AUSSERHALB)
    gezaehlt, ungelesen, ohne_aufruf, mldsa = Counter(), [], [], Counter()
    for datei, text in quellen.items():
        for ort, gelesen in _sign_aufrufe(datei, text):
            gezaehlt[ort] += 1
            if ort not in AUSSERHALB and not gelesen:
                ungelesen.append(ort)
        ohne_aufruf.extend(_sign_ohne_aufruf(datei, text))
        mldsa.update(_mldsa_bezuege(datei, text))
    return {"ungelesen": sorted(ungelesen),
            "nicht_gelistet": sorted(set(gezaehlt) - set(erwartet)),
            "anzahl_falsch": sorted(ort for ort in erwartet if gezaehlt[ort] != erwartet[ort]),
            "sign_ohne_aufruf": sorted(ohne_aufruf),
            "mldsa_ausserhalb": sorted(f"{d}:{f}:{a}" for (d, f, a) in (mldsa - MLDSA_ERLAUBT) + (MLDSA_ERLAUBT - mldsa))}


LEER = {"ungelesen": [], "nicht_gelistet": [], "anzahl_falsch": [], "sign_ohne_aufruf": [], "mldsa_ausserhalb": []}

#: The two helpers that sign with ML-DSA, outside the Ed25519 rule, and the only places that refer to them today.
MLDSA_HELFER = ("sign_mldsa", "cosign_checkpoint_mldsa")
MLDSA_ERLAUBT = Counter({("renewal.py", None, "import"): 1, ("renewal.py", "_sign_ats_content", "aufruf"): 1})


def _mldsa_bezuege(datei, text):
    """Every reference to an ML-DSA helper outside its own definition, as (file, function, kind)."""
    baum = ast.parse(text)
    eltern = {kind: knoten for knoten in ast.walk(baum) for kind in ast.iter_child_nodes(knoten)}
    ziele = {id(k.func) for k in ast.walk(baum) if isinstance(k, ast.Call)}
    # A helper imported under another name is followed under that name too.
    namen = set(MLDSA_HELFER) | {a.asname for k in ast.walk(baum) if isinstance(k, ast.ImportFrom)
                                 for a in k.names if a.name in MLDSA_HELFER and a.asname}
    for k in ast.walk(baum):
        if isinstance(k, ast.ImportFrom):
            for a in k.names:
                if a.name in MLDSA_HELFER:
                    yield (datei, _funktion_von(k, eltern), "import" if a.asname is None else "import_als")
        name = k.id if isinstance(k, ast.Name) else (k.attr if isinstance(k, ast.Attribute) else None)
        if name in namen:
            yield (datei, _funktion_von(k, eltern), "aufruf" if id(k) in ziele else "bezug")
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id == "getattr" and len(k.args) >= 2
                and isinstance(k.args[1], ast.Constant) and k.args[1].value in MLDSA_HELFER):
            yield (datei, _funktion_von(k, eltern), "getattr")


def test_the_list_binds_every_ed25519_signing_call_to_the_reader():
    """Twelve `.sign(` calls: each of the ten Ed25519 ones is the one argument of the reader, in a listed function
    with exactly one call; the two ML-DSA ones stand where they are named."""
    assert sum(1 for d, t in _quellen().items() for _ in _sign_aufrufe(d, t)) == 12
    assert _befund(_quellen()) == LEER


def _mutiert(datei, alt, neu):
    quellen = _quellen()
    assert quellen[datei].count(alt) == 1, alt
    quellen[datei] = quellen[datei].replace(alt, neu)
    return quellen


def test_mutation_a_missing_reader_in_a_file_with_other_readers_is_found():
    quellen = _mutiert("checkpoint.py", "sig = _ed25519_signatur_von(witness_signer.sign(",
                       "sig = (witness_signer.sign(")
    assert _befund(quellen)["ungelesen"] == ["checkpoint.py:cosign_checkpoint"]


def test_mutation_a_second_unread_call_inside_a_listed_function_is_found():
    zeile = "    sig = _ed25519_signatur_von(signer.sign(pae(payload_type, body)))\n"
    quellen = _mutiert("dsse.py", zeile, zeile + "    zweite = signer.sign(pae(payload_type, body))\n")
    befund = _befund(quellen)
    assert befund["ungelesen"] == ["dsse.py:sign_envelope"]
    assert befund["anzahl_falsch"] == ["dsse.py:sign_envelope"]


def test_mutation_a_new_unlisted_producer_is_found_even_when_it_reads_its_output():
    quellen = _quellen()
    quellen["dsse.py"] += "\n\ndef neu(signer):\n    return _ed25519_signatur_von(signer.sign(b\"x\"))\n"
    assert _befund(quellen) == {**LEER, "nicht_gelistet": ["dsse.py:neu"]}


def test_mutation_a_second_signature_through_an_alias_is_found():
    """Pre-review 8: the second signature of dsse.sign_envelope through ``weiter = signer.sign``."""
    zeile = "    sig = _ed25519_signatur_von(signer.sign(pae(payload_type, body)))\n"
    quellen = _mutiert("dsse.py", zeile, zeile + "    weiter = signer.sign\n    zweite = bytes(weiter(pae(payload_type, body)))\n")
    assert _befund(quellen) == {**LEER, "sign_ohne_aufruf": ["dsse.py:sign_envelope"]}


def test_mutation_a_signing_method_read_by_getattr_is_found():
    zeile = "    sig = _ed25519_signatur_von(signer.sign(pae(payload_type, body)))\n"
    quellen = _mutiert("dsse.py", zeile, zeile + '    zweite = getattr(signer, "sign")(pae(payload_type, body))\n')
    assert _befund(quellen) == {**LEER, "sign_ohne_aufruf": ["dsse.py:sign_envelope"]}


class _Zaehler:
    """Returns the real signature on the first call and 750,001 bytes on every later call, and counts the calls."""

    def __init__(self, schluessel):
        self.schluessel = schluessel
        self.aufrufe = 0

    def sign(self, data):
        self.aufrufe += 1
        return self.schluessel.sign(data) if self.aufrufe == 1 else b"s" * 750_001

    def public_key(self):
        return self.schluessel.public_key()


@pytest.mark.parametrize("name,erzeuge,fehler,signer_typ", FAELLE, ids=[f[0] for f in FAELLE])
def test_every_producer_asks_its_signer_exactly_once(name, erzeuge, fehler, signer_typ):
    schluessel = HOLDER if signer_typ is _HolderSigner else KEY
    zaehler = _Zaehler(schluessel)
    assert erzeuge(zaehler) == erzeuge(schluessel)
    assert zaehler.aufrufe == 1


def test_mutation_the_ml_dsa_helper_with_a_second_signer_is_found():
    """Pre-review 9: dsse.sign_envelope appends a second signature through pqsig.sign_mldsa and a signer of its own."""
    zeile = "    sig = _ed25519_signatur_von(signer.sign(pae(payload_type, body)))\n"
    quellen = _mutiert("dsse.py", zeile, zeile + "    zweite = _sign_other(_SecondSigner(), pae(payload_type, body))\n")
    quellen["dsse.py"] = "from .pqsig import sign_mldsa as _sign_other\n" + quellen["dsse.py"]
    befund = _befund(quellen)
    assert befund["mldsa_ausserhalb"] == ["dsse.py:None:import_als", "dsse.py:sign_envelope:aufruf"], befund
    assert {k: v for k, v in befund.items() if k != "mldsa_ausserhalb"} == {k: v for k, v in LEER.items() if k != "mldsa_ausserhalb"}


#: The length of each producer's output for the fixed inputs above, in bytes of its serialization (bytes as they are,
#: str as UTF-8, a dict as compact sorted JSON), measured over five key pairs on 9 November 2026 before this test.
ERWARTETE_LAENGE = {"emit_bundle": 404, "dsse.sign_envelope": 234, "sign_checkpoint": 177, "cosign_checkpoint": 302,
                    "issue_status_list_token": 281, "issue_enclave_attestation": 285, "renewal ed25519": 104,
                    "sign_trust_pack": 1039, "issue_sd_jwt": 593, "present_with_key_binding": 887}


def _laenge(ausgabe):
    if isinstance(ausgabe, (bytes, bytearray)):
        return len(ausgabe)
    if isinstance(ausgabe, str):
        return len(ausgabe.encode("utf-8"))
    return len(json.dumps(ausgabe, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


@pytest.mark.parametrize("name,erzeuge,fehler,signer_typ", FAELLE, ids=[f[0] for f in FAELLE])
def test_every_producer_writes_the_length_measured_before(name, erzeuge, fehler, signer_typ):
    schluessel = HOLDER if signer_typ is _HolderSigner else KEY
    assert set(ERWARTETE_LAENGE) == {f[0] for f in FAELLE}
    assert _laenge(erzeuge(schluessel)) == ERWARTETE_LAENGE[name]
    assert _laenge(erzeuge(_Zaehler(schluessel))) == ERWARTETE_LAENGE[name]
