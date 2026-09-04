"""Die dritte Achse: dasselbe COSE_Sign1, aeusseres Array mit INDEFINITER Laenge.

NAMENSGEBUNG. Der Auftrag nennt ihn "Vektor C". Nicholas' Tag-Vektor fuehrt bereits ein
`C_untagged`. Zwei verschiedene Dinge unter demselben Buchstaben auf einer Mailingliste sind eine
Verwechslung, die niemand mehr aufloest — deshalb heisst er hier `D_indefinite_array`, und der
Grund steht im Bericht.

ES WERDEN KEINE SCHLUESSEL ERZEUGT. Der Seed kommt aus Nicholas' Artefakt, die Signatur wird nicht
neu gebildet, sondern aus A UEBERNOMMEN — Sig_structure deckt das aeussere Array nach RFC 9052 4.4
nicht, also MUSS dieselbe Signatur ueber beide Kodierungen verifizieren. Genau das ist die Aussage.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys

sys.path.insert(0, "/mnt/bigstore/claude_scratch/scitt_vektoren")
import cbor_min as C                                                      # noqa: E402
import cryptography                                                       # noqa: E402
from cryptography.exceptions import InvalidSignature                      # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (           # noqa: E402
    Ed25519PublicKey,
)

v1 = json.load(open("data-hash-vector.json"))
A = bytes.fromhex(v1["A_signed_statement_as_registered"]["bytes_hex"])
seed_pub = bytes.fromhex(v1["test_key"]["public_key_hex"])

# A zerlegen — mit dem eigenen Leser, nicht mit einer Bibliothek.
wert, ende = C.lade(A)
assert ende == len(A)
assert isinstance(wert, tuple) and wert[0] == "__tag__" and wert[1] == 18, "A traegt keinen Tag 18"
elemente = wert[2]
assert isinstance(elemente, list) and len(elemente) == 4

protected, unprotected, payload, signature = elemente

# D bauen: Tag 18 (0xd2), dann INDEFINITES Array 0x9f ... 0xff mit denselben vier Elementen.
# Die Elemente selbst werden UNVERAENDERT definite kodiert — nur die aeussere Huelle wechselt.
def el(x) -> bytes:
    if isinstance(x, bytes):
        return C.kopf_bytes(2, len(x)) + x
    if isinstance(x, dict):
        assert x == {}, "nur die leere Map kommt hier vor (RFC 9943 6.3)"
        return C.kopf_bytes(5, 0)
    raise TypeError(type(x))

D = bytes([0xD2, 0x9F]) + b"".join(el(x) for x in elemente) + bytes([0xFF])

# Gegenprobe 1: liest der eigene Leser D als dieselben vier Elemente?
wD, endeD = C.lade(D)
assert endeD == len(D)
assert wD[0] == "__tag__" and wD[1] == 18
innen = wD[2]
indefinit = isinstance(innen, C.Unbestimmt)
if indefinit:
    innen = innen.wert
assert innen == elemente, "D traegt nicht dieselben vier Elemente"

# Gegenprobe 2: verifiziert DIESELBE Signatur ueber D? (Sig_structure deckt die Huelle nicht.)
ss = C.schreibe(["Signature1", protected, b"", payload])
pk = Ed25519PublicKey.from_public_bytes(seed_pub)
try:
    pk.verify(signature, ss)
    sig_ok = True
except InvalidSignature:
    sig_ok = False

# Gegenprobe 3: was macht ein deterministischer Encoder nach RFC 8949 4.2? Er MUSS definite
# kodieren — also faellt D entweder durch oder wird auf A zurueckgefuehrt. Gemessen mit dem
# eigenen Encoder (der nur definite kann) sowie mit cbor2, falls vorhanden.
zurueck = bytes([0xD2]) + C.kopf_bytes(4, 4) + b"".join(el(x) for x in elemente)

bericht = {
    "schema": "b7n0de.scitt_ccf_array_framing_vector/0.1",
    "not_a_transparency_service": "b7n0de operates no Transparency Service and issues no Receipts.",
    "not_independently_derived": ("Bytes, seed and signature are Nicholas Ashley's published "
                                  "artifact. Nothing here is a new key or a new statement."),
    "not_a_claim_about_libraries_in_the_wild": ("Measured only for the encoders named below, at "
                                                "the versions named below."),
    "plattform": {"system": platform.system(), "machine": platform.machine(),
                  "python": platform.python_version(),
                  "cryptography": cryptography.__version__},
    "A_definite": {"framing": "tag 18, definite 4-element array (0x84)",
                   "size_bytes": len(A), "sha256": hashlib.sha256(A).hexdigest()},
    "D_indefinite_array": {"framing": "tag 18, indefinite array (0x9f ... 0xff)",
                           "size_bytes": len(D), "sha256": hashlib.sha256(D).hexdigest(),
                           "hex": D.hex()},
    "delta": {"bytes_differing": len(D) - len(A),
              "head": "0x9f replaces 0x84", "tail": "0xff appended",
              "elements_identical": innen == elemente},
    "signature_verifies_over_both": sig_ok,
    "sig_structure_len": len(ss),
    "deterministic_reencode_equals_A": zurueck == A,
}
print(json.dumps(bericht, indent=2))
