"""Erwartung am Kopf 8626618: GRUEN.

Die Tests messen die benannte Einheit: ``input_bytes`` zaehlt UTF-8-Bytes und
nicht Python-Codepoints. Zusaetzlich urteilen Python und der unabhaengige
Rust-Verifizierer ueber exakt dieselben DSSE-Bytes gleich, auch wenn Unicode
die Codepoint- und Byte-Laengen auseinanderzieht.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle._strict_json import loads_strict
from proofbundle.budget import BudgetExceeded, VerificationBudget
from proofbundle.dsse import sign_envelope, verify_envelope
from proofbundle.errors import BundleFormatError


ROOT = Path(__file__).resolve().parents[1]
RUST_MANIFEST = ROOT / "tools" / "pb_verify_rs" / "Cargo.toml"
# BEIDE Profile, wie `tests/test_relation_statement_rust_parity.py` es schon tut. Release zuerst,
# weil CI dieses Profil baut.
RUST_BIN_RELEASE = ROOT / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"
RUST_BIN_DEBUG = ROOT / "tools" / "pb_verify_rs" / "target" / "debug" / "pb_verify_rs"


def test_input_bytes_uses_encoded_bytes_not_codepoints():
    budget = VerificationBudget(input_bytes=16)
    ascii_document = json.dumps("a" * 12, ensure_ascii=False)
    multibyte_document = json.dumps("é" * 12, ensure_ascii=False)
    assert len(ascii_document) == len(multibyte_document)
    assert len(ascii_document.encode()) <= budget.input_bytes
    assert len(multibyte_document.encode()) > budget.input_bytes
    assert loads_strict(ascii_document, budget=budget) == "a" * 12
    with pytest.raises(BudgetExceeded) as caught:
        loads_strict(multibyte_document, budget=budget)
    assert caught.value.dimension == "input_bytes"


@pytest.fixture(scope="module")
def rust_verifier() -> Path:
    """Der gebaute Verifizierer, egal unter welchem Cargo-Profil er liegt.

    GEAENDERT VON DER JURY (un_echoXX, 09.09.2026), und der Grund ist genau die Klasse, die
    diese Datei prueft. Die eingereichte Fassung band an EINE PFADFORM (`target/debug`) statt
    an die Eigenschaft "ein gebauter Verifizierer ist da". CI dieses Repos baut
    `cargo build --release` (ci.yml Zeilen 52 und 132) — dort liegt also nur das
    Release-Erzeugnis. GEMESSEN am Kopf 7621f69, Ansage vorher genannt und exakt getroffen:
    mit vorhandenem Release-Erzeugnis und entferntem Debug-Erzeugnis meldete die alte Fassung
    `1 passed, 2 skipped`. Der Differentialtest waere in genau dem Lauf still ausgefallen, fuer
    den er gebaut ist, und die Suite haette gruen gemeldet.

    ZWEITE AENDERUNG: nicht mehr BAUEN im Test. Das Haus hat dafuer eine Naht
    (`tests/test_relation_statement_rust_parity.py`): Binaerdatei da oder ehrlich uebersprungen,
    kein Bauversuch in der Testlaufzeit. Ein `cargo build` im Test macht das Verdikt von Netz,
    Cache und Werkzeugkette abhaengig, und sein Fehlschlag wird zu einem stillen SKIP — dieselbe
    Klasse noch einmal. Wer den Differentialtest laufen sehen will, baut vorher:
    `cargo build --release --manifest-path tools/pb_verify_rs/Cargo.toml`.
    """
    for kandidat in (RUST_BIN_RELEASE, RUST_BIN_DEBUG):
        if kandidat.exists():
            return kandidat
    pytest.skip("pb_verify_rs nicht gebaut (cargo build --release --manifest-path "
                f"{RUST_MANIFEST.relative_to(ROOT)}) — Differential ehrlich ungemessen, nie gruen")
    raise AssertionError("unerreichbar")   # nur fuer den Typpruefer


@pytest.mark.parametrize("surplus_padding", [False, True], ids=["canonical", "surplus-padding"])
def test_python_and_rust_give_the_same_verdict_for_the_same_unicode_dsse_bytes(
    rust_verifier: Path, tmp_path: Path, surplus_padding: bool
):
    signer = Ed25519PrivateKey.generate()
    public_key = signer.public_key().public_bytes_raw()
    envelope = sign_envelope("vier Bytes: 🧪".encode(), signer, payload_type="typ/ä")
    if surplus_padding:
        envelope["payload"] += "="

    try:
        python_ok = verify_envelope(envelope, public_key)
    except BundleFormatError:
        python_ok = False
    envelope_path = tmp_path / "envelope.json"
    envelope_path.write_bytes(json.dumps(envelope, ensure_ascii=False).encode())
    rust = subprocess.run(
        [str(rust_verifier), "verify-dsse", str(envelope_path), base64.b64encode(public_key).decode()],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    rust_ok = rust.returncode == 0
    assert python_ok is rust_ok
    assert python_ok is (not surplus_padding)
