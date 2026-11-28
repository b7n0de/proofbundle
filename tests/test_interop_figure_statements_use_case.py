"""The third-party use case of the 716 figure statements, and its negative case, checked by its own checker.

interop/scitt-statement-identification-04/use-cases/figure-statements-20261125/ holds the statements, the two lists and
the key as fetched on 2026-11-25 (see its README). This test runs check_figure_statements.py on that folder and on
three changed copies of it, so that each part of the check is shown to fail when its input is wrong: a statement byte
changed, the issued_in_error mark removed from the list, and another key.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "interop/scitt-statement-identification-04/use-cases/figure-statements-20261125"


def _checker():
    spec = importlib.util.spec_from_file_location("figure_statements_checker", FOLDER / "check_figure_statements.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _failed(results) -> list[str]:
    return [name for name, good, _ in results if not good]


def test_every_check_of_the_use_case_gives_its_expected_result():
    results = _checker().check(FOLDER)
    assert _failed(results) == []
    assert sum(1 for name, _, _ in results if name.startswith("statement ")) == 716
    assert len(results) == 716 + 1 + 5


@pytest.fixture()
def copy(tmp_path):
    target = tmp_path / "case"
    shutil.copytree(FOLDER, target)
    return target


def test_gate_meta_a_changed_byte_in_one_statement_fails_its_check(copy):
    path = copy / "statements" / "conv-national-denial-rate-2025.cose"
    raw = bytearray(path.read_bytes())
    raw[-70] ^= 0x01  # a payload byte before the 64 signature bytes
    path.write_bytes(bytes(raw))
    assert _failed(_checker().check(copy)) == ["statement conv-national-denial-rate-2025"]


def test_gate_meta_without_the_mark_the_negative_case_is_not_rejected(copy):
    path = copy / "lists" / "statement-digests-sequence-3.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for entry in data["digests"]["metro-gap-fort-wayne-in-2025"]:
        entry.pop("issued_in_error", None)
    path.write_text(json.dumps(data), encoding="utf-8")
    checker = _checker()
    assert _failed(checker.check(copy)) == ["negative: marked issued_in_error at sequence 3, not accepted"]
    assert checker.list_state(data, "metro-gap-fort-wayne-in-2025", checker.NEGATIVE_DIGEST) == "superseded"


def test_gate_meta_another_key_fails_every_signature(copy):
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    path = copy / "statement-key.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    def b64(value: int) -> str:
        import base64
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()
    data["public_jwk"]["x"], data["public_jwk"]["y"] = b64(numbers.x), b64(numbers.y)
    path.write_text(json.dumps(data), encoding="utf-8")
    failed = _failed(_checker().check(copy))
    assert len([name for name in failed if name.startswith("statement ")]) == 716
    assert "negative: ES256 valid under the publisher's key" in failed
