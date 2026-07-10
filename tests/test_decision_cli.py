"""WP4 tests: `proofbundle decision {init,emit,verify,inspect}` CLI + --version predicates line.

Exercises the exit-code contract (0 ok / 1 crypto fail / 2 malformed) end to end through cli.main()."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from proofbundle.cli import main
from proofbundle.emit import generate_signer, save_signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _pub_b64_for(keyfile: Path) -> str:
    from proofbundle.emit import load_signer
    s = load_signer(str(keyfile))
    return base64.b64encode(s.public_key().public_bytes_raw()).decode()


def test_version_lists_predicates(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "predicates: eval-result/v0.1 decision-receipt/v0.1" in out


def test_init_emits_valid_template(capsys):
    assert main(["decision", "init"]) == 0
    template = json.loads(capsys.readouterr().out)
    from proofbundle.decision import validate_decision_predicate
    assert validate_decision_predicate(template, strict=True) == []


def test_emit_verify_roundtrip(tmp_path, capsys):
    keyfile = tmp_path / "signer.bin"
    save_signer(generate_signer(), str(keyfile))
    receipt = tmp_path / "r.json"
    rc_emit = main(["decision", "emit", str(EXAMPLES / "decision_receipt_deny.json"),
                    "--out", str(receipt), "--key", str(keyfile)])
    assert rc_emit == 0 and receipt.is_file()
    capsys.readouterr()
    rc_verify = main(["decision", "verify", str(receipt), "--pub", _pub_b64_for(keyfile), "--strict"])
    assert rc_verify == 0
    out = capsys.readouterr().out
    assert "CRYPTO: OK" in out and "POLICY: NOT_EVALUATED" in out and "STRUCTURE: OK" in out


def test_verify_wrong_key_exit_1(tmp_path, capsys):
    keyfile = tmp_path / "signer.bin"
    save_signer(generate_signer(), str(keyfile))
    receipt = tmp_path / "r.json"
    main(["decision", "emit", str(EXAMPLES / "decision_receipt_deny.json"), "--out", str(receipt), "--key", str(keyfile)])
    capsys.readouterr()
    other = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode()
    assert main(["decision", "verify", str(receipt), "--pub", other]) == 1


def test_verify_malformed_exit_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    assert main(["decision", "verify", str(bad), "--pub", "AAAA"]) == 2


def test_inspect_prints_predicate(tmp_path, capsys):
    keyfile = tmp_path / "signer.bin"
    save_signer(generate_signer(), str(keyfile))
    receipt = tmp_path / "r.json"
    main(["decision", "emit", str(EXAMPLES / "decision_receipt_escalate.json"), "--out", str(receipt), "--key", str(keyfile)])
    capsys.readouterr()
    assert main(["decision", "inspect", str(receipt)]) == 0
    predicate = json.loads(capsys.readouterr().out)
    assert predicate["decision"]["verdict"] == "ESCALATE"


def test_emit_json_matches_receipt_module(tmp_path):
    # the CLI-emitted receipt verifies through the library verify path too
    keyfile = tmp_path / "signer.bin"
    save_signer(generate_signer(), str(keyfile))
    receipt = tmp_path / "r.json"
    main(["decision", "emit", str(EXAMPLES / "decision_receipt_allow.json"), "--out", str(receipt), "--key", str(keyfile)])
    from proofbundle.decision import verify_decision_receipt
    env = json.loads(receipt.read_text())
    pub = base64.b64decode(_pub_b64_for(keyfile))
    assert verify_decision_receipt(env, pub, strict=True)["crypto_ok"] is True
