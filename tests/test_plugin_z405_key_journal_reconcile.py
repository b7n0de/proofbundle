"""D65, follow-up note 25, owner choice of 2026-10-17 on O24-1: the key signer's journal in the records and in the
reconciliation.

At the end of each window the key account exports its journal with its sha256 into keysigner/ of the records
(`key_signer.py --export`), a folder only it writes: it owns the folder, no other account may write it, and its parent
belongs to root or to it and is writable by no one else or carries the sticky bit. reconcile.py reads the journal
there, checked against that sha256, and names two counts of its own: signed lines without a receipt and receipts
without a signed line. Either not 0 ends it with KEY_JOURNAL_DISAGREES; a journal the records do not keep as exported
ends it with KEY_JOURNAL_NOT_READ. The comparison by hand stays the way back.

The export runs anywhere; the reconciliation needs the decision verifier of main 22aa954e (verify_decision_receipt
with now=), as tests/test_plugin_z405_reconcile.py does, and skips where the interpreter's proofbundle lacks it. RED
at e484002d, where the key signer has no export and the reconciliation reads no journal.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import test_plugin_gate_n2c_push_done as pd
import test_plugin_z405_decision_receipt as p1
import test_plugin_z405_key_signer as ks
import test_plugin_z405_signer_service as s

gate = pd.gate
k = ks.k
RECONCILE = ks.PILOT / "reconcile.py"


def _has_now() -> bool:
    try:
        from proofbundle.decision import verify_decision_receipt
    except ImportError:
        return False
    return "now" in inspect.signature(verify_decision_receipt).parameters


needs_verifier = pytest.mark.skipif(not _has_now(), reason="the reconciliation needs the decision verifier of main "
                                    "22aa954e (verify_decision_receipt with now=); this proofbundle does not have it")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return pd.env.__wrapped__(tmp_path, monkeypatch)


def export(config: pathlib.Path, folder: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(ks.KEY_SIGNER), "--config", str(config), "--export", str(folder)],
                          capture_output=True, text=True, timeout=60, check=False)


def keysigner_folder(records: pathlib.Path) -> pathlib.Path:
    folder = records / "keysigner"
    folder.mkdir(mode=0o755, exist_ok=True)
    folder.chmod(0o755)
    return folder


def reconcile(records: pathlib.Path) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, str(RECONCILE), "--records", str(records)], capture_output=True, text=True,
                          timeout=300, check=False)
    path = records / "reconciliation" / "reconciliation.json"
    assert path.exists(), (proc.returncode, proc.stderr)
    return proc.returncode, json.loads(path.read_text(encoding="utf-8"))["keyJournal"]


def decided(env, tmp_path) -> s.Service:
    """Records with one receipt the service had signed by the key signer: the comment the gate asks."""
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert len(p1.receipts_in(service.records)) == 1
    return service


# --- the export ---------------------------------------------------------------------------------------------------

def test_the_export_copies_the_journal_with_its_sha256(env, tmp_path):
    key = ks.Key(tmp_path)
    ks.run_key_signer(key.config, ks.request_of(gate._pilot_canonical(ks.statement(env))))
    folder = tmp_path / "records" / "keysigner"
    folder.parent.mkdir()
    folder.mkdir(mode=0o755)
    proc = export(key.config, folder)
    assert proc.returncode == 0, proc
    data = key.journal.read_bytes()
    assert (folder / "journal.jsonl").read_bytes() == data
    document = json.loads((folder / "export.json").read_text(encoding="ascii"))
    assert document == {**document, "schema": "proofbundle/pilot-key-journal-export/v1", "file": "journal.jsonl",
                        "sha256": hashlib.sha256(data).hexdigest(), "lines": 2}
    assert json.loads(proc.stdout) == document
    assert sorted(p.name for p in folder.iterdir()) == ["export.json", "journal.jsonl"]


def test_an_export_before_the_first_signature_is_an_empty_journal(env, tmp_path):
    key = ks.Key(tmp_path)
    folder = tmp_path / "keysigner"
    folder.mkdir(mode=0o755)
    assert export(key.config, folder).returncode == 0
    assert (folder / "journal.jsonl").read_bytes() == b""
    assert json.loads((folder / "export.json").read_text())["sha256"] == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("case", ["folder writable by others", "folder writable by its group", "parent writable by "
                                  "others without the sticky bit", "a link in the folder's place", "a relative path",
                                  "no folder"])
def test_the_export_goes_only_where_no_other_account_writes(env, tmp_path, case):
    key = ks.Key(tmp_path)
    parent = tmp_path / "records"
    parent.mkdir(mode=0o755)
    folder = parent / "keysigner"
    target = folder
    if case == "folder writable by others":
        folder.mkdir()
        folder.chmod(0o757)
    elif case == "folder writable by its group":
        folder.mkdir()
        folder.chmod(0o775)
    elif case == "parent writable by others without the sticky bit":
        folder.mkdir(mode=0o755)
        parent.chmod(0o777)
    elif case == "a link in the folder's place":
        (tmp_path / "elsewhere").mkdir(mode=0o755)
        folder.symlink_to(tmp_path / "elsewhere")
    elif case == "a relative path":
        folder.mkdir(mode=0o755)
        target = pathlib.Path(os.path.relpath(folder))
    proc = export(key.config, target)
    assert (proc.returncode, proc.stdout.strip()) == (3, "export_folder_unsafe"), proc
    assert not (folder / "export.json").exists() and not (tmp_path / "elsewhere" / "export.json").exists()


def test_a_parent_with_the_sticky_bit_takes_the_export(env, tmp_path):
    key = ks.Key(tmp_path)
    parent = tmp_path / "records"
    parent.mkdir()
    parent.chmod(0o1777)
    folder = parent / "keysigner"
    folder.mkdir(mode=0o755)
    assert export(key.config, folder).returncode == 0
    assert (folder / "export.json").is_file()


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to give the folder to another "
                    "account")
def test_a_folder_another_account_owns_takes_no_export(env, tmp_path):
    key = ks.Key(tmp_path)
    folder = tmp_path / "keysigner"
    folder.mkdir(mode=0o755)
    os.chown(folder, 65534, 65534)
    proc = export(key.config, folder)
    assert (proc.returncode, proc.stdout.strip()) == (3, "export_folder_unsafe"), proc


# --- the reconciliation -------------------------------------------------------------------------------------------

@needs_verifier
def test_complete_pairs_give_0_and_0(env, tmp_path):
    service = decided(env, tmp_path)
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    code, journal = reconcile(service.records)
    assert code == 0, journal
    assert journal == {**journal, "read": True, "signed": 1, "signedWithoutReceipt": 0, "receiptsWithoutSignedLine": 0,
                       "notHandedOut": 0, "unconfirmed": 0, "unreadableLines": 0}


@needs_verifier
def test_a_signed_line_without_receipt_gives_1_and_its_own_exit(env, tmp_path):
    """The deciding account, held, has the key signer sign a statement of its own: no receipt carries it."""
    service = decided(env, tmp_path)
    body = gate._pilot_canonical(ks.statement(env, verdict="ALLOW"))
    assert ks.run_key_signer(service.key_config, ks.request_of(body)).returncode == 0
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    code, journal = reconcile(service.records)
    assert code == 3 and (journal["signedWithoutReceipt"], journal["receiptsWithoutSignedLine"]) == (1, 0), journal
    assert journal["signedWithoutReceiptLines"] == [{"decisionId": json.loads(body)["predicate"]["decisionId"],
                                                     "statementSha256": hashlib.sha256(body).hexdigest()}]


@needs_verifier
def test_a_receipt_without_signed_line_gives_1_and_its_own_exit(env, tmp_path):
    """The journal was exported before the decision: its receipt has no line in the export."""
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    code, journal = reconcile(service.records)
    assert code == 3 and (journal["signedWithoutReceipt"], journal["receiptsWithoutSignedLine"]) == (0, 1), journal
    (envelope_file,) = (service.records / "decisions").glob("*.json")
    assert journal["receiptsWithoutSignedLineFiles"] == [f"decisions/{envelope_file.name}"]


@needs_verifier
def test_a_changed_receipt_gives_1_and_1(env, tmp_path):
    service = decided(env, tmp_path)
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    (path,) = (service.records / "decisions").glob("*.json")
    envelope = json.loads(path.read_text())
    raw = bytearray(base64.b64decode(envelope["payload"]))
    raw[raw.index(b"ESCALATE")] = ord("D")
    envelope["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    path.write_text(json.dumps(envelope), encoding="utf-8")
    code, journal = reconcile(service.records)
    assert code == 3 and (journal["signedWithoutReceipt"], journal["receiptsWithoutSignedLine"]) == (1, 1), journal


@needs_verifier
def test_a_signature_that_never_left_is_counted_apart(env, tmp_path):
    """A signed line whose second line says handedOut false: recognizable, not a signature without receipt."""
    service = decided(env, tmp_path)
    proc = subprocess.Popen([sys.executable, "-I", str(ks.KEY_SIGNER), "--config", str(service.key_config)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc.stdout.close()
    proc.stdin.write(json.dumps(ks.request_of(gate._pilot_canonical(ks.statement(env)))).encode("ascii"))
    proc.stdin.close()
    assert proc.wait(timeout=60) == 3
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    code, journal = reconcile(service.records)
    assert code == 0 and (journal["signed"], journal["notHandedOut"], journal["signedWithoutReceipt"]) == (2, 1, 0), \
        journal


@needs_verifier
def test_a_line_without_its_handout_counts_as_handed_out(env, tmp_path):
    """Unconfirmed: the signed line stands alone (the key signer was stopped after it); it counts as handed out."""
    service = decided(env, tmp_path)
    body = gate._pilot_canonical(ks.statement(env))
    line = {"at": "2026-10-17T00:00:00Z", "signed": True, "reason": None, "elapsedMs": 1,
            "decisionId": json.loads(body)["predicate"]["decisionId"], "statementSha256": hashlib.sha256(body).hexdigest()}
    with open(service.key_journal, "a", encoding="ascii") as handle:
        handle.write(json.dumps(line) + "\n")
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    code, journal = reconcile(service.records)
    assert code == 3 and (journal["unconfirmed"], journal["signedWithoutReceipt"]) == (1, 1), journal


@needs_verifier
def test_records_without_the_export_are_not_read(env, tmp_path):
    service = decided(env, tmp_path)
    code, journal = reconcile(service.records)
    assert code == 4 and journal == {"read": False, "why": "not in the records",
                                     "signedWithoutReceipt": "not measured",
                                     "receiptsWithoutSignedLine": "not measured"}, journal


@needs_verifier
@pytest.mark.parametrize("change", ["a line taken out", "the export's digest", "the journal gone"])
def test_a_journal_that_is_not_the_exported_bytes_is_not_read(env, tmp_path, change):
    service = decided(env, tmp_path)
    folder = keysigner_folder(service.records)
    assert export(service.key_config, folder).returncode == 0
    if change == "a line taken out":
        lines = (folder / "journal.jsonl").read_text().splitlines(keepends=True)
        (folder / "journal.jsonl").write_text("".join(lines[1:]))
    elif change == "the export's digest":
        document = json.loads((folder / "export.json").read_text())
        (folder / "export.json").write_text(json.dumps({**document, "sha256": "0" * 64}))
    else:
        (folder / "journal.jsonl").unlink()
    code, journal = reconcile(service.records)
    assert code == 4 and journal["read"] is False, journal
    assert journal["why"] == "the journal differs from the sha256 of its export"


@needs_verifier
def test_a_line_cut_short_is_counted_and_reads_as_no_signature(env, tmp_path):
    service = decided(env, tmp_path)
    with open(service.key_journal, "ab") as handle:
        handle.write(b'{"signed": tr')
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    code, journal = reconcile(service.records)
    assert code == 0 and journal["unreadableLines"] == 1, journal


@needs_verifier
def test_a_copy_of_the_records_gives_the_same_bytes(env, tmp_path):
    service = decided(env, tmp_path)
    assert export(service.key_config, keysigner_folder(service.records)).returncode == 0
    code, _ = reconcile(service.records)
    copy = tmp_path / "elsewhere" / "records"
    shutil.copytree(service.records, copy, ignore=shutil.ignore_patterns("reconciliation"))
    again, _ = reconcile(copy)
    assert code == again == 0
    assert (service.records / "reconciliation" / "reconciliation.json").read_bytes() == \
        (copy / "reconciliation" / "reconciliation.json").read_bytes()
