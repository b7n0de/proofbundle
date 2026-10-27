"""D65, follow-up note 25, T4-a: no signature leaves the key signer, nor the service, without a durable journal line.

Before, the key signer signed and wrote its journal line afterwards, and a journal it could not write was passed over
(`except OSError: pass`): on a full disk or with its rights taken away there was a signature without a line, while D64
and the reconciliation of the key signer's journal rest on every signature having one. Now the line that names a
signature (decisionId, sha256 of the statement, time) is written and synced to the disk before the signature is
written on stdout; a journal that cannot be written gives no signature and the name journal_unwritable, which the
service passes on as key_journal_unwritable. A second line says whether stdout took the signature (`handedOut`). The
service keeps the same rule for its own journal.

The journal is made unwritable here as a full disk (/dev/full, ENOSPC), as a file at the size limit (RLIMIT_FSIZE, the
same as a full disk for a regular file), as a folder in the journal's place, and as a refused open (EACCES) inside the
process; a read-only file and a folder without rights need an account that is not root, so they run only there and
the probe of the delivery measures them with the real accounts. RED at 1a0624a0, the head of Teil 4.
"""
from __future__ import annotations

import base64
import errno
import io
import json
import os
import pathlib
import resource
import subprocess
import sys

import pytest

import test_plugin_gate_n2c_push_done as pd
import test_plugin_z405_decision_receipt as p1
import test_plugin_z405_key_signer as ks
import test_plugin_z405_signer_service as s

gate = pd.gate
k = ks.k
ROOT_ONLY_BYPASS = hasattr(os, "geteuid") and os.geteuid() == 0


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path):
    return pd.env.__wrapped__(tmp_path)


def key_with_journal(tmp_path: pathlib.Path, journal: str) -> ks.Key:
    key = ks.Key(tmp_path)
    config = json.loads(key.config.read_text(encoding="utf-8"))
    key.config.write_text(json.dumps({**config, "journal": journal}), encoding="utf-8")
    key.journal = pathlib.Path(journal)
    return key


def request(env) -> dict:
    return ks.request_of(gate._pilot_canonical(ks.statement(env)))


def assert_no_signature(proc: subprocess.CompletedProcess, name: str = "journal_unwritable") -> None:
    """Exit 3, the one name on stdout and nothing else: no byte of a signature."""
    assert (proc.returncode, proc.stdout) == (3, f"{name}\n".encode("ascii")), proc
    for word in proc.stdout.split():
        try:
            decoded = base64.b64decode(word, validate=True)
        except ValueError:
            continue
        assert len(decoded) != 64, proc


# --- the key signer -------------------------------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full to stand in for a full disk")
def test_a_full_disk_gives_no_signature_and_the_name(env, tmp_path):
    key = key_with_journal(tmp_path, "/dev/full")
    assert_no_signature(ks.run_key_signer(key.config, request(env)))


def test_a_journal_at_its_size_limit_gives_no_signature(env, tmp_path):
    """RLIMIT_FSIZE 0 on a regular journal file: every write fails (EFBIG), as on a full disk; root is held to it too."""
    key = ks.Key(tmp_path)
    key.journal.write_bytes(b"")

    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

    proc = subprocess.run([sys.executable, "-I", str(ks.KEY_SIGNER), "--config", str(key.config)],
                          input=json.dumps(request(env)).encode("ascii"), capture_output=True, timeout=60, check=False,
                          preexec_fn=limit)
    assert_no_signature(proc)
    assert key.journal.read_bytes() == b""


def test_a_folder_in_the_journals_place_gives_no_signature(env, tmp_path):
    key = ks.Key(tmp_path)
    key.journal.mkdir()
    assert_no_signature(ks.run_key_signer(key.config, request(env)))


def test_a_journal_the_key_signer_may_not_open_gives_no_signature(env, tmp_path, monkeypatch, capsys):
    """EACCES on the journal, inside the process, whoever runs the test: the open of the journal is refused."""
    key = ks.Key(tmp_path)
    real_open = k.os.open

    def refused(path, *args, **kwargs):
        if str(path) == str(key.journal):
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(k.os, "open", refused)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request(env)).encode("ascii"))))
    code = k.main(["--config", str(key.config)])
    out = capsys.readouterr().out
    assert (code, out) == (3, "journal_unwritable\n")
    assert not key.journal.exists()


@pytest.mark.skipif(ROOT_ONLY_BYPASS, reason="root writes a read-only file; measured with the key account in the probe")
def test_a_read_only_journal_gives_no_signature(env, tmp_path):
    key = ks.Key(tmp_path)
    key.journal.write_bytes(b"")
    key.journal.chmod(0o444)
    assert_no_signature(ks.run_key_signer(key.config, request(env)))
    assert key.journal.read_bytes() == b""


@pytest.mark.skipif(ROOT_ONLY_BYPASS, reason="root writes into any folder; measured with the key account in the probe")
def test_a_journal_folder_without_rights_gives_no_signature(env, tmp_path):
    folder = tmp_path / "closed"
    folder.mkdir()
    key = key_with_journal(tmp_path, str(folder / "journal.jsonl"))
    folder.chmod(0o500)
    try:
        assert_no_signature(ks.run_key_signer(key.config, request(env)))
        assert not key.journal.exists()
    finally:
        folder.chmod(0o700)


def test_the_line_of_a_signature_names_it_and_is_followed_by_its_handout(env, tmp_path):
    key = ks.Key(tmp_path)
    body = gate._pilot_canonical(ks.statement(env))
    proc = ks.run_key_signer(key.config, ks.request_of(body))
    assert proc.returncode == 0 and len(base64.b64decode(proc.stdout.strip())) == 64, proc
    signed, handout = ks.all_key_lines(key.journal)
    digest = __import__("hashlib").sha256(body).hexdigest()
    assert signed["signed"] is True and signed["statementSha256"] == digest and signed["at"].endswith("Z")
    assert signed["decisionId"] == json.loads(body)["predicate"]["decisionId"]
    assert handout == {**handout, "handedOut": True, "decisionId": signed["decisionId"], "statementSha256": digest}
    assert "signed" not in handout


def test_a_signature_stdout_did_not_take_is_marked_so(env, tmp_path):
    """Nobody reads the key signer's stdout: the signed line stands, and its second line says handedOut false."""
    key = ks.Key(tmp_path)
    proc = subprocess.Popen([sys.executable, "-I", str(ks.KEY_SIGNER), "--config", str(key.config)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc.stdout.close()
    proc.stdin.write(json.dumps(request(env)).encode("ascii"))
    proc.stdin.close()
    assert proc.wait(timeout=60) == 3
    signed, handout = ks.all_key_lines(key.journal)
    assert signed["signed"] is True and handout["handedOut"] is False
    assert handout["statementSha256"] == signed["statementSha256"]


def test_the_journal_line_is_synced_to_the_disk_before_the_function_returns(tmp_path, monkeypatch):
    """journal() syncs the file, and the folder of a file it created, before it returns."""
    synced = []
    real_fsync = k.os.fsync

    def fsync(fd):
        synced.append(os.readlink(f"/proc/self/fd/{fd}") if os.path.exists(f"/proc/self/fd/{fd}") else fd)
        real_fsync(fd)

    monkeypatch.setattr(k.os, "fsync", fsync)
    path = tmp_path / "folder" / "journal.jsonl"
    k.journal({"journal": str(path)}, {"signed": True})
    assert synced[:2] == [str(path), str(path.parent)], synced
    synced.clear()
    k.journal({"journal": str(path)}, {"signed": True})
    assert synced == [str(path)], synced
    assert [json.loads(x) for x in path.read_text(encoding="ascii").splitlines()] == [{"signed": True}] * 2


def test_a_line_an_earlier_write_cut_short_stands_alone(tmp_path):
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b'{"signed": tr')
    k.journal({"journal": str(path)}, {"signed": False, "reason": "outside_window"})
    first, second = path.read_text(encoding="ascii").splitlines()
    assert first == '{"signed": tr' and json.loads(second) == {"signed": False, "reason": "outside_window"}


# --- the service ------------------------------------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full to stand in for a full disk")
def test_a_key_signer_whose_journal_is_full_gives_no_receipt(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    config = json.loads(service.key_config.read_text(encoding="utf-8"))
    service.key_config.write_text(json.dumps({**config, "journal": "/dev/full"}), encoding="utf-8")
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_key_journal_unwritable"
    (line,) = service.lines()
    assert (line["signed"], line["reason"]) == (False, "key_journal_unwritable")


@pytest.mark.skipif(not os.path.exists("/dev/full"), reason="needs /dev/full to stand in for a full disk")
def test_a_service_whose_journal_is_full_gives_no_receipt(env, tmp_path):
    """The key signer signed and wrote its line; the service cannot write its own: no signature leaves the service."""
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    config = json.loads(service.config.read_text(encoding="utf-8"))
    service.config.write_text(json.dumps({**config, "journal": "/dev/full"}), encoding="utf-8")
    request = s.proposal(env, service, s.comment_event(repo), "claude", "ESCALATE")
    assert_no_signature(service.ask(request))
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_journal_unwritable"
    # the key signer's lines show the signatures that did not leave the service: a check for O24-1 to find (D65)
    assert [x["signed"] for x in service.key_lines()] == [True, True]


def test_a_service_signature_is_followed_by_its_handout(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    signed, handout = service.all_lines()
    assert signed["signed"] is True and handout == {"at": handout["at"], "handedOut": True,
                                                    "decisionId": signed["decisionId"]}
