"""D120, O49-1: the owner's own doors that the gate held nowhere are a house rule, H5, a deny no card opens.

Measured in Nachtrag 49 (point 4) and named O49-1: sudo, twine upload, uv publish, gpg, cosign and ssh-keygen -Y sign
went through decide() without a word at 380e9d2a and at e7ffa935 (messung/zeilen_*.jsonl of PLUGIN_N49_20261023, and
measured again at the farmer on 2026-10-24 at 6b382418 and e7ffa935 in the work profile of b7n0de under --autonomous:
twelve door lines and five counter cases give None, with and without a release). D119 reads their words as doors, so
no card frees them, but nothing stopped them either. Owner choice A of 2026-10-24, 11:5x Berlin: they are a house
rule, with the sentence "own door, the owner types it themselves", and no card frees them, not even with a release of
D119.

H5 reads the kinds of D119 (_RELEASE_DOORS) with the grammar of each program, run by run as D73 reads a command:
root (sudo, su, doas, pkexec, run0, at the head of a run or behind a wrapper), an upload to PyPI (twine upload and
register, also as `python -m twine`, through uvx and `pipx run`; publish of uv, poetry, flit, hatch, pdm, rye and
maturin, and maturin upload) and a signature with a key (gpg and gpg2 with a signing option, cosign sign, sign-blob,
attest and attest-blob, ssh-keygen -Y sign and the certificate signature of -s, minisign -S, signify -S, sigstore sign,
notation sign, rekor-cli upload, openssl with -sign or -signkey and openssl ca).

RED at e7ffa935 (the head of Nachtrag 49): every door form, the line, the release that does not open it, the hook and
the order of H5 behind H1 and H4. The counter cases keep the answer they have at e7ffa935 and are controls, green at
both. The repository, the environment and the stand-in gh are those of test_plugin_n30_short_line_d72.py; no case runs
a door, reaches a network or names a key.
"""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n42_release_d111 as d111
from test_plugin_n30_short_line_d72 import HOSTS, _answer, _clean, _line, _outcome, _repo, gate, pytestmark  # noqa: F401

REASON = {"root": "house_own_door_root", "pypi": "house_own_door_pypi", "signatur": "house_own_door_signature"}

#: (form, kind of _RELEASE_DOORS, step of the line)
DOORS = [
    # root
    ("sudo systemctl restart proofbundle-fetch", "root", "sudo"),
    ("sudo -n true", "root", "sudo"),
    ("sudo -u root id", "root", "sudo"),
    ("/usr/bin/sudo id", "root", "sudo"),
    ("doas id", "root", "doas"),
    ("pkexec id", "root", "pkexec"),
    ("su -c id", "root", "su"),
    ("run0 id", "root", "run0"),
    ("env sudo id", "root", "sudo"),
    ("timeout 5 sudo id", "root", "sudo"),
    ("nohup sudo id &", "root", "sudo"),
    ("bash -c 'sudo id'", "root", "sudo"),
    ("echo x && sudo id", "root", "sudo"),
    ("x=$(sudo cat /etc/hostname)", "root", "sudo"),
    # an upload to PyPI
    ("twine upload dist/proofbundle-6.3.1.tar.gz", "pypi", "twine upload"),
    ("/opt/venv/bin/twine upload --repository pypi dist/proofbundle-6.3.1-py3-none-any.whl", "pypi", "twine upload"),
    ("twine --no-color upload dist/x.tar.gz", "pypi", "twine upload"),
    ("twine register dist/x.tar.gz", "pypi", "twine register"),
    ("python -m twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("python3.12 -m twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("uvx twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("uvx --from twine twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("pipx run twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("uv publish dist/proofbundle-6.3.1.tar.gz", "pypi", "uv publish"),
    ("uv --directory pkg publish", "pypi", "uv publish"),
    ("poetry publish", "pypi", "poetry publish"),
    ("hatch publish", "pypi", "hatch publish"),
    ("flit publish", "pypi", "flit publish"),
    ("pdm publish", "pypi", "pdm publish"),
    ("rye publish", "pypi", "rye publish"),
    ("maturin publish", "pypi", "maturin publish"),
    ("maturin upload dist/x.whl", "pypi", "maturin upload"),
    ("curl -F content=@dist/x.tar.gz https://upload.pypi.org/legacy/", "pypi", "curl to PyPI"),
    # a neighbour, measured on 2026-10-24 at the working state of O49-1: a publisher or a signer behind `python -m`
    # or a runner passed decide() without a word; the module stands for its program, a runner runs a later word
    ("python -m poetry publish", "pypi", "poetry publish"),
    ("python3 -m uv publish", "pypi", "uv publish"),
    ("python -m sigstore sign dist/x", "signatur", "sigstore sign"),
    ("uvx hatch publish", "pypi", "hatch publish"),
    ("uvx --from sigstore sigstore sign dist/x", "signatur", "sigstore sign"),
    ("pipx run hatch publish", "pypi", "hatch publish"),
    ("uv tool run flit publish", "pypi", "flit publish"),
    ("uv run twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("uv run --with twine twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("poetry run twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("uv run python -m twine upload dist/x.tar.gz", "pypi", "twine upload"),
    ("uv run python -mtwine upload dist/x.tar.gz", "pypi", "twine upload"),   # the interpreter, no door word after it
    ("uv run sudo id", "root", "sudo"),
    # a signature with a key
    ("gpg --sign dist/x", "signatur", "gpg --sign"),
    ("gpg --detach-sign dist/proofbundle-6.3.1.tar.gz", "signatur", "gpg --detach-sign"),
    ("gpg --detach dist/x", "signatur", "gpg --detach"),
    ("gpg --clearsign notes.txt", "signatur", "gpg --clearsign"),
    ("gpg --clear-sign notes.txt", "signatur", "gpg --clear-sign"),
    ("gpg --armor --detach-sign dist/x", "signatur", "gpg --detach-sign"),
    ("gpg -s dist/x", "signatur", "gpg -s"),
    ("gpg -b dist/x", "signatur", "gpg -b"),
    ("gpg -ab dist/x", "signatur", "gpg -ab"),
    ("gpg -o out.sig -b dist/x", "signatur", "gpg -b"),
    ("gpg --batch -u someone --sign dist/x", "signatur", "gpg --sign"),
    ("gpg --sign-key someone", "signatur", "gpg --sign-key"),
    ("gpg --quick-sign-key 0123456789ABCDEF", "signatur", "gpg --quick-sign-key"),
    ("gpg2 --sign dist/x", "signatur", "gpg2 --sign"),
    ("cosign sign ghcr.io/b7n0de/proofbundle@sha256:" + "0" * 64, "signatur", "cosign sign"),
    ("cosign sign-blob dist/x", "signatur", "cosign sign-blob"),
    ("cosign attest --predicate p.json ghcr.io/b7n0de/proofbundle", "signatur", "cosign attest"),
    ("cosign attest-blob --predicate p.json dist/x", "signatur", "cosign attest-blob"),
    ("ssh-keygen -Y sign -n file -f signer dist/x", "signatur", "ssh-keygen -Y sign"),
    ("ssh-keygen -Ysign -n file -f signer dist/x", "signatur", "ssh-keygen -Y sign"),
    ("ssh-keygen -s ca_signer -I someone user.pub", "signatur", "ssh-keygen -s"),
    ("minisign -S -m dist/x", "signatur", "minisign -S"),
    ("signify -S -s signer -m dist/x", "signatur", "signify -S"),
    ("sigstore sign dist/x", "signatur", "sigstore sign"),
    ("notation sign ghcr.io/b7n0de/proofbundle", "signatur", "notation sign"),
    ("rekor-cli upload --artifact dist/x --signature x.sig --public-key signer.pub", "signatur", "rekor-cli upload"),
    ("openssl dgst -sha256 -sign signer.der -out x.sig dist/x", "signatur", "openssl -sign"),
    ("openssl pkeyutl -sign -inkey signer.der -in dist/x", "signatur", "openssl -sign"),
    ("openssl x509 -req -in r.csr -signkey signer.der -out c.crt", "signatur", "openssl -signkey"),
    ("openssl ca -in r.csr -out c.crt", "signatur", "openssl ca"),
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form, kind, step", DOORS)
def test_D120_H5_an_own_door_denies_under_both_hosts(tmp_path, form, kind, step, host):
    repo = _repo(tmp_path)
    out = _outcome(repo, form, host)
    assert out is not None and out.decision == "deny", (form, host, out and out.decision)
    assert REASON[kind] in [v.reason_id for v in out.verdicts], (form, [v.reason_id for v in out.verdicts])
    assert out.step == step, (form, out.step)
    line = _line(out, host)
    assert line.startswith(f"Gate blocks {step} because") and line.endswith("(D120)."), line
    assert "an own door, the owner types it themselves" in line, line
    assert "eigene Tür, der Owner tippt sie selbst" in _line(out, host, "de"), _line(out, host, "de")


def test_D120_H5_the_long_reason_says_no_card_frees_it():
    out = gate.decide("sudo id", "/", time.monotonic() + 60, "claude")
    assert "an own door of the owner" in out.text and "no card frees it" in out.text and "D120" in out.text, out.text
    assert "the owner types it themselves" in out.text


def test_D120_H5_the_short_lines_of_the_three_kinds():
    deadline = time.monotonic() + 60
    for form, en, de in (
            ("sudo id", "Gate blocks sudo because it runs as root, an own door, the owner types it themselves (D120).",
             "Tor sperrt sudo, weil es als root läuft, eigene Tür, der Owner tippt sie selbst (D120)."),
            ("twine upload dist/x", "Gate blocks twine upload because it uploads to PyPI, an own door, the owner types "
                                    "it themselves (D120).",
             "Tor sperrt twine upload, weil es nach PyPI hochlädt, eigene Tür, der Owner tippt sie selbst (D120)."),
            ("gpg -b dist/x", "Gate blocks gpg -b because it signs with a key, an own door, the owner types it "
                              "themselves (D120).",
             "Tor sperrt gpg -b, weil es mit einem Schlüssel signiert, eigene Tür, der Owner tippt sie selbst (D120).")):
        out = gate.decide(form, "/", deadline, "claude")
        assert _line(out) == en and _line(out, language="de") == de, (_line(out), _line(out, language="de"))


# --- counter cases: they keep the answer they have at e7ffa935 ---------------------------------------------------------

#: The answer at e7ffa935 and at the head, per host (claude, codex), measured with this file's repository.
COUNTER = {
    "gpg --verify dist/x.asc dist/x": ((None, []), (None, [])),
    "gpg --list-keys": ((None, []), (None, [])),
    "gpg -k": ((None, []), (None, [])),
    "gpg --armor --export someone": ((None, []), (None, [])),
    "cosign verify --key cosign.pub ghcr.io/b7n0de/proofbundle": ((None, []), (None, [])),
    "cosign verify-blob --key cosign.pub --signature x.sig dist/x": ((None, []), (None, [])),
    "cosign version": ((None, []), (None, [])),
    "ssh-keygen -Y verify -f allowed_signers -I b7n0de -n file -s x.sig": ((None, []), (None, [])),
    "ssh-keygen -Y check-novalidate -n file -s x.sig": ((None, []), (None, [])),
    "ssh-keygen -l -f host.pub": ((None, []), (None, [])),
    "twine check dist/proofbundle-6.3.1.tar.gz": ((None, []), (None, [])),
    "python -m twine check dist/x.tar.gz": ((None, []), (None, [])),
    "uv build": ((None, []), (None, [])),
    "uv run pytest -q": ((None, []), (None, [])),
    "poetry build": ((None, []), (None, [])),
    "minisign -V -p minisign.pub -m dist/x": ((None, []), (None, [])),
    "signify -V -p signer.pub -m dist/x": ((None, []), (None, [])),
    "openssl dgst -sha256 dist/x": ((None, []), (None, [])),
    "openssl dgst -sha256 -verify signer.pub -signature x.sig dist/x": ((None, []), (None, [])),
    "sigstore verify identity dist/x": ((None, []), (None, [])),
    "notation verify ghcr.io/b7n0de/proofbundle": ((None, []), (None, [])),
    "command -v sudo": ((None, []), (None, [])),
    "command -V twine": ((None, []), (None, [])),
    "which sudo": ((None, []), (None, [])),
    "man gpg": ((None, []), (None, [])),
    "echo sudo is an own door": ((None, []), (None, [])),
    "grep -rn 'twine upload' notes.md": ((None, []), (None, [])),
    "cat > notes2.md <<'EOF'\nsudo id\ntwine upload x\ngpg --sign x\nEOF": ((None, []), (None, [])),
    "systemctl status proofbundle-fetch": ((None, []), (None, [])),
    # an upload to another host stays the ask of D103
    "curl -F content=@dist/x.tar.gz https://example.org/upload": (("ask", ["upload_to_host"]),
                                                                   ("ask", ["upload_to_host"])),
}


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", sorted(COUNTER))
def test_D120_control_a_counter_case_keeps_its_answer(tmp_path, form, host):
    repo = _repo(tmp_path)
    assert _answer(repo, form, host) == COUNTER[form][HOSTS.index(host)], (form, host)


# --- the order: H5 follows the rules of D73, a deny of H1 keeps its line ----------------------------------------------

def test_D120_H5_follows_H1_in_the_line_and_both_stand_in_the_log(tmp_path):
    repo = _repo(tmp_path)
    out = _outcome(repo, "sudo -u root gh pr merge 12 --admin")
    reasons = [v.reason_id for v in out.verdicts]
    assert out.decision == "deny" and out.step == "gh pr merge --admin", (out.decision, out.step)
    assert "house_admin_merge" in reasons and "house_own_door_root" in reasons, reasons
    assert reasons.index("house_admin_merge") < reasons.index("house_own_door_root"), reasons


def test_D120_H5_makes_a_kill_behind_sudo_a_deny(tmp_path):
    """changed against D73 (tests/test_plugin_n30_house_rules_d73.py, H4): `sudo pkill -f sleep` asked for its pattern;
    with H5 sudo is an own door, so the line is a deny of H5 and the ask of H4 stays in the log, after it, as the house
    findings stand by their strictness (_HOUSE_ORDER, D73)."""
    repo = _repo(tmp_path)
    out = _outcome(repo, "sudo pkill -f sleep")
    reasons = [v.reason_id for v in out.verdicts]
    assert out.decision == "deny" and out.step == "sudo" and reasons == ["house_own_door_root",
                                                                        "house_kill_pattern"], reasons


@pytest.mark.parametrize("host", HOSTS)
def test_D120_H5_behind_a_wrapper_glob_keeps_the_not_measured_of_the_net(tmp_path, host):
    """changed against R14-1 (tests/test_plugin_gate_runde15_n37.py, tests/test_plugin_ask_load_c_steps.py):
    `sudo gi* status` asked under Claude Code for the program the net could not read; it is a deny of H5 now, and the
    NOT MEASURED of the net stays in the log. `nice gi* status` took its place there."""
    repo = _repo(tmp_path)
    out = _outcome(repo, "sudo gi* status", host)
    reasons = [v.reason_id for v in out.verdicts]
    assert out.decision == "deny" and "net_unmodeled_git" in reasons and "house_own_door_root" in reasons, reasons


def test_D120_H5_goes_before_every_answer_that_lets_a_call_run(tmp_path):
    deadline = time.monotonic() + 60
    for decision, reason in (("pass", "free_work_profile"), ("ask", "push_not_measured"), ("warn", "codex_context_unbound")):
        own = gate.Verdict(decision, "detail (DECISIONS.md D3).", reason)
        out = gate._with_house_rules(gate.Outcome(decision, own.detail, [own]), "twine upload dist/x", str(tmp_path),
                                     deadline)
        assert out.decision == "deny" and out.cause.reason_id == "house_own_door_pypi", (decision, out.decision)
    assert gate._with_house_rules(None, "twine check dist/x", str(tmp_path), deadline) is None


# --- no card opens an own door: a release of the owner for the exact line leaves the deny ------------------------------

@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", d111.SESSION)
    (tmp_path / "gatedir").mkdir(exist_ok=True)
    return tmp_path


@pytest.mark.parametrize("command, kind", [("sudo systemctl restart proofbundle-fetch", "root"),
                                           ("twine upload dist/proofbundle-6.3.1.tar.gz", "pypi"),
                                           ("uv publish dist/proofbundle-6.3.1.tar.gz", "pypi"),
                                           ("gpg --detach-sign dist/proofbundle-6.3.1.tar.gz", "signatur"),
                                           ("cosign sign-blob dist/x", "signatur"),
                                           ("ssh-keygen -Y sign -n file -f signer dist/x", "signatur")])
def test_D120_no_card_frees_an_own_door_not_even_with_a_release(env, command, kind):
    repo = d71._repo(env)
    before = d111.answered(repo, command)
    assert before[0] == "deny" and REASON[kind] in before[1], before
    d111._release(env, command)
    decision, reasons, _klasse = d111.answered(repo, command)
    assert decision == "deny" and "released_by_owner" not in reasons and REASON[kind] in reasons, (decision, reasons)
    assert not (env / "data" / gate.RELEASES_USED).exists()


#: A neighbour of the class, measured on 2026-10-24 at e7ffa935 in the work profile under --autonomous: git signs with
#: the owner's key also through its configuration, and a release let that line run (released_by_owner), while -S and
#: --gpg-sign stayed closed. The signature is an own door of D119; its words now hold the release back.
#: (`git -c tag.gpgSign=true tag v1` is a door already, by its tag.)
GIT_SIGNS = ["git -c commit.gpgsign=true commit -m x", "git -c rebase.gpgSign=true rebase main",
             "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=true git commit -m x",
             "git commit -Ssomeone -m x"]


@pytest.mark.parametrize("command", GIT_SIGNS)
def test_D120_a_release_does_not_open_a_signature_through_the_configuration_of_git(env, command):
    repo = d71._repo(env)
    assert gate._release_door(command, gate.Outcome("deny", "", [])) == "signatur", command
    d111._release(env, command)
    decision, reasons, _klasse = d111.answered(repo, command)
    assert decision != "pass" and "released_by_owner" not in reasons, (command, decision, reasons)


@pytest.mark.parametrize("command", ["git commit -s -m signed-off", "git config --get commit.template",
                                     "git log --oneline -3"])
def test_D120_control_a_git_line_without_a_signature_touches_no_signature_door(command):
    assert gate._release_door(command, gate.Outcome("deny", "", [])) != "signatur", command


# --- the hook as the host runs it -------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("command, word", [("sudo systemctl restart proofbundle-fetch", "sudo"),
                                           ("twine upload dist/x.tar.gz", "twine upload"),
                                           ("gpg --detach-sign dist/x", "gpg --detach-sign")])
def test_D120_the_hook_as_the_host_runs_it(tmp_path, host, command, word):
    repo = _repo(tmp_path)
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": command}, "session_id": "o49"})
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host], event, env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert proc.returncode == 0, proc.stderr
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert word in answer["systemMessage"] and "(D120)." in answer["systemMessage"], answer["systemMessage"]


# --- the registry of the reasons ---------------------------------------------------------------------------------------

def test_D120_the_reasons_are_known_to_the_line_and_counted_as_catches():
    for reason in REASON.values():
        assert gate._SHORT_REASONS[reason][0] == "D120", reason
        assert reason in gate._SHORT_DANGER_IN_REASON and reason in gate.FANG_REASONS, reason


# --- the grammar of H5 ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("words, door", [
    (["sudo", "id"], ("root", "sudo")), (["env", "-u", "X", "sudo", "id"], ("root", "sudo")),
    (["command", "-v", "sudo"], None), (["command", "sudo", "id"], ("root", "sudo")),
    (["twine", "check", "x"], None), (["twine", "upload", "x"], ("pypi", "twine upload")),
    (["python3", "-m", "twine", "check", "x"], None), (["python3", "-c", "print(1)"], None),
    (["uv", "run", "publish.py"], None), (["uv", "publish"], ("pypi", "uv publish")),
    (["uv", "run", "publish"], None), (["uv", "pip", "install", "publish"], None), (["poetry", "run", "publish"], None),
    (["curl", "https://pypi.org/simple/proofbundle/"], None),
    (["curl", "-F", "a=@x", "https://pypi.org.example.net/"], None),
    (["wget", "--post-file=dist/x", "https://upload.pypi.org/legacy/"], ("pypi", "wget to PyPI")),
    (["python3", "-m", "report", "upload", "x"], None), (["python3", "-m", "pip", "install", "twine"], None),
    (["uv", "run", "pytest", "-k", "twine"], None), (["poetry", "run", "python", "-m", "pytest"], None),
    (["hatch", "run", "gpg", "--list-keys"], None), (["gpg", "-o", "-sig", "--verify", "x"], None),
    (["curl", "-T", "dist/x", "https://upload.pypi.org/legacy/"], ("pypi", "curl to PyPI")),
    (["gpg", "--verify", "x.asc"], None), (["gpg", "-d", "x"], None), (["gpg", "-r", "s", "-e", "x"], None),
    (["gpg", "-u", "sb", "--verify", "x"], None), (["gpg", "-usb", "--verify", "x"], None),
    (["gpg", "-bu", "k", "x"], ("signatur", "gpg -bu")), (["gpg", "--", "--sign"], None),
    (["ssh-keygen", "-Y", "verify", "-s", "x.sig"], None), (["ssh-keygen", "-t", "ed25519", "-f", "k"], None),
    (["cosign", "verify-blob", "x"], None), (["openssl", "dgst", "-verify", "p", "x"], None),
    (["minisign", "-G"], None), (["signify", "-V", "-m", "x"], None)])
def test_D120_the_grammar_of_the_doors(words, door):
    assert gate._house_door([(w, False) for w in words]) == (None if door is None else door), (words,)
