#!/usr/bin/env python3
"""Measure which capability ships where: the published v6.1.0 artifacts on PyPI, and the main branch.

A row names one capability. For each it records what was measured in the v6.1.0 wheel, the v6.1.0
sdist and the main tree (a module file, a console subcommand, an entry point, a repository path), the
label the project itself gives the capability at that point (read from the named file at the tag and at
the main commit, never from memory), and whether the capability's files changed between the tag and
main. The status of each cell is DERIVED from those measurements by `status()`; nothing is set by hand.

Statuses (the closed vocabulary of this matrix):
  published       present in that artifact or tree, and not labelled experimental by the project there
  experimental    present, and labelled experimental by the project there
  main only       present on main, absent from every v6.1.0 artifact and from the tag
  planned         absent from the tag and from main; present on a named branch only
  from elsewhere  provided by a component outside this project, which the docs reference; no code here
  absent          not present (only ever the release cell of a row that is main only or planned)

A capability's CHANNEL is how a user gets it: the PyPI wheel, a git tag of this repository (the GitHub
Action), the repository only (the Rust verifier, built from source), or another project.

Inputs: the two v6.1.0 files as PyPI serves them and PyPI's JSON for that release (for the digests),
the tag v6.1.0 and a main commit of this repository. `--fresh-venv` additionally installs the wheel in a
new virtual environment and runs a user's first steps there. Network: only to download the two files
and the JSON (`--download`) and for pip inside the fresh environment.

Usage:
  python tools/capability_matrix/measure.py --download DIR --main origin/main --fresh-venv \
      --out-json docs/capability_matrix/matrix.json --out-md docs/capability_matrix/README.md
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERSION = "6.1.0"
TAG = "v6.1.0"
PYPI_JSON = f"https://pypi.org/pypi/proofbundle/{VERSION}/json"
STATUSES = ("published", "experimental", "main only", "planned", "from elsewhere", "absent")

#: One entry per capability. `modules` are paths inside the package (proofbundle/...), `cli` console
#: subcommands, `entry_points` "group:name", `repo_paths` repository paths that are no package member.
#: `label` lists (file, pattern) pairs that state the project's own status for the capability; the first
#: that matches at a ref gives the label text there, and "experimental" in it makes the cell experimental.
#: A capability present at a ref with no label found there stops the measurement (fail closed). `branch` names a
#: branch for a capability that is on neither the tag nor main; `elsewhere` names the outside provider.
CAPABILITIES = [
    {"id": "decision", "name": "Decision receipt (decision-receipt/v0.1)",
     "modules": ["proofbundle/decision.py"], "cli": ["decision"],
     "label": [("docs/predicates/README.md", r"\| `decision-receipt/v0\.1` \| ([^|]+) \|")]},
    {"id": "outcome", "name": "Action outcome (action-outcome/v0.1)",
     "modules": ["proofbundle/outcome.py"], "cli": ["outcome"],
     "label": [("docs/predicates/README.md", r"\| `action-outcome/v0\.1` \| ([^|]+) \|")]},
    {"id": "hf-export", "name": "Hugging Face Community Evals export (verifyToken, .eval_results entry)",
     "modules": ["proofbundle/hf_evals.py"], "cli": ["hf-token"],
     "label": [("INTEGRATIONS.md", r"(## Hugging Face Community Evals[^\n]*)")]},
    {"id": "eat-bridge", "name": "EAT bridge (TEE Attestation Result, verify-enclave)",
     "modules": ["proofbundle/experimental/enclave.py"], "cli": ["verify-enclave"],
     "label": [("COMPATIBILITY.md", r"(\*\*the `\[experimental\]` extra\*\*[^\n]*)")]},
    {"id": "rust-verifier", "name": "Rust second verifier (pb_verify_rs)",
     "repo_paths": ["tools/pb_verify_rs/src/main.rs", "tools/pb_verify_rs/Cargo.toml"],
     "registry": "scripts/rust_parity_registry.json",
     "label": [("README.md", r"\| Independent Rust cross-verifier[^|]*\|[^|]*\| ([^|]+) \|"),
               ("README.md", r"(The Rust cross verifier is [^.]*\.)")]},
    {"id": "inspect-hook", "name": "Inspect lifecycle hook (inspect_ai entry point)",
     "modules": ["proofbundle/inspect_hook.py", "proofbundle/_inspect_registry.py"],
     "entry_points": ["inspect_ai:proofbundle"],
     "label": [("INTEGRATIONS.md", r"(## inspect_ai \(end-of-task hook\)[^\n]*)")]},
    {"id": "pytest-plugin", "name": "pytest plugin (pytest11 entry point)",
     "modules": ["proofbundle/pytest_plugin.py"], "entry_points": ["pytest11:proofbundle"],
     "label": [("INTEGRATIONS.md", r"(## pytest \(pytest11 plugin\)[^\n]*)")]},
    {"id": "github-action", "name": "GitHub Action (action/action.yml)",
     "repo_paths": ["action/action.yml"], "git_tag": "v1.0.0",
     "label": [("INTEGRATIONS.md", r"(A composite action is prepared[^\n]*)")]},
    {"id": "slsa-provenance", "name": "SLSA build provenance over a receipt",
     "elsewhere": "actions/attest-build-provenance (GitHub), referenced in INTEGRATIONS.md; no code here",
     "label": [("INTEGRATIONS.md", r"(\*\*Optional, complementary\*\* [^\n]*)")]},
    {"id": "promptfoo", "name": "promptfoo adapter (results.json)",
     "modules": ["proofbundle/adapters/promptfoo.py"],
     "label": [("INTEGRATIONS.md", r"(## promptfoo[^\n]*)")]},
    {"id": "lm-eval", "name": "lm-evaluation-harness adapter (results_*.json)",
     "modules": ["proofbundle/adapters/lm_eval.py"],
     "label": [("INTEGRATIONS.md", r"(## lm-evaluation-harness[^\n]*)")]},
    {"id": "inspect-log", "name": "Inspect log adapter (read_eval_log)",
     "modules": ["proofbundle/adapters/inspect_ai.py"],
     "label": [("INTEGRATIONS.md", r"(## inspect_ai \(end-of-task hook\)[^\n]*)")]},
    {"id": "eee", "name": "Every Eval Ever converter (from_eee_dataset)",
     "modules": ["proofbundle/adapters/eee.py", "proofbundle/eee_eval_schema.json"],
     "label": [("CHANGELOG.md", r"(- \*\*Every Eval Ever converter\*\*[^\n]*)")]},
    {"id": "agt-receipt", "name": "AGT MCP tool-call receipt verifier (adapters.agt_receipt)",
     "modules": ["proofbundle/adapters/agt_receipt.py"],
     "label": [("CHANGELOG.md", r"(\(`src/proofbundle/adapters/agt_receipt\.py`\)[^\n]*)")]},
    {"id": "scitt", "name": "SCITT receipts (scitt-ccf/v1 reader)",
     "modules": ["proofbundle/scitt_ccf.py"], "branch": "feat/640-scitt-anker",
     "label": [("CHANGELOG.md", r"(scitt-ccf/v1[^\n]*)")]},
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True).stdout


def _git_bytes(ref: str, path: str):
    lauf = subprocess.run(["git", "-C", str(REPO), "show", f"{ref}:{path}"], capture_output=True)
    return lauf.stdout if lauf.returncode == 0 else None


def _src(module: str) -> str:
    """Repository path of a package member: proofbundle/x.py -> src/proofbundle/x.py."""
    return "src/" + module


def _subcommands(cli_source: str) -> set:
    """Console subcommands the parser registers at the top level (sub.add_parser("name", ...))."""
    return set(re.findall(r"\bsub\.add_parser\(\s*\"([a-z0-9-]+)\"", cli_source))


def _registry_counts(ref: str, pfad: str):
    """How many surfaces the parity registry names at `ref`, by status."""
    roh = _git_bytes(ref, pfad)
    if roh is None:
        return None
    eintraege = json.loads(roh)["entries"]
    eintraege = list(eintraege.values()) if isinstance(eintraege, dict) else eintraege
    zaehlung = {}
    for e in eintraege:
        zaehlung[e["status"]] = zaehlung.get(e["status"], 0) + 1
    return {"entries": len(eintraege), **dict(sorted(zaehlung.items()))}


def _entry_points(text: str) -> set:
    gruppe, gefunden = None, set()
    for zeile in text.splitlines():
        zeile = zeile.strip()
        if zeile.startswith("[") and zeile.endswith("]"):
            gruppe = zeile[1:-1]
        elif "=" in zeile and gruppe:
            gefunden.add(f"{gruppe}:{zeile.split('=', 1)[0].strip()}")
    return gefunden


def _entry_points_in_pyproject(text: str) -> set:
    """Entry points declared in pyproject.toml ([project.scripts] and [project.entry-points.<g>])."""
    gefunden, gruppe = set(), None
    for zeile in text.splitlines():
        kopf = re.fullmatch(r"\[project\.(scripts|entry-points\.\"?([A-Za-z0-9_.-]+)\"?)\]", zeile.strip())
        if kopf:
            gruppe = "console_scripts" if kopf.group(1) == "scripts" else kopf.group(2)
            continue
        if zeile.strip().startswith("["):
            gruppe = None
        elif gruppe and "=" in zeile and not zeile.strip().startswith("#"):
            gefunden.add(f"{gruppe}:{zeile.split('=', 1)[0].strip().strip(chr(34))}")
    return gefunden


def _label_at(ref: str, paare: list):
    """(label text, file) of the first (file, pattern) that matches at `ref`, else (None, None)."""
    for datei, muster in paare:
        roh = _git_bytes(ref, datei)
        treffer = re.search(muster, roh.decode("utf-8")) if roh is not None else None
        if treffer:
            return " ".join(treffer.group(1).split()), datei
    return None, None


def _present_at(ref: str, module: list, cli: list, eps: list, repo: list) -> bool:
    """Every module, console subcommand, entry point and repository path of a capability is found at `ref`."""
    commands = _subcommands((_git_bytes(ref, "src/proofbundle/cli.py") or b"").decode("utf-8")) if cli else set()
    points = _entry_points_in_pyproject((_git_bytes(ref, "pyproject.toml") or b"").decode("utf-8")) if eps else set()
    return (all(_git_bytes(ref, _src(m)) is not None for m in module) and all(c in commands for c in cli)
            and all(e in points for e in eps) and all(_git_bytes(ref, p) is not None for p in repo))


class LabelMissing(Exception):
    """A capability is present at a ref and no label for it was found there: its status is not measured."""


def status(present: bool, label, *, main_only: bool = False, elsewhere: bool = False, planned: bool = False) -> str:
    """The cell's status from what was measured; the only place a status is decided."""
    if elsewhere:
        return "from elsewhere"
    if not present:
        return "planned" if planned else "absent"
    if label is None:
        raise LabelMissing("present, but the project's label for it was not found")
    if main_only:
        return "main only"
    return "experimental" if label and "experimental" in label.lower() else "published"


def download(ziel: Path) -> dict:
    ziel.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(PYPI_JSON, timeout=60) as antwort:  # noqa: S310 - fixed https URL
        roh = antwort.read()
    (ziel / f"pypi_{VERSION}.json").write_bytes(roh)
    for datei in json.loads(roh)["urls"]:
        with urllib.request.urlopen(datei["url"], timeout=120) as antwort:  # noqa: S310
            (ziel / datei["filename"]).write_bytes(antwort.read())
    return json.loads(roh)


def measure_artifacts(verzeichnis: Path, pypi: dict) -> dict:
    ergebnis = {"version": VERSION, "pypi_json": PYPI_JSON, "files": {}}
    for datei in pypi["urls"]:
        daten = (verzeichnis / datei["filename"]).read_bytes()
        ergebnis["files"][datei["packagetype"]] = {
            "filename": datei["filename"], "size": len(daten), "sha256": _sha256(daten),
            "sha256_pypi": datei["digests"]["sha256"], "upload_time": datei["upload_time_iso_8601"],
            "url": datei["url"], "digest_matches_pypi": _sha256(daten) == datei["digests"]["sha256"]}
    rad = zipfile.ZipFile(verzeichnis / ergebnis["files"]["bdist_wheel"]["filename"])
    namen = sorted(n for n in rad.namelist() if not n.endswith("/"))
    ergebnis["wheel_files"] = {n: _sha256(rad.read(n)) for n in namen}
    ep = next(n for n in namen if n.endswith(".dist-info/entry_points.txt"))
    ergebnis["wheel_entry_points"] = sorted(_entry_points(rad.read(ep).decode("utf-8")))
    ergebnis["wheel_subcommands"] = sorted(_subcommands(rad.read("proofbundle/cli.py").decode("utf-8")))
    # Is the wheel the tag? Every package file against the tag's src/ bytes.
    gleich, anders, fehlt = 0, [], []
    for n, digest in ergebnis["wheel_files"].items():
        if not n.startswith("proofbundle/"):
            continue
        am_tag = _git_bytes(TAG, _src(n))
        if am_tag is None:
            fehlt.append(n)
        elif _sha256(am_tag) == digest:
            gleich += 1
        else:
            anders.append(n)
    ergebnis["wheel_against_tag"] = {"identical": gleich, "different": anders, "absent_at_tag": fehlt}
    with tarfile.open(verzeichnis / ergebnis["files"]["sdist"]["filename"]) as tar:
        sdist = sorted(m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile() and "/" in m.name)
    ergebnis["sdist_file_count"] = len(sdist)
    ergebnis["sdist_files"] = sdist
    return ergebnis


def measure_rows(artefakte: dict, main: str) -> list:
    wheel = artefakte["wheel_files"]
    sdist = set(artefakte["sdist_files"])
    main_cli = _subcommands((_git_bytes(main, "src/proofbundle/cli.py") or b"").decode("utf-8"))
    tag_cli = _subcommands((_git_bytes(TAG, "src/proofbundle/cli.py") or b"").decode("utf-8"))
    main_ep = _entry_points_in_pyproject((_git_bytes(main, "pyproject.toml") or b"").decode("utf-8"))
    zeilen = []
    for cap in CAPABILITIES:
        module, cli = cap.get("modules", []), cap.get("cli", [])
        eps, repo = cap.get("entry_points", []), cap.get("repo_paths", [])
        mess_rel = {"modules_in_wheel": {m: m in wheel for m in module},
                    "modules_in_sdist": {m: _src(m) in sdist for m in module},
                    "subcommands_in_wheel": {c: c in artefakte["wheel_subcommands"] for c in cli},
                    "entry_points_in_wheel": {e: e in artefakte["wheel_entry_points"] for e in eps},
                    "repo_paths_in_sdist": {p: p in sdist for p in repo},
                    "repo_paths_at_tag": {p: _git_bytes(TAG, p) is not None for p in repo},
                    "subcommands_at_tag": {c: c in tag_cli for c in cli}}
        mess_main = {"modules_at_main": {m: _git_bytes(main, _src(m)) is not None for m in module},
                     "subcommands_at_main": {c: c in main_cli for c in cli},
                     "entry_points_at_main": {e: e in main_ep for e in eps},
                     "repo_paths_at_main": {p: _git_bytes(main, p) is not None for p in repo}}
        if cap.get("registry"):
            mess_rel["parity_registry_at_tag"] = _registry_counts(TAG, cap["registry"])
            mess_main["parity_registry_at_main"] = _registry_counts(main, cap["registry"])
        if cap.get("git_tag"):
            # The docs pin a tag of this repository; what the user gets is that tag's file, not the release's.
            mess_rel["documented_tag"] = cap["git_tag"]
            mess_rel["changed_between_documented_tag_and_release"] = _git(
                "diff", "--shortstat", cap["git_tag"], TAG, "--", *repo).strip() or "no change"
        label_tag, quelle_tag = _label_at(TAG, cap["label"])
        label_main, quelle_main = _label_at(main, cap["label"])
        kanal = "PyPI wheel"
        if cap.get("elsewhere"):
            kanal = "another project"
            rel_da = main_da = True
        elif module:
            rel_da = all(mess_rel["modules_in_wheel"].values()) and all(mess_rel["subcommands_in_wheel"].values()) \
                and all(mess_rel["entry_points_in_wheel"].values())
            main_da = all(mess_main["modules_at_main"].values()) and all(mess_main["subcommands_at_main"].values()) \
                and all(mess_main["entry_points_at_main"].values())
        else:
            rel_da = all(mess_rel["repo_paths_at_tag"].values())
            main_da = all(mess_main["repo_paths_at_main"].values())
            kanal = f"git tag {cap['git_tag']}" if cap.get("git_tag") else "repository only (built from source)"
        if not rel_da and not cap.get("elsewhere"):
            # The release column reads the wheel (the tag for a repository capability), but main only and
            # planned promise absence from every v6.1.0 artifact and from the tag. The sdist is read as a file
            # list, so there the capability's files decide.
            carried_by = [where for where, found in (
                ("the sdist", all(mess_rel["modules_in_sdist"].values()) and all(mess_rel["repo_paths_in_sdist"].values())),
                ("the tag", _present_at(TAG, module, cli, eps, repo))) if found]
            if carried_by:
                raise SystemExit(f"{cap['id']}: absent from the v{VERSION} wheel but carried by "
                                 f"{' and '.join(carried_by)}; no status in the vocabulary says so")
        pfade = [_src(m) for m in module] + repo
        diff = _git("diff", "--shortstat", TAG, main, "--", *pfade).strip() if pfade and rel_da and main_da else ""
        branch = cap.get("branch")
        branch_kopf = None
        if not main_da:
            # Planned is absent from the tag and from main and present on the named branch, measured at the head
            # this row records; that a ref of the name resolves says nothing about what its head carries.
            if rel_da:
                raise SystemExit(f"{cap['id']}: present in v{VERSION}, absent from main {main[:8]}; "
                                 "no status in the vocabulary says so")
            if not branch:
                raise SystemExit(f"{cap['id']}: absent from v{VERSION} and from main {main[:8]}, and no branch "
                                 "is named; no status in the vocabulary says so")
            head = _git("rev-parse", f"origin/{branch}").strip()
            if not _present_at(head, module, cli, eps, repo):
                raise SystemExit(f"{cap['id']}: branch {branch} at {head} does not carry the capability; "
                                 "planned is not measured")
            branch_kopf = head
        if not rel_da and not cap.get("elsewhere"):
            kanal = f"branch {branch} only" if branch_kopf else "main tree only, in no release"
        try:
            st_rel = status(rel_da, label_tag, elsewhere=bool(cap.get("elsewhere")))
            st_main = status(main_da, label_main, main_only=main_da and not rel_da,
                             elsewhere=bool(cap.get("elsewhere")), planned=bool(branch_kopf))
        except LabelMissing as exc:
            raise SystemExit(f"{cap['id']}: {exc} (tag: {label_tag!r}, main: {label_main!r})") from exc
        zeilen.append({
            "id": cap["id"], "name": cap["name"], "channel": kanal,
            "evidence": {"modules": module, "subcommands": cli, "entry_points": eps, "repo_paths": repo,
                         "label_sources": [d for d, _ in cap["label"]], "elsewhere": cap.get("elsewhere")},
            "release": {"version": VERSION, "tag": TAG,
                        "status": st_rel, "label": label_tag, "label_source": quelle_tag, "measured": mess_rel},
            "main": {"status": st_main, "label": label_main, "label_source": quelle_main, "measured": mess_main,
                     "changed_since_release": diff or ("no change" if rel_da and main_da and pfade else None),
                     "branch": ({"name": branch, "head": branch_kopf} if branch_kopf else None)},
        })
    return zeilen


def _lauf(befehl: list, cwd: Path, umgebung: dict) -> dict:
    lauf = subprocess.run(befehl, cwd=cwd, env=umgebung, capture_output=True, text=True, timeout=900)
    ausgabe = (lauf.stdout + lauf.stderr).strip().splitlines()
    return {"command": " ".join(befehl[1:] if befehl[0].endswith("proofbundle") else befehl),
            "exit": lauf.returncode, "output_head": ausgabe[:3], "output_tail": ausgabe[-2:] if len(ausgabe) > 3 else []}


def fresh_venv(rad: Path, python: str, extra: str = "eval") -> dict:
    """A new virtual environment, the wheel installed with its [eval] extra from PyPI, then a user's first
    steps: sign a payload, verify it, verify a tampered copy, and the built-in demo."""
    with tempfile.TemporaryDirectory() as tmp:
        ort = Path(tmp)
        subprocess.run([python, "-m", "venv", str(ort / "venv")], check=True)
        py = ort / "venv" / "bin" / "python"
        pb = ort / "venv" / "bin" / "proofbundle"
        umgebung = {"PATH": f"{ort / 'venv' / 'bin'}:/usr/bin:/bin", "HOME": str(ort), "LANG": "C.UTF-8"}
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "PIP_INDEX_URL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                  "PIP_CERT"):
            if k in os.environ:
                umgebung[k] = os.environ[k]
        install = subprocess.run([str(py), "-m", "pip", "install", "--no-cache-dir", "-q", f"{rad}[{extra}]"],
                                 env=umgebung, capture_output=True, text=True, timeout=900)
        pakete = subprocess.run([str(py), "-m", "pip", "list", "--format=freeze"], env=umgebung,
                                capture_output=True, text=True).stdout.split()
        arbeit = ort / "work"
        arbeit.mkdir()
        (arbeit / "payload.txt").write_bytes(b"an example payload\n")
        schritte = [
            _lauf([str(pb), "--version"], arbeit, umgebung),
            _lauf([str(pb), "emit", "--payload-file", "payload.txt", "--out", "receipt.json",
                   "--new-key", "signer.key"], arbeit, umgebung),
            _lauf([str(pb), "verify", "receipt.json"], arbeit, umgebung),
        ]
        bundle = json.loads((arbeit / "receipt.json").read_text(encoding="utf-8"))
        feld, alt = _tamper(bundle)
        (arbeit / "tampered.json").write_text(json.dumps(bundle), encoding="utf-8")
        schritte.append(_lauf([str(pb), "verify", "tampered.json"], arbeit, umgebung))
        schritte[-1]["tampered_field"] = feld
        schritte[-1]["tamper"] = alt
        schritte.append(_lauf([str(pb), "demo"], arbeit, umgebung))
        version = subprocess.run([str(py), "-c", "import sys; print(sys.version.split()[0])"], env=umgebung,
                                 capture_output=True, text=True).stdout.strip()
    return {"wheel": rad.name, "wheel_sha256": _sha256(rad.read_bytes()), "python": version, "extra": extra,
            "pip_install_exit": install.returncode, "installed": pakete, "steps": schritte}


def _tamper(bundle: dict):
    """Change one byte of the signed payload: the first base64 character of `payload` (or the first
    string field whose name contains 'payload'), replaced by another valid base64 character."""
    for feld in ("payload", "payload_b64"):
        wert = bundle.get(feld)
        if isinstance(wert, str) and wert:
            neu = ("B" if wert[0] != "B" else "C") + wert[1:]
            bundle[feld] = neu
            return feld, f"first character {wert[0]!r} -> {neu[0]!r}"
    raise SystemExit(f"no payload field to tamper with among {sorted(bundle)}")


def build_main_wheel(main: str, ziel: Path, python: str) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "-C", str(REPO), "worktree", "add", "--detach", str(Path(tmp) / "tree"), main],
                       check=True, capture_output=True)
        try:
            subprocess.run([python, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(ziel), str(Path(tmp) / "tree")],
                           check=True, capture_output=True)
        finally:
            subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(Path(tmp) / "tree")],
                           capture_output=True)
    return next(ziel.glob("proofbundle-*.whl"))


def _kurz(label):
    """A label as it reads, without the Markdown around it."""
    if not label:
        return label
    ohne_links = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", label)   # a relative link would not resolve here
    return re.sub(r"^[#*\-\s]+", "", ohne_links.replace("**", "")).strip()


def _registry_text(zahlen) -> str:
    if not zahlen:
        return ""
    rest = ", ".join(f"{v} {k}" for k, v in zahlen.items() if k != "entries")
    return f"; parity registry: {rest} of {zahlen['entries']} surfaces"


def render_table(daten: dict) -> str:
    """The matrix as a Markdown table, from the measured JSON alone."""
    kopf = daten["main_commit"][:8]
    zeilen = [f"| capability | channel | v{VERSION} (tag `{TAG}`, PyPI) | main `{kopf}` | changed since v{VERSION} |",
              "|---|---|---|---|---|"]
    for z in daten["rows"]:
        rel, mai = z["release"], z["main"]
        rel_zelle = rel["status"] + (f" — {_kurz(rel['label'])}" if rel["label"] and rel["status"] != "absent" else "")
        rel_zelle += _registry_text(rel["measured"].get("parity_registry_at_tag"))
        mai_zelle = mai["status"]
        if mai.get("branch"):
            mai_zelle += f" (branch `{mai['branch']['name']}` at `{mai['branch']['head'][:8]}`)"
        elif mai["label"] and mai["label"] != rel["label"]:
            mai_zelle += f" — {_kurz(mai['label'])}"
        mai_zelle += _registry_text(mai["measured"].get("parity_registry_at_main"))
        geaendert = mai.get("changed_since_release") or "—"
        kanal = z["channel"]
        if rel["measured"].get("documented_tag"):
            kanal += (f" (the docs pin it; the release's file differs from it: "
                      f"{rel['measured']['changed_between_documented_tag_and_release']})")
        zeilen.append(f"| {z['name']} | {_md(kanal)} | {_md(rel_zelle)} | {_md(mai_zelle)} | {_md(geaendert)} |")
    return "\n".join(zeilen) + "\n"


def _md(text: str) -> str:
    return text.replace("|", "\\|")


def render_fresh(daten: dict) -> str:
    """The fresh-environment runs as a Markdown table, from the measured JSON alone."""
    zeilen = ["| wheel | step | exit | first line of output |", "|---|---|---|---|"]
    for name, lauf in daten.get("fresh_venv", {}).items():
        kopf = f"{lauf['wheel']} ({'PyPI' if name == 'release_wheel' else 'built from ' + lauf['built_from'][:8]})"
        for schritt in lauf["steps"]:
            erste = (schritt["output_head"] or [""])[0]
            if schritt.get("tampered_field"):
                erste += f" (tampered: `{schritt['tampered_field']}`, {schritt['tamper']})"
            zeilen.append(f"| {kopf} | `proofbundle {schritt['command']}` | {schritt['exit']} | {_md(erste)} |")
    return "\n".join(zeilen) + "\n"


BLOECKE = {"matrix": render_table, "fresh environment": render_fresh}


def _marken(name: str) -> tuple:
    return (f"<!-- {name}: written by tools/capability_matrix/measure.py -->", f"<!-- end of {name} -->")


def write_md(pfad: Path, daten: dict) -> None:
    text = pfad.read_text(encoding="utf-8")
    for name, render in BLOECKE.items():
        begin, end = _marken(name)
        anfang, ende = text.index(begin) + len(begin), text.index(end)
        text = text[:anfang] + "\n\n" + render(daten) + "\n" + text[ende:]
    pfad.write_text(text, encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--download", type=Path, help="download the v6.1.0 files and PyPI's JSON into this directory")
    p.add_argument("--artifacts", type=Path, help="a directory that already holds them (instead of --download)")
    p.add_argument("--main", default="origin/main")
    p.add_argument("--fresh-venv", action="store_true")
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--out-json", type=Path, required=True)
    p.add_argument("--out-md", type=Path)
    a = p.parse_args(argv)
    if a.download:
        pypi, verzeichnis = download(a.download), a.download
    else:
        verzeichnis = a.artifacts
        pypi = json.loads((verzeichnis / f"pypi_{VERSION}.json").read_text(encoding="utf-8"))
    artefakte = measure_artifacts(verzeichnis, pypi)
    main_commit = _git("rev-parse", a.main).strip()
    daten = {"format": "capability-matrix/1", "measured_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "tag": TAG, "tag_commit": _git("rev-parse", f"{TAG}^{{commit}}").strip(), "main_ref": a.main,
             "main_commit": main_commit, "statuses": list(STATUSES), "release": artefakte,
             "rows": measure_rows(artefakte, main_commit)}
    # The sdist's file list served the lookups each row records; the file keeps its count and a digest.
    liste = artefakte.pop("sdist_files")
    artefakte["sdist_file_list_sha256"] = _sha256("\n".join(liste).encode("utf-8"))
    if a.fresh_venv:
        rad = verzeichnis / artefakte["files"]["bdist_wheel"]["filename"]
        daten["fresh_venv"] = {"release_wheel": fresh_venv(rad, a.python)}
        with tempfile.TemporaryDirectory() as tmp:
            haupt = build_main_wheel(main_commit, Path(tmp), a.python)
            daten["fresh_venv"]["main_wheel"] = fresh_venv(haupt, a.python)
            daten["fresh_venv"]["main_wheel"]["built_from"] = main_commit
            inhalt = set(zipfile.ZipFile(haupt).namelist())
            daten["fresh_venv"]["main_wheel"]["main_only_modules_inside"] = sorted(
                m for z in daten["rows"] if z["main"]["status"] == "main only" for m in z["evidence"]["modules"]
                if m in inhalt)
    a.out_json.parent.mkdir(parents=True, exist_ok=True)
    a.out_json.write_text(json.dumps(daten, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    if a.out_md:
        write_md(a.out_md, daten)
    return 0


if __name__ == "__main__":
    sys.exit(main())
