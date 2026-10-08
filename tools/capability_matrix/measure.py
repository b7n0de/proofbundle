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
  from elsewhere  the docs name a component outside this project as the provider; no code here. Whether that
                  project provides it is not measured (Codex thread 4219678096 on pull request 304)
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
#: branch for a capability that is on neither the tag nor main; `elsewhere` names the outside provider, and
#: `provider` the name the docs must carry at both refs for it. `git_tag_from` is the pattern for the tag of this
#: repository the docs pin, read at both refs, never configured here (Codex threads 4217983161 and 4217983172 on pull
#: request 304: the provider and the tag were taken from this table, not from the docs). Provider and tag are read in
#: the passage the row's label cites, never elsewhere in the file (`_cited_passage`, Codex thread 4218719393).
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
     "repo_paths": ["action/action.yml"],
     "git_tag_from": r"uses: b7n0de/proofbundle/action@(\S+)",
     "label": [("INTEGRATIONS.md", r"(A composite action is prepared[^\n]*)")]},
    {"id": "slsa-provenance", "name": "SLSA build provenance over a receipt",
     "elsewhere": "actions/attest-build-provenance (GitHub), referenced in INTEGRATIONS.md; no code here",
     "provider": "actions/attest-build-provenance",
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
     "label": [("CHANGELOG.md", r"(scitt-ccf/v1[^\n]*)"),
               ("docs/adr/0009-scitt-anchor-cose-profile.md", r"(\*\*Status:\*\* [^\n]*)")]},
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
    """Console subcommands the parser registers at the top level, `sub.add_parser("name", ...)`, read as calls in the
    parsed source: a commented-out or quoted registration is no call (Codex thread 4220770815 on pull request 304, a
    pattern over the text found `# sub.add_parser("decision")`). A source that does not parse stops the measurement."""
    import ast  # noqa: PLC0415
    try:
        baum = ast.parse(cli_source)
    except SyntaxError as exc:
        raise SystemExit(f"cli.py does not parse ({exc.msg}); its subcommands are not measured") from exc
    # Read statically, so what a static reading cannot decide stops the measurement instead of guessing (Codex thread
    # 4221179837): a registration with a computed name, or one under a condition that is a constant, such as
    # `if False:`, whose branch the reading cannot tell taken from dead.
    namen, eltern = set(), {}
    for knoten in ast.walk(baum):
        for kind in ast.iter_child_nodes(knoten):
            eltern[kind] = knoten
    for k in ast.walk(baum):
        if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr == "add_parser"
                and isinstance(k.func.value, ast.Name) and k.func.value.id == "sub"):
            continue
        if not (k.args and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str)):
            raise SystemExit("cli.py registers a subcommand with a computed name; its subcommands are not measured")
        oben = eltern.get(k)
        while oben is not None:
            if isinstance(oben, (ast.If, ast.While, ast.IfExp)) and isinstance(oben.test, ast.Constant):
                raise SystemExit("cli.py registers a subcommand under a constant condition; its subcommands are not "
                                 "measured")
            oben = eltern.get(oben)
        if re.fullmatch(r"[a-z0-9-]+", k.args[0].value):
            namen.add(k.args[0].value)
    return namen


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


#: A TOML key as written: bare, a basic string in double quotes, or a literal string in single quotes.
_TOML_SCHLUESSEL = r"""(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')"""


def _toml_schluessel(roh: str) -> str:
    """The key a TOML key spells: a basic string's escapes decoded, a literal string as written."""
    if roh.startswith('"'):
        return json.loads(roh)
    if roh.startswith("'"):
        return roh[1:-1]
    return roh


def _entry_points_in_pyproject(text: str) -> set:
    """Entry points declared in pyproject.toml ([project.scripts] and [project.entry-points.<g>]). Read by hand, as
    tomllib is not in Python 3.10, with every TOML spelling of a key: bare, double-quoted and single-quoted (Codex
    thread 4221179857: a single-quoted key was recorded with its quotes). A declaration in another form, a dotted key
    or an inline table under [project] or [project.entry-points], stops the measurement instead of being missed."""
    gefunden, gruppe, abschnitt = set(), None, None
    kopf_muster = re.compile(r"\[\s*project\s*\.\s*(?:(scripts)|entry-points\s*\.\s*(" + _TOML_SCHLUESSEL + r"))\s*\]")
    eintrag_muster = re.compile(r"(" + _TOML_SCHLUESSEL + r")\s*=")
    for zeile in text.splitlines():
        rein = zeile.strip()
        if not rein or rein.startswith("#"):
            continue
        kopf = kopf_muster.fullmatch(rein)
        if kopf:
            gruppe = "console_scripts" if kopf.group(1) else _toml_schluessel(kopf.group(2))
            abschnitt = None
            continue
        if rein.startswith("["):
            gruppe = None
            abschnitt = re.sub(r"\s+", "", rein)
            continue
        if gruppe:
            eintrag = eintrag_muster.match(rein)
            if not eintrag:
                raise SystemExit(f"pyproject.toml declares an entry point of {gruppe} in a form this reader does not "
                                 "read; entry points are not measured")
            gefunden.add(f"{gruppe}:{_toml_schluessel(eintrag.group(1))}")
        elif (abschnitt == "[project.entry-points]"
              or (abschnitt == "[project]" and re.match(r"""(?:scripts|["']?entry-points["']?)\s*[.=]""", rein))):
            raise SystemExit("pyproject.toml declares entry points as a dotted key or an inline table; entry "
                             "points are not measured")
    return gefunden


def _label_at(ref: str, paare: list):
    """(label text, file) of the first (file, pattern) that matches at `ref`, else (None, None)."""
    for datei, muster in paare:
        roh = _git_bytes(ref, datei)
        treffer = re.search(muster, roh.decode("utf-8")) if roh is not None else None
        if treffer:
            return " ".join(treffer.group(1).split()), datei
    return None, None


def _passage(text: str, stelle: int) -> str:
    """The passage around position `stelle`: its paragraph and the fenced code blocks that follow it directly,
    up to the next paragraph of prose or heading. That is the text a label cites, its example included."""
    zeilen = text.splitlines(keepends=True)
    anfang, n = 0, 0
    for i, zeile in enumerate(zeilen):
        if n + len(zeile) > stelle:
            anfang = i
            break
        n += len(zeile)
    while anfang > 0 and zeilen[anfang - 1].strip() and not zeilen[anfang - 1].lstrip().startswith(("#", "```")):
        anfang -= 1
    ende = anfang
    while ende < len(zeilen) and zeilen[ende].strip():
        ende += 1
    while True:
        weiter = ende
        while weiter < len(zeilen) and not zeilen[weiter].strip():
            weiter += 1
        if weiter >= len(zeilen) or not zeilen[weiter].lstrip().startswith("```"):
            break
        weiter += 1
        while weiter < len(zeilen) and not zeilen[weiter].lstrip().startswith("```"):
            weiter += 1
        ende = min(weiter + 1, len(zeilen))
    return "".join(zeilen[anfang:ende])


def _cited_passage(ref: str, paare: list):
    """(passage, file) the first (file, pattern) of a label cites at `ref`, the match's passage, else (None, None).

    Codex thread 4218719393 on pull request 304: the provider was searched in the whole file, so a docs page that
    dropped it from the cited example and named it in an unrelated paragraph kept the cell. The tag the docs pin is
    the same class and is read here too."""
    for datei, muster in paare:
        roh = _git_bytes(ref, datei)
        text = roh.decode("utf-8") if roh is not None else ""
        treffer = re.search(muster, text)
        if treffer:
            return _passage(text, treffer.start()), datei
    return None, None


def _documented_tag(ref: str, cap: dict):
    """The one tag the passage the row's label cites at `ref` pins with `uses:`, or a SystemExit when it pins none
    or more than one, or when there is no such passage."""
    passage, datei = _cited_passage(ref, cap["label"])
    if passage is not None:
        # A commented-out line, in the example or as an HTML comment, is no instruction (Codex thread 4221179850).
        passage = "\n".join(z for z in re.sub(r"<!--.*?-->", "", passage, flags=re.S).splitlines()
                             if not z.lstrip().startswith("#"))
    tags = sorted(set(re.findall(cap["git_tag_from"], passage))) if passage is not None else []
    if len(tags) != 1:
        raise SystemExit(f"{cap['id']}: the passage its label cites in {datei or 'no file'} at {ref[:12]} pins "
                         f"{tags or 'no tag'} with `uses:`; the channel is not measured")
    return tags[0]


def _tag_ref(tag: str):
    """The commit a tag of this repository named exactly `tag` points at, or None. The name must be a valid ref name
    under refs/tags (git check-ref-format), and that ref must exist as written (git show-ref --verify), so a branch, a
    commit id (Codex thread 4219678084 on pull request 304) or a revision expression such as v1~1 or v1^ (thread
    4220245923, which rev-parse resolved under refs/tags) is no tag. The ref is then peeled to its commit."""
    voll = f"refs/tags/{tag}"
    if subprocess.run(["git", "check-ref-format", voll], capture_output=True).returncode != 0:
        return None
    ref = subprocess.run(["git", "-C", str(REPO), "show-ref", "--verify", "-s", voll], capture_output=True, text=True)
    objekt = ref.stdout.strip()
    if ref.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", objekt):
        return None
    lauf = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--verify", "-q", f"{objekt}^{{commit}}"],
                          capture_output=True, text=True)
    return lauf.stdout.strip() if lauf.returncode == 0 and lauf.stdout.strip() else None


def _tag_carries(tag: str, cap: dict) -> str:
    """A SystemExit unless the documented ref is a tag of this repository and carries every repository path of the
    capability there: a channel names how a user gets it, and a tag without the action gives the user nothing (Codex
    thread 4219207478 on pull request 304: the tag was read from the docs and never looked up). The paths are read
    at the commit the tag points at (`_tag_ref`), so neither a branch of the same name nor a revision expression
    stands in for it."""
    commit = _tag_ref(tag)
    if commit is None:
        raise SystemExit(f"{cap['id']}: the documented ref {tag} is not a tag of this repository; the channel is "
                         "not measured")
    fehlt = [p for p in cap.get("repo_paths", []) if _git_bytes(commit, p) is None]
    if fehlt:
        raise SystemExit(f"{cap['id']}: the documented tag {tag} does not carry {', '.join(fehlt)}; the channel is "
                         "not measured")
    return commit


#: A sentence that turns a provider's name against it: a warning, a refusal or a migration away from it.
_VERNEINT_ANBIETER = re.compile(r"\b(?:do\s+not|don't|not|never|no\s+longer|unsupported|deprecated|avoid|instead\s+of)\b",
                                re.IGNORECASE)


def _names_provider(ref: str, cap: dict) -> bool:
    """Whether the passage the row's label cites at `ref` names the provider. A sentence of the passage that names it
    together with a negation stops the measurement, as the reading cannot tell a provider from a warning against it
    (Codex thread 4221179864: "Do not use actions/attest-build-provenance" counted as naming it)."""
    passage, _datei = _cited_passage(ref, cap["label"])
    if passage is None or cap["provider"] not in passage:
        return False
    for satz in re.split(r"(?<=[.;!?])\s+|\n", passage):
        if cap["provider"] in satz and _VERNEINT_ANBIETER.search(satz):
            raise SystemExit(f"{cap['id']}: the passage its label cites at {ref[:12]} names {cap['provider']} in a "
                             "negated sentence; from elsewhere is not measured")
    return True


def _present_at(ref: str, module: list, cli: list, eps: list, repo: list) -> bool:
    """Every module, console subcommand, entry point and repository path of a capability is found at `ref`."""
    commands = _subcommands((_git_bytes(ref, "src/proofbundle/cli.py") or b"").decode("utf-8")) if cli else set()
    points = _entry_points_in_pyproject((_git_bytes(ref, "pyproject.toml") or b"").decode("utf-8")) if eps else set()
    return (all(_git_bytes(ref, _src(m)) is not None for m in module) and all(c in commands for c in cli)
            and all(e in points for e in eps) and all(_git_bytes(ref, p) is not None for p in repo))


#: "experimental" right after a negation, as a graduation note writes it.
_VERNEINT_EXPERIMENTAL = re.compile(
    r"\b(?:no\s+longer|no\s+more|not|never|non|out\s+of|graduated\s+from)[\s\-]*[(\[`'\"]*experimental", re.IGNORECASE)


class LabelMissing(Exception):
    """A capability is present at a ref and no label for it was found there: its status is not measured."""


def status(present: bool, label, *, main_only: bool = False, elsewhere: bool = False, planned: bool = False) -> str:
    """The cell's status from what was measured; the only place a status is decided.

    Every status that says a user can get the capability somewhere needs the project's own words for it: a present
    one, a planned one (its label read at the branch head) and one provided elsewhere (the docs that point there).
    Codex thread 4217201386 on pull request 304: planned and from elsewhere returned before this check, so a row
    whose label had gone kept asserting the branch or the provider."""
    if elsewhere:
        if label is None:
            raise LabelMissing("provided elsewhere, but the docs that point there were not found")
        return "from elsewhere"
    if not present:
        if not planned:
            return "absent"
        if label is None:
            raise LabelMissing("planned on a branch, but the project's label for it was not found at the branch head")
        return "planned"
    if label is None:
        raise LabelMissing("present, but the project's label for it was not found")
    if main_only:
        return "main only"
    # Experimental when the label says so; a label that negates it ("no longer experimental") is published, and one
    # that both says and negates it stops (Codex thread 4220770827 on pull request 304: the keyword alone was read).
    genannt = len(re.findall(r"experimental", label, re.IGNORECASE))
    verneint = len(_VERNEINT_EXPERIMENTAL.findall(label))
    if verneint and verneint < genannt:
        raise LabelMissing("the label both says experimental and negates it; the rule does not decide it")
    return "experimental" if genannt and not verneint else "published"


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
    # A provenance check that fails stops the measurement: the release column says what PyPI serves as v6.1.0 and
    # that the wheel is the tag, and bytes that disprove either are no ground for a status (Codex thread 4218719417
    # on pull request 304: a mismatch was recorded and the rows were derived from the local bytes all the same).
    problems = provenance_problems(ergebnis)
    if problems:
        raise SystemExit("the v6.1.0 artifacts are not the published ones: " + "; ".join(problems))
    with tarfile.open(verzeichnis / ergebnis["files"]["sdist"]["filename"]) as tar:
        sdist = sorted(m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile() and "/" in m.name)
    ergebnis["sdist_file_count"] = len(sdist)
    ergebnis["sdist_files"] = sdist
    return ergebnis


def provenance_problems(ergebnis: dict) -> list:
    """Every recorded provenance check that failed: a file whose SHA-256 is not PyPI's, and a package file of the
    wheel that differs from the tag or is absent there."""
    out = [f"{art} {d['filename']}: SHA-256 {d['sha256'][:12]} is not PyPI's {d['sha256_pypi'][:12]}"
           for art, d in sorted(ergebnis["files"].items()) if not d["digest_matches_pypi"]]
    vergleich = ergebnis.get("wheel_against_tag") or {}
    if vergleich.get("different"):
        out.append(f"wheel files that differ from {TAG}: {', '.join(vergleich['different'])}")
    if vergleich.get("absent_at_tag"):
        out.append(f"wheel files absent at {TAG}: {', '.join(vergleich['absent_at_tag'])}")
    return out


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
        if cap.get("git_tag_from"):
            # The docs pin a tag of this repository; what the user gets is that tag's file, not the release's. The tag
            # is read from the passage the label cites, at the release and at main.
            mess_rel["documented_tag"] = _documented_tag(TAG, cap)
            mess_main["documented_tag_at_main"] = _documented_tag(main, cap)
            commits = {tag: _tag_carries(tag, cap)
                       for tag in sorted({mess_rel["documented_tag"], mess_main["documented_tag_at_main"]})}
            # The diff takes the commit the tag resolved to, never the name read from the docs: a tag named
            # --output=x is an exact tag and would be an option of git diff (Codex thread 4220770798 on pull request 304).
            mess_rel["changed_between_documented_tag_and_release"] = _git(
                "diff", "--shortstat", commits[mess_rel["documented_tag"]], TAG, "--", *repo).strip() or "no change"
        if cap.get("elsewhere"):
            # From elsewhere needs the docs to point there: the passage the label cites names the provider at both refs.
            for ref, wo in ((TAG, mess_rel), (main, mess_main)):
                wo["provider_named_in_docs"] = _names_provider(ref, cap)
                if not wo["provider_named_in_docs"]:
                    raise SystemExit(f"{cap['id']}: the passage its label cites at {ref[:12]} does not name "
                                     f"{cap['provider']}; from elsewhere is not measured")
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
            kanal = ("repository only (built from source)" if not cap.get("git_tag_from")
                     else f"git tag {mess_rel['documented_tag']}"
                     if mess_rel["documented_tag"] == mess_main["documented_tag_at_main"]
                     # Codex thread 4218719408 on pull request 304: one channel column for two refs said the release's
                     # tag beside a main cell whose docs pin another; when they differ, both are named.
                     else f"git tag {mess_rel['documented_tag']} at {TAG}, {mess_main['documented_tag_at_main']} at main")
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
            # The capability lives at the branch head only, so the project's words for it are read there.
            label_main, quelle_main = _label_at(head, cap["label"])
        if not rel_da and not cap.get("elsewhere"):
            # Only what was inspected: the v6.1.0 artifacts and tag, main and the named branch head. Releases before
            # 6.1.0 are not measured (Codex thread 4217983178 on pull request 304: "in no release" said more).
            kanal = (f"branch {branch}, not in v{VERSION} or on main" if branch_kopf
                     else f"main tree only, not in v{VERSION}")
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
    # --end-of-options: the main ref is a value of the command line, never an option of rev-parse (the sibling of
    # Codex thread 4220770798); its commit is what every later call reads.
    main_commit = _git("rev-parse", "--verify", "--end-of-options", f"{a.main}^{{commit}}").strip()
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
