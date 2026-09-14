#!/usr/bin/env python3
"""Produce a SIGNED, CANDIDATE-BOUND release-evidence artifact — the producer half of the admission
path in ``scripts/audit_candidate_matrix.py`` (deep gate 2026-09-05, finding L5-G7-02, class A).

WHY THIS SCRIPT EXISTS. The gate now refuses evidence that is unsigned, version-free or unbound to
the release candidate. A refusal mechanism without a way to PRODUCE admissible evidence would be a
gate nobody can ever pass — a mechanism without a caller. This is the caller.

WHAT IT ADDS to a raw measurement artifact (e.g. what ``fuzz_soak.py`` writes):

    version        the release under test, read from pyproject.toml unless given
    candidate      commit + tree_digest + sdist_sha256 + wheel_sha256 — the exact candidate
    gate_zeile     the gate line of the DECIDING deep-gate verdict, copied VERBATIM out of that
                   verdict file — never composed here (release standard 6.0.0, 2026-09-05, line 18)
    producer       tool + tool_version — WHO measured
    input_digest   the corpus/input the measurement consumed
    produced_at    when, RFC-3339 UTC, measured by the runner
    signer_role    the role the signing key speaks for
    signature      ed25519 over the RFC-8785 canonical bytes of everything above

WHY THE GATE LINE IS NOT OPTIONAL. The standard says it in one sentence: "Damit die Baumaschine
nicht ihre eigene Freigabe beglaubigt, traegt jedes signierte Artefakt Kandidatenbindung … und die
Gate-Zeile des Lauf-5-Verdikts als Feld. Der Verifier prueft die Bindung, nicht nur die Signatur."
A machine that measures, signs and releases attests only that IT was the author. The gate line is the
foreign instance inside the signed body — so this script cannot COMPOSE one: it can only copy
``notes.gate_zeile`` out of a verdict file, and it refuses when that file does not carry one.

``tree_digest`` is the same quantity a pre-tag receipt binds, narrowed for the deliberately-mutable
release-evidence files: sha256 over the sorted ``git ls-tree -r HEAD`` lines EXCLUDING exactly the
paths in :data:`MUTABLE_EVIDENCE_RELS` — the artifacts a release run writes AS PART of measuring
them. Everything else under ``audit_artifacts/`` (the trust anchor, the class ledger, prior
releases' historical records) IS part of the bound tree (deep gate 2026-09-05, NACHTRAG2 Teil C
Auflage C3: "audit_artifacts nicht pauschal aus dem Baumdigest ausschliessen" — a whole-directory
exclusion let a key be introduced in the very build path it would go on to authorise, invisibly to
this binding).

AUFLOESUNG DES MERGE-KONFLIKTS 2026-09-07, damit sie nachvollziehbar ist statt stillschweigend:
`3f15b4b` wurde gegen `bedb0a5` geschrieben und brachte hier den DAMALIGEN tree_digest-Satz mit,
der das ganze Verzeichnis ``audit_artifacts/`` ausschliesst. Genau diesen Satz hat der Kandidat
seither durch Auflage C3 ersetzt. Uebernommen ist deshalb der Gate-Zeilen-Absatz, NICHT der
veraltete tree_digest-Absatz — sonst haette der Docstring zwei einander widersprechende Regeln fuer
dieselbe Groesse getragen, und der Code haette die eine, der Leser die andere geglaubt.

TWO MODES, the same signed body in both (mirrors scripts/pre_tag_receipt.py's split, and for the
same reason: the release private key lives on the owner's machine, never on the build host) —
NEITHER of which ever reads a private key on this machine:

  emit      --emit-payload P --context-out C: write the canonical bytes to P and the body to C.
            NO private key is read, here or anywhere in this script. The key holder signs P
            out of band; the build host then assembles.
  assemble  --assemble --context-in C --sig-file S --signer-pubkey B --out A: wrap body + signature.
            Self-checks the signature and REFUSES on a mismatch, so a bad pair never reaches disk.

WHY THERE IS NO THIRD, INLINE MODE (deep gate 2026-09-05, Runde 2, Auflage C9 — this is the fix, not
a design note about a removed feature). A prior revision of this script also accepted
``--privkey-file`` and signed the body ITSELF, in the same process that built it. That is
self-certification: a signature only means "an independent party attests this" when the party
holding the key is not the party that produced and shaped what gets signed. Once
``--privkey-file`` shipped in this repo's tree (``MANIFEST.in`` grafts ``scripts/``, so this file
ships in the sdist), the capability to self-certify shipped too — whether or not anyone ever
invoked it. There is now no code path in this file, reachable by any flag, that reads a private
key. The only way admissible evidence comes to exist is: this script builds the canonical bytes
(``emit``), something OUTSIDE this process and this host signs them, and this script assembles the
result — checking the signature itself before it ever touches disk.

Usage (keyless, both steps run — possibly on different hosts):
  sign_readiness_artifact.py --in audit_artifacts/600/fuzz_soak_latest.json \\
      --producer-tool scripts/fuzz_soak.py --producer-tool-version 6.0.0 \\
      --input-digest <sha256 of the corpus> --signer-role release-runner \\
      --gate-zeile-aus-verdikt <deep-gate verdict json> \\
      --sdist dist/proofbundle-6.0.0.tar.gz --wheel dist/proofbundle-6.0.0-py3-none-any.whl \\
      --emit-payload /tmp/payload.bin --context-out /tmp/context.json
  # ... the key holder signs /tmp/payload.bin out of band, producing sig.b64 ...
  sign_readiness_artifact.py --assemble --context-in /tmp/context.json --sig-file sig.b64 \\
      --signer-pubkey <base64 pubkey> --out audit_artifacts/600/fuzz_soak_latest.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

#: The unsigned wrapper. Everything else in the artifact is inside the signed body.
SIGNATURE_KEY = "signature"

#: Release-evidence files that legitimately change AS PART OF producing them for this exact
#: candidate — excluded from the tree digest so writing one does not retroactively change the tree
#: it just bound (the circular-reference problem: the digest cannot include a file whose own
#: content is "the digest of this tree").
#:
#: NOTHING ELSE is exempted. Before this fix, the whole ``audit_artifacts/`` directory was excluded
#: as one non-recursive ``git ls-tree`` entry — which also hid ``readiness_trusted_pubkeys.txt``
#: (the trust anchor read by ``scripts/audit_candidate_matrix.py``) from the binding. A key added
#: to that anchor in the SAME commit as the candidate it would go on to authorise was therefore
#: invisible to ``tree_digest`` — the exact self-authorisation shape Auflage C3 (Runde 2) names.
#: Recursive ``git ls-tree -r HEAD`` plus this narrow, explicit allowlist closes that while still
#: letting a soak/differential run write its own result file without invalidating its own binding.
#:
#: SHARED BY NAME with ``scripts/audit_candidate_matrix.py`` (which imports this module rather than
#: re-deriving its own list): a producer and a gate that excluded DIFFERENT paths would silently
#: stop agreeing on what a candidate binds, and neither side would notice.
MUTABLE_EVIDENCE_RELS = (
    "audit_artifacts/360/fuzz_soak_latest.json",
    "audit_artifacts/360/rust_differential_matrix.json",
    # Owner-Karte OA-dc37e26295 (08.09.2026), Erzeuger `scripts/budget_axis_measurement.py`. Er
    # gehoert aus demselben Grund hierher wie seine zwei Nachbarn: ein Release-Lauf SCHREIBT ihn
    # waehrend er misst, und ohne diesen Eintrag traefe er genau den Zirkelbezug, den diese
    # Konstante fuer Soak und Differential verhindert — das Artefakt waere Teil des Baumes, den
    # es beurteilt. Eingetragen bevor er getrackt wird, nicht danach: eine Schutzliste, die der
    # geschuetzten Datei hinterherlaeuft, schuetzt die eine Runde nicht, in der es darauf ankommt.
    "audit_artifacts/360/budget_axis_latest.json",
)


def pyproject_version(repo: Path) -> str | None:
    try:
        roh = (repo / "pyproject.toml").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', roh)
    return m.group(1) if m else None


def head_commit(repo: Path) -> str:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise SystemExit(f"cannot read HEAD in {repo}: {r.stderr.strip()}")
    return r.stdout.strip()


def tree_digest(repo: Path, *, exclude: tuple[str, ...] = MUTABLE_EVIDENCE_RELS) -> str:
    """The quantity the gate recomputes: sha256 over sorted, RECURSIVE `git ls-tree HEAD`, minus
    exactly the paths in ``exclude`` (see :data:`MUTABLE_EVIDENCE_RELS`) — never a whole directory."""
    r = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise SystemExit(f"cannot read the tree in {repo}: {r.stderr.strip()}")
    suffixe = tuple(f"\t{p}" for p in exclude)
    zeilen = [ln for ln in r.stdout.splitlines() if not ln.endswith(suffixe)]
    return hashlib.sha256("\n".join(sorted(zeilen)).encode("utf-8")).hexdigest()


#: Der Vertrauensanker, dessen Digest ein Artefakt mitbringt. Derselbe Pfad, den
#: ``scripts/audit_candidate_matrix.py`` liest — geteilt als KONSTANTE, nicht als zwei getippte
#: Zeichenketten, weil ein Erzeuger und ein Tor, die verschiedene Dateien meinen, beide gruen
#: waeren und nichts gemeinsam haetten.
TRUST_ANCHOR_REL = "audit_artifacts/readiness_trusted_pubkeys.txt"


def trust_anchor_digest(repo: Path) -> str:
    """sha256 des COMMITTETEN Vertrauensankers (Auflage C3, dritter Teil, 2026-09-06).

    WARUM DAS ARTEFAKT IHN TRAEGT. Die Auflage verlangt, den Anker "vor dem Messlauf festzulegen und
    AN DAS ARTEFAKT ZU BINDEN". Ohne diese Bindung sagt ein Artefakt nur, WER es unterschrieben hat;
    es sagt nicht, gegen welchen Ankerzustand das galt. Wird der Anker spaeter erweitert — ein
    Schluessel kommt hinzu, eine Rolle wird gelockert, eine Frist verlaengert —, sieht ein spaeter
    gelesenes Artefakt genauso aus wie vorher, und niemand kann sagen, unter welcher Vertrauensbasis
    es entstanden ist. Mit dem Digest kann das Tor genau das: es vergleicht, was heute gilt, mit dem,
    was zur Messzeit galt.

    WARUM SHA256 DES INHALTS UND NICHT DIE GIT-BLOB-ID. Die Blob-ID ist git-intern (sie hasht einen
    Kopf mit); der Inhaltsdigest ist ohne git nachrechenbar — von einem Leser, der nur die Datei hat.
    Gelesen wird der COMMITTETE Stand, nie der Arbeitsbaum: aus dem Arbeitsbaum koennte ein
    schmutziger Checkout einen Schluessel einlegen und sich selbst beglaubigen, dieselbe Begruendung
    wie beim Anker selbst.

    Fehlt die Datei im HEAD, ist der Digest der leeren Zeichenkette FALSCH — dann gaebe es einen
    Wert, der wie eine Bindung aussieht und keine ist. Stattdessen: leerer String, und der Verifier
    behandelt das wie einen fehlenden Anker (fail-closed).
    """
    r = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{TRUST_ANCHOR_REL}"],
                       capture_output=True, timeout=10)
    if r.returncode != 0:
        return ""
    return hashlib.sha256(r.stdout).hexdigest()


def file_sha256(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def gate_zeile_aus_verdikt(pfad: Path) -> dict:
    """Die Gate-Zeile WOERTLICH aus dem Verdikt des entscheidenden Laufs holen.

    Nicht zusammensetzen, nicht ergaenzen, nicht normalisieren — kopieren. Ein Erzeuger, der die
    Gate-Zeile selbst bauen koennte, waere wieder die Baumaschine, die ihre eigene Freigabe
    beglaubigt. Fehlt ``notes.gate_zeile``, bricht das hier ab statt ein Feld zu erfinden.
    """
    try:
        verdikt = json.loads(Path(pfad).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"gate line: verdict file {pfad} is unreadable: {exc}")
    if not isinstance(verdikt, dict):
        raise SystemExit(f"gate line: verdict file {pfad} is not a JSON object")
    zeile = (verdikt.get("notes") or {}).get("gate_zeile")
    if not isinstance(zeile, dict) or not zeile:
        raise SystemExit(f"gate line: {pfad} carries no notes.gate_zeile — refusing to invent one")
    return zeile


def canonical_bytes(body: dict) -> bytes:
    """The exact bytes signed and verified: RFC-8785 over the body WITHOUT the signature wrapper.

    Everything else is inside — so a field the gate reads is a field the signature covers. That is
    the structural half of property P-A7 ("every line derives its statement from the SIGNED fields");
    an artifact cannot smuggle an unsigned field past the gate, because there is no room for one.
    """
    from proofbundle import canonical  # noqa: PLC0415
    return canonical.canonicalize_statement({k: v for k, v in body.items() if k != SIGNATURE_KEY})


def build_body(measurement: dict, *, repo: Path, version: str, producer_tool: str,
               producer_tool_version: str, input_digest: str, signer_role: str,
               sdist_sha256: str, wheel_sha256: str, produced_at: str,
               gate_zeile: dict) -> dict:
    """The signed body: the measurement, its provenance, its candidate binding AND the gate line.

    The gate line sits INSIDE the body, not in the envelope — the envelope is not signed, so a gate
    line outside it would bind nothing and be decoration."""
    body = {k: v for k, v in measurement.items() if k != SIGNATURE_KEY}
    body["version"] = version
    body["candidate"] = {
        "commit": head_commit(repo),
        "tree_digest": tree_digest(repo),
        "sdist_sha256": sdist_sha256,
        "wheel_sha256": wheel_sha256,
    }
    # Auflage C3, dritter Teil: das Artefakt bindet den Ankerzustand, unter dem es entstand.
    body["trust_anchor_digest"] = trust_anchor_digest(repo)
    # Release-Standard 6.0.0 Zeile 18: das Artefakt bindet zusaetzlich das Verdikt des Tores.
    # Die beiden Felder konkurrieren nicht — sie beantworten verschiedene Fragen. Der Ankerdigest
    # sagt, UNTER WELCHER Vertrauensbasis gemessen wurde; die Gate-Zeile sagt, WELCHES Tor den
    # Kopf durchgelassen hat. Der Merge-Konflikt entstand nur daraus, dass beide Zeilen an
    # derselben Stelle in denselben Rumpf geschrieben werden.
    body["gate_zeile"] = gate_zeile
    body["producer"] = {"tool": producer_tool, "tool_version": producer_tool_version}
    body["input_digest"] = input_digest
    body["signer_role"] = signer_role
    body["produced_at"] = produced_at
    return body


def assemble(body: dict, sig_b64: str, signer_pubkey_b64: str) -> dict:
    """Wrap an externally produced signature. REFUSES on a mismatch — fail-closed, so a bad
    signature/body pair never becomes an artifact on disk."""
    import binascii  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    # LAUF11-L2: strikt und kanonisch, und eine unkanonische Schreibweise wird ABGEWIESEN statt
    # zu werfen — dieselbe Form wie der Signatur-Mismatch eine Zeile weiter.
    try:
        pub = Ed25519PublicKey.from_public_bytes(decode_b64(signer_pubkey_b64))
        roh_sig = decode_b64(sig_b64)
    except (binascii.Error, ValueError) as e:
        raise SystemExit(f"assemble: signature/pubkey field is not canonical base64 — refusing: {e}")
    try:
        pub.verify(roh_sig, canonical_bytes(body))
    except InvalidSignature:
        raise SystemExit("assemble: the signature does not verify over the canonical body — refusing")
    out = dict(body)
    out[SIGNATURE_KEY] = {"alg": "ed25519", "public_key_b64": signer_pubkey_b64, "sig_b64": sig_b64}
    return out


#: Flaggen, deren Ablage anders heisst als die Flagge (``--in`` ist in Python kein Name).
_ABLAGE = {"in": "quelle"}


def _need(args, namen: list[str], modus: str) -> None:
    """Fehlende Pflichtflaggen NENNEN, statt spaeter an einem AttributeError zu sterben.

    GEMESSEN 2026-09-05 vom Erzeuger-gegen-Verbraucher-Test: hier stand
    ``getattr(args, n.replace("-", "_"))``, und fuer ``--in`` (Ablage ``quelle``) gibt es kein
    Attribut ``in`` — das Werkzeug brach mit einem Stacktrace ab, statt zu sagen, was fehlt. Ein
    Erzeuger, den nur sein Autor bedienen kann, ist so gut wie keiner.
    """
    fehlt = [n for n in namen
             if getattr(args, _ABLAGE.get(n, n.replace("-", "_")), None) is None]
    if fehlt:
        raise SystemExit(f"{modus} mode needs: {', '.join('--' + m for m in fehlt)}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=REPO)
    p.add_argument("--in", dest="quelle", type=Path, default=None,
                   help="the raw measurement artifact to bind and sign")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--version", default=None, help="default: the version in pyproject.toml")
    p.add_argument("--producer-tool", default=None)
    p.add_argument("--producer-tool-version", default=None)
    p.add_argument("--input-digest", default=None, help="sha256 (hex) of the corpus/input consumed")
    p.add_argument("--signer-role", default=None, help="e.g. release-runner")
    p.add_argument("--gate-zeile-aus-verdikt", type=Path, default=None,
                   help="deep-gate verdict json; notes.gate_zeile is copied VERBATIM into the "
                        "signed body (never composed here)")
    p.add_argument("--sdist", type=Path, default=None, help="the candidate sdist (digested here)")
    p.add_argument("--wheel", type=Path, default=None, help="the candidate wheel (digested here)")
    p.add_argument("--sdist-sha256", default=None, help="instead of --sdist, when only the digest is at hand")
    p.add_argument("--wheel-sha256", default=None)
    p.add_argument("--produced-at", default=None, help="RFC-3339 UTC; default: now, measured here")
    p.add_argument("--emit-payload", type=Path, default=None,
                   help="keyless: write the canonical bytes here (needs --context-out)")
    p.add_argument("--context-out", type=Path, default=None)
    p.add_argument("--assemble", action="store_true")
    p.add_argument("--context-in", type=Path, default=None)
    p.add_argument("--sig-file", type=Path, default=None)
    p.add_argument("--signer-pubkey", default=None)
    args = p.parse_args(argv)
    repo = args.repo.resolve()

    if args.assemble:
        _need(args, ["context-in", "sig-file", "signer-pubkey", "out"], "assemble")
        body = json.loads(args.context_in.read_text(encoding="utf-8"))
        artefakt = assemble(body, args.sig_file.read_text(encoding="utf-8").strip(),
                            args.signer_pubkey.strip())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(artefakt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"assembled signed evidence -> {args.out}")
        return 0

    # Die Gate-Zeile ist PFLICHT, nicht optional: fehlt die Flagge, bricht das Werkzeug hier ab,
    # statt ein Artefakt ohne Tor-Bindung zu emittieren. Die Modusbezeichnung heisst "emit" und
    # nicht mehr "emit/inline" wie in 3f15b4b — die dritte, inline signierende Form gibt es seit
    # Auflage C9 (Runde 2) nicht mehr, und ein Modusname fuer einen Modus, den es nicht gibt,
    # waere eine Meldung, die den Leser an einen Weg schickt, der nicht existiert.
    _need(args, ["in", "producer-tool", "producer-tool-version", "input-digest", "signer-role",
                 "gate-zeile-aus-verdikt"], "emit")
    version = args.version or pyproject_version(repo)
    if not version:
        raise SystemExit("cannot read the release version from pyproject.toml — pass --version")
    sdist = args.sdist_sha256 or (file_sha256(args.sdist) if args.sdist else None)
    wheel = args.wheel_sha256 or (file_sha256(args.wheel) if args.wheel else None)
    if not sdist or not wheel:
        raise SystemExit("the candidate binding needs both distributions: pass --sdist/--wheel "
                         "(or --sdist-sha256/--wheel-sha256)")
    produced_at = args.produced_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = build_body(json.loads(args.quelle.read_text(encoding="utf-8")), repo=repo, version=version,
                      producer_tool=args.producer_tool,
                      producer_tool_version=args.producer_tool_version,
                      input_digest=args.input_digest, signer_role=args.signer_role,
                      sdist_sha256=sdist, wheel_sha256=wheel, produced_at=produced_at,
                      gate_zeile=gate_zeile_aus_verdikt(args.gate_zeile_aus_verdikt))

    # KEINE dritte, inline Signierform mehr (Auflage C9, Runde 2). Wer signieren will, laesst diesen
    # Prozess NUR die kanonischen Bytes emittieren (--emit-payload) und packt die extern erzeugte
    # Signatur ueber --assemble zusammen. Ein privater Schluessel wird an keiner Stelle dieses
    # Skripts mehr gelesen.
    _need(args, ["emit-payload", "context-out"], "emit")
    args.emit_payload.parent.mkdir(parents=True, exist_ok=True)
    args.emit_payload.write_bytes(canonical_bytes(body))
    args.context_out.parent.mkdir(parents=True, exist_ok=True)
    args.context_out.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8")
    print(f"emitted payload -> {args.emit_payload}  body -> {args.context_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
