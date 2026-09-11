#!/usr/bin/env python3
"""Ceremony: build the structured findings register — and let SOMEBODY ELSE sign it.

WHAT THIS FILE IS FOR. The register is the SINGLE STRUCTURED SOURCE for "how many open P0/P1"
(RT-10 / PB-2026-0718-14). It replaced a lexical "0 open P0/P1" substring scan of a stale .md that
granted a FALSE PASS in ``audit_candidate_matrix`` C12.2 while current open P0/P1 existed. It
carries, per finding, STRUCTURED fields (id, severity, status, superseded_by) plus an ed25519
signature over the canonical (RFC-8785 / JCS) bytes of the register WITHOUT its signature block.

NO PRIVATE KEY IS READ OR CREATED IN THIS FILE (Teil F, 2026-09-06). This is the same fix that
``scripts/sign_readiness_artifact.py`` received under Auflage C9, applied to the neighbour that
still carried the defect — closing a class at one surface while its twin keeps it is how a
capability moves one file over instead of going away.

  Until 2026-09-06 this script called ``_load_or_create_key()``: it read
  ``audit_artifacts/.findings_register_key.ed25519`` or, if that file was absent, GENERATED a fresh
  private key and wrote it to disk — and then signed, in the same process that had just built the
  body. That is self-certification: a signature means "an independent party attests this" only when
  the party holding the key is not the party that shaped what gets signed. It had a second, quieter
  failure mode: run from a tree without the key file, it silently minted a NEW key, so the register
  was validly signed and rejected by the trust anchor, and the message said nothing about why.

  The owner's signing policy (card OA-e10ba2ba39, 2026-09-06) is explicit: the anchor key signs
  "the three readiness artefacts AND THE REGISTER BODY … the private half stays with the owner on
  the Mac, nothing of it on the farmer". So the build host emits, the owner signs, the build host
  assembles — and ``scripts/findings_register.py`` verifies against the ANCHOR, not against a
  second pin of its own.

TWO MODES, the same signed body in both:

  emit      --emit-payload P --context-out C: write the canonical bytes to P and the body to C.
            The key holder signs P out of band; the build host then assembles.
  assemble  --assemble --context-in C --sig-file S --signer-pubkey B --out A: wrap body +
            signature. Self-checks the signature and REFUSES on a mismatch, so a bad pair never
            reaches disk.

Usage:
  python scripts/gen_findings_register.py --emit-payload /tmp/reg.bin --context-out /tmp/reg.json
  # ... the owner signs /tmp/reg.bin on the Mac, producing sig.b64 ...
  python scripts/gen_findings_register.py --assemble --context-in /tmp/reg.json \\
      --sig-file sig.b64 --signer-pubkey <base64 pubkey> --out audit_artifacts/findings_register_361.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from proofbundle import canonical  # noqa: E402

REGISTER_REL = "audit_artifacts/findings_register_361.json"

#: Die Fassung, ueber die dieses Register spricht. Sie MUSS der ausliefernden Identitaet
#: entsprechen — `findings_register._version_binding_error` weist alles andere fail-closed ab, und
#: genau daran fiel C12.2 am 2026-09-06: ein gueltig signiertes Register auf `3.6.1` entschied ueber
#: 6.0.0. Wer diese Zahl aendert, aendert auch FINDINGS; ein Register mit neuer Version und alten
#: Funden waere dieselbe Luege eine Ebene tiefer.
VERSION = "6.0.0"

#: DER EHRLICHE STAND DER 6.0.0-FUNDE, abgeleitet aus `RESTRISIKO_600.md` (N1..N15) — nicht aus
#: dem Gedaechtnis und nicht aus der 3.6.1-Liste, die hier vorher stand.
#:
#: SCHWEREGRAD NACH WIRKUNG, nicht nach Wunsch. Der Gate liest {P0, P1} als freigabeentscheidend;
#: einen Fund niedriger einzustufen, damit das Tor gruen wird, waere genau der falsche PASS, gegen
#: den dieses Register gebaut ist. Massgeblich ist die Spalte „Wirkung" des Restrisiko-Registers,
#: Wort fuer Wort. Zwei Eintraege bleiben ausdruecklich OFFEN (N14, N15) — beide mit
#: Owner-Entscheidung und beide ohne Wirkung auf einen Nutzer des Pakets.
FINDINGS = [
    {"id": "N1", "severity": "P3", "status": "closed",
     "note": "flip oracle of the A5 corpus test read one field; fixed to require ok (bc95dd6). The "
             "wider class — narrow-scope comparison oracles — is not swept repo-wide"},
    {"id": "N2", "severity": "P3", "status": "closed",
     "note": "corpus input key serialised the whole params; fixed to the keys the runner reads, "
             "meta test both ways (bc95dd6)"},
    {"id": "N3", "severity": "P2", "status": "closed",
     "note": "the Receipt: line of a published disclosure block is the file hash, not "
             "receipt_digest(); documented in 6.0.0 rather than changed, because two published "
             "receipts carry it. Can mislead a reader who copies the line into priorDigest"},
    {"id": "N4", "severity": "P3", "status": "closed",
     "note": "POLICY_NOT_EVALUATED and AGENT_REVIEW_LEGACY_V01 moved from reason_codes to "
             "advisory_codes; no released build carried either code before 6.0.0"},
    {"id": "N5", "severity": "P2", "status": "closed",
     "note": "agent-review/v0.2 emits only selfDeclared assurance; a witness outside the agent "
             "workspace is not provided — documented honest limit"},
    {"id": "N6", "severity": "P3", "status": "closed",
     "note": "the time block of a policy file is evaluated only when present; the shipped standard "
             "policy carries none (time_policy_decision: null)"},
    {"id": "N7", "severity": "P3", "status": "closed",
     "note": "the skipped set of the PR-185 full run was not enumerated; the freeze audit run "
             "(pytest -rs) enumerates it and the receipt README lists it"},
    {"id": "N8", "severity": "P3", "status": "closed",
     "note": "C12.1 reports not-applicable on a pull request and absent on main until the signed "
             "6.0.0 receipt exists — the gate at work, not a defect"},
    {"id": "N9", "severity": "P3", "status": "closed",
     "note": "the relative CHANGELOG.md link in the new README section was dead in the sdist; "
             "fixed to an absolute URL (72c21e7)"},
    {"id": "N10", "severity": "P3", "status": "closed",
     "note": "CAP-1 coverage (feat/cap1-abdeckung, target 6.1.0) is not part of 6.0.0 by decision; "
             "the branch is not in the frozen tree"},
    {"id": "N11", "severity": "P2", "status": "closed",
     "note": "the canonical full mutation run was started on 658ed063 before this file existed; "
             "the byte-identity of src/, tests/ and scripts/ against the frozen head is measured "
             "and recorded, or the run is repeated"},
    {"id": "N12", "severity": "P2", "status": "closed",
     "note": "the learned-class ledger replay cannot finish inside the 240 s default window its "
             "runner carries (182 nodes measured 479 s); measured to completion under a wide "
             "window it reports pass. A property of the release-side replay runner, not of shipped "
             "code"},
    {"id": "N13", "severity": "P2", "status": "closed",
     "note": "the replay set contains at least one node whose result depends on runtime state "
             "OUTSIDE the tree under test (tests/test_warte_riegel.py in the 2bedone repository); "
             "recorded because it can decide this package's gate verdict"},
    # ── DIE ZWEI, DIE OFFEN BLEIBEN, und sie stehen als offen da, weil sie es sind ─────────────
    {"id": "N14", "severity": "P2", "status": "open",
     "note": "CLASS: a signing path in the shipped tree. sign_readiness_artifact.py is CLOSED (no "
             "code path loads a private key, measured by AST); pre_tag_receipt.py is DEFUSED, not "
             "closed — excluded from the sdist file by file and refusing to run inline without "
             "PB_INLINE_SIGNING=1, never on an automated build host. The CLASS — a build host that "
             "can reach a private key at all — is carried to 6.1 with the separate signing "
             "principal, so this entry stays OPEN until then. Owner decision 2026-09-06, card "
             "OA-8b1a31cc4f"},
    {"id": "N15", "severity": "P2", "status": "open",
     "note": "the wheel of 6.0.0 is bit-reproducible in both directions and also built from the "
             "shipped sdist; the sdist is not. Cause measured to the byte: the sdist path of "
             "setuptools 84.0.0 does not honour SOURCE_DATE_EPOCH, so each archive carries a pax "
             "header with the wall clock. The CONTENT of both builds is identical. Owner decision "
             "2026-09-06: 6.0.0 ships with this sdist and the non-reproducibility is named rather "
             "than played down; the build-backend change is a 6.1 item"},
    # ── DIE DREI FUNDE DES ADVERSARIAL DEEP GATE, LAUF 5 (2026-09-06) ──────────────────────────
    #
    # SCHWEREGRAD IST HIER NICHT GEWAEHLT, SONDERN UEBERNOMMEN. Alle drei tragen P2, weil die
    # dreikoepfige Jury des Laufs sie so bewertet hat — nicht, weil P2 das Tor gruen laesst. Der
    # Unterschied ist wichtig genug, ihn hinzuschreiben: der Kommentar oben warnt genau davor,
    # einen Fund herunterzustufen, damit C12.2 durchgeht, und wer diese Zeilen liest, soll die
    # Herkunft der Zahl pruefen koennen statt sie glauben zu muessen. Verdikt des Laufs:
    # FIX_FIRST. Fuer 6.0.0 wird KEIN WITHSTANDS_DEEPGATE behauptet.
    #
    # Alle drei stehen OFFEN. Owner-Entscheid OA-b4489d0204 vom 2026-09-06: sie bleiben fuer
    # 6.0.0 unter der Halte-Schwelle und werden im Sammelrelease geschlossen.
    {"id": "N16", "severity": "P2", "status": "open",
     "note": "deep gate run 5, L6-02: action/action.yml:35-36 interpolates ${{ inputs.version }} "
             "and ${{ inputs.extras }} directly into a run: shell body, while lines 43-44 route "
             "inputs.command through env: and say why. A class fix applied to one of three inputs "
             "of one file and never swept to its siblings. NOT introduced by this release: the "
             "file is byte-identical to the one at the public v1.0.0 tag (sha256 91cfcdc4…, a "
             "single commit ever touched it, that tag is an ancestor of this candidate). Measured "
             "reach: INTEGRATIONS.md points at action@v1.0.0, that tag is FIXED, and no moving "
             "major ref v1 exists — so a fix on main does NOT reach the documented users; a new "
             "action ref is outward-facing and needs its own owner GO. Owner decision "
             "OA-b4489d0204: first item after the tag, not pulled forward, because "
             "action/action.yml lies inside the frozen tree"},
    {"id": "N17", "severity": "P2", "status": "open",
     "note": "deep gate run 5, L5-G8-01: scripts/rust_parity_gate.py:124 swallows an unparseable "
             "or unreadable source file (except (SyntaxError, OSError): continue), and "
             "registry_integrity_ok derives its verdict as ok = not (untracked or orphaned or "
             "stale) — an assertion from ABSENT complaint over the resulting population. The "
             "consumers c8_1_registry_integrity and c8_3_pending_documented are RELEASE-DECIDING "
             "(measured: neither is in _INFORMATIVE_CHECKS, audit_candidate_matrix.py:84). "
             "MEASURED LIMIT on this candidate: the population is COMPLETE — 68 of 68 .py under "
             "src/ parse and are readable — so no verdict of this release rests on a narrowed "
             "set; the finding is the CAPABILITY of a false pass, not its occurrence. The same "
             "class is already closed in the neighbour (type_confusion_gate.py:487-499, which "
             "names rust_parity_gate.py:124 verbatim as the defect site), and the docstring of "
             "the defective function itself lists FOUR narrowings of this class lifted on "
             "2026-08-26; this branch survived that sweep and carries no test (no occurrence of "
             "SyntaxError or OSError in tests/test_rust_parity_gate.py). Owner decision "
             "OA-b4489d0204: below the hold threshold for 6.0.0, closed in the collection release "
             "following the pattern the neighbour already carries, with a catch-proof"},
    {"id": "N18", "severity": "P2", "status": "open",
     "note": "deep gate run 5, L6-01: pip install <sdist> && pytest WITHOUT the [test] extras is "
             "RED, not skipped, while the shipped pyproject.toml promises a bare [eval] install "
             "'degrades to clean skips'. Measured: 1 failed, 3075 passed, 482 skipped; the red "
             "node is tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py::"
             "test_gate_meta_koexistenz_im_selben_job_reicht_nicht_mehr, which reaches PyYAML "
             "INDIRECTLY through scripts/audit_candidate_matrix.py:1395 and therefore does not "
             "carry the module's own @_braucht_yaml guard — the guard sits where the import is "
             "VISIBLE, not where the dependency IS. Introduced by this candidate's own commit "
             "1311498. Additionally measured: the CI step whose own comment claims to pin exactly "
             "this property (published-artifact-gate.yml:83-84, 'Stops the invariant from "
             "drifting false again') installs [test] into the same venv at line 86 before the "
             "suite starts at line 92 — the bare path is exercised NOWHERE; and the guard built "
             "for the earlier instance of this class (L6-F1-SDIST-PYYAML, 2026-08-25) is scaled "
             "to a single file (tests/test_sdist_selftest_optional_deps.py:35), while the "
             "regression landed in its sibling. Owner decision OA-b4489d0204, Auflage 4: own "
             "register entry and named in the release note; in the collection release the promise "
             "is either honoured or reworded in pyproject.toml"},
    # ── DIE MESSGRENZEN DER STUFE-6-EVIDENZ, Owner-Auflage vom 2026-09-06 ──────────────────────
    {"id": "N19", "severity": "P3", "status": "open",
     "note": "the mutation gate collects its test population with unittest discover and therefore "
             "measures a SUBSET: measured on this candidate, unittest discover runs 2537 tests "
             "while pytest collects 3702, and 59 of 252 test files carry only pytest functions and "
             "are invisible to that collector. Every stage-6 statement of this release is bounded "
             "by that subset: SURVIVED means 'no unittest-visible test catches this'. Of the 100 "
             "operators, 91 were killed, 7 survived only because the gate cannot see the test that "
             "kills them (each proven by running pytest against the MEASURED covering file), 1 is "
             "not measurable (N20), 1 is a documented equivalent expected to survive — and ZERO "
             "are real gaps. Sibling scope figures of this release: the learned-class ledger "
             "replay ran 94 of 182 classes (the other 88 carry no evidence in either direction), "
             "the Python/Rust parity gate saw 68 of 68 source files. Closing action after the tag: "
             "move the gate to a collector that sees every test, with a catch-proof"},
    {"id": "N20", "severity": "P3", "status": "open",
     "note": "one mutation operator is NOT MEASURABLE rather than killed or survived: 'budget: "
             "data_digests-Schranke praktisch entfernt' removes the very resource ceiling under "
             "test, and the mutated run reached 116519388 kB RSS (111 GiB, 88.3 % of memory, 1 GiB "
             "free) before it was stopped deliberately rather than left to the OOM killer, whose "
             "choice of victim would not have been the same process. An earlier attempt ended at "
             "signal 9. Neither outcome is a test verdict — what stopped the run was the kernel, "
             "not an assertion — so it is counted in neither sort. This is evidence that the "
             "ceiling the operator removes does its job, not a defect of the candidate"},
    # N21 FEHLTE HIER BIS 2026-09-08, und die Luecke war strukturell unsichtbar: C12.2 zaehlt
    # OFFENE P0/P1 im signierten Register, und eine FEHLENDE Zeile kann dort nicht offen sein. Das
    # Restrisiko-Register fuehrte N1..N21, dieses hier N1..N20, und audit_artifacts/600/README.md
    # zaehlte ausdruecklich „R1-R7 and N1-N21" — drei Dokumente, zwei Zahlen, kein Vergleich. Der
    # Riegel dagegen ist jetzt tests/test_register_population_gegen_restrisiko.py: er VERGLEICHT
    # die beiden Populationen, statt die eine aus der anderen abzuleiten. Owner-GO 08.09.2026.
    {"id": "N21", "severity": "P3", "status": "open",
     "note": "the release-deciding check C12.2 flips PASS to FAIL on 2027-09-07 BY DESIGN, and this "
             "line exists so that a gate which turns red on a calendar date is written down BEFORE "
             "it does, not explained afterwards. The closing-round fix makes an expired anchor key "
             "authorise nothing NOW, and the sole key carries not_after=2027-09-06; an empty "
             "authorised set is FAIL, not DATA_BLOCKED (only an unreadable anchor is the latter). "
             "From that day the audit matrix goes red until the key is rotated. Intended behaviour "
             "of a validity window, not a defect of the candidate. Closing action: rotate the key "
             "before 2027-09-06, or accept the red"},
]


def build_register(generated_at: str) -> dict:
    return {
        "schema": "proofbundle.findings_register.v1",
        "version": VERSION,
        "generated_at": generated_at,
        "findings": FINDINGS,
    }


def canonical_bytes(body: dict) -> bytes:
    """The exact bytes signed and verified: RFC-8785 over the body WITHOUT the signature wrapper."""
    return canonical.canonicalize_statement({k: v for k, v in body.items() if k != "signature"})


def assemble(body: dict, sig_b64: str, signer_pubkey_b64: str) -> dict:
    """Wrap an externally produced signature. REFUSES on a mismatch — fail-closed, so a bad
    signature/body pair never becomes a register on disk."""
    import binascii  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey)
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    # LAUF11-L2: strikt und kanonisch; unkanonisch wird abgewiesen, nicht geworfen.
    try:
        pub = Ed25519PublicKey.from_public_bytes(decode_b64(signer_pubkey_b64))
        roh_sig = decode_b64(sig_b64)
    except (binascii.Error, ValueError) as e:
        raise SystemExit(f"assemble: signature/pubkey field is not canonical base64 — refusing: {e}") from None
    try:
        pub.verify(roh_sig, canonical_bytes(body))
    except InvalidSignature:
        raise SystemExit("assemble: the signature does not verify over the canonical register body "
                         "— refusing") from None
    out = dict(body)
    out["signature"] = {"alg": "ed25519", "public_key_b64": signer_pubkey_b64, "sig_b64": sig_b64}
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--generated-at", default=None,
                   help="RFC-3339 UTC; default: measured now")
    p.add_argument("--emit-payload", type=Path, default=None,
                   help="keyless: write the canonical bytes here (needs --context-out)")
    p.add_argument("--context-out", type=Path, default=None)
    p.add_argument("--assemble", action="store_true")
    p.add_argument("--context-in", type=Path, default=None)
    p.add_argument("--sig-file", type=Path, default=None)
    p.add_argument("--signer-pubkey", default=None)
    p.add_argument("--out", type=Path, default=None)
    a = p.parse_args(argv)

    if a.assemble:
        fehlt = [n for n in ("context_in", "sig_file", "signer_pubkey", "out")
                 if getattr(a, n, None) is None]
        if fehlt:
            raise SystemExit("assemble mode needs: "
                             + ", ".join("--" + n.replace("_", "-") for n in fehlt))
        body = json.loads(a.context_in.read_text(encoding="utf-8"))
        register = assemble(body, a.sig_file.read_text(encoding="utf-8").strip(),
                            a.signer_pubkey.strip())
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8")
        print(f"assembled signed register -> {a.out} ({len(FINDINGS)} findings, version {VERSION})")
        return 0

    fehlt = [n for n in ("emit_payload", "context_out") if getattr(a, n, None) is None]
    if fehlt:
        raise SystemExit("emit mode needs: "
                         + ", ".join("--" + n.replace("_", "-") for n in fehlt))
    # DIE ZEITMARKE WIRD GEMESSEN, nicht fortgeschrieben. Die frueheren Fassungen trugen hier
    # `2026-07-18T00:00:00Z` als Vorgabewert, und dieses Datum stand danach in einem Register, das
    # ueber eine Fassung zwei Hauptversionen spaeter entschied. `findings_register` prueft die
    # Marke auf Form; sie soll auch stimmen.
    if a.generated_at is None:
        from datetime import datetime, timezone  # noqa: PLC0415
        a.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = build_register(a.generated_at)
    a.emit_payload.parent.mkdir(parents=True, exist_ok=True)
    a.emit_payload.write_bytes(canonical_bytes(body))
    a.context_out.parent.mkdir(parents=True, exist_ok=True)
    a.context_out.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    print(f"emitted payload -> {a.emit_payload}  body -> {a.context_out} "
          f"({len(FINDINGS)} findings, version {VERSION}, generated_at {a.generated_at})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
