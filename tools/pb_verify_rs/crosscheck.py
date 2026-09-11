#!/usr/bin/env python3
"""Cross-implementation conformance harness (3.2.0 O8).

Drives the independent Rust verifier (`pb_verify_rs`, built with cargo) against fixtures that the
Python implementation produces, and asserts AGREEMENT on the core verifier properties — with NO
shared canonicalization or parser code between the two implementations:

  1. jcs-sha256-v1 content root of a signed statement (RFC 8785)  -> Rust == Python
  2. DSSE / Ed25519 signature verify over the exact PAE bytes      -> Rust OK on a Python-signed env
  3. a flipped payload byte                                         -> Rust FAIL (negative vector)
  4. a duplicate JSON key                                           -> Rust REJECT (parser-differential)
  5. RFC 6962 Merkle tree head                                      -> Rust == Python
  6. trust-pack/v0.1 root-of-trust THRESHOLD (Ed25519 leg, Finding 11) -> Rust == Python
     root_threshold_met, on both a threshold-met and a threshold-NOT-met envelope

Exit 0 iff every property agrees; non-zero (and a printed diff) on the first mismatch. Read-only:
writes only to a temp dir, no network.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
#: WELCHE BINAERDATEI GEMESSEN WIRD, ist eine Eigenschaft des Laufs und gehoert in seine Ausgabe.
#:
#: GEMESSEN AN MIR SELBST, 10.09.2026: ich habe die RELEASE-Binaerdatei gegen eine mit korrigierter
#: JCS-Crate getauscht und zweimal dasselbe Urteil bekommen. Daraus wurde ein Befund
#: ("das Differential unterscheidet die Implementierungen nicht"), und er war falsch. In diesem
#: Baum lag eine `target/debug`-Datei vom 18.07.2026, zwei Monate alt — und die Auswahl unten
#: nimmt debug MIT VORRANG. Beide Laeufe gingen gegen dieselbe alte Datei; ich habe die falsche
#: Flaeche ersetzt und das Ergebnis als Eigenschaft des Pruefstands gelesen.
#:
#: Die Reihenfolge bleibt (debug zuerst ist beim Entwickeln richtig, weil `cargo build` ohne
#: --release dorthin schreibt). Was sich aendert: der Lauf SAGT, welche Datei er nimmt, mit
#: Aenderungszeit — und er sagt es auch, wenn beide existieren. Wer filtert, nennt die
#: Ausschussmenge; das gilt auch, wenn der Filter nur zwei Kandidaten hat.
_KANDIDATEN = [ROOT / "tools" / "pb_verify_rs" / "target" / t / "pb_verify_rs"
               for t in ("debug", "release")]
BIN = next((b for b in _KANDIDATEN if b.exists()), _KANDIDATEN[0])


def _binaer_herkunft() -> str:
    """Eine Zeile, die sagt WOMIT gemessen wurde — und was daneben lag, aber nicht genommen wurde."""
    import datetime  # noqa: PLC0415
    def _zeit(b: pathlib.Path) -> str:
        try:
            return datetime.datetime.fromtimestamp(
                b.stat().st_mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except OSError:
            return "?"
    andere = [b for b in _KANDIDATEN if b != BIN and b.exists()]
    zeile = f"BINARY UNDER TEST: {BIN} (mtime {_zeit(BIN)})"
    if andere:
        zeile += ("; NOT used, though present: "
                  + ", ".join(f"{b} (mtime {_zeit(b)})" for b in andere))
    return zeile

sys.path.insert(0, str(SRC))
# F1: the differential reproduces the SAME corpus in the SAME common vocabulary as the
# conformance runner and cross-format comparator — no third ad-hoc labelling here.
sys.path.insert(0, str(ROOT / "conformance"))
from common_vocabulary import compare, exit_class, expected_label, label_from_verify  # noqa: E402

# 3.5.0 WP-B: relation vectors are driven differentially through these three kinds. The Rust
# subcommand is verify-relation for the in-receipt (decision/outcome) path and verify-relation-statement
# for the standalone relation-statement/v0.1 path; the Python CLI verb is the matching one.
_RELATION_KINDS = {
    "decision_relation": ("verify-relation", "decision"),
    "outcome_relation": ("verify-relation", "outcome"),
    "relation_statement": ("verify-relation-statement", "relation-statement"),
}

#: Korpus-`kind`s, die dieses Differential BEWUSST nicht faehrt — je mit Grund, nicht stillschweigend.
#:
#: WARUM DIESE LISTE UEBERHAUPT EXISTIERT (gemessen 10.09.2026, deep gate Lauf 10, Fund
#: L1-JCS-IMPL-SPLIT-01). Die Korpus-Schleife unten war ein `if/elif/elif` OHNE `else`. Ein Fall mit
#: einer unbekannten `kind` fiel lautlos heraus: kein Vergleich, keine Meldung, `reproduced` blieb
#: stehen. Die Zahl ging exakt auf — 94 Faelle im Manifest, 57 gemeldet, und die Differenz von 37
#: verteilte sich auf genau drei ungedeckte `kind`s (agent_review_predicate 17,
#: envelope_profile_rule 10, provenance_version_status 10).
#:
#: WAS DAS GEKOSTET HAT: unter den zehn stummen `envelope_profile_rule`-Faellen lag
#: `r1-positive-control-canonical-root`, der die kanonische Wurzel NORMATIV pinnt. Der
#: ausgelieferte Rust-Verifizierer verfehlt sie (2131bd93… statt cbb19685…), weil serde_jcs 0.1.0
#: nach UTF-8-Bytes statt nach UTF-16-Code-Units sortiert. Dieses Differential hat das nicht
#: gemeldet — gemessen gab es fuer eine KONFORME und eine NICHT-konforme Binaerdatei zeichengleich
#: `CROSS-IMPL OK … 57/94`. Ein Differential, das zwei messbar verschiedene Implementierungen nicht
#: unterscheidet, misst die Implementierung nicht.
#:
#: DIE REGEL AB HIER: eine Luecke ist entweder GEFAHREN oder NAMENTLICH GENANNT. Ein `kind`, der in
#: keiner der beiden Mengen steht, BLOCKT — derselbe Schluss-Arm wie bei der Strukturschranke
#: (S78): vier Zweige ohne Sonst sind vier Zweige und ein Loch.
_NICHT_DIFFERENTIELL = {
    "agent_review_predicate": ("das agent-review-Praedikat hat im Rust-Verifizierer keine "
                               "Entsprechung; es wird vom Python-Konformanzlauf gefahren"),
    "provenance_version_status": ("der Provenance-/Versionsstatus ist eine Python-seitige "
                                  "Ableitung ohne Rust-Unterbefehl"),
}


def _run(*args: str) -> tuple[int, str]:
    p = subprocess.run([str(BIN), *args], capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip()


def _relation_argv_common(case: dict, cdir: pathlib.Path) -> list[str]:
    argv: list[str] = []
    for rel in case.get("related", []) or []:
        argv += ["--with-related", str(cdir / rel)]
    for rp in case.get("relatedPubs", []) or []:
        argv += ["--related-pub", str(rp)]
    if case.get("policy"):
        argv += ["--policy", str(cdir / case["policy"])]
    return argv


def _python_relation_label(verb: str, inp: str, pub_b64: str, common: list[str]) -> tuple[int, dict]:
    """Run the REAL Python CLI verify (in-process) and project its --json output onto the common
    label. This makes the relation differential a genuine Python<->Rust comparison, not merely
    Rust-vs-declared-expectation."""
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415
    from proofbundle.cli import main as _cli_main  # noqa: PLC0415
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = _cli_main([verb, "verify", inp, "--pub", pub_b64, "--json", *common])
    try:
        report = json.loads(out.getvalue())
    except ValueError:
        report = None
    return rc, label_from_verify(rc, report)


def main() -> int:
    if not BIN.exists():
        print(f"FAIL: rust binary not built ({BIN}) — run `cargo build` in tools/pb_verify_rs first")
        return 2
    # VOR der Messung, nicht erst im Erfolgsfall: ein Lauf, der scheitert, muss genauso sagen,
    # womit er gescheitert ist.
    print(_binaer_herkunft())

    from datetime import datetime, timedelta, timezone

    from proofbundle import canonical
    from proofbundle.emit import generate_signer
    from proofbundle.outcome import build_outcome_statement, emit_outcome_receipt
    from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack

    #: Der in-toto-Statement-Payloadtyp, unter dem dieses Projekt signiert.
    INTOTO_PT = "application/vnd.in-toto+json"
    failures: list[str] = []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="pb_crosscheck_"))

    pred = {
        "schemaVersion": "0.1.0", "outcomeId": "o-crosscheck",
        "decisionRef": {"sha256": "a" * 64}, "executor": {"id": "exec:1", "keyId": "k"},
        "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
    }
    sk = generate_signer()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()

    # (1) content root
    stmt = build_outcome_statement(pred)
    stmt_bytes = canonical.canonicalize_statement(stmt)
    (tmp / "stmt.json").write_bytes(stmt_bytes)
    py_root = hashlib.sha256(stmt_bytes).hexdigest()
    _, rust_root = _run("content-root", str(tmp / "stmt.json"))
    if rust_root != py_root:
        failures.append(f"content-root mismatch: py={py_root} rust={rust_root}")

    # (2) real DSSE verify
    env = emit_outcome_receipt(pred, sk)
    (tmp / "env.json").write_text(json.dumps(env))
    code, out = _run("verify-dsse", str(tmp / "env.json"), pub)
    if not (code == 0 and out == "OK"):
        failures.append(f"real DSSE verify should be OK/exit0, got {out}/exit{code}")

    # (3) tampered payload -> FAIL
    from proofbundle._wire_b64 import decode_b64_either  # noqa: PLC0415
    # LAUF11-L2: DSSE-Feld -> der DSSE-Decoder (beide Alphabete, gepolstert, kanonisch).
    body = json.loads(decode_b64_either(env["payload"]))
    body["predicate"]["outcomeId"] = "EVIL"
    env_t = dict(env)
    env_t["payload"] = base64.b64encode(json.dumps(body).encode()).decode()
    (tmp / "env_t.json").write_text(json.dumps(env_t))
    code, out = _run("verify-dsse", str(tmp / "env_t.json"), pub)
    if not (code == 1 and out == "FAIL"):
        failures.append(f"tampered payload should FAIL/exit1, got {out}/exit{code}")

    # (4) duplicate JSON key -> REJECT
    (tmp / "dup.json").write_text('{"a":1,"a":2}')
    code, out = _run("strict-parse", str(tmp / "dup.json"))
    if not (code == 1 and out.startswith("REJECT")):
        failures.append(f"duplicate key should REJECT/exit1, got {out}/exit{code}")

    # (4b) LAUF11-L4: DIE BUDGET-ACHSE, der negative Vektor, der in Lauf 11 fehlte.
    #
    # WARUM ER FEHLTE UND WAS ES KOSTETE: dieser Kreuzvergleich prueft, worueber er Vektoren hat.
    # Fuer die Ressourcenschranken hatte er keine — und genau dort liefen die beiden
    # Implementierungen auseinander, ohne dass hier etwas aufgefallen waere. Gemessen in Lauf 11:
    # ein echtes, kanonisches, GUELTIG SIGNIERTES DSSE-Ziel mit einem Feld ueber 1 MB liess Python
    # mit exit 2 abbrechen ("verification budget exceeded: string_len = 1333724 > limit 1000000"),
    # waehrend der Rust-Verifizierer exit 0 und {"lineage":"VERIFIED"} meldete. Der Kreuzvergleich
    # meldete in derselben Runde CROSS-IMPL OK.
    #
    # DIE KLASSE, dritte Auspraegung an dieser Flaeche: ein Kreuzvergleich ohne Vektor fuer eine
    # Flaeche SCHWEIGT ueber sie — und sein Schweigen liest sich wie Uebereinstimmung. Der Vektor
    # unten ist der Unterschied zwischen "die Flaechen stimmen ueberein" und "die Flaechen, die ich
    # kenne, stimmen ueberein".
    #
    # Zwei Haelften, weil zwei Dinge auseinanderlaufen koennen: die WIRKUNG (weist derselbe Fall
    # beide ab?) und die ZAHL (haben beide dieselbe Schranke?). Die erste ohne die zweite ginge
    # gruen, solange irgendeine Schranke greift, auch eine andere.
    from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    from proofbundle.dsse import sign_envelope as _sign_env  # noqa: PLC0415
    from proofbundle.dsse import verify_envelope as _verify_env  # noqa: PLC0415

    # Das DSSE-Primitiv direkt, nicht ueber ein Predicate: `emit_outcome_receipt` weist ein
    # unbekanntes Feld schon am Schema ab (additionalProperties:false), und dann traegt der Vektor
    # gar kein Feld ueber der Schranke mehr — er pruefte die Schema-Schicht statt der Budget-Achse.
    # Genau dieselbe Verwechslung wie beim `canonicalize_refuses`-Zweig weiter unten: eine
    # Erwartung auf den falschen Pruefpfad gelegt.
    gross = {"a": 1, "ueberDerSchranke": "x" * (DEFAULT_BUDGET.string_len + 1)}
    env_b = _sign_env(json.dumps(gross).encode(), sk, payload_type=INTOTO_PT)
    (tmp / "env_budget.json").write_text(json.dumps(env_b))
    try:
        # LAUF11-L2, MEIN EIGENER RUECKFALL: diese Zeile entstand BEIM Bau des L4-Vektors und
        # rief wieder den stdlib-Dekoder — genau die Klasse, die derselbe Commit schliesst.
        # Der Riegel hat sie gefangen, nicht ich.
        py_budget_ok = bool(_verify_env(env_b, decode_b64(pub)))
    except Exception as exc:  # noqa: BLE001 — eine typisierte Abweisung IST das Urteil
        py_budget_ok, py_budget_grund = False, f"{type(exc).__name__}: {exc}"
    else:
        py_budget_grund = "accepted"
    code, out = _run("verify-dsse", str(tmp / "env_budget.json"), pub)
    rust_budget_ok = code == 0
    if py_budget_ok != rust_budget_ok:
        failures.append(
            f"budget axis: python_ok={py_budget_ok} ({py_budget_grund}) but rust exit={code} "
            f"({out}) — one verifier accepts a target the other refuses to even parse; the "
            f"independent instance is then not a second opinion but a second door")
    if py_budget_ok:
        failures.append(f"budget fixture bug: python should refuse a field over string_len, "
                        f"got {py_budget_grund}")

    # Die ZAHLEN selbst, nicht nur ihre Wirkung: `pb_verify_rs budget` gibt aus, was der Binary
    # WIRKLICH benutzt. Ein Kommentar im Quelltext waere hier kein Beleg.
    code, out = _run("budget")
    if code != 0:
        failures.append(f"the rust verifier does not report its budget (exit {code}: {out}) — a "
                        f"drift between the two schedules would be unmeasurable from here")
    else:
        try:
            rust_budget = json.loads(out)
        except ValueError:
            rust_budget = None
        if not isinstance(rust_budget, dict) or not rust_budget:
            failures.append(f"`pb_verify_rs budget` is not a JSON object: {out!r}")
        else:
            for dim, wert in sorted(rust_budget.items()):
                py_wert = getattr(DEFAULT_BUDGET, dim, None)
                if py_wert != wert:
                    failures.append(f"budget drift on {dim}: rust={wert} python={py_wert} — the "
                                    f"same document gets two verdicts depending on which verifier "
                                    f"reads it")

    # (5) RFC 6962 Merkle head
    la = hashlib.sha256(b"leafA").hexdigest()
    lb = hashlib.sha256(b"leafB").hexdigest()
    py_merkle = hashlib.sha256(bytes([1]) + bytes.fromhex(la) + bytes.fromhex(lb)).hexdigest()
    _, rust_merkle = _run("merkle-root", la, lb)
    if rust_merkle != py_merkle:
        failures.append(f"merkle mismatch: py={py_merkle} rust={rust_merkle}")

    # (6) trust-pack/v0.1 root-of-trust THRESHOLD (Finding 11, Ed25519 leg): a 3-key root role with
    # threshold 2, signed by 2 keys (met) and by only 1 key (NOT met) — Rust's dedicated
    # verify-trust-pack-threshold subcommand must agree with Python's verify_trust_pack on BOTH.
    tp_r1, tp_r2, tp_r3 = generate_signer(), generate_signer(), generate_signer()
    tp_pub = {
        kid: base64.b64encode(sk.public_key().public_bytes_raw()).decode()
        for kid, sk in (("r1", tp_r1), ("r2", tp_r2), ("r3", tp_r3))
    }
    tp_expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tp_predicate = {
        "schemaVersion": "0.1.0", "trustPackId": "tp-crosscheck", "version": 1,
        "expires": tp_expires, "prevVersionDigest": None,
        "roles": {"root": {"keyIds": ["r1", "r2", "r3"], "threshold": 2}},
        "keys": {kid: {"publicKey": pk} for kid, pk in tp_pub.items()},
        "nonClaims": ["does not assert the key holders are honest, only that a threshold signed"],
    }
    tp_env_met = sign_trust_pack(tp_predicate, {"r1": tp_r1, "r2": tp_r2})
    tp_env_unmet = sign_trust_pack(tp_predicate, {"r1": tp_r1})
    py_met = verify_trust_pack(tp_env_met)["root_threshold_met"]
    py_unmet = verify_trust_pack(tp_env_unmet)["root_threshold_met"]
    if py_met is not True:
        failures.append(f"trust-pack fixture bug: Python root_threshold_met should be True, got {py_met}")
    if py_unmet is not False:
        failures.append(f"trust-pack fixture bug: Python root_threshold_met should be False, got {py_unmet}")
    (tmp / "tp_met.json").write_text(json.dumps(tp_env_met))
    (tmp / "tp_unmet.json").write_text(json.dumps(tp_env_unmet))
    code, out = _run("verify-trust-pack-threshold", str(tmp / "tp_met.json"))
    if not (code == 0 and out.startswith("OK") and py_met):
        failures.append(f"trust-pack threshold-met mismatch: py={py_met} rust={out}/exit{code}")
    code, out = _run("verify-trust-pack-threshold", str(tmp / "tp_unmet.json"))
    if not (code == 1 and out.startswith("FAIL") and py_unmet is False):
        failures.append(f"trust-pack threshold-unmet mismatch: py={py_unmet} rust={out}/exit{code}")

    # (7) reproduce the actual conformance corpus (§7 "Zweitverifier reproduziert den Conformance-Corpus")
    corpus = ROOT / "conformance"
    manifest = json.loads((corpus / "manifest.json").read_text())
    reproduced = 0
    skipped: list[str] = []
    #: kind -> Fall-Kennungen, die BENANNT nicht differentiell gefahren werden.
    nicht_gedeckt: dict[str, list[str]] = {}
    matrix_rows: list[dict] = []
    for cid in manifest.get("cases", []):
        cdir = corpus / cid
        case = json.loads((cdir / "case.json").read_text())
        kind, expected = case.get("kind"), case.get("expected", {})
        if kind == "decision_crossimpl":
            # independent Rust content root of the decision statement == the pinned corpus value,
            # and the committed .jcs bytes hash to the same root (byte-identical canonicalization).
            want = expected.get("decision_content_root")
            _, got = _run("content-root", str(cdir / "decision_receipt.json"))
            if want and got != want:
                failures.append(f"corpus {cid}: content root py-pinned={want} rust={got}")
            jcs_hash = hashlib.sha256((cdir / "decision_receipt.jcs").read_bytes()).hexdigest()
            if want and jcs_hash != want:
                failures.append(f"corpus {cid}: committed .jcs hash {jcs_hash} != pinned root {want}")
            reproduced += 1
        elif kind == "native_bundle":
            # The Rust verify-bundle reproduces the exit-code contract on the signature + RFC 6962 merkle
            # + relying-party root/tree-size surface. Cases whose DECIDING check is the sd_jwt_vc block or an
            # external anchor need the not-yet-built sd-jwt / anchor slices and are honestly skipped.
            if False:  # all native_bundle cases now covered
                skipped.append(cid)
                continue
            args = case.get("verifyArgs") or []
            code, _ = _run("verify-bundle", str(cdir / "bundle.json"), *args)
            want = expected.get("exitCode")
            if want is not None and exit_class(code) != exit_class(want):
                failures.append(f"corpus {cid}: verify-bundle {exit_class(code)} (exit {code}) "
                                f"!= expected {exit_class(want)} (exit {want})")
            reproduced += 1
        elif kind in _RELATION_KINDS:
            # (8) relation/relation-statement differential (3.5.0 WP-B): the INDEPENDENT Rust relation
            # engine must land on the SAME common-vocabulary label (exit class + lineage) as the Python
            # CLI on EVERY relation vector — positive AND negative (incl. the 3.4.0 decoy-parent /
            # subject-mismatch / signer / t1 vectors and the new standalone statement vectors). A
            # mismatch on any axis, or a divergence from the case's declared expectation, is a hard fail.
            rust_sub, py_verb = _RELATION_KINDS[kind]
            pub = (cdir / case.get("pub", "pub.b64")).read_text(encoding="utf-8").strip()
            inp = str(cdir / case.get("input", "receipt.json"))
            common = _relation_argv_common(case, cdir)
            rust_rc, rust_out = _run(rust_sub, inp, pub, *common)
            try:
                rust_report = json.loads(rust_out)
            except ValueError:
                rust_report = None
            rust_label = label_from_verify(rust_rc, rust_report)
            py_rc, py_label = _python_relation_label(py_verb, inp, pub, common)
            exp_label = expected_label(expected)
            ok_pr, diffs_pr = compare(py_label, rust_label)   # Python<->Rust agreement
            ok_re, diffs_re = compare(exp_label, rust_label)   # Rust reproduces the declared expectation
            if not ok_pr:
                failures.append(f"corpus {cid}: Python!=Rust differential — {'; '.join(diffs_pr)}")
            if not ok_re:
                failures.append(f"corpus {cid}: Rust!=declared-expectation — {'; '.join(diffs_re)}")
            matrix_rows.append({
                "caseId": case.get("caseId", cid), "kind": kind,
                "expected": exp_label, "python": py_label, "rust": rust_label,
                "python_exit": py_rc, "rust_exit": rust_rc,
                "agree_python_rust": ok_pr, "rust_reproduces_expectation": ok_re,
            })
            reproduced += 1
        elif kind == "envelope_profile_rule":
            # R1, die EINE normative Kanonisierung. Der positive Kontrollfall pinnt die content-root
            # des Eingabeobjekts; der unabhaengige Rust-Verifizierer muss sie byte-genau
            # reproduzieren. Genau dieser Fall lag bis zum 10.09.2026 im stummen Pfad.
            # GENAU EINE ERWARTUNGSACHSE, uebernommen aus run_conformance.py Zeile 359 folgende:
            # ein unter-deklarierter Fall kann nicht fehlschlagen, ein ueber-deklarierter verdeckt
            # alles nach der ersten Achse. Die Achsenliste wird DORT gefuehrt; hier wird nur
            # geprueft, dass genau eine davon dasteht.
            _ACHSEN = ("contentRootHex", "nonConformantDiffers", "canonicalizeRefuses",
                       "classification")
            genannt = [a for a in _ACHSEN if a in expected]
            if len(genannt) != 1:
                failures.append(f"corpus {cid}: envelope_profile_rule muss GENAU EINE "
                                f"Erwartungsachse tragen, gefunden {genannt or 'keine'}")
                continue
            want = expected.get("contentRootHex")
            if want:
                _, got = _run("content-root", str(cdir / case.get("input", "object.json")))
                if got != want:
                    failures.append(f"corpus {cid}: content root pinned={want} rust={got} "
                                    f"— the second verifier does not reproduce the normative "
                                    f"canonical root (RFC 8785 §3.2.3)")
                reproduced += 1
            elif "canonicalizeRefuses" in expected:
                # ZURUECKGENOMMEN, gemessen 10.09.2026. Mein erster Entwurf fuhr diese Achse ueber
                # `content-root` auf der Eingabedatei und meldete "rust emitted a root, Python
                # refuses". Das war FALSCH und haette einen erfundenen Befund gelandet: gemessen
                # liefert `statement_content_root([{"x":1e-07},{"x":2.0}])` den Hash 62f69993…,
                # also GENAU den, den Rust liefert — Python weist hier gar nichts ab.
                #
                # Die Achse meint etwas anderes: run_conformance.py Zeile 391 folgende prueft
                # JEDES OBJEKT DER LISTE EINZELN mit `proofbundle.evalclaim.canonicalize` und
                # erwartet EvalClaimError. Das ist die Profilschicht, nicht die
                # RFC-8785-Kanonisierung — und dafuer hat der Rust-Verifizierer keinen
                # Unterbefehl. Eine benannte Luecke, kein Fehler.
                #
                # Die Lehre steht hier, weil sie teuer war: eine Erwartung auf den falschen
                # PRUEFPFAD zu legen erzeugt einen Befund, der ueberzeugend aussieht und niemanden
                # meint. Vor jedem neuen Zweig lesen, was die bestehende Fassung damit TUT.
                nicht_gedeckt.setdefault(kind, []).append(cid)
            elif expected.get("nonConformantDiffers") is True:
                # Der Gegenbeweis-Vektor sagt etwas ueber einen FREMDEN, nicht-konformen
                # Serialisierer aus, nicht ueber uns. Dazu hat dieser Verifizierer nichts
                # beizutragen — eine benannte Grenze, keine stille.
                nicht_gedeckt.setdefault(kind, []).append(cid)
            elif "classification" in expected:
                # R2/R3/R4 pruefen Schema-Klassifikation, Sample-Binding und Issuer-Bindung. Der
                # Rust-Verifizierer hat dafuer keinen Unterbefehl; der Python-Konformanzlauf faehrt
                # sie. GEMESSEN am 10.09.2026: sieben der zehn envelope_profile_rule-Vektoren
                # tragen genau diese Form.
                nicht_gedeckt.setdefault(kind, []).append(cid)
            else:
                # Die vier Erwartungsformen oben sind GEMESSEN, nicht angenommen. Eine fuenfte ist
                # damit neu — und neu heisst hier: jemand hat eine Regel hinzugefuegt, ohne zu
                # sagen, ob der zweite Verifizierer sie tragen soll.
                failures.append(f"corpus {cid}: kind={kind} traegt eine unbekannte Erwartungsform "
                                f"{sorted(expected)} — gefahren werden contentRootHex und "
                                f"canonicalizeRefuses, benannt uebersprungen nonConformantDiffers "
                                f"und classification. Nicht lesbar ist keine Freigabe")
        elif kind in _NICHT_DIFFERENTIELL:
            nicht_gedeckt.setdefault(kind, []).append(cid)
        else:
            # DER SCHLUSS-ARM. Ohne ihn ist jede kuenftige `kind` ein stiller Durchgang, und die
            # Erfolgszeile zaehlt sie trotzdem nicht — der Leser sieht eine Zahl und keinen Grund.
            failures.append(f"corpus {cid}: unbekannte kind {kind!r}. Dieses Differential faehrt "
                            f"sie nicht und kennt sie auch nicht als benannte Luecke. Entweder "
                            f"einen Zweig dafuer bauen oder sie in _NICHT_DIFFERENTIELL mit Grund "
                            f"eintragen — schweigend ueberspringen ist keine der beiden Optionen")

    if failures:
        print("CROSS-IMPL DISAGREEMENT:")
        for f in failures:
            print("  -", f)
        return 1
    total = len(manifest.get("cases", []))
    tail = f" ({len(skipped)} skipped: {', '.join(skipped)})" if skipped else ""
    rel_n = len(matrix_rows)
    matrix_path = _matrix_out_path()
    if matrix_path is not None:
        _write_matrix_artifact(matrix_path, matrix_rows)
        print(f"wrote relation differential matrix ({rel_n} vector(s)) -> {matrix_path}")
    # DIE ZAHL MUSS SAGEN, WAS SIE NICHT ENTHAELT. Bis zum 10.09.2026 stand hier nur
    # "57/94 reproduced" — woertlich wahr und trotzdem irrefuehrend: die fehlenden 37 waren nicht
    # etwa geprueft und schwach, sie waren NIE BETRACHTET. Wer eine Erfolgszeile liest, nimmt das
    # Gegenteil an. Die benannten Luecken stehen deshalb ab jetzt mit Zahl und Grund daneben.
    if nicht_gedeckt:
        n_offen = sum(len(v) for v in nicht_gedeckt.values())
        print(f"NOT RUN DIFFERENTIALLY: {n_offen} of {total} corpus case(s), by kind — "
              + "; ".join(f"{k} ({len(v)}): {_NICHT_DIFFERENTIELL.get(k, 'siehe Zweig oben')}"
                          for k, v in sorted(nicht_gedeckt.items())))
    print("CROSS-IMPL OK: content-root, DSSE verify (real+tampered), dup-key reject, RFC6962 merkle, "
          "budget axis (over-limit refused by both, schedules identical), "
          "trust-pack root-threshold (met+unmet) agree; "
          f"{reproduced}/{total} conformance-corpus case(s) reproduced independently"
          f" (incl. {rel_n} relation vector(s) differentially, Python==Rust on exit-class + lineage)"
          f"{tail}")
    return 0


def _matrix_out_path() -> pathlib.Path | None:
    """--matrix <path> (optional) writes the reproducible differential matrix artifact. Kept opt-in so
    the default crosscheck run stays read-only (writes only to a temp dir)."""
    argv = sys.argv[1:]
    if "--matrix" in argv:
        i = argv.index("--matrix")
        if i + 1 < len(argv):
            return pathlib.Path(argv[i + 1])
    return None


def _tool_version(*cmd: str) -> str:
    try:
        p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=10)
        return (p.stdout or p.stderr or "").strip().splitlines()[0] if (p.stdout or p.stderr) else "unknown"
    except (OSError, ValueError):
        return "unavailable"


def _write_matrix_artifact(path: pathlib.Path, rows: list[dict]) -> None:
    """No-Fake: the Vector x {Python, Rust} result matrix as a reproducible artifact WITH an
    environment freeze (cargo / rustc / python), so "Rust == Python on these vectors" is BELEGT, not
    behauptet (SPEC §3.4). Deterministic ordering; the frozen tool versions are the only run-specific
    field, and they are captured explicitly."""
    import platform  # noqa: PLC0415
    rows_sorted = sorted(rows, key=lambda r: r.get("caseId", ""))
    artifact = {
        "schema": "proofbundle.rust_relation_differential_matrix.v1",
        "description": ("Vector x {Python, Rust} differential result matrix for the relation/v0.1 and "
                        "relation-statement/v0.1 conformance vectors. Each row is one vector verified by "
                        "BOTH the Python CLI and the independent Rust verifier (pb_verify_rs); "
                        "agree_python_rust asserts they land on the SAME common-vocabulary label "
                        "(exit class + lineage). Differential AGREEMENT on these vectors, NOT a "
                        "correctness proof of either implementation."),
        "environment": {
            "cargo": _tool_version("cargo", "--version"),
            "rustc": _tool_version("rustc", "--version"),
            "python": platform.python_version(),
        },
        "total_relation_vectors": len(rows_sorted),
        "all_agree": all(r.get("agree_python_rust") and r.get("rust_reproduces_expectation")
                         for r in rows_sorted),
        "rows": rows_sorted,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
