#!/usr/bin/env python3
"""Claims-hygiene gate — fail CI if a forbidden overclaim appears in the docs outside a negation.

proofbundle's product IS the boundary "authorship + integrity, never truth". An unqualified
"proves correctness", "compliance ready" or "quantum-safe" in its own docs is the single bug it
cannot ship. This gate greps the user-facing docs for the forbidden phrasings from the six-lens
review (2026-07-04, §15) and fails on any occurrence that is NOT negated.

A match is ALLOWED when its sentence carries a negation marker — the docs legitimately say
"does not prove ... is true" and "not quantum-safe". A match with no negation in its sentence is a
VIOLATION. Code fences (``` ... ```) and inline `code` spans are skipped (CLI/JSON output is not
prose). Read-only; exit 0 clean, exit 1 on any violation.

CLI: [--json] [paths...]  (default: the canonical user-facing doc set)
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Default scan set: the docs a stranger or a citation actually reads. CHANGELOG/SPEC/THREAT_MODEL
# included on purpose — an honest claim must hold everywhere, not only above the fold.
# Every entry MUST exist: a listed-but-missing path is a FAIL, never a silent skip (WP-N1 — six of
# sixteen entries were silently skipped for months because they lacked the docs/ prefix).
_DEFAULT_DOCS = [
    "README.md", "CITATION.cff", "COMPLIANCE.md", "INTEROP.md", "INTEGRATIONS.md", "SECURITY.md",
    "PREDICATE.md", "THREAT_MODEL.md", "SPEC.md", "CHANGELOG.md", "EVAL_CLAIM.md", "RELEASE.md",
    "GOVERNANCE.md", "CONTRIBUTING.md", "MAINTAINERS.md", "TRADEMARK.md",
    "docs/FAQ.md", "docs/GLOSSARY.md", "docs/TRUST_ANCHORS.md", "docs/PROJECT_BRIEF.md",
    "docs/INSPECT_HAPPY_PATH.md", "docs/NON_CLAIMS.md", "docs/DEMO.md", "docs/ANCHORS.md",
    "docs/ANCHORS_MARKOVIAN.md", "docs/REVIEWERS.md", "docs/EXPERIMENTAL_ENCLAVE.md",
    "docs/OPERATIONS_SECURITY.md", "docs/GRANT_MILESTONES.md",
    # v2-audit deliverables (WP3/WP5/WP6/WP7): user-facing docs, held to the same discipline.
    # ADRs (docs/adr/*) are deliberately NOT in this list, matching 0001/0002's precedent — a design
    # record's freeform "options considered" prose is not the same genre as a capability claim.
    "docs/POLICY_PROFILES.md", "docs/PUBLIC_TRANSPARENCY_PROFILE.md", "docs/SD_JWT_VC_PROFILE.md",
    "docs/predicates/relation.md",
    "docs/MIGRATION_EVAL_PREDICATE.md",
    # 3.2.0 O-predicate + profile docs (release-review scan-gap fix): capability-claim genre, same discipline.
    "docs/predicates/README.md", "docs/predicates/action-outcome.md", "docs/predicates/decision-receipt.md",
    "docs/predicates/run-ledger.md", "docs/predicates/trust-pack.md", "docs/predicates/verification-summary.md",
    "docs/SDJWT_VC_PROFILE.md", "docs/SUBJECT_BINDING.md",
]

# The signed-root rule (P0-C §5.4) carries a per-sample SECTION exception (see `_CONTEXT_EXEMPT`), so
# its pattern + label are named constants shared with that map.
_SIGNED_ROOT_PATTERN = r"signed\s+(?:merkle\s+|bundle\s+|tree\s+|samples\s+)?root"
_SIGNED_ROOT_LABEL = ("signed (Merkle) root — the root is a commitment, not the signed object "
                      "(per-sample samples-root excepted)")
# "append-only" is a CORRECT property of an external public transparency log (Rekor, CT); it is an
# overclaim only for proofbundle's OWN issuer-local tree. Exempt it inside a section that discusses
# such an external public log (see `_CONTEXT_EXEMPT`).
_APPEND_ONLY_PATTERN = r"append[- ]only"
_APPEND_ONLY_LABEL = "append-only (needs a public transparency log)"

# Forbidden phrasings (§15). Each is a VIOLATION unless its sentence is negated.
_FORBIDDEN = [
    (r"proves?\s+(?:the\s+)?(?:truth|correctness)", "proves truth/correctness"),
    (r"relationship\s+proves\s+the\s+new\s+version\s+is\s+correct", "relationship proves the new version is correct"),
    (r"supersession\s+proves\s+the\s+successor", "supersession proves the successor"),
    (r"proves?\s+(?:the\s+number\s+is\s+)?true", "proves the number is true"),
    (r"compliance[- ]ready", "compliance ready"),
    (r"satisfies\s+article\s+12", "satisfies Article 12"),
    (r"audit[- ]proof", "audit-proof"),
    (r"certifies\s+safety", "certifies safety"),
    (r"quantum[- ]safe", "quantum-safe"),
    (r"post[- ]quantum\s+secure", "post-quantum secure"),
    (r"industry\s+standard", "industry standard"),
    (r"TEE\s+proves\s+(?:the\s+)?computation", "TEE proves computation"),
    (r"prevents?\s+cherry[- ]picking", "prevents cherry-picking (needs a mode qualifier)"),
    # Gate-3 additions (WP-N1/N2, standard-track 2026-07-11):
    (r"safe\s+to\s+deploy", "safe to deploy"),
    (r"safe\s+model", "safe model"),
    (r"verified\s+result", "verified result"),
    (r"correct\s+decision", "correct decision"),
    (r"authorized\s+action", "authorized action"),
    (r"\btrustless\b", 'trustless (say "trust-minimized (Bitcoin PoW time)" or negate it)'),
    # P0-C additions (Hardening 3.0.1 §5.2/§5.4, 2026-07-12). The audit found these drifting on the
    # website: the OUTER Merkle root is a commitment, not a signed object and not a public anchor; a
    # threshold verdict is not an exact score; a decision is not an execution. Each is a VIOLATION
    # unless its sentence is negated (and, for signed-root, unless its section is the per-sample one).
    (_SIGNED_ROOT_PATTERN, _SIGNED_ROOT_LABEL),
    (r"publicly\s+anchored", "publicly anchored (needs a public-log receipt)"),
    (_APPEND_ONLY_PATTERN, _APPEND_ONLY_LABEL),
    (r"exact\s+score\s+verified", "exact score verified"),
    (r"verified\s+score", "verified score (only a signed threshold verdict, unless the exact-score profile is used)"),
    (r"benchmark\s+is\s+secure", "benchmark is secure"),
    (r"evaluation\s+is\s+correct", "evaluation is correct"),
    (r"action\s+(?:was\s+)?executed", "action was executed (needs a signed action-outcome receipt)"),
    # 'compliant' ONLY in the regulatory sense — spec-/RFC-/C2SP-compliant are honest technical claims,
    # and "Article 12 compliant" is deliberately NOT here (the positive overclaim is covered by
    # "satisfies article 12"; COMPLIANCE.md legitimately QUOTES "Article 12 compliant" as an anti-pattern).
    (r"(?:EU\s+AI\s+Act|AI\s+Act|GDPR)[- ]?compliant", "regulatory-compliant (a receipt cannot prove regulation)"),
    (r"compliant\s+with\s+(?:the\s+)?(?:EU\s+AI\s+Act|AI\s+Act|GDPR)", "compliant with a regulation"),
    # 'truth' ONLY as a proof CLAIM (extends "proves truth" on L52). Bare 'truth' is deliberately NOT
    # banned: it over-fires on the honest idioms "source of truth", "ground truth", "toward truth" and
    # on NON_CLAIMS.md's own disclaimers. Ban the claim VERBS instead — that is the §5.2 intent.
    (r"(?:verif(?:ies|y|ied)|guarantees?|certif(?:ies|y)|establish(?:es)?|reveals?|delivers?)\s+(?:the\s+|semantic\s+)?truth",
     "truth as a claim (a receipt proves authorship + integrity, never truth)"),
]
_FORBIDDEN_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in _FORBIDDEN]

# §5.4 exceptions, TIGHTENED after the six-lens audit (2026-07-13) found the earlier SECTION-scoped
# exemption unsound: a genuine outer-root or own-tree overclaim co-located in the SAME section as
# legitimate per-sample / external-log language was silently exempted (exactly the risk §5.4 names).
#
# signed-root: the SAMPLES root and prereg_sha256 ARE fields of the signed eval-claim payload. A match
# that EXPLICITLY names the OUTER root ("signed MERKLE root" / "signed BUNDLE root") is NEVER exempt —
# even inside a per-sample section — because the outer root is precisely what must not be called signed
# (this closes the audit's over-exemption: "the signed Merkle root of the whole bundle" in a per-sample
# section is now flagged). "signed SAMPLES root" is always exempt (a real signed field); a bare
# "signed root" / "signed tree root" stays exempt only inside a per-sample section (docs legitimately
# write it there, e.g. FAQ.md audit openings, CHANGELOG per-sample entries).
_PERSAMPLE_CTX = re.compile(r"per-sample|samples[ -]root|audit[- ]challenge|prereg", re.IGNORECASE)
#
# append-only: a CORRECT property of an EXTERNAL public transparency log (Rekor, CT); an overclaim only
# for proofbundle's OWN issuer-local tree. Exempt when the enclosing section discusses such a log, UNLESS
# the match's own CLAUSE names a FIRST-PARTY subject (our / issuer-local / this tree) — that clause is the
# overclaim, and it is flagged even inside a Rekor section.
_PUBLIC_LOG_CTX = re.compile(
    r"rekor|transparency[- ]?log|public[- ]?log|certificate\s+transparency|c2sp|tlog", re.IGNORECASE)
_FIRST_PARTY_SUBJECT = re.compile(
    r"\b(?:our|we|us|its\s+own|issuer[- ]local|proofbundle'?s?\s+own|this\s+bundle|this\s+tree|"
    r"this\s+receipt|own\s+(?:merkle\s+)?tree)\b", re.IGNORECASE)
_HEADING_RE = re.compile(r"(?m)^#{1,6}\s")


def _section_around(text: str, pos: int) -> str:
    """The enclosing Markdown section (previous heading up to the next heading) around ``pos`` — the
    §5.4 'same section' scope for the per-sample signed-root exception. Headings survive `_strip_code`
    and `_soft_unwrap`, so this is computed on the same text scan_file matches against."""
    left = 0
    for m in _HEADING_RE.finditer(text):
        if m.start() <= pos:
            left = m.start()
        else:
            return text[left:m.start()]
    return text[left:]


# A negation anywhere in the same sentence exonerates the match (the docs say "does not prove ...").
_NEGATION_RE = re.compile(
    r"\b(?:not|never|no|cannot|can't|isn't|aren't|doesn't|don't|won't|without|"
    r"neither|nor|deliberately\s+not|does\s+not|do\s+not)\b",
    re.IGNORECASE,
)


def _strip_code(text: str) -> str:
    """Blank out fenced code blocks and inline `code` so CLI/JSON samples are not scanned as prose
    (keeps line count stable by preserving newlines)."""
    def _blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"```.*?```", _blank, text, flags=re.DOTALL)
    text = re.sub(r"`[^`\n]*`", _blank, text)
    return text


# A line whose START opens a new block: blank, heading, list item, quote, table row, numbered
# item, code fence. The newline BEFORE such a line is always a real boundary.
_NEXT_STARTS_BLOCK_RE = re.compile(r"[ \t]*(?:$|[#\-\*\+>|]|\d+\.|```)")
# A line that can never CONTINUE into following prose: blank, heading, table row, fence, setext
# underline — CommonMark forbids a paragraph lazily continuing any of them, so merging one forward
# would let a negation inside a heading/table cell exonerate the NEXT paragraph (six-lens review,
# 2026-07-11). List items and quotes DO wrap (their continuation lines are why _soft_unwrap exists).
_LINE_NEVER_WRAPS_RE = re.compile(r"[ \t]*(?:$|#|\||```|={3,}[ \t]*$|-{3,}[ \t]*$)")


def _soft_unwrap(text: str) -> str:
    """Join soft-wrapped Markdown lines back into their sentence (WP-N1). Markdown wraps prose
    mid-sentence, and `_sentence_around` treats a newline as a sentence boundary — so a negation on
    the previous physical line ("... not a statement that a\\n  model is safe to deploy") was lost and
    the wrapped tail read as an un-negated claim. A newline stays a boundary when the NEXT line
    starts a new block OR when the CURRENT line cannot continue into prose (see the two regexes
    above); any other newline is a soft wrap and becomes a space. 1:1 replacement, so offsets/line
    numbers computed against the raw text stay valid.

    Known, accepted limitations (both fail in the closed direction — a false VIOLATION, never a
    silent pass): a continuation line that itself starts with `*`/`>`/`-`/`<digit>.` reads as a
    block start, so an in-sentence negation on its previous line is not seen; the patterns are
    ASCII, so Unicode-homoglyph evasion is a documented residual for the FORBIDDEN list itself."""
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines[:-1]):
        keep = (_NEXT_STARTS_BLOCK_RE.match(lines[i + 1]) is not None
                or _LINE_NEVER_WRAPS_RE.match(line) is not None)
        out.append(line + ("\n" if keep else " "))
    out.append(lines[-1])
    return "".join(out)


def _sentence_around(text: str, start: int, end: int) -> str:
    """The clause containing [start,end): from the previous boundary to the next one. Boundaries are
    sentence ends (.!?), newlines, and CLAUSE separators (';', ':', ' — '): a negation in an earlier,
    grammatically independent clause must not exonerate a positive claim in a later one (six-lens
    review, 2026-07-11 — "X is not producible — the anchor is trustless" would otherwise pass)."""
    marks = (".", "!", "?", "\n", ";", ":", "—")
    left = max(text.rfind(mk, 0, start) for mk in marks)
    right_candidates = [i for i in (text.find(mk, end) for mk in marks) if i != -1]
    right = min(right_candidates) if right_candidates else len(text)
    return text[left + 1:right]


def scan_file(path: Path) -> list[dict]:
    """Scan one doc. A read error (missing/unreadable) RAISES OSError — the caller decides; the gate
    treats it as a FAIL entry, never a silent skip (six-lens review: a listed-but-unreadable doc
    previously counted as scanned + PASS, the exact class WP-N1 eliminates)."""
    raw = path.read_text(encoding="utf-8")
    text = _soft_unwrap(_strip_code(raw))
    violations = []
    for rx, label in _FORBIDDEN_RE:
        for m in rx.finditer(text):
            sentence = _sentence_around(text, m.start(), m.end())
            if _NEGATION_RE.search(sentence):
                continue   # negated → allowed
            # §5.4 exceptions (tightened 2026-07-13, see the constants block above).
            if label is _SIGNED_ROOT_LABEL:
                mtext = m.group(0).lower()
                if "samples" in mtext:
                    continue   # "signed samples root" is a real signed field
                if "merkle" not in mtext and "bundle" not in mtext \
                        and _PERSAMPLE_CTX.search(_section_around(text, m.start())):
                    continue   # bare "signed root" in a per-sample section = the samples root
                # an explicit "signed MERKLE/BUNDLE root" is the OUTER root → never exempt (flag)
            elif label is _APPEND_ONLY_LABEL:
                clause = _sentence_around(text, m.start(), m.end())
                if (_PUBLIC_LOG_CTX.search(_section_around(text, m.start()))
                        and not _FIRST_PARTY_SUBJECT.search(clause)):
                    continue   # accurate for an external public log, and not a first-party overclaim
            line = raw.count("\n", 0, m.start()) + 1
            try:
                rel = str(path.relative_to(REPO))
            except ValueError:
                rel = path.name
            violations.append({"file": rel, "line": line,
                               "phrase": label, "match": m.group(0),
                               "sentence": sentence.strip()[:120]})
    return violations


# ── CLI-surface scan (WP-N3, OTS calendar-risk hardening 2026-07-17) ─────────────────────────────────
# The Markdown docs were scanned, but the CLI --help / print() surface never was — so the exact
# overclaim class this hardening retracts ("the PROVEN redundancy that is evidence") had ZERO automatic
# coverage and lived on unflagged in `cli.py`. This scan closes that hole. It reads the CLI's OWN
# user-facing strings — argparse `help=`/`description=` and the literal text of `print(...)` — via the
# AST (so code comments and internal docstrings are NOT scanned, only what a user actually sees), and
# flags the redundancy-overclaim phrasings unless the same string carries an explicit unverified/negation
# hedge. The embedded calendar set is an unauthenticated, offline-constructible transparency hint (a
# PendingAttestation URI is not signed), never audit evidence — calling it "proven calendars/operators/
# redundancy" or "redundancy … evidence" without a hedge is the overclaim.
_CLI_SURFACE_FILE = "src/proofbundle/cli.py"
_CLI_OVERCLAIM_RE = [
    (re.compile(r"\bproven\s+(?:calendars?|operators?|redundancy)\b", re.IGNORECASE),
     "proven calendar/operator/redundancy (embedded calendar data is unverified, not proven)"),
    (re.compile(r"\bredundancy\b[^.\n]{0,60}?\bevidence\b", re.IGNORECASE),
     "redundancy presented as evidence (embedded calendar data is not cryptographic evidence)"),
]
# A hedge anywhere in the SAME string exonerates: an explicit unverified / transparency-hint marker or a
# negation ("not audit/cryptographic evidence", "never", "not"). The retracted wording carries one; the
# old overclaim did not.
_CLI_HEDGE_RE = re.compile(
    r"\bunverified\b|\btransparency\s+hint\b|\bnot\s+(?:audit|cryptographic)\b|\bnever\b|\bnot\b",
    re.IGNORECASE)


def _cli_surface_strings(tree: ast.AST):
    """Yield the (string, lineno) pairs a CLI user actually sees: argparse ``help=``/``description=``
    keyword strings and the literal text of every ``print(...)`` argument (f-string constant parts
    included, interpolated ``{...}`` values excluded). Comments and internal docstrings are NOT yielded —
    they are not the CLI surface, and the claim-retraction on them is a separate concern."""
    def _literal(node) -> str:
        # A plain string, an implicitly-concatenated string (already one Constant), an f-string, or a
        # BinOp (``"tmpl %s" % x`` / ``"a" + b``): collect only the static text parts so an overclaim in
        # literal prose is seen while dynamic values are ignored.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(p.value for p in node.values
                           if isinstance(p, ast.Constant) and isinstance(p.value, str))
        if isinstance(node, ast.BinOp):
            return (_literal(node.left) + " " + _literal(node.right)).strip()
        return ""

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_print = isinstance(func, ast.Name) and func.id == "print"
        if is_print:
            for arg in node.args:
                s = _literal(arg)
                if s:
                    yield s, getattr(arg, "lineno", getattr(node, "lineno", 0))
        for kw in node.keywords:
            if kw.arg in ("help", "description"):
                s = _literal(kw.value)
                if s:
                    yield s, getattr(kw.value, "lineno", getattr(node, "lineno", 0))


def scan_cli_surface(path: Path) -> list[dict]:
    """Scan the CLI's user-facing strings for un-hedged redundancy overclaims. A read/parse error RAISES
    (OSError/SyntaxError) — the caller treats it as a FAIL, never a silent skip (WP-N1 discipline)."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    violations: list[dict] = []
    try:
        rel = str(path.relative_to(REPO))
    except ValueError:
        rel = path.name
    for text, lineno in _cli_surface_strings(tree):
        if _CLI_HEDGE_RE.search(text):
            continue   # the string hedges (unverified / not-evidence / negation) → allowed
        for rx, label in _CLI_OVERCLAIM_RE:
            m = rx.search(text)
            if m:
                violations.append({"file": rel, "line": lineno, "phrase": label,
                                   "match": m.group(0), "sentence": text.strip()[:120]})
                break
    return violations


def main(argv=None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    rels = args or _DEFAULT_DOCS
    scan_cli = not args   # only on the DEFAULT run (an explicit path set scopes the request narrowly)
    violations = []
    scanned = []
    missing = []
    for rel in rels:
        p = REPO / rel
        # WP-N1: a listed-but-missing OR unreadable path is a FAIL, never a silent skip. A gate that
        # quietly narrows its own scan set stops being a gate (6/16 entries were skipped for months;
        # an unreadable doc previously counted as scanned + PASS — same class, six-lens 2026-07-11).
        try:
            file_violations = scan_file(p)
        except OSError as exc:
            missing.append(f"{rel} ({type(exc).__name__})")
            continue
        scanned.append(rel)
        violations.extend(file_violations)
    # WP-N3: on the default run, also scan the CLI's own user-facing surface (help/print). A missing or
    # unparseable cli.py is a FAIL entry, never a silent skip (same discipline as a missing doc).
    cli_scanned = False
    if scan_cli:
        try:
            violations.extend(scan_cli_surface(REPO / _CLI_SURFACE_FILE))
            cli_scanned = True
        except (OSError, SyntaxError) as exc:
            missing.append(f"{_CLI_SURFACE_FILE} ({type(exc).__name__})")
    failed = bool(violations or missing)
    out = {
        "schema": "proofbundle.claims_hygiene.v1",
        "verdict": "FAIL" if failed else "PASS",
        "scanned": len(scanned),
        "cli_surface_scanned": cli_scanned,
        "missing": missing,
        "violations": violations,
        "note": ("A forbidden phrasing appeared outside a negation, or a listed doc is missing. "
                 "Reword to the boundary language (authorship/integrity/tamper-evident/"
                 "offline-verifiable), negate it explicitly, or fix the scan list."
                 if failed else "no un-negated forbidden claims"),
    }
    if as_json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"[claims-hygiene] {out['verdict']} · {len(scanned)} docs scanned · "
              f"{len(violations)} violation(s) · {len(missing)} missing listed doc(s)")
        for rel in missing:
            print(f"  MISSING {rel}  — listed in the scan set but not a readable file "
                  "(fix the list or restore the doc)")
        for v in violations:
            print(f"  {v['file']}:{v['line']}  '{v['match']}' ({v['phrase']})  — {v['sentence']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
