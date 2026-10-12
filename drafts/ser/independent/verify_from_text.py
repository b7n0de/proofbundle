#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent verifier for draft-gruszka-signed-evaluation-receipts-02.

Written from the text of the draft alone (the version in this folder).  Every
rule below is re-derived from that text; section and step numbers in comments
point at the sentence the rule comes from.

Round 28 (owner choice of 2026-10-12, confirmation review of the -02, blocks 1 and 2): Section 11 gives the refusal of
a key before any receipt is read to the show-eval command with --expect-issuer, with exit status 2, and says that the
receipt verification function reads the receipt first and refuses a key of mixed order, as in N61, at step 11; the
earlier wording ("already when the Receiver fixes it", "the verdict stays FAIL") is gone, and the five vectors named
there expect FAIL at step 11 in Appendix A. The point on Section 11 since -01 says that this description is limited
to the command-line interface. Rounds 25 and 27 read it so. Owner choice A of 2026-10-12 (card
SER-02-BLOCK1-SCHLUESSELKLASSE-01): the keys that command refuses are those whose y-coordinate is not below p or that
are points of small order; "that rule 1 of Section 4.4 rejects" is gone from that sentence, and the keys of N12, N18,
N53 and N54 are counted here as of that class, the key of N61 as of neither.

Round 27 (owner choices A of 2026-10-12, card SER-ID-02-SEIT-00-01): Section 11 names the implementation at
a339424e, which reaches the expected verdict and first failing step on all 66 vectors; the appendix of changes has the
points since -01 (with the review blocks A to C) and since -00. Round 25 now holds every point of both subsections, in
order, and counts them.

Round 26 (owner choice A of 2026-10-12, review of the -01, blocks A to C): the field 'Security considerations' of
10.1 now ends "See Section 8 of this document and [RFC8259] Section 12." (block C), and round 18 reads it so; the
sentences of Section 11 of round 25 name the measured scope, the verdict and the first failing step of each vector.

Round 25 (owner choice A of 2026-10-12, revision -02): the text is now draft-gruszka-signed-evaluation-receipts-02;
its vectors are those of the -01, byte for byte. Section 11 gives the conformance run of the implementation it names
and the result of a further verifier written from the text, and the numbers it states for Appendix A (66 vectors, 56
that expect FAIL, 9 of them at step 1) are counted here from the text. The Open Items are gone, and an unnumbered
appendix of changes follows Appendix A. Two checks of round 25 hold it.

Round 24 (owner choice A of 2026-10-12, size limits, no change to the text): parse() reads at most MAX_INPUT_BYTES
(1 MiB) and raises ResourceLimitError above it, before anything else, so a larger receipt is RESOURCE_LIMIT at step 1
(Section 8: "Oversized inputs, long strings and deeply nested invalid JSON"); before, P1 followed by 64 MiB of
whitespace gave PASS. n_ok reads a token of more than 16 digits as no n without converting it: under the reading W7,
which keeps number tokens as written, int() met Python's limit of 4300 digits and stopped with ValueError. Probes
Q32 and Q33 hold the size limit; a self-test holds n_ok.

Round 23 (owner choice A of 2026-10-12, point 7a, no change to the text): a byte order mark and bytes that are not
UTF-8 are judged before the depth, in the order of the receipts draft's own checker, so that both give the same
verdict on the same bytes: parse() hands the violations it found before the depth to ResourceLimitError, and verify()
reports them as FAIL at step 1 or 4. Before, a byte order mark followed by 65 nested arrays was RESOURCE_LIMIT here
and FAIL at step 1 there. Probes Q28 to Q31 hold the order.

Round 22 (resource limit, no change to the text): Section 5 says that a Receiver that stops at a resource limit
reports a resource-limit error, neither PASS nor the FAIL of a step, and Section 8 lets the limits apply before and
during processing. parse() now measures the nesting of arrays and objects before it parses and raises
ResourceLimitError past MAX_DEPTH (64); verify() reports it as RESOURCE_LIMIT at step 1 or 4. Before, the parser
raised the interpreter's recursion limit to 20000 and turned a RecursionError into FAIL at step 1; at 5000 levels
the RecursionError still came. Probes Q20 to Q27 hold the limit, for the receipt and for B.

Round 21 (card DRAFTS-01-INHALT-03, review block E of 2026-10-11): the paragraph on the two parties ends with
"the same verdict on the same receipt bytes and verification key, provided verification completes."; the check of
round 20 reads it in that wording and finds the old ending "on the same bytes." nowhere.

Round 20 (card DRAFTS-01-INHALT-02, owner choice 5 of 2026-10-11): the Introduction holds, after its second
paragraph, the paragraph on the two parties that use the format; the check finds it word for word in that place,
confirms that the "Section 5" it cites is the Verification Procedure, and that it has no BCP 14 keyword.

Round 19 (card DRAFTS-01-INHALT-01, review point 5 of 2026-10-08): the paragraph of 3.2 on the version also
says that the test vectors of this version are those of Appendix A and are maintained in this document, and that
a later version comes with its own test vectors; the check of round 14 reads the whole paragraph and finds the
heading "Appendix A.  Test Vectors".
The two checks of 10.1 follow owner choices 4 and 8 of 2026-10-11: the contact field is named as in RFC 6838
("Person & email address to contact for further information"), and contact and change controller read
"Konrad Gruszka <kontakt@b7n0de.com>". The exit code now carries the self-tests, the claim checks and the probes
as well as the vector verdicts; before, a claim mismatch printed MISMATCH and exited 0.

Round 18 (card DRAFTS-01-VORARBEIT-01, preparation of the -01): 10.1 begins with the sentence that the template
is the one for the registration of the type in the vendor tree and is given for information, and its field
"Security considerations" states what RFC 6838 Section 4.6 asks every registration to state: no active
content, no compression, integrity and origin only under a key fixed before verification, no confidentiality,
resource limits. The sentences are found in the text and the replaced ones are gone; the file name read is
the -01 name. No rule changed.

Round 17 (owner choices of 2026-10-08, card 02 before submission): the check of the measurement sentence of
Section 11 reads the library verdicts the text names (which of the seven vectors the plain library accepted
and which it rejected) and compares them with the verdicts of the library in this run; a library version
other than the one the text names is printed as information, not counted as a mismatch. 3.3 says, at the
first use of SHA-256, that SHA-256 is the hash function specified in RFC 6234, which is a normative reference.
No rule changed.

Round 16 (owner choices of 2026-10-08, before submission): the vector named P11 in rounds 10 to 15 is N61; in
Table 2, Appendix A.2 and the table of contents it stands after N60, its bytes, key, expected result and step
are unchanged. Section 5 says its expected result without the identifier history. Section 8 names the vectors
that the plain library verification accepted (N12, N16, N18, N61) and rejected (N6, N17, N59) in the
measurements of Section 11, and says that the profile rejects all seven. Appendix A begins with the sentence
that identifiers are labels: a P vector expects PASS, an N vector expects FAIL, gaps carry no meaning. The
sentences are found in the text, the replaced ones are gone, and the label rule is checked on every vector
of the text. No rule changed.

Round 15 (owner choices of 2026-10-08, Restpunkte): the statement that this document has no IANA actions
stands directly under Section 10, before 10.1, and names Section 10.1 for the media type; 10.1 is titled
"Media Type Registration Template" and begins with the sentence that the template is given for information.
The field "Provisional registration?" is gone (RFC 6838 Section 5.6 lists it for the standards tree only);
every other field of the template stands in its order with its value unchanged. In the plain text, the type
in the first sentence of 10.1 is broken after a hyphen at the end of a line; the check joins such a line
with the next without a space (a hyphen that ends a line is part of the word). No rule changed.

Round 14 (owner choices of 2026-10-08): the type is application/vnd.signed-evidence.eval-receipt+json, a
media type name in the vendor tree, and the payload schema https://signed-evidence.org/eval-receipt/v1; the
IANA Considerations have no IANA action, 10.2 and its references are gone, and the intended status is
Informational. 3.1 and step 1 say "before or after the JSON text". The new P13 (a line feed followed by the
receipt of P1) passes; a reading that admits whitespace only after the text is measured as M-P13, and B of
P1 after a line feed, signed anew, is probe Q19 (step 5). The sentences are found in the text, the replaced
ones are gone. No other rule changed.

Round 13 (closing round, owner choices of 2026-10-07): step 1 now says "anything after the end of the JSON
text other than insignificant whitespace ([RFC8259] Section 2)", as 3.1 already did; step 4 refers to the
rules of step 1. The new P12 (the receipt of P1 followed by a line feed) passes, the new N60 (B of P1 followed
by a line feed, signed anew) fails at step 5. A reading of steps 1 and 4 without 3.1, in which any whitespace
after the value is trailing data, is measured as M-K2. 4.4 now defines L as the order of B' and says "the
first 32 bytes of the 64-byte signature"; 3.2 attributes to RFC 3339 Section 5.7 only the maximum day of the
month. These sentences are found in the text and the replaced ones are gone. No other rule changed.

Round 12 (adversarial review, owner choices of 2026-10-07): Section 4.4 says that the two equations accept
exactly the same signatures, that this specification defines individual verification only and that a
randomized batch result MUST NOT substitute for the four rules on each signature; Section 5 keeps the name
P11 and says its expected result; the DSSE reference is dated 28 May 2024, the date of tag v1.0.2. The
sentences are found in the text (page breaks removed) and the old batch sentence is gone.

Round 11: Section 4.4 rule 2 now reads "A and R MUST have order L: L*A and L*R are the neutral element,
and A and R are not the neutral element". P11 becomes a FAIL at step 11, rule 2 for the key, and the new
N59 (issuer key, R of mixed order) fails at step 11, rule 2 for R. The new paragraph after the rules says
that with A and R of order L the cofactorless and the cofactored equation accept the same signatures; it is
recomputed on every vector whose A and R pass rules 1 and 2 and whose S passes rule 3, and for N59 the
text's statement that the cofactored equation holds and the cofactorless one does not.

Round 10: Appendix A.1 adds a mixed-order test key, used only by the new vector P11 ("the public point
of the issuer test key plus a point of order 8"). The key is read from the text, not from vectors.json,
and the text's claim about it is recomputed: the point given first has order exactly 8, the issuer
point plus that point encodes to the given key, and the key passes rules 1 and 2 of 4.4 while L times
it is not the neutral element (mixed order). No rule of Section 5 changed.

Round 8: the receipt has no inclusion member any more.  3.1: "exactly these
members" are schema, payload_b64 and signature; "The receipt object has no
number member."  The Merkle section and step 12 are gone; Section 5 is now the
verification procedure with eleven steps, Section 6 what a receipt does not
prove, Section 8 the security considerations.  Every other rule is unchanged.

Round 7: draft SHA-256 ca652b67...c3ea50a4 (3.2 and the new 3.5).
The Payload may carry one optional member, criteria_digest (3.2: "criteria_digest
is the only optional member"); its type is string (Table 1, step 6) and it shares
the pattern sha256: followed by 64 lowercase hex digits with the commitments
(3.5, step 7: "A commitment, or criteria_digest when present, is not sha256:
...: FAIL").  No other rule changed.

Round 6: draft SHA-256 13f8fe15...68b881ad.  Only Appendix A labels changed (the
"payload bytes carried" bullet and hex label for vectors stopping at steps 1 to
3); the extraction reads both labels.  No rule changed.

Round 5: draft SHA-256 b80b42ec...ccb69cfc.  Step 4 now says "rounded to
nearest with ties to even and overflowing to infinity"; no rule changed.

Round 4: draft SHA-256 f660c639...6df8c2de.  Step 4 now says "the IEEE 754
double nearest to it (ties to even)"; Python float() already rounds that way,
so no rule changed.  N56 (n written 1800.0) needs no change either.

Round 3: draft SHA-256 33ee7a7a...35a00f21.  No rule changed against round 2:
the new text states the step 8 exception of 3.2, defines a lowercase
hexadecimal digit, and restricts the step 4 citation of RFC 8785 Section 3.1
to duplicate names; all three were already this verifier's defaults.

Round 2: rules re-derived from the revised draft (SHA-256 4ba8f9ab...782d47f).
Changed defaults against round 1: step 4 judges no numbers (a number with no
finite double, such as 1e400, now fails step 5).  Readings that round 1 had to
choose (key before R, ASCII digits, year 0000, commitment pattern at step 7,
base64 for sig and key as for payload_b64, non-object receipt at step 1, no
I-JSON number rule for the receipt) are now stated by the text and are the
defaults; the round-1 alternatives are kept only as measurements.

Primitives implemented here, in pure Python (standard library only):
  * JSON parser for RFC 8259 with the I-JSON (RFC 7493) restrictions the draft
    names (Section 3.1, Section 5 steps 1 and 4), keeping exact number tokens;
  * RFC 8785 serialization including ECMAScript number serialization (3.2.2.3);
  * RFC 4648 Section 4 base64 with padding and the canonical check of 3.5;
  * Ed25519 point decoding of RFC 8032 Section 5.1.3 and the verification
    profile of Section 4.4 (rules 1 to 4, in order).

pyca/cryptography is used only for an informational column (what a library
verdict alone says), never for the verdict.

Input: vectors.json in this folder (receipt_hex, verification_key_b64, expected,
step).  The draft text in this folder is parsed as well, to cross-check that the
bytes of Appendix A equal the bytes of vectors.json.

Usage:  /usr/bin/python3 verify_from_text.py
Exit:   0 if every vector matches verdict and step, 1 otherwise.
"""

import base64
import hashlib
import json
import os
import re
import sys
from decimal import Decimal
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
DRAFT = os.path.join(HERE, "..", "draft", "draft-gruszka-signed-evaluation-receipts-02.txt")
VECTORS = os.path.join(HERE, "..", "examples", "vectors.json")

# ---------------------------------------------------------------------------
# Constants transcribed from the body of the draft
# ---------------------------------------------------------------------------

RECEIPT_SCHEMA = "application/vnd.signed-evidence.eval-receipt+json"   # 3.1, step 2
PAE_TYPE = "application/vnd.signed-evidence.eval-receipt+json"         # 4.2
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"         # 3.2, below Table 1
COMMIT_ALG = "sha256-salted-v1"                               # Table 1, 3.3
SIG_ALG = "ed25519"                                           # 3.1, step 9

RECEIPT_MEMBERS = frozenset(["schema", "payload_b64", "signature"])
SIGNATURE_SETS = (frozenset(["alg", "sig"]), frozenset(["alg", "sig", "key"]))
OPTIONAL_PAYLOAD_MEMBER = "criteria_digest"                   # 3.2, 3.5: the only optional member
PAYLOAD_MEMBERS = frozenset([
    "schema", "suite", "suite_version", "metric", "comparator", "threshold",
    "score", "passed", "n", "model_id_commit", "dataset_id_commit",
    "commit_alg", "timestamp",
])
COMPARATORS = (">=", ">", "<=", "<")
TWO_53 = 2 ** 53


class Reading(object):
    """Readings of the text.  DEFAULT follows the revised draft (round 2); every
    alternative is either a round-1 reading the revised text now excludes, or
    a deliberately deviating verifier used only to measure vector coverage."""

    def __init__(self, **kw):
        # 3.2 (revised): "The Type column states every constraint a member has
        # except the commitment pattern of Section 3.3; ... a commitment without
        # that pattern fails step 7."  Alternative (round-1 literal reading):
        # the pattern is a step 6 check.
        self.commit_pattern_in_step6 = kw.get("commit_pattern_in_step6", False)
        # 4.4 (revised): "within rules 1 and 2 the key before R".
        # Alternative: R before the key.
        self.profile_r_before_key = kw.get("profile_r_before_key", False)
        # Step 4 (revised): "Numbers are not judged here: each is read as an
        # IEEE 754 double ..., and a number with no finite double, such as
        # 1e400, fails step 5."  Default: no number rule at step 4.
        # Alternatives (round-1 readings): an overflowing token fails step 4;
        # a token that is not exactly a double fails step 4.
        self.overflow_fails_step4 = kw.get("overflow_fails_step4", False)
        self.inexact_number_fails_step4 = kw.get("inexact_number_fails_step4", False)
        # 3.1 (revised): "The number rules of I-JSON are not checked when the
        # receipt is parsed".  Alternative: RFC 7493 2.2 range applied at step 1.
        self.receipt_number_range_step1 = kw.get("receipt_number_range_step1", False)
        # Measurement only: I-JSON rules left out of step 4, to see which later
        # step (if any) would still reject a vector.  Default: none left out.
        self.step4_skip = frozenset(kw.get("step4_skip", ()))
        # 3.2 (revised): "In this document a digit is one of the ASCII digits 0
        # to 9 (0x30 to 0x39); no other Unicode digit counts."
        # Alternative: any Unicode decimal digit in the decimal string.
        self.unicode_digits = kw.get("unicode_digits", False)
        # 3.2 (revised): "under the leap-year rule of [RFC3339] Appendix C, so
        # the year 0000 exists and is a leap year".  Alternative: a library
        # calendar without year 0 (Python datetime, years 1..9999).
        self.calendar_no_year0 = kw.get("calendar_no_year0", False)
        # New in round 2 (finding R2-1): the digit definition read literally for
        # "lowercase hexadecimal digits", i.e. only 0-9 allowed in commitments.
        # Measurement of an absurd reading.
        self.hexdigit_is_digit = kw.get("hexdigit_is_digit", False)
        # New in round 2 (finding R2-2): the Meaning column of passed read as
        # part of its row, so the agreement of passed is a step 6 check.
        self.passed_agreement_in_step6 = kw.get("passed_agreement_in_step6", False)
        # Coverage measurement only: deliberately deviating verifiers.  If one of
        # them still matches every vector, no vector exercises that rule.
        self.w_require_key = kw.get("w_require_key", False)          # {alg, sig} rejected at step 1
        self.w_receipt_codepoints = kw.get("w_receipt_codepoints", False)  # step 1 ignores UTF-8/surrogate/nonchar
        self.w_comparator_ge = kw.get("w_comparator_ge", False)      # step 8 treats every comparator as >=
        self.w_float_compare = kw.get("w_float_compare", False)      # step 8 compares as binary floats
        self.w_n_no_upper = kw.get("w_n_no_upper", False)            # step 6 has no upper bound for n
        self.w_raw_number_tokens = kw.get("w_raw_number_tokens", False)  # step 5 keeps number tokens as written
        self.w_n_by_value = kw.get("w_n_by_value", False)            # step 6 judges n by its double value
        # Round 4: step 4 "read as the IEEE 754 double nearest to it (ties to
        # even)" read literally as the nearest FINITE double (1e400 -> DBL_MAX)
        # instead of IEEE 754 roundTiesToEven with overflow to infinity.
        self.nearest_finite_double = kw.get("nearest_finite_double", False)
        # Round 13: steps 1 and 4 read without 3.1, so that whitespace after the
        # value counts as data after the end of the JSON text.  Measurement only.
        self.trailing_ws_is_data = kw.get("trailing_ws_is_data", False)
        # Round 14: steps 1 and 4 read as the round-13 text, which named only the side after the JSON
        # text, so that whitespace before the value counts as data.  Measurement only.
        self.leading_ws_is_data = kw.get("leading_ws_is_data", False)


DEFAULT = Reading()

# ---------------------------------------------------------------------------
# JSON parser: RFC 8259 grammar; I-JSON restrictions reported as violations
# ---------------------------------------------------------------------------


class JSONSyntaxError(Exception):
    pass


class ResourceLimitError(Exception):
    """A limit of this Receiver was reached (Section 5: a resource-limit error, neither PASS nor FAIL). viol holds
    what parse() found before the depth (a byte order mark, bytes that are not UTF-8), judged first (round 23)."""

    def __init__(self, msg, viol=()):
        super().__init__(msg)
        self.viol = list(viol)


# Section 8: limits apply "before and during processing". All limits of this script are here.
# The largest input parse() reads, in bytes (a receipt; B within it); the largest receipt of Appendix A is far below.
MAX_INPUT_BYTES = 1 << 20
# The deepest nesting of arrays and objects that is parsed; a top-level array or object is depth 1.
MAX_DEPTH = 64


def nesting_depth_ok(text):
    """True if text nests arrays and objects at most MAX_DEPTH deep; brackets inside strings do not count."""
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "[" or ch == "{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif ch == "]" or ch == "}":
            depth -= 1
    return True


class JNum(object):
    """A JSON number: the exact token as written, and its IEEE 754 double."""
    __slots__ = ("token", "value")

    def __init__(self, token):
        self.token = token
        self.value = float(token)  # correctly rounded; inf on overflow

    def __repr__(self):
        return "JNum(%s)" % self.token


class JObj(object):
    """A JSON object: members in document order, plus a last-wins dict."""
    __slots__ = ("pairs", "d")

    def __init__(self, pairs):
        self.pairs = pairs
        self.d = {}
        for k, v in pairs:
            self.d[k] = v

    def names(self):
        return set(self.d)

    def get(self, k, default=None):
        return self.d.get(k, default)

    def __contains__(self, k):
        return k in self.d

    def __getitem__(self, k):
        return self.d[k]


_NUM_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX4_RE = re.compile(r"[0-9A-Fa-f]{4}")
_WS = " \t\n\r"   # RFC 8259 Section 2, insignificant whitespace
_SIMPLE_ESC = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
               "n": "\n", "r": "\r", "t": "\t"}


def is_noncharacter(cp):
    # Unicode noncharacters: U+FDD0..U+FDEF and U+xxFFFE, U+xxFFFF of every plane
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def is_surrogate(cp):
    return 0xD800 <= cp <= 0xDFFF


class _Parser(object):
    def __init__(self, text):
        self.s = text
        self.n = len(text)
        self.i = 0
        self.v = []          # list of (kind, detail) violations of I-JSON rules
        self.numbers = []    # every JNum, for the RFC 8785 / RFC 7493 number rules

    def err(self, msg):
        raise JSONSyntaxError("%s at character %d" % (msg, self.i))

    def ws(self):
        while self.i < self.n and self.s[self.i] in _WS:
            self.i += 1

    def text(self):
        self.ws()
        val = self.value()
        self.ws()
        if self.i != self.n:
            self.v.append(("trailing", "%d character(s) after the end of the JSON text" % (self.n - self.i)))
        return val

    def value(self):
        if self.i >= self.n:
            self.err("unexpected end of text")
        c = self.s[self.i]
        if c == "{":
            return self.obj()
        if c == "[":
            return self.arr()
        if c == '"':
            return self.string()
        if c == "-" or "0" <= c <= "9":
            m = _NUM_RE.match(self.s, self.i)
            if not m:
                self.err("invalid number")
            self.i = m.end()
            num = JNum(m.group(0))
            self.numbers.append(num)
            return num
        for lit, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        self.err("unexpected character %r" % c)

    def obj(self):
        self.i += 1
        pairs = []
        seen = set()
        self.ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return JObj(pairs)
        while True:
            self.ws()
            if self.i >= self.n or self.s[self.i] != '"':
                self.err("expected a member name")
            name = self.string()          # unescaped (RFC 8259 Section 8.3)
            self.ws()
            if self.i >= self.n or self.s[self.i] != ":":
                self.err("expected ':'")
            self.i += 1
            self.ws()
            val = self.value()
            if name in seen:
                self.v.append(("duplicate", "duplicate member name %r (after unescaping)" % name))
            seen.add(name)
            pairs.append((name, val))
            self.ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                return JObj(pairs)
            self.err("expected ',' or '}'")

    def arr(self):
        self.i += 1
        items = []
        self.ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return items
        while True:
            self.ws()
            items.append(self.value())
            self.ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.s[self.i] == "]":
                self.i += 1
                return items
            self.err("expected ',' or ']'")

    def hex4(self, at):
        h = self.s[at:at + 4]
        if not _HEX4_RE.fullmatch(h):
            self.err("invalid \\u escape")
        return int(h, 16)

    def string(self):
        self.i += 1
        out = []
        s = self.s
        while True:
            if self.i >= self.n:
                self.err("unterminated string")
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                if self.i + 1 >= self.n:
                    self.err("unterminated escape")
                e = s[self.i + 1]
                if e in _SIMPLE_ESC:
                    out.append(_SIMPLE_ESC[e])
                    self.i += 2
                elif e == "u":
                    cp = self.hex4(self.i + 2)
                    self.i += 6
                    if 0xD800 <= cp <= 0xDBFF and s.startswith("\\u", self.i):
                        lo = self.hex4(self.i + 2)
                        if 0xDC00 <= lo <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            self.i += 6
                    out.append(chr(cp))
                else:
                    self.err("invalid escape \\%s" % e)
            elif ord(c) < 0x20:
                self.err("unescaped control character U+%04X in a string" % ord(c))
            else:
                out.append(c)
                self.i += 1
        res = "".join(out)
        for ch in res:
            cp = ord(ch)
            if is_surrogate(cp):
                self.v.append(("surrogate", "string contains the surrogate code point U+%04X" % cp))
            elif is_noncharacter(cp):
                self.v.append(("noncharacter", "string contains the noncharacter U+%04X" % cp))
        return res


def parse(data):
    """Parse bytes as one JSON text.

    Returns (value, violations, numbers).  violations lists I-JSON problems
    (bom, utf8, surrogate, noncharacter, duplicate, trailing); for a lenient
    reading the value is still produced (BOM stripped, invalid UTF-8 replaced,
    last duplicate wins, trailing data ignored).  Raises JSONSyntaxError when
    the bytes are not JSON at all, and ResourceLimitError when arrays and objects
    nest deeper than MAX_DEPTH (measured before parsing).
    """
    if len(data) > MAX_INPUT_BYTES:   # round 24: before anything else
        raise ResourceLimitError("%d bytes, more than %d" % (len(data), MAX_INPUT_BYTES))
    viol = []
    if data.startswith(b"\xef\xbb\xbf"):
        viol.append(("bom", "starts with a UTF-8 byte order mark"))
        data = data[3:]
    try:
        text = data.decode("utf-8")   # strict: rejects overlong forms and encoded surrogates
    except UnicodeDecodeError as e:
        viol.append(("utf8", "not UTF-8: %s at byte %d" % (e.reason, e.start)))
        text = data.decode("utf-8", errors="replace")
    if not nesting_depth_ok(text):
        raise ResourceLimitError("arrays and objects nested deeper than %d" % MAX_DEPTH, viol)
    p = _Parser(text)
    val = p.text()
    return val, viol + p.v, p.numbers


# ---------------------------------------------------------------------------
# RFC 8785 serialization
# ---------------------------------------------------------------------------


def es_number(x):
    """ECMAScript Number::toString for a finite double (RFC 8785 Section 3.2.2.3)."""
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("NaN or Infinity has no RFC 8785 serialization")
    if x == 0:
        return "0"            # also for -0
    if x < 0:
        return "-" + es_number(-x)
    _, digits, exp = Decimal(repr(x)).as_tuple()   # repr: shortest round-trip digits
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    ds = "".join(str(d) for d in digits)
    k = len(ds)
    n = exp + k
    if k <= n <= 21:
        return ds + "0" * (n - k)
    if 0 < n <= 21:
        return ds[:n] + "." + ds[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + ds
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return ds + "e" + es
    return ds[0] + "." + ds[1:] + "e" + es


_JCS_CTRL = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(_JCS_CTRL.get(o, "\\u%04x" % o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


_CLAMP = [False]


def _jcs(v, raw=False):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, JNum):
        if raw:
            return v.token
        x = v.value
        if _CLAMP[0] and x in (float("inf"), float("-inf")):
            x = sys.float_info.max if x > 0 else -sys.float_info.max
        return es_number(x)
    if isinstance(v, str):
        return jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x, raw) for x in v) + "]"
    if isinstance(v, JObj):
        keys = sorted(v.d.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))  # 3.2.3
        return "{" + ",".join(jcs_string(k) + ":" + _jcs(v.d[k], raw) for k in keys) + "}"
    raise TypeError("cannot serialize %r" % (v,))


def jcs_bytes(v, raw_numbers=False):
    return _jcs(v, raw_numbers).encode("utf-8", "surrogatepass")


# ---------------------------------------------------------------------------
# Base64: RFC 4648 Section 4 with padding, canonical per Section 3.5
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def b64_check(s):
    """Returns (bytes_or_None, problem_or_None).  Bytes are returned also for a
    non-canonical but decodable string (lenient diagnostics only)."""
    if not isinstance(s, str):
        return None, "not a string"
    if not _B64_RE.fullmatch(s):
        return None, "not a string of the base64 alphabet with padding (RFC 4648 Section 4)"
    raw = base64.b64decode(s, validate=True)
    if b64(raw) != s:
        return raw, "not the canonical encoding (RFC 4648 Section 3.5): re-encoding gives %r" % b64(raw)
    return raw, None


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032 Section 5.1) and the profile of Section 4.4
# ---------------------------------------------------------------------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENT = (0, 1, 1, 0)   # extended coordinates (X, Y, Z, T)


def point_add(p1, p2):
    # RFC 8032 Section 5.1.4 (a = -1), complete for all inputs
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def scalar_mult(k, pt):
    q = IDENT
    while k > 0:
        if k & 1:
            q = point_add(q, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return q


def point_equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def is_neutral(pt):
    return point_equal(pt, IDENT)


def _recover_x(y):
    """RFC 8032 Section 5.1.3 steps 2 and 3; returns x or None."""
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 == u:
        return x
    if vx2 == (-u) % P:
        return x * SQRT_M1 % P
    return None


def decode_point(b):
    """RFC 8032 Section 5.1.3 decoding.  Returns (point, None) or (None, reason)."""
    if len(b) != 32:
        return None, "encoding is %d bytes, not 32" % len(b)
    n = int.from_bytes(b, "little")
    x0 = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:                                   # step 1
        return None, "y-coordinate is not below p (y = p + %d)" % (y - P)
    x = _recover_x(y)                            # steps 2, 3
    if x is None:
        return None, "no square root: not the encoding of a curve point"
    if x == 0 and x0 == 1:                       # step 4
        return None, "x = 0 with the sign bit set"
    if x0 != (x & 1):
        x = P - x
    return (x, y, 1, x * y % P), None


def decode_point_lenient(b):
    """Decoder that reduces y modulo p and ignores the x = 0 sign rule.
    Used only to measure claims of the text, never for a verdict."""
    n = int.from_bytes(b, "little")
    x0 = n >> 255
    y = (n & ((1 << 255) - 1)) % P
    x = _recover_x(y)
    if x is None:
        return None
    if x != 0 and x0 != (x & 1):
        x = P - x
    return (x, y, 1, x * y % P)


def encode_point(pt):
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


BASE, _ = decode_point((4 * pow(5, P - 2, P) % P).to_bytes(32, "little"))
assert BASE is not None and BASE[0] == 15112221349535400772501151409588531511454012693041857206046113283949847762202


def secret_expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_from_seed(seed):
    return encode_point(scalar_mult(secret_expand(seed)[0], BASE))


def ed25519_sign(seed, msg):
    """RFC 8032 Section 5.1.6, for self-tests only."""
    a, prefix = secret_expand(seed)
    pub = encode_point(scalar_mult(a, BASE))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    rb = encode_point(scalar_mult(r, BASE))
    k = int.from_bytes(hashlib.sha512(rb + pub + msg).digest(), "little") % L
    return rb + ((r + k * a) % L).to_bytes(32, "little")


def profile_verify(A_bytes, sig, msg, reading=DEFAULT):
    """Section 4.4: rules 1 to 4, checked in the order given; the first failing
    rule decides.  Returns (None, None, "") on success, else (rule, which, reason)
    with which in ("key", "R", None)."""
    R_bytes, S_bytes = sig[:32], sig[32:64]
    order = (("R", R_bytes), ("key", A_bytes)) if reading.profile_r_before_key else \
            (("key", A_bytes), ("R", R_bytes))
    pts = {}
    # Rule 1: canonical encodings, i.e. RFC 8032 Section 5.1.3 decoding succeeds.
    for which, enc in order:
        pt, why = decode_point(enc)
        if pt is None:
            return 1, which, "%s: %s" % (which, why)
        pts[which] = pt
    # Rule 2 (round 11): A and R have order L: L*A and L*R are the neutral element, A and R are not.
    for which, _ in order:
        name = "A" if which == "key" else "R"
        if is_neutral(pts[which]):
            return 2, which, "%s: %s is the neutral element" % (which, name)
        if not is_neutral(scalar_mult(L, pts[which])):
            return 2, which, "%s: L*%s is not the neutral element (not of order L)" % (which, name)
    # Rule 3: S below L.
    S = int.from_bytes(S_bytes, "little")
    if S >= L:
        return 3, None, "S is not below L (S = L + %d)" % (S - L)
    # Rule 4: cofactorless equation with k = SHA-512(R || A || M) mod L.
    k = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + msg).digest(), "little") % L
    if not point_equal(scalar_mult(S, BASE), point_add(pts["R"], scalar_mult(k, pts["key"]))):
        return 4, None, "S*B' != R + k*A"
    return None, None, ""


def profile_all_rules(A_bytes, sig, msg):
    """Informational: every rule evaluated independently.  Where rule 1 fails,
    rules 2 and 4 are evaluated on the lenient (y mod p) decoding, marked '~'."""
    R_bytes, S_bytes = sig[:32], sig[32:64]
    out = {}
    pts = {}
    for which, enc in (("key", A_bytes), ("R", R_bytes)):
        pt, why = decode_point(enc)
        out["1" + which] = "ok" if pt else "FAIL"
        if pt is None:
            lp = decode_point_lenient(enc)
            pts[which] = (lp, True)
        else:
            pts[which] = (pt, False)
    for which in ("key", "R"):
        pt, len_ = pts[which]
        if pt is None:
            out["2" + which] = "n/a"
        else:
            out["2" + which] = ("~" if len_ else "") + ("FAIL" if is_neutral(pt) or not is_neutral(scalar_mult(L, pt))
                                                        else "ok")
    S = int.from_bytes(S_bytes, "little")
    out["3"] = "ok" if S < L else "FAIL"
    if pts["key"][0] is None or pts["R"][0] is None:
        out["4"] = "n/a"
    else:
        k = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + msg).digest(), "little") % L
        ok = point_equal(scalar_mult(S, BASE), point_add(pts["R"][0], scalar_mult(k, pts["key"][0])))
        out["4"] = ("~" if (pts["key"][1] or pts["R"][1]) else "") + ("ok" if ok else "FAIL")
    return out


# ---------------------------------------------------------------------------
# PAE (Section 4.1)
# ---------------------------------------------------------------------------


def pae(typ, body):
    t = typ.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


# ---------------------------------------------------------------------------
# Payload rules (Section 3.2, 3.3)
# ---------------------------------------------------------------------------

_DEC_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")           # 3.2 decimal string
_DEC_RE_UNICODE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?")          # alternative reading A7 only
_COMMIT_RE = re.compile(r"sha256:[0-9a-f]{64}")                     # 3.3, step 7
_TS_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
_COMMIT_RE_DIGITS = re.compile(r"sha256:[0-9]{64}")                 # reading A10 only


def timestamp_ok(s, reading=None):
    """3.2: exactly YYYY-MM-DDTHH:MM:SSZ, date exists in the proleptic Gregorian
    calendar (RFC 3339 Section 5.7), hour 00-23, minute 00-59, second 00-59."""
    m = _TS_RE.fullmatch(s)
    if not m:
        return False
    y, mo, d, h, mi, se = (int(g) for g in m.groups())
    if reading is not None and reading.calendar_no_year0:
        import datetime
        try:
            datetime.date(y, mo, d)
        except ValueError:
            return False
    if not 1 <= mo <= 12:
        return False
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return 1 <= d <= dim and h <= 23 and mi <= 59 and se <= 59


def nonempty_string(v):
    return isinstance(v, str) and len(v) >= 1


def is_bool(v):
    return v is True or v is False


def n_ok(v):
    # After step 5 the token is the RFC 8785 form of its value, so a positive
    # integer below 1e21 is written as plain digits; any other value fails.
    # Round 24: more than 16 digits is above 2^53 - 1, judged without int(), which stops at 4300 digits.
    return isinstance(v, JNum) and re.fullmatch(r"[1-9][0-9]*", v.token) is not None and len(v.token) <= 16 \
        and 1 <= int(v.token) <= TWO_53 - 1


def step6_problems(pl, reading):
    probs = []
    names = pl.names()
    if names - {OPTIONAL_PAYLOAD_MEMBER} != PAYLOAD_MEMBERS:          # 3.2: criteria_digest optional
        probs.append("member set differs from Table 1 (missing %s, extra %s)"
                     % (sorted(PAYLOAD_MEMBERS - names), sorted(names - PAYLOAD_MEMBERS - {OPTIONAL_PAYLOAD_MEMBER})))
    g = pl.get
    if "schema" in pl and g("schema") != PAYLOAD_SCHEMA:
        probs.append("schema %r is not %s" % (g("schema"), PAYLOAD_SCHEMA))
    for m in ("suite", "suite_version", "metric"):
        if m in pl and not nonempty_string(g(m)):
            probs.append("%s %r is not a non-empty string" % (m, g(m)))
    if "comparator" in pl and not (isinstance(g("comparator"), str) and g("comparator") in COMPARATORS):
        probs.append("comparator %r is not one of >=, >, <=, <" % (g("comparator"),))
    dec_re = _DEC_RE_UNICODE if reading.unicode_digits else _DEC_RE
    for m in ("threshold", "score"):
        if m in pl and not (isinstance(g(m), str) and dec_re.fullmatch(g(m))):
            probs.append("%s %r is not a decimal string" % (m, g(m)))
    if "passed" in pl and not is_bool(g("passed")):
        probs.append("passed %r is not true or false" % (g("passed"),))
    if reading.w_n_by_value and "n" in pl and isinstance(g("n"), JNum):
        nv = g("n").value
        if not (nv == nv and nv not in (float("inf"), float("-inf")) and nv == int(nv) and 1 <= nv <= TWO_53 - 1):
            probs.append("n %r is not an integer from 1 to 2^53 - 1 [W7b]" % (g("n"),))
    elif "n" in pl and not (n_ok(g("n")) or (reading.w_n_no_upper and isinstance(g("n"), JNum)
                                             and re.fullmatch(r"[1-9][0-9]*", g("n").token))):
        probs.append("n %r is not an integer from 1 to 2^53 - 1" % (g("n"),))
    for m in ("model_id_commit", "dataset_id_commit"):
        if m in pl:
            if not isinstance(g(m), str):
                probs.append("%s is not a string" % m)
            elif reading.commit_pattern_in_step6 and not _COMMIT_RE.fullmatch(g(m)):
                probs.append("%s is not a commitment (Section 3.3) [reading: 3.2 literal]" % m)
    if OPTIONAL_PAYLOAD_MEMBER in pl and not isinstance(g(OPTIONAL_PAYLOAD_MEMBER), str):   # Table 1: string
        probs.append("criteria_digest is not a string")
    if "commit_alg" in pl and g("commit_alg") != COMMIT_ALG:
        probs.append("commit_alg %r is not %s" % (g("commit_alg"), COMMIT_ALG))
    if "timestamp" in pl and not (isinstance(g("timestamp"), str) and timestamp_ok(g("timestamp"), reading)):
        probs.append("timestamp %r is not of the form of Section 3.2" % (g("timestamp"),))
    if reading.passed_agreement_in_step6 and not probs:
        if compare(g("score"), g("comparator"), g("threshold")) != g("passed"):
            probs.append("passed does not agree with its Meaning column [reading A11]")
    return probs


def compare(score, comparator, threshold):
    a, b = Fraction(score), Fraction(threshold)     # exact decimal numbers
    return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[comparator]


# ---------------------------------------------------------------------------
# Section 5: the eleven steps, in order; the first failing step gives FAIL
# ---------------------------------------------------------------------------

STEP1_KINDS = ("bom", "utf8", "surrogate", "noncharacter", "duplicate", "trailing")


class Result(object):
    def __init__(self, verdict, step="all", rule=None, which=None, reason="", B=None, sig=None):
        self.verdict, self.step, self.rule, self.which = verdict, step, rule, which
        self.reason, self.B, self.sig = reason, B, sig

    def label(self):
        if self.verdict == "PASS":
            return "all"
        if self.step == 11:
            return "11 (profile %d%s)" % (self.rule, (", " + self.which) if self.which else "")
        return str(self.step)


def verify(receipt, vk, reading=DEFAULT):
    def FAIL(step, reason, **kw):
        return Result("FAIL", step, reason=reason, **kw)

    # Step 1: parse the receipt as one I-JSON text; member sets.
    try:
        rec, viol, nums = parse(receipt)
    except JSONSyntaxError as e:
        return FAIL(1, "receipt is not a JSON text: %s" % e)
    except ResourceLimitError as e:
        bad = [d for k, d in e.viol if k in STEP1_KINDS     # round 23: judged before the depth
               and not (reading.w_receipt_codepoints and k in ("utf8", "surrogate", "noncharacter"))]
        if bad:
            return FAIL(1, "receipt: " + "; ".join(bad))
        return Result("RESOURCE_LIMIT", 1, reason="receipt: %s" % e)
    bad = [d for k, d in viol if k in STEP1_KINDS
           and not (reading.w_receipt_codepoints and k in ("utf8", "surrogate", "noncharacter"))]
    if reading.receipt_number_range_step1:
        bad += ["number %s outside IEEE 754 double range" % n.token for n in nums
                if n.value in (float("inf"), float("-inf"))]
    if reading.trailing_ws_is_data and not any(k == "trailing" for k, _ in viol) \
            and receipt != receipt.rstrip(_WS.encode("ascii")):
        bad.append("whitespace after the end of the JSON text [M-K2 reading]")
    if reading.leading_ws_is_data and receipt != receipt.lstrip(_WS.encode("ascii")):
        bad.append("whitespace before the JSON text [M-P13 reading]")
    if bad:
        return FAIL(1, "receipt: " + "; ".join(bad))
    if not isinstance(rec, JObj):
        return FAIL(1, "receipt top-level value is not an object")
    if rec.names() != RECEIPT_MEMBERS:
        return FAIL(1, "receipt member set %s is not schema, payload_b64, signature" % sorted(rec.names()))
    sg = rec["signature"]
    sets = SIGNATURE_SETS[1:] if reading.w_require_key else SIGNATURE_SETS
    if not isinstance(sg, JObj) or sg.names() not in sets:
        return FAIL(1, "signature is not an object with exactly alg, sig (and optionally key): %s"
                    % (sorted(sg.names()) if isinstance(sg, JObj) else type(sg).__name__))

    # Step 2: receipt schema (string values compared after unescaping).
    if rec["schema"] != RECEIPT_SCHEMA:
        return FAIL(2, "receipt schema %r is not %s" % (rec["schema"], RECEIPT_SCHEMA))

    # Step 3: payload_b64 -> B.
    B, why = b64_check(rec["payload_b64"])
    if why:
        return FAIL(3, "payload_b64: " + why)

    # Step 4: B is one I-JSON text whose value is an object (rules of step 1,
    # RFC 8785 Section 3.1, RFC 7493 Section 2.3).
    try:
        pl, viol, nums = parse(B)
    except JSONSyntaxError as e:
        return FAIL(4, "B is not a JSON text: %s" % e, B=B)
    except ResourceLimitError as e:
        bad = [d for k, d in e.viol if k in STEP1_KINDS and k not in reading.step4_skip]   # round 23
        if bad:
            return FAIL(4, "B: " + "; ".join(bad), B=B)
        return Result("RESOURCE_LIMIT", 4, reason="B: %s" % e, B=B)
    bad = [d for k, d in viol if k in STEP1_KINDS and k not in reading.step4_skip]
    if reading.trailing_ws_is_data and "trailing" not in reading.step4_skip \
            and not any(k == "trailing" for k, _ in viol) and B != B.rstrip(_WS.encode("ascii")):
        bad.append("whitespace after the end of the JSON text [M-K2 reading]")
    if reading.leading_ws_is_data and B != B.lstrip(_WS.encode("ascii")):
        bad.append("whitespace before the JSON text [M-P13 reading]")
    # Revised step 4: "Numbers are not judged here"; a number with no finite
    # double fails step 5.  The two checks below are round-1 alternatives only.
    for n in nums:
        if n.value in (float("inf"), float("-inf")):
            if reading.overflow_fails_step4 or reading.inexact_number_fails_step4:
                bad.append("number %s is not expressible as an IEEE 754 double [round-1 reading]" % n.token)
        elif reading.inexact_number_fails_step4 and Fraction(Decimal(n.token)) != Fraction(n.value):
            bad.append("number %s is not exactly an IEEE 754 double [round-1 reading]" % n.token)
    if bad:
        return FAIL(4, "B: " + "; ".join(bad), B=B)
    if not isinstance(pl, JObj):
        return FAIL(4, "B's value is not an object", B=B)

    # Step 5: B is its own RFC 8785 serialization.
    _CLAMP[0] = reading.nearest_finite_double
    try:
        canon = jcs_bytes(pl, raw_numbers=reading.w_raw_number_tokens)
    except ValueError as e:
        _CLAMP[0] = False
        return FAIL(5, "no RFC 8785 serialization (a number with no finite double): %s" % e, B=B)
    _CLAMP[0] = False
    if canon != B:
        off = next((i for i in range(min(len(canon), len(B))) if canon[i] != B[i]), min(len(canon), len(B)))
        return FAIL(5, "B (%d bytes) is not its RFC 8785 serialization (%d bytes); first difference at byte %d"
                    % (len(B), len(canon), off), B=B)

    # Step 6: member set and rows of Table 1.
    probs = step6_problems(pl, reading)
    if probs:
        return FAIL(6, "payload: " + "; ".join(probs), B=B)

    # Step 7: commitment pattern.
    crx = _COMMIT_RE_DIGITS if reading.hexdigit_is_digit else _COMMIT_RE
    pattern_members = ("model_id_commit", "dataset_id_commit") + ((OPTIONAL_PAYLOAD_MEMBER,) if OPTIONAL_PAYLOAD_MEMBER in pl else ())
    badc = [m for m in pattern_members if not crx.fullmatch(pl[m])]                # 3.5, step 7
    if badc:
        return FAIL(7, "; ".join("%s %r is not sha256: followed by 64 lowercase hex digits" % (m, pl[m]) for m in badc), B=B)

    # Step 8: passed equals the exact comparison.
    if reading.w_float_compare:
        a_, b_ = float(pl["score"]), float(pl["threshold"])
        want = {">=": a_ >= b_, ">": a_ > b_, "<=": a_ <= b_, "<": a_ < b_}[pl["comparator"]]
    else:
        want = compare(pl["score"], ">=" if reading.w_comparator_ge else pl["comparator"], pl["threshold"])
    if pl["passed"] != want:
        return FAIL(8, "passed = %s but %s %s %s is %s" % (str(pl["passed"]).lower(), pl["score"],
                    pl["comparator"], pl["threshold"], str(want).lower()), B=B)

    # Step 9: signature.alg and signature.sig.
    if sg["alg"] != SIG_ALG:
        return FAIL(9, "signature.alg %r is not ed25519" % (sg["alg"],), B=B)
    sig, why = b64_check(sg["sig"])
    if why:
        return FAIL(9, "signature.sig: " + why, B=B, sig=sig)
    if len(sig) != 64:
        return FAIL(9, "signature.sig decodes to %d bytes, not 64" % len(sig), B=B, sig=sig)

    # Step 10: key hint.
    if "key" in sg and sg["key"] != b64(vk):
        return FAIL(10, "signature.key %r is not the canonical base64 of the verification key %s"
                    % (sg["key"], b64(vk)), B=B, sig=sig)

    # Step 11: profile of Section 4.4 over PAE(type, B) with the fixed type.
    rule, which, why = profile_verify(vk, sig, pae(PAE_TYPE, B), reading)
    if rule is not None:
        return FAIL(11, why, rule=rule, which=which, B=B, sig=sig)

    return Result("PASS", B=B, sig=sig)


# ---------------------------------------------------------------------------
# Informational helpers
# ---------------------------------------------------------------------------


def lenient_parts(receipt):
    """Lenient reading of a receipt, for informational columns only: returns
    (B or None, sig bytes or None)."""
    try:
        rec, _, _ = parse(receipt)
    except (JSONSyntaxError, ResourceLimitError):
        return None, None
    if not isinstance(rec, JObj):
        return None, None
    B, _ = b64_check(rec.get("payload_b64"))
    sg = rec.get("signature")
    sig = None
    if isinstance(sg, JObj):
        sig, _ = b64_check(sg.get("sig"))
    return B, sig


def library_verdict(vk, sig, B):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except Exception as e:  # pragma: no cover
        return "unavailable (%s)" % e
    if sig is None or B is None or len(sig) != 64:
        return "n/a"
    try:
        pk = Ed25519PublicKey.from_public_bytes(vk)
    except Exception as e:
        return "key rejected (%s)" % type(e).__name__
    try:
        pk.verify(sig, pae(PAE_TYPE, B))
        return "accept"
    except InvalidSignature:
        return "reject"
    except Exception as e:
        return "error (%s)" % type(e).__name__


def step5_would_reject(B):
    """Lenient parse of B (BOM stripped, last duplicate wins, trailing ignored):
    is B its own RFC 8785 serialization?  None if B is not JSON at all or nests
    deeper than MAX_DEPTH."""
    try:
        v, _, _ = parse(B)
    except (JSONSyntaxError, ResourceLimitError):
        return None
    try:
        return jcs_bytes(v) != B
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Appendix A extraction (cross-check of the text against vectors.json)
# ---------------------------------------------------------------------------

_FOOTER_RE = re.compile(r"^\S.*\s\[Page \d+\]\s*$")
_HEADER_RE = re.compile(r"^Internet-Draft\s{2,}\S.*\s{2,}\S+ \d{4}\s*$")
_VEC_HEAD_RE = re.compile(r"^A\.2\.(\d+)\.\s+([PN]\d+) \((.+?); expected (PASS|FAIL), step (.+)\)\s*$")
_HEXLINE_RE = re.compile(r"[0-9a-f]+")


def clean_lines(text):
    out = []
    for line in text.split("\n"):
        line = line.rstrip("\r").replace("\f", "")
        if _FOOTER_RE.match(line) or _HEADER_RE.match(line):
            out.append("")
            continue
        out.append(line.rstrip())
    return out


def paragraphs(lines):
    paras, cur = [], []
    for ln in lines:
        if ln.strip():
            cur.append(ln)
        elif cur:
            paras.append(cur)
            cur = []
    if cur:
        paras.append(cur)
    return paras


def _hexblock(lines):
    parts = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if not _HEXLINE_RE.fullmatch(s):
            raise ValueError("non-hex line in a hex block: %r" % s)
        parts.append(s)
    return bytes.fromhex("".join(parts))


def extract_appendix(path):
    with open(path, "rb") as f:
        raw = f.read()
    # Round 8: the text is UTF-8 since a reference names an author with non-ASCII letters (RFC 7997); the
    # vector bytes of Appendix A are hex and stay ASCII.
    text = raw.decode("utf-8")
    lines = clean_lines(text)
    # A heading may wrap onto an indented continuation line (N53, N54 in round 3).
    for i in range(len(lines) - 1):
        if re.match(r"^A\.2\.\d+\.\s", lines[i]) and not _VEC_HEAD_RE.match(lines[i]) \
                and lines[i + 1].startswith(" ") and lines[i + 1].strip():
            lines[i] = lines[i] + " " + lines[i + 1].strip()
            lines[i + 1] = ""
    heads = [i for i, s in enumerate(lines) if _VEC_HEAD_RE.match(s)]
    out = {}
    for hi in heads:
        end = next((j for j in range(hi + 1, len(lines)) if lines[j] and not lines[j][0].isspace()), len(lines))
        sect = lines[hi:end]
        m = _VEC_HEAD_RE.match(sect[0])
        vid = m.group(2)
        # Round 6: for vectors that stop before B exists the label is "Payload bytes carried (hex):"
        ib = next((i for i, s in enumerate(sect) if s.strip() in ("B (hex):", "Payload bytes carried (hex):")), None)
        ir = next((i for i, s in enumerate(sect) if s.strip() == "Receipt (hex):"), None)
        bullets = {}
        for para in paragraphs(sect[1:(ib if ib is not None else ir)]):
            joined = " ".join(x.strip() for x in para)
            if joined.startswith("*"):
                body = joined[1:].strip()
                mc = re.match(r"payload bytes carried \(not B: the procedure stops at step (\d+) before it obtains B\): (.*)$", body)
                if mc:
                    bullets["payload bytes b"] = mc.group(2).strip()
                    bullets["carried stop step"] = mc.group(1)
                    continue
                k, _, v = body.partition(": ")
                bullets[k.strip().lower()] = v.strip()
        out[vid] = {
            "num": int(m.group(1)), "label": m.group(3), "expected": m.group(4), "step": m.group(5),
            "vk_desc": bullets.get("verification key"),
            "B_bullet": bullets.get("payload bytes b"), "R_bullet": bullets.get("receipt bytes"),
            "carried_stop": bullets.get("carried stop step"),
            "B_label": sect[ib].strip() if ib is not None else None,
            "B": _hexblock(sect[ib + 1:ir]) if ib is not None else None,
            "receipt": _hexblock(sect[ir + 1:]),
        }
    # Table 2: rows between +---+ separators, multi-line cells joined.
    table2 = {}
    i_t2 = next(i for i, s in enumerate(lines) if s.strip().startswith("| ID") and "What it shows" in s)
    i_end = next(i for i in range(i_t2, len(lines)) if lines[i].strip() == "Table 2")
    cur = None
    for s in lines[i_t2 + 1:i_end]:
        st = s.strip()
        if st.startswith("+"):
            if cur and cur[0][0]:
                table2[" ".join(cur[0])] = {"step": " ".join(cur[1]), "expected": " ".join(cur[2]),
                                            "label": " ".join(cur[3])}
            cur = [[], [], [], []]
            continue
        if st.startswith("|") and cur is not None:
            cells = [c.strip() for c in st.strip("|").split("|")]
            for k in range(4):
                if cells[k]:
                    cur[k].append(cells[k])
    return out, table2, hashlib.sha256(raw).hexdigest(), len(raw)


def key_from_description(desc, issuer_pub, mixed_pub=None):
    d = " ".join((desc or "").split())
    if d == "the issuer test key":
        return issuer_pub
    if d == "the mixed-order test key":
        return mixed_pub
    if d == "the neutral element, canonical encoding (01 followed by 31 zero bytes)":
        return b"\x01" + b"\x00" * 31
    if d == "the neutral element, non-canonical encoding y = p + 1 (EE, 30 bytes FF, 7F)":
        return b"\xee" + b"\xff" * 30 + b"\x7f"
    return None


# ---------------------------------------------------------------------------
# Self-tests of the primitives
# ---------------------------------------------------------------------------


def self_tests():
    res = []
    # RFC 8032 Section 7.1 TEST 1 (values as remembered from the RFC; cross-checked with the library below)
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sg = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    res.append(("RFC 8032 7.1 TEST 1: public key from seed", public_from_seed(sk) == pk))
    res.append(("RFC 8032 7.1 TEST 1: signature reproduced", ed25519_sign(sk, b"") == sg))
    res.append(("RFC 8032 7.1 TEST 1: passes the profile", profile_verify(pk, sg, b"")[0] is None))
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        ok = True
        for i in range(8):
            seed = hashlib.sha256(b"selftest-%d" % i).digest()
            msg = hashlib.sha512(b"m%d" % i).digest()[: 7 * i]
            k = Ed25519PrivateKey.from_private_bytes(seed)
            pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            ok = ok and pub == public_from_seed(seed) and k.sign(msg) == ed25519_sign(seed, msg) \
                and profile_verify(pub, k.sign(msg), msg)[0] is None
        res.append(("8 keys/messages: pure-Python Ed25519 equals pyca/cryptography", ok))
    except Exception as e:  # pragma: no cover
        res.append(("pyca/cryptography cross-check unavailable: %s" % e, False))
    cases = [(1e21, "1e+21"), (1e-7, "1e-7"), (0.000001, "0.000001"), (123.0, "123"), (4.5, "4.5"),
             (float(2 ** 53), "9007199254740992"), (float("9007199254740993"), "9007199254740992"),
             (1.5e300, "1.5e+300"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
             (0.1 + 0.2, "0.30000000000000004"), (-0.0, "0"), (1e20, "100000000000000000000"),
             (295147905179352830000.0, "295147905179352830000"), (-1.5, "-1.5"), (1.0, "1")]
    res.append(("ECMAScript number serialization (%d cases)" % len(cases), all(es_number(x) == s for x, s in cases)))
    res.append(("n_ok: 9007199254740991 is n, 9007199254740992 and a token of 5000 digits are not (round 24)",
                n_ok(JNum("9007199254740991")) and not n_ok(JNum("9007199254740992"))
                and not n_ok(JNum("1" + "0" * 4999))))
    res.append(("JCS string escaping (control, quote, backslash, solidus, U+007F, U+2028)",
                jcs_string('a"\\/\x00\x1f\b\t\n\f\r\x7f\u2028') == '"a\\"\\\\/\\u0000\\u001f\\b\\t\\n\\f\\r\x7f\u2028"'))
    res.append(("JCS key order by UTF-16 code units (U+E000 sorts after U+1F600)",
                _jcs(JObj([("\ue000", True), ("\U0001F600", False)])) == '{"\U0001F600":false,"\ue000":true}'))
    ts_cases = [("2026-10-02T00:00:00Z", True), ("2024-02-29T23:59:59Z", True), ("2023-02-29T00:00:00Z", False),
                ("1900-02-29T00:00:00Z", False), ("2000-02-29T00:00:00Z", True), ("2026-02-30T00:00:00Z", False),
                ("2026-12-31T23:59:60Z", False), ("2026-10-02t00:00:00Z", False), ("2026-10-02T00:00:00z", False),
                ("2026-10-02T24:00:00Z", False), ("2026-10-02T00:00:00.5Z", False), ("2026-10-02T00:00:00+00:00", False)]
    res.append(("timestamp rule (%d cases)" % len(ts_cases), all(timestamp_ok(s) == w for s, w in ts_cases)))
    b_cases = [("", True), ("QQ==", True), ("QR==", False), ("QQ=", False), ("Q===", False), ("QUJD", True),
               ("QUJ", False), ("QU JD", False), ("QUJD\n", False), ("QUI=", True), ("QUJ=", False)]
    res.append(("base64 canonical check (%d cases)" % len(b_cases), all((b64_check(s)[1] is None) == w for s, w in b_cases)))
    return res


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    with open(VECTORS, "rb") as f:
        vj = json.loads(f.read().decode("utf-8"))
    vectors = vj["vectors"]
    try:
        import cryptography
        libver = cryptography.__version__
    except Exception:
        libver = "unavailable"
    print("Independent verifier for draft-gruszka-signed-evaluation-receipts-02 (from the text alone)")
    print("python      : %s" % sys.version.split()[0])
    print("cryptography: %s (informational column only)" % libver)
    with open(DRAFT, "rb") as f:
        print("draft       : %s SHA-256 %s" % (os.path.basename(DRAFT), hashlib.sha256(f.read()).hexdigest()))
    with open(VECTORS, "rb") as f:
        print("vectors     : %s SHA-256 %s" % (os.path.basename(VECTORS), hashlib.sha256(f.read()).hexdigest()))
    print()

    print("SELF-TESTS OF PRIMITIVES")
    st = self_tests()
    for name, ok in st:
        print("  [%s] %s" % ("ok" if ok else "FAIL", name))
    print()

    # ---------------- main run
    print("RESULTS (steps of Section 5 evaluated in order; first failing step reported)")
    hdr = "  %-4s %-8s %-20s %-8s %-20s %-5s %-24s %s" % ("ID", "expected", "expected step", "computed",
                                                       "computed step", "match", "library (pyca) verify", "reason")
    print(hdr)
    print("  " + "-" * (len(hdr) + 30))
    results = {}
    mismatches = []
    for v in vectors:
        rb = bytes.fromhex(v["receipt_hex"])
        vk = base64.b64decode(v["verification_key_b64"], validate=True)
        r = verify(rb, vk)
        results[v["id"]] = (r, rb, vk)
        lb, ls = lenient_parts(rb)
        lib = library_verdict(vk, ls, lb)
        ok = r.verdict == v["expected"] and r.label() == v["step"]
        if not ok:
            mismatches.append((v["id"], "%s/%s" % (r.verdict, r.label()), "%s/%s" % (v["expected"], v["step"])))
        print("  %-4s %-8s %-20s %-8s %-20s %-5s %-24s %s" % (v["id"], v["expected"], v["step"], r.verdict, r.label(),
                                                           "yes" if ok else "NO", lib, r.reason or "-"))
    print()

    # ---------------- diagnostics
    print("DIAGNOSTICS (informational; not part of the verdict)")
    print("  Profile rules evaluated independently, for every vector whose first failing step is 11")
    print("  (1key 1R 2key 2R 3 4; '~' = evaluated on the lenient y-mod-p decoding because rule 1 fails):")
    for v in vectors:
        r, rb, vk = results[v["id"]]
        if r.step == 11:
            rules = profile_all_rules(vk, r.sig, pae(PAE_TYPE, r.B))
            print("    %-4s %s" % (v["id"], " ".join("%s:%s" % (k, rules[k]) for k in ("1key", "1R", "2key", "2R", "3", "4"))))
    print("  Step 5 on a lenient parse of B, for vectors whose first failing step is 4 (claim of step 5):")
    for v in vectors:
        r, rb, vk = results[v["id"]]
        if r.step == 4:
            w = step5_would_reject(r.B)
            print("    %-4s step 5 would %s   (step 4 reason: %s)" % (v["id"],
                  {True: "also reject", False: "ACCEPT", None: "not apply (B is not JSON text)"}[w], r.reason))
    print("    (N40 and N41 depend on this lenient reading: invalid UTF-8 replaced by U+FFFD, a lone surrogate")
    print("    written raw; RFC 8785 defines neither.)")
    rB = results["N41"][0].B
    lv, _, _ = parse(rB)
    esc = jcs_bytes(lv).replace("\ud800".encode("utf-8", "surrogatepass"), b"\\ud800") == rB
    print("    N41 with the lone surrogate serialized as the escape \\ud800 instead: B is its own serialization: %s"
          % ("yes" if esc else "no"))
    print()

    # ---------------- alternative readings
    print("ALTERNATIVE READINGS (measured: vectors whose verdict or step changes under a reading other than DEFAULT)")
    print("  R1-x / R2-x = round-1 / round-2 reading that the current text excludes;")
    print("  M-x = measurement of which later step would still reject a vector.")
    alts = [
        ("R1-A1 commitment pattern checked in step 6", Reading(commit_pattern_in_step6=True)),
        ("R1-A2 profile rules 1 and 2 check R before the key", Reading(profile_r_before_key=True)),
        ("R1-A3 inexact number tokens fail step 4", Reading(inexact_number_fails_step4=True)),
        ("R1-A9' overflowing number tokens fail step 4 (round-1 default)", Reading(overflow_fails_step4=True)),
        ("R1-A4 RFC 7493 2.2 number range applied to the receipt at step 1", Reading(receipt_number_range_step1=True)),
        ("R1-A7 decimal-string digits read as any Unicode decimal digit", Reading(unicode_digits=True)),
        ("R1-A8 timestamp date checked with a calendar that has no year 0", Reading(calendar_no_year0=True)),
        ("R2-A10 'a digit is one of the ASCII digits 0 to 9' applied to 'lowercase hexadecimal digits'",
         Reading(hexdigit_is_digit=True)),
        ("R2-A11 Meaning column of passed read as part of its row (agreement checked at step 6)",
         Reading(passed_agreement_in_step6=True)),
        ("R4-A12 step 4 'double nearest to it' read as nearest finite double (1e400 -> DBL_MAX)",
         Reading(nearest_finite_double=True)),
        ("M-A5 step 4 without the surrogate and noncharacter rules", Reading(step4_skip=("surrogate", "noncharacter"))),
        ("M-A6 step 4 without BOM, duplicate and trailing-data rules (claim of step 5)",
         Reading(step4_skip=("bom", "duplicate", "trailing"))),
        ("M-K2 steps 1 and 4 read without 3.1: whitespace after the end of the JSON text counts as data",
         Reading(trailing_ws_is_data=True)),
        ("M-P13 steps 1 and 4 read as the round-13 text: whitespace before the JSON text counts as data",
         Reading(leading_ws_is_data=True)),
    ]
    moved_by = {}
    for name, rd in alts:
        moved = []
        for v in vectors:
            r0, rb, vk = results[v["id"]]
            r1 = verify(rb, vk, rd)
            if (r1.verdict, r1.label()) != (r0.verdict, r0.label()):
                moved.append("%s: %s/%s -> %s/%s" % (v["id"], r0.verdict, r0.label(), r1.verdict, r1.label()))
        moved_by[name.split(" ")[0]] = sorted(m.split(":")[0] for m in moved)
        print("  %s" % name)
        print("    moved (%d): %s" % (len(moved), "; ".join(moved) if moved else "none"))
    print()

    # ---------------- coverage: deviating verifiers
    print("COVERAGE (measured: does some vector catch a verifier that deviates from the text as described?)")
    ws = [
        ("W1 rejects a signature object without key (the {alg, sig} member set of 3.1)", Reading(w_require_key=True)),
        ("W2 step 1 ignores invalid UTF-8, surrogates and noncharacters in the receipt", Reading(w_receipt_codepoints=True)),
        ("W4 step 8 treats >, <= and < as >=", Reading(w_comparator_ge=True)),
        ("W5 step 8 compares score and threshold as binary floats", Reading(w_float_compare=True)),
        ("W6 step 6 has no upper bound 2^53 - 1 for n", Reading(w_n_no_upper=True)),
        ("W7 step 5 keeps number tokens as written (no RFC 8785 number serialization)", Reading(w_raw_number_tokens=True)),
        ("W7b as W7, and step 6 judges n by its double value", Reading(w_raw_number_tokens=True, w_n_by_value=True)),
    ]
    for name, rd in ws:
        caught = []
        for v in vectors:
            r1 = verify(bytes.fromhex(v["receipt_hex"]), base64.b64decode(v["verification_key_b64"]), rd)
            if (r1.verdict, r1.label()) != (v["expected"], v["step"]):
                caught.append("%s gets %s/%s (expected %s/%s)" % (v["id"], r1.verdict, r1.label(), v["expected"], v["step"]))
        print("  %-84s matches %d of %d" % (name, len(vectors) - len(caught), len(vectors)))
        print("    caught by: %s" % ("; ".join(caught) if caught else "NO VECTOR"))
    print()

    # ---------------- consistency of the vectors with the text
    print("CONSISTENCY OF vectors.json WITH THE TEXT (measured)")
    checks = []

    def chk(name, ok, note=""):
        checks.append(ok)
        print("  [%s] %s%s" % ("ok" if ok else "MISMATCH", name, (" -- " + note) if note else ""))

    # Round 9: the transcribed names stand in the text as written (no other source holds them).
    with open(DRAFT, "rb") as f:
        dtext = f.read().decode("utf-8")
    for nm, val in (("type (4.2)", PAE_TYPE), ("payload schema identifier (3.2)", PAYLOAD_SCHEMA)):
        chk("the %s %s stands in the text on a line of its own" % (nm, val),
            any(line.strip() == val for line in dtext.splitlines()))
    app, table2, dsha, dlen = extract_appendix(DRAFT)
    chk("Appendix A headings found for every vector in vectors.json",
        set(app) == set(v["id"] for v in vectors), "%d headings, %d vectors" % (len(app), len(vectors)))
    chk("Table 2 has a row for every vector", set(table2) == set(v["id"] for v in vectors), "%d rows" % len(table2))
    issuer_seed = bytes.fromhex(vj["test_keys"]["issuer"]["ed25519_seed_hex"])
    issuer_pub = base64.b64decode(vj["test_keys"]["issuer"]["public_raw_b64"])
    other_seed = bytes.fromhex(vj["test_keys"]["other"]["ed25519_seed_hex"])
    other_pub = base64.b64decode(vj["test_keys"]["other"]["public_raw_b64"])
    chk("A.1 issuer seed derives the A.1 issuer public key (x7ppA99D...)",
        public_from_seed(issuer_seed) == issuer_pub and b64(issuer_pub) == "x7ppA99DtumHO/Au0M/gumSK8IwCzNwPiID92BSFbak=")
    chk("A.1 second seed derives the A.1 second public key (tvFn0pKi...)",
        public_from_seed(other_seed) == other_pub and b64(other_pub) == "tvFn0pKiOvm4eNHsrH3T6OsiYk7X0aMfy60UyuObvMQ=")
    # Round 10: the mixed-order test key, from the text of A.1 alone.
    tl = dtext.splitlines()
    im = next((i for i, x in enumerate(tl) if x.strip().startswith("Mixed-order test key, used only by vector N61")), None)
    mixed_pub = None
    if im is None:
        chk("A.1 names a mixed-order test key", False)
    else:
        vals = [x.strip() for x in tl[im + 1:im + 20] if re.fullmatch(r"[0-9a-f]{64}|[A-Za-z0-9+/]{43}=", x.strip())]
        t8_enc, mixed_pub = bytes.fromhex(vals[0]), base64.b64decode(vals[1], validate=True)
        t8 = decode_point(t8_enc)[0]
        chk("A.1 the point given first has order exactly 8",
            t8 is not None and is_neutral(scalar_mult(8, t8)) and not is_neutral(scalar_mult(4, t8)))
        chk("A.1 the issuer public point plus that point encodes to the mixed-order key",
            t8 is not None and encode_point(point_add(decode_point(issuer_pub)[0], t8)) == mixed_pub)
        am = decode_point(mixed_pub)[0]
        chk("A.1 the mixed-order key passes rule 1 of 4.4 and fails rule 2 (L times it is not the neutral element)",
            am is not None and not is_neutral(scalar_mult(8, am)) and not is_neutral(scalar_mult(L, am)))
    for kind in ("model", "dataset"):
        s = vj["test_salts"][kind]
        c = "sha256:" + hashlib.sha256(bytes.fromhex(s["salt_hex"]) + s["identifier"].encode()).hexdigest()
        chk("A.1 %s commitment = SHA-256(salt || UTF-8 identifier) (Section 3.3)" % kind, c == s["commit"])
    chk("A.1 and vectors.json carry no Merkle filler leaves (the receipt has no inclusion member)",
        "merkle_other_leaves_hex" not in vj)
    for v in vectors:
        a = app.get(v["id"], {})
        rb = bytes.fromhex(v["receipt_hex"])
        pb = bytes.fromhex(v["payload_hex"]) if v.get("payload_hex") else None
        notes = []
        ok = True
        if a.get("receipt") != rb:
            ok = False
            notes.append("receipt hex differs from Appendix A")
        if a.get("B") != pb:
            ok = False
            notes.append("payload hex differs from Appendix A")
        if hashlib.sha256(rb).hexdigest() != v["receipt_sha256"] or v["receipt_sha256"] not in (a.get("R_bullet") or ""):
            ok = False
            notes.append("receipt SHA-256 differs")
        if ("%d bytes" % len(rb)) not in (a.get("R_bullet") or ""):
            ok = False
            notes.append("receipt length differs from the bullet")
        if pb is not None and (("%d bytes" % len(pb)) not in (a.get("B_bullet") or "")
                               or hashlib.sha256(pb).hexdigest() not in (a.get("B_bullet") or "")):
            ok = False
            notes.append("payload length/SHA-256 differs from the bullet")
        if a.get("expected") != v["expected"] or a.get("step") != v["step"]:
            ok = False
            notes.append("heading says %s/%s" % (a.get("expected"), a.get("step")))
        t2 = table2.get(v["id"], {})
        if t2.get("expected") != v["expected"] or t2.get("step") != v["step"] or t2.get("label") != a.get("label"):
            ok = False
            notes.append("Table 2 says %s/%s/%s" % (t2.get("expected"), t2.get("step"), t2.get("label")))
        kd = key_from_description(a.get("vk_desc"), issuer_pub, mixed_pub)
        if kd is None or b64(kd) != v["verification_key_b64"]:
            ok = False
            notes.append("verification key description %r does not give %s" % (a.get("vk_desc"), v["verification_key_b64"]))
        # payload_b64 decodes (leniently) to payload_hex
        lb, _ = lenient_parts(rb)
        if lb != pb:
            ok = False
            notes.append("payload_b64 does not decode to payload_hex")
        chk("%-4s text bytes, digests, heading, Table 2, key == vectors.json" % v["id"], ok, "; ".join(notes))
    # Round 6 labels: "payload bytes carried (not B: ... stops at step N ...)" exactly for vectors whose
    # computed first failing step is 1, 2 or 3, with N equal to that step; "B (hex):" for all others.
    lab_ok, lab_notes = True, []
    for v in vectors:
        a = app.get(v["id"], {})
        r = results[v["id"]][0]
        early = r.verdict == "FAIL" and r.step in (1, 2, 3)
        if early and a.get("B") is None and (a.get("B_bullet") or "").startswith("none"):
            good = True   # no payload bytes at all (N24); bullet wording reported below
            print("  [info] %-4s first failing step %s, carries no payload bytes; bullet still reads 'payload bytes B: %s'"
                  % (v["id"], r.step, a.get("B_bullet")))
        elif early:
            good = a.get("carried_stop") == str(r.step) and a.get("B_label") == "Payload bytes carried (hex):"
        else:
            good = a.get("carried_stop") is None and a.get("B_label") in ("B (hex):", None)
        if not good:
            lab_ok = False
            lab_notes.append("%s: step %s, label %r, carried %r" % (v["id"], r.step, a.get("B_label"), a.get("carried_stop")))
    n_carried = sum(1 for v in vectors if app.get(v["id"], {}).get("carried_stop"))
    chk("Appendix A labels: 'payload bytes carried ... step N' where the computed first failing step N is 1, 2 or 3"
        " and payload bytes exist; 'B' labels elsewhere",
        lab_ok, "%d vectors carry the label; %s" % (n_carried, "; ".join(lab_notes) or "all consistent"))
    print()

    # ---------------- claims of the text
    print("CLAIMS OF THE TEXT (measured)")
    steps_seen = sorted(set(r.step for (r, _, _) in results.values() if r.verdict == "FAIL"))
    chk("Section 5: each of the eleven steps is the first failing step of at least one vector",
        steps_seen == list(range(1, 12)), "steps seen: %s" % steps_seen)
    cov = {}
    for vid, (r, _, _) in results.items():
        if r.step == 11:
            cov.setdefault((r.rule, r.which), []).append(vid)
    want_cov = {(1, "key"): ["N18"], (1, "R"): ["N17"], (2, "key"): ["N12"], (2, "R"): ["N16"], (3, None): ["N6"], (4, None): ["N7"]}
    chk("Section 5: profile coverage N18 1/key, N17 1/R, N12 2/key, N16 2/R, N6 3, N7 4",
        set(cov) == set(want_cov) and all(set(want_cov[k]) <= set(cov[k]) for k in want_cov),
        "named vector in each bucket (containment, 'cover'): " + str(sorted(cov.items(), key=lambda x: (x[0][0], str(x[0][1])))))
    lib = {}
    for vid in ("N12", "N16", "N18", "N61", "N6", "N17", "N59"):
        r, rb, vk = results[vid]
        lib[vid] = library_verdict(vk, r.sig, r.B)
    chk("Sections 8 and 11: pyca/cryptography %s accepts N12, N16, N18, N61 and rejects N6, N17, N59" % libver,
        [lib[x] for x in ("N12", "N16", "N18", "N61")] == ["accept"] * 4
        and [lib[x] for x in ("N6", "N17", "N59")] == ["reject"] * 3, str(lib))
    # Section 5 last paragraph: every non-canonical encoding that decodes at all is small or mixed order
    encs = [((y + P) | (sg << 255)).to_bytes(32, "little") for y in range(19) for sg in (0, 1)]
    encs += [(y | (1 << 255)).to_bytes(32, "little") for y in (1, P - 1)]   # x = 0 with the sign bit set
    tally = {"undecodable": 0, "small": 0, "mixed": 0, "prime-order": 0}
    for e in encs:
        assert decode_point(e)[0] is None
        pt = decode_point_lenient(e)
        if pt is None:
            tally["undecodable"] += 1
        elif is_neutral(scalar_mult(8, pt)):
            tally["small"] += 1
        elif is_neutral(scalar_mult(L, pt)):
            tally["prime-order"] += 1
        else:
            tally["mixed"] += 1
    chk("Section 5: every non-canonical encoding that decodes (y mod p) is of small or mixed order",
        tally["prime-order"] == 0, "%d encodings: %s" % (len(encs), tally))
    chk("Section 5 (revised): 'Rule 1 rejects 40 encodings ... 14 of them give no point, 6 ... small order and 20 ... mixed order'",
        len(encs) == 40 and tally == {"undecodable": 14, "small": 6, "mixed": 20, "prime-order": 0})
    # Under a prime-order key a mixed-order R never satisfies the cofactorless equation: for each of the 20
    # mixed-order points M, M + k*A has a torsion component for every k, so it is never S*B'.
    mixed_pts = [decode_point_lenient(e) for e in encs]
    mixed_pts = [m for m in mixed_pts if m is not None and not is_neutral(scalar_mult(8, m))]
    A_iss, _ = decode_point(issuer_pub)
    ok_mixed = all(not is_neutral(scalar_mult(L, point_add(m, scalar_mult(k, A_iss)))) for m in mixed_pts for k in (1, 2, 3, 12345))
    chk("Section 5 (round 11): 'None of these 26 points has order L, so a Receiver without rule 1 would still "
        "reject each of them under rule 2'", tally["prime-order"] == 0 and tally["small"] + tally["mixed"] == 26)
    chk("Section 5 (round 11, N59): under the prime-order issuer key, M + k*A stays outside the prime-order "
        "subgroup, so no S satisfies the cofactorless equation (20 mixed points, 4 values of k)",
        len(mixed_pts) == 20 and ok_mixed)
    # Round 11: the equivalence paragraph of 4.4, and the N59 and N61 (P11 until round 15) sentences of Section 5
    def _cof(A_bytes, sig, msg, cofactored):
        A_, R_ = decode_point(A_bytes)[0], decode_point(sig[:32])[0]
        S_ = int.from_bytes(sig[32:64], "little")
        k_ = int.from_bytes(hashlib.sha512(sig[:32] + A_bytes + msg).digest(), "little") % L
        lhs, rhs = scalar_mult(S_, BASE), point_add(R_, scalar_mult(k_, A_))
        if cofactored:
            lhs, rhs = scalar_mult(8, lhs), scalar_mult(8, rhs)
        return point_equal(lhs, rhs)
    n_eq, n_cmp = 0, 0
    for v in vectors:
        r, rb, vk = results[v["id"]]
        if r.sig is None or r.B is None or len(r.sig) != 64:
            continue
        pa, pr = decode_point(vk)[0], decode_point(r.sig[:32])[0]
        if pa is None or pr is None or is_neutral(pa) or is_neutral(pr):
            continue
        if not (is_neutral(scalar_mult(L, pa)) and is_neutral(scalar_mult(L, pr))):
            continue
        if int.from_bytes(r.sig[32:64], "little") >= L:
            continue
        msg_ = pae(PAE_TYPE, r.B)
        n_cmp += 1
        n_eq += _cof(vk, r.sig, msg_, False) == _cof(vk, r.sig, msg_, True)
    chk("4.4 (round 11): 'Because A and R have order L, the cofactorless equation of rule 4 and the cofactored "
        "equation ... accept the same signatures': same result on every vector that passes rules 1 to 3",
        n_cmp > 0 and n_eq == n_cmp, "%d of %d vectors" % (n_eq, n_cmp))
    r59, _, vk59 = results["N59"]
    m59 = pae(PAE_TYPE, r59.B)
    chk("Section 5 (round 11): N59 uses the issuer key, its R has mixed order, the cofactored equation holds and "
        "the cofactorless one does not",
        vk59 == issuer_pub and not is_neutral(scalar_mult(8, decode_point(r59.sig[:32])[0]))
        and not is_neutral(scalar_mult(L, decode_point(r59.sig[:32])[0]))
        and _cof(vk59, r59.sig, m59, True) and not _cof(vk59, r59.sig, m59, False))
    r11, _, vk11 = results["N61"]
    chk("Section 5 (round 11): N61's signature satisfies the cofactorless equation under the mixed-order key; "
        "only rule 2 rejects it", _cof(vk11, r11.sig, pae(PAE_TYPE, r11.B), False) and r11.label() == "11 (profile 2, key)")
    # Round 12: the batch sentence and the DSSE date, read from the text without page breaks (the P11 sentence of
    # round 12 is replaced in round 16).
    with open(DRAFT, "r", encoding="utf-8") as f:
        kept = [ln for ln in f.read().split("\n") if "\f" not in ln
                and not re.match(r"^Gruszka\s+Expires .*\[Page \d+\]$", ln)
                and not re.match(r"^Internet-Draft\s{2,}", ln)]
    flat12 = re.sub(r"\s+", " ", " ".join(kept))
    batch12 = ("accept exactly the same signatures. This specification defines individual verification only. A "
               "randomized batch result MUST NOT substitute for checking all four rules for each signature. A "
               "Receiver MUST NOT leave out any of the four rules.")
    chk("4.4 (round 12): the batch sentence stands, and the sentence that equated a batch with verifying each "
        "signature is gone", batch12 in flat12 and "randomized batch verification reaches the same verdict" not in flat12)
    n61s = ("N61 uses the mixed-order test key, the issuer's public point plus a point of order 8, with a signature "
            "that satisfies the cofactorless equation; only rule 2 rejects it. Its expected result is FAIL at step 11, "
            "rule 2 for the verification key.")
    chk("Section 5 (round 16): the N61 sentences stand without identifier history, and N61 fails at step 11, rule 2 "
        "for the key", n61s in flat12 and "retains its original identifier" not in flat12
        and "revised prime-order rule" not in flat12 and r11.label() == "11 (profile 2, key)")
    chk("References (round 12): DSSE is dated 28 May 2024, the date of tag v1.0.2",
        re.search(r"\[DSSE\][^\[]*28 May 2024", flat12) is not None and "10 May 2024" not in flat12)
    # Round 13: the closing-round sentences of 3.2, 4.4 and step 1, and the vectors P12 and N60.
    k1 = ("In it, x*P is the scalar multiplication of the point P by the integer x, B' is the base point, and L "
          "is the order of B' ([RFC8032] Section 5.1).")
    chk("4.4 (round 13, K1): L is defined as the order of B', and L*B' is the neutral element",
        k1 in flat12 and "and B' is the base point." not in flat12 and is_neutral(scalar_mult(L, BASE))
        and not is_neutral(BASE))
    k2 = ("anything before or after the JSON text other than insignificant whitespace ([RFC8259] Section 2)")
    chk("Section 5 step 1 (round 14, K2 and P13): only insignificant whitespace may stand before or after the "
        "JSON text, as in 3.1", k2 in flat12 and "data after the end of the JSON text ([RFC8259] Section 2)" not in flat12
        and "anything after the end of the JSON text" not in flat12
        and "nothing before or after the JSON text other than insignificant whitespace ([RFC8259] Section 2)." in flat12
        and "nothing after the end of the JSON text" not in flat12)
    k3 = "the first 32 bytes of the 64-byte signature and the verification key."
    chk("4.4 rule 4 (round 13, K3): R is the first 32 bytes of the 64-byte signature",
        k3 in flat12 and "the first 32 bytes of sig" not in flat12)
    k4 = ("The date exists in the proleptic Gregorian calendar: the day of the month is at most the maximum that "
          "[RFC3339] Section 5.7 gives for its month and year, under the leap-year rule of [RFC3339] Appendix C, "
          "so the year 0000 exists and is a leap year;")
    chk("3.2 (round 13, K4): RFC 3339 Section 5.7 is cited for the day maximum only",
        k4 in flat12 and "proleptic Gregorian calendar ([RFC3339] Section 5.7)" not in flat12)
    cov13 = ("P12 is the receipt of P1 followed by a line feed, insignificant whitespace that step 1 admits. N60 is "
             "B of P1 followed by a line feed, signed anew: step 4 admits the line feed under the rules of step 1, "
             "and step 5 rejects B, because its RFC 8785 serialization has no insignificant whitespace.")
    r12, rb12, vk12 = results["P12"]
    r60, rb60, vk60 = results["N60"]
    rp1, rbp1, vkp1 = results["P1"]
    chk("Section 5 (round 13): P12 is the receipt bytes of P1 followed by 0a under the issuer key, and passes",
        cov13 in flat12 and rb12 == rbp1 + b"\n" and vk12 == vkp1 == issuer_pub and r12.label() == "all"
        and r12.verdict == "PASS")
    chk("Section 5 (round 13): N60's B is P1's B followed by 0a, its signature meets the four rules under the "
        "issuer key, and it fails at step 5",
        r60.B == rp1.B + b"\n" and vk60 == issuer_pub
        and profile_verify(vk60, lenient_parts(rb60)[1], pae(PAE_TYPE, r60.B)) == (None, None, "")
        and (r60.verdict, r60.label()) == ("FAIL", "5"))
    chk("Section 5 (round 13): under M-K2, which reads steps 1 and 4 without 3.1, exactly P12 and N60 move",
        moved_by.get("M-K2") == ["N60", "P12"], str(moved_by.get("M-K2")))
    # Round 14: P13, the names under signed-evidence.org, the IANA Considerations and the intended status.
    cov14 = ("P13 is a line feed followed by the receipt of P1, insignificant whitespace before the JSON text "
             "that step 1 admits.")
    r13, rb13, vk13 = results["P13"]
    chk("Section 5 (round 14): P13 is 0a followed by the receipt bytes of P1 under the issuer key, and passes",
        cov14 in flat12 and rb13 == b"\n" + rbp1 and vk13 == issuer_pub and (r13.verdict, r13.label()) == ("PASS", "all"))
    chk("Section 5 (round 14): under M-P13, which admits whitespace only after the JSON text, exactly P13 moves",
        moved_by.get("M-P13") == ["P13"], str(moved_by.get("M-P13")))
    v42 = ("It MUST NOT change for this format, because a change would invalidate every signature made under it; "
           "a new format uses a new type. The string is a media type name in the vendor tree ([RFC6838] Section "
           "3.2) with the +json structured syntax suffix ([RFC6839] Section 3.1). It is the same string that a "
           "DSSE envelope would carry as payloadType.")
    chk("4.2 (round 14): the type is a media type name in the vendor tree, and it MUST NOT change for this format",
        v42 in flat12 and "standards tree" not in flat12 and "requests its registration" not in flat12)
    # Revision -01, review point 5 of 2026-10-08: the paragraph also says where the vectors of this version are
    # maintained and that a later version comes with its own vectors; {{vectors}} is Appendix A, Test Vectors.
    v32 = ("The version of the format lives in the schema identifier. The test vectors of this version are those "
           "of Appendix A; they are maintained in this document. A later version uses a different identifier "
           "under https://signed-evidence.org/eval-receipt/ and comes with its own test vectors. The identifier "
           "above keeps naming the format of this document. 3.3.")
    chk("3.2 (round 14): a later version uses a different identifier under https://signed-evidence.org/eval-receipt/ "
        "(on a line of its own), and the payload schema of this version stands under it", v32 in flat12
        and any(line.strip() == "https://signed-evidence.org/eval-receipt/" for line in dtext.splitlines())
        and PAYLOAD_SCHEMA.startswith("https://signed-evidence.org/eval-receipt/") and "sub-namespace" not in flat12
        and any(line.rstrip() == "Appendix A.  Test Vectors" for line in dtext.splitlines()))
    m_sub = re.search(r"Subtype name: (\S+)", flat12)
    m_typ = re.search(r"Type name: (\S+)", flat12)
    chk("10.1 (round 14): the template's type and subtype name give the type of 4.2",
        m_sub is not None and m_typ is not None
        and m_typ.group(1) + "/" + m_sub.group(1) == PAE_TYPE, "%s/%s" % (m_typ and m_typ.group(1), m_sub and m_sub.group(1)))
    # Round 15: a line that ends with a hyphen continues the word on the next line (xml2rfc breaks only after a
    # hyphen that the word carries), so this reading joins the two without a space.
    flat15 = re.sub(r"\s+", " ", re.sub(r"(?<=\S-)\n\s*(?=\S)", "", "\n".join(kept)))
    lines15 = [ln.rstrip() for ln in kept]
    i10 = next((i for i, ln in enumerate(lines15) if ln == "10.  IANA Considerations"), None)
    i101 = next((i for i, ln in enumerate(lines15) if ln == "10.1.  Media Type Registration Template"), None)
    i11 = next((i for i, ln in enumerate(lines15) if ln == "11.  Implementation Status"), None)
    v15 = ("This document has no IANA actions. Registering the media type of Section 10.1 in the vendor tree goes "
           "directly to IANA ([RFC6838] Section 3.2) and is not an action of this document.")
    between = (re.sub(r"\s+", " ", " ".join(lines15[i10 + 1:i101])).strip()
               if i10 is not None and i101 is not None and i10 < i101 else None)
    chk("10 (round 15): the statement stands directly under Section 10, before 10.1, and is all that stands there",
        between == v15, between if between is not None else "Section 10 or 10.1 heading not found")
    s101 = (re.sub(r"\s+", " ", re.sub(r"(?<=\S-)\n\s*(?=\S)", "", "\n".join(lines15[i101 + 1:i11]))).strip()
            if i101 is not None and i11 is not None and i101 < i11 else "")
    first101 = ("The following template for application/vnd.signed-evidence.eval-receipt+json is the one for its "
                "registration in the vendor tree; it is given for information. This media type identifies the "
                "canonical payload bytes B defined in Section 3.4.")
    chk("10.1 (round 18): the title is 'Media Type Registration Template', in the table of contents too, and 10.1 "
        "begins with the sentence that the template for the type of 4.2 is the one for its registration in the "
        "vendor tree and is given for information, followed by the paragraph 'This media type identifies ...'",
        i101 is not None and s101.startswith(first101) and PAE_TYPE in first101
        and any(re.match(r"^ {5}10\.1\.  Media Type Registration Template \.", ln) for ln in lines15),
        s101[:160])
    chk("10.1 (round 15): the sentences replaced in this round are gone",
        "A registration in the vendor tree goes directly" not in flat15
        and "The template below is given for information" not in flat15
        and "Media Type application/vnd" not in flat15)
    sec18 = ("Security considerations: B is data and contains no active content: it carries no directive and "
             "nothing a recipient executes. B is not compressed. A receipt that carries B gives integrity and "
             "origin of B only under a key the Receiver fixed before verification, and only with the procedure "
             "of Section 5; a key named in the receipt is never used on its own. B gives no confidentiality: its "
             "members are readable by anyone who holds it, and model and dataset identifiers appear in it only as "
             "salted commitments (Section 3.3, Section 9). Parsing untrusted input needs documented resource "
             "limits; reaching a limit is not a verdict. See Section 8 of this document and [RFC8259] Section 12.")
    chk("10.1 (round 18): the field 'Security considerations' states active content (none), compression (none), "
        "integrity and origin only under a key fixed before verification, no confidentiality, resource limits "
        "(RFC 6838 Section 4.6), and the earlier two sentences are gone",
        sec18 in s101 and "Security considerations: See Section 8 of this document. A Receiver verifies" not in s101,
        s101[s101.find("Security considerations:"):s101.find("Security considerations:") + 120])
    want_fields = ["Type name", "Subtype name", "Required parameters", "Optional parameters",
                   "Encoding considerations", "Security considerations", "Interoperability considerations",
                   "Published specification", "Applications that use this media type",
                   "Fragment identifier considerations", "Additional information",
                   "Person & email address to contact for further information", "Intended usage",
                   "Restrictions on usage", "Author", "Change controller"]
    got_fields = [m.group(1) for m in re.finditer(r"^ {3}(%s):" % "|".join(re.escape(f) for f in
                  want_fields + ["Provisional registration\\?"]), "\n".join(lines15[(i101 or 0):(i11 or 0)]), re.M)]
    chk("10.1 (round 15, A): 'Provisional registration?' is gone (RFC 6838 Section 5.6: standards tree only), and "
        "the other sixteen fields stand in their order",
        got_fields == want_fields and "Provisional registration" not in flat15, str(got_fields))
    # Round 19 (owner choices 4 and 8 of 2026-10-11): the contact field carries the name RFC 6838 gives it, and
    # contact and change controller are "Konrad Gruszka <kontakt@b7n0de.com>", with the angle brackets in the text.
    m_cc = re.search(r"Change controller: (.*?) 11\. Implementation Status", flat12)
    m_pc = re.search(r"Person & email address to contact for further information: (.*?) Intended usage:", flat12)
    owner_cc = "Konrad Gruszka <kontakt@b7n0de.com>"
    chk("10.1 (round 19): contact and change controller are %s, and the author is Konrad Gruszka" % owner_cc,
        m_cc is not None and m_cc.group(1) == owner_cc and m_pc is not None and m_pc.group(1) == owner_cc
        and re.search(r"Author: Konrad Gruszka Change controller:", flat12) is not None and "mailto:" not in flat12,
        "%s | %s" % (m_cc.group(1) if m_cc else "not found", m_pc.group(1) if m_pc else "not found"))
    chk("10 (round 14): 10.2, the URN sub-namespace and its references are gone, and IANA is asked for nothing",
        "URN Sub-namespace" not in flat12 and "urn:ietf:params" not in flat12 and "[RFC3553]" not in flat12
        and "[RFC8141]" not in flat12 and "IANA is requested" not in flat12 and "two requests" not in flat12)
    chk("Names (round 14): neither name used before 2026-10-08 stands in the text",
        "application/eval-receipt+json" not in flat12 and "urn:ietf:params:eval-receipt" not in flat12)
    chk("Header (round 14): the intended status is Informational, and no Standards Track is named",
        re.search(r"Intended status: Informational", dtext) is not None and "Standards Track" not in dtext)
    pschema = sorted(set(parse(results[v["id"]][0].B)[0]["schema"] for v in vectors
                         if v["expected"] == "PASS"))
    chk("3.2 (round 14): every positive vector's B carries exactly the payload schema identifier",
        pschema == [PAYLOAD_SCHEMA], str(pschema))
    # Round 20 (card DRAFTS-01-INHALT-02, owner choice 5 of 2026-10-11): the paragraph on the two parties stands in
    # the Introduction right after the second paragraph, word for word, and its cross-reference names Section 5, the
    # Verification Procedure. It carries no BCP 14 keyword.
    p20 = ("Two parties that share no infrastructure can use this format: an Issuer that ran an evaluation, such as "
           "the provider of a model or a test laboratory, and a Receiver that decides on the result, such as an "
           "operator that admits a model into service or an auditor. The Issuer hands over one receipt; the Receiver "
           "checks it under a key it fixed beforehand, without access to the Issuer's systems, and learns which result "
           "the Issuer reports for which committed model and dataset, under which threshold and comparator. The "
           "receipt object exists next to the DSSE-compatible signature because it carries, together with B, the "
           "fixed type and the payload schema identifier and is verified by one procedure (Section 5), so that every "
           "Receiver reaches the same verdict on the same receipt bytes and verification key, provided verification "
           "completes. A DSSE signature check alone is not that verdict.")
    old21 = "so that every Receiver reaches the same verdict on the same bytes."
    before20 = "over a pre-authentication encoding that binds a fixed type. "
    after20 = " A receipt establishes integrity and origin:"
    sec5 = any(ln == "5.  Verification Procedure" for ln in lines15)
    kw20 = [k for k in ("MUST", "SHOULD", "SHALL", "REQUIRED", "RECOMMENDED", "MAY", "OPTIONAL") if re.search(r"\b%s\b" % k, p20)]
    chk("1 (rounds 20 and 21): the paragraph on the two parties, in the wording of review block E, stands word for "
        "word after the second paragraph of the Introduction, its 'Section 5' is the Verification Procedure, it has "
        "no BCP 14 keyword, and the old ending is gone",
        (before20 + p20 + after20) in flat15 and flat15.count(p20) == 1 and sec5 and not kw20
        and old21 not in flat15,
        "found in place: %s; heading 5 is the Verification Procedure: %s; keywords: %s; old ending left: %s"
        % ((before20 + p20 + after20) in flat15, sec5, kw20 or "none", old21 in flat15))
    # Round 16: Section 8, the Appendix A label sentence, the order of Table 2 and A.2, and the counts.
    s8 = ("In the measurements of Section 11, the plain Ed25519 verification of a general library accepted the "
          "signatures of vectors N12, N16, N18 and N61 and rejected those of N6, N17 and N59; the profile of Section "
          "4.4 rejects all seven. A Receiver that relies on a library verdict alone therefore does not implement "
          "this format.")
    seven = ("N12", "N16", "N18", "N61", "N6", "N17", "N59")
    chk("Section 8 (round 16): the sentence on the library measurements stands, the old one is gone, and the profile "
        "rejects all seven vectors it names",
        s8 in flat12 and "accepted some of the signatures" not in flat12 and "rejects all six" not in flat12
        and all(results[x][0].verdict == "FAIL" for x in seven), str([(x, results[x][0].verdict) for x in seven]))
    # Round 17: the pattern of library verdicts the text names, against this run; the version is information.
    m11 = re.search(r"In the measurements behind Appendix A, the plain Ed25519 verification of pyca/cryptography "
                    r"(\S+) accepted the signatures of vectors (.+?), and rejected those of (.+?)\. ", flat12 + " ")
    acc11 = re.findall(r"\b[PN]\d+\b", m11.group(2)) if m11 else []
    rej11 = re.findall(r"\b[PN]\d+\b", m11.group(3)) if m11 else []
    chk("Section 11 (round 17): the library verdicts the text names (accepted %s; rejected %s) are those of the "
        "library in this run, and the seven vectors are those of Section 8" % (", ".join(acc11), ", ".join(rej11)),
        m11 is not None and sorted(acc11 + rej11) == sorted(seven) and len(set(acc11 + rej11)) == 7
        and all(lib.get(x) == "accept" for x in acc11) and all(lib.get(x) == "reject" for x in rej11), str(lib))
    if m11 is not None and m11.group(1) != libver:
        print("  [info] Section 11 names pyca/cryptography %s; this run uses %s. The verdicts above are this run's."
              % (m11.group(1), libver))
    # Round 25: revision -02. Section 11 gives the conformance run and the further verifier; the numbers it states for
    # Appendix A are counted from the text. The Open Items are gone; an appendix of changes follows Appendix A.
    flat25 = re.sub(r"\s+", " ", re.sub(r"(?<=\S-)\n\s*(?=\S)", "", "\n".join(kept)))
    s25 = ["On 2026-10-12, the implementation named above, at commit a339424e07fd58fa261d8ca3f41af5de4dcbf751 of its "
           "work branch, was run on the 66 vectors of Appendix A with the bytes given there, and for each vector its "
           "verdict and first failing step were compared with the expected ones: it reached the expected verdict and "
           "the expected first failing step on all 66 vectors.",
           "A further verifier, written from the published text of this document alone, agreed with the verifier "
           "written by the author of the generator on the verdict and the first failing step of each of the 66 "
           "vectors, on 23000 targeted inputs across all eleven "
           "steps and on 4002 serializations of numbers by [RFC8785], with no deviation on these inputs (measured "
           "on 2026-10-11).",
           # Round 28: the refusal of a key before any receipt is read is that of the command-line interface
           "The show-eval command of that implementation with --expect-issuer refuses a verification key whose "
           "y-coordinate is not below p or that is a point of small order, as in vectors N12, N18, N53 and N54, "
           "before reading any receipt, with exit status 2.",
           "The receipt verification function reads the receipt first.",
           "It refuses a key of mixed order, as in N61, at step 11."]
    gone28 = ["already when the Receiver fixes it", "the verdict stays FAIL", "that rule 1 of Section 4.4 rejects"]
    named28 = {v: app.get(v) for v in ("N12", "N18", "N53", "N54", "N61")}

    def class28(k):
        # the key class of that sentence: y-coordinate not below p, or a point of small order (8*A is the neutral
        # element); any other key is of neither
        if k is None or len(k) != 32:
            return "no key"
        if int.from_bytes(k, "little") & ((1 << 255) - 1) >= P:
            return "y not below p"
        pt, _ = decode_point(k)
        return "small order" if pt is not None and is_neutral(scalar_mult(8, pt)) else "neither"
    cls28 = {v: class28(key_from_description(r["vk_desc"], issuer_pub, mixed_pub)) if r is not None else "no vector"
             for v, r in named28.items()}
    keys28 = (all(r is not None and r["expected"] == "FAIL" and r["step"].split()[0] == "11"
                  for r in named28.values())
              and all(cls28[v] in ("y not below p", "small order") for v in ("N12", "N18", "N53", "N54"))
              and cls28["N61"] == "neither")
    chk("Section 11 (rounds 25, 27 and 28): the conformance run of the implementation and the further verifier stand, "
        "the number of vectors they give is that of Appendix A (%d), and the refusal of a key before any receipt is "
        "read is that of the show-eval command, for a key whose y-coordinate is not below p or that is a point of "
        "small order; the vectors it names expect FAIL at step 11, and their keys are of the class it says"
        % len(app),
        all(x in flat25 for x in s25) and len(app) == 66 and not any(x in flat25 for x in gone28) and keys28,
        "missing: " + (", ".join(x[:40] for x in s25 if x not in flat25) or "none")
        + "; still standing: " + (", ".join(x for x in gone28 if x in flat25) or "none")
        + "; keys: " + ", ".join("%s %s" % kv for kv in cls28.items()))
    lines25 = [ln.rstrip() for ln in kept]
    i_ch25 = next((i for i, ln in enumerate(lines25) if ln == "Changes (to be removed before publication)"), None)
    i_last25 = max((i for i, ln in enumerate(lines25) if re.match(r"^A\.2\.\d+\.  ", ln)), default=None)
    i_aa25 = next((i for i, ln in enumerate(lines25) if ln == "Author's Address"), None)
    ch25 = (re.sub(r"\s+", " ", re.sub(r"(?<=\S-)\n\s*(?=\S)", "", "\n".join(lines25[i_ch25:i_aa25])))
            if None not in (i_ch25, i_aa25) else "")
    # Round 27: every point of both subsections, in order; the points are counted
    s25c = {"01": ["Section 1 ends with the scope of this document and its interoperability target.",
                   "Section 6 opens with what PASS does not mean and says that establishing who controls the key is "
                   "outside the procedure.",
                   "The security considerations of Section 10.1 also refer to [RFC8259] Section 12.",
                   "Section 11 adds the conformance run of the implementation named there, at commit a339424e, on the "
                   "vectors of Appendix A, and the result of a further verifier written from the text. It also limits "
                   "the description of key rejection before reading a receipt to the command-line interface.",
                   "The Open Items section is removed. The references were checked against the published documents on "
                   "2026-10-12, and Section 11 now gives the conformance result it asked for.",
                   "This appendix is added."],
            "00": ["Section 1 names the two parties the format serves, an Issuer and a Receiver that share no "
                   "infrastructure, and says why the receipt object stands next to the DSSE-compatible signature.",
                   "Section 3.2 states that the vectors of this version are maintained in Appendix A and that a later "
                   "version of the format uses a different identifier with its own vectors.",
                   "Section 6 adds that a receipt does not show where B came from.",
                   "Section 8 adds that criteria_digest binds bytes, not a time, and carries weight only against "
                   "criteria bytes the Receiver obtained independently.",
                   "Section 10.1 writes out the security considerations of the registration template and names "
                   "contact, author and change controller.",
                   "Section 11 adds a local measurement on 2026-10-10 of a receipt made from the result of a test run."]}
    h01 = ch25.find("Since draft-gruszka-signed-evaluation-receipts-01")
    h00 = ch25.find("Since draft-gruszka-signed-evaluation-receipts-00")
    got25 = {"01": [b.strip() for b in ch25[h01:h00 if h00 > h01 else None].split(" * ")[1:]] if h01 > -1 else [],
             "00": [b.strip() for b in ch25[h00:].split(" * ")[1:]] if -1 < h01 < h00 else []}
    chk("Revision -02 (rounds 25 and 27): the name is draft-gruszka-signed-evaluation-receipts-02, no Open Items stand, "
        "and the unnumbered appendix of changes follows Appendix A with the points since -01 (%d) and since -00 (%d), "
        "each as written, in that order" % (len(got25["01"]), len(got25["00"])),
        any(ln.strip() == "draft-gruszka-signed-evaluation-receipts-02" for ln in lines25)
        and not any(ln.strip().startswith("Open Items") for ln in lines25)
        and None not in (i_ch25, i_last25, i_aa25) and i_last25 < i_ch25 < i_aa25 and got25 == s25c,
        "differing points: " + (", ".join("%s %d" % (k, i + 1) for k in s25c for i in range(max(len(s25c[k]),
                                len(got25[k]))) if s25c[k][i:i + 1] != got25[k][i:i + 1]) or "none"))
    # Round 17: SHA-256 at its first use, and RFC 6234 among the normative references.
    sha17 = "SHA-256 is the hash function specified in [RFC6234]."
    i33 = next((i for i, ln in enumerate(lines15) if ln == "3.3.  Salted Commitments"), None)
    i34 = next((i for i, ln in enumerate(lines15) if ln.startswith("3.4.  ")), None)
    i1 = next((i for i, ln in enumerate(lines15) if ln == "1.  Introduction"), None)
    first_sha = next((i for i in range(i1 or 0, len(lines15)) if "SHA-256" in lines15[i]), None)
    s33 = re.sub(r"\s+", " ", " ".join(lines15[i33 + 1:i34])) if i33 is not None and i34 is not None else ""
    chk("3.3 (round 17): the first use of SHA-256 in the body is in 3.3, and the sentence on RFC 6234 follows it "
        "there, right after 'There is no separator and no length prefix.'",
        i33 is not None and first_sha is not None and i33 < first_sha < i34
        and ("There is no separator and no length prefix. " + sha17) in s33 and flat12.count(sha17) == 1,
        "first SHA-256 at text line %s, 3.3 spans %s to %s" % (first_sha, i33, i34))
    in_ = next((i for i, ln in enumerate(lines15) if re.match(r"^\d+\.1\.  Normative References$", ln)), None)
    ii_ = next((i for i, ln in enumerate(lines15) if re.match(r"^\d+\.2\.  Informative References$", ln)), None)
    norm17 = re.sub(r"\s+", " ", " ".join(lines15[in_ + 1:ii_])) if in_ is not None and ii_ is not None else ""
    chk("References (round 17): [RFC6234] is a normative reference, 'US Secure Hash Algorithms (SHA and SHA-based "
        "HMAC and HKDF)', RFC 6234, May 2011",
        "[RFC6234] Eastlake 3rd, D. and T. Hansen, \"US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)\", "
        "RFC 6234, May 2011, <https://www.rfc-editor.org/info/rfc6234>." in norm17, norm17[norm17.find("[RFC6234]"):][:160])
    iA = next((i for i, ln in enumerate(lines15) if ln == "Appendix A.  Test Vectors"), None)
    iA1 = next((i for i, ln in enumerate(lines15) if ln.startswith("A.1.  ")), None)
    firstA = (re.sub(r"\s+", " ", " ".join(lines15[iA + 1:iA1])).strip()
              if iA is not None and iA1 is not None and iA < iA1 else "")
    labelA = ("Vector identifiers are labels: a P vector expects PASS, an N vector expects FAIL, and gaps in the "
              "numbering carry no meaning.")
    chk("Appendix A (round 16): the label sentence is the first paragraph after the heading",
        firstA.startswith(labelA + " "), firstA[:160])
    # The A.2 headings as extract_appendix read them (wrapped headings joined), in the order of their numbers.
    heads = [(vid, a["expected"]) for vid, a in sorted(app.items(), key=lambda x: x[1]["num"])]
    n_p = sum(1 for vid, _ in heads if vid[0] == "P")
    n_n = sum(1 for vid, _ in heads if vid[0] == "N")
    chk("Appendix A (round 16): every P heading expects PASS and every N heading FAIL, also in Table 2 and as "
        "computed, 10 P and 56 N",
        len(heads) == 66 and n_p == 10 and n_n == 56
        and all((vid[0] == "P") == (exp == "PASS") for vid, exp in heads)
        and all((vid[0] == "P") == (table2[vid]["expected"] == "PASS") for vid, _ in heads)
        and all((v["id"][0] == "P") == (results[v["id"]][0].verdict == "PASS") for v in vectors),
        "%d headings, %d P, %d N" % (len(heads), n_p, n_n))
    want_order = sorted((vid for vid, _ in heads), key=lambda x: (x[0] != "P", int(x[1:])))
    chk("Appendix A.2 and Table 2 (round 16): P vectors by number, then N vectors by number, N61 last",
        [vid for vid, _ in heads] == want_order and want_order[-2:] == ["N60", "N61"] and app["N61"]["num"] == 66
        and list(table2) == want_order, ", ".join(want_order[-3:]))
    toc61 = [ln for ln in lines15 if re.match(r"^ {7}A\.2\.66\. N61 \(mixed-order-key; expected FAIL, step", ln)]
    chk("Table of contents (round 16): A.2.66 is N61, and the identifier P11 stands nowhere in the text",
        len(toc61) == 1 and "P11" not in dtext, toc61[0] if toc61 else "A.2.66 not found")
    pins = [("R1-A8", ["P9"], "the year 0000 (P9)"), ("R1-A7", ["N51"], "ASCII digits (N51)"),
            ("R1-A9'", ["N52"], "a number without a finite double (N52)"),
            ("R1-A2", ["N53", "N54"], "the key before R in rules 1 and 2 (N53, N54)"),
            ("R1-A4", ["N55"], "no number rule at step 1 (N55)")]
    for rid, want, phrase in pins:
        got = moved_by.get(rid)
        chk("Section 5 (round 3): 'P9 and N51 to N55 pin rules that no other vector reaches': %s; reading %s moves %s"
            % (phrase, rid, got), got == sorted(want))
    p6 = next((v for v in vectors if v["id"] == "P6"), None)
    if p6 is not None:
        rec6, _, _ = parse(bytes.fromhex(p6["receipt_hex"]))
        chk("Section 5 (revised): P6 has no key hint (signature members exactly alg, sig)",
            rec6["signature"].names() == {"alg", "sig"})
    for vid, which in (("N17", "R"), ("N18", "key")):
        r, rb, vk = results[vid]
        enc = r.sig[:32] if which == "R" else vk
        lp = decode_point_lenient(enc)
        chk("Section 5/A.2: %s %s fails rule 1, and under y-mod-p decoding is the neutral element (rule 2 would fail)"
            % (vid, which), decode_point(enc)[0] is None and lp is not None and is_neutral(lp))
    # A.2.21/22/23 descriptions
    a, _ = secret_expand(issuer_seed)
    for vid in ("N16", "N17"):
        r, rb, vk = results[vid]
        k = int.from_bytes(hashlib.sha512(r.sig[:32] + vk + pae(PAE_TYPE, r.B)).digest(), "little") % L
        chk("A.2 %s: S = k*a mod L with the issuer's secret scalar" % vid, int.from_bytes(r.sig[32:], "little") == (k * a) % L)
    r, rb, vk = results["N12"]
    chk("A.2 N12: R = S*B'", encode_point(scalar_mult(int.from_bytes(r.sig[32:], "little"), BASE)) == r.sig[:32])
    r, rb, vk = results["N18"]
    chk("A.2 N18: R = r*B' and S = r", encode_point(scalar_mult(int.from_bytes(r.sig[32:], "little"), BASE)) == r.sig[:32])
    r6, _, _ = results["N6"]
    r1, _, _ = results["P1"]
    chk("A.2 N6: R equals P1's R and S = S(P1) + L",
        r6.sig[:32] == r1.sig[:32] and int.from_bytes(r6.sig[32:], "little") == int.from_bytes(r1.sig[32:], "little") + L)
    print()

    # ---------------- probes for rules the vectors do not exercise
    print("PROBES (receipts built here from the A.1 test material and P1's B, validly signed with the issuer")
    print("        seed over PAE(type, B'); informational, not counted in the match total)")
    p1B = bytes.fromhex(next(v for v in vectors if v["id"] == "P1")["payload_hex"])
    p1R = bytes.fromhex(next(v for v in vectors if v["id"] == "P1")["receipt_hex"])

    def build(B, sig=None, key_hint=True, tail=b"", schema=None):
        if sig is None:
            sig = ed25519_sign(issuer_seed, pae(PAE_TYPE, B))
        sgm = [("alg", SIG_ALG)] + ([("key", b64(issuer_pub))] if key_hint else []) + [("sig", b64(sig))]
        rec = JObj([("schema", schema if schema is not None else RECEIPT_SCHEMA), ("payload_b64", b64(B)),
                    ("signature", JObj(sgm))])
        return jcs_bytes(rec) + tail

    def deep(open_, n):
        """n nested arrays, or n nested objects with the one member name "a"."""
        if open_ == "[":
            return b"[" * n + b"]" * n
        return b'{"a":' * (n - 1) + b"{}" + b"}" * (n - 1)

    def rep(old, new, data=p1B):
        assert data.count(old) == 1, old
        return data.replace(old, new)

    n18_key = b"\xee" + b"\xff" * 30 + b"\x7f"
    n17_R = results["N17"][0].sig[:32]
    neutral = b"\x01" + b"\x00" * 31
    a_issuer, _ = secret_expand(issuer_seed)
    # Each probe: (id, description, receipt bytes, key, alternative readings, what the revised text says)
    probes = [
        ("Q0", "P1 rebuilt from its B and the issuer seed", build(p1B), issuer_pub, [], "PASS/all"),
        ("Q1", "n written 9007199254740993 (rounds to 2^53 as a double)",
         build(rep(b'"n":1800', b'"n":9007199254740993')), issuer_pub,
         [("R1-A3", Reading(inexact_number_fails_step4=True))], "FAIL/5 -- 3.4, step 4"),
        ("Q2", "n written 1e400 (no finite double) [now vector N52]", build(rep(b'"n":1800', b'"n":1e400')), issuer_pub,
         [("R1-A9'", Reading(overflow_fails_step4=True)), ("R4-A12", Reading(nearest_finite_double=True))], "FAIL/5 -- step 4: 'such as 1e400, fails step 5'"),
        ("Q2b", "n written 1e-400 (underflows to 0)", build(rep(b'"n":1800', b'"n":1e-400')), issuer_pub,
         [], "FAIL/5 -- 0 has a finite double; not its own serialization"),
        ("Q3", "n written 1.0 (Section 3.4 example)", build(rep(b'"n":1800', b'"n":1.0')), issuer_pub, [], "FAIL/5 -- 3.4"),
        ("Q4", "n written 1e0 (Section 3.4 example)", build(rep(b'"n":1800', b'"n":1e0')), issuer_pub, [], "FAIL/5 -- 3.4"),
        ("Q5", "n = 9007199254740992 = 2^53 (canonical, out of range; as N50)",
         build(rep(b'"n":1800', b'"n":9007199254740992')), issuer_pub, [], "FAIL/6 -- Table 1"),
        ("Q6", "key = y=p+1 encoding (as N18) and R = y=p+1 encoding (as N17): both fail rule 1 [now vector N53]",
         build(p1B, sig=n17_R + (1).to_bytes(32, "little"), key_hint=False), n18_key,
         [("R1-A2", Reading(profile_r_before_key=True))], "FAIL/11 (profile 1, key) -- 4.4 'the key before R'"),
        ("Q7", "key = neutral element and R = neutral element, S = 0: both fail rule 2 [now vector N54]",
         build(p1B, sig=neutral + bytes(32), key_hint=False), neutral, [("R1-A2", Reading(profile_r_before_key=True))],
         "FAIL/11 (profile 2, key) -- 4.4"),
        ("Q8", "model_id_commit with uppercase hex digits",
         build(rep(b"904de42562f9a19651e19eb7ab165e4ffe114ce5a2f98e57da5838959684fb0f",
                   b"904DE42562F9A19651E19EB7AB165E4FFE114CE5A2F98E57DA5838959684FB0F")), issuer_pub,
         [("R1-A1", Reading(commit_pattern_in_step6=True))], "FAIL/7 -- 3.2"),
        ("Q9", "receipt schema written as the number 1e400 [now vector N55]",
         rep(b'"schema":"' + RECEIPT_SCHEMA.encode() + b'"', b'"schema":1e400', build(p1B)), issuer_pub,
         [("R1-A4", Reading(receipt_number_range_step1=True))], "FAIL/2 -- 3.1 'fails the step that checks that member'"),
        ("Q10", "timestamp 0000-02-29T00:00:00Z [now vector P9]", build(rep(b"2026-10-02T00:00:00Z", b"0000-02-29T00:00:00Z")),
         issuer_pub, [("R1-A8", Reading(calendar_no_year0=True))], "PASS/all -- 3.2 'the year 0000 exists and is a leap year'"),
        ("Q10b", "timestamp 1900-02-29T00:00:00Z (not a leap year)",
         build(rep(b"2026-10-02T00:00:00Z", b"1900-02-29T00:00:00Z")), issuer_pub, [], "FAIL/6"),
        ("Q11", "score 0.834 with ARABIC-INDIC digits (U+0668 U+0663 U+0664) after the full stop [now vector N51]",
         build(rep(b'"score":"0.834"', '"score":"0.\u0668\u0663\u0664"'.encode())), issuer_pub,
         [("R1-A7", Reading(unicode_digits=True))], "FAIL/6 -- 3.2 'no other Unicode digit counts'"),
        ("Q12", "P1 receipt bytes followed by a newline (insignificant whitespace)", p1R + b"\n", issuer_pub, [],
         "PASS/all -- 3.1"),
        ("Q13", "signature.sig in base64 without padding", None, issuer_pub, [], "FAIL/9 -- 3.1 'as for payload_b64'"),
        ("Q13b", "signature.sig in the base64url alphabet ('-' and '_')", "url", issuer_pub, [], "FAIL/9 -- 3.1"),
        ("Q14", "score -0 >= threshold 0, passed true (exact decimal comparison)",
         build(rep(b'"score":"0.834"', b'"score":"-0"', rep(b'"threshold":"0.800"', b'"threshold":"0"'))),
         issuer_pub, [], "PASS/all -- 3.2 exact decimal numbers"),
        ("Q15", "receipt top-level value is an array holding P1's object", b"[" + p1R + b"]", issuer_pub, [],
         "FAIL/1 -- step 1 'a top-level value that is not an object'"),
        ("Q17", "n written 0.1 (its own RFC 8785 form, but not exactly a double)",
         build(rep(b'"n":1800', b'"n":0.1')), issuer_pub,
         [("R1-A3", Reading(inexact_number_fails_step4=True)), ("W7", Reading(w_raw_number_tokens=True))],
         "FAIL/6 -- step 5 passes, n is not an integer"),
        ("Q18", "n written 1.0 under W7 (Section 3.4 example)", build(rep(b'"n":1800', b'"n":1.0')), issuer_pub,
         [("W7", Reading(w_raw_number_tokens=True)), ("W7b", Reading(w_raw_number_tokens=True, w_n_by_value=True))],
         "FAIL/5 -- 3.4"),
        ("Q16", "signature.sig given as the number 1e400", None, issuer_pub, [],
         "FAIL/9 -- 3.1 'fails the step that checks that member'"),
        ("Q19", "B of P1 after one line feed (0a), signed anew (round 14)", build(b"\n" + p1B), issuer_pub,
         [("M-P13", Reading(leading_ws_is_data=True))],
         "FAIL/5 -- step 4 admits whitespace before the JSON text, B is not its own RFC 8785 serialization"),
        # Round 22: Section 5, a resource-limit error is neither PASS nor FAIL; MAX_DEPTH levels are read
        ("Q20", "receipt: arrays 60000 deep", deep("[", 60000), issuer_pub, [],
         "RESOURCE_LIMIT/1 -- 5 'a resource-limit error; that is neither PASS nor the FAIL of one of the steps'"),
        ("Q21", "receipt: objects 30000 deep", deep("{", 30000), issuer_pub, [], "RESOURCE_LIMIT/1 -- 5"),
        ("Q22", "B: arrays 60000 deep, signed", build(deep("[", 60000)), issuer_pub, [], "RESOURCE_LIMIT/4 -- 5"),
        ("Q23", "B: objects 30000 deep, signed", build(deep("{", 30000)), issuer_pub, [], "RESOURCE_LIMIT/4 -- 5"),
        ("Q24", "receipt: arrays %d deep (the limit), read" % MAX_DEPTH, deep("[", MAX_DEPTH), issuer_pub, [],
         "FAIL/1 -- the top-level value is not an object"),
        ("Q25", "receipt: arrays %d deep (the limit + 1)" % (MAX_DEPTH + 1), deep("[", MAX_DEPTH + 1), issuer_pub, [],
         "RESOURCE_LIMIT/1 -- 5"),
        ("Q26", "B: objects %d deep (the limit), read, signed" % MAX_DEPTH, build(deep("{", MAX_DEPTH)), issuer_pub,
         [], "FAIL/6 -- the members are not those of Table 1"),
        ("Q27", "B: objects %d deep (the limit + 1), signed" % (MAX_DEPTH + 1), build(deep("{", MAX_DEPTH + 1)),
         issuer_pub, [], "RESOURCE_LIMIT/4 -- 5"),
        # Round 23: the byte order mark and UTF-8 before the depth, as in the receipts draft's checker
        ("Q28", "receipt: a byte order mark, then arrays %d deep" % (MAX_DEPTH + 1),
         b"\xef\xbb\xbf" + deep("[", MAX_DEPTH + 1), issuer_pub, [],
         "FAIL/1 -- 3.1 no byte order mark, judged before the depth as check_receipts does"),
        ("Q29", "receipt: arrays %d deep with one byte ff inside" % (MAX_DEPTH + 1),
         b"[" * (MAX_DEPTH + 1) + b"\xff" + b"]" * (MAX_DEPTH + 1), issuer_pub, [],
         "FAIL/1 -- 3.1 UTF-8, judged before the depth as check_receipts does"),
        ("Q30", "B: a byte order mark, then arrays %d deep, signed" % (MAX_DEPTH + 1),
         build(b"\xef\xbb\xbf" + deep("[", MAX_DEPTH + 1)), issuer_pub, [], "FAIL/4 -- as Q28, at step 4"),
        ("Q31", "B: arrays %d deep with one byte ff inside, signed" % (MAX_DEPTH + 1),
         build(b"[" * (MAX_DEPTH + 1) + b"\xff" + b"]" * (MAX_DEPTH + 1)), issuer_pub, [], "FAIL/4 -- as Q29, at step 4"),
        # Round 24: the size limit; P1 followed by whitespace, which the text allows around a JSON text
        ("Q32", "P1 receipt followed by whitespace up to %d bytes (the limit)" % MAX_INPUT_BYTES,
         p1R + b" " * (MAX_INPUT_BYTES - len(p1R)), issuer_pub, [], "PASS/all -- 3.1, as Q12"),
        ("Q33", "P1 receipt followed by whitespace up to %d bytes (the limit + 1)" % (MAX_INPUT_BYTES + 1),
         p1R + b" " * (MAX_INPUT_BYTES + 1 - len(p1R)), issuer_pub, [],
         "RESOURCE_LIMIT/1 -- 8 'Oversized inputs ... can exhaust memory or processing time'"),
    ]
    sig_p1 = ed25519_sign(issuer_seed, pae(PAE_TYPE, p1B))
    q13 = p1R.replace(b64(sig_p1).encode(), b64(sig_p1).rstrip("=").encode())
    assert q13 != p1R
    # a signature whose standard base64 contains '+' or '/', re-encoded with '-' and '_'
    q13b = None
    for i in range(64):
        Bi = rep(b'"suite":"acme-safety-suite"', ('"suite":"acme-safety-suite-%d"' % i).encode())
        si = ed25519_sign(issuer_seed, pae(PAE_TYPE, Bi))
        if "+" in b64(si) or "/" in b64(si):
            r_i = build(Bi, sig=si)
            q13b = r_i.replace(b64(si).encode(), base64.urlsafe_b64encode(si))
            break
    assert q13b is not None
    q16 = p1R.replace(b'"' + b64(sig_p1).encode() + b'"', b"1e400")
    assert q16 != p1R
    probes = [(a, b, {None: (q16 if a == "Q16" else q13), "url": q13b}.get(c, c) if not isinstance(c, bytes) else c,
               d, e, f) for (a, b, c, d, e, f) in probes]
    probe_ok = 0
    for qid, desc, data, key, alts_q, says in probes:
        r = verify(data, key)
        extra = ""
        for an, rd in alts_q:
            r2 = verify(data, key, rd)
            extra += "; under %s: %s/%s" % (an, r2.verdict, r2.label())
        got = "%s/%s" % (r.verdict, r.label())
        agree = says.split(" -- ")[0] == got
        probe_ok += agree
        note = " (bytes equal to P1 receipt: %s)" % ("yes" if data == p1R else "no") if qid == "Q0" else ""
        print("  %-5s %-84s -> %s%s%s" % (qid, desc, got, extra, note))
        print("        text says: %s  [%s]" % (says, "agrees" if agree else "DIFFERS"))
        if r.reason:
            print("        reason: %s" % r.reason)
    print("  probes whose result agrees with what the revised text says: %d of %d" % (probe_ok, len(probes)))
    import math
    lo = math.nextafter(0.1, 0.0)
    print("  rounding (step 4 'read as an IEEE 754 double', direction not stated): 0.1 rounds to nearest %s,"
          " toward zero %s; RFC 8785 form %s vs %s" % (repr(0.1), repr(lo), es_number(0.1), es_number(lo)))
    print()

    # ---------------- summary
    n_ok = sum(1 for v in vectors if results[v["id"]][0].verdict == v["expected"] and results[v["id"]][0].label() == v["step"])
    n_verdict = sum(1 for v in vectors if results[v["id"]][0].verdict == v["expected"])
    print("SUMMARY")
    print("  self-tests: %d ok, %d failed" % (sum(1 for _, o in st if o), sum(1 for _, o in st if not o)))
    print("  consistency and claim checks: %d ok, %d mismatch" % (checks.count(True), checks.count(False)))
    print("  verdict matches: %d of %d" % (n_verdict, len(vectors)))
    print("MATCH (verdict and step): %d of %d; mismatches: %s"
          % (n_ok, len(vectors), ("; ".join("%s computed %s expected %s" % m for m in mismatches) if mismatches else "none")))
    # Revision -01 (card DRAFTS-01-INHALT-01): the exit code also carries the self-tests, the consistency and
    # claim checks and the probes; before, only the vector verdicts set it, so a claim mismatch exited 0.
    ok = (n_ok == len(vectors) and all(o for _, o in st) and all(checks) and probe_ok == len(probes))
    print("EXIT: %d (vectors, self-tests, claim checks and probes all hold: %s)" % (0 if ok else 1, ok))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
