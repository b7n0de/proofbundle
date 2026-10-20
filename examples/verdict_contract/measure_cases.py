"""Measure the byte-binding trap as cases: per case the reply digest, find_verdict on the raw bytes,
the offline check against a receipt issued over exactly these bytes, the offline check of these
bytes against the baseline receipt, and what find_verdict says after common normalizations.

    python measure_cases.py
"""
import contextlib
import hashlib
import io
import shutil
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_example  # noqa: E402
import make_example  # noqa: E402
import verdict_contract as vc  # noqa: E402

BODY = b"Reviewed calc.py.\n\nNo MED or HIGH issues: sub mirrors add and has no side effects.\n\n"
CASES = [
    ("LF (baseline)", BODY + b"===VERDICT=== APPROVE\n"),
    ("CRLF", (BODY + b"===VERDICT=== APPROVE\n").replace(b"\n", b"\r\n")),
    ("blank line at the end", BODY + b"===VERDICT=== APPROVE\n\n"),
    ("spaces at the end", BODY + b"===VERDICT=== APPROVE   \n"),
    ("APPROVE in a closed fence, fence on the last line", BODY + b"```\n===VERDICT=== APPROVE\n```\n"),
    ("APPROVE in an unclosed fence on the last line", BODY + b"```\n===VERDICT=== APPROVE\n"),
    ("two APPROVE sentinels", b"===VERDICT=== APPROVE\n\n" + BODY + b"===VERDICT=== APPROVE\n"),
    ("REQUEST_CHANGES quoted", b"> ===VERDICT=== REQUEST_CHANGES\n> (from the previous round)\n\n"
                               + BODY + b"===VERDICT=== APPROVE\n"),
    # Beyond the six requested forms: line breaks that str.splitlines knows and a byte reader may not.
    ("additional: lone CR before the sentinel", BODY.rstrip(b"\n") + b"\r===VERDICT=== APPROVE\n"),
    ("additional: U+2028 before the sentinel", BODY.rstrip(b"\n") + " ".encode() + b"===VERDICT=== APPROVE\n"),
]


def _crlf_to_lf(b):
    return b.replace(b"\r\n", b"\n")


def _strip_line_ends(b):
    return b"".join(line.rstrip(b" \t\r\n") + (b"\n" if line.endswith(b"\n") else b"")
                    for line in b.splitlines(keepends=True))


def _strip_trailing_blank_lines(b):
    return b.rstrip(b"\r\n \t") + b"\n"


def _drop_cr(b):
    return b.replace(b"\r", b"")


def _nfc(b):
    return unicodedata.normalize("NFC", b.decode("utf-8")).encode("utf-8")


NORMALIZATIONS = [("CRLF->LF", _crlf_to_lf), ("strip line ends", _strip_line_ends),
                  ("strip trailing blank lines", _strip_trailing_blank_lines),
                  ("drop CR", _drop_cr), ("NFC", _nfc)]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def quiet(fn, *a):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()


def main() -> int:
    work = HERE / "cases"
    if work.exists():
        raise SystemExit(f"{work} exists, refusing to overwrite; move it away first")
    baseline = HERE / "out"
    rows = []
    for i, (name, raw) in enumerate(CASES):
        d = work / f"case{i:02d}"
        d.mkdir(parents=True)
        (d / "reply.in").write_bytes(raw)
        verdict = vc.find_verdict(raw.decode("utf-8"))
        rc_make, _ = quiet(make_example.main, ["--reply", str(d / "reply.in"), "--out", str(d / "out"),
                                               "--key", str(HERE / "example.key"),
                                               "--declared-at", "2026-10-11T08:30:00Z"])
        rc_own, _ = quiet(check_example.main, d / "out")
        cross = d / "cross"
        shutil.copytree(baseline, cross, ignore=shutil.ignore_patterns("toyrepo"))
        (cross / "reply.txt").write_bytes(raw)
        rc_cross, out_cross = quiet(check_example.main, cross)
        failed = [line[6:] for line in out_cross.splitlines() if line.startswith("FAIL")]
        norm = []
        for nname, fn in NORMALIZATIONS:
            nb = fn(raw)
            nv = vc.find_verdict(nb.decode("utf-8"))
            norm.append(f"{nname}: {'same bytes' if nb == raw else 'other bytes'}, "
                        f"{nv}{' (CHANGED)' if nv != verdict else ''}")
        rows.append((name, sha(raw), len(raw), verdict, vc.exit_code(verdict), rc_make, rc_own,
                     rc_cross, failed, norm))
    for r in rows:
        print(f"## {r[0]}\n- reply sha256 {r[1]} ({r[2]} bytes)\n- find_verdict {r[3]}, exit_code {r[4]}"
              f"\n- receipt over these bytes: make rc {r[5]}, offline check rc {r[6]}"
              f"\n- these bytes against the baseline receipt: offline check rc {r[7]}"
              + (f", failed: {r[8]}" if r[8] else "")
              + "\n- after normalization: " + "; ".join(r[9]) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
