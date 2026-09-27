"""Inflate exactly one complete zlib stream, and nothing after it.

WHY A MODULE FOR FOUR LINES. Two verify surfaces decompress a zlib field: the `pb1.` receipt token
(`hf_evals.verify_receipt_token`) and a status list's `lst` (`statuslist.verify_status_snapshot`).
Both capped the OUTPUT (a decompression bomb) and neither asked whether the stream had ended, or
whether bytes followed it. Measured by the deep gate against main 5b53ab3e (finding
L2-Z195-TOKEN-TRAILING-DATA-01, confirmed 2 of 3): a genuine token with bytes appended after the
end of its zlib stream still verified ok=True, from the library and from `hf-token --verify`, and
12 MiB of them verified in the library while the CLI refused the same token on its input budget.
A decoder that stops at the end of its frame and ignores the rest accepts a form its format does
not define. The same shape stood in `statuslist.py`, so the rule lives here once.

WHAT IT DOES NOT CLAIM. A token or a status list has no single wire form: another zlib level, other
JSON whitespace or key order are other valid encodings of the same content. This refuses bytes
that are not part of the one stream; it does not make the encoding canonical.
"""
from __future__ import annotations

import zlib

__all__ = ["InflateCapExceeded", "inflate_whole_stream"]


class InflateCapExceeded(ValueError):
    """The stream would inflate past the caller's output cap (a decompression bomb, fail-closed)."""


def inflate_whole_stream(data: bytes, max_output: int) -> bytes:
    """The decompressed content of ``data``, which must be ONE complete zlib stream and nothing else.

    Raises :class:`InflateCapExceeded` when the output would pass ``max_output``, ``ValueError`` when
    the stream ends before its end-of-stream marker or when bytes follow that marker, and
    ``zlib.error`` for a stream that is not zlib at all. Callers map all three to their own typed
    verdict; none of them is ever a silent pass."""
    d = zlib.decompressobj()
    # THE ORDER OF THE THREE CHECKS AT THE CAP, measured rather than assumed (2026-09-26, CPython zlib):
    # over 24648 streams whose content is EXACTLY `max_output` bytes (lengths 0..2048 and five larger
    # ones, zeros/random/text, levels 0/1/6/9), `decompress(data, max_output)` always reached the end
    # marker; over 8994 streams one byte OVER the cap (lengths 2..2999, three kinds), `unconsumed_tail`
    # was never empty. So content at the cap is not misread as truncated, and content past it is not
    # misread as complete. A draft gave the call one byte of headroom for the first case; no stream
    # showed a difference, so the headroom was code no test could catch, and it went.
    out = d.decompress(data, max_output)
    if d.unconsumed_tail:
        raise InflateCapExceeded(f"the zlib stream inflates past the {max_output}-byte cap")
    if not d.eof:
        raise ValueError("the zlib stream ends before its end-of-stream marker (truncated)")
    if d.unused_data:
        raise ValueError(f"{len(d.unused_data)} byte(s) follow the end of the zlib stream")
    return out
