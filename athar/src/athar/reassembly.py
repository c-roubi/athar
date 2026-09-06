"""TCP stream reassembly.

Dissecting one packet at a time misses anything that spans segments: an HTTP
request whose headers are split across two packets, a ClientHello that isn't in
the first data segment, or segments that arrive out of order or are retransmitted.
This reconstructs the ordered byte stream for one direction of a connection from
its segments, keyed on the TCP sequence number, so the dissectors see the real
application data.

Sequence numbers are treated modulo 2**32 relative to the first observed segment,
which tolerates the random ISN and wrap-around. Overlapping bytes keep the
earliest copy seen; the contiguous prefix from the start is returned (analysis
stops at the first gap rather than inventing missing bytes).
"""

from __future__ import annotations

_MASK = 0xFFFFFFFF
MAX_STREAM = 8 << 20  # cap per-direction reassembly/buffering at 8 MiB


def reassemble(segments: list[tuple[int, bytes]], cap: int = MAX_STREAM) -> bytes:
    """Reassemble ``(seq, payload)`` segments into one ordered byte stream.

    *cap* bounds the reconstructed length so a malformed or hostile stream can't
    exhaust memory. Returns the contiguous bytes from the stream start.
    """
    data_segs = [(seq, data) for seq, data in segments if data]
    if not data_segs:
        return b""

    # Pick the earliest sequence number in modular space as the stream base, so
    # out-of-order arrival and 32-bit wrap are both handled (the span of one
    # direction is assumed < 2**31, which always holds within a TCP window).
    base = data_segs[0][0]
    for seq, _ in data_segs[1:]:
        if (seq - base) & _MASK >= 0x80000000:  # seq lies before the current base
            base = seq

    # First copy wins at each offset (ignore retransmitted/overlapping duplicates).
    chunks: dict[int, bytes] = {}
    for seq, data in data_segs:
        off = (seq - base) & _MASK
        if off > cap:
            continue
        chunks.setdefault(off, data)

    out = bytearray()
    for off in sorted(chunks):
        if off > len(out):
            break  # a gap -- return what is contiguous so far
        tail = chunks[off][len(out) - off:]  # skip bytes we already have (overlap)
        if tail:
            out.extend(tail)
        if len(out) >= cap:
            return bytes(out[:cap])
    return bytes(out)
