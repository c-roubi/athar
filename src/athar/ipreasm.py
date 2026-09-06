"""IPv4 fragment reassembly.

A single IP datagram can be split across several frames; only the first carries
the L4 header, so a naive per-frame decoder mis-reads the rest. This reassembles
fragments (keyed by src/dst/id/proto) into the original datagram before decoding,
matching what Wireshark does with "Reassemble fragmented IPv4 datagrams".

It runs as a streaming pre-pass over Ethernet frames: complete or unfragmented
datagrams pass straight through; fragments are buffered until the datagram is
whole, then emitted as one rebuilt frame. Incomplete datagrams are simply never
emitted (as a real stack would eventually time them out), bounded by a cap.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

_DLT_EN10MB = 1
_ETH_IP4 = 0x0800
_MAX_DATAGRAM = 1 << 16   # IPv4 datagrams can't exceed 65535 bytes
_MAX_PENDING = 4096       # cap concurrently-reassembling datagrams


class _Pending:
    __slots__ = ("l2l3", "frags", "total")

    def __init__(self, l2l3: bytes) -> None:
        self.l2l3 = l2l3            # ethernet + IPv4 header of the first fragment
        self.frags: dict[int, bytes] = {}
        self.total: int | None = None   # known once the last fragment arrives


def _ip_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


class IPReassembler:
    """Streaming IPv4 defragmenter over Ethernet frames."""

    def __init__(self) -> None:
        self._pending: dict[tuple[bytes, bytes, int, int], _Pending] = {}

    def process(self, link_type: int, frame: bytes) -> Iterator[bytes]:
        """Yield zero or more complete frames for one input frame."""
        if link_type != _DLT_EN10MB or len(frame) < 34 or \
                struct.unpack("!H", frame[12:14])[0] != _ETH_IP4:
            yield frame
            return
        ihl = (frame[14] & 0x0F) * 4
        if ihl < 20 or len(frame) < 14 + ihl:
            yield frame
            return

        flags_frag = struct.unpack("!H", frame[20:22])[0]
        mf = bool(flags_frag & 0x2000)
        offset = (flags_frag & 0x1FFF) * 8
        if not mf and offset == 0:
            yield frame          # not fragmented
            return

        ident = struct.unpack("!H", frame[18:20])[0]
        proto = frame[23]
        src, dst = frame[26:30], frame[30:34]
        key = (src, dst, ident, proto)
        payload = frame[14 + ihl:]

        pend = self._pending.get(key)
        if pend is None:
            if len(self._pending) >= _MAX_PENDING:
                yield frame      # overloaded: don't buffer, pass through
                return
            pend = self._pending[key] = _Pending(frame[:14 + ihl] if offset == 0 else b"")
        if offset == 0 and not pend.l2l3:
            pend.l2l3 = frame[:14 + ihl]
        pend.frags[offset] = payload
        if not mf:
            pend.total = offset + len(payload)

        rebuilt = self._try_complete(key, pend)
        if rebuilt is not None:
            yield rebuilt

    def _try_complete(self, key: tuple[bytes, bytes, int, int], pend: _Pending) -> bytes | None:
        if pend.total is None or not pend.l2l3:
            return None
        # Walk the fragments in order; bail if there's a gap.
        data = bytearray()
        for off in sorted(pend.frags):
            if off > len(data):
                return None      # gap — still waiting
            chunk = pend.frags[off]
            if off + len(chunk) > len(data):
                data.extend(chunk[len(data) - off:])
        if len(data) < pend.total:
            return None
        del self._pending[key]

        eth = pend.l2l3[:14]
        iphdr = bytearray(pend.l2l3[14:])
        struct.pack_into("!H", iphdr, 2, len(iphdr) + len(data))  # total length
        struct.pack_into("!H", iphdr, 6, 0)                       # clear flags/offset
        struct.pack_into("!H", iphdr, 10, 0)                      # zero checksum
        struct.pack_into("!H", iphdr, 10, _ip_checksum(bytes(iphdr)))
        return eth + bytes(iphdr) + bytes(data[:_MAX_DATAGRAM])
