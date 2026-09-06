"""Dependency-free reader for the pcapng capture format.

pcapng is what Wireshark and tshark write by default, so supporting it is what
lets athar ingest real-world evidence rather than only legacy ``.pcap``. Only the
blocks needed to recover timestamped link-layer frames are interpreted -- the
Section Header, Interface Description, Enhanced Packet and Simple Packet blocks;
anything else is skipped by block length. Frames are yielded as the same
:class:`~athar.pcap.Frame` the classic reader produces, so decoding is shared.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from .pcap import Frame, PcapError

_SHB = 0x0A0D0D0A   # Section Header Block (also the file magic)
_IDB = 0x00000001   # Interface Description Block
_SPB = 0x00000003   # Simple Packet Block
_EPB = 0x00000006   # Enhanced Packet Block
_BYTE_ORDER_MAGIC = 0x1A2B3C4D


class _Interface:
    __slots__ = ("link_type", "tsdiv")

    def __init__(self, link_type: int, tsdiv: float) -> None:
        self.link_type = link_type
        self.tsdiv = tsdiv  # divisor turning the raw 64-bit stamp into seconds


def read_frames(path: str | Path) -> Iterator[Frame]:
    """Yield every packet in a pcapng file as a :class:`Frame`, streaming from disk.

    Blocks are read one at a time rather than loading the whole file, so memory
    stays flat regardless of capture size.
    """
    with open(path, "rb") as fh:
        first = fh.read(4)
        if len(first) < 4 or struct.unpack("<I", first)[0] != _SHB:
            raise PcapError("not a pcapng file (missing section header)")
        fh.seek(0)

        interfaces: list[_Interface] = []
        index, endian = 0, "<"
        while True:
            type_len = fh.read(8)
            if len(type_len) < 8:
                break
            block_type = struct.unpack(endian + "I", type_len[:4])[0]
            # An SHB restarts the section and re-fixes endianness; read its
            # length in native order first, then confirm the byte-order magic.
            if block_type == _SHB:
                rest = fh.read(4)
                if len(rest) < 4:
                    break
                endian = "<" if struct.unpack("<I", rest)[0] == _BYTE_ORDER_MAGIC else ">"
                block_len = struct.unpack(endian + "I", type_len[4:8])[0]
                remaining = fh.read(block_len - 12)
                if len(remaining) < block_len - 12:
                    break
                interfaces = []
                continue

            block_len = struct.unpack(endian + "I", type_len[4:8])[0]
            if block_len < 12:
                break
            body_and_trailer = fh.read(block_len - 8)
            if len(body_and_trailer) < block_len - 8:
                break  # truncated trailing block
            body = body_and_trailer[:-4]  # drop the redundant trailing length

            if block_type == _IDB:
                interfaces.append(_read_idb(body, endian))
            elif block_type == _EPB:
                frame = _read_epb(body, endian, interfaces, index)
                if frame is not None:
                    yield frame
                    index += 1
            elif block_type == _SPB:
                frame = _read_spb(body, interfaces, index)
                if frame is not None:
                    yield frame
                    index += 1


def _read_idb(body: bytes, endian: str) -> _Interface:
    link_type = struct.unpack(endian + "H", body[0:2])[0]
    tsdiv = _timestamp_divisor(body[8:], endian)
    return _Interface(link_type, tsdiv)


def _timestamp_divisor(options: bytes, endian: str) -> float:
    """Read the if_tsresol option (code 9); default is microseconds."""
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos:pos + 4])
        pos += 4
        if code == 0:  # opt_endofopt
            break
        if code == 9 and length >= 1:  # if_tsresol
            resol = options[pos]
            if resol & 0x80:
                return float(1 << (resol & 0x7F))       # 2^-n seconds
            return float(10 ** resol)                    # 10^-n seconds
        pos += length + (-length % 4)                    # options are 32-bit padded
    return 1_000_000.0


def _read_epb(body: bytes, endian: str, interfaces: list[_Interface], index: int) -> Frame | None:
    if len(body) < 20:
        return None
    iface_id, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[0:20])
    if 20 + caplen > len(body):
        return None
    iface = interfaces[iface_id] if iface_id < len(interfaces) else _Interface(1, 1_000_000.0)
    ts = ((ts_hi << 32) | ts_lo) / iface.tsdiv
    return Frame(index=index, ts=ts, link_type=iface.link_type, data=body[20:20 + caplen])


def _read_spb(body: bytes, interfaces: list[_Interface], index: int) -> Frame | None:
    # Simple packets carry no timestamp and assume the first interface.
    if not interfaces or len(body) < 4:
        return None
    return Frame(index=index, ts=0.0, link_type=interfaces[0].link_type, data=body[4:])
