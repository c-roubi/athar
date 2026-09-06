"""Dependency-free reader for classic pcap capture files.

Only the classic ``.pcap`` format is handled here (magic ``0xA1B2C3D4`` in
either byte order). It is deliberately small: it yields raw link-layer frames
with their timestamps and leaves all protocol decoding to :mod:`athar.decode`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond-precision variant


@dataclass(frozen=True)
class Frame:
    """A single captured link-layer frame."""

    index: int
    ts: float          # capture time, seconds since epoch
    link_type: int     # DLT_* value from the file header
    data: bytes        # raw frame bytes (truncated to the on-disk snap length)


class PcapError(ValueError):
    """Raised when a file is not a well-formed classic pcap capture."""


def read_frames(path: str | Path) -> Iterator[Frame]:
    """Yield every :class:`Frame` in *path* in capture order, streaming from disk.

    The file is read record by record rather than loaded whole, so memory stays
    flat regardless of capture size. Raises :class:`PcapError` if the global
    header is missing or malformed; a truncated trailing record is ignored rather
    than fatal, so a capture cut off mid-write still yields everything before the
    break.
    """
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise PcapError("file is too short to contain a pcap header")

        (magic,) = struct.unpack("<I", header[:4])
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian, nano = "<", magic == PCAP_MAGIC_NS_LE
        elif magic == PCAP_MAGIC_BE:
            endian, nano = ">", False
        else:
            raise PcapError(f"unrecognised pcap magic 0x{magic:08X}")

        link_type = struct.unpack(endian + "I", header[20:24])[0]
        divisor = 1_000_000_000 if nano else 1_000_000
        rec_hdr = struct.Struct(endian + "IIII")

        index = 0
        while True:
            head = fh.read(16)
            if len(head) < 16:
                break  # clean end of file, or a truncated record header
            ts_sec, ts_frac, caplen, _origlen = rec_hdr.unpack(head)
            data = fh.read(caplen)
            if len(data) < caplen:
                break  # truncated final record
            yield Frame(
                index=index,
                ts=ts_sec + ts_frac / divisor,
                link_type=link_type,
                data=data,
            )
            index += 1
