"""Backend selection: use the native C++ core when it is built, else pure Python.

Both backends yield identical ``(timestamp, Packet)`` pairs, so the rest of the
pipeline neither knows nor cares which one ran. The native module is optional:
if it was not compiled (no toolchain at install time), everything still works
through the standard-library decoder, just slower.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from . import ipreasm, pcap, pcapng
from .decode import Packet, decode

if TYPE_CHECKING:  # the stub in _core.pyi types the native module for the checker
    from . import _core
    _HAS_NATIVE = True
else:
    try:
        from . import _core
        _HAS_NATIVE = True
    except ImportError:  # native extension not built -- fall back to pure Python
        _core = None
        _HAS_NATIVE = False

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _is_pcapng(path: str | Path) -> bool:
    with open(path, "rb") as fh:
        return fh.read(4) == _PCAPNG_MAGIC


def backend() -> str:
    """Return which decode backend is active: ``"native"`` or ``"python"``."""
    return "native" if _HAS_NATIVE else "python"


def iter_packets(path: str | Path) -> Iterator[tuple[float, Packet]]:
    """Yield ``(timestamp, Packet)`` for every decodable packet in *path*.

    Classic ``.pcap`` uses the native core when available; ``.pcapng`` always
    uses the pure-Python reader (the native core handles only classic pcap).
    """
    if _is_pcapng(path):
        reasm = ipreasm.IPReassembler()
        for frame in pcapng.read_frames(path):
            for whole in reasm.process(frame.link_type, frame.data):
                pkt = decode(whole, frame.link_type)
                if pkt is not None:
                    yield frame.ts, pkt
        return

    if _HAS_NATIVE:
        for row in _core.parse_file(str(path)):
            ts, src_ip, dst_ip, proto, sport, dport, flags, payload, smac, dmac, seq, win, ack = row
            yield ts, Packet(
                src_ip=src_ip, dst_ip=dst_ip, proto=proto,
                src_port=sport, dst_port=dport, payload=payload,
                tcp_flags=flags, seq=seq, ack=ack, window=win, src_mac=smac, dst_mac=dmac,
            )
    else:
        reasm = ipreasm.IPReassembler()
        for frame in pcap.read_frames(path):
            for whole in reasm.process(frame.link_type, frame.data):
                pkt = decode(whole, frame.link_type)
                if pkt is not None:
                    yield frame.ts, pkt
