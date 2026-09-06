"""Benchmark the native C++ core against the pure-Python decoder.

Builds a large capture by repeating the sample scenario, then times a full
decode of every packet with each backend and reports throughput and speed-up.
Run from the project root:

    python benchmarks/bench.py            # ~1M packets
    python benchmarks/bench.py 2000000    # custom packet count
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import make_sample_pcap  # noqa: E402

from athar import decode, pcap  # noqa: E402

try:
    from athar import _core
except ImportError:
    _core = None


def build_capture(target_packets: int, path: Path) -> int:
    """Write a capture of at least *target_packets* packets; return the count."""
    base = make_sample_pcap.build()
    header, body = base[:24], base[24:]
    per_run = _count(base)
    repeats = max(1, target_packets // per_run)
    path.write_bytes(header + body * repeats)
    return per_run * repeats


def _count(blob: bytes) -> int:
    tmp = Path("._count.pcap")
    tmp.write_bytes(blob)
    n = sum(1 for _ in pcap.read_frames(tmp))
    tmp.unlink()
    return n


def time_python(path: Path) -> float:
    start = time.perf_counter()
    n = 0
    for frame in pcap.read_frames(path):
        if decode.decode(frame.data, frame.link_type) is not None:
            n += 1
    return time.perf_counter() - start


def time_native(path: Path) -> float:
    start = time.perf_counter()
    _core.parse_file(str(path))
    return time.perf_counter() - start


def main() -> int:
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    path = Path("._bench.pcap")
    total = build_capture(target, path)
    size_mb = path.stat().st_size / 1_048_576
    print(f"capture: {total:,} packets  ({size_mb:.1f} MB)\n")

    py = time_python(path)
    print(f"  python   {py:6.3f}s   {total / py / 1e6:6.3f} M pkt/s")

    if _core is not None:
        nat = time_native(path)
        print(f"  native   {nat:6.3f}s   {total / nat / 1e6:6.3f} M pkt/s")
        print(f"\n  speed-up: {py / nat:.1f}x")
    else:
        print("  native   (not built)")

    path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
