"""Link- and transport-layer decoding for captured frames.

The decoders return light dataclasses and never raise on malformed input: a
frame that cannot be understood yields ``None`` so one bad packet never aborts
a capture. Ethernet II, IPv4, IPv6 (no extension-header chains), TCP and UDP
are covered -- enough to reconstruct conversations and reach the payload.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# Ethernet link type (DLT_EN10MB) and Linux "cooked" capture (DLT_LINUX_SLL).
DLT_EN10MB = 1
DLT_LINUX_SLL = 113

ETH_IP4 = 0x0800
ETH_IP6 = 0x86DD

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PROTO_ICMP6 = 58

PROTO_NAMES = {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp", PROTO_ICMP6: "icmp6"}


@dataclass(frozen=True)
class Packet:
    """A decoded packet reduced to the fields conversations are keyed on."""

    src_ip: str
    dst_ip: str
    proto: int
    src_port: int         # 0 for protocols without ports
    dst_port: int
    payload: bytes        # transport payload (may be empty)
    tcp_flags: int = 0    # raw TCP flag byte, 0 for non-TCP
    seq: int = 0          # TCP sequence number, 0 for non-TCP
    ack: int = 0          # TCP acknowledgement number, 0 for non-TCP
    window: int = 0       # TCP advertised window size, 0 for non-TCP
    src_mac: str = ""
    dst_mac: str = ""

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.proto, f"ip/{self.proto}")


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def decode(data: bytes, link_type: int) -> Packet | None:
    """Decode one frame into a :class:`Packet`, or ``None`` if unsupported."""
    try:
        if link_type == DLT_EN10MB:
            return _from_ethernet(data)
        if link_type == DLT_LINUX_SLL:
            return _from_sll(data)
    except (struct.error, IndexError, OSError):
        return None
    return None


def _from_ethernet(data: bytes) -> Packet | None:
    if len(data) < 14:
        return None
    dst_mac, src_mac = _mac(data[0:6]), _mac(data[6:12])
    ethertype = struct.unpack("!H", data[12:14])[0]
    return _from_l3(ethertype, data[14:], src_mac, dst_mac)


def _from_sll(data: bytes) -> Packet | None:
    if len(data) < 16:
        return None
    ethertype = struct.unpack("!H", data[14:16])[0]
    return _from_l3(ethertype, data[16:], "", "")


def _from_l3(ethertype: int, rest: bytes, src_mac: str, dst_mac: str) -> Packet | None:
    if ethertype == ETH_IP4:
        return _from_ipv4(rest, src_mac, dst_mac)
    if ethertype == ETH_IP6:
        return _from_ipv6(rest, src_mac, dst_mac)
    return None


def _from_ipv4(data: bytes, src_mac: str, dst_mac: str) -> Packet | None:
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    src_ip = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst_ip = socket.inet_ntop(socket.AF_INET, data[16:20])
    return _from_l4(proto, data[ihl:], src_ip, dst_ip, src_mac, dst_mac)


def _from_ipv6(data: bytes, src_mac: str, dst_mac: str) -> Packet | None:
    if len(data) < 40:
        return None
    next_header = data[6]
    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    return _from_l4(next_header, data[40:], src_ip, dst_ip, src_mac, dst_mac)


def _from_l4(
    proto: int, data: bytes, src_ip: str, dst_ip: str, src_mac: str, dst_mac: str
) -> Packet | None:
    src_port = dst_port = 0
    flags = 0
    seq = 0
    ack = 0
    window = 0
    payload = b""
    if proto == PROTO_TCP and len(data) >= 20:
        src_port, dst_port = struct.unpack("!HH", data[0:4])
        seq = struct.unpack("!I", data[4:8])[0]
        ack = struct.unpack("!I", data[8:12])[0]
        data_offset = (data[12] >> 4) * 4
        flags = data[13]
        window = struct.unpack("!H", data[14:16])[0]
        payload = data[data_offset:] if len(data) >= data_offset else b""
    elif proto == PROTO_UDP and len(data) >= 8:
        src_port, dst_port = struct.unpack("!HH", data[0:4])
        payload = data[8:]
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        tcp_flags=flags,
        seq=seq,
        ack=ack,
        window=window,
        src_mac=src_mac,
        dst_mac=dst_mac,
    )
