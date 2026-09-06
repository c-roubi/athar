// athar native core: fast pcap decode.
//
// A pybind11 extension that reads a classic pcap file and decodes every frame
// down to the transport layer, returning one tuple per packet. It mirrors the
// semantics of the pure-Python decoder in athar/decode.py exactly, so the two
// backends are interchangeable and verified against each other by the test
// suite. The heavy per-packet work -- byte parsing and address formatting --
// runs entirely in native code, which is where the speed-up comes from.

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace py = pybind11;

namespace {

constexpr uint32_t PCAP_MAGIC_LE = 0xA1B2C3D4u;
constexpr uint32_t PCAP_MAGIC_NS_LE = 0xA1B23C4Du;
constexpr uint32_t PCAP_MAGIC_BE = 0xD4C3B2A1u;

constexpr int DLT_EN10MB = 1;
constexpr int DLT_LINUX_SLL = 113;

constexpr uint16_t ETH_IP4 = 0x0800;
constexpr uint16_t ETH_IP6 = 0x86DD;

constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;

// Read integers in a chosen byte order.
inline uint16_t rd16(const uint8_t* p, bool le) {
    return le ? static_cast<uint16_t>(p[0] | (p[1] << 8))
              : static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t rd32(const uint8_t* p, bool le) {
    return le ? (uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
                 (uint32_t(p[3]) << 24))
              : (uint32_t(p[3]) | (uint32_t(p[2]) << 8) | (uint32_t(p[1]) << 16) |
                 (uint32_t(p[0]) << 24));
}
// Network-order (big-endian) 16-bit: ethertype, ports.
inline uint16_t rd16be(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

std::string mac_str(const uint8_t* p) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  p[0], p[1], p[2], p[3], p[4], p[5]);
    return std::string(buf);
}

std::string ip_str(int family, const uint8_t* p) {
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(family, p, buf, sizeof(buf)) == nullptr) return std::string();
    return std::string(buf);
}

// A decoded packet, matching athar.decode.Packet's fields.
struct Decoded {
    std::string src_ip, dst_ip;
    int proto = 0;
    int src_port = 0, dst_port = 0;
    int tcp_flags = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    int window = 0;
    std::string src_mac, dst_mac;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

// Fill transport fields; always succeeds once we have an L3 packet.
void decode_l4(uint8_t proto, const uint8_t* d, size_t n, Decoded& out) {
    out.proto = proto;
    if (proto == PROTO_TCP && n >= 20) {
        out.src_port = rd16be(d);
        out.dst_port = rd16be(d + 2);
        out.ack = (uint32_t(d[8]) << 24) | (uint32_t(d[9]) << 16) |
                  (uint32_t(d[10]) << 8) | uint32_t(d[11]);
        out.seq = (uint32_t(d[4]) << 24) | (uint32_t(d[5]) << 16) |
                  (uint32_t(d[6]) << 8) | uint32_t(d[7]);
        size_t data_offset = static_cast<size_t>((d[12] >> 4) * 4);
        out.tcp_flags = d[13];
        out.window = rd16be(d + 14);
        if (n >= data_offset) {
            out.payload = d + data_offset;
            out.payload_len = n - data_offset;
        }
    } else if (proto == PROTO_UDP && n >= 8) {
        out.src_port = rd16be(d);
        out.dst_port = rd16be(d + 2);
        out.payload = d + 8;
        out.payload_len = n - 8;
    }
}

bool decode_ipv4(const uint8_t* d, size_t n, Decoded& out) {
    if (n < 20 || (d[0] >> 4) != 4) return false;
    size_t ihl = static_cast<size_t>(d[0] & 0x0F) * 4;
    if (ihl < 20 || n < ihl) return false;
    out.src_ip = ip_str(AF_INET, d + 12);
    out.dst_ip = ip_str(AF_INET, d + 16);
    decode_l4(d[9], d + ihl, n - ihl, out);
    return true;
}

bool decode_ipv6(const uint8_t* d, size_t n, Decoded& out) {
    if (n < 40) return false;
    out.src_ip = ip_str(AF_INET6, d + 8);
    out.dst_ip = ip_str(AF_INET6, d + 24);
    decode_l4(d[6], d + 40, n - 40, out);
    return true;
}

bool decode_l3(uint16_t ethertype, const uint8_t* d, size_t n, Decoded& out) {
    if (ethertype == ETH_IP4) return decode_ipv4(d, n, out);
    if (ethertype == ETH_IP6) return decode_ipv6(d, n, out);
    return false;
}

bool decode_frame(const uint8_t* d, size_t n, int link_type, Decoded& out) {
    if (link_type == DLT_EN10MB) {
        if (n < 14) return false;
        out.dst_mac = mac_str(d);
        out.src_mac = mac_str(d + 6);
        return decode_l3(rd16be(d + 12), d + 14, n - 14, out);
    }
    if (link_type == DLT_LINUX_SLL) {
        if (n < 16) return false;
        return decode_l3(rd16be(d + 14), d + 16, n - 16, out);
    }
    return false;
}

py::list parse_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open capture file: " + path);
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    if (raw.size() < 24) throw std::invalid_argument("file is too short to contain a pcap header");

    uint32_t magic = rd32(raw.data(), true);
    bool le, nano = false;
    if (magic == PCAP_MAGIC_LE || magic == PCAP_MAGIC_NS_LE) {
        le = true;
        nano = (magic == PCAP_MAGIC_NS_LE);
    } else if (magic == PCAP_MAGIC_BE) {
        le = false;
    } else {
        char msg[48];
        std::snprintf(msg, sizeof(msg), "unrecognised pcap magic 0x%08X", magic);
        throw std::invalid_argument(msg);
    }

    int link_type = static_cast<int>(rd32(raw.data() + 20, le));
    double divisor = nano ? 1e9 : 1e6;

    py::list out;
    size_t offset = 24, total = raw.size();
    while (offset + 16 <= total) {
        uint32_t ts_sec = rd32(raw.data() + offset, le);
        uint32_t ts_frac = rd32(raw.data() + offset + 4, le);
        uint32_t caplen = rd32(raw.data() + offset + 8, le);
        offset += 16;
        if (offset + caplen > total) break;  // truncated final record

        Decoded p;
        if (decode_frame(raw.data() + offset, caplen, link_type, p)) {
            double ts = static_cast<double>(ts_sec) + static_cast<double>(ts_frac) / divisor;
            py::bytes payload(reinterpret_cast<const char*>(p.payload), p.payload_len);
            out.append(py::make_tuple(ts, p.src_ip, p.dst_ip, p.proto, p.src_port,
                                      p.dst_port, p.tcp_flags, payload, p.src_mac, p.dst_mac,
                                      p.seq, p.window, p.ack));
        }
        offset += caplen;
    }
    return out;
}

std::string backend_name() { return "native"; }

}  // namespace

PYBIND11_MODULE(_core, m) {
    m.doc() = "athar native pcap decode core";
    m.def("parse_file", &parse_file, py::arg("path"),
          "Decode every frame in a pcap file into a list of packet tuples.");
    m.def("backend_name", &backend_name, "Return the backend identifier.");
}
