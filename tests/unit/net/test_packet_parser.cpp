// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/net/PacketParser.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

namespace {

void append_be16(std::vector<std::uint8_t>& frame, std::uint16_t value) {
    frame.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_be32(std::vector<std::uint8_t>& frame, std::uint32_t value) {
    frame.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    frame.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    frame.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::vector<std::uint8_t> build_tcp_frame(const std::vector<std::uint16_t>& vlan_ethertypes) {
    std::vector<std::uint8_t> frame;
    frame.reserve(14 + vlan_ethertypes.size() * 4 + 20 + 20);

    const std::array<std::uint8_t, 6> dst_mac{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const std::array<std::uint8_t, 6> src_mac{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
    frame.insert(frame.end(), dst_mac.begin(), dst_mac.end());
    frame.insert(frame.end(), src_mac.begin(), src_mac.end());

    if (vlan_ethertypes.empty()) {
        append_be16(frame, 0x0800);
    } else {
        append_be16(frame, vlan_ethertypes.front());
        for (std::size_t i = 0; i < vlan_ethertypes.size(); ++i) {
            append_be16(frame, static_cast<std::uint16_t>(0x0064 + i)); // TCI
            append_be16(frame, i + 1 < vlan_ethertypes.size() ? vlan_ethertypes[i + 1] : 0x0800);
        }
    }

    // IPv4 header
    frame.push_back(0x45); // version + IHL
    frame.push_back(0x00); // DSCP/ECN
    append_be16(frame, 40); // total length
    append_be16(frame, 0x1234); // identification
    append_be16(frame, 0x0000); // flags/fragment offset
    frame.push_back(64); // TTL
    frame.push_back(6);  // TCP
    append_be16(frame, 0x0000); // header checksum
    append_be32(frame, 0xc0a82903u); // 192.168.41.3
    append_be32(frame, 0xc0a82902u); // 192.168.41.2

    // TCP header
    append_be16(frame, 40000);
    append_be16(frame, 5201);
    append_be32(frame, 1);
    append_be32(frame, 2);
    frame.push_back(0x50); // data offset 5
    frame.push_back(0x18); // PSH + ACK
    append_be16(frame, 4096);
    append_be16(frame, 0x0000); // checksum
    append_be16(frame, 0x0000); // urgent pointer

    return frame;
}

void assert_decodes(const std::vector<std::uint8_t>& frame) {
    openpenny::net::PacketView packet{};
    assert(openpenny::net::PacketParser::decode(frame.data(), frame.size(), packet));
    assert(packet.flow.src == 0xc0a82903u);
    assert(packet.flow.dst == 0xc0a82902u);
    assert(packet.flow.sport == 40000);
    assert(packet.flow.dport == 5201);
    assert(packet.ip_proto == 6);
}

} // namespace

int main() {
    assert_decodes(build_tcp_frame({}));
    assert_decodes(build_tcp_frame({0x8100}));
    assert_decodes(build_tcp_frame({0x88A8}));
    assert_decodes(build_tcp_frame({0x88A8, 0x8100}));
    return 0;
}
