// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: PacketParser::decode() extracts the TCP 5-tuple from
// IPv4/TCP frames regardless of the VLAN tagging on the wire.
//
// Scenarios:
//   - bare Ethernet (no VLAN tag)            -> EtherType 0x0800 (IPv4)
//   - single VLAN tag (802.1Q, 0x8100)
//   - single QinQ tag  (802.1ad, 0x88A8)
//   - nested QinQ + VLAN tags
//
// If this fails: trunked traffic is silently mis-parsed; the flow
// 5-tuple ends up wrong and the dataplane drops or mis-routes
// matching packets.

#include "openpenny/net/PacketParser.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void append_be16(std::vector<std::uint8_t>& frame, std::uint16_t value) {
    frame.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>( value       & 0xff));
}

void append_be32(std::vector<std::uint8_t>& frame, std::uint32_t value) {
    frame.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    frame.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    frame.push_back(static_cast<std::uint8_t>((value >>  8) & 0xff));
    frame.push_back(static_cast<std::uint8_t>( value        & 0xff));
}

// Build a minimal IPv4 + TCP frame, optionally prefixed with N VLAN
// tags. The last vlan_ethertypes entry must encode the outer EtherType
// of the stacked tag header; subsequent tags chain via the embedded
// "next EtherType" field until the IPv4 (0x0800) payload starts.
std::vector<std::uint8_t> build_tcp_frame(const std::vector<std::uint16_t>& vlan_ethertypes) {
    std::vector<std::uint8_t> frame;
    frame.reserve(14 + vlan_ethertypes.size() * 4 + 20 + 20);

    // Destination + source MAC.
    const std::array<std::uint8_t, 6> dst_mac{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const std::array<std::uint8_t, 6> src_mac{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
    frame.insert(frame.end(), dst_mac.begin(), dst_mac.end());
    frame.insert(frame.end(), src_mac.begin(), src_mac.end());

    // EtherType + optional VLAN chain.
    if (vlan_ethertypes.empty()) {
        append_be16(frame, 0x0800); // IPv4
    } else {
        append_be16(frame, vlan_ethertypes.front());
        for (std::size_t i = 0; i < vlan_ethertypes.size(); ++i) {
            append_be16(frame, static_cast<std::uint16_t>(0x0064 + i));     // TCI: arbitrary VID
            append_be16(frame,
                        i + 1 < vlan_ethertypes.size() ? vlan_ethertypes[i + 1]
                                                       : 0x0800);            // next or IPv4
        }
    }

    // IPv4 header.
    frame.push_back(0x45);                 // version 4, IHL 5
    frame.push_back(0x00);                 // DSCP / ECN
    append_be16(frame, 40);                // total length (20 IP + 20 TCP)
    append_be16(frame, 0x1234);            // identification
    append_be16(frame, 0x0000);            // flags / fragment offset
    frame.push_back(64);                   // TTL
    frame.push_back(6);                    // protocol: TCP
    append_be16(frame, 0x0000);            // header checksum
    append_be32(frame, 0xc0a82903u);       // 192.168.41.3 (src)
    append_be32(frame, 0xc0a82902u);       // 192.168.41.2 (dst)

    // TCP header.
    append_be16(frame, 40000);             // src port
    append_be16(frame, 5201);              // dst port
    append_be32(frame, 1);                 // seq
    append_be32(frame, 2);                 // ack
    frame.push_back(0x50);                 // data offset 5
    frame.push_back(0x18);                 // flags: PSH+ACK
    append_be16(frame, 4096);              // window
    append_be16(frame, 0x0000);            // checksum
    append_be16(frame, 0x0000);            // urgent pointer

    return frame;
}

void assert_decodes_to_5_tuple(const std::vector<std::uint8_t>& frame) {
    openpenny::net::PacketView pkt{};
    assert(openpenny::net::PacketParser::decode(frame.data(), frame.size(), pkt));
    assert(pkt.flow.src      == 0xc0a82903u);
    assert(pkt.flow.dst      == 0xc0a82902u);
    assert(pkt.flow.sport    == 40000);
    assert(pkt.flow.dport    == 5201);
    assert(pkt.flow.ip_proto == 6);
    assert(pkt.ip_proto      == 6);
}

} // namespace

int main() {
    std::cout << "scenario: bare Ethernet (no VLAN)\n";
    assert_decodes_to_5_tuple(build_tcp_frame({}));

    std::cout << "scenario: single 802.1Q VLAN tag\n";
    assert_decodes_to_5_tuple(build_tcp_frame({0x8100}));

    std::cout << "scenario: single 802.1ad QinQ tag\n";
    assert_decodes_to_5_tuple(build_tcp_frame({0x88A8}));

    std::cout << "scenario: nested QinQ + VLAN tags\n";
    assert_decodes_to_5_tuple(build_tcp_frame({0x88A8, 0x8100}));

    return 0;
}
