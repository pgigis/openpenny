// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/net/PacketParser.h"

#include <arpa/inet.h>
#include <cstring>

namespace openpenny::net {

namespace {

// Read a big-endian 16-bit value without unaligned casts (portable and fast).
inline uint16_t load_be16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// Read a big-endian 32-bit value without unaligned casts (portable and fast).
inline uint32_t load_be32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

} // namespace

bool PacketParser::decode(const uint8_t* frame, std::size_t length, PacketView& out) {
    // Need at least an Ethernet header.
    if (!frame || length < 14) {
        return false;
    }

    const uint8_t* const frame_end = frame + length;

    // ---------------------------------------------------------------------
    // 1. Ethernet header (+ optional single 802.1Q VLAN tag).
    // ---------------------------------------------------------------------
    uint16_t eth_type = load_be16(frame + 12);
    std::size_t offset = 14; // start of L3 header

    // Single 802.1Q VLAN tag.
    if (eth_type == 0x8100) {
        if (length < 18) {
            return false; // truncated VLAN header
        }
        eth_type = load_be16(frame + 16);
        offset = 18;
    }

    // Only handle IPv4.
    if (eth_type != 0x0800 || length < offset + 20) {
        return false;
    }

    // ---------------------------------------------------------------------
    // 2. IPv4 header (with optional options) and IP packet bounds.
    // ---------------------------------------------------------------------
    const uint8_t* const ip = frame + offset;
    if (ip + 20 > frame_end) {
        return false; // truncated minimal IPv4 header
    }

    const uint8_t vihl = ip[0];
    const uint8_t version = static_cast<uint8_t>(vihl >> 4);
    if (version != 4) {
        return false;
    }

    const uint8_t ihl_words = static_cast<uint8_t>(vihl & 0x0F);
    const std::size_t ihl_bytes = static_cast<std::size_t>(ihl_words) * 4;
    if (ihl_bytes < 20) {
        return false; // invalid IHL
    }
    if (ip + ihl_bytes > frame_end) {
        return false; // IPv4 header with options is truncated
    }

    const uint16_t ip_total_len = load_be16(ip + 2);
    if (ip_total_len < ihl_bytes) {
        return false; // malformed IPv4 total length
    }

    // End of the IPv4 packet as per the header, clamped to captured bytes.
    const uint8_t* ip_end = ip + ip_total_len;
    if (ip_end > frame_end) {
        ip_end = frame_end;
    }

    const uint32_t src   = load_be32(ip + 12);
    const uint32_t dst   = load_be32(ip + 16);
    const uint8_t  proto = ip[9];

    // ---------------------------------------------------------------------
    // 3. L4 header (TCP/UDP) and payload length.
    // ---------------------------------------------------------------------
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint8_t  flags = 0;
    uint32_t seq_num = 0;
    uint32_t ack_num = 0;
    uint64_t payload_bytes = 0;

    const uint8_t* const l4 = ip + ihl_bytes;
    if (l4 > ip_end) {
        // No L4 header present (e.g. very short IP packet). We still
        // report the L3 info below.
        goto build_view;
    }

    // Ports (for TCP/UDP) if we have at least 4 bytes.
    if ((proto == 6 || proto == 17) && (l4 + 4) <= ip_end) {
        sport = load_be16(l4);
        dport = load_be16(l4 + 2);
    }

    if (proto == 6) {
        // TCP: need at least the fixed 20-byte header.
        if (l4 + 20 <= ip_end) {
            const uint8_t doff_words = static_cast<uint8_t>(l4[12] >> 4);
            std::size_t tcp_header_bytes = static_cast<std::size_t>(doff_words) * 4;
            if (tcp_header_bytes < 20) {
                tcp_header_bytes = 20; // defensive clamp
            }

            const uint8_t* const l4_payload = l4 + tcp_header_bytes;
            if (l4_payload <= ip_end) {
                const uint8_t tcp_flags = l4[13];

                // Store a compact subset of TCP flags.
                if (tcp_flags & 0x02) flags |= 0x02; // SYN
                if (tcp_flags & 0x01) flags |= 0x01; // FIN
                if (tcp_flags & 0x04) flags |= 0x04; // RST
                if (tcp_flags & 0x10) flags |= 0x10; // ACK

                seq_num = load_be32(l4 + 4);
                ack_num = load_be32(l4 + 8);

                // TCP payload bytes: IP payload minus TCP header (including options).
                if (l4_payload < ip_end) {
                    payload_bytes = static_cast<uint64_t>(ip_end - l4_payload);
                }
            }
        }
    } else if (proto == 17) {
        // UDP: fixed 8-byte header; use UDP length field.
        if (l4 + 8 <= ip_end) {
            const uint16_t udp_len = load_be16(l4 + 4);
            if (udp_len >= 8) {
                const uint8_t* const udp_payload = l4 + 8;
                const uint8_t* udp_end = l4 + udp_len;
                if (udp_end > ip_end) {
                    udp_end = ip_end; // clamp to capture
                }
                if (udp_payload < udp_end) {
                    payload_bytes = static_cast<uint64_t>(udp_end - udp_payload);
                }
            }
        }
    }

build_view:
    // ---------------------------------------------------------------------
    // 4. Populate PacketView.
    // ---------------------------------------------------------------------
    PacketView view{};
    view.flow.src   = src;
    view.flow.dst   = dst;
    view.flow.sport = sport;
    view.flow.dport = dport;

    view.tcp.src_port = sport;
    view.tcp.dst_port = dport;
    view.tcp.seq      = seq_num;
    view.tcp.ack      = ack_num;
    view.tcp.flags    = flags;

    view.payload_bytes = payload_bytes;

    view.layer3_ptr    = ip;
    view.layer3_length = static_cast<uint32_t>(ip_end - ip); // bytes of IPv4 in capture

    // timestamp_ns is filled by the packet source; we leave it at 0 here.
    out = view;
    return true;
}

} // namespace openpenny::net
