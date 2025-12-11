// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/net/Packet.h"

#include <cstddef>
#include <cstdint>

namespace openpenny::net {

/**
 * @brief Lightweight packet frame decoder.
 *
 * Decodes a raw network frame into a PacketView structure without owning or
 * allocating memory. Used in the Penny pipeline to parse NIC-sourced frames
 * (AF_XDP, DPDK, PCAP, etc.).
 *
 * This parser is entirely stateless and exposes a single static entry point,
 * ensuring it can be safely called from hot paths or background threads.
 */
class PacketParser {
public:
    /**
     * @brief Decode a raw frame into a parsed PacketView representation.
     *
     * Requirements:
     *  - The frame must contain a valid Ethernet header and an IPv4 or IPv6 packet.
     *  - Parsing does not allocate or store memory internally.
     *  - Output references memory in the original frame via PacketView.
     *
     * @param frame  Pointer to the start of the raw frame buffer.
     * @param length Length of the frame in bytes.
     * @param out    Output parameter populated with header and packet view pointers.
     *
     * @return true  if decoding succeeded and @p out is valid.
     * @return false if the frame is malformed or unsupported.
     */
    static bool decode(const std::uint8_t* frame, std::size_t length, PacketView& out);
};

} // namespace openpenny::net
