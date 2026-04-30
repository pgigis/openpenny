// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <cstdint>
#include <string>

namespace openpenny::penny {

// Packet drop IDs must remain exact because they are used as hash keys and
// compared across threads/timer callbacks. Packing seq and payload length into
// one integer keeps the hot path allocation-free without introducing the
// rounding/equality hazards of a floating-point encoding.
using PacketDropId = std::uint64_t;

constexpr PacketDropId make_packet_drop_id(std::uint32_t seq,
                                           std::uint32_t payload_bytes) noexcept {
    return (static_cast<PacketDropId>(seq) << 32) |
           static_cast<PacketDropId>(payload_bytes);
}

constexpr std::uint32_t packet_drop_id_seq(PacketDropId id) noexcept {
    return static_cast<std::uint32_t>(id >> 32);
}

constexpr std::uint32_t packet_drop_id_payload_bytes(PacketDropId id) noexcept {
    return static_cast<std::uint32_t>(id & 0xffffffffULL);
}

inline std::string format_packet_drop_id(PacketDropId id) {
    return std::to_string(packet_drop_id_seq(id)) + "-" +
           std::to_string(packet_drop_id_payload_bytes(id));
}

} // namespace openpenny::penny
