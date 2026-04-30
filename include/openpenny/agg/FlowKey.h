// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>

namespace openpenny {

struct FlowKey {
    /**
     * @brief Protocol-aware flow tuple in host byte order.
     *
     * Encodes IPv4 source/destination, L4 ports, and the IPv4 protocol
     * number so TCP/UDP traffic with the same addresses/ports do not
     * alias to the same key.
     */
    std::uint32_t src{0};
    std::uint32_t dst{0};
    std::uint16_t sport{0};
    std::uint16_t dport{0};
    std::uint8_t ip_proto{0};

    bool operator==(const FlowKey& o) const noexcept {
        return src == o.src &&
               dst == o.dst &&
               sport == o.sport &&
               dport == o.dport &&
               ip_proto == o.ip_proto;
    }
};

struct FlowKeyHash {
    /**
     * @brief Mix all FlowKey fields into a single hash using 64-bit avalanching.
     */
    std::size_t operator()(const FlowKey& k) const noexcept {
        const std::uint64_t addr_pair =
            (static_cast<std::uint64_t>(k.src) << 32) | k.dst;
        const std::uint64_t ports_proto =
            (static_cast<std::uint64_t>(k.sport) << 24) |
            (static_cast<std::uint64_t>(k.dport) << 8) |
            static_cast<std::uint64_t>(k.ip_proto);

        std::uint64_t v =
            addr_pair ^ (ports_proto + 0x9e3779b97f4a7c15ULL +
                         (addr_pair << 6) + (addr_pair >> 2));
        v ^= (v >> 33);
        v *= 0xff51afd7ed558ccdULL;
        v ^= (v >> 33);
        v *= 0xc4ceb9fe1a85ec53ULL;
        v ^= (v >> 33);
        return static_cast<std::size_t>(v);
    }
};

template <typename T>
using FlowMap = std::unordered_map<FlowKey, T, FlowKeyHash>;

using FlowSet = std::unordered_set<FlowKey, FlowKeyHash>;

} // namespace openpenny
