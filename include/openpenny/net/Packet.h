// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/agg/Stats.h" // for FlowKey

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace openpenny::net {

/**
 * @brief Minimal non-owning TCP header view with helpers for decoding control flags.
 *
 * TcpHeaderView intentionally stores only the subset of fields required by Penny.
 * It is stateless, trivially copyable, and safe to call from hot paths.
 */
struct TcpHeaderView {
    uint16_t src_port{0};  ///< Source TCP port (host endian).
    uint16_t dst_port{0};  ///< Destination TCP port (host endian).
    uint32_t seq{0};       ///< TCP sequence number (host endian).
    uint32_t ack{0};       ///< TCP acknowledgement number (host endian).
    uint8_t  flags{0};     ///< Encodes 8 TCP control bits (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).

    /**
     * @brief Structured decoded representation of TCP control flags.
     */
    struct TcpFlags {
        bool cwr; ///< Congestion Window Reduced.
        bool ece; ///< ECN Echo.
        bool urg; ///< Urgent pointer field significant.
        bool ack; ///< ACK flag.
        bool psh; ///< Push Function.
        bool rst; ///< Reset the connection.
        bool syn; ///< Synchronise sequence numbers (connection start).
        bool fin; ///< No more data from sender (connection teardown).
    };

    /**
     * @brief Decode a single 8-bit flags value into a structured TcpFlags bundle.
     *
     * This method does not mutate any state and performs no allocation.
     */
    static constexpr TcpFlags decode_flags_direct(uint8_t value) noexcept {
        return TcpFlags{
            (value & 0x80) != 0, // CWR
            (value & 0x40) != 0, // ECE
            (value & 0x20) != 0, // URG
            (value & 0x10) != 0, // ACK
            (value & 0x08) != 0, // PSH
            (value & 0x04) != 0, // RST
            (value & 0x02) != 0, // SYN
            (value & 0x01) != 0  // FIN
        };
    }

    /**
     * @brief Build a 256-entry compile-time lookup table for fast flag decoding.
     *
     * This ensures decode_flags() becomes a constant-time LUT access. The table is
     * generated once at compile-time and reused for all decode operations.
     */
    static constexpr std::array<TcpFlags, 256> build_flag_lut() noexcept {
        std::array<TcpFlags, 256> lut{};
        for (std::size_t i = 0; i < lut.size(); ++i) {
            lut[i] = decode_flags_direct(static_cast<uint8_t>(i));
        }
        return lut;
    }

    /**
     * @brief Constant-time decoding of TCP flags using a compile-time LUT.
     *
     * Internally backed by a static constexpr std::array built by build_flag_lut().
     */
    static const TcpFlags& decode_flags(uint8_t value) noexcept {
        static const auto flag_lut = build_flag_lut();
        return flag_lut[value];
    }

    /**
     * @brief Convenience accessor returning decoded flags of the current header.
     */
    const TcpFlags& view_flags() const noexcept {
        return decode_flags(flags);
    }

    // Backward-compatible alias used by older call sites.
    const TcpFlags& flags_view() const noexcept { return view_flags(); }
};

/**
 * @brief Lightweight, backend-agnostic view over a parsed packet.
 *
 * PacketParser writes this object to avoid allocation or ownership overhead.
 * All pointers into the packet buffer are valid only during the handler call.
 */
struct PacketView {
    FlowKey    flow{};            ///< Flow identifier (5-tuple or 4-tuple depending on source).
    TcpHeaderView tcp{};          ///< Minimal parsed TCP header subset.
    uint64_t   payload_bytes{0};  ///< L4 payload length (0 for pure ACKs or empty payloads).
    uint64_t   timestamp_ns{0};   ///< Packet capture timestamp in nanoseconds.
    
    const uint8_t* layer3_ptr{nullptr}; ///< Pointer into the source buffer (non-owning).
    uint32_t   layer3_length{0};        ///< Length of the Layer 3 (IP) packet parsed.

    /**
     * @brief Build a logical identifier for snapshot bookkeeping.
     *
     * Format: "<seq>-<payload_bytes>". No timestamp is included to ensure determinism.
     */
    std::string packet_id() const noexcept {
        return std::to_string(tcp.seq) + "-" + std::to_string(payload_bytes);
    }
};

/**
 * @brief Handler invoked for each packet decoded by any PacketSource backend.
 *
 * C++ lambda or std::function compatible: `void(const PacketView&)`.
 */
using PacketHandler = std::function<void(const PacketView&)>;

/**
 * @brief Abstract packet source interface for Penny's packet ingestion layer.
 *
 * Contract:
 *  - open() should initialise the backend and prepare for polling.
 *  - close() should release backend resources safely.
 *  - poll() should fetch up to @p budget packets and deliver them to @p handler.
 *
 * This interface deliberately hides backend details (AF_XDP, DPDK, PCAP, etc.).
 */
class PacketSource {
public:
    virtual ~PacketSource() = default;
    
    virtual bool open(const std::string& ifname, unsigned queue) = 0;
    virtual void close() = 0;
    virtual bool poll(const PacketHandler& handler, std::size_t budget = 32) = 0;
};

/**
 * @brief Owning pointer to a concrete PacketSource implementation.
 *
 * Use of unique_ptr ensures:
 *  1. Ownership is unambiguous,
 *  2. Backend implementations remain hidden,
 *  3. And closing/cleanup happens automatically when erased or on destruction.
 */
using PacketSourcePtr = std::unique_ptr<PacketSource>;

} // namespace openpenny::net
