// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"
#include "openpenny/net/TrafficMatch.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace openpenny::ingress::af_packet {

/**
 * @brief AF_PACKET-based mirror reader for passive observation.
 *
 * Unlike the AF_XDP reader (which *redirects* packets out of the kernel
 * stack), this reader taps the interface via `AF_PACKET` / `SOCK_RAW`:
 * the kernel continues to deliver each packet up the normal stack to the
 * final application, and we receive a copy alongside it. Ideal for the
 * passive pipeline where our job is to *observe* without perturbing the
 * traffic.
 *
 * Scope of this MVP:
 *  - Single worker per reader (no PACKET_FANOUT). Supports queue_count=1.
 *  - Filtering happens in userspace via the shared TrafficMatchConfig;
 *    kernel-side cBPF filtering can be added later if capture rate is
 *    an issue.
 *  - IPv4 only, matching the rest of the pipeline.
 */
class AfPacketMirrorReader : public net::PacketSource {
public:
    /**
     * @brief Runtime-tunable options; only a handful matter in practice.
     */
    struct Options {
        /// Upper bound on frames pulled from the socket per poll() call.
        std::size_t batch = 256;
        /// Poll timeout in milliseconds (0 = non-blocking).
        int poll_timeout_ms = 0;
        /// Capture buffer size (bytes). Jumbo frames need at least 9000.
        std::size_t frame_size = 9216;
        /// SO_RCVBUF size in bytes; 0 leaves the kernel default.
        std::size_t rcvbuf_bytes = 0;
        /// Ignore outbound frames (PACKET_OUTGOING). Almost always desired.
        bool drop_outgoing = true;
        /// Match rules applied in userspace before the handler is invoked.
        net::TrafficMatchConfig match_config{};
    };

    AfPacketMirrorReader();
    ~AfPacketMirrorReader() override;

    /**
     * @brief Explicit configuration entry point.
     *
     * Must be called before open(). Safe to call again between close() and
     * the next open(), for example to swap the match config.
     */
    void configure(const Options& opts);

    /**
     * @brief Populate options from the parsed Config.
     *
     * Mirrors XdpReader::configure_from_config() semantics so the
     * dataplane::Factory can stay backend-agnostic.
     */
    void configure_from_config(const Config& cfg);

    /**
     * @brief Open an AF_PACKET socket bound to @p ifname.
     *
     * @param ifname Interface to tap (e.g., "ens5f0np0").
     * @param queue  Advisory queue id, reserved for future PACKET_FANOUT use.
     * @return true on success; false if the socket/bind failed.
     */
    bool open(const std::string& ifname, unsigned queue) override;

    /**
     * @brief Close the socket and release buffers.
     */
    void close() override;

    /**
     * @brief Drain up to @p budget frames and invoke @p handler for each.
     *
     * Non-blocking by default; if Options::poll_timeout_ms > 0 we wait
     * briefly for new data. Frames that fail to parse as IPv4 or fail the
     * traffic-match check are silently dropped (they are already on the
     * kernel stack path; we just don't surface them to the pipeline).
     */
    bool poll(const net::PacketHandler& handler, std::size_t budget = 32) override;

    /**
     * @brief Swap the in-memory match config; effective on the next poll().
     */
    bool update_match_rules(const net::TrafficMatchConfig& config) override;

    /// Whether the socket is currently open.
    bool active() const noexcept { return fd_ >= 0; }

private:
    Options opts_{};
    int fd_{-1};
    unsigned ifindex_{0};
    std::string ifname_;
    std::vector<std::uint8_t> frame_buf_{};

    // Diagnostic counters. Logged periodically as `[afpkt_counters]`
    // so the operator can see *exactly* where in the AF_PACKET path
    // packets are being lost (e.g. seen on the socket but rejected by
    // PacketParser, or seen and parsed but rejected by the match
    // policy). Single worker only — no atomics needed.
    std::uint64_t rx_packets_{0};
    std::uint64_t decode_failures_{0};
    std::uint64_t outgoing_skipped_{0};
    std::uint64_t filter_rejects_{0};
    std::uint64_t handler_invocations_{0};
    std::chrono::steady_clock::time_point last_counter_log_{};
};

} // namespace openpenny::ingress::af_packet
