// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace openpenny {

/**
 * @brief AF_XDP-based packet reader and XDP attachment wrapper.
 *
 * When libbpf is available and Options::enable_real_reader is set, this
 * reader attaches the configured XDP program to the interface, opens an
 * AF_XDP socket on the given queue, drains the RX ring, and surfaces
 * packets through the backend-neutral dataplane session interface.
 *
 * All AF_XDP / libbpf plumbing lives behind a pImpl so callers don't pull
 * libbpf headers transitively.
 */
class XdpReader : public net::PacketSource {
public:
    /**
     * @brief Public AF_XDP tunables.
     *
     * Exposes only the knobs the surrounding pipeline needs: ring sizing,
     * polling budget, the queue layout shared across workers, and the
     * traffic-match rules. Low-level BPF settings (object/map/pin paths,
     * attach-mode preferences, SSH-bypass) live in an impl-private struct
     * populated by configure_from_config(Config).
     */
    struct Options {
        bool enable_real_reader = false;   ///< Use AF_XDP pipeline when true; otherwise act as disabled.

        // Polling / batching
        unsigned batch          = 256;     ///< Max packets to fetch from AF_XDP per poll iteration.
        unsigned poll_timeout_ms = 0;      ///< Poll timeout in milliseconds (if blocking is used).

        // Full pipeline queue layout (shared across all queue workers on this NIC).
        // Used at open() to verify the NIC's RSS indirection table only routes
        // to queues that OpenPenny actually serves; a mismatch is the classic
        // "xsk_miss on 98% of matched packets" bug.
        unsigned base_queue    = 0;        ///< First queue id served by the pipeline.
        unsigned queue_count   = 1;        ///< Number of queues served (starting at base_queue).

        net::TrafficMatchConfig match_config{}; ///< Backend-neutral match rules programmed into BPF.

        // AF_XDP ring/UMEM configuration
        uint32_t frame_size = 2048;        ///< Size of each UMEM frame.
        uint32_t num_frames = 65536;       ///< Number of UMEM frames in total.
        uint32_t rx_ring    = 4096;        ///< Size of RX ring.
    };

    XdpReader() = default;
    ~XdpReader();

    /// Apply explicit options. Must be called before open(). Does not check
    /// for libbpf/AF_XDP support; that is deferred to open().
    void configure(const Options& opts);

    /**
     * @brief Populate Options from the parsed Config.
     *
     * Typical usage:
     *   XdpReader reader;
     *   reader.configure_from_config(cfg);
     *   reader.open("eth0", queue);
     */
    void configure_from_config(const Config& cfg);

    /**
     * @brief Open the reader against an interface and queue.
     *
     * When enable_real_reader is false, this returns false; callers should
     * treat that as "no backend available".
     *
     * @param ifname Network interface name (e.g. "eth0").
     * @param queue  Hardware queue index to bind the AF_XDP socket to.
     * @return true on success.
     */
    bool open(const std::string& ifname, unsigned queue) override;

    /// Tear down the AF_XDP socket and UMEM, optionally detach the XDP
    /// program, and clear all internal state. Idempotent.
    void close() override;

    /**
     * @brief Pull up to @p budget packets and forward them to @p handler.
     *
     * Reads up to Options::batch packets from the AF_XDP RX ring, wraps
     * each as a PacketView, and invokes @p handler.
     *
     * @return true on success (even when no packets were available).
     */
    bool poll(const net::PacketHandler& handler, std::size_t budget = 32) override;

    bool update_match_rules(const net::TrafficMatchConfig& config) override;

    /// True between a successful open() and the next close().
    bool active() const noexcept { return opened_; }

private:
    /// Opaque pImpl. Hides libbpf/AF_XDP types so callers don't pull libbpf
    /// headers transitively and recompiles stay localized.
    struct Impl;

    struct ImplDeleter {
        void operator()(Impl*) const;
    };

    /// Read the kernel XDP counters map and log a single line. Rate-limited
    /// so it's cheap to call from poll(). When operators report "no packets",
    /// the seen/match/redirect/xsk_hit/xsk_miss values pinpoint which stage
    /// is dropping traffic.
    void log_xdp_counters_if_due();

    /// Verify the NIC's RSS indirection table only targets served queues.
    /// Reads the table via ethtool ioctl and checks it against
    /// [base_queue, base_queue + queue_count). Logs a WARN with an
    /// actionable fix if RSS steers traffic to queues without an AF_XDP
    /// socket; INFO confirmation otherwise. Called once per NIC.
    void check_rss_coverage(const std::string& ifname);

    /// Pointer to the underlying AF_XDP / libbpf implementation.
    std::unique_ptr<Impl, ImplDeleter> impl_{nullptr};

    bool initialized_{false};  ///< True once configure() / configure_from_config() has run.
    bool opened_{false};       ///< True after a successful open(), false after close().
};

} // namespace openpenny
