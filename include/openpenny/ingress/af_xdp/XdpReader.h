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
 * When libbpf support is available and enabled via Options, this reader:
 *  - attaches the configured XDP program to the given interface,
 *  - sets up an AF_XDP socket bound to a specific queue,
 *  - drains packets from the NIC via the AF_XDP path, and
 *  - exposes them through the backend-neutral dataplane session interface.
 *
 * The intent is to keep the AF_XDP / XDP plumbing encapsulated, so the rest of
 * the system sees a standard dataplane session abstraction.
 */
class XdpReader : public net::PacketSource {
public:
    /**
     * @brief Public tunables controlling AF_XDP runtime behaviour.
     *
     * This struct only exposes knobs that the surrounding pipeline actually
     * needs to observe or tweak (ring sizing, polling budget, the queue
     * layout shared across workers, and the traffic-match rules). All the
     * low-level BPF plumbing -- object/map/pin paths, XDP attach mode
     * preferences, SSH-bypass toggles -- used to live here and leaked
     * libbpf-specific concerns into every translation unit that included
     * XdpReader.h. Chunk 3 of the driver refactor moved that tuning into
     * an impl-private struct populated inside configure_from_config(Config),
     * so callers outside the AF_XDP module only see what they actually use.
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

    /**
     * @brief Assign options explicitly.
     *
     * Must be called before open(). Does not attempt to validate the presence
     * of libbpf / AF_XDP support; that is deferred to open().
     */
    void configure(const Options& opts);

    /**
     * @brief Convenience helper that copies settings from the parsed Config object.
     *
     * Typical usage:
     *   XdpReader reader;
     *   reader.configure_from_config(cfg);
     *   reader.open("eth0", queue);
     */
    void configure_from_config(const Config& cfg);

    /**
     * @brief Open the reader against a given interface and queue.
     *
     * When enable_real_reader is false, this may either fail fast or behave as
     * a no-op depending on the implementation, but higher layers should treat
     * a false return value as "no backend available".
     *
     * @param ifname Name of the network interface (e.g., "eth0").
     * @param queue  Hardware queue index to bind the AF_XDP socket to.
     * @return true  if the AF_XDP/XDP setup succeeded and the reader is ready.
     */
    bool open(const std::string& ifname, unsigned queue) override;

    /**
     * @brief Release any resources and reset state.
     *
     * This will typically:
     *  - tear down the AF_XDP socket and UMEM,
     *  - optionally detach the XDP program (depending on options),
     *  - and clear any internal handles.
     */
    void close() override;

    /**
     * @brief Pull up to @p budget packets and forward them to @p handler.
     *
     * The implementation is expected to:
     *  - fetch up to Options::batch packets from the AF_XDP RX ring,
     *  - wrap them as PacketView instances,
     *  - and invoke handler() for each packet.
     *
     * @param handler  Callback used to process each packet.
     * @param budget   Upper bound on packets processed during this call.
     * @return true    if polling succeeded (even if no packets were available).
     */
    bool poll(const net::PacketHandler& handler, std::size_t budget = 32) override;

    bool update_match_rules(const net::TrafficMatchConfig& config) override;

    /**
     * @brief Whether the reader currently has an open backend.
     *
     * This simply reflects whether open() succeeded and close() has not yet
     * been called.
     */
    bool active() const noexcept { return opened_; }

private:
    /**
     * @brief Opaque implementation wrapper.
     *
     * All libbpf and AF_XDP details are hidden behind this pImpl to keep
     * consumers of XdpReader free from libbpf headers and to minimise
     * recompilation when low-level details change.
     */
    struct Impl;

    struct ImplDeleter {
        void operator()(Impl*) const;
    };

    /**
     * @brief Periodically read the kernel XDP counters map and log it.
     *
     * Rate-limited internally so it is cheap to call on every poll(). When
     * `no packets arrive` is reported by an operator, the values of these
     * counters (seen / ipv4 / match / redirect / xsk_hit / xsk_miss /
     * queue_mismatch) point directly at which pipeline stage is dropping
     * the traffic.
     */
    void log_xdp_counters_if_due();

    /**
     * @brief Verify the NIC's RSS indirection table only targets served queues.
     *
     * Reads the hardware RSS indirection table via ethtool ioctl and checks it
     * against the served set [base_queue, base_queue + queue_count). Logs a
     * loud WARN with an actionable fix if RSS steers traffic to queues we have
     * no AF_XDP socket on. Logs an INFO confirmation when coverage is correct.
     *
     * Called once per interface (gated on shared_attach state) so we don't
     * spam when multiple queue workers open on the same NIC.
     */
    void check_rss_coverage(const std::string& ifname);

    /// Pointer to the underlying AF_XDP / libbpf implementation.
    std::unique_ptr<Impl, ImplDeleter> impl_{nullptr};

    bool initialized_{false};  ///< True once configure() / configure_from_config() has run.
    bool opened_{false};       ///< True after a successful open(), false after close().
};

} // namespace openpenny
