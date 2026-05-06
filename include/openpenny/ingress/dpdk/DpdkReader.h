// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"

namespace openpenny {

/**
 * @brief DPDK-backed implementation of the dataplane session interface.
 *
 * Polls an interface in promiscuous mode through a single RX queue and
 * surfaces parsed packets to the pipeline via PacketHandler. DPDK
 * specifics (EAL, mempools, mbufs) stay inside the .cpp.
 *
 * Lifecycle: configure() -> open() -> poll()... -> close().
 */
class DpdkReader : public net::PacketSource {
public:
    /// Per-reader knobs. Defaults are safe for a single-queue setup.
    struct Options {
        bool enable = false;        ///< Set to true to actually open the port.
        unsigned burst = 32;        ///< Max packets pulled per rte_eth_rx_burst().
        net::TrafficMatchConfig match_config{}; ///< Userspace filter; empty matches all.
    };

    DpdkReader() = default;
    ~DpdkReader() override = default;

    /// Apply explicit options. Must be called before open().
    void configure(const Options& opts) {
        opts_ = opts;
        configured_ = true;
    }

    /// Populate Options from the parsed Config. Mirrors the other readers.
    void configure_from_config(const Config& cfg) {
        Options opts;
        opts.enable       = cfg.input.backend == PacketInputBackend::Dpdk;
        opts.burst        = cfg.dpdk.burst;
        opts.match_config = cfg.traffic_match;
        configure(opts);
    }

    /**
     * Open a DPDK port and bring up RX.
     *
     * @param ifname DPDK port identifier: PCI bus address (e.g. "0000:01:00.0")
     *               or vdev name (e.g. "net_tap0"). Linux ifnames like "eth0"
     *               are not accepted unless EAL has registered a matching
     *               device.
     * @param queue  RX queue index. The port is configured with (queue + 1)
     *               RX queues, so a single reader can target any queue.
     * @return true on success, false on any DPDK setup failure (logged).
     */
    bool open(const std::string& ifname, unsigned queue) override;

    /// Stop the port and disable promiscuous mode. Idempotent.
    void close() override;

    /**
     * Pull at most @p budget packets and dispatch them to @p handler.
     *
     * Multi-segment mbufs are linearized before parsing so PacketHandler
     * always sees a contiguous frame. Packets that fail PacketParser or
     * the match filter are silently dropped.
     *
     * @return true on success (even when zero packets were received).
     */
    bool poll(const net::PacketHandler& handler, std::size_t budget = 32) override;

    /// Swap the userspace match filter; effective on the next poll().
    bool update_match_rules(const net::TrafficMatchConfig& config) override {
        opts_.match_config = config;
        return true;
    }

private:
    Options opts_{};
    bool configured_{false};   ///< Set once configure*() has been called.
    bool opened_{false};       ///< True between a successful open() and close().
    std::string ifname_{};     ///< DPDK port name passed to open().
    unsigned queue_{0};        ///< RX queue index passed to open().
    std::uint16_t port_id_{0}; ///< Resolved DPDK port id; valid while opened_.
};

} // namespace openpenny
