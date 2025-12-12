// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"

namespace openpenny {

/**
 * @brief Packet reader using a :contentReference[oaicite:0]{index=0} data plane.
 *
 * This class integrates with the Penny pipeline by implementing the PacketSource
 * interface. Its goal is to pull packets from an interface using DPDK without
 * exposing DPDK specifics to upper layers.
 */
class DpdkReader : public net::PacketSource {
public:
    // -------------------------------------------------------------------------
    // Configuration options
    // -------------------------------------------------------------------------

    /// Controls whether the reader is enabled and how many packets to pull per burst.
    struct Options {
        bool enable = false;     ///< If false, open()/poll() can be safely skipped.
        unsigned burst = 32;    ///< Maximum number of packets pulled per DPDK burst.
    };

    DpdkReader() = default;
    ~DpdkReader() override = default;

    /**
     * @brief Configure the reader using explicit options.
     *
     * Must be called before open(). Sets the configured flag so poll() can validate
     * state without re-reading configuration.
     */
    void configure(const Options& opts) {
        opts_ = opts;
        configured_ = true;
    }

    /**
     * @brief Configure options by reading them from a central Penny configuration.
     *
     * Convenience method that extracts DPDK options from the global Config object.
     */
    void configure_from_config(const Config& cfg) {
        Options opts;
        opts.enable = cfg.dpdk.enable;
        opts.burst  = cfg.dpdk.burst;
        configure(opts);
    }

    // -------------------------------------------------------------------------
    // PacketSource interface implementation
    // -------------------------------------------------------------------------

    /**
     * @brief Open the interface for packet polling using DPDK.
     *
     * @param ifname Name of the network interface (e.g., "eth0").
     * @param queue  Queue index, if multi-queue polling is used.
     * @return true  if the interface was opened successfully.
     */
    bool open(const std::string& ifname, unsigned queue) override;

    /**
     * @brief Close the packet reader and release interface resources.
     *
     * Safe to call even if open() was never successful.
     */
    void close() override;

    /**
     * @brief Poll packets from the interface and hand them to the provided handler.
     *
     * @param handler  The callback that processes incoming packets.
     * @param budget   Optional maximum packet count to process in one poll cycle.
     * @return true    if polling succeeded (even if no packets were received).
     */
    bool poll(const net::PacketHandler& handler, std::size_t budget = 32) override;

private:
    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    Options opts_{};           ///< Effective configuration for this reader.
    bool configured_{false};   ///< Set once configure() or configure_from_config() is called.
    bool opened_{false};       ///< Set once open() succeeds; cleared on close().
    std::string ifname_{};     ///< Name of the interface currently opened.
    unsigned queue_{0};        ///< Queue index used when open() was called.

    /// DPDK port identifier corresponding to the opened interface.
    std::uint16_t port_id_{0};
};

} // namespace openpenny
