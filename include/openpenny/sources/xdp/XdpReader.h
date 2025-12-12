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
 *  - exposes them through the net::PacketSource interface.
 *
 * The intent is to keep the AF_XDP / XDP plumbing encapsulated, so the rest of
 * the system sees a standard PacketSource abstraction.
 */
class XdpReader : public net::PacketSource {
public:
    /**
     * @brief Tunables controlling AF_XDP attachment and runtime behaviour.
     *
     * These options are typically populated from the global Config object
     * (via configure_from_config()) and then passed to configure().
     */
    struct Options {
        // High-level toggles
        bool enable_real_reader = false;   ///< Use AF_XDP pipeline when true; otherwise act as disabled.
        bool attach_program     = true;    ///< Attach XDP program on open().
        bool detach_on_close    = true;    ///< Detach XDP program when close() is called.
        bool reuse_pins         = false;   ///< Reuse pre-pinned maps instead of re-creating them.
        bool pin_maps           = true;    ///< Pin created maps into bpffs for reuse/inspection.
        bool update_conf_map    = true;    ///< Update configuration map with prefix/mask, etc.
        bool verbose            = false;   ///< Enable verbose logging at the libbpf / XDP level.
        bool drop_unmatched     = false;   ///< Drop packets not matching the configured prefix.
        bool allow_ssh_bypass   = true;    ///< Allow SSH traffic to bypass XDP redirection.
        bool allow_skb_fallback = false;   ///< Allow generic (skb) XDP mode if native fails.
        bool force_copy_mode    = false;   ///< Force copy mode in AF_XDP even if zero-copy is possible.
        bool require_zerocopy   = true;    ///< Require zero-copy; fail if not available.
        bool allow_copy_fallback = false;  ///< If zero-copy fails, allow copy-mode fallback.

        // Polling / batching
        unsigned batch          = 256;     ///< Max packets to fetch from AF_XDP per poll iteration.
        unsigned poll_timeout_ms = 0;      ///< Poll timeout in milliseconds (if blocking is used).

        // BPF object and symbol names
        std::string bpf_object  = "xdp_redirect_dstprefix.o";  ///< BPF ELF object file.
        std::string bpf_program = "xdp_redirect_dstprefix";    ///< XDP program function name.
        std::string map_conf_name  = "conf";       ///< Name of configuration map inside the BPF object.
        std::string map_xsks_name  = "xsks_map";   ///< Name of AF_XDP socket map.
        std::string map_stats_name = "counters";   ///< Name of per-CPU stats map.

        // bpffs pin paths
        std::string pin_conf_path  = "/sys/fs/bpf/openpenny_conf";
        std::string pin_xsks_path  = "/sys/fs/bpf/openpenny_xsks";
        std::string pin_stats_path = "/sys/fs/bpf/openpenny_stats";

        // Prefix selection for redirection / filtering (host endian).
        uint32_t prefix_host = 0;          ///< IPv4 prefix in host byte order.
        uint32_t mask_host   = 0;          ///< IPv4 mask in host byte order.

        // AF_XDP ring/UMEM configuration
        uint32_t frame_size = 2048;        ///< Size of each UMEM frame.
        uint32_t num_frames = 65536;       ///< Number of UMEM frames in total.
        uint32_t rx_ring    = 4096;        ///< Size of RX ring.

        // XDP mode preferences
        bool prefer_drv_mode   = true;     ///< Prefer native driver mode over generic.
        bool request_zerocopy  = true;     ///< Request zero-copy from the driver when possible.
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

    /// Pointer to the underlying AF_XDP / libbpf implementation.
    std::unique_ptr<Impl, ImplDeleter> impl_{nullptr};

    bool initialized_{false};  ///< True once configure() / configure_from_config() has run.
    bool opened_{false};       ///< True after a successful open(), false after close().
};

} // namespace openpenny
