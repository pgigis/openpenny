// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file Config.h
 * @brief Configuration holder parsed from YAML.
 */
#include <optional>
#include <string>
#include <cstddef>
#include <cstdint>

namespace openpenny {

/**
 * @brief In-memory representation of the YAML configuration file.
 */
struct Config {
    /**
     * @brief Parameters steering Penny-style active decision heuristics.
     */
    struct ActiveConfig {
        bool enabled = true;
        double drop_probability = 0.0;
        double max_duplicate_fraction = 0.15; // ratio of duplicates to unique data packets (e.g., 0.15 == 15%)
        double retransmission_miss_probability = 0.05;
        double drop_state_seconds = 0.0;
        double flow_idle_timeout_seconds = 0.0; // Expire idle flows after this silence (0 disables).
        int    min_drops_per_flow = 0;
        int    max_drops_per_indiv_flow = 0; // When >0, evaluate hypotheses exactly at this drop count.
        int    max_drops_aggregates = 0;     // Optional cross-thread drop cap.
        double rtt_timeout_factor = 3.0;          // absolute timeout (seconds) before expiring drops / promoting data-only flows
        double flow_grace_period_seconds = 3.0; // pending->active wait threshold
        std::size_t max_tracked_flows = 0; // YAML: active.aggregates.max_monitored_flows; 0 means unlimited
        std::size_t stop_after_individual_flows = 0; // When >0, stop once this many individual flows finish.
        double max_out_of_order_fraction = 0.8; // fraction of out-of-order packets allowed
        bool aggregates_enabled = false;   // YAML: active.aggregates.enabled
    };

    struct PassiveConfig {
        bool enabled = false;
        std::size_t min_number_of_flows_to_finish = 0;    // Minimum flows to finish before stopping (0 = disable).
        std::size_t max_parallel_flows = 5;  // Max passive flows tracked concurrently across all threads (0 = unlimited).
        double max_execution_time_seconds = 0.0; // Stop passive processing after this time (0 = no timeout).
        double flow_idle_timeout_seconds = 0.0;  // Evict idle passive flows after this silence.
        double flow_grace_period_seconds = 0.0;  // Reserved for symmetry with active (not enforced for passive).
    };

    /**
     * @brief Runtime switches for wiring in a real AF_XDP data path.
     */
    struct XdpRuntimeConfig {
        bool        enable            = false;   // enable real AF_XDP reader
        bool        attach_program    = true;    // load + attach the BPF program automatically
        bool        detach_on_close   = true;    // detach program when reader closes
        bool        reuse_pins        = false;   // reuse pinned maps without reattaching
        bool        pin_maps          = true;    // pin maps after load for reuse
        bool        update_conf_map   = true;    // write prefix/mask/qid into conf map
        bool        verbose           = false;   // emit verbose libbpf diagnostics
        bool        drop_unmatched    = false;   // drop frames not redirected to TX (unused currently)
        bool        allow_ssh_bypass  = true;    // keep parity with Penny policy (unused but parsed)
        bool        allow_skb_fallback = false;  // prefer failing fast over fallback for perf
        bool        force_copy_mode   = false;   // force copy mode even if zerocopy requested
        bool        require_zerocopy  = true;    // fail if zerocopy cannot be enabled
        bool        allow_copy_fallback = false; // disallow copy-mode fallback to keep ZC
        unsigned    batch             = 256;     // max frames to pull per poll
        unsigned    poll_timeout_ms   = 0;       // busy-poll for lowest latency
        std::string bpf_object        = "xdp_redirect_dstprefix.o";
        std::string bpf_program       = "xdp_redirect_dstprefix";
        std::string map_conf_name     = "conf";
        std::string map_xsks_name     = "xsks_map";
        std::string map_stats_name    = "counters";
        std::string pin_conf_path     = "/sys/fs/bpf/openpenny_conf";
        std::string pin_xsks_path     = "/sys/fs/bpf/openpenny_xsks";
        std::string pin_stats_path    = "/sys/fs/bpf/openpenny_stats";
        std::string prefix_text       = "0.0.0.0";
        std::string mask_text         = "0.0.0.0";
        int         mask_bits         = 0;       // optional alternative mask representation
        uint32_t    prefix_host       = 0;       // derived host-order prefix
        uint32_t    mask_host         = 0;       // derived host-order mask
    };

    struct DpdkConfig {
        bool     enable      = false; // enable DPDK-backed packet source
        unsigned burst       = 32;    // max packets per poll
    };

    // Ingest
    std::string ifname = "lo";     // Interface to attach to.
    unsigned    queue  = 0;        // AF_XDP queue index.
    unsigned    queue_count = 1;   // Number of queues/threads to spawn (starting at queue).
    std::string mode   = "active"; // legacy field (active pipeline runs by default)

    // XDP reader tuning
    bool      xdp_drv_mode = true; // Prefer native driver when attaching XDP.
    bool      zerocopy     = true; // Request AF_XDP zero-copy support.
    unsigned  frame_size   = 2048; // UMEM frame size in bytes.
    unsigned  num_frames   = 65536; // Number of UMEM frames to allocate (larger for 100G).
    unsigned  rx_ring      = 4096; // RX ring depth.
    XdpRuntimeConfig xdp_runtime{};
    DpdkConfig dpdk{};

    // Active mode policy parameters
    ActiveConfig active{};
    PassiveConfig passive{};

    // Logging
    std::string log_mode     = "console"; // console|file|silent
    std::string log_level    = "info";    // trace|debug|info|warn|error
    std::string log_file     = "openpenny.log"; // Only used when mode==file.

    /**
     * @brief Parse configuration from a YAML-like document.
     *
     * @param path File path to read.
     * @return Populated config on success, std::nullopt on failure.
     */
    static std::optional<Config> from_file(const std::string& path);
};

} // namespace openpenny
