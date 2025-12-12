// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/agg/Stats.h"
#include "openpenny/penny/flow/state/PennySnapshot.h"
#include "openpenny/app/core/PerThreadStats.h"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <memory>
#include <mutex>
#include <vector>
#include <atomic>

namespace openpenny {
namespace net {
class IPacketSourceFactory;
}

/**
 * @brief Configuration for a pipeline execution invocation.
 */
struct PipelineOptions {
    enum class Mode {
        Active,
        Passive
    };

    // Strings
    std::string prefix_ip;        // Raw dotted prefix entered by user.
    std::string prefix_cidr;      // Canonical CIDR string derived from prefix/mask.
    std::string tun_name;         // Friendly label for logging/UX.
    std::string stats_socket_path; // Optional Unix datagram socket for live stats.
    std::string forward_device;   // Optional non-TUN forward target label.

    // Callbacks
    std::function<bool()> should_stop; // Cooperative cancellation callback.

    // Integral types
    uint32_t prefix_host = 0;     // Host-order prefix used for fast comparisons.
    uint32_t mask_host = 0;       // Host-order mask (0 means disabled).
    unsigned queue_count = 1;     // How many queues/threads to spawn, starting at cfg.queue.
    int mask_bits = 0;            // Original number of prefix bits (if provided).
    int tun_fd = -1;              // Optional TUN file descriptor to forward to.
    int forward_fd = -1;          // Generic forward target file descriptor (raw socket, pipe, etc.).

    // Mode
    Mode mode{Mode::Active};

    // Flags
    bool has_prefix = false;      // Whether prefix filtering is enabled at all.
    bool forward_to_tun = false;  // Mirror matched packets into a TUN device.
    bool forward_raw_socket = false; // Forward packets via raw socket bound to an interface.
    const net::IPacketSourceFactory* packet_source_factory = nullptr; // Optional override for source creation.
};

struct DropSnapshotRecord {
    FlowKey key{};
    std::string packet_id;
    penny::PacketDropSnapshot snapshot{};
    openpenny::app::AggregatedCounters counters{};
    std::string thread_name;
};

/**
 * @brief Shared drop snapshot collector across all active pipeline threads.
 *
 * Threads append/update records here; ordering/sorting happens in the driver.
 */
struct DropCollector {
    std::mutex mtx;
    std::atomic<bool> accepting{true};
    std::vector<DropSnapshotRecord> snapshots;
};

using DropCollectorPtr = std::shared_ptr<DropCollector>;

/**
 * @brief Execution summary for the active pipeline.
 */
struct ModeResult {
    std::size_t packets_processed = 0;
    std::size_t packets_forwarded = 0;
    std::size_t forward_errors = 0;
    std::size_t pure_ack_packets = 0;
    std::size_t data_packets = 0;
    std::size_t duplicate_packets = 0;
    std::size_t in_order_packets = 0;
    std::size_t out_of_order_packets = 0;
    std::size_t retransmitted_packets = 0;
    std::size_t non_retransmitted_packets = 0;
    std::size_t pending_retransmissions = 0;
    std::size_t flows_tracked_syn = 0;
    std::size_t flows_tracked_data = 0;
    bool penny_completed = false; // True when Penny heuristics triggered shutdown.
    bool aggregates_penny_completed = false; // Flag representing aggregate Penny status.
    // Passive-mode gap summary.
    std::size_t passive_flows_with_open_gaps = 0;
    std::size_t passive_open_gaps = 0;
    std::vector<std::string> passive_gap_summaries;
    std::size_t passive_flows_rst = 0;
    std::size_t passive_flows_syn_only = 0;
    std::size_t passive_flows_finished = 0;
    std::optional<openpenny::app::AggregatedCounters> aggregates_snapshot;
};

/**
 * @brief Aggregated results from the pipeline driver.
 */
struct PipelineSummary {
    std::optional<ModeResult> active; // Populated when active pipeline runs.
    bool aggregates_enabled = false;  // Whether aggregate-wide limits/logic are active.
    std::vector<DropSnapshotRecord> drop_snapshots; // Collected drop snapshots across threads (newest first).
};

/**
 * @brief Snapshot of the current runtime setup for observer threads.
 */
struct RuntimeStatus {
    Config config{};
    PipelineOptions options{};
    bool use_xdp = false;
    bool use_dpdk = false;

    enum class AggregatesStatus {
        PENDING,
        CLOSED_LOOP,
        NON_CLOSED_LOOP,
        DUPLICATES_EXCEEDED
    };

    bool aggregates_active = true;
    bool testing_finished = false;
    AggregatesStatus aggregates_status{AggregatesStatus::PENDING};
    struct AggregateEvalCounters {
        std::uint64_t data_packets{0};
        std::uint64_t duplicate_packets{0};
        std::uint64_t retransmitted_packets{0};
        std::uint64_t non_retransmitted_packets{0};
    } aggregate_eval_counters{};
    bool has_aggregate_eval{false};

};

using RuntimeSetupSnapshot = RuntimeStatus;

/**
 * @brief Store the current runtime setup so worker threads can inspect it.
 */
void set_runtime_setup(const Config& cfg,
                       const PipelineOptions& opts,
                       bool use_xdp,
                       bool use_dpdk);

/**
 * @brief Retrieve the most recently stored runtime setup snapshot.
 */
const RuntimeSetupSnapshot& current_runtime_setup();

/**
 * @brief Drive the active pipeline according to options.
 *
 * Builds a packet source, wires the appropriate pipeline runner, and returns the run summary.
 */
PipelineSummary drive_pipeline(const Config& cfg, const PipelineOptions& opts);

/**
 * @brief Run drive_pipeline on a dedicated thread and return its summary.
 *
 * Useful when callers want pipeline work (and its per-queue worker threads)
 * offloaded from the invoking thread while retaining synchronous semantics.
 */
PipelineSummary drive_pipeline_threaded(const Config& cfg, const PipelineOptions& opts);

} // namespace openpenny
