// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/agg/Stats.h"
#include "openpenny/egress/PacketSink.h"
#include "openpenny/penny/flow/state/PennySnapshot.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/net/TrafficMatch.h"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <memory>
#include <mutex>
#include <vector>
#include <atomic>

namespace openpenny {
namespace dataplane {
class IFactory;
}

/**
 * @brief Configuration for a pipeline execution invocation.
 *
 * After Chunk 3, this struct only carries information that is specific
 * to a single run of the pipeline: how many queues to drive, which mode
 * to run in, an optional cancellation callback, traffic selection, and
 * (for SDK users) an override egress sink. Everything else — TUN/raw
 * socket selection, NIC/queue binding, BPF/XDP tuning — lives on
 * Config and is read by the pipeline driver directly.
 */
struct PipelineOptions {
    enum class Mode {
        Active,
        Passive
    };

    // Strings
    std::string stats_socket_path; ///< Optional Unix datagram socket for live stats.
    net::TrafficMatchConfig traffic_match{}; ///< Per-run override of cfg.traffic_match.

    // Callbacks
    std::function<bool()> should_stop; ///< Cooperative cancellation callback.

    // Integral types
    unsigned queue_count = 1;     ///< How many queues/threads to spawn, starting at cfg.queue.

    // Mode
    Mode mode{Mode::Active};

    const dataplane::IFactory* dataplane_factory = nullptr; ///< Optional override for session creation.

    /**
     * @brief Optional caller-supplied egress sink.
     *
     * When non-null, the pipeline writes matched packets through this
     * sink instead of constructing one from Config::egress. Intended
     * primarily for tests and SDK callers that want to plug in their
     * own PacketSink implementation; production binaries should leave
     * this null and drive egress declaratively via Config::egress.
     */
    egress::PacketSinkPtr sink;
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
