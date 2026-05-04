// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/agg/FlowKey.h"
#include "openpenny/egress/PacketSink.h"
#include "openpenny/penny/flow/state/PennySnapshot.h"
#include "openpenny/penny/flow/state/PacketDropId.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/net/TrafficMatch.h"

#include <cstddef>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <memory>
#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <unordered_map>
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
    penny::PacketDropId packet_id{0};
    penny::PacketDropSnapshot snapshot{};
    openpenny::app::AggregatedCounters counters{}; // Decorated when exporting/evaluating aggregates.
    std::string thread_name;
};

/**
 * @brief Shared drop snapshot collector across all active pipeline threads.
 *
 * Threads append/update records in their own shard; ordering/sorting happens
 * in the driver.
 */
struct DropCollector {
    static constexpr std::size_t kMaxShards = 128;
    using TimestampRep = std::chrono::steady_clock::duration::rep;
    static constexpr TimestampRep kNoSnapshotTimestamp =
        std::numeric_limits<TimestampRep>::min();

    struct SnapshotKey {
        FlowKey key{};
        penny::PacketDropId packet_id{0};

        bool operator==(const SnapshotKey& other) const noexcept {
            return key == other.key && packet_id == other.packet_id;
        }
    };

    struct SnapshotKeyHash {
        std::size_t operator()(const SnapshotKey& value) const noexcept {
            std::size_t h = FlowKeyHash{}(value.key);
            const auto hs = std::hash<penny::PacketDropId>{}(value.packet_id);
            return h ^ (hs + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        }
    };

    struct alignas(64) Shard {
        mutable std::mutex mtx;
        std::vector<DropSnapshotRecord> snapshots;
        std::unordered_map<SnapshotKey, std::size_t, SnapshotKeyHash> snapshot_index;
        std::atomic<std::size_t> snapshot_count{0};
        std::atomic<std::size_t> pending_snapshot_count{0};
        std::atomic<std::size_t> latest_snapshot_index{0};
        std::atomic<TimestampRep> latest_snapshot_timestamp{kNoSnapshotTimestamp};
    };

    explicit DropCollector(std::size_t requested_shards = 1)
        : shard_count(std::max<std::size_t>(1, std::min(requested_shards, kMaxShards))) {}

    std::atomic<bool> accepting{true};
    std::size_t shard_count{1};
    std::size_t snapshot_limit{0};
    std::atomic<std::size_t> accepted_snapshot_count{0};
    mutable std::mutex frozen_aggregate_counters_mtx;
    std::optional<openpenny::app::AggregatedCounters> frozen_aggregate_counters;
    std::array<Shard, kMaxShards> shards{};

    std::size_t clamp_shard_index(std::size_t idx) const noexcept {
        return idx < shard_count ? idx : shard_count - 1;
    }

    Shard& shard_for(std::size_t idx) noexcept {
        return shards[clamp_shard_index(idx)];
    }

    const Shard& shard_for(std::size_t idx) const noexcept {
        return shards[clamp_shard_index(idx)];
    }
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
    bool closed_loop_stop_hit = false; // True when the configured min_closed_loop_flows threshold was observed.
    // Passive-mode gap summary.
    std::size_t passive_flows_with_open_gaps = 0;
    std::size_t passive_open_gaps = 0;
    std::vector<std::string> passive_gap_summaries;
    std::vector<std::string> closed_loop_flow_summaries;
    std::vector<std::string> duplicate_exceeded_flow_summaries;
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
