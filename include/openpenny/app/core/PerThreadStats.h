// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "openpenny/agg/Stats.h" // for FlowKey
#include "openpenny/penny/flow/state/PacketDropId.h"

namespace openpenny::app {

// Per-thread counters aligned to cache lines to avoid false sharing.
struct alignas(64) PerThreadStats {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::uint64_t errors{0};
    std::uint64_t flows_monitored{0};
    std::uint64_t active_flows{0};
    std::uint64_t duplicate_packets{0};
    std::uint64_t droppable_packets{0};
    std::uint64_t in_order_packets{0};
    std::uint64_t out_of_order_packets{0};
    std::uint64_t retransmitted_packets{0};
    std::uint64_t non_retransmitted_packets{0};
    std::uint64_t pending_retransmissions{0};
    std::uint64_t dropped_packets{0};
    std::uint64_t pure_ack_packets{0};
    std::uint64_t data_packets{0};
    std::uint64_t flows_finished{0};
    std::uint64_t flows_rst{0};
    std::uint64_t flows_closed_loop{0};
    std::uint64_t flows_not_closed_loop{0};
    std::uint64_t flows_duplicates_exceeded{0};

    struct DropSnapshotInfo {
        FlowKey key{};
        penny::PacketDropId packet_id{0};
        std::uint64_t timestamp_ns{0};
        std::uint64_t duplicates{0};
        std::uint64_t data_packets{0};
        std::uint64_t retransmitted_packets{0};
        std::uint64_t dropped_packets{0};
        std::uint64_t pending_retransmissions{0};
    };
    std::vector<DropSnapshotInfo> drop_snapshots;
};

struct AggregatedCounters {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::uint64_t errors{0};
    std::uint64_t flows_monitored{0};
    std::uint64_t active_flows{0};
    std::uint64_t duplicate_packets{0};
    std::uint64_t droppable_packets{0};
    std::uint64_t in_order_packets{0};
    std::uint64_t out_of_order_packets{0};
    std::uint64_t retransmitted_packets{0};
    std::uint64_t non_retransmitted_packets{0};
    std::uint64_t pending_retransmissions{0};
    std::uint64_t dropped_packets{0};
    std::uint64_t pure_ack_packets{0};
    std::uint64_t data_packets{0};
    std::uint64_t flows_finished{0};
    std::uint64_t flows_rst{0};
    std::uint64_t flows_closed_loop{0};
    std::uint64_t flows_not_closed_loop{0};
    std::uint64_t flows_duplicates_exceeded{0};
};

void init_thread_counters(std::size_t count);
void set_thread_counter_index(std::size_t idx);
std::size_t current_thread_counter_index() noexcept;
PerThreadStats& current_thread_counters();
const std::vector<PerThreadStats>& thread_counters();
AggregatedCounters aggregate_counters();
std::uint64_t aggregate_active_flows();

/**
 * Best-effort aggregate drop-budget reservation across worker slots.
 *
 * Sums the per-worker atomic drop counters and, if the total is still below
 * @p max_total_drops, increments the current worker's slot and returns true.
 * This path is intentionally lock-free and may overshoot slightly under races.
 */
bool try_reserve_aggregate_drop(std::uint64_t max_total_drops) noexcept;

/// Return the current summed value of the per-worker aggregate drop budget.
std::uint64_t aggregate_drop_budget_drops() noexcept;

} // namespace openpenny::app
