// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/AggregatesController.h"
#include "openpenny/app/core/DropCollectorBinding.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/config/Config.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

namespace {

openpenny::FlowKey make_key(std::uint16_t sport) {
    openpenny::FlowKey key{};
    key.src = 0x0a000001;
    key.dst = 0x0a000002;
    key.sport = sport;
    key.dport = 5201;
    key.ip_proto = 6;
    return key;
}

openpenny::penny::PacketDropSnapshot make_pending_snapshot() {
    openpenny::penny::PacketDropSnapshot snap{};
    snap.timestamp = std::chrono::steady_clock::now();
    snap.state = openpenny::penny::SnapshotState::Pending;
    snap.stats.record_data_packet();
    snap.stats.record_droppable_packet();
    snap.stats.record_drop();
    snap.stats.inc_pending_retransmission();
    return snap;
}

} // namespace

int main() {
    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.aggregates_enabled = true;
    cfg.active.max_drops_aggregates = 1;
    cfg.active.max_duplicate_fraction = 1.0;
    cfg.active.retransmission_miss_probability = 0.0;

    openpenny::PipelineOptions opts{};
    opts.mode = openpenny::PipelineOptions::Mode::Active;

    openpenny::set_runtime_setup(cfg, opts, false, false);
    auto& runtime = openpenny::runtime_setup_mutable();
    runtime.aggregates_status = openpenny::RuntimeStatus::AggregatesStatus::PENDING;
    runtime.aggregate_eval_counters = {};
    runtime.has_aggregate_eval = false;
    runtime.aggregates_active = true;

    std::atomic<bool> stop_flag{false};
    auto collector = std::make_shared<openpenny::DropCollector>(1);
    openpenny::AggregatesController controller(
        cfg,
        opts,
        collector,
        stop_flag,
        std::function<bool()>{});

    auto& counters = openpenny::app::current_thread_counters();
    counters.droppable_packets = 10;
    counters.data_packets = 10;
    counters.dropped_packets = 1;
    counters.pending_retransmissions = 1;

    const auto first_key = make_key(40001);
    const auto first_id = openpenny::penny::make_packet_drop_id(1000, 100);
    auto first_snapshot = make_pending_snapshot();
    openpenny::app::DropCollectorBinding::instance().upsert(
        collector,
        "worker-0",
        0,
        first_key,
        first_id,
        first_snapshot);

    counters.droppable_packets = 100;
    counters.data_packets = 100;
    counters.dropped_packets = 2;
    counters.pending_retransmissions = 2;

    const auto second_key = make_key(40002);
    const auto second_id = openpenny::penny::make_packet_drop_id(2000, 100);
    auto second_snapshot = make_pending_snapshot();
    openpenny::app::DropCollectorBinding::instance().upsert(
        collector,
        "worker-0",
        0,
        second_key,
        second_id,
        second_snapshot);

    assert(collector->accepted_snapshot_count.load(std::memory_order_relaxed) == 1);

    counters.pending_retransmissions = 0;
    counters.non_retransmitted_packets = 50;
    first_snapshot.state = openpenny::penny::SnapshotState::Expired;
    first_snapshot.stats.dec_pending_retransmission();
    first_snapshot.stats.inc_non_retransmitted();
    openpenny::app::DropCollectorBinding::instance().upsert(
        collector,
        "worker-0",
        0,
        first_key,
        first_id,
        first_snapshot);

    openpenny::PipelineSummary summary;
    controller.populate_drop_snapshots(summary);
    assert(summary.drop_snapshots.size() == 1);

    controller.evaluate_pending_if_needed(cfg, summary);

    assert(runtime.aggregates_status ==
           openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    assert(runtime.has_aggregate_eval);
    assert(runtime.aggregate_eval_counters.data_packets == 10);
    assert(runtime.aggregate_eval_counters.duplicate_packets == 0);
    assert(runtime.aggregate_eval_counters.retransmitted_packets == 0);
    assert(runtime.aggregate_eval_counters.non_retransmitted_packets == 1);

    return 0;
}
