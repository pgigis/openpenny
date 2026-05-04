// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/AggregatesController.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/config/Config.h"

#include <atomic>
#include <cassert>
#include <chrono>

namespace {

openpenny::DropSnapshotRecord make_expired_snapshot_record() {
    openpenny::DropSnapshotRecord record{};
    record.key.src = 0x0a000001;
    record.key.dst = 0x0a000002;
    record.key.sport = 1111;
    record.key.dport = 5201;
    record.key.ip_proto = 6;
    record.packet_id = openpenny::penny::make_packet_drop_id(1000, 100);
    record.snapshot.timestamp = std::chrono::steady_clock::now();
    record.snapshot.state = openpenny::penny::SnapshotState::Expired;
    for (int i = 0; i < 5; ++i) {
        record.snapshot.stats.record_data_packet();
        record.snapshot.stats.record_droppable_packet();
    }
    record.snapshot.stats.record_drop();
    record.snapshot.stats.inc_non_retransmitted();
    return record;
}

openpenny::DropSnapshotRecord make_invalid_snapshot_record() {
    auto record = make_expired_snapshot_record();
    record.snapshot.state = openpenny::penny::SnapshotState::Invalid;
    record.snapshot.stats = {};
    for (int i = 0; i < 5; ++i) {
        record.snapshot.stats.record_data_packet();
        record.snapshot.stats.record_droppable_packet();
    }
    record.snapshot.stats.record_drop();
    return record;
}

openpenny::DropSnapshotRecord make_duplicate_exceeded_snapshot_record() {
    openpenny::DropSnapshotRecord record{};
    record.key.src = 0x0a000011;
    record.key.dst = 0x0a000012;
    record.key.sport = 2222;
    record.key.dport = 5201;
    record.key.ip_proto = 6;
    record.packet_id = openpenny::penny::make_packet_drop_id(2000, 100);
    record.snapshot.timestamp = std::chrono::steady_clock::now();
    record.snapshot.state = openpenny::penny::SnapshotState::Expired;
    for (int i = 0; i < 10; ++i) {
        record.snapshot.stats.record_data_packet();
        record.snapshot.stats.record_droppable_packet();
    }
    for (int i = 0; i < 2; ++i) {
        record.snapshot.stats.record_duplicate_packet();
    }
    record.snapshot.stats.record_drop();
    record.snapshot.stats.inc_non_retransmitted();
    return record;
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
    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::PENDING);
    runtime.aggregate_eval_counters = {};
    openpenny::set_current_has_aggregate_eval(false);
    openpenny::set_current_aggregates_active(true);

    std::atomic<bool> stop_flag{false};
    auto collector = std::make_shared<openpenny::DropCollector>(1);
    openpenny::AggregatesController controller(
        cfg,
        opts,
        collector,
        stop_flag,
        std::function<bool()>{});

    openpenny::PipelineSummary summary;
    summary.drop_snapshots.push_back(make_expired_snapshot_record());

    controller.evaluate_pending_if_needed(cfg, summary);

    assert(runtime.aggregates_status ==
           openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    assert(runtime.has_aggregate_eval);
    assert(controller.aggregates_ready());
    assert(controller.collector_completed());

    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::PENDING);
    runtime.aggregate_eval_counters = {};
    openpenny::set_current_has_aggregate_eval(false);
    openpenny::set_current_aggregates_active(true);

    openpenny::PipelineSummary invalid_summary;
    invalid_summary.drop_snapshots.push_back(make_invalid_snapshot_record());

    controller.evaluate_pending_if_needed(cfg, invalid_summary);

    assert(runtime.aggregates_status ==
           openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    assert(runtime.has_aggregate_eval);

    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::PENDING);
    runtime.aggregate_eval_counters = {};
    openpenny::set_current_has_aggregate_eval(false);
    openpenny::set_current_aggregates_active(true);
    cfg.active.max_duplicate_fraction = 0.1;

    openpenny::PipelineSummary duplicate_summary;
    duplicate_summary.drop_snapshots.push_back(make_duplicate_exceeded_snapshot_record());

    controller.evaluate_pending_if_needed(cfg, duplicate_summary);

    assert(runtime.aggregates_status ==
           openpenny::RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED);
    assert(runtime.has_aggregate_eval);
    assert(runtime.aggregate_eval_counters.data_packets == 10);
    assert(runtime.aggregate_eval_counters.duplicate_packets == 2);

    return 0;
}
