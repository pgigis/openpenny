// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: AggregatesController::evaluate_pending_if_needed()
// produces the correct verdict for three end-of-run snapshot states:
//
//   1. Expired snapshot      -> NON_CLOSED_LOOP (no retransmission seen).
//   2. Invalid snapshot      -> NON_CLOSED_LOOP (the drop never produced
//      enough evidence either way; verdict still falls negative).
//   3. Expired + duplicate
//      threshold exceeded     -> DUPLICATES_EXCEEDED (duplicate fallback
//      wins over plain not-closed-loop).
//
// If this fails: end-of-run aggregate evaluation produces the wrong
// final status, which is what the CLI / gRPC clients report.

#include "test_helpers.h"

#include "openpenny/app/core/AggregatesController.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/config/Config.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <functional>
#include <memory>

namespace {

openpenny::DropSnapshotRecord make_expired_record() {
    openpenny::DropSnapshotRecord r{};
    r.key.src      = 0x0a000001;
    r.key.dst      = 0x0a000002;
    r.key.sport    = 1111;
    r.key.dport    = 5201;
    r.key.ip_proto = 6;
    r.packet_id    = openpenny::penny::make_packet_drop_id(1000, 100);
    r.snapshot.timestamp = std::chrono::steady_clock::now();
    r.snapshot.state     = openpenny::penny::SnapshotState::Expired;
    for (int i = 0; i < 5; ++i) {
        r.snapshot.stats.record_data_packet();
        r.snapshot.stats.record_droppable_packet();
    }
    r.snapshot.stats.record_drop();
    r.snapshot.stats.inc_non_retransmitted();
    return r;
}

openpenny::DropSnapshotRecord make_invalid_record() {
    auto r = make_expired_record();
    r.snapshot.state = openpenny::penny::SnapshotState::Invalid;
    r.snapshot.stats = {};
    for (int i = 0; i < 5; ++i) {
        r.snapshot.stats.record_data_packet();
        r.snapshot.stats.record_droppable_packet();
    }
    r.snapshot.stats.record_drop();
    return r;
}

openpenny::DropSnapshotRecord make_duplicate_exceeded_record() {
    openpenny::DropSnapshotRecord r{};
    r.key.src      = 0x0a000011;
    r.key.dst      = 0x0a000012;
    r.key.sport    = 2222;
    r.key.dport    = 5201;
    r.key.ip_proto = 6;
    r.packet_id    = openpenny::penny::make_packet_drop_id(2000, 100);
    r.snapshot.timestamp = std::chrono::steady_clock::now();
    r.snapshot.state     = openpenny::penny::SnapshotState::Expired;
    for (int i = 0; i < 10; ++i) {
        r.snapshot.stats.record_data_packet();
        r.snapshot.stats.record_droppable_packet();
    }
    for (int i = 0; i < 2; ++i) r.snapshot.stats.record_duplicate_packet();
    r.snapshot.stats.record_drop();
    r.snapshot.stats.inc_non_retransmitted();
    return r;
}

// Reset runtime to a clean PENDING state before each scenario.
void reset_runtime(openpenny::RuntimeStatus& runtime) {
    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::PENDING);
    runtime.aggregate_eval_counters = {};
    openpenny::set_current_has_aggregate_eval(false);
    openpenny::set_current_aggregates_active(true);
}

} // namespace

int main() {
    using openpenny::test::Section;
    using AggStatus = openpenny::RuntimeStatus::AggregatesStatus;

    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.aggregates_enabled              = true;
    cfg.active.max_drops_aggregates            = 1;
    cfg.active.max_duplicate_fraction          = 1.0;
    cfg.active.retransmission_miss_probability = 0.0;

    openpenny::PipelineOptions opts{};
    opts.mode = openpenny::PipelineOptions::Mode::Active;
    openpenny::set_runtime_setup(cfg, opts, false, false);

    auto& runtime = openpenny::runtime_setup_mutable();
    std::atomic<bool> stop_flag{false};
    auto collector = std::make_shared<openpenny::DropCollector>(1);
    openpenny::AggregatesController controller(
        cfg, opts, collector, stop_flag, std::function<bool()>{});

    {
        Section _{"Expired snapshot -> NON_CLOSED_LOOP"};
        reset_runtime(runtime);

        openpenny::PipelineSummary summary;
        summary.drop_snapshots.push_back(make_expired_record());
        controller.evaluate_pending_if_needed(cfg, summary);

        assert(runtime.aggregates_status == AggStatus::NON_CLOSED_LOOP);
        assert(runtime.has_aggregate_eval);
        assert(controller.aggregates_ready());
        assert(controller.collector_completed());
    }

    {
        Section _{"Invalid snapshot -> NON_CLOSED_LOOP"};
        reset_runtime(runtime);

        openpenny::PipelineSummary summary;
        summary.drop_snapshots.push_back(make_invalid_record());
        controller.evaluate_pending_if_needed(cfg, summary);

        assert(runtime.aggregates_status == AggStatus::NON_CLOSED_LOOP);
        assert(runtime.has_aggregate_eval);
    }

    {
        Section _{"Expired snapshot + duplicate-ratio threshold -> DUPLICATES_EXCEEDED"};
        reset_runtime(runtime);
        cfg.active.max_duplicate_fraction = 0.1; // tighten so 2/10 trips it

        openpenny::PipelineSummary summary;
        summary.drop_snapshots.push_back(make_duplicate_exceeded_record());
        controller.evaluate_pending_if_needed(cfg, summary);

        assert(runtime.aggregates_status == AggStatus::DUPLICATES_EXCEEDED);
        assert(runtime.has_aggregate_eval);
        assert(runtime.aggregate_eval_counters.data_packets      == 10);
        assert(runtime.aggregate_eval_counters.duplicate_packets == 2);
    }

    return 0;
}
