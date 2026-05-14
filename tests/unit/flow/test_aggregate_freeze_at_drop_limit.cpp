// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: when the aggregate drop budget is exhausted, the
// DropCollector freezes — further drop-snapshot upserts are rejected,
// existing snapshots can still transition (e.g. expire), and on
// teardown the controller emits NON_CLOSED_LOOP for the snapshot that
// reached terminal state without retransmissions.
//
// Setup:
//   - max_drops_aggregates = 1   (only the first upsert is accepted)
//   - max_duplicate_fraction = 1 (duplicate fallback off)
//   - retransmission_miss_probability = 0
//
// Steps:
//   1. Upsert snapshot A (pending). Budget consumed; accepted=1.
//   2. Upsert snapshot B (pending). Budget full; rejected. accepted stays 1.
//   3. Mutate A to Expired (the late retransmit deadline path) and
//      upsert again — same record, allowed; transitions through.
//   4. populate_drop_snapshots() returns exactly the one frozen record.
//   5. evaluate_pending_if_needed() lifts the verdict to NON_CLOSED_LOOP
//      with aggregate eval counters reflecting snapshot A's stats.
//
// If this fails: the aggregate budget either accepts too many records
// (overshoots `max_drops_aggregates`) or refuses legitimate transitions
// of already-accepted snapshots.

#include "test_helpers.h"

#include "openpenny/app/core/AggregatesController.h"
#include "openpenny/app/core/DropCollectorBinding.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/config/Config.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <functional>
#include <memory>

namespace {

openpenny::FlowKey make_key(std::uint16_t sport) {
    openpenny::FlowKey k{};
    k.src      = 0x0a000001;
    k.dst      = 0x0a000002;
    k.sport    = sport;
    k.dport    = 5201;
    k.ip_proto = 6;
    return k;
}

openpenny::penny::PacketDropSnapshot make_pending_snapshot() {
    openpenny::penny::PacketDropSnapshot s{};
    s.timestamp = std::chrono::steady_clock::now();
    s.state     = openpenny::penny::SnapshotState::Pending;
    s.stats.record_data_packet();
    s.stats.record_droppable_packet();
    s.stats.record_drop();
    s.stats.inc_pending_retransmission();
    return s;
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
    runtime.aggregates_status        = AggStatus::PENDING;
    runtime.aggregate_eval_counters  = {};
    runtime.has_aggregate_eval       = false;
    runtime.aggregates_active        = true;

    std::atomic<bool> stop_flag{false};
    auto collector = std::make_shared<openpenny::DropCollector>(1);
    openpenny::AggregatesController controller(
        cfg, opts, collector, stop_flag, std::function<bool()>{});

    auto& counters = openpenny::app::current_thread_counters();

    const auto first_key  = make_key(40001);
    const auto first_id   = openpenny::penny::make_packet_drop_id(1000, 100);
    auto       first_snap = make_pending_snapshot();

    {
        Section _{"snapshot A (pending) is accepted; budget = 1/1"};
        counters.droppable_packets       = 10;
        counters.data_packets            = 10;
        counters.dropped_packets         = 1;
        counters.pending_retransmissions = 1;

        openpenny::app::DropCollectorBinding::instance().upsert(
            collector, "worker-0", 0, first_key, first_id, first_snap);
    }

    {
        Section _{"snapshot B (pending) is rejected; budget full"};
        counters.droppable_packets       = 100;
        counters.data_packets            = 100;
        counters.dropped_packets         = 2;
        counters.pending_retransmissions = 2;

        const auto second_key  = make_key(40002);
        const auto second_id   = openpenny::penny::make_packet_drop_id(2000, 100);
        auto       second_snap = make_pending_snapshot();

        openpenny::app::DropCollectorBinding::instance().upsert(
            collector, "worker-0", 0, second_key, second_id, second_snap);
        assert(collector->accepted_snapshot_count.load(std::memory_order_relaxed) == 1);
    }

    {
        Section _{"snapshot A transitions to Expired; existing record updates in place"};
        counters.pending_retransmissions   = 0;
        counters.non_retransmitted_packets = 50;
        first_snap.state = openpenny::penny::SnapshotState::Expired;
        first_snap.stats.dec_pending_retransmission();
        first_snap.stats.inc_non_retransmitted();

        openpenny::app::DropCollectorBinding::instance().upsert(
            collector, "worker-0", 0, first_key, first_id, first_snap);
    }

    {
        Section _{"summary exposes exactly the one accepted record"};
        openpenny::PipelineSummary summary;
        controller.populate_drop_snapshots(summary);
        assert(summary.drop_snapshots.size() == 1);

        controller.evaluate_pending_if_needed(cfg, summary);

        assert(runtime.aggregates_status == AggStatus::NON_CLOSED_LOOP);
        assert(runtime.has_aggregate_eval);
        assert(runtime.aggregate_eval_counters.data_packets             == 10);
        assert(runtime.aggregate_eval_counters.duplicate_packets        == 0);
        assert(runtime.aggregate_eval_counters.retransmitted_packets    == 0);
        assert(runtime.aggregate_eval_counters.non_retransmitted_packets == 1);
    }

    return 0;
}
