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
#include <thread>

namespace {

openpenny::FlowKey make_key() {
    openpenny::FlowKey key{};
    key.src = 0x0a000011;
    key.dst = 0x0a000012;
    key.sport = 2222;
    key.dport = 5201;
    key.ip_proto = 6;
    return key;
}

openpenny::penny::PacketDropSnapshot make_duplicate_exceeded_snapshot() {
    openpenny::penny::PacketDropSnapshot snap{};
    snap.timestamp = std::chrono::steady_clock::now();
    snap.state = openpenny::penny::SnapshotState::Expired;
    for (int i = 0; i < 10; ++i) {
        snap.stats.record_data_packet();
        snap.stats.record_droppable_packet();
    }
    for (int i = 0; i < 2; ++i) {
        snap.stats.record_duplicate_packet();
    }
    snap.stats.record_drop();
    snap.stats.inc_non_retransmitted();
    return snap;
}

} // namespace

int main() {
    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.aggregates_enabled = true;
    cfg.active.max_drops_aggregates = 1;
    cfg.active.max_duplicate_fraction = 0.1;
    cfg.active.retransmission_miss_probability = 0.0;
    cfg.active.min_closed_loop_flows = 0;

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
    controller.start();

    auto& counters = openpenny::app::current_thread_counters();
    counters.droppable_packets = 10;
    counters.data_packets = 10;
    counters.duplicate_packets = 2;
    counters.dropped_packets = 1;
    counters.non_retransmitted_packets = 1;
    counters.pending_retransmissions = 0;

    openpenny::app::DropCollectorBinding::instance().upsert(
        collector,
        "worker-0",
        0,
        make_key(),
        openpenny::penny::make_packet_drop_id(2000, 100),
        make_duplicate_exceeded_snapshot());

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (runtime.aggregates_status == openpenny::RuntimeStatus::AggregatesStatus::PENDING &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    assert(runtime.aggregates_status ==
           openpenny::RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED);
    assert(runtime.has_aggregate_eval);
    assert(runtime.aggregate_eval_counters.data_packets == 10);
    assert(runtime.aggregate_eval_counters.duplicate_packets == 2);
    assert(!runtime.aggregates_active);
    assert(!collector->accepting.load(std::memory_order_relaxed));
    assert(!controller.collector_completed());
    assert(!stop_flag.load(std::memory_order_relaxed));

    stop_flag.store(true, std::memory_order_relaxed);
    controller.join();
    return 0;
}
