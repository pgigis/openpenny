// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/AggregatesController.h"

#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/log/Log.h"
#include "openpenny/penny/flow/engine/FlowEvaluation.h"

#include <algorithm>

namespace openpenny {
namespace {

DropCollector::TimestampRep snapshot_timestamp(
    const penny::PacketDropSnapshot& snap) noexcept {
    return snap.timestamp.time_since_epoch().count();
}

bool is_pending_snapshot(const penny::PacketDropSnapshot& snap) noexcept {
    return snap.state == penny::SnapshotState::Pending;
}

void set_runtime_eval_counters(RuntimeStatus& runtime,
                               const penny::PennyStats& stats) {
    runtime.aggregate_eval_counters.data_packets = stats.droppable_packets();
    runtime.aggregate_eval_counters.duplicate_packets = stats.duplicate_packets();
    runtime.aggregate_eval_counters.retransmitted_packets = stats.retransmitted_packets();
    runtime.aggregate_eval_counters.non_retransmitted_packets = stats.non_retransmitted_packets();
}

void set_runtime_eval_counters(RuntimeStatus& runtime,
                               const openpenny::app::AggregatedCounters& agg) {
    runtime.aggregate_eval_counters.data_packets = agg.droppable_packets;
    runtime.aggregate_eval_counters.duplicate_packets = agg.duplicate_packets;
    runtime.aggregate_eval_counters.retransmitted_packets = agg.retransmitted_packets;
    runtime.aggregate_eval_counters.non_retransmitted_packets = agg.non_retransmitted_packets;
}

void store_aggregate_snapshot_once(
    std::optional<openpenny::app::AggregatedCounters>& snapshot_slot,
    std::mutex& snapshot_mtx,
    const openpenny::app::AggregatedCounters& agg) {
    std::lock_guard<std::mutex> lk(snapshot_mtx);
    if (!snapshot_slot) snapshot_slot = agg;
}

std::optional<openpenny::app::AggregatedCounters> collect_frozen_aggregate_counters(
    const DropCollector& collector) {
    std::lock_guard<std::mutex> lock(collector.frozen_aggregate_counters_mtx);
    return collector.frozen_aggregate_counters;
}

penny::PennyStats make_eval_stats_from_aggregates(
    const openpenny::app::AggregatedCounters& agg) {
    penny::PennyStats stats;
    stats.overwrite_from_aggregates(agg);
    return stats;
}

std::vector<DropSnapshotRecord> collect_all_drop_snapshots(
    const DropCollector& collector) {
    std::vector<DropSnapshotRecord> out;
    std::size_t total = 0;
    for (std::size_t shard_index = 0; shard_index < collector.shard_count; ++shard_index) {
        const auto& shard = collector.shard_for(shard_index);
        total += shard.snapshot_count.load(std::memory_order_relaxed);
    }
    out.reserve(total);
    for (std::size_t shard_index = 0; shard_index < collector.shard_count; ++shard_index) {
        const auto& shard = collector.shard_for(shard_index);
        std::lock_guard<std::mutex> lock(shard.mtx);
        out.insert(out.end(), shard.snapshots.begin(), shard.snapshots.end());
    }
    return out;
}

std::optional<DropSnapshotRecord> collect_latest_drop_snapshot(
    const DropCollector& collector) {
    std::size_t best_shard_index = 0;
    auto best_timestamp = DropCollector::kNoSnapshotTimestamp;
    for (std::size_t shard_index = 0; shard_index < collector.shard_count; ++shard_index) {
        const auto& shard = collector.shard_for(shard_index);
        if (shard.snapshot_count.load(std::memory_order_relaxed) == 0) {
            continue;
        }
        const auto latest_timestamp =
            shard.latest_snapshot_timestamp.load(std::memory_order_relaxed);
        if (latest_timestamp >= best_timestamp) {
            best_timestamp = latest_timestamp;
            best_shard_index = shard_index;
        }
    }
    if (best_timestamp == DropCollector::kNoSnapshotTimestamp) {
        return std::nullopt;
    }

    const auto& best_shard = collector.shard_for(best_shard_index);
    {
        std::lock_guard<std::mutex> lock(best_shard.mtx);
        const auto latest_index =
            best_shard.latest_snapshot_index.load(std::memory_order_relaxed);
        if (latest_index < best_shard.snapshots.size()) {
            auto record = best_shard.snapshots[latest_index];
            if (snapshot_timestamp(record.snapshot) == best_timestamp) {
                return record;
            }
        }
    }

    std::optional<DropSnapshotRecord> latest;
    for (std::size_t shard_index = 0; shard_index < collector.shard_count; ++shard_index) {
        const auto& shard = collector.shard_for(shard_index);
        std::lock_guard<std::mutex> lock(shard.mtx);
        auto it = std::max_element(
            shard.snapshots.begin(),
            shard.snapshots.end(),
            [](const DropSnapshotRecord& a, const DropSnapshotRecord& b) {
                return a.snapshot.timestamp < b.snapshot.timestamp;
            });
        if (it == shard.snapshots.end()) {
            continue;
        }
        if (!latest || latest->snapshot.timestamp < it->snapshot.timestamp) {
            latest = *it;
        }
    }
    return latest;
}

struct CollectorSnapshotSummary {
    std::size_t snapshot_count{0};
    std::size_t pending_snapshot_count{0};
};

CollectorSnapshotSummary summarize_collector_snapshots(const DropCollector& collector) {
    CollectorSnapshotSummary summary;
    for (std::size_t shard_index = 0; shard_index < collector.shard_count; ++shard_index) {
        const auto& shard = collector.shard_for(shard_index);
        summary.snapshot_count += shard.snapshot_count.load(std::memory_order_relaxed);
        summary.pending_snapshot_count +=
            shard.pending_snapshot_count.load(std::memory_order_relaxed);
    }
    return summary;
}

CollectorSnapshotSummary summarize_drop_snapshots(
    const std::vector<DropSnapshotRecord>& snapshots) {
    CollectorSnapshotSummary summary;
    summary.snapshot_count = snapshots.size();
    summary.pending_snapshot_count = static_cast<std::size_t>(std::count_if(
        snapshots.begin(),
        snapshots.end(),
        [](const DropSnapshotRecord& record) {
            return is_pending_snapshot(record.snapshot);
        }));
    return summary;
}

bool aggregates_ready_for_evaluation(std::size_t required_drops,
                                     std::size_t snapshot_count,
                                     std::size_t pending_snapshot_count,
                                     std::uint64_t pending_rtx_count) noexcept {
    return required_drops > 0 &&
           snapshot_count >= required_drops &&
           pending_snapshot_count == 0 &&
           pending_rtx_count == 0;
}

} // namespace

AggregatesController::AggregatesController(const Config& cfg,
                                           const PipelineOptions& opts,
                                           DropCollectorPtr collector,
                                           std::atomic<bool>& stop_flag,
                                           const std::function<bool()>& user_should_stop)
    : cfg_{cfg},
      collector_{std::move(collector)},
      stop_flag_{stop_flag},
      user_should_stop_{user_should_stop},
      required_drops_{static_cast<std::size_t>(std::max(0, cfg.active.max_drops_aggregates))},
      collector_enabled_{cfg.active.aggregates_enabled &&
                         opts.mode == PipelineOptions::Mode::Active &&
                         required_drops_ > 0},
      individual_limit_enabled_{opts.mode == PipelineOptions::Mode::Active &&
                                cfg.active.stop_after_individual_flows > 0},
      min_closed_loop_enabled_{opts.mode == PipelineOptions::Mode::Active &&
                               cfg.active.min_closed_loop_flows > 0} {
    if (collector_enabled_ && collector_) {
        collector_->snapshot_limit = required_drops_;
    }
}

void AggregatesController::start() {
    if (collector_enabled_) {
        collector_thread_ = std::thread([this]() { collector_loop(); });
    }
}

void AggregatesController::start_individual_limit() {
    if (individual_limit_enabled_) {
        individual_limit_thread_ = std::thread([this]() { individual_limit_loop(); });
    }
}

void AggregatesController::start_min_closed_loop() {
    if (min_closed_loop_enabled_) {
        min_closed_loop_thread_ = std::thread([this]() { min_closed_loop_loop(); });
    }
}

void AggregatesController::join() {
    if (collector_thread_.joinable()) {
        collector_thread_.join();
    }
    if (individual_limit_thread_.joinable()) {
        individual_limit_thread_.join();
    }
    if (min_closed_loop_thread_.joinable()) {
        min_closed_loop_thread_.join();
    }
}

bool AggregatesController::collector_completed() const {
    return collector_completed_.load(std::memory_order_relaxed);
}

bool AggregatesController::aggregates_ready() const {
    return aggregates_ready_.load(std::memory_order_relaxed);
}

bool AggregatesController::individual_stop_hit() const {
    return individual_stop_hit_.load(std::memory_order_relaxed);
}

bool AggregatesController::closed_loop_stop_hit() const {
    return closed_loop_stop_hit_.load(std::memory_order_relaxed);
}

std::optional<openpenny::app::AggregatedCounters> AggregatesController::aggregates_snapshot() const {
    std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
    return aggregates_snapshot_;
}

void AggregatesController::populate_drop_snapshots(PipelineSummary& summary) const {
    if (!collector_) return;
    auto snaps = collect_all_drop_snapshots(*collector_);
    std::sort(
        snaps.begin(),
        snaps.end(),
        [](const DropSnapshotRecord& a, const DropSnapshotRecord& b) {
            return a.snapshot.timestamp > b.snapshot.timestamp;
        });
    summary.drop_snapshots = std::move(snaps);
}

void AggregatesController::evaluate_pending_if_needed(const Config& cfg,
                                                      PipelineSummary& summary) {
    auto& runtime = runtime_setup_mutable();
    const auto snapshot_summary = summarize_drop_snapshots(summary.drop_snapshots);
    const auto agg = openpenny::app::aggregate_counters();
    const auto frozen_agg =
        collector_ ? collect_frozen_aggregate_counters(*collector_) : std::nullopt;
    const auto pending_rtx_count =
        frozen_agg ? frozen_agg->pending_retransmissions : agg.pending_retransmissions;
    const bool ready = aggregates_ready_for_evaluation(
        required_drops_,
        snapshot_summary.snapshot_count,
        snapshot_summary.pending_snapshot_count,
        pending_rtx_count);
    if (!cfg.active.aggregates_enabled ||
        current_aggregates_status() != RuntimeStatus::AggregatesStatus::PENDING ||
        !ready ||
        summary.drop_snapshots.empty()) {
        return;
    }
    aggregates_ready_.store(true, std::memory_order_relaxed);
    if (frozen_agg) {
        store_aggregate_snapshot_once(aggregates_snapshot_, aggregates_snapshot_mtx_, *frozen_agg);
    } else {
        store_aggregate_snapshot_once(aggregates_snapshot_, aggregates_snapshot_mtx_, agg);
    }
    const auto& latest = summary.drop_snapshots.front();
    const auto stats = frozen_agg
        ? make_eval_stats_from_aggregates(*frozen_agg)
        : latest.snapshot.stats;
    const auto miss_prob = std::clamp(
        cfg.active.retransmission_miss_probability,
        0.0,
        1.0);
    const auto eval = penny::evaluate_flow_decision(
        stats,
        miss_prob,
        cfg.active.max_duplicate_fraction);
    if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP) {
        set_current_aggregates_status(RuntimeStatus::AggregatesStatus::CLOSED_LOOP);
    } else if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP) {
        set_current_aggregates_status(RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    } else if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED) {
        set_current_aggregates_status(RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED);
    } else {
        set_current_aggregates_status(RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    }
    set_current_has_aggregate_eval(true);
    if (frozen_agg) {
        set_runtime_eval_counters(runtime, *frozen_agg);
    } else {
        set_runtime_eval_counters(runtime, stats);
    }
    collector_completed_.store(true, std::memory_order_relaxed);
}

void AggregatesController::collector_loop() {
    using namespace std::chrono_literals;
    // High-level contract for this loop:
    //
    //   1. Wait until `max_drops_aggregates` drop snapshots have been
    //      collected across all worker threads (the "12-drop" trigger
    //      point in the operator's mental model).
    //   2. Evaluate the aggregate stats once.
    //         - bidirectional / closed-loop -> stop the pipeline and
    //           report CLOSED_LOOP.
    //         - anything else
    //           (NON_CLOSED_LOOP or DUPLICATES_EXCEEDED)
    //           -> freeze the aggregate verdict, then switch to the
    //           separate per-flow phase.
    //   3. Watch the per-flow CLOSED_LOOP termination tally and stop as
    //      soon as it reaches `min_closed_loop_flows` (defaulting to 2
    //      when the operator did not configure it). This is a separate
    //      per-flow stop condition; it does NOT rewrite the aggregate
    //      verdict from step 2.
    auto& runtime = runtime_setup_mutable();
    bool aggregate_eval_done = false;
    bool wait_for_closed_loops = false;
    bool ready_logged = false;
    // Resolve the closed-loop fallback threshold once. An explicit
    // operator setting wins outright (including 1, for the rare
    // "any single closed-loop flow is enough" mode); when unset, fall
    // back to the historical default of 2 closed-loop flows.
    const std::size_t closed_loop_required =
        cfg_.active.min_closed_loop_flows > 0
            ? cfg_.active.min_closed_loop_flows
            : static_cast<std::size_t>(2);
    auto finalize_aggregate_verdict =
        [&](RuntimeStatus::AggregatesStatus status,
            const std::optional<openpenny::app::AggregatedCounters>& frozen_agg,
            const openpenny::app::AggregatedCounters& agg_now,
            const std::optional<penny::PennyStats>& stats) {
            set_current_aggregates_status(status);
            set_current_aggregates_active(false);
            set_current_has_aggregate_eval(true);
            if (frozen_agg) {
                set_runtime_eval_counters(runtime, *frozen_agg);
                store_aggregate_snapshot_once(
                    aggregates_snapshot_,
                    aggregates_snapshot_mtx_,
                    *frozen_agg);
            } else if (stats) {
                set_runtime_eval_counters(runtime, *stats);
                store_aggregate_snapshot_once(
                    aggregates_snapshot_,
                    aggregates_snapshot_mtx_,
                    agg_now);
            } else {
                set_runtime_eval_counters(runtime, agg_now);
                store_aggregate_snapshot_once(
                    aggregates_snapshot_,
                    aggregates_snapshot_mtx_,
                    agg_now);
            }
        };
    auto switch_to_individual_flow_phase =
        [&](RuntimeStatus::AggregatesStatus status,
            const char* verdict_text,
            const std::optional<openpenny::app::AggregatedCounters>& frozen_agg,
            const openpenny::app::AggregatedCounters& agg_now,
            const std::optional<penny::PennyStats>& stats) {
            finalize_aggregate_verdict(status, frozen_agg, agg_now, stats);
            aggregate_eval_done = true;
            wait_for_closed_loops = true;
            TCPLOG_INFO(
                "[agg_phase] action=switch_to_individual agg_status=%s drops=%zu "
                "next=individual wait_closed_loop_flows=%llu",
                verdict_text,
                required_drops_,
                static_cast<unsigned long long>(closed_loop_required));
        };
    while (!stop_flag_.load(std::memory_order_relaxed)) {
        if (user_should_stop_ && user_should_stop_()) break;
        if (wait_for_closed_loops) {
            auto agg = openpenny::app::aggregate_counters();
            if (agg.flows_closed_loop >= closed_loop_required) {
                TCPLOG_INFO(
                    "[closed_loop_threshold] flows_closed_loop=%llu flows_not_closed_loop=%llu flows_finished=%llu "
                    "aggregate_status=%d",
                    static_cast<unsigned long long>(agg.flows_closed_loop),
                    static_cast<unsigned long long>(agg.flows_not_closed_loop),
                    static_cast<unsigned long long>(agg.flows_finished),
                    static_cast<int>(current_aggregates_status()));
                collector_completed_.store(true, std::memory_order_relaxed);
                closed_loop_stop_hit_.store(true, std::memory_order_relaxed);
                stop_flag_.store(true, std::memory_order_relaxed);
                break;
            }
            std::this_thread::sleep_for(25ms);
            continue;
        }
        bool ready = false;
        std::size_t snapshot_count = 0;
        std::size_t pending_snapshot_count = 0;
        std::uint64_t pending_rtx_count = 0;
        {
            const auto collector_summary = summarize_collector_snapshots(*collector_);
            const auto frozen_agg = collect_frozen_aggregate_counters(*collector_);
            snapshot_count = collector_summary.snapshot_count;
            pending_snapshot_count = collector_summary.pending_snapshot_count;
            pending_rtx_count = frozen_agg
                ? frozen_agg->pending_retransmissions
                : openpenny::app::aggregate_counters().pending_retransmissions;
            ready = aggregates_ready_for_evaluation(
                required_drops_,
                snapshot_count,
                pending_snapshot_count,
                pending_rtx_count);
        }
        // Periodic gate diagnostic: when snapshot_count has reached the
        // required threshold but ready stays false, this line tells the
        // operator EXACTLY which gate is still held closed.
        if (snapshot_count >= required_drops_ && !ready) {
            using Clock = std::chrono::steady_clock;
            static std::atomic<Clock::rep> g_last_gate_log_ns{0};
            const auto now_ns = Clock::now().time_since_epoch().count();
            auto last = g_last_gate_log_ns.load(std::memory_order_relaxed);
            const auto next =
                (Clock::now() + std::chrono::seconds(5)).time_since_epoch().count();
            if (now_ns - last >= std::chrono::seconds(5).count() &&
                g_last_gate_log_ns.compare_exchange_strong(
                    last, next, std::memory_order_acq_rel)) {
                TCPLOG_INFO(
                    "[agg_wait] drops=%zu/%zu pending_snapshots=%zu pending_rtx=%llu "
                    "state=waiting",
                    snapshot_count,
                    required_drops_,
                    pending_snapshot_count,
                    static_cast<unsigned long long>(pending_rtx_count));
            }
        }
        if (ready) {
            aggregates_ready_.store(true, std::memory_order_relaxed);
            if (!ready_logged) {
                TCPLOG_INFO(
                    "[agg_ready] drops=%zu required=%zu",
                    snapshot_count,
                    required_drops_);
                ready_logged = true;
            }
            collector_->accepting.store(false, std::memory_order_relaxed);
            const auto agg_now = openpenny::app::aggregate_counters();
            const auto frozen_agg = collect_frozen_aggregate_counters(*collector_);
            const auto eval_stats = frozen_agg
                ? make_eval_stats_from_aggregates(*frozen_agg)
                : penny::PennyStats{};
            if (cfg_.active.max_duplicate_fraction > 0.0) {
                const auto dup_data_packets =
                    frozen_agg ? eval_stats.data_packets() : agg_now.data_packets;
                const auto dup_packets =
                    frozen_agg ? eval_stats.duplicate_packets() : agg_now.duplicate_packets;
                if (dup_data_packets > 0) {
                    const double agg_dup_ratio = static_cast<double>(dup_packets) /
                                                 static_cast<double>(dup_data_packets);
                    if (agg_dup_ratio > cfg_.active.max_duplicate_fraction) {
                        switch_to_individual_flow_phase(
                            RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED,
                            "duplicates_exceeded",
                            frozen_agg,
                            agg_now,
                            std::nullopt);
                    }
                }
            }
            if (!aggregate_eval_done) {
                aggregate_eval_done = true;
                auto latest_snapshot = collect_latest_drop_snapshot(*collector_);

                if (latest_snapshot) {
                    const auto pending_window_rtx = frozen_agg
                        ? frozen_agg->pending_retransmissions
                        : agg_now.pending_retransmissions;
                    if (pending_window_rtx > 0) {
                        continue;
                    }
                    const auto stats = frozen_agg
                        ? make_eval_stats_from_aggregates(*frozen_agg)
                        : latest_snapshot->snapshot.stats;
                    const auto miss_prob = std::clamp(
                        cfg_.active.retransmission_miss_probability,
                        0.0,
                        1.0);
                    const auto data_pkts = stats.data_packets();
                    const bool dup_threshold_hit =
                        cfg_.active.max_duplicate_fraction > 0.0 &&
                        data_pkts > 0 &&
                        (static_cast<double>(stats.duplicate_packets()) /
                         static_cast<double>(data_pkts)) > cfg_.active.max_duplicate_fraction;
                    const auto eval = penny::evaluate_flow_decision(
                        stats,
                        miss_prob,
                        cfg_.active.max_duplicate_fraction);
                    const auto packet_id_text = penny::format_packet_drop_id(latest_snapshot->packet_id);
                    const auto* eval_verdict_text = [&]() -> const char* {
                        switch (eval.decision) {
                            case penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP:
                                return "closed_loop";
                            case penny::FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP:
                                return "not_closed_loop";
                            case penny::FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED:
                                return "duplicates_exceeded";
                            case penny::FlowEngine::FlowDecision::FINISHED_NO_DECISION:
                                return "no_decision";
                            case penny::FlowEngine::FlowDecision::PENDING:
                            default:
                                return "pending";
                        }
                    }();
                    TCPLOG_INFO(
                        "[agg_eval] verdict=%s data=%llu dup=%llu rtx=%llu non_rtx=%llu "
                        "dup_ratio=%.6f miss_prob=%.6f p_closed=%.6f p_not_closed=%.6f closed_weight=%.6f "
                        "packet_id=%s thread=%s",
                        eval_verdict_text,
                        static_cast<unsigned long long>(stats.data_packets()),
                        static_cast<unsigned long long>(stats.duplicate_packets()),
                        static_cast<unsigned long long>(stats.retransmitted_packets()),
                        static_cast<unsigned long long>(stats.non_retransmitted_packets()),
                        eval.dup_ratio,
                        miss_prob,
                        eval.p_closed,
                        eval.p_not_closed,
                        eval.closed_weight,
                        packet_id_text.c_str(),
                        latest_snapshot->thread_name.c_str());

                    if (dup_threshold_hit) {
                        switch_to_individual_flow_phase(
                            RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED,
                            "duplicates_exceeded",
                            frozen_agg,
                            agg_now,
                            stats);
                        continue;
                    }

                    if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP) {
                        finalize_aggregate_verdict(
                            RuntimeStatus::AggregatesStatus::CLOSED_LOOP,
                            frozen_agg,
                            agg_now,
                            stats);
                        collector_completed_.store(true, std::memory_order_relaxed);
                        stop_flag_.store(true, std::memory_order_relaxed);
                        break;
                    }
                    switch_to_individual_flow_phase(
                        RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP,
                        "not_closed_loop",
                        frozen_agg,
                        agg_now,
                        stats);
                } else {
                    set_current_aggregates_status(RuntimeStatus::AggregatesStatus::PENDING);
                }
            }
        }
        std::this_thread::sleep_for(25ms);
    }
}

void AggregatesController::individual_limit_loop() {
    using namespace std::chrono_literals;
    while (!stop_flag_.load(std::memory_order_relaxed)) {
        if (collector_enabled_ &&
            current_aggregates_status() == RuntimeStatus::AggregatesStatus::PENDING) {
            std::this_thread::sleep_for(100ms);
            continue;
        }
        auto agg = openpenny::app::aggregate_counters();
        if (agg.flows_finished >= cfg_.active.stop_after_individual_flows) {
            TCPLOG_INFO(
                "[individual_limit] flows_finished=%llu closed_loop=%llu not_closed_loop=%llu rst=%llu dup_exceeded=%llu",
                static_cast<unsigned long long>(agg.flows_finished),
                static_cast<unsigned long long>(agg.flows_closed_loop),
                static_cast<unsigned long long>(agg.flows_not_closed_loop),
                static_cast<unsigned long long>(agg.flows_rst),
                static_cast<unsigned long long>(agg.flows_duplicates_exceeded));
            store_aggregate_snapshot_once(aggregates_snapshot_, aggregates_snapshot_mtx_, agg);
            stop_flag_.store(true, std::memory_order_relaxed);
            individual_stop_hit_.store(true, std::memory_order_relaxed);
            break;
        }
        std::this_thread::sleep_for(100ms);
    }
}

void AggregatesController::min_closed_loop_loop() {
    using namespace std::chrono_literals;
    // Mirrors individual_limit_loop, but watches the per-flow CLOSED_LOOP
    // tally instead of the total finished-flow count. Stops the pipeline
    // as soon as the configured min_closed_loop_flows threshold is hit
    // and the aggregate eval (if enabled) is not still pending.
    while (!stop_flag_.load(std::memory_order_relaxed)) {
        if (collector_enabled_ &&
            current_aggregates_status() == RuntimeStatus::AggregatesStatus::PENDING) {
            std::this_thread::sleep_for(100ms);
            continue;
        }
        auto agg = openpenny::app::aggregate_counters();
        if (agg.flows_closed_loop >= cfg_.active.min_closed_loop_flows) {
            TCPLOG_INFO(
                "[min_closed_loop] flows_closed_loop=%llu (threshold=%llu) "
                "flows_finished=%llu not_closed_loop=%llu rst=%llu dup_exceeded=%llu",
                static_cast<unsigned long long>(agg.flows_closed_loop),
                static_cast<unsigned long long>(cfg_.active.min_closed_loop_flows),
                static_cast<unsigned long long>(agg.flows_finished),
                static_cast<unsigned long long>(agg.flows_not_closed_loop),
                static_cast<unsigned long long>(agg.flows_rst),
                static_cast<unsigned long long>(agg.flows_duplicates_exceeded));
            auto& runtime = runtime_setup_mutable();
            if (current_aggregates_status() == RuntimeStatus::AggregatesStatus::PENDING) {
                store_aggregate_snapshot_once(aggregates_snapshot_, aggregates_snapshot_mtx_, agg);
                set_current_aggregates_status(RuntimeStatus::AggregatesStatus::CLOSED_LOOP);
                set_current_has_aggregate_eval(true);
                set_runtime_eval_counters(runtime, agg);
            }
            collector_completed_.store(true, std::memory_order_relaxed);
            closed_loop_stop_hit_.store(true, std::memory_order_relaxed);
            stop_flag_.store(true, std::memory_order_relaxed);
            break;
        }
        std::this_thread::sleep_for(100ms);
    }
}

} // namespace openpenny
