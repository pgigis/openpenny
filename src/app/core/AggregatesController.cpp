// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/AggregatesController.h"

#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/log/Log.h"
#include "openpenny/penny/flow/engine/FlowEvaluation.h"

#include <algorithm>

namespace openpenny {

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
                                cfg.active.stop_after_individual_flows > 0} {}

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

void AggregatesController::join() {
    if (collector_thread_.joinable()) {
        collector_thread_.join();
    }
    if (individual_limit_thread_.joinable()) {
        individual_limit_thread_.join();
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

std::optional<openpenny::app::AggregatedCounters> AggregatesController::aggregates_snapshot() const {
    std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
    return aggregates_snapshot_;
}

void AggregatesController::populate_drop_snapshots(PipelineSummary& summary) const {
    if (!collector_) return;
    std::lock_guard<std::mutex> lock(collector_->mtx);
    auto snaps = collector_->snapshots;
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
    if (!cfg.active.aggregates_enabled ||
        runtime.aggregates_status != RuntimeStatus::AggregatesStatus::PENDING ||
        !aggregates_ready_.load(std::memory_order_relaxed) ||
        summary.drop_snapshots.empty()) {
        return;
    }
    const auto& latest = summary.drop_snapshots.front();
    const auto& stats = latest.snapshot.stats;
    const auto miss_prob = std::clamp(
        cfg.active.retransmission_miss_probability,
        0.0,
        1.0);
    const auto eval = penny::evaluate_flow_decision(
        stats,
        miss_prob,
        cfg.active.max_duplicate_fraction);
    if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP) {
        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::CLOSED_LOOP;
    } else if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP) {
        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP;
    } else {
        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED;
    }
    runtime.has_aggregate_eval = true;
    runtime.aggregate_eval_counters.data_packets = stats.droppable_packets();
    runtime.aggregate_eval_counters.duplicate_packets = stats.duplicate_packets();
    runtime.aggregate_eval_counters.retransmitted_packets = stats.retransmitted_packets();
    runtime.aggregate_eval_counters.non_retransmitted_packets = stats.non_retransmitted_packets();
    collector_completed_.store(true, std::memory_order_relaxed);
}

void AggregatesController::collector_loop() {
    using namespace std::chrono_literals;
    auto& runtime = runtime_setup_mutable();
    bool aggregate_eval_done = false;
    bool wait_for_closed_loops = false;
    bool ready_logged = false;
    while (!stop_flag_.load(std::memory_order_relaxed)) {
        if (user_should_stop_ && user_should_stop_()) break;
        if (wait_for_closed_loops) {
            auto agg = openpenny::app::aggregate_counters();
            if (agg.flows_closed_loop >= 2) {
                TCPLOG_INFO(
                    "[aggregates_closed_loop] flows_closed_loop=%llu flows_not_closed_loop=%llu flows_finished=%llu",
                    static_cast<unsigned long long>(agg.flows_closed_loop),
                    static_cast<unsigned long long>(agg.flows_not_closed_loop),
                    static_cast<unsigned long long>(agg.flows_finished));
                runtime.aggregates_status = RuntimeStatus::AggregatesStatus::CLOSED_LOOP;
                runtime.has_aggregate_eval = true;
                runtime.aggregate_eval_counters.data_packets = agg.droppable_packets;
                runtime.aggregate_eval_counters.duplicate_packets = agg.duplicate_packets;
                runtime.aggregate_eval_counters.retransmitted_packets = agg.retransmitted_packets;
                runtime.aggregate_eval_counters.non_retransmitted_packets = agg.non_retransmitted_packets;
                collector_completed_.store(true, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
                    if (!aggregates_snapshot_) aggregates_snapshot_ = openpenny::app::aggregate_counters();
                }
                stop_flag_.store(true, std::memory_order_relaxed);
                break;
            }
        }
        bool ready = false;
        bool pending = false;
        bool pending_rtx = false;
        std::size_t snapshot_count = 0;
        {
            std::lock_guard<std::mutex> lock(collector_->mtx);
            snapshot_count = collector_->snapshots.size();
            for (const auto& rec : collector_->snapshots) {
                if (rec.snapshot.state == penny::SnapshotState::Pending) {
                    pending = true;
                    break;
                }
            }
            pending_rtx = openpenny::app::aggregate_counters().pending_retransmissions > 0;
            ready = snapshot_count >= required_drops_ && !pending && !pending_rtx;
        }
        if (ready) {
            aggregates_ready_.store(true, std::memory_order_relaxed);
            if (!ready_logged) {
                TCPLOG_INFO(
                    "Aggregates have %zu drops ready (required=%zu)",
                    snapshot_count,
                    required_drops_);
                ready_logged = true;
            }
            collector_->accepting.store(false, std::memory_order_relaxed);
            if (cfg_.active.max_duplicate_fraction > 0.0) {
                auto agg_now = openpenny::app::aggregate_counters();
                if (agg_now.data_packets > 0) {
                    const double agg_dup_ratio = static_cast<double>(agg_now.duplicate_packets) /
                                                 static_cast<double>(agg_now.data_packets);
                    if (agg_dup_ratio > cfg_.active.max_duplicate_fraction) {
                        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED;
                        runtime.aggregates_active = false;
                        runtime.has_aggregate_eval = true;
                        runtime.aggregate_eval_counters.data_packets = agg_now.droppable_packets;
                        runtime.aggregate_eval_counters.duplicate_packets = agg_now.duplicate_packets;
                        runtime.aggregate_eval_counters.retransmitted_packets = agg_now.retransmitted_packets;
                        runtime.aggregate_eval_counters.non_retransmitted_packets = agg_now.non_retransmitted_packets;
                        collector_completed_.store(true, std::memory_order_relaxed);
                        {
                            std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
                            if (!aggregates_snapshot_) aggregates_snapshot_ = agg_now;
                        }
                        stop_flag_.store(true, std::memory_order_relaxed);
                        break;
                    }
                }
            }
            if (!aggregate_eval_done) {
                aggregate_eval_done = true;
                std::optional<DropSnapshotRecord> latest_snapshot;
                {
                    std::lock_guard<std::mutex> lock(collector_->mtx);
                    auto it = std::max_element(
                        collector_->snapshots.begin(),
                        collector_->snapshots.end(),
                        [](const DropSnapshotRecord& a, const DropSnapshotRecord& b) {
                            return a.snapshot.timestamp < b.snapshot.timestamp;
                        });
                    if (it != collector_->snapshots.end()) {
                        latest_snapshot = *it;
                    }
                }

                if (latest_snapshot) {
                    if (openpenny::app::aggregate_counters().pending_retransmissions > 0) {
                        continue;
                    }
                    auto stats = latest_snapshot->snapshot.stats;
                    stats.overwrite_from_aggregates(openpenny::app::aggregate_counters());
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

                    const auto denom = eval.p_closed + eval.p_not_closed;
                    TCPLOG_INFO(
                        "[agg_eval] data_pkts=%llu dup_pkts=%llu rtx_pkts=%llu non_rtx_pkts=%llu "
                        "dup_ratio=%.6f miss_prob=%.6f p_closed=%.6f p_not_closed=%.6f denom=%.6f closed_weight=%.6f decision=%s "
                        "packet_id=%s thread=%s",
                        static_cast<unsigned long long>(stats.data_packets()),
                        static_cast<unsigned long long>(stats.duplicate_packets()),
                        static_cast<unsigned long long>(stats.retransmitted_packets()),
                        static_cast<unsigned long long>(stats.non_retransmitted_packets()),
                        eval.dup_ratio,
                        miss_prob,
                        eval.p_closed,
                        eval.p_not_closed,
                        denom,
                        eval.closed_weight,
                        penny::flow_decision_to_string(eval.decision),
                        latest_snapshot->packet_id.c_str(),
                        latest_snapshot->thread_name.c_str());

                    if (dup_threshold_hit) {
                        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED;
                        runtime.aggregates_active = false;
                        runtime.has_aggregate_eval = true;
                        runtime.aggregate_eval_counters.data_packets = stats.droppable_packets();
                        runtime.aggregate_eval_counters.duplicate_packets = stats.duplicate_packets();
                        runtime.aggregate_eval_counters.retransmitted_packets = stats.retransmitted_packets();
                        runtime.aggregate_eval_counters.non_retransmitted_packets = stats.non_retransmitted_packets();
                        collector_completed_.store(true, std::memory_order_relaxed);
                        {
                            std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
                            if (!aggregates_snapshot_) aggregates_snapshot_ = openpenny::app::aggregate_counters();
                        }
                        break;
                    }

                    if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP) {
                        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::CLOSED_LOOP;
                        {
                            std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
                            if (!aggregates_snapshot_) aggregates_snapshot_ = openpenny::app::aggregate_counters();
                        }
                        runtime.has_aggregate_eval = true;
                        runtime.aggregate_eval_counters.data_packets = stats.droppable_packets();
                        runtime.aggregate_eval_counters.duplicate_packets = stats.duplicate_packets();
                        runtime.aggregate_eval_counters.retransmitted_packets = stats.retransmitted_packets();
                        runtime.aggregate_eval_counters.non_retransmitted_packets = stats.non_retransmitted_packets();
                        collector_completed_.store(true, std::memory_order_relaxed);
                        stop_flag_.store(true, std::memory_order_relaxed);
                        break;
                    } else if (eval.decision == penny::FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP) {
                        runtime.aggregates_status = RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP;
                    }

                    runtime.aggregate_eval_counters.data_packets = stats.droppable_packets();
                    runtime.aggregate_eval_counters.duplicate_packets = stats.duplicate_packets();
                    runtime.aggregate_eval_counters.retransmitted_packets = stats.retransmitted_packets();
                    runtime.aggregate_eval_counters.non_retransmitted_packets = stats.non_retransmitted_packets();
                    runtime.has_aggregate_eval = true;

                    if (cfg_.active.aggregates_enabled &&
                        eval.decision != penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP) {
                        runtime.aggregates_active = false;
                        wait_for_closed_loops = true;
                    } else {
                        {
                            std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
                            if (!aggregates_snapshot_) aggregates_snapshot_ = openpenny::app::aggregate_counters();
                        }
                        collector_completed_.store(true, std::memory_order_relaxed);
                        stop_flag_.store(true, std::memory_order_relaxed);
                        break;
                    }
                } else {
                    runtime.aggregates_status = RuntimeStatus::AggregatesStatus::PENDING;
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
            runtime_setup_mutable().aggregates_status == RuntimeStatus::AggregatesStatus::PENDING) {
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
            {
                std::lock_guard<std::mutex> lk(aggregates_snapshot_mtx_);
                if (!aggregates_snapshot_) aggregates_snapshot_ = agg;
            }
            stop_flag_.store(true, std::memory_order_relaxed);
            individual_stop_hit_.store(true, std::memory_order_relaxed);
            break;
        }
        std::this_thread::sleep_for(100ms);
    }
}

} // namespace openpenny
