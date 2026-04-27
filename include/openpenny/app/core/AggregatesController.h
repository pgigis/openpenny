// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/RuntimeSetup.h"

#include <atomic>
#include <mutex>
#include <optional>
#include <thread>

namespace openpenny {

class AggregatesController {
public:
    AggregatesController(const Config& cfg,
                         const PipelineOptions& opts,
                         DropCollectorPtr collector,
                         std::atomic<bool>& stop_flag,
                         const std::function<bool()>& user_should_stop);

    void start();
    void start_individual_limit();
    /// Spawn a background watcher that stops the pipeline as soon as the
    /// configured min_closed_loop_flows threshold is reached. No-op when
    /// the threshold is 0.
    void start_min_closed_loop();
    void join();

    bool collector_completed() const;
    bool aggregates_ready() const;
    bool individual_stop_hit() const;
    /// True once start_min_closed_loop() observed at least
    /// active.min_closed_loop_flows individual CLOSED_LOOP terminations and
    /// triggered an early stop.
    bool closed_loop_stop_hit() const;
    std::optional<openpenny::app::AggregatedCounters> aggregates_snapshot() const;
    void populate_drop_snapshots(PipelineSummary& summary) const;
    void evaluate_pending_if_needed(const Config& cfg, PipelineSummary& summary);

private:
    void collector_loop();
    void individual_limit_loop();
    void min_closed_loop_loop();

    const Config& cfg_;
    DropCollectorPtr collector_;
    std::atomic<bool>& stop_flag_;
    std::function<bool()> user_should_stop_;
    const std::size_t required_drops_;
    const bool collector_enabled_;
    const bool individual_limit_enabled_;
    const bool min_closed_loop_enabled_;
    std::atomic<bool> aggregates_ready_{false};
    std::atomic<bool> collector_completed_{false};
    std::atomic<bool> individual_stop_hit_{false};
    std::atomic<bool> closed_loop_stop_hit_{false};
    std::optional<openpenny::app::AggregatedCounters> aggregates_snapshot_;
    mutable std::mutex aggregates_snapshot_mtx_;
    std::thread collector_thread_;
    std::thread individual_limit_thread_;
    std::thread min_closed_loop_thread_;
};

} // namespace openpenny
