// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/agg/Stats.h"

#include <algorithm>
#include <utility>

#include "openpenny/app/core/ActiveTestPipeline.h"
#include "openpenny/app/core/PassiveTestPipeline.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/AggregatesController.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/net/PacketSourceFactory.h"
#include "openpenny/log/Log.h"
#include "openpenny/penny/flow/engine/FlowEvaluation.h"

#include <atomic>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>

namespace openpenny {
namespace {

// Coordinates aggregate drop evaluation and optional individual stop limits for active mode.
template <typename Matcher>
void run_queue_worker(unsigned idx,
                      const Config& base_cfg,
                      const PipelineOptions& opts,
                      const Matcher& matcher,
                      DropCollectorPtr drop_collector,
                      std::vector<std::optional<ModeResult>>& results) {
    Config cfg_local = base_cfg;
    cfg_local.queue = base_cfg.queue + idx; // Map queue offset to physical queue.

    openpenny::app::set_thread_counter_index(idx);

    const net::IPacketSourceFactory* factory = opts.packet_source_factory
        ? opts.packet_source_factory
        : &net::default_packet_source_factory();
    auto source = factory->create(cfg_local);
    const std::string thread_name = "thread-queue-" + std::to_string(idx);

    if (opts.mode == PipelineOptions::Mode::Active) {
        ActiveTestPipelineRunner runner(cfg_local, opts, matcher, std::move(source), drop_collector, thread_name);
        results[idx] = runner.run();
    } else {
        PassiveTestPipelineRunner runner(cfg_local, opts, matcher, std::move(source));
        results[idx] = runner.run();
    }
}

/**
 * @brief Check whether a flow's source address matches an IPv4 prefix.
 *
 * @param key         Flow tuple to inspect.
 * @param prefix_host IPv4 prefix in host byte order.
 * @param mask_host   Subnet mask in host byte order.
 * @param has_prefix  Whether prefix filtering is enabled.
 *
 * @return true if no prefix is configured, or if the source address matches
 *         the given prefix and mask; false otherwise.
 */
bool flow_matches_prefix(const FlowKey& key,
                         uint32_t prefix_host,
                         uint32_t mask_host,
                         bool has_prefix) {
    if (!has_prefix || mask_host == 0) {
        // No prefix filter configured, accept all flows.
        return true;
    }
    // Apply mask in host byte order and compare the masked source address.
    return (key.src & mask_host) == (prefix_host & mask_host);
}

} // namespace

/**
 * @brief Run the active or passive pipeline across one or more queues.
 *
 * This function:
 *   - Spawns one worker thread per queue.
 *   - Constructs a packet source per queue.
 *   - Runs either the active or passive pipeline based on @p opts.mode.
 *   - Aggregates per-thread statistics into a single summary result.
 *
 * @param cfg   Base configuration (interface, starting queue index, etc.).
 * @param opts  Execution parameters (mode, queue count, prefix filter).
 *
 * @return A PipelineSummary that includes an aggregated active-mode result
 *         if any worker produced data.
 */
PipelineSummary drive_pipeline(const Config& cfg, const PipelineOptions& opts) {
    PipelineOptions opts_local = opts;
    std::atomic<bool> stop_flag{false};
    const auto user_should_stop = opts.should_stop;
    opts_local.should_stop = [user_should_stop, &stop_flag]() {
        if (stop_flag.load(std::memory_order_relaxed)) return true;
        return user_should_stop ? user_should_stop() : false;
    };

    // Capture the runtime setup at worker start so observers can inspect it.
    set_runtime_setup(cfg, opts_local, cfg.xdp_runtime.enable, cfg.dpdk.enable);

    // Collect the results. Supports both active and passive modes.
    PipelineSummary summary;
    summary.aggregates_enabled = cfg.active.aggregates_enabled;

    // Build a reusable matcher for optional prefix-based flow filtering.
    // TODO: Expose a more general matching API.
    auto matcher = [&](const FlowKey& key) {
        return flow_matches_prefix(key, opts_local.prefix_host, opts_local.mask_host, opts_local.has_prefix);
    };
    // Number of queues to process traffic.
    const unsigned qcount = std::max(1u, opts_local.queue_count);

    // One worker thread and one result slot per queue.
    std::vector<std::thread> threads;
    std::vector<std::optional<ModeResult>> results(qcount);
    
    // Shared drop snapshot collector across worker threads.
    auto drop_collector = std::make_shared<DropCollector>();
    AggregatesController aggregates_controller(cfg, opts_local, drop_collector, stop_flag, user_should_stop);
    aggregates_controller.start();
    aggregates_controller.start_individual_limit();

    // Launch a pipeline runner per queue.
    for (unsigned i = 0; i < qcount; ++i) {
        threads.emplace_back([&, i]() {
            run_queue_worker(i, cfg, opts_local, matcher, drop_collector, results);
        });
    }

    // Wait for all worker threads to complete.
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    stop_flag.store(true, std::memory_order_relaxed);
    aggregates_controller.join();
    const auto agg_counters_now = openpenny::app::aggregate_counters();
    bool individual_stop_hit = aggregates_controller.individual_stop_hit();
    if (!individual_stop_hit &&
        cfg.active.stop_after_individual_flows > 0 &&
        opts_local.mode == PipelineOptions::Mode::Active &&
        agg_counters_now.flows_finished >= static_cast<std::size_t>(cfg.active.stop_after_individual_flows)) {
        individual_stop_hit = true;
    }
    if (individual_stop_hit &&
        cfg.active.aggregates_enabled &&
        runtime_setup_mutable().aggregates_status == RuntimeStatus::AggregatesStatus::PENDING &&
        aggregates_controller.aggregates_ready()) {
        runtime_setup_mutable().aggregates_status = RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED;
    }
    aggregates_controller.populate_drop_snapshots(summary);
    aggregates_controller.evaluate_pending_if_needed(cfg, summary);

    // Fold per-thread results into a single aggregated ModeResult.
    ModeResult aggregate{};
    bool any = false;

    for (const auto& r : results) {
        if (!r) continue;
        any = true;

        aggregate.packets_processed          += r->packets_processed;
        aggregate.packets_forwarded          += r->packets_forwarded;
        aggregate.forward_errors             += r->forward_errors;
        aggregate.pure_ack_packets           += r->pure_ack_packets;
        aggregate.data_packets               += r->data_packets;
        aggregate.duplicate_packets          += r->duplicate_packets;
        aggregate.in_order_packets           += r->in_order_packets;
        aggregate.out_of_order_packets       += r->out_of_order_packets;
        aggregate.retransmitted_packets      += r->retransmitted_packets;
        aggregate.non_retransmitted_packets  += r->non_retransmitted_packets;
        aggregate.pending_retransmissions    += r->pending_retransmissions;
        aggregate.flows_tracked_syn          += r->flows_tracked_syn;
        aggregate.flows_tracked_data         += r->flows_tracked_data;
        aggregate.passive_flows_finished     += r->passive_flows_finished;
        aggregate.passive_flows_with_open_gaps += r->passive_flows_with_open_gaps;
        aggregate.passive_open_gaps          += r->passive_open_gaps;
        aggregate.passive_flows_rst          += r->passive_flows_rst;
        aggregate.passive_flows_syn_only     += r->passive_flows_syn_only;
        if (!r->passive_gap_summaries.empty()) {
            aggregate.passive_gap_summaries.insert(
                aggregate.passive_gap_summaries.end(),
                r->passive_gap_summaries.begin(),
                r->passive_gap_summaries.end());
        }

        // Completion flags are combined with logical OR.
        aggregate.penny_completed =
            aggregate.penny_completed || r->penny_completed;
        aggregate.aggregates_penny_completed =
            aggregate.aggregates_penny_completed || r->aggregates_penny_completed;
    }
    // Use aggregated counters to avoid undercounting packets processed.
    aggregate.packets_processed = std::max<std::size_t>(
        aggregate.packets_processed,
        static_cast<std::size_t>(agg_counters_now.packets));
    if (aggregates_controller.collector_completed()) {
        const bool agg_done_status =
            runtime_setup_mutable().aggregates_status != RuntimeStatus::AggregatesStatus::PENDING;
        aggregate.aggregates_penny_completed = agg_done_status;
        aggregate.penny_completed = agg_done_status;
    }
    if (individual_stop_hit) {
        aggregate.penny_completed = true;
    }
    if (auto snapshot = aggregates_controller.aggregates_snapshot()) {
        aggregate.aggregates_snapshot = snapshot;
    }

    // Only populate the summary if at least one worker reported results.
    if (any) {
        summary.active = aggregate;
    }

    return summary;
}

PipelineSummary drive_pipeline_threaded(const Config& cfg, const PipelineOptions& opts) {
    PipelineSummary summary;
    std::thread driver_thread([&]() {
        summary = drive_pipeline(cfg, opts);
    });
    if (driver_thread.joinable()) {
        driver_thread.join();
    }
    return summary;
}

} // namespace openpenny
