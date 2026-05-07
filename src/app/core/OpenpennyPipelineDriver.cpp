// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/agg/FlowKey.h"

#include <algorithm>
#include <utility>

#include "openpenny/app/core/ActiveTestPipeline.h"
#include "openpenny/app/core/PassiveTestPipeline.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/AggregatesController.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/dataplane/Factory.h"
#include "openpenny/log/Log.h"
#include "openpenny/net/TrafficMatch.h"
#include "openpenny/penny/flow/engine/FlowEvaluation.h"

#include <atomic>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#include <cstring>
#endif

namespace openpenny {
namespace {

#ifdef __linux__
void pin_current_thread_to_cpu(unsigned cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(static_cast<int>(cpu), &cpuset);
    const int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    if (rc != 0) {
        // Bubble pin failures up at WARN — they usually mean the worker count
        // exceeds the available CPUs and the operator should know.
        TCPLOG_WARN("Failed to pin queue worker to CPU %u: %s", cpu, std::strerror(rc));
    } else {
        // The success case fires once per worker thread. With many queues that
        // is a lot of repeated lines, so we keep it at DEBUG.
        TCPLOG_DEBUG("Pinned queue worker to CPU %u", cpu);
    }
}
#else
void pin_current_thread_to_cpu(unsigned) {}
#endif

unsigned cpu_for_queue_worker(const Config& cfg, unsigned idx) {
    if (idx < cfg.worker_cpus.size()) {
        return cfg.worker_cpus[idx];
    }
    return idx;
}

// Coordinates aggregate drop evaluation and optional individual stop limits for active mode.
template <typename Matcher>
void run_queue_worker(unsigned idx,
                      const Config& base_cfg,
                      const PipelineOptions& opts,
                      const Matcher& matcher,
                      DropCollectorPtr drop_collector,
                      std::vector<std::optional<ModeResult>>& results) {
    Config cfg_local = base_cfg;
    // Preserve the invariant starting queue (queue_base) across per-worker mutation.
    // Consumers like XdpReader::configure_from_config() rely on it to derive the
    // full served-set for RSS coverage checks; cfg_local.queue is rewritten below.
    cfg_local.queue_base = base_cfg.queue_base ? base_cfg.queue_base : base_cfg.queue;
    cfg_local.queue = base_cfg.queue + idx; // Map queue offset to physical queue.

    openpenny::app::set_thread_counter_index(idx);
    pin_current_thread_to_cpu(cpu_for_queue_worker(base_cfg, idx));

    const dataplane::IFactory* factory = opts.dataplane_factory
        ? opts.dataplane_factory
        : &dataplane::default_factory();
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
 * @param opts  Execution parameters (mode, queue count, traffic match, forwarding).
 *
 * @return A PipelineSummary that includes an aggregated active-mode result
 *         if any worker produced data.
 */
PipelineSummary drive_pipeline(const Config& cfg_in, const PipelineOptions& opts) {
    PipelineOptions opts_local = opts;
    std::atomic<bool> stop_flag{false};
    const auto user_should_stop = opts.should_stop;
    opts_local.should_stop = [user_should_stop, &stop_flag]() {
        if (stop_flag.load(std::memory_order_relaxed)) return true;
        return user_should_stop ? user_should_stop() : false;
    };

    // Resolve ingress semantics up front. IngressMode::Auto picks Copy
    // (AF_PACKET mirror) for passive mode and Redirect (AF_XDP) for
    // active mode. If the operator explicitly set backend=af_packet or
    // backend=dpdk we leave that alone -- the explicit choice wins.
    Config cfg = cfg_in;
    const bool is_passive = opts_local.mode == PipelineOptions::Mode::Passive;
    IngressMode resolved = cfg.input.mode;
    if (resolved == IngressMode::Auto) {
        resolved = is_passive ? IngressMode::Copy : IngressMode::Redirect;
    }
    cfg.input.mode = resolved;
    if (resolved == IngressMode::Copy &&
        cfg.input.backend == PacketInputBackend::XdpAfXdp) {
        cfg.input.backend = PacketInputBackend::AfPacketMirror;
        TCPLOG_INFO("[openpenny] passive copy mode selected: using AF_PACKET mirror "
                    "on '%s' (kernel stack continues to deliver packets)",
                    cfg.ifname.c_str());
    } else if (resolved == IngressMode::Redirect &&
               cfg.input.backend == PacketInputBackend::AfPacketMirror) {
        cfg.input.backend = PacketInputBackend::XdpAfXdp;
        TCPLOG_WARN("[openpenny] ingress mode 'redirect' requested but backend was "
                    "af_packet_mirror; switching to af_xdp");
    }

    // AF_PACKET mirror has no PACKET_FANOUT fast path yet. Multiple workers
    // each bind a fresh socket on the same ifindex and receive *duplicate*
    // copies of every frame, which silently inflates counters. Collapse to a
    // single worker and warn.
    if (cfg.input.backend == PacketInputBackend::AfPacketMirror &&
        cfg.queue_count > 1) {
        TCPLOG_WARN("[openpenny] af_packet_mirror backend does not support "
                    "queue_count=%u (no PACKET_FANOUT); collapsing to a single "
                    "worker to avoid duplicate packet delivery",
                    cfg.queue_count);
        cfg.queue_count = 1;
        opts_local.queue_count = 1;
    }

    if (opts_local.traffic_match.empty()) {
        opts_local.traffic_match = cfg.traffic_match;
    }

    // Resolve the egress sink once, up front.
    //
    // Priority order:
    //   1. Caller-provided opts.sink (tests, SDK users).
    //   2. Declarative cfg.egress (YAML-driven path; the normal case).
    //
    // The historical legacy path (forward_to_tun / forward_raw_socket /
    // tun_fd / forward_fd on PipelineOptions) was removed in Chunk 3:
    // CLI / worker / gRPC callers now all populate cfg.egress instead.
    if (!opts_local.sink && cfg.egress.enabled()) {
        opts_local.sink = egress::make_packet_sink(cfg.egress);
        if (!opts_local.sink) {
            TCPLOG_ERROR("Egress sink configuration failed (kind=%s, device='%s'); "
                         "forwarded packets will be dropped",
                         egress::egress_kind_name(cfg.egress.kind),
                         cfg.egress.device.c_str());
        }
    }
    if (opts_local.sink) {
        TCPLOG_INFO("[openpenny] egress sink: %s",
                    opts_local.sink->describe().c_str());
        if (cfg.egress.kind == egress::EgressKind::RawNic) {
            TCPLOG_WARN("[openpenny] raw_nic replays the original Ethernet "
                        "frame out '%s'. It does not reinject packets into "
                        "the local host stack, and it does not resolve or "
                        "rewrite L2 next-hop MAC addresses. Use egress.kind=tun "
                        "for local application delivery, or raw_socket if the "
                        "kernel routing table should choose the egress hop.",
                        cfg.egress.device.c_str());
            if (!cfg.ifname.empty() && cfg.egress.device == cfg.ifname) {
                TCPLOG_WARN("[openpenny] raw_nic egress matches the ingress "
                            "interface '%s'. Redirected packets destined for "
                            "this host will not be delivered locally on this "
                            "path; they are transmitted back out the NIC with "
                            "their original Ethernet header.",
                            cfg.ifname.c_str());
            }
        }
    }

    // Traffic match policy applies process-wide (every worker uses the
    // same compiled config), so print it once here at the driver level
    // rather than once per worker's on_opened().
    TCPLOG_INFO("[openpenny] traffic match: %s",
                net::describe_traffic_match(opts_local.traffic_match).c_str());

    // Number of queues to process traffic.
    const unsigned qcount = std::max(1u, opts_local.queue_count);

    // Capture the runtime setup at worker start so observers can inspect it.
    set_runtime_setup(cfg,
                      opts_local,
                      cfg.input.backend == PacketInputBackend::XdpAfXdp,
                      cfg.input.backend == PacketInputBackend::Dpdk);

    // Collect the results. Supports both active and passive modes.
    PipelineSummary summary;
    summary.aggregates_enabled = cfg.active.aggregates_enabled;

    // Build a reusable matcher from the backend-neutral traffic-match config.
    auto matcher = [&](const FlowKey& key) {
        return net::traffic_matches_flow(opts_local.traffic_match, key);
    };

    // ------------------------------------------------------------------
    // One-line startup summary at INFO. With many queues the per-worker
    // chatter (pin info, attach traces, per-queue rx-batch lines) lives
    // at DEBUG, so this single line is the authoritative "what did we
    // actually start" record at the default log level.
    // ------------------------------------------------------------------
    auto backend_name = [](PacketInputBackend b) -> const char* {
        switch (b) {
            case PacketInputBackend::XdpAfXdp:       return "af_xdp";
            case PacketInputBackend::Dpdk:           return "dpdk";
            case PacketInputBackend::AfPacketMirror: return "af_packet_mirror";
        }
        return "unknown";
    };
    {
        const unsigned q_first = cfg.queue;
        const unsigned q_last  = cfg.queue + qcount - 1;
        if (qcount > 1) {
            TCPLOG_INFO("[openpenny] starting %s mode: %u workers on '%s' "
                        "queues %u-%u, backend=%s, aggregates=%s",
                        is_passive ? "passive" : "active",
                        qcount,
                        cfg.ifname.c_str(),
                        q_first, q_last,
                        backend_name(cfg.input.backend),
                        cfg.active.aggregates_enabled ? "on" : "off");
        } else {
            TCPLOG_INFO("[openpenny] starting %s mode: 1 worker on '%s' "
                        "queue %u, backend=%s, aggregates=%s",
                        is_passive ? "passive" : "active",
                        cfg.ifname.c_str(),
                        q_first,
                        backend_name(cfg.input.backend),
                        cfg.active.aggregates_enabled ? "on" : "off");
        }
    }

    // One worker thread and one result slot per queue.
    std::vector<std::thread> threads;
    std::vector<std::optional<ModeResult>> results(qcount);

    // Shared drop snapshot collector across worker threads.
    auto drop_collector = std::make_shared<DropCollector>(qcount);
    AggregatesController aggregates_controller(cfg, opts_local, drop_collector, stop_flag, user_should_stop);
    aggregates_controller.start();
    aggregates_controller.start_individual_limit();
    aggregates_controller.start_min_closed_loop();

    // ------------------------------------------------------------------
    // No-packets watchdog. With many queues a silent zero-RX run is
    // hard to diagnose: the user sees `processed=0` in the summary but
    // gets no signal during the run. This thread polls the aggregate
    // counters and emits exactly one of:
    //   - INFO "first packet seen at +X.Xs" once any worker observes RX,
    //   - WARN "no packets after Ns" with concrete next-step guidance.
    // The watchdog stops as soon as either fires, or stop_flag is set.
    // ------------------------------------------------------------------
    std::thread watchdog([&, qcount]() {
        const auto deadline = std::chrono::seconds(5);
        const auto t0 = std::chrono::steady_clock::now();
        while (!stop_flag.load(std::memory_order_relaxed)) {
            const auto agg = openpenny::app::aggregate_counters();
            const auto now = std::chrono::steady_clock::now();
            const double elapsed = std::chrono::duration<double>(now - t0).count();
            if (agg.packets > 0) {
                TCPLOG_INFO("[openpenny] first packet observed at +%.1fs "
                            "(across %u queue worker%s)",
                            elapsed, qcount, qcount == 1 ? "" : "s");
                return;
            }
            if (now - t0 >= deadline) {
                TCPLOG_WARN("[openpenny] no packets received after %.0fs across "
                            "%u queue worker%s on '%s'. Common causes:",
                            std::chrono::duration<double>(deadline).count(),
                            qcount, qcount == 1 ? "" : "s",
                            cfg.ifname.c_str());
                TCPLOG_WARN("[openpenny]   1) RSS routes traffic to queues outside "
                            "%u..%u — see [rss_check] above and `ethtool -x %s`",
                            cfg.queue, cfg.queue + qcount - 1, cfg.ifname.c_str());
                TCPLOG_WARN("[openpenny]   2) traffic_match rule does not match the "
                            "live flow — try --log-level debug to inspect [xdp_counters]");
                TCPLOG_WARN("[openpenny]   3) link is down or no traffic is flowing — "
                            "check `ip -s link show %s` rx counters",
                            cfg.ifname.c_str());
                if (cfg.input.backend == PacketInputBackend::XdpAfXdp) {
                    TCPLOG_WARN("[openpenny]   4) AF_XDP socket not attached to the "
                                "queue receiving traffic — verify queue %u..%u "
                                "match RSS targets",
                                cfg.queue, cfg.queue + qcount - 1);
                }
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

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
    if (watchdog.joinable()) {
        watchdog.join();
    }
    aggregates_controller.join();
    const auto agg_counters_now = openpenny::app::aggregate_counters();
    bool individual_stop_hit = aggregates_controller.individual_stop_hit();
    bool closed_loop_stop_hit = aggregates_controller.closed_loop_stop_hit();
    if (!individual_stop_hit &&
        cfg.active.stop_after_individual_flows > 0 &&
        opts_local.mode == PipelineOptions::Mode::Active &&
        agg_counters_now.flows_finished >= static_cast<std::size_t>(cfg.active.stop_after_individual_flows)) {
        individual_stop_hit = true;
    }
    if (individual_stop_hit &&
        cfg.active.aggregates_enabled &&
        current_aggregates_status() == RuntimeStatus::AggregatesStatus::PENDING &&
        aggregates_controller.aggregates_ready()) {
        set_current_aggregates_status(RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    }
    aggregates_controller.populate_drop_snapshots(summary);
    aggregates_controller.evaluate_pending_if_needed(cfg, summary);
    if (!closed_loop_stop_hit &&
        opts_local.mode == PipelineOptions::Mode::Active &&
        cfg.active.min_closed_loop_flows > 0 &&
        agg_counters_now.flows_closed_loop >= cfg.active.min_closed_loop_flows) {
        closed_loop_stop_hit = true;
    }

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
        if (!r->closed_loop_flow_summaries.empty()) {
            aggregate.closed_loop_flow_summaries.insert(
                aggregate.closed_loop_flow_summaries.end(),
                r->closed_loop_flow_summaries.begin(),
                r->closed_loop_flow_summaries.end());
        }
        if (!r->duplicate_exceeded_flow_summaries.empty()) {
            aggregate.duplicate_exceeded_flow_summaries.insert(
                aggregate.duplicate_exceeded_flow_summaries.end(),
                r->duplicate_exceeded_flow_summaries.begin(),
                r->duplicate_exceeded_flow_summaries.end());
        }

        // Completion flags are combined with logical OR.
        aggregate.penny_completed =
            aggregate.penny_completed || r->penny_completed;
        aggregate.aggregates_penny_completed =
            aggregate.aggregates_penny_completed || r->aggregates_penny_completed;
        aggregate.closed_loop_stop_hit =
            aggregate.closed_loop_stop_hit || r->closed_loop_stop_hit;
    }
    // Use aggregated counters to avoid undercounting packets processed.
    aggregate.packets_processed = std::max<std::size_t>(
        aggregate.packets_processed,
        static_cast<std::size_t>(agg_counters_now.packets));
    if (aggregates_controller.collector_completed()) {
        const bool agg_done_status =
            current_aggregates_status() != RuntimeStatus::AggregatesStatus::PENDING;
        aggregate.aggregates_penny_completed = agg_done_status;
        aggregate.penny_completed = agg_done_status;
    }
    if (individual_stop_hit) {
        aggregate.penny_completed = true;
    }
    if (closed_loop_stop_hit) {
        aggregate.closed_loop_stop_hit = true;
    }
    if (auto snapshot = aggregates_controller.aggregates_snapshot()) {
        aggregate.aggregates_snapshot = snapshot;
    }
    std::sort(aggregate.closed_loop_flow_summaries.begin(),
              aggregate.closed_loop_flow_summaries.end());
    std::sort(aggregate.duplicate_exceeded_flow_summaries.begin(),
              aggregate.duplicate_exceeded_flow_summaries.end());

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
