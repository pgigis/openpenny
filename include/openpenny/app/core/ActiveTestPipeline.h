// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/PipelineRunner.h"
#include "openpenny/net/Packet.h"
#include "openpenny/penny/flow/manager/ThreadFlowManager.h"

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace openpenny {

/**
 * Runs the active packet processing loop.
 *
 * Reads packets from a network interface or other source.
 * Sends matching traffic into Penny for classification.
 * Tracks open TCP flows while dropping packets stochastically.
 * Periodically logs per-flow metrics.
 *
 * Implemented as an IPipelineStrategy: the shared PipelineRunner drives
 * the source and the poll loop; this class supplies the active-mode
 * packet handling, timer draining, idle back-off, and result
 * finalization via the strategy hooks.
 */
class ActiveTestPipelineRunner : public IPipelineStrategy {
public:
    /**
     * Construct the pipeline runner.
     *
     * @param cfg     Shared config values (interface, queue, thresholds, drop probs).
     * @param opts    Pipeline options (traffic matching, egress sink, etc).
     * @param matcher User predicate to filter/log specific flows.
     * @param source  Packet reader source (AF_PACKET, AF_XDP, pcap, etc).
     * @param drop_collector Shared drop snapshot collector across threads.
     * @param thread_name Friendly identifier for this worker thread.
     */
    ActiveTestPipelineRunner(const Config& cfg,
                             const PipelineOptions& opts,
                             FlowMatcher matcher,
                             net::PacketSourcePtr source,
                             DropCollectorPtr drop_collector,
                             std::string thread_name);

    /**
     * Start the pipeline.
     *
     * Delegates the loop skeleton to a PipelineRunner configured with
     * this object as the strategy. Runs until:
     *   - the Penny test completes, or
     *   - a stop signal is triggered, or
     *   - the packet reader fails to return packets.
     *
     * @return ModeResult on any clean exit, or std::nullopt when the
     *         packet source failed to open.
     */
    std::optional<ModeResult> run();

    // ---------------------------------------------------------------------
    // IPipelineStrategy hooks. Marked public because the PipelineRunner
    // calls them via the IPipelineStrategy vtable; declared as overrides
    // so the compiler catches signature drift.
    // ---------------------------------------------------------------------

    void on_opened() override;
    void on_closing() override;
    std::size_t poll_budget() const override;
    bool filter_at_input() const override { return false; } // XDP/BPF filters.
    void before_poll(const std::chrono::steady_clock::time_point& now) override;
    void on_packet(const net::PacketView& packet,
                   const std::chrono::steady_clock::time_point& now,
                   ModeResult& result) override;
    void after_poll(const std::chrono::steady_clock::time_point& now,
                    std::size_t processed_delta,
                    ModeResult& result) override;
    bool should_terminate() const override { return penny_finished_; }
    bool penny_completed() const override { return penny_finished_; }
    void finalize(ModeResult& result) override;

private:
    // -------------------------------------------------------------------------
    // Packet processing logic
    // -------------------------------------------------------------------------

    /** Process one packet through the Penny + monitoring heuristics path. */
    void handle_packet(const net::PacketView& packet,
                       const std::chrono::steady_clock::time_point& now);

    /** Check user-provided cooperative stop callback. */
    bool should_stop() const;

    /** Push a packet to the configured egress sink. */
    void forward_packet(const net::PacketView& packet);

    /** Print a single short debug line for a packet (if DEBUG is enabled). */
    void log_packet_line(const net::PacketView& packet) const;

    /**
     * Decide what to do with a newly seen packet/flow.
     *
     * Either:
     *  - register it in the flow table for Penny monitoring, or
     *  - immediately forward it if no monitoring is required.
     *
     * @return pointer to table entry if the flow is admitted, nullptr otherwise.
     */
    penny::FlowEngineEntry* admit_or_forward_flow(const net::PacketView& packet,
                                                 const std::chrono::steady_clock::time_point& now);

    /**
     * Promote a pending flow to active monitoring when we see evidence of repairs
     * (e.g. retransmissions filling sequence gaps).
     *
     * @return true if promoted, false otherwise.
     */
    bool promote_pending_flow(penny::FlowEngineEntry& entry,
                              const net::PacketView& packet,
                              const std::chrono::steady_clock::time_point& now);

    // -------------------------------------------------------------------------
    // Monitoring and decision helpers
    // -------------------------------------------------------------------------

    /** Return true if the duplicate packet threshold for this flow is exceeded. */
    bool flow_duplicate_threshold_exceeded(const penny::FlowEngine& flow);

    /** Return true if the out-of-order packet threshold for this flow is exceeded. */
    bool flow_out_of_order_threshold_exceeded(const penny::FlowEngine& flow);

    /** Process FIN packet and mark the connection as closed-loop finished. */
    void handle_fin(penny::FlowEngineEntry& entry, const net::PacketView& packet);

    /** Process RST packet and mark the flow as reset/interrupted. */
    void handle_rst(penny::FlowEngineEntry& entry, const net::PacketView& packet);

    /** Handle pure ACK packets (ACKs without payload), mainly for flow tracking. */
    void handle_pure_ack(penny::FlowEngineEntry& entry, const net::PacketView& packet);

    /**
     * Handle data packets:
     *  - feeding TCP payload into Penny,
     *  - recording sequence gaps,
     *  - repairing gaps via retransmissions if seen,
     *  - applying threshold heuristics.
     */
    void handle_data_packet(penny::FlowEngineEntry& entry,
                            const net::PacketView& packet,
                            const std::chrono::steady_clock::time_point& now);

    // -------------------------------------------------------------------------
    // Flow statistics logging
    // -------------------------------------------------------------------------

    /**
     * Periodically log per-flow classification stats.
     * Keeps output light if called too frequently.
     */
    void maybe_log_flow_stats(penny::FlowEngineEntry& entry,
                              const std::chrono::steady_clock::time_point& now);

    /** Expire idle flows based on configured timeout. */
    void expire_idle_flows(const std::chrono::steady_clock::time_point& now);

    /** Sweep pending snapshots and expire those past timeout. */
    void sweep_expired_snapshots(const std::chrono::steady_clock::time_point& now);

    // -------------------------------------------------------------------------
    // Member state
    // -------------------------------------------------------------------------

    /**
     * Immutable shared configuration reference.
     */
    const Config& cfg_;

    /**
     * Pipeline options. Read-only in hot paths.
     */
    const PipelineOptions& opts_;

    /**
     * User matcher. Retained for observability / per-flow logging; the
     * PipelineRunner is told not to apply it at ingress because active
     * mode filters in XDP/BPF instead.
     */
    FlowMatcher matcher_;

    /**
     * Per-thread flow manager tracking monitored flows and aggregating stats.
     */
    penny::ThreadFlowManager flow_manager_;

    /**
     * Shared collector for drop snapshots across all active pipeline threads.
     */
    DropCollectorPtr drop_collector_;

    /**
     * Collector shard assigned to this worker thread.
     */
    std::size_t drop_collector_shard_index_{0};

    /**
     * Friendly name for this worker thread.
     */
    std::string thread_name_;

    /**
     * Packet source handle. Ownership is handed to the PipelineRunner
     * when run() is called; kept here until then so the strategy can
     * be constructed before the runner.
     */
    net::PacketSourcePtr source_;

    /**
     * Flag flipped to true when Penny classifies enough traffic to end
     * the test. Read via should_terminate() so the shared loop exits
     * at the next iteration boundary.
     */
    bool penny_finished_{false};

    /**
     * Per-worker forward accounting. Runner owns packets_processed in
     * the ModeResult; these totals are merged in during finalize().
     */
    std::size_t total_pkts_forwarded_{0};
    std::size_t total_forward_errors_{0};

    /**
     * Last time we logged global stats (prevents log flooding).
     */
    std::chrono::steady_clock::time_point last_stats_log_{std::chrono::steady_clock::now()};

    /** Idle timeout to expire flows when traffic stops (0 disables). */
    std::chrono::steady_clock::duration idle_timeout_{};

    /**
     * Idle back-off state. Tracked across after_poll() invocations so
     * the shared runner can re-enter before_poll() without resetting
     * the warning cadence.
     */
    unsigned idle_polls_{0};
    std::chrono::steady_clock::time_point idle_start_{std::chrono::steady_clock::now()};
};

} // namespace openpenny
