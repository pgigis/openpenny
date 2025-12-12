// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/net/Packet.h"
#include "openpenny/penny/flow/manager/ThreadFlowManager.h"

#include <functional>
#include <memory>
#include <optional>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace openpenny {

/** 
 * Function that checks if an incoming flow matches the one we are testing.
 * Return true to log/track the flow, false to ignore it.
 */
using FlowMatcher = std::function<bool(const FlowKey&)>;

/**
 * Runs the active packet processing loop.
 *
 * Reads packets from a network interface or other source.
 * Sends matching traffic into Penny for classification.
 * Tracks open TCP flows while dropping packets stochastically.
 * Periodically logs per-flow metrics.
 */
class ActiveTestPipelineRunner {
public:
    /**
     * Construct the pipeline runner.
     *
     * @param cfg     Shared config values (interface, queue, thresholds, drop probs).
     * @param opts    Pipeline options (prefix filter, TUN forwarding, etc).
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
     * Runs until:
     *  - the Penny test completes, or
     *  - a stop signal is triggered, or
     *  - the packet reader fails to return packets.
     *
     * @return ModeResult if Penny finishes cleanly, or std::nullopt otherwise.
     */
    std::optional<ModeResult> run();

private:
    // -------------------------------------------------------------------------
    // Packet processing logic
    // -------------------------------------------------------------------------

    /** Process one packet through the Penny + monitoring heuristics path. */
    void handle_packet(const net::PacketView& packet,
                       const std::chrono::steady_clock::time_point& now);

    /** Check early-exit condition (stop flag or Penny finished). */
    bool should_stop() const;

    /** Push a packet to TUN interface or next hop if forwarding is enabled. */
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
     * Avoids copying config into multiple places.
     */
    const Config& cfg_;

    /**
     * Pipeline options.
     * Not mutated during runtime, only read in hot paths.
     */
    const PipelineOptions& opts_;

    /**
     * User matcher to decide if a flow is of interest.
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
     * Friendly name for this worker thread.
     */
    std::string thread_name_;

    /**
     * Packet source handle.
     * Must be opened via source_->open(if, queue) before pipeline starts.
     */
    net::PacketSourcePtr source_;

    /**
     * Flag to track when Penny finishes the test.
     * Once true, the loop exits early.
     */
    bool penny_finished_{false};

    /**
     * Total number of packets processed by the pipeline.
     * Used for rate-based stats logging.
     */
    std::size_t total_pkts_processed_{0};
    std::size_t total_pkts_forwarded_{0};
    std::size_t total_forward_errors_{0};

    /**
     * Last time we logged global stats.
     * Prevents log flooding.
     */
    std::chrono::steady_clock::time_point last_stats_log_{std::chrono::steady_clock::now()};

    /** Idle timeout to expire flows when traffic stops (0 disables). */
    std::chrono::steady_clock::duration idle_timeout_{};
};

} // namespace openpenny
