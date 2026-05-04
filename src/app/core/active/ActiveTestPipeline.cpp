// SPDX-License-Identifier: BSD-2-Clause

#include <cstddef>
#include <cerrno>
#include <cinttypes>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "openpenny/app/core/utils/FlowDebug.h"
#include "openpenny/app/core/ActiveTestPipeline.h"
#include "openpenny/app/core/PipelineRunner.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/DropCollectorBinding.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/log/Log.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <algorithm>

namespace openpenny {

namespace {
thread_local ActiveTestPipelineRunner* tls_runner = nullptr;

std::string format_closed_loop_flow_summary(const FlowKey& key,
                                            const penny::FlowEngine& flow) {
    std::ostringstream summary;
    summary << flow_debug_details(key)
            << " data=" << flow.data_packets()
            << " dropped=" << flow.dropped_packets()
            << " rtx=" << flow.retransmitted_packets()
            << " non_rtx=" << flow.non_retransmitted_packets()
            << " dup=" << flow.duplicate_packets()
            << " in_order=" << flow.in_order_packets()
            << " out_of_order=" << flow.out_of_order_packets();
    return summary.str();
}
} // namespace

// Constructs an active OpenPenny traffic processing pipeline runner.
ActiveTestPipelineRunner::ActiveTestPipelineRunner(
    const Config& cfg,
    const PipelineOptions& opts,
    FlowMatcher matcher,
    net::PacketSourcePtr source,
    DropCollectorPtr drop_collector,
    std::string thread_name
) : cfg_{cfg},                        // Store the pipeline configuration (e.g., ports, drop rates, logging cadence).
    opts_{opts},                      // Store runtime pipeline options (e.g., scheduling parameters, throughput modes).
    matcher_{std::move(matcher)},      // Take ownership of the FlowMatcher used to classify relevant packets/flows.
    flow_manager_{cfg.active},         // Manage active monitored flows and aggregate per-flow stats.
    drop_collector_{std::move(drop_collector)}, // Shared drop snapshot collector across threads.
    drop_collector_shard_index_{app::current_thread_counter_index()}, // Bind collector writes to the current worker shard.
    thread_name_{std::move(thread_name)},       // Friendly identifier for this worker thread.
    source_{std::move(source)},        // Take ownership of the packet source interface used to receive network packets.
    last_stats_log_{std::chrono::steady_clock::now()},  // Record current time to pace the first periodic stats log.
    idle_timeout_{std::chrono::duration_cast<std::chrono::steady_clock::duration>(
        std::chrono::duration<double>(cfg.active.flow_idle_timeout_seconds))} // Idle expiry window.
{
    if (drop_collector_) {
        flow_manager_.set_drop_sink(
            [collector = drop_collector_,
             name = thread_name_,
             shard_index = drop_collector_shard_index_](const FlowKey& key,
                                                        penny::PacketDropId packet_id,
                                                        penny::PacketDropSnapshot snapshot) {
            app::DropCollectorBinding::instance().upsert(
                collector,
                name,
                shard_index,
                key,
                packet_id,
                snapshot);
        });
        flow_manager_.set_snapshot_refresh_sink(
            [collector = drop_collector_,
             name = thread_name_,
             shard_index = drop_collector_shard_index_](
                const FlowKey& key,
                const std::vector<std::pair<penny::PacketDropId, penny::PacketDropSnapshot>>& snapshots,
                std::size_t start_index) {
                app::DropCollectorBinding::instance().refresh_from(
                    collector,
                    name,
                    shard_index,
                    key,
                    snapshots,
                    start_index);
            });
    }
}

bool ActiveTestPipelineRunner::should_stop() const {
    return opts_.should_stop && opts_.should_stop();
}

// Public-facing entry point. Installs the thread-local runner guard,
// hands ownership of the source to a PipelineRunner, and delegates the
// loop.
std::optional<ModeResult> ActiveTestPipelineRunner::run() {
    struct RunnerGuard {
        ActiveTestPipelineRunner*& slot;
        ActiveTestPipelineRunner* prev;
        ~RunnerGuard() { slot = prev; }
    };
    auto* prev_runner = tls_runner;
    tls_runner = this;
    RunnerGuard guard{tls_runner, prev_runner};

    PipelineRunner runner(cfg_,
                          opts_,
                          matcher_,
                          std::move(source_),
                          *this,
                          thread_name_);
    return runner.run();
}

// ---------------------------------------------------------------------------
// IPipelineStrategy hooks
// ---------------------------------------------------------------------------

std::size_t ActiveTestPipelineRunner::poll_budget() const {
    // Derive a poll budget from source configuration when available.
    if (cfg_.input.backend == PacketInputBackend::Dpdk && cfg_.dpdk.burst > 0) {
        return cfg_.dpdk.burst;
    }
    if (cfg_.xdp_runtime.batch > 0) {
        return cfg_.xdp_runtime.batch;
    }
    return 0;
}

void ActiveTestPipelineRunner::on_opened() {
    // Traffic match and egress sink lines used to print here, once per
    // worker. With many workers that produced 63+ duplicate lines per
    // run. They now print once at the driver level (see
    // OpenpennyPipelineDriver::drive_pipeline). on_opened() now only
    // resets the per-queue idle accumulator.
    idle_polls_ = 0;
    idle_start_ = std::chrono::steady_clock::now();
}

void ActiveTestPipelineRunner::before_poll(
    const std::chrono::steady_clock::time_point& /*now*/) {
    // Apply timer-produced callbacks on this thread to keep FlowEngine single-threaded.
    penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
}

void ActiveTestPipelineRunner::on_packet(
    const net::PacketView& packet,
    const std::chrono::steady_clock::time_point& now,
    ModeResult& /*result*/) {
    handle_packet(packet, now);
}

void ActiveTestPipelineRunner::after_poll(
    const std::chrono::steady_clock::time_point& now,
    std::size_t processed_delta,
    ModeResult& /*result*/) {
    if (processed_delta == 0) {
        // No packets processed this poll; back off to avoid hot-spinning
        // when sockets/maps are misconfigured.
        ++idle_polls_;
        const auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 now - idle_start_).count();
        if (idle_ms >= 3000) {
            // Per-queue idle log is at DEBUG. With many workers this would
            // be 21+ lines/s of identical "no packets" warnings; the
            // process-level no-packets watchdog (in OpenpennyPipelineDriver)
            // already prints a single actionable WARN at 5s.
            if (TCPLOG_ENABLED(DEBUG)) {
                TCPLOG_DEBUG("No packets processed on %s q%u for %lld ms "
                             "(polls=%u); backing off (check XDP/XSK binding)",
                             cfg_.ifname.c_str(),
                             cfg_.queue,
                             static_cast<long long>(idle_ms),
                             idle_polls_);
            }
            // Reset the accumulator regardless of log level. Without this,
            // idle_polls_ counts forever once DEBUG is off and the next
            // DEBUG message (if level changes mid-run) would print stale
            // values.
            idle_start_ = now;
            idle_polls_ = 0;
        }
        if (idle_ms >= 3000) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            // Drain timer callbacks so expirations still apply while idle.
            penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
        }
    } else {
        idle_polls_ = 0;
        idle_start_ = now;
    }

    if (idle_timeout_.count() > 0) {
        expire_idle_flows(now);
    }
    evaluate_individual_flows_if_enabled();
    complete_resolved_terminal_flows();
    // Mirrors the post-loop drain in the legacy run() so deferred
    // expirations aren't stranded between iterations.
    penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
}

void ActiveTestPipelineRunner::on_closing() {
    // Flush any callbacks that arrived after the final poll iteration.
    penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
    evaluate_individual_flows_if_enabled();
    complete_resolved_terminal_flows();
}

void ActiveTestPipelineRunner::finalize(ModeResult& result) {
    // Resolve any pending snapshots on remaining flows without bypassing the
    // configured retransmission timeout at shutdown.
    flow_manager_.for_each_flow([](const FlowKey&, penny::FlowEngineEntry& entry) {
        entry.flow.resolve_pending_snapshots(std::chrono::steady_clock::now());
    });
    evaluate_individual_flows_if_enabled();
    complete_resolved_terminal_flows();

    result.packets_forwarded = total_pkts_forwarded_;
    result.forward_errors = total_forward_errors_;
    result.closed_loop_flow_summaries = closed_loop_flow_summaries_;
    result.duplicate_exceeded_flow_summaries = duplicate_exceeded_flow_summaries_;
}

// ---------------------------------------------------------------------------
// Flow / timer helpers (unchanged from pre-Chunk-2 implementation)
// ---------------------------------------------------------------------------

// Entry point for each packet: log, admit flow, and dispatch to ACK/data handlers.
void ActiveTestPipelineRunner::expire_idle_flows(const std::chrono::steady_clock::time_point& now) {
    if (idle_timeout_.count() <= 0) return;
    auto expired = flow_manager_.collect_idle_flows(now, idle_timeout_);
    for (const auto& key : expired) {
        complete_flow_with_summary(key, "idle_timeout");
    }
}

bool ActiveTestPipelineRunner::individual_flow_evaluation_enabled() const {
    const bool aggregate_phase_configured =
        cfg_.active.aggregates_enabled &&
        cfg_.active.max_drops_aggregates > 0;
    if (!aggregate_phase_configured) {
        return true;
    }
    const auto status = openpenny::current_aggregates_status();
    return status == RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP ||
           status == RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED;
}

void ActiveTestPipelineRunner::evaluate_individual_flows_if_enabled() {
    if (!individual_flow_evaluation_enabled()) {
        return;
    }

    flow_manager_.for_each_flow([&](const FlowKey& key, penny::FlowEngineEntry& entry) {
        const bool immutable_terminal_state =
            entry.state == penny::FlowTrackingState::INTERRUPTED_RST ||
            entry.state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
            entry.state == penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED ||
            entry.state == penny::FlowTrackingState::FINISHED;

        if (!immutable_terminal_state) {
            if (flow_out_of_order_threshold_exceeded(entry.flow)) {
                entry.state = penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED;
                if (TCPLOG_ENABLED(DEBUG)) {
                    const auto flow_tag = flow_debug_details(key);
                    TCPLOG_DEBUG("Out-of-order threshold exceeded %s", flow_tag.c_str());
                }
                return;
            }
            if (flow_duplicate_threshold_exceeded(entry.flow)) {
                entry.state = penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED;
                if (TCPLOG_ENABLED(DEBUG)) {
                    const auto flow_tag = flow_debug_details(key);
                    TCPLOG_DEBUG("Duplicate threshold exceeded %s", flow_tag.c_str());
                }
                return;
            }
        }

        if (entry.flow.final_decision() == penny::FlowEngine::FlowDecision::PENDING) {
            entry.flow.evaluate_if_ready();
        }

        if (entry.state != penny::FlowTrackingState::CONNECTION_CLOSED_FIN &&
            !immutable_terminal_state &&
            entry.flow.final_decision() != penny::FlowEngine::FlowDecision::PENDING) {
            entry.state = penny::FlowTrackingState::FINISHED;
        }
    });
}

void ActiveTestPipelineRunner::complete_resolved_terminal_flows() {
    std::vector<FlowKey> completed_keys;
    const bool individual_eval_enabled = individual_flow_evaluation_enabled();
    flow_manager_.for_each_flow([&](const FlowKey& key, penny::FlowEngineEntry& entry) {
        const bool terminal_state =
            entry.state == penny::FlowTrackingState::INTERRUPTED_RST ||
            entry.state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
            entry.state == penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED ||
            entry.state == penny::FlowTrackingState::CONNECTION_CLOSED_FIN ||
            entry.state == penny::FlowTrackingState::FINISHED;
        if (!terminal_state) return;
        if (!individual_eval_enabled &&
            entry.flow.final_decision() == penny::FlowEngine::FlowDecision::PENDING) {
            return;
        }
        if (entry.flow.pending_retransmissions() != 0) return;
        completed_keys.push_back(key);
    });

    for (const auto& key : completed_keys) {
        complete_flow_with_summary(key, "terminal_state");
    }
}

void ActiveTestPipelineRunner::complete_flow_with_summary(const FlowKey& key, const char* reason) {
    auto* existing = flow_manager_.find(key);
    if (!existing) {
        return;
    }
    existing->flow.resolve_pending_snapshots(std::chrono::steady_clock::now());
    const auto final_decision = existing->flow.final_decision();
    const auto summary = format_closed_loop_flow_summary(key, existing->flow);
    if (final_decision == penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP) {
        closed_loop_flow_summaries_.push_back(summary);
    }
    if (existing->state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
        final_decision == penny::FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED) {
        duplicate_exceeded_flow_summaries_.push_back(summary);
    }
    flow_manager_.complete_flow(key, reason);
}

void ActiveTestPipelineRunner::handle_packet(const net::PacketView& packet,
                                             const std::chrono::steady_clock::time_point& now) {
    // Check whether the packet belongs to one of the currently monitored flows.
    // If it does not, and parallel monitoring capacity is still available, start
    // tracking the new flow. A flow can be added to monitoring using a SYN packet
    // (which initiates a TCP handshake) or any other packet observed in the traffic.
    auto* penny_entry = admit_or_forward_flow(packet, now);
    if (!penny_entry) {
        return;
    }
    flow_manager_.touch_flow(packet.flow, now);

    // Check if packet is RST.
    handle_rst(*penny_entry, packet);
    if (penny_entry->state == penny::FlowTrackingState::INTERRUPTED_RST) {
        forward_packet(packet);
        return;
    }

    handle_fin(*penny_entry, packet);
    if (penny_entry->state == penny::FlowTrackingState::CONNECTION_CLOSED_FIN) {
        forward_packet(packet);
        return;
    }

    if (packet.payload_bytes == 0) {
        handle_pure_ack(*penny_entry, packet);
        return;
    }

    handle_data_packet(*penny_entry, packet, now);
}

// Decide whether to monitor this flow or simply forward it.
// Returns a pointer to the flow entry if it is actively monitored.
// Otherwise forwards the packet and returns nullptr.
penny::FlowEngineEntry* ActiveTestPipelineRunner::admit_or_forward_flow(
    const net::PacketView& packet,
    const std::chrono::steady_clock::time_point& now) {
    auto* flow_entry = flow_manager_.find(packet.flow);

    // Skip flows we've already monitored in the past.
    if (!flow_entry && flow_manager_.was_completed(packet.flow)) {
        forward_packet(packet);
        return nullptr;
    }

    if (!flow_entry && flow_manager_.is_flow_monitoring_capacity_full()) {
        // Flow is not tracked, and there are no spare monitoring slots.
        forward_packet(packet);
        return nullptr;
    }

    if (flow_entry &&
        (flow_entry->state == penny::FlowTrackingState::INTERRUPTED_RST ||
         flow_entry->state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
         flow_entry->state == penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED ||
         flow_entry->state == penny::FlowTrackingState::CONNECTION_CLOSED_FIN ||
         flow_entry->state == penny::FlowTrackingState::FINISHED)) {
        // Terminal flows with unresolved drops stay resident until the
        // retransmission gap is filled or the timeout expires.
        if (flow_entry->flow.pending_retransmissions() == 0) {
            complete_flow_with_summary(packet.flow, "terminal_state");
        }
        forward_packet(packet);
        return nullptr;
    }

    if (flow_entry) {
        const auto penny_flow_decision = flow_entry->flow.final_decision();
        const bool terminal_state =
        flow_entry->state == penny::FlowTrackingState::INTERRUPTED_RST ||
        flow_entry->state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
        flow_entry->state == penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED ||
        flow_entry->state == penny::FlowTrackingState::CONNECTION_CLOSED_FIN ||
        flow_entry->state == penny::FlowTrackingState::FINISHED;

        if (!terminal_state && penny_flow_decision != penny::FlowEngine::FlowDecision::PENDING) {
            flow_entry->state = penny::FlowTrackingState::FINISHED;
            complete_flow_with_summary(packet.flow, "penny_decision");
            forward_packet(packet);
            return nullptr;
        }
    }

    if (!flow_entry) {
        try {
            const bool is_syn = packet.tcp.flags_view().syn;
            flow_entry = flow_manager_.add_new_flow(
                packet.flow,
                packet.tcp.seq,
                static_cast<uint32_t>(packet.payload_bytes),
                is_syn,
                now);
            if (flow_entry) {
                if (TCPLOG_ENABLED(INFO)) {
                    const auto flow_tag = flow_debug_details(packet.flow);
                    TCPLOG_INFO("[flow_track] action=start trigger=%s flow=%s seq=%" PRIu32 " payload=%zu",
                        is_syn ? "syn" : "data",
                        flow_tag.c_str(),
                        packet.tcp.seq,
                        packet.payload_bytes);
                }
            }
        } catch (const std::exception& ex) {
            const auto src_ip = to_ipv4_string(packet.flow.src);
            const auto dst_ip = to_ipv4_string(packet.flow.dst);
            TCPLOG_ERROR(
                "Failed to monitor new flow for packet src=%s:%u dst=%s:%u seq=%u ack=%u "
                "flags=0x%02x payload=%llu: %s",
                src_ip.c_str(),
                packet.flow.sport,
                dst_ip.c_str(),
                packet.flow.dport,
                packet.tcp.seq,
                packet.tcp.ack,
                static_cast<unsigned>(packet.tcp.flags),
                static_cast<unsigned long long>(packet.payload_bytes),
                ex.what());
        }
        forward_packet(packet);
        return nullptr;
    }

    // The flow is already monitored, but we first observed a data packet and are now
    // collecting sequence observations until we are confident about the highest SEQ number.
    if (flow_entry && flow_entry->state == penny::FlowTrackingState::PENDING_SEEN_DATA) {
        if (!promote_pending_flow(*flow_entry, packet, now)) {
            forward_packet(packet);
            return nullptr;
        }
    }
    return flow_entry;
}


/**
 * Decide whether a pending flow has accumulated enough sequential data to become active.
 * @param entry  Penny flow table entry currently in PENDING_SEEN_DATA.
 * @param packet Latest data-bearing packet for the flow (provides SEQ for progress detection).
 * @param now    Timestamp of packet arrival used to test the monitoring delay window.
 * @return true when the flow transitions to ACTIVE_SEEN_DATA; false to keep observing.
 */
bool ActiveTestPipelineRunner::promote_pending_flow(
    penny::FlowEngineEntry& entry,
    const net::PacketView& packet,
    const std::chrono::steady_clock::time_point& now) {

    auto& flow = entry.flow;

    const uint32_t packet_end_seq =
        packet.tcp.seq + static_cast<uint32_t>(packet.payload_bytes);
    const bool new_highest_seq = packet_end_seq > flow.highest_sequence(); // Track forward progress to avoid flapping.
    if (!new_highest_seq) return false;

    const auto first_data_time = flow.first_data_time();
    const double wait_seconds = cfg_.active.flow_grace_period_seconds;
    const bool ready_to_promote =
        first_data_time.has_value() && wait_seconds > 0.0 &&
        std::chrono::duration<double>(now - *first_data_time).count() >= wait_seconds;

    if (ready_to_promote) {
        entry.state = penny::FlowTrackingState::ACTIVE_SEEN_DATA;
        return true;
    }

    // Still inside the waiting window; remember the newest SEQ so we can later detect growth past the threshold.
    flow.record_data(packet.tcp.seq, now);
    return false;
}

// Fast-path check for RST that marks outstanding drop snapshots as invalid.
void ActiveTestPipelineRunner::handle_rst(penny::FlowEngineEntry& entry, const net::PacketView& packet) {
    if ((packet.tcp.flags & 0x04) == 0) return; // RST bit not set.

    auto& flow = entry.flow;
    if (flow.pending_retransmissions() > 0) {
        const auto& snapshots = flow.drop_snapshots();
        for (const auto& snap_pair : snapshots) {
            const auto& snapshot = snap_pair.second;

            // Skip snapshots already decided.
            if (snapshot.state != penny::SnapshotState::Pending ||
                snapshot.stats.pending_retransmissions() == 0) {
                continue;
            }

            flow.mark_snapshot_invalid(snap_pair.first); // Treat pending gaps as invalid on reset.
            if (flow.pending_retransmissions() == 0) break;
        }
        penny::ThreadFlowEventTimerManager::instance().purge_flow(&flow);
    }
    entry.state = penny::FlowTrackingState::INTERRUPTED_RST;
}

// Fast-path check for FIN. A clean close means any still-missing dropped
// payload was not retransmitted before teardown, so we resolve it immediately.
void ActiveTestPipelineRunner::handle_fin(penny::FlowEngineEntry& entry, const net::PacketView& packet) {
    if ((packet.tcp.flags & 0x01) == 0) return; // FIN bit not set.

    auto& flow = entry.flow;
    if (flow.pending_retransmissions() > 0) {
        const auto& snapshots = flow.drop_snapshots();
        for (const auto& snap_pair : snapshots) {
            const auto& snapshot = snap_pair.second;

            if (snapshot.state != penny::SnapshotState::Pending ||
                snapshot.stats.pending_retransmissions() == 0) {
                continue;
            }

            flow.mark_snapshot_expired(snap_pair.first);
            if (flow.pending_retransmissions() == 0) break;
        }
        penny::ThreadFlowEventTimerManager::instance().purge_flow(&flow);
    }
    entry.state = penny::FlowTrackingState::CONNECTION_CLOSED_FIN;
}

// Lightweight path for ACK-only packets: update counters and forward.
void ActiveTestPipelineRunner::handle_pure_ack(penny::FlowEngineEntry& entry,
                                           const net::PacketView& packet) {
    entry.flow.record_pure_ack();
    maybe_log_flow_stats(entry, std::chrono::steady_clock::now());
    forward_packet(packet);
}

// Full data-path handling: ordering/duplicate detection, gap accounting, drop heuristic, and forwarding.
void ActiveTestPipelineRunner::handle_data_packet(penny::FlowEngineEntry& entry,
                            const net::PacketView& packet,
                            const std::chrono::steady_clock::time_point& now) {
    // Count flow-level stats for data-bearing packets.
    entry.flow.record_data_packet();

    const uint32_t start_seq = packet.tcp.seq;
    const uint32_t end_seq = start_seq + static_cast<uint32_t>(packet.payload_bytes);

    // Combined ordering + interval tracking.
    const auto interval_mark = entry.flow.mark_interval(start_seq, end_seq);

    if (interval_mark.in_sequence) {
        // If its in-sequence it can not be a duplicate or a retransmission
        entry.flow.record_droppable_packet();

        const auto packet_id = packet.packet_id();
        const bool dropped = entry.flow.drop_packet(start_seq, end_seq, packet_id, packet.flow, now);
        if (dropped) {
            return;
        }
        // We forward the packet.
        forward_packet(packet);
        return;
    }

    // The packet is out of sequence. It may be a duplicate, either caused by a retransmission
    // triggered by the sequence gap created when we dropped a packet, or a duplicate of a packet
    // we never interfered with. There is also the possibility that the packet is not a duplicate
    // at all, but contains previously unseen bytes and is genuinely unique, just arriving out of order.

    const bool raw_duplicate = interval_mark.duplicate;
    // If the packet has not been seen before, it is simply an out-of-order packet.
    if (!raw_duplicate){
        if (TCPLOG_ENABLED(DEBUG)) {
            const auto flow_tag = flow_debug_details(packet.flow);
            TCPLOG_DEBUG("[ooo] flow=%s seq=%u-%u highest_seen=%u",
                         flow_tag.c_str(),
                         start_seq,
                         end_seq,
                         entry.flow.highest_sequence());
        }
        const bool ooo_exceeded =
            individual_flow_evaluation_enabled() &&
            flow_out_of_order_threshold_exceeded(entry.flow);
        if (ooo_exceeded) {
            entry.state = penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED;
            if (TCPLOG_ENABLED(DEBUG)) {
                const auto flow_tag = flow_debug_details(packet.flow);
                TCPLOG_DEBUG("Out-of-order threshold exceeded %s", flow_tag.c_str());
            }
        }
        forward_packet(packet);
        return;
    }

    // If the packet retransmits data, this can be either a full or partial retransmission
    // caused by the gap we introduced, or a packet retransmitting bytes that we did not drop,
    // which should be marked as a duplicate. If the packet retransmits both bytes that we dropped
    // and bytes that we did not, we should fill the sequence gap but count the packet as a duplicate
    // for measurement purposes.

    const bool touches_gap = interval_mark.touches_gap;
    bool gap_partially_filled = false;
    std::vector<penny::PacketDropId> filled_gaps;
    bool fills_only_gap_space = false;
     // First, we check whether the packet touches the byte ranges affected by our packet drops.
        if (!touches_gap){
            entry.flow.record_duplicate_packet();
            penny::ThreadFlowEventTimerManager::instance().enqueue_duplicate(&entry.flow, start_seq, packet.payload_bytes);
            // Logging handled in timer callback.

            const bool dup_exceeded =
                individual_flow_evaluation_enabled() &&
                flow_duplicate_threshold_exceeded(entry.flow);
            if (dup_exceeded) {
                entry.state = penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED;
                if (TCPLOG_ENABLED(DEBUG)) {
                const auto flow_tag = flow_debug_details(packet.flow);
                TCPLOG_DEBUG("Duplicate threshold exceeded %s", flow_tag.c_str());
            }
        }
        forward_packet(packet);
        return;

    }else{
        // The packet overlaps with byte ranges that fall within the sequence gaps we introduced.
        fills_only_gap_space = entry.flow.fills_only_gap_space(start_seq, end_seq);
        filled_gaps = entry.flow.fill_gaps(start_seq, end_seq, &gap_partially_filled);
        if (!filled_gaps.empty()) {
            entry.flow.register_filled_gaps(filled_gaps);
        }
        if (!fills_only_gap_space){
            entry.flow.record_duplicate_packet();
            penny::ThreadFlowEventTimerManager::instance().enqueue_duplicate(&entry.flow, start_seq, packet.payload_bytes);
            // Logging handled in timer callback.

            const bool dup_exceeded =
                individual_flow_evaluation_enabled() &&
                flow_duplicate_threshold_exceeded(entry.flow);
            if (dup_exceeded) {
                entry.state = penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED;
                if (TCPLOG_ENABLED(DEBUG)) {
                    const auto flow_tag = flow_debug_details(packet.flow);
                    TCPLOG_DEBUG("Duplicate threshold exceeded %s", flow_tag.c_str());
                }
            }
            forward_packet(packet);
            return;
            }
        }
    forward_packet(packet);
}

// Emit a matched packet via the configured PacketSink. Per-worker
// totals live on this runner and are merged into ModeResult in
// finalize().
void ActiveTestPipelineRunner::forward_packet(const net::PacketView& packet) {
    TCPLOG_DEBUG("Forward Packet%s", "");
    if (!opts_.sink) {
        return;
    }
    if (opts_.sink->write(packet)) {
        ++total_pkts_forwarded_;
    } else if (!packet.layer3_ptr || packet.layer3_length == 0) {
        // No payload to forward -- not a sink error.
    } else {
        // Sink logs the specific failure; we just count it.
        ++total_forward_errors_;
    }
}

// Check duplicate ratio on live flow counters.
bool ActiveTestPipelineRunner::flow_duplicate_threshold_exceeded(const penny::FlowEngine& flow) {
    if (cfg_.active.max_duplicate_fraction <= 0.0) return false;
    const auto data_pkts = flow.data_packets();
    if (data_pkts == 0) return false;
    double dup_ratio = static_cast<double>(flow.duplicate_packets()) /
                       static_cast<double>(data_pkts);
    if (dup_ratio > cfg_.active.max_duplicate_fraction) {
        if (TCPLOG_ENABLED(DEBUG)) {
            const auto flow_tag = flow_debug_details(flow.flow_key());
            TCPLOG_DEBUG("FlowEngine duplicate ratio %.3f exceeded threshold %.3f %s",
                         dup_ratio,
                         cfg_.active.max_duplicate_fraction,
                         flow_tag.c_str());
        }
        return true;
    }
    return false;
}

// Check out-of-order ratio on live flow counters.
bool ActiveTestPipelineRunner::flow_out_of_order_threshold_exceeded(const penny::FlowEngine& flow) {
    if (cfg_.active.max_out_of_order_fraction <= 0.0) return false;
    const auto ordering_samples = flow.droppable_packets() + flow.out_of_order_packets();
    if (ordering_samples == 0) return false;
    double ooo_ratio = static_cast<double>(flow.out_of_order_packets()) /
                       static_cast<double>(ordering_samples);
    if (ooo_ratio > cfg_.active.max_out_of_order_fraction) {
        if (TCPLOG_ENABLED(DEBUG)) {
            const auto flow_tag = flow_debug_details(flow.flow_key());
            TCPLOG_DEBUG("FlowEngine out-of-order ratio %.3f exceeded threshold %.3f %s",
                         ooo_ratio,
                         cfg_.active.max_out_of_order_fraction,
                         flow_tag.c_str());
        }
        return true;
    }
    return false;
}

// Emit a concise single-line trace for the current packet. Gated on the
// global log level so it's a no-op outside DEBUG (the header comment
// promises this).
void ActiveTestPipelineRunner::log_packet_line(const net::PacketView& packet) const {
    if (!TCPLOG_ENABLED(DEBUG)) return;
    TCPLOG_DEBUG("TCP src=%s:%u dst=%s:%u seq=%u ack=%u flags=0x%02x",
                 to_ipv4_string(packet.flow.src).c_str(),
                 static_cast<unsigned>(packet.flow.sport),
                 to_ipv4_string(packet.flow.dst).c_str(),
                 static_cast<unsigned>(packet.flow.dport),
                 packet.tcp.seq,
                 packet.tcp.ack,
                 static_cast<unsigned>(packet.tcp.flags));
}

void ActiveTestPipelineRunner::maybe_log_flow_stats(penny::FlowEngineEntry& entry,
                                              const std::chrono::steady_clock::time_point& now) {
    if (entry.state != penny::FlowTrackingState::FINISHED) return;
    last_stats_log_ = now;
    const auto& key = entry.flow.flow_key();
    const auto flow_tag = flow_debug_details(key);
    TCPLOG_INFO(
        "Flow stats %s seen=%llu pure_ack=%llu data=%llu droppable=%llu dropped=%llu dup=%llu "
        "in_order=%llu out_of_order=%llu retransmitted=%llu non_rtx=%llu pending_rtx=%llu highest_seq=%u",
        flow_tag.c_str(),
        static_cast<unsigned long long>(entry.flow.packets_seen()),
        static_cast<unsigned long long>(entry.flow.pure_ack_packets()),
        static_cast<unsigned long long>(entry.flow.data_packets()),
        static_cast<unsigned long long>(entry.flow.droppable_packets()),
        static_cast<unsigned long long>(entry.flow.dropped_packets()),
        static_cast<unsigned long long>(entry.flow.duplicate_packets()),
        static_cast<unsigned long long>(entry.flow.in_order_packets()),
        static_cast<unsigned long long>(entry.flow.out_of_order_packets()),
        static_cast<unsigned long long>(entry.flow.retransmitted_packets()),
        static_cast<unsigned long long>(entry.flow.non_retransmitted_packets()),
        static_cast<unsigned long long>(entry.flow.pending_retransmissions()),
        static_cast<unsigned>(entry.flow.highest_sequence()));
}

} // namespace openpenny
