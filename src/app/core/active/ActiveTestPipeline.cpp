// SPDX-License-Identifier: BSD-2-Clause

#include <cstddef>
#include <cerrno>
#include <cinttypes>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <mutex>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "openpenny/app/core/utils/FlowDebug.h"
#include "openpenny/app/core/ActiveTestPipeline.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/DropCollectorBinding.h"
#include "openpenny/log/Log.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <algorithm>

namespace openpenny {

namespace {
thread_local ActiveTestPipelineRunner* tls_runner = nullptr;
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
    thread_name_{std::move(thread_name)},       // Friendly identifier for this worker thread.
    source_{std::move(source)},        // Take ownership of the packet source interface used to receive network packets.
    last_stats_log_{std::chrono::steady_clock::now()},  // Record current time to pace the first periodic stats log.
    idle_timeout_{std::chrono::duration_cast<std::chrono::steady_clock::duration>(
        std::chrono::duration<double>(cfg.active.flow_idle_timeout_seconds))} // Idle expiry window.
{
    if (drop_collector_) {
        app::DropCollectorBinding::instance().ensure_snapshot_hook();
        flow_manager_.set_drop_sink(
            [collector = drop_collector_, name = thread_name_](const FlowKey& key,
                                                               const std::string& packet_id,
                                                               penny::PacketDropSnapshot snapshot) {
            const auto agg = openpenny::app::aggregate_counters();
            snapshot.stats.overwrite_from_aggregates(agg);
            app::DropCollectorBinding::instance().upsert(
                collector,
                name,
                key,
                packet_id,
                snapshot,
                agg);
        });
    }
}

bool ActiveTestPipelineRunner::should_stop() const {
    return opts_.should_stop && opts_.should_stop();
}

// Main loop: open packet source, poll until Penny completes or stop requested, return run stats.
std::optional<ModeResult> ActiveTestPipelineRunner::run() {
    struct RunnerGuard {
        ActiveTestPipelineRunner*& slot;
        ActiveTestPipelineRunner* prev;
        ~RunnerGuard() { slot = prev; }
    };
    auto* prev_runner = tls_runner;
    tls_runner = this;
    RunnerGuard guard{tls_runner, prev_runner};

    if (!source_) {
        TCPLOG_ERROR("Packet source unavailable"); // Hardware or capture backend not configured or crashed.
        return std::nullopt;
    }

    // Open the configured interface and queue, similar to binding a monitoring box in an ISP rack.
    if (!source_->open(cfg_.ifname, cfg_.queue)) {
        TCPLOG_ERROR("Failed to open packet source on %s q%u",
                    cfg_.ifname.c_str(),
                    cfg_.queue); // Likely permission issue, absent NIC queue, or interface down.
        return std::nullopt;
    }

    // Print effective source filtering mode.
    if (opts_.has_prefix) {
        std::cout << "[openpenny] source prefix filter: " << opts_.prefix_cidr << '\n'; 
        // Only packets whose source IP matches the given CIDR prefix will be processed.
    } else {
        std::cout << "[openpenny] no source prefix filter (accepting all sources)" << '\n';
        // No upstream source restriction, pipeline sees the full access link aggregate.
    }

    // Print forwarding behaviour if TUN reinjection is enabled.
    if (opts_.forward_to_tun) {
        std::cout << "[openpenny] forwarding matched packets to TUN device: "
                  << (opts_.tun_name.empty() ? "<default>" : opts_.tun_name)
                  << '\n';
    } else if (opts_.forward_fd >= 0) {
        std::cout << "[openpenny] forwarding matched packets to fd "
                  << opts_.forward_fd
                  << (opts_.forward_device.empty() ? "" : (" (" + opts_.forward_device + ")"))
                  << '\n';
        // Realistic for an ISP scenario where sampled traffic slices are analysed off-box and reinjected.
    }
    
    net::PacketHandler handler = [this](const net::PacketView& packet) {
        handle_packet(packet, std::chrono::steady_clock::now());
    };

    // Derive a poll budget from source configuration when available.
    std::size_t poll_budget = 0;
    if (cfg_.dpdk.enable && cfg_.dpdk.burst > 0) {
        poll_budget = cfg_.dpdk.burst;
    } else if (cfg_.xdp_runtime.batch > 0) {
        poll_budget = cfg_.xdp_runtime.batch;
    }
    unsigned idle_polls = 0;
    auto idle_start = std::chrono::steady_clock::now();

    while (true) {
        // Apply timer-produced callbacks on this thread to keep FlowEngine single-threaded.
        penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
        if (penny_finished_) break;
        if (should_stop()) break;
        const auto before = total_pkts_processed_;
        if (!source_->poll(handler, poll_budget)) {
            TCPLOG_ERROR("Packet poll failed");
            break;
        }
        if (total_pkts_processed_ == before) {
            // No packets processed this poll; back off to avoid hot-spinning when sockets/maps are misconfigured.
            ++idle_polls;
            auto now = std::chrono::steady_clock::now();
            auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - idle_start).count();
            if (idle_ms >= 3000 && TCPLOG_ENABLED(WARN)) {
                TCPLOG_WARN("No packets processed on %s q%u for %lld ms (polls=%u); backing off (check XDP/XSK binding)",
                            cfg_.ifname.c_str(),
                            cfg_.queue,
                            static_cast<long long>(idle_ms),
                            idle_polls);
                idle_start = now;
                idle_polls = 0;
            }
            if (idle_ms >= 3000) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                // Drain timer callbacks so expirations still apply while idle.
                penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
            }
        } else {
            idle_polls = 0;
            idle_start = std::chrono::steady_clock::now();
        }
        if (idle_timeout_.count() > 0) {
            expire_idle_flows(std::chrono::steady_clock::now());
        }
        sweep_expired_snapshots(std::chrono::steady_clock::now());
        if (penny_finished_) break;
        penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
    }

    // Flush any callbacks that arrived after the final poll iteration.
    penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
    sweep_expired_snapshots(std::chrono::steady_clock::now());
    source_->close();

    // Expire any pending snapshots on remaining flows to ensure expirations are logged/applied.
    flow_manager_.for_each_flow([](const FlowKey&, penny::FlowEngineEntry& entry) {
        entry.flow.expire_all_pending_snapshots();
    });

    ModeResult result;
    result.packets_processed = total_pkts_processed_;
    result.packets_forwarded = total_pkts_forwarded_;
    result.forward_errors = total_forward_errors_;
    result.penny_completed = penny_finished_;
    result.aggregates_penny_completed = penny_finished_;
    return result;
}

// Entry point for each packet: log, admit flow, and dispatch to ACK/data handlers.
void ActiveTestPipelineRunner::expire_idle_flows(const std::chrono::steady_clock::time_point& now) {
    if (idle_timeout_.count() <= 0) return;
    auto expired = flow_manager_.collect_idle_flows(now, idle_timeout_);
    for (const auto& key : expired) {
        if (auto* entry = flow_manager_.find(key)) {
            app::DropCollectorBinding::instance().unbind(&entry->flow);
        }
        flow_manager_.complete_flow(key, "idle_timeout");
    }
}

void ActiveTestPipelineRunner::sweep_expired_snapshots(const std::chrono::steady_clock::time_point& now) {
    // Expire packet drop snapshots using the configured retransmission timeout (seconds).
    const auto retransmission_timeout = std::chrono::duration<double>(cfg_.active.rtt_timeout_factor);
    if (retransmission_timeout.count() <= 0.0) return;
    flow_manager_.for_each_flow([&](const FlowKey&, penny::FlowEngineEntry& entry) {
        const auto& snaps = entry.flow.drop_snapshots();
        for (const auto& pair : snaps) {
            if (pair.second.state != penny::SnapshotState::Pending) continue;
            if (now - pair.second.timestamp >= retransmission_timeout) {
                if (TCPLOG_ENABLED(INFO)) {
                    TCPLOG_INFO("[packet_expired] flow=%s packet_id=%s",
                                flow_debug_details(entry.flow.flow_key()).c_str(),
                                pair.first.c_str());
                }
                entry.flow.mark_snapshot_expired(pair.first);
            }
        }
    });
}

void ActiveTestPipelineRunner::handle_packet(const net::PacketView& packet,
                                             const std::chrono::steady_clock::time_point& now) {
    // Increase the global number of processed packets in this thread pipeline.
    ++total_pkts_processed_;
    // Count every packet observed on this thread (monitored or not).
    auto& counters = openpenny::app::current_thread_counters();
    counters.packets += 1;
    counters.bytes += static_cast<uint64_t>(packet.payload_bytes);

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

    // Skip flows we've already monitored in the past.
    if (flow_manager_.was_completed(packet.flow)) {
        forward_packet(packet);
        return nullptr;
    }

    const auto monitor_state = flow_manager_.flow_state(packet.flow);
    if (monitor_state == penny::FlowTrackingState::NOT_ACTIONABLE &&
        flow_manager_.is_flow_monitoring_capacity_full()) {
        // Flow is not tracked, and there are no spare monitoring slots.
        forward_packet(packet);
        return nullptr;
    }

    if (monitor_state == penny::FlowTrackingState::INTERRUPTED_RST ||
        monitor_state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
        monitor_state == penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED ||
        monitor_state == penny::FlowTrackingState::CONNECTION_CLOSED_FIN ||
        monitor_state == penny::FlowTrackingState::FINISHED) {
        // Mark flow as complete and free the monitoring slot.
        if (auto* existing = flow_manager_.find(packet.flow)) {
            app::DropCollectorBinding::instance().unbind(&existing->flow);
        }
        flow_manager_.complete_flow(packet.flow, "terminal_state");
        forward_packet(packet);
        return nullptr;
    }

    // Check whether the packet belongs to one of the flows currently being monitored.
    auto* flow_entry = flow_manager_.find(packet.flow);

    if (flow_entry) {
        const auto penny_flow_decision = flow_entry->flow.final_decision();
        if (penny_flow_decision != penny::FlowEngine::FlowDecision::PENDING){
            // From Penny perspective the test for the flow is done.


        }   
        const bool terminal_state =
        flow_entry->state == penny::FlowTrackingState::INTERRUPTED_RST ||
        flow_entry->state == penny::FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED ||
        flow_entry->state == penny::FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED ||
        flow_entry->state == penny::FlowTrackingState::CONNECTION_CLOSED_FIN ||
        flow_entry->state == penny::FlowTrackingState::FINISHED;

        if (!terminal_state && penny_flow_decision != penny::FlowEngine::FlowDecision::PENDING) {
            flow_entry->state = penny::FlowTrackingState::FINISHED;
            app::DropCollectorBinding::instance().unbind(&flow_entry->flow);
            flow_manager_.complete_flow(packet.flow, "penny_decision");
            forward_packet(packet);
            return nullptr;
        }
    }

    if (!flow_entry && !flow_manager_.is_flow_monitoring_capacity_full()) {
        try {
            const bool is_syn = packet.tcp.flags_view().syn;
            const bool inserted = flow_manager_.add_new_flow(
                packet.flow,
                packet.tcp.seq,
                static_cast<uint32_t>(packet.payload_bytes),
                is_syn,
                now);
            if (inserted) {
                if (drop_collector_) {
                    if (auto* entry = flow_manager_.find(packet.flow)) {
                        app::DropCollectorBinding::instance().bind(&entry->flow, drop_collector_, thread_name_);
                    }
                }
                if (TCPLOG_ENABLED(INFO)) {
                    const auto flow_tag = flow_debug_details(packet.flow);
                    TCPLOG_INFO("[monitor_start] %s flow=%s seq=%" PRIu32 " payload_bytes=%zu",
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

// Fast-path check for RST that marks outstanding drop snapshots as expired.
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

// Fast-path check for FIN that marks outstanding drop snapshots as expired.
void ActiveTestPipelineRunner::handle_fin(penny::FlowEngineEntry& entry, const net::PacketView& packet) {
    if ((packet.tcp.flags & 0x01) == 0) return; // FIN bit not set.

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

            flow.mark_snapshot_invalid(snap_pair.first); // Treat pending gaps as invalid on close.
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
    /*if (TCPLOG_ENABLED(DEBUG)) {
        TCPLOG_DEBUG("Interval mark seq=%u-%u in_seq=%d duplicate=%d touches_gap=%d",
                     start_seq,
                     end_seq,
                     interval_mark.in_sequence ? 1 : 0,
                     interval_mark.duplicate ? 1 : 0,
                     interval_mark.touches_gap ? 1 : 0);
    }*/

    if (interval_mark.in_sequence) {
        // If its in-sequence it can not be a duplicate or a retransmission
        entry.flow.record_droppable_packet();

        const bool dropped = entry.flow.drop_packet(start_seq, end_seq, packet.packet_id(), packet.flow, now);
        if (dropped) {
            entry.flow.register_gap(start_seq, end_seq, packet.packet_id());
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
    // TODO: Consider that for less than 4 packets may it does not make sense to do the comparison
    if (!raw_duplicate){
        if (TCPLOG_ENABLED(DEBUG)) {
            const auto flow_tag = flow_debug_details(packet.flow);
            TCPLOG_DEBUG("[ooo] flow=%s seq=%u-%u highest_seen=%u",
                         flow_tag.c_str(),
                         start_seq,
                         end_seq,
                         entry.flow.highest_sequence());
        }
        const bool ooo_exceeded = flow_out_of_order_threshold_exceeded(entry.flow);
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
    std::vector<std::string> filled_gaps;
    bool fills_only_gap_space = false;
     // First, we check whether the packet touches the byte ranges affected by our packet drops.
        if (!touches_gap){
            entry.flow.record_duplicate_packet();
            penny::ThreadFlowEventTimerManager::instance().enqueue_duplicate(&entry.flow, start_seq, packet.payload_bytes);
            // Logging handled in timer callback.

            const bool dup_exceeded = flow_duplicate_threshold_exceeded(entry.flow);
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

            const bool dup_exceeded = flow_duplicate_threshold_exceeded(entry.flow);
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

// Attempt to forward a packet to the configured TUN device; collects stats and logs errors.
void ActiveTestPipelineRunner::forward_packet(const net::PacketView& packet) {
    const bool raw = opts_.forward_raw_socket;
    int fd = raw ? opts_.forward_fd
                 : (opts_.forward_fd >= 0 ? opts_.forward_fd : opts_.tun_fd);
    if (fd < 0 || !packet.layer3_ptr || packet.layer3_length <= 0) {
        return;
    }

    ssize_t written = -1;
    if (raw) {
        if (packet.layer3_length < 20) {
            return;
        }
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        std::memcpy(&dst.sin_addr.s_addr, packet.layer3_ptr + 16, sizeof(dst.sin_addr.s_addr));
        written = ::sendto(fd,
                           packet.layer3_ptr,
                           static_cast<size_t>(packet.layer3_length),
                           0,
                           reinterpret_cast<sockaddr*>(&dst),
                           sizeof(dst));
    } else {
        written = ::write(fd,
                          packet.layer3_ptr,
                          static_cast<size_t>(packet.layer3_length));
    }
    if (written >= 0) {
        ++total_pkts_forwarded_;
    } else {
        int err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK) {
            TCPLOG_WARN("Failed to forward packet (%d bytes) via fd %d: %s",
                        static_cast<int>(packet.layer3_length),
                        fd,
                        std::strerror(err));
            ++total_forward_errors_;
        }
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

// Emit a concise single-line trace for the current packet.
void ActiveTestPipelineRunner::log_packet_line(const net::PacketView& packet) const {
    std::cout << "TCP src=" << to_ipv4_string(packet.flow.src) << ':' << packet.flow.sport
              << " dst=" << to_ipv4_string(packet.flow.dst) << ':' << packet.flow.dport
              << " seq=" << packet.tcp.seq
              << " ack=" << packet.tcp.ack
              << " flags=0x" << std::hex
              << static_cast<unsigned>(packet.tcp.flags)
              << std::dec << '\n';
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
