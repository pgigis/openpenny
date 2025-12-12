// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/penny/flow/manager/ThreadFlowManager.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/utils/FlowDebug.h"
#include "openpenny/log/Log.h"

namespace openpenny::penny {

ThreadFlowManager::ThreadFlowManager() = default;

ThreadFlowManager::ThreadFlowManager(const Config::ActiveConfig& cfg) : table_cfg_(cfg) {}

void ThreadFlowManager::configure(const Config::ActiveConfig& cfg) {
    table_cfg_ = cfg;
    for (auto& [_, entry] : table_active_flows_) {
        entry.flow.configure(table_cfg_);
        entry.flow.set_drop_sink(drop_sink_);
    }
}

void ThreadFlowManager::set_drop_sink(FlowEngine::DropSnapshotSink sink) {
    drop_sink_ = std::move(sink);
    for (auto& [_, entry] : table_active_flows_) {
        entry.flow.set_drop_sink(drop_sink_);
    }
}

bool ThreadFlowManager::add_new_flow(const FlowKey& key,
                                  uint32_t seq,
                                  uint32_t payload_bytes,
                                  bool is_syn,
                                  const std::chrono::steady_clock::time_point& ts) {
    
    // Ignore ACK packets with no payload when deciding whether to start monitoring a new flow.
    if (payload_bytes == 0 && !is_syn) {
        return false;
    }

    // try_emplace: insert a new entry if the key is absent, otherwise return the existing one without extra copies.
    auto [it, inserted] = table_active_flows_.try_emplace(key);
    auto& entry = it->second;
    if (!inserted) {
        return false;
    }
    auto& counters = openpenny::app::current_thread_counters();
    counters.flows_monitored++;
    counters.active_flows++;
    entry.flow.configure(table_cfg_); // apply current config for counters/thresholds
    entry.flow.set_drop_sink(drop_sink_);
    entry.flow.set_flow_key(key); // stash identifiers once
    entry.last_seen = ts;
    entry.first_seen = ts;
    entry.state = is_syn ? FlowTrackingState::ACTIVE_SEEN_SYN : FlowTrackingState::PENDING_SEEN_DATA;
    if (is_syn) {
        entry.flow.record_syn(seq); // seed sequence space with SYN seq
    }
    if (payload_bytes > 0) {
        const uint32_t end_seq = seq + payload_bytes;
        entry.flow.record_data(seq, ts); // track data timestamp + initial sequence observation
        (void)end_seq; // end_seq retained for potential future use
    }
    entry.flow.record_packet(); // count the first packet
    return true;
}

void ThreadFlowManager::track_packet(const ::openpenny::net::PacketView& packet,
                                  const std::chrono::steady_clock::time_point& ts) {
    const auto max_flows = table_cfg_.max_tracked_flows;
    const bool is_syn = packet.tcp.flags_view().syn;
    const auto now = ts;

    auto it = table_active_flows_.find(packet.flow);
    if (it == table_active_flows_.end()) {
        if (max_flows != 0 && active_flow_count(max_flows) >= max_flows) {
            return;
        }
        add_new_flow(packet.flow,
                     packet.tcp.seq,
                     static_cast<uint32_t>(packet.payload_bytes),
                     is_syn,
                     now);
        it = table_active_flows_.find(packet.flow);
    }
    if (it == table_active_flows_.end()) return;

    auto& entry = it->second;
    auto& flow = entry.flow;
    entry.last_seen = now;
    // Flow starts in PENDING_SEEN_DATA when we first see payload without SYN.
    // Promote to ACTIVE_SEEN_DATA after grace/timer, or immediately if SYN arrives.

    if (is_syn) {
        entry.state = FlowTrackingState::ACTIVE_SEEN_SYN;
        flow.record_syn(packet.tcp.seq);
        flow.record_packet();
        return;
    }

    if (packet.payload_bytes > 0) {
        flow.record_data_packet();
        flow.record_data(packet.tcp.seq, now);
        flow.record_packet();

        if (entry.state == FlowTrackingState::PENDING_SEEN_DATA) {
            const auto elapsed = std::chrono::duration<double>(now - entry.first_seen).count();
            if (elapsed >= table_cfg_.rtt_timeout_factor) {
                entry.state = FlowTrackingState::ACTIVE_SEEN_DATA;
            }
        } else if (entry.state == FlowTrackingState::ACTIVE_SEEN_SYN) {
            entry.state = FlowTrackingState::ACTIVE_SEEN_DATA;
        }
    } else {
        flow.record_packet();
    }
}

bool ThreadFlowManager::complete_flow(const FlowKey& key, const char* reason) {
    auto it = table_active_flows_.find(key);
    if (it == table_active_flows_.end()) {
        return false;
    }

    auto& entry = it->second;
    auto& flow  = entry.flow;

    // Map FlowTrackingState -> string
    const auto* tcp_state_text = [] (FlowTrackingState state) -> const char* {
        switch (state) {
            case FlowTrackingState::INTERRUPTED_RST:
                return "INTERRUPTED_RST";
            case FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED:
                return "INTERRUPTED_DUPLICATE_EXCEEDED";
            case FlowTrackingState::INTERRUPTED_OUT_OF_ORDER_EXCEEDED:
                return "INTERRUPTED_OUT_OF_ORDER_EXCEEDED";
            case FlowTrackingState::CONNECTION_CLOSED_FIN:
                return "CONNECTION_CLOSED_FIN";
            case FlowTrackingState::PENDING:
                return "PENDING";
            case FlowTrackingState::ACTIVE_SEEN_SYN:
                return "ACTIVE_SEEN_SYN";
            case FlowTrackingState::PENDING_SEEN_DATA:
                return "PENDING_SEEN_DATA";
            case FlowTrackingState::ACTIVE_SEEN_DATA:
                return "ACTIVE_SEEN_DATA";
            case FlowTrackingState::FINISHED:
                return "FINISHED";
            case FlowTrackingState::NOT_ACTIONABLE:
                return "NOT_ACTIONABLE";
            default:
                return "ACTIVE";
        }
    }(entry.state);

    // Map FlowEngine::FlowDecision -> string (test decision)
    const auto* test_status_text = [] (FlowEngine::FlowDecision status) -> const char* {
        switch (status) {
            case FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP:
                return "FINISHED_CLOSED_LOOP";
            case FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP:
                return "FINISHED_NOT_CLOSED_LOOP";
            case FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED:
                return "FINISHED_DUPLICATE_EXCEEDED";
            case FlowEngine::FlowDecision::FINISHED_NO_DECISION:
                return "FINISHED_NO_DECISION";
            case FlowEngine::FlowDecision::PENDING:
            default:
                return "PENDING";
        }
    }(flow.final_decision());

    if (TCPLOG_ENABLED(INFO)) {
        const auto flow_tag = flow_debug_details(key);

        TCPLOG_INFO(
            "[flow_complete] reason=%s tcp_state=%s test_status=%s flow=%s "
            "data_pkts=%llu dup_pkts=%llu in_order_pkts=%llu out_of_order_pkts=%llu "
            "rtx_pkts=%llu non_rtx_pkts=%llu pending_rtx_pkts=%llu",
            reason ? reason : "completed",
            tcp_state_text,
            test_status_text,
            flow_tag.c_str(),
            static_cast<unsigned long long>(flow.data_packets()),
            static_cast<unsigned long long>(flow.duplicate_packets()),
            static_cast<unsigned long long>(flow.in_order_packets()),
            static_cast<unsigned long long>(flow.out_of_order_packets()),
            static_cast<unsigned long long>(flow.retransmitted_packets()),
            static_cast<unsigned long long>(flow.non_retransmitted_packets()),
            static_cast<unsigned long long>(flow.pending_retransmissions()));
    }

    // Expire any remaining pending snapshots before tearing down the flow.
    entry.flow.expire_all_pending_snapshots();

    table_completed_flows_.insert(it->first);
    table_active_flows_.erase(it);
    // Adjust the current thread's active flow count after marking this flow complete.
    auto& counters = openpenny::app::current_thread_counters();
    if (counters.active_flows > 0) {
        counters.active_flows--;
    }
    counters.flows_finished++;
    if (entry.state == FlowTrackingState::INTERRUPTED_RST) {
        counters.flows_rst++;
    }
    if (entry.state == FlowTrackingState::INTERRUPTED_DUPLICATE_EXCEEDED) {
        counters.flows_duplicates_exceeded++;
    }
    switch (flow.final_decision()) {
        case FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP:
            counters.flows_closed_loop++;
            break;
        case FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP:
            counters.flows_not_closed_loop++;
            break;
        case FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED:
            counters.flows_duplicates_exceeded++;
            break;
        default:
            break;
    }
    return true;
}

void ThreadFlowManager::touch_flow(const FlowKey& key,
                                   const std::chrono::steady_clock::time_point& ts) {
    auto it = table_active_flows_.find(key);
    if (it == table_active_flows_.end()) return;
    it->second.last_seen = ts;
}

std::vector<FlowKey> ThreadFlowManager::collect_idle_flows(
    const std::chrono::steady_clock::time_point& now,
    const std::chrono::steady_clock::duration& timeout) const {
    std::vector<FlowKey> expired;
    if (timeout <= std::chrono::steady_clock::duration::zero()) return expired;
    for (const auto& kv : table_active_flows_) {
        const auto delta = now - kv.second.last_seen;
        if (delta > timeout) {
            expired.push_back(kv.first);
        }
    }
    return expired;
}

} // namespace openpenny::penny
