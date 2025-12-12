// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/PassiveTestPipeline.h"

#include "openpenny/log/Log.h"
#include "openpenny/app/core/utils/FlowDebug.h"
#include "openpenny/app/core/PerThreadStats.h"

#include <atomic>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>

namespace openpenny {

namespace {
uint32_t packet_end_seq(const net::PacketView& pkt) {
    return pkt.tcp.seq + static_cast<uint32_t>(pkt.payload_bytes);
}

// Global concurrent passive flow cap across threads.
std::atomic<std::size_t> g_passive_active_flows{0};
}

PassiveTestPipelineRunner::PassiveTestPipelineRunner(const Config& cfg,
                                                               const PipelineOptions& opts,
                                                               FlowMatcher matcher,
                                                               net::PacketSourcePtr source)
    : cfg_(cfg),
      opts_(opts),
      matcher_(std::move(matcher)),
      source_(std::move(source)) {}

std::optional<ModeResult> PassiveTestPipelineRunner::run() {
    if (!source_) {
        TCPLOG_ERROR("Packet source unavailable");
        return std::nullopt;
    }
    if (!source_->open(cfg_.ifname, cfg_.queue)) {
        TCPLOG_ERROR("Failed to open packet source on %s q%u", cfg_.ifname.c_str(), cfg_.queue);
        return std::nullopt;
    }

    ModeResult result{};
    const auto idle_timeout = std::chrono::duration<double>(
        cfg_.passive.flow_idle_timeout_seconds);
    const auto max_exec = std::chrono::duration<double>(
        cfg_.passive.max_execution_time_seconds);
    const auto grace = std::chrono::duration<double>(cfg_.passive.flow_grace_period_seconds);
    net::PacketHandler handler = [this, &result, idle_timeout, grace](const net::PacketView& packet) {
        if (opts_.should_stop && opts_.should_stop()) return;
        if (matcher_ && !matcher_(packet.flow)) return;

        ++result.packets_processed;
        auto& counters = openpenny::app::current_thread_counters();
        counters.packets++;
        counters.bytes += static_cast<uint64_t>(packet.payload_bytes);

        const auto now = std::chrono::steady_clock::now();
        // If the flow already finished and we now observe FIN/RST, update the end reason.
        if (auto it = finished_index_.find(packet.flow); it != finished_index_.end()) {
            const auto flags = packet.tcp.flags_view();
            if (flags.fin || flags.rst) {
                auto idx = it->second;
                if (idx < finished_flows_.size()) {
                    finished_flows_[idx].end_reason = flags.rst ? "rst" : "fin";
                }
            }
        }

        // Admit or lookup flow and update passive stats.
        auto* flow_state = [&]() -> PassiveFlowState* {
            if (grace.count() > 0.0 &&
                now - start_time_ < std::chrono::duration_cast<std::chrono::steady_clock::duration>(grace)) {
                return nullptr;
            }
            return admit_flow(packet, now);
        }();
        if (flow_state) {
            flow_state->last_seen = now;
            if (packet.payload_bytes > 0) {
                handle_data_packet(*flow_state, packet);
            } else {
                flow_state->pure_ack_packets++;
                counters.pure_ack_packets++;
            }
            const auto flags = packet.tcp.flags_view();
            if (flags.rst) {
                flow_state->seen_rst = true;
                if (TCPLOG_ENABLED(INFO)) {
                    TCPLOG_INFO("[passive_flag] flow=%s RST observed",
                                flow_debug_details(packet.flow).c_str());
                }
                finish_flow(packet.flow, "rst");
            } else if (flags.fin) {
                if (TCPLOG_ENABLED(INFO)) {
                    TCPLOG_INFO("[passive_flag] flow=%s FIN observed",
                                flow_debug_details(packet.flow).c_str());
                }
                finish_flow(packet.flow, "fin");
            } else if (flags.syn) {
                flow_state->seen_syn = true;
            }

            if (TCPLOG_ENABLED(DEBUG)) {
                if (flags.fin || flags.syn || flags.rst || flags.ack || flags.psh || flags.urg) {
                    TCPLOG_DEBUG(
                        "[passive_flags] flow=%s flags=%s%s%s%s%s%s seq=%u ack=%u payload=%zu",
                        flow_debug_details(packet.flow).c_str(),
                        flags.syn ? "S" : "",
                        flags.fin ? "F" : "",
                        flags.rst ? "R" : "",
                        flags.ack ? "A" : "",
                        flags.psh ? "P" : "",
                        flags.urg ? "U" : "",
                        packet.tcp.seq,
                        packet.tcp.ack,
                        packet.payload_bytes);
                }
            }
        }
        if (TCPLOG_ENABLED(DEBUG) && flow_state) {
            const auto flow_tag = flow_debug_details(flow_state->key);
            TCPLOG_DEBUG("[passive_packet] flow=%s seq=%u-%u payload=%zu",
                         flow_tag.c_str(),
                         packet.tcp.seq,
                         packet_end_seq(packet),
                         packet.payload_bytes);
        }

        const bool raw = opts_.forward_raw_socket;
        int fd = raw ? opts_.forward_fd : (opts_.forward_fd >= 0 ? opts_.forward_fd : opts_.tun_fd);
        if (fd >= 0 && packet.layer3_ptr && packet.layer3_length > 0) {
            ssize_t written = -1;
            if (raw) {
                if (packet.layer3_length >= 20) {
                    sockaddr_in dst{};
                    dst.sin_family = AF_INET;
                    std::memcpy(&dst.sin_addr.s_addr, packet.layer3_ptr + 16, sizeof(dst.sin_addr.s_addr));
                    written = ::sendto(fd,
                                       packet.layer3_ptr,
                                       static_cast<size_t>(packet.layer3_length),
                                       0,
                                       reinterpret_cast<sockaddr*>(&dst),
                                       sizeof(dst));
                }
            } else {
                written = ::write(fd,
                                  packet.layer3_ptr,
                                  static_cast<size_t>(packet.layer3_length));
            }
            if (written >= 0) {
                ++result.packets_forwarded;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ++result.forward_errors;
            }
        }
    };

    bool poll_failed = false;
    while (true) {
        if (opts_.should_stop && opts_.should_stop()) break;
        if (!source_->poll(handler)) {
            TCPLOG_ERROR("Packet poll failed");
            poll_failed = true;
            break;
        }
        if (idle_timeout.count() > 0.0) {
            expire_idle_flows(std::chrono::steady_clock::now(),
                              std::chrono::duration_cast<std::chrono::steady_clock::duration>(idle_timeout));
        }
        const bool target_met = cfg_.passive.min_number_of_flows_to_finish > 0 &&
            flows_finished_ >= cfg_.passive.min_number_of_flows_to_finish &&
            flows_.empty();
        if (target_met) {
            if (!stop_grace_active_) {
                stop_grace_active_ = true;
                stop_grace_start_ = std::chrono::steady_clock::now();
            } else {
                // Allow a short grace to catch trailing FIN/RST packets for already-finished flows.
                constexpr auto kStopGrace = std::chrono::seconds(1);
                if (std::chrono::steady_clock::now() - stop_grace_start_ >= kStopGrace) {
                    break;
                }
            }
        }
        if (max_exec.count() > 0.0 &&
            std::chrono::steady_clock::now() - start_time_ >=
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(max_exec)) {
            break;
        }
    }

    source_->close();
    // Treat any remaining flows as finished when shutting down.
    result.penny_completed = !poll_failed;
    result.aggregates_penny_completed = result.penny_completed;
    summarize_gaps(result);
    return result;
}

PassiveFlowState* PassiveTestPipelineRunner::admit_flow(const net::PacketView& packet,
                                                        const std::chrono::steady_clock::time_point& now) {
    if (cfg_.passive.max_parallel_flows > 0 &&
        g_passive_active_flows.load(std::memory_order_relaxed) >= cfg_.passive.max_parallel_flows) {
        return nullptr;
    }
    // Do not re-monitor flows that already finished.
    if (finished_keys_.find(packet.flow) != finished_keys_.end()) {
        return nullptr;
    }

    auto [it, inserted] = flows_.try_emplace(packet.flow);
    auto& state = it->second;
    if (inserted) {
        state.key = packet.flow;
        state.last_seen = now;
        state.started_with_syn = packet.tcp.flags_view().syn;
        ++flows_seen_;
        g_passive_active_flows.fetch_add(1, std::memory_order_relaxed);
        if (TCPLOG_ENABLED(INFO)) {
            TCPLOG_INFO("[passive_flow_add] flow=%s",
                        flow_debug_details(packet.flow).c_str());
        }
    }
    return &state;
}

void PassiveTestPipelineRunner::finish_flow(const FlowKey& key, const char* reason) {
    auto it = flows_.find(key);
    if (it == flows_.end()) return;
    if (reason) it->second.end_reason = reason;
    finished_index_[key] = finished_flows_.size();
    finished_flows_.push_back(it->second);
    finished_keys_.insert(key);
    ++flows_finished_;
    if (g_passive_active_flows.load(std::memory_order_relaxed) > 0) {
        g_passive_active_flows.fetch_sub(1, std::memory_order_relaxed);
    }
    if (TCPLOG_ENABLED(INFO)) {
        TCPLOG_INFO("[passive_flow_end] flow=%s reason=%s data=%zu pure_ack=%zu dup=%zu in_order=%zu ooo=%zu gaps=%zu",
                    flow_debug_details(key).c_str(),
                    reason ? reason : "unknown",
                    it->second.data_packets,
                    it->second.pure_ack_packets,
                    it->second.duplicate_packets,
                    it->second.in_order_packets,
                    it->second.out_of_order_packets,
                    it->second.gaps.size());
    }
    flows_.erase(it);
}

void PassiveTestPipelineRunner::handle_data_packet(PassiveFlowState& state, const net::PacketView& packet) {
    const uint32_t start_seq = packet.tcp.seq;
    const uint32_t end_seq = packet_end_seq(packet);
    state.data_packets++;
    auto& counters = openpenny::app::current_thread_counters();
    counters.data_packets++;

    if (!state.seen_seq) {
        state.seen_seq = true;
        state.highest_seq = end_seq;
        state.in_order_packets++;
        counters.in_order_packets++;
        return;
    }

    const bool overlaps_seen = start_seq < state.highest_seq;
    if (overlaps_seen) {
        state.duplicate_packets++;
        state.out_of_order_packets++;
        counters.duplicate_packets++;
        counters.out_of_order_packets++;
        // Consider a flow finished if it exceeds grace and duplicates grow? (no-op for now)
    } else {
        // Gap detection: if new start is beyond highest_seq, record missing bytes.
        if (start_seq > state.highest_seq) {
            state.gaps.push_back(PassiveFlowState::Gap{state.highest_seq, start_seq, false});
        }
        state.in_order_packets++;
        counters.in_order_packets++;
    }

    // Extend coverage window.
    state.highest_seq = std::max(state.highest_seq, end_seq);

    // Attempt to mark any gaps as filled.
    state.gaps.erase(
        std::remove_if(state.gaps.begin(), state.gaps.end(),
                       [&](const PassiveFlowState::Gap& gap) {
                           if (gap.filled) return true;
                           if (end_seq >= gap.end && start_seq <= gap.start) {
                               return true; // Drop filled gaps from memory.
                           }
                           return false;
                       }),
        state.gaps.end());
}

void PassiveTestPipelineRunner::expire_idle_flows(const std::chrono::steady_clock::time_point& now,
                                                  const std::chrono::steady_clock::duration& timeout) {
    if (timeout <= std::chrono::steady_clock::duration::zero()) return;
    for (auto it = flows_.begin(); it != flows_.end(); ) {
        if (now - it->second.last_seen > timeout) {
            const auto key = it->first;
            ++it; // advance before erasing via finish_flow
            finish_flow(key, "idle");
        } else {
            ++it;
        }
    }
}

void PassiveTestPipelineRunner::summarize_gaps(ModeResult& result) {
    // Reset per-flow aggregates to avoid double counting with packet-loop counters.
    result.data_packets = 0;
    result.pure_ack_packets = 0;
    result.duplicate_packets = 0;
    result.in_order_packets = 0;
    result.out_of_order_packets = 0;
    std::size_t total_gaps = 0;
    std::size_t open_gaps = 0;
    std::size_t flows_with_open = 0;

    auto accumulate = [&](const PassiveFlowState& state) {
        result.data_packets += state.data_packets;
        result.pure_ack_packets += state.pure_ack_packets;
        result.duplicate_packets += state.duplicate_packets;
        result.in_order_packets += state.in_order_packets;
        result.out_of_order_packets += state.out_of_order_packets;
        const auto flow_tag = flow_debug_details(state.key);

        std::size_t flow_open_gaps = 0;
        std::size_t flow_total_gaps = 0;
        for (const auto& g : state.gaps) {
            ++flow_total_gaps;
            if (!g.filled) ++flow_open_gaps;
        }
        total_gaps += flow_total_gaps;
        open_gaps += flow_open_gaps;
        if (flow_open_gaps > 0) flows_with_open++;

        std::ostringstream oss;
        oss << flow_tag
            << " start=" << (state.started_with_syn ? "syn" : "data")
            << " end=" << (state.end_reason.empty() ? "active" : state.end_reason)
            << " data=" << state.data_packets
            << " pure_ack=" << state.pure_ack_packets
            << " dup=" << state.duplicate_packets
            << " in_order=" << state.in_order_packets
            << " out_of_order=" << state.out_of_order_packets
            << " rst=" << (state.seen_rst ? 1 : 0)
            << " syn=" << (state.seen_syn ? 1 : 0)
            << " gaps_open=" << flow_open_gaps << " gaps=";
        bool first = true;
        for (const auto& g : state.gaps) {
            if (g.filled) continue; // Only print unfilled gaps.
            if (!first) oss << ", ";
            oss << g.start << "-" << g.end;
            first = false;
        }

        if (state.seen_rst) {
            result.passive_flows_rst++;
        }
        if (state.seen_syn && state.data_packets == 0) {
            result.passive_flows_syn_only++;
        }

        result.passive_gap_summaries.push_back(oss.str());
    };

    for (const auto& st : finished_flows_) {
        accumulate(st);
    }
    for (const auto& kv : flows_) {
        accumulate(kv.second);
    }

    result.passive_flows_with_open_gaps = flows_with_open;
    result.passive_open_gaps = open_gaps;
    result.passive_flows_finished = flows_finished_;

    if (TCPLOG_ENABLED(INFO)) {
        TCPLOG_INFO(
            "[passive_summary] flows=%zu data=%zu dup=%zu ooo=%zu gaps_total=%zu gaps_open=%zu flows_with_open=%zu",
            flows_.size(),
            result.data_packets,
            result.duplicate_packets,
            result.out_of_order_packets,
            total_gaps,
            open_gaps,
            flows_with_open);
    }
}

} // namespace openpenny
