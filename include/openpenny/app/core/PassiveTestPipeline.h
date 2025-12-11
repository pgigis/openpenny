// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"
#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/ActiveTestPipeline.h"
#include "openpenny/agg/Stats.h"

#include <functional>
#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace openpenny {

struct PassiveFlowState {
    FlowKey key{};
    uint32_t highest_seq{0};
    bool seen_seq{false};
    bool seen_syn{false};
    bool seen_rst{false};
    bool started_with_syn{false};
    std::string end_reason;
    std::size_t data_packets{0};
    std::size_t pure_ack_packets{0};
    std::size_t duplicate_packets{0};
    std::size_t in_order_packets{0};
    std::size_t out_of_order_packets{0};
    std::chrono::steady_clock::time_point last_seen{};
    struct Gap {
        uint32_t start{0};
        uint32_t end{0};
        bool filled{false};
    };
    std::vector<Gap> gaps;
};

class PassiveTestPipelineRunner {
public:
    PassiveTestPipelineRunner(const Config& cfg,
                                   const PipelineOptions& opts,
                                   FlowMatcher matcher,
                                   net::PacketSourcePtr source);

    std::optional<ModeResult> run();

private:
    const Config& cfg_;
    const PipelineOptions& opts_;
    FlowMatcher matcher_;
    net::PacketSourcePtr source_;
    std::unordered_map<FlowKey, PassiveFlowState, FlowKeyHash> flows_;
    std::chrono::steady_clock::time_point start_time_{std::chrono::steady_clock::now()};
    std::size_t flows_seen_{0};
    std::size_t flows_finished_{0};
    std::vector<PassiveFlowState> finished_flows_;
    std::unordered_map<FlowKey, std::size_t, FlowKeyHash> finished_index_;
    std::unordered_set<FlowKey, FlowKeyHash> finished_keys_;
    bool stop_grace_active_{false};
    std::chrono::steady_clock::time_point stop_grace_start_{};

    PassiveFlowState* admit_flow(const net::PacketView& packet,
                                 const std::chrono::steady_clock::time_point& now);
    void handle_data_packet(PassiveFlowState& state, const net::PacketView& packet);
    void finish_flow(const FlowKey& key, const char* reason = nullptr);
    void expire_idle_flows(const std::chrono::steady_clock::time_point& now,
                           const std::chrono::steady_clock::duration& timeout);
    void summarize_gaps(ModeResult& result);
};

} // namespace openpenny
