// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/agg/Stats.h"
#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/PipelineRunner.h"
#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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

/**
 * Passive pipeline strategy.
 *
 * Implemented as an IPipelineStrategy: the shared PipelineRunner drives
 * the source and the poll loop; this class supplies passive-mode
 * packet handling (flow admission, gap tracking, grace periods) and
 * final gap summarization.
 */
class PassiveTestPipelineRunner : public IPipelineStrategy {
public:
    PassiveTestPipelineRunner(const Config& cfg,
                              const PipelineOptions& opts,
                              FlowMatcher matcher,
                              net::PacketSourcePtr source);

    /// Public entry point. Delegates to a PipelineRunner wrapping *this.
    std::optional<ModeResult> run();

    // ---------------------------------------------------------------------
    // IPipelineStrategy hooks
    // ---------------------------------------------------------------------

    void on_opened() override;
    void on_packet(const net::PacketView& packet,
                   const std::chrono::steady_clock::time_point& now,
                   ModeResult& result) override;
    void after_poll(const std::chrono::steady_clock::time_point& now,
                    std::size_t processed_delta,
                    ModeResult& result) override;
    bool should_terminate() const override { return stop_requested_; }
    bool penny_completed() const override { return true; }
    void finalize(ModeResult& result) override;

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
    bool stop_requested_{false};

    // Cached timing derived from cfg_ at on_opened() so we don't convert
    // from double-seconds on every poll iteration.
    std::chrono::steady_clock::duration idle_timeout_{};
    std::chrono::steady_clock::duration max_execution_time_{};
    std::chrono::steady_clock::duration grace_period_{};

    PassiveFlowState* admit_flow(const net::PacketView& packet,
                                 const std::chrono::steady_clock::time_point& now);
    void handle_data_packet(PassiveFlowState& state, const net::PacketView& packet);
    void finish_flow(const FlowKey& key, const char* reason = nullptr);
    void expire_idle_flows(const std::chrono::steady_clock::time_point& now);
    void summarize_gaps(ModeResult& result);
};

} // namespace openpenny
