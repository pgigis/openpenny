// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

namespace {

openpenny::FlowKey make_flow_key(std::uint16_t sport) {
    openpenny::FlowKey key{};
    key.src = 0x0a000001;
    key.dst = 0x0a000002;
    key.sport = sport;
    key.dport = 5201;
    key.ip_proto = 6;
    return key;
}

} // namespace

int main() {
    using Clock = std::chrono::steady_clock;

    openpenny::penny::ThreadFlowEventTimerManager::instance().stop();
    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.drop_probability = 1.0;
    cfg.active.rtt_timeout_factor = 60.0;

    {
        openpenny::penny::FlowEngine flow(cfg.active);
        std::vector<openpenny::penny::SnapshotState> observed_states;
        flow.set_flow_key(make_flow_key(1111));
        flow.set_drop_sink([&observed_states](const openpenny::FlowKey&,
                                              openpenny::penny::PacketDropId,
                                              const openpenny::penny::PacketDropSnapshot& snapshot) {
            observed_states.push_back(snapshot.state);
        });
        const auto drop_time = Clock::now();
        const auto key = make_flow_key(1111);
        const auto packet_id = openpenny::penny::make_packet_drop_id(1000, 100);

        flow.record_data(1000, drop_time);
        assert(flow.drop_packet(1000, 1100, packet_id, key, drop_time));
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 1);

        // Generic teardown before the timeout should NOT mark the drop expired.
        flow.resolve_pending_snapshots(drop_time + std::chrono::seconds(1));

        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 0);
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 0);
        assert(flow.drop_snapshots().size() == 1);
        assert(flow.drop_snapshots().front().second.state ==
               openpenny::penny::SnapshotState::Invalid);
        assert(observed_states.size() == 2);
        assert(observed_states.front() == openpenny::penny::SnapshotState::Pending);
        assert(observed_states.back() == openpenny::penny::SnapshotState::Invalid);
    }

    {
        openpenny::penny::FlowEngine flow(cfg.active);
        flow.set_flow_key(make_flow_key(1112));
        const auto drop_time = Clock::now();
        const auto key = make_flow_key(1112);
        const auto packet_id = openpenny::penny::make_packet_drop_id(1500, 100);

        flow.record_data(1500, drop_time);
        assert(flow.drop_packet(1500, 1600, packet_id, key, drop_time));

        // FIN semantics are immediate: outstanding drops become non-retransmitted.
        flow.mark_snapshot_expired(packet_id);

        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 1);
        assert(flow.drop_snapshots().size() == 1);
        assert(flow.drop_snapshots().front().second.state ==
               openpenny::penny::SnapshotState::Expired);
    }

    {
        openpenny::penny::FlowEngine flow(cfg.active);
        std::vector<openpenny::penny::SnapshotState> observed_states;
        flow.set_flow_key(make_flow_key(1113));
        flow.set_drop_sink([&observed_states](const openpenny::FlowKey&,
                                              openpenny::penny::PacketDropId,
                                              const openpenny::penny::PacketDropSnapshot& snapshot) {
            observed_states.push_back(snapshot.state);
        });
        const auto drop_time = Clock::now();
        const auto key = make_flow_key(1113);
        const auto packet_id = openpenny::penny::make_packet_drop_id(2000, 100);

        flow.record_data(2000, drop_time);
        assert(flow.drop_packet(2000, 2100, packet_id, key, drop_time));
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 1);

        // Once the timeout has elapsed, teardown should promote to Expired.
        flow.resolve_pending_snapshots(drop_time + std::chrono::seconds(61));

        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 1);
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 0);
        assert(flow.drop_snapshots().size() == 1);
        assert(flow.drop_snapshots().front().second.state ==
               openpenny::penny::SnapshotState::Expired);
        assert(observed_states.size() == 2);
        assert(observed_states.front() == openpenny::penny::SnapshotState::Pending);
        assert(observed_states.back() == openpenny::penny::SnapshotState::Expired);
    }

    openpenny::penny::ThreadFlowEventTimerManager::instance().stop();
    return 0;
}
