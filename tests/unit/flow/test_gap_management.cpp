// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/manager/ThreadFlowManager.h"
#include "openpenny/net/Packet.h"

#include <cassert>
#include <chrono>
#include <string>

using namespace std::chrono;
using openpenny::penny::FlowTrackingState;
namespace net = openpenny::net;

static openpenny::penny::FlowEngineEntry& track(openpenny::penny::ThreadFlowManager& table,
                                               const openpenny::FlowKey& key,
                                               bool syn,
                                               uint32_t seq,
                                               steady_clock::time_point ts) {
    net::PacketView pkt{};
    pkt.flow = key;
    pkt.tcp.seq = seq;
    pkt.tcp.flags = syn ? 0x02 : 0x00;
    pkt.payload_bytes = syn ? 0 : 100;
    table.track_packet(pkt, ts);
    return *table.find(key);
}

int main() {
    openpenny::Config cfg;
    cfg.active.rtt_timeout_factor = 3.0;

    openpenny::penny::ThreadFlowManager table(cfg.active);
    openpenny::FlowKey flow{10, 20, 1111, 2222};
    auto now = steady_clock::time_point{};

    // Register a gap representing a dropped packet.
    auto& entry = track(table, flow, true, 1000, now);
    std::string gap_id = "pkt-1000-1100";
    entry.flow.register_gap(1000, 1100, gap_id);

    // First retransmission partially fills the gap.
    auto partial_time = now + milliseconds(100);
    auto& entry_after_partial = track(table, flow, false, 1000, partial_time);
    auto filled_partial = entry_after_partial.flow.fill_gaps(1000, 1050);
    assert(filled_partial.empty()); // partial repair should not be reported yet.

    // Another retransmission completes the gap.
    auto final_time = now + milliseconds(200);
    auto& entry_after_final = track(table, flow, false, 1050, final_time);
    auto filled_final = entry_after_final.flow.fill_gaps(1050, 1100);
    assert(filled_final.size() == 1 && filled_final.front() == gap_id);

    return 0;
}
