// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/manager/ThreadFlowManager.h"
#include "openpenny/net/Packet.h"

#include <cassert>
#include <chrono>

using namespace std::chrono;
using openpenny::penny::FlowTrackingState;
using openpenny::net::PacketView;
namespace net = openpenny::net;

    static void assert_state(FlowTrackingState actual, FlowTrackingState expected) {
        assert(actual == expected && "Unexpected flow monitor state");
    }

    int main() {
        openpenny::Config cfg;
        cfg.active.rtt_timeout_factor = 3.0;

        openpenny::penny::ThreadFlowManager table(cfg.active);
    auto now = steady_clock::time_point{};

    // Case 1: Flow starts with SYN.
    openpenny::FlowKey flow_syn{1, 2, 1000, 2000};
    net::PacketView syn_pkt{};
    syn_pkt.flow = flow_syn;
    syn_pkt.tcp.seq = 100;
    syn_pkt.tcp.flags = 0x02; // SYN
    syn_pkt.payload_bytes = 0;
    table.track_packet(syn_pkt, now);
    auto* syn_entry_ptr = table.find(flow_syn);
    auto& syn_entry = *syn_entry_ptr;
    assert_state(syn_entry.state, FlowTrackingState::ACTIVE_SEEN_SYN);
    assert(syn_entry.flow.highest_sequence() == 100);

    // Subsequent data packet after SYN should remain active and update highest seq.
    auto later = now + milliseconds(500);
    net::PacketView syn_data_pkt{};
    syn_data_pkt.flow = flow_syn;
    syn_data_pkt.tcp.seq = 150;
    syn_data_pkt.payload_bytes = 1;
    table.track_packet(syn_data_pkt, later);
    auto* syn_entry_data_ptr = table.find(flow_syn);
    auto& syn_entry_data = *syn_entry_data_ptr;

    // Case 2: Flow starts with data (no SYN yet).
    openpenny::FlowKey flow_data{3, 4, 3000, 4000};
    auto t0 = steady_clock::time_point{};
    net::PacketView data_pkt0{};
    data_pkt0.flow = flow_data;
    data_pkt0.tcp.seq = 50;
    data_pkt0.payload_bytes = 10;
    table.track_packet(data_pkt0, t0);
    auto& data_entry = *table.find(flow_data);
    assert_state(data_entry.state, FlowTrackingState::PENDING_SEEN_DATA);
    assert(data_entry.flow.highest_sequence() == 50);

    // Another data packet before timeout should remain in PENDING_SEEN_DATA.
    auto t1 = t0 + milliseconds(500);
    net::PacketView data_pkt1{};
    data_pkt1.flow = flow_data;
    data_pkt1.tcp.seq = 60;
    data_pkt1.payload_bytes = 10;
    table.track_packet(data_pkt1, t1);
    auto& data_entry2 = *table.find(flow_data);
    assert_state(data_entry2.state, FlowTrackingState::PENDING_SEEN_DATA);
    assert(data_entry2.flow.highest_sequence() == 60);

    // After rtt_timeout_factor elapses without SYN, flow should promote to ACTIVE_SEEN_DATA.
    auto t2 = t0 + milliseconds(3500);
    net::PacketView data_pkt2{};
    data_pkt2.flow = flow_data;
    data_pkt2.tcp.seq = 40;
    data_pkt2.payload_bytes = 10;
    table.track_packet(data_pkt2, t2);
    auto& data_entry3 = *table.find(flow_data);
    assert_state(data_entry3.state, FlowTrackingState::ACTIVE_SEEN_DATA);
    assert(data_entry3.flow.highest_sequence() == 60);

    // Case 3: Flow receives SYN after data-first start.
    openpenny::FlowKey flow_data_then_syn{5, 6, 1234, 4321};
    auto td0 = steady_clock::time_point{};
    net::PacketView first_data_pkt{};
    first_data_pkt.flow = flow_data_then_syn;
    first_data_pkt.tcp.seq = 5;
    first_data_pkt.payload_bytes = 5;
    table.track_packet(first_data_pkt, td0);
    auto& first_data = *table.find(flow_data_then_syn);
    assert_state(first_data.state, FlowTrackingState::PENDING_SEEN_DATA);

    auto td1 = td0 + milliseconds(200);
    net::PacketView second_data_pkt{};
    second_data_pkt.flow = flow_data_then_syn;
    second_data_pkt.tcp.seq = 6;
    second_data_pkt.payload_bytes = 5;
    table.track_packet(second_data_pkt, td1);
    auto& second_data = *table.find(flow_data_then_syn);
    assert_state(second_data.state, FlowTrackingState::PENDING_SEEN_DATA);

    auto td2 = td0 + milliseconds(500);
    net::PacketView syn_after_pkt{};
    syn_after_pkt.flow = flow_data_then_syn;
    syn_after_pkt.tcp.seq = 1000;
    syn_after_pkt.tcp.flags = 0x02;
    syn_after_pkt.payload_bytes = 0;
    table.track_packet(syn_after_pkt, td2);
    auto& syn_after_data = *table.find(flow_data_then_syn);
    assert_state(syn_after_data.state, FlowTrackingState::ACTIVE_SEEN_SYN);
    assert(syn_after_data.flow.highest_sequence() == 1000);

    // Case 4: Duplicate detection (no state change but sequence update).
    auto td3 = td2 + milliseconds(50);
    net::PacketView data_after_syn_pkt{};
    data_after_syn_pkt.flow = flow_data_then_syn;
    data_after_syn_pkt.tcp.seq = 1500;
    data_after_syn_pkt.payload_bytes = 10;
    table.track_packet(data_after_syn_pkt, td3);
    auto& data_after_syn = *table.find(flow_data_then_syn);
    assert_state(data_after_syn.state, FlowTrackingState::ACTIVE_SEEN_DATA);
    assert(data_after_syn.flow.highest_sequence() == 1500);

    return 0;
}
