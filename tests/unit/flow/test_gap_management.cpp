// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: FlowEngine::fill_gaps() reports a gap as filled only when
// the retransmissions cover the entire registered range.
//
// Scenario: register one gap for [1000, 1100). The first retransmit
// covers [1000, 1050) (half). fill_gaps() must return an empty list
// then. The second retransmit covers [1050, 1100). Now fill_gaps()
// must return the original gap's packet_id.
//
// If this fails: partial retransmissions either get silently absorbed
// (false positive — flow looks closed-loop too early) or never close
// out (false negative — flow stays pending forever).

#include "test_helpers.h"

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/manager/ThreadFlowManager.h"
#include "openpenny/net/Packet.h"

#include <cassert>
#include <chrono>

using namespace std::chrono;
using openpenny::test::Section;
using openpenny::test::kTcpSyn;
using openpenny::test::make_packet;

namespace {

// Push one packet through the manager and return the resulting entry.
openpenny::penny::FlowEngineEntry& track(openpenny::penny::ThreadFlowManager& table,
                                         const openpenny::FlowKey& key,
                                         bool                       syn,
                                         std::uint32_t              seq,
                                         steady_clock::time_point   ts) {
    const auto pkt = make_packet(key,
                                 seq,
                                 /*payload=*/syn ? 0 : 100,
                                 /*flags=*/  syn ? kTcpSyn : 0);
    table.track_packet(pkt, ts);
    return *table.find(key);
}

} // namespace

int main() {
    openpenny::Config cfg;
    cfg.active.rtt_timeout_factor = 3.0;

    openpenny::penny::ThreadFlowManager table(cfg.active);
    const openpenny::FlowKey flow{10, 20, 1111, 2222, /*ip_proto=*/6};
    const auto now    = steady_clock::time_point{};
    const auto gap_id = openpenny::penny::make_packet_drop_id(1000, 100);

    {
        Section _{"register a gap for [1000, 1100)"};
        auto& entry = track(table, flow, /*syn=*/true, 1000, now);
        entry.flow.register_gap(1000, 1100, gap_id);
    }

    {
        Section _{"partial retransmit [1000, 1050) does not close the gap"};
        auto& entry = track(table, flow, /*syn=*/false, 1000, now + milliseconds(100));
        const auto filled = entry.flow.fill_gaps(1000, 1050);
        assert(filled.empty());
    }

    {
        Section _{"second retransmit completes the range and reports gap closed"};
        auto& entry = track(table, flow, /*syn=*/false, 1050, now + milliseconds(200));
        const auto filled = entry.flow.fill_gaps(1050, 1100);
        assert(filled.size() == 1);
        assert(filled.front() == gap_id);
    }

    return 0;
}
