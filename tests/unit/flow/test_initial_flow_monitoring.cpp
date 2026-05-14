// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: ThreadFlowManager admits new flows into the correct
// FlowTrackingState depending on the packets seen so far.
//
//   - SYN first             -> ACTIVE_SEEN_SYN
//   - Data first, < grace   -> PENDING_SEEN_DATA
//   - Data first, > grace   -> ACTIVE_SEEN_DATA (promotion on timeout)
//   - Data first then SYN   -> ACTIVE_SEEN_SYN (promotion on SYN arrival)
//
// Each transition also updates the engine's highest_sequence().
//
// If this fails: data-first flows never promote (or promote too soon),
// breaking the closed-loop / open-loop classification for sessions
// whose SYN was missed.

#include "test_helpers.h"

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"
#include "openpenny/penny/flow/manager/ThreadFlowManager.h"

#include <cassert>
#include <chrono>

using namespace std::chrono;
using openpenny::penny::FlowTrackingState;
using openpenny::test::Section;
using openpenny::test::kTcpSyn;
using openpenny::test::make_packet;

namespace {

void assert_state(FlowTrackingState actual, FlowTrackingState expected) {
    assert(actual == expected && "Unexpected flow monitor state");
}

} // namespace

int main() {
    openpenny::Config cfg;
    cfg.active.rtt_timeout_factor = 3.0; // 3s grace before data-first promotion

    openpenny::penny::ThreadFlowManager table(cfg.active);

    {
        Section _{"SYN-first flow -> ACTIVE_SEEN_SYN"};
        const openpenny::FlowKey flow{1, 2, 1000, 2000, /*ip_proto=*/6};
        const auto now = steady_clock::time_point{};

        table.track_packet(make_packet(flow, /*seq=*/100, /*payload=*/0, kTcpSyn), now);
        auto& entry = *table.find(flow);
        assert_state(entry.state, FlowTrackingState::ACTIVE_SEEN_SYN);
        assert(entry.flow.highest_sequence() == 100);

        // A later data packet keeps the state and advances the seq.
        table.track_packet(make_packet(flow, /*seq=*/150), now + milliseconds(500));
        auto& entry2 = *table.find(flow);
        assert(entry2.flow.highest_sequence() == 150);
    }

    {
        Section _{"data-first flow within grace -> PENDING_SEEN_DATA"};
        const openpenny::FlowKey flow{3, 4, 3000, 4000, /*ip_proto=*/6};
        const auto t0 = steady_clock::time_point{};

        table.track_packet(make_packet(flow, 50,  /*payload=*/10), t0);
        auto& entry = *table.find(flow);
        assert_state(entry.state, FlowTrackingState::PENDING_SEEN_DATA);
        assert(entry.flow.highest_sequence() == 50);

        table.track_packet(make_packet(flow, 60,  /*payload=*/10), t0 + milliseconds(500));
        auto& entry2 = *table.find(flow);
        assert_state(entry2.state, FlowTrackingState::PENDING_SEEN_DATA);
        assert(entry2.flow.highest_sequence() == 60);
    }

    {
        Section _{"data-first flow promotes to ACTIVE_SEEN_DATA after grace period"};
        const openpenny::FlowKey flow{3, 4, 3000, 4000, /*ip_proto=*/6};
        const auto t0 = steady_clock::time_point{};

        table.track_packet(make_packet(flow, 40, /*payload=*/10), t0 + milliseconds(3500));
        auto& entry = *table.find(flow);
        assert_state(entry.state, FlowTrackingState::ACTIVE_SEEN_DATA);
        assert(entry.flow.highest_sequence() == 60); // unchanged: 40 < 60
    }

    {
        Section _{"data-first followed by SYN promotes to ACTIVE_SEEN_SYN"};
        const openpenny::FlowKey flow{5, 6, 1234, 4321, /*ip_proto=*/6};
        const auto t0 = steady_clock::time_point{};

        table.track_packet(make_packet(flow, 5, /*payload=*/5), t0);
        table.track_packet(make_packet(flow, 6, /*payload=*/5), t0 + milliseconds(200));
        assert_state(table.find(flow)->state, FlowTrackingState::PENDING_SEEN_DATA);

        table.track_packet(make_packet(flow, /*seq=*/1000, /*payload=*/0, kTcpSyn),
                           t0 + milliseconds(500));
        auto& entry = *table.find(flow);
        assert_state(entry.state, FlowTrackingState::ACTIVE_SEEN_SYN);
        assert(entry.flow.highest_sequence() == 1000);
    }

    {
        Section _{"post-promotion data updates seq and stays ACTIVE_SEEN_DATA"};
        const openpenny::FlowKey flow{5, 6, 1234, 4321, /*ip_proto=*/6};
        const auto t = steady_clock::time_point{} + milliseconds(550);

        table.track_packet(make_packet(flow, /*seq=*/1500, /*payload=*/10), t);
        auto& entry = *table.find(flow);
        assert_state(entry.state, FlowTrackingState::ACTIVE_SEEN_DATA);
        assert(entry.flow.highest_sequence() == 1500);
    }

    return 0;
}
