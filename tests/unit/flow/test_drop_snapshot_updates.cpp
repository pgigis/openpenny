// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: drop snapshots evolve correctly as drops, retransmissions
// and duplicates are recorded.
//
// Contract: each call to `drop_packet()` captures a `PacketDropSnapshot`
// whose `.stats` field is a frozen copy of the flow's stats at that
// instant. Later events MUST update the matching snapshot AND propagate
// forward to every newer snapshot — older snapshots stay untouched.
//
// Scenarios:
//   1. Two consecutive drops bump pending and append a snapshot per
//      drop, each with its own frozen stats.
//   2. `register_filled_gaps()` (the success path) decrements pending
//      on the matching snapshot and on every later snapshot; older
//      snapshots are not touched.
//   3. `register_duplicate_snapshot()` increments duplicate_packets on
//      snapshots whose covered seq range is at or after the duplicate's
//      seq. Duplicates with seq smaller than a snapshot's range update
//      every snapshot up the chain.
//
// Synchronisation note: `register_filled_gaps()` enqueues a Retransmit
// event on the thread-local `ThreadFlowEventTimerManager`; the
// mutation runs when the worker drains callbacks. The test polls and
// drives that drain explicitly so assertions are deterministic.

#include "test_helpers.h"

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>
#include <chrono>
#include <vector>

using namespace std::chrono;
using openpenny::test::Section;
using TimerMgr = openpenny::penny::ThreadFlowEventTimerManager;

namespace {

// Wait up to `timeout` for `predicate()`. Drains timer callbacks each
// pass so the cooperative event path makes progress.
template <class Predicate>
bool wait_for(Predicate predicate, milliseconds timeout = milliseconds{2000}) {
    const auto deadline = steady_clock::now() + timeout;
    while (steady_clock::now() < deadline) {
        TimerMgr::instance().drain_callbacks();
        if (predicate()) return true;
        std::this_thread::sleep_for(milliseconds{5});
    }
    TimerMgr::instance().drain_callbacks();
    return predicate();
}

} // namespace

int main() {
    openpenny::Config cfg;
    // Always drop, so the test is deterministic regardless of RNG state.
    cfg.active.drop_probability   = 1.0;
    // Generous deadline; only the explicit register_filled_gaps() path
    // should produce snapshot transitions during this test.
    cfg.active.rtt_timeout_factor = 60.0;

    openpenny::penny::FlowEngine flow(cfg.active);

    auto now = steady_clock::now();
    openpenny::FlowKey key{};

    const auto drop1_id = openpenny::penny::make_packet_drop_id(1000, 100);
    const auto drop2_id = openpenny::penny::make_packet_drop_id(2000, 100);

    {
        Section _{"two drops appended in order; pending climbs 1 then 2"};

        flow.record_data(1000, now);
        assert(flow.drop_packet(1000, 1100, drop1_id, key, now));
        assert(flow.pending_retransmissions() == 1);
        assert(flow.drop_snapshots().size()   == 1);

        flow.record_data(2000, now);
        assert(flow.drop_packet(2000, 2100, drop2_id, key, now));
        assert(flow.pending_retransmissions() == 2);
        assert(flow.drop_snapshots().size()   == 2);
    }

    {
        Section _{"frozen stats: drop1 sees pending=1, drop2 sees pending=2"};

        const auto& snaps = flow.drop_snapshots();
        const auto& s1 = snaps.front().second; // oldest
        const auto& s2 = snaps.back().second;  // newest
        assert(s1.stats.pending_retransmissions() == 1);
        assert(s2.stats.pending_retransmissions() == 2);
        assert(s1.stats.retransmitted_packets()   == 0);
        assert(s2.stats.retransmitted_packets()   == 0);
    }

    {
        Section _{"register_filled_gaps(drop1) -> drop1 Retransmitted, drop2 forward-updated"};

        flow.register_filled_gaps(std::vector<openpenny::penny::PacketDropId>{drop1_id});
        assert(wait_for([&] { return flow.retransmitted_packets() == 1; }));

        // Flow-wide counters.
        assert(flow.pending_retransmissions() == 1);
        assert(flow.retransmitted_packets()   == 1);

        // Per-snapshot frozen stats.
        const auto& snaps = flow.drop_snapshots();
        const auto& s1 = snaps.front().second;
        const auto& s2 = snaps.back().second;

        // drop1 itself: pending 1 -> 0, retransmitted 0 -> 1.
        assert(s1.stats.pending_retransmissions() == 0);
        assert(s1.stats.retransmitted_packets()   == 1);

        // drop2 (newer): forward propagation drops pending 2 -> 1 and
        // bumps retransmitted 0 -> 1.
        assert(s2.stats.pending_retransmissions() == 1);
        assert(s2.stats.retransmitted_packets()   == 1);
    }

    {
        Section _{"duplicate at seq 1950 only updates snapshots covering >= 1950"};

        flow.register_duplicate_snapshot(1950);
        const auto& s1 = flow.drop_snapshots().front().second;
        const auto& s2 = flow.drop_snapshots().back().second;
        // drop1 coverage ends at 1100 < 1950 -> untouched.
        // drop2 coverage extends past 1950 -> incremented.
        assert(s1.stats.duplicate_packets() == 0);
        assert(s2.stats.duplicate_packets() == 1);
    }

    {
        Section _{"duplicate at seq 900 (earlier than every drop) updates both"};

        flow.register_duplicate_snapshot(900);
        const auto& s1 = flow.drop_snapshots().front().second;
        const auto& s2 = flow.drop_snapshots().back().second;
        assert(s1.stats.duplicate_packets() == 1);
        assert(s2.stats.duplicate_packets() == 2);
    }

    return 0;
}
