// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/net/Packet.h"

#include <cassert>
#include <chrono>
#include <vector>

    using namespace std::chrono;

    int main() {
        openpenny::Config cfg;
        cfg.active.drop_probability = 1.0; // Ensure drop_packet always drops.

        openpenny::penny::FlowEngine flow(cfg.active);
    auto now = steady_clock::time_point{};
    openpenny::FlowKey key{};

    // First drop.
    flow.record_data(1000, now);
    bool dropped1 = flow.drop_packet(1000, 1100, "drop1", key, now);
    assert(dropped1);
    assert(flow.pending_retransmissions() == 1);
    assert(flow.drop_snapshots().size() == 1);

    // Second drop with higher sequence.
    flow.record_data(2000, now);
    bool dropped2 = flow.drop_packet(2000, 2100, "drop2", key, now);
    assert(dropped2);
    assert(flow.pending_retransmissions() == 2);
    assert(flow.drop_snapshots().size() == 2);

    const auto& snaps_before_fill = flow.drop_snapshots();
    // Latest drop is at the front; oldest at the back.
    auto& snap_drop1_before = snaps_before_fill.back().second;
    auto& snap_drop2_before = snaps_before_fill.front().second;
    assert(snap_drop1_before.stats.pending_retransmissions() == 1);
    assert(snap_drop2_before.stats.pending_retransmissions() == 2);
    assert(snap_drop1_before.stats.retransmitted_packets() == 0);
    assert(snap_drop2_before.stats.retransmitted_packets() == 0);

    // Mark the first drop as filled; it should decrement pending counts and bump retransmissions
    // for the matching snapshot and all newer ones.
    flow.register_filled_gaps(std::vector<std::string>{"drop1"});
    assert(flow.pending_retransmissions() == 1);
    assert(flow.retransmitted_packets() == 1);
    const auto& snaps_after_fill = flow.drop_snapshots();
    auto& snap_drop1_after = snaps_after_fill.back().second;
    auto& snap_drop2_after = snaps_after_fill.front().second;
    assert(snap_drop1_after.stats.pending_retransmissions() == 0);
    assert(snap_drop2_after.stats.pending_retransmissions() == 1);
    assert(snap_drop1_after.stats.retransmitted_packets() == 1);
    assert(snap_drop2_after.stats.retransmitted_packets() == 1);

    // Record a duplicate with seq between the two drops: only the newer snapshot should count it.
    flow.register_duplicate_snapshot(1950);
    assert(snap_drop1_after.stats.duplicate_packets() == 0);
    assert(snap_drop2_after.stats.duplicate_packets() == 1);

    // Record a duplicate earlier than both: both snapshots should count it.
    flow.register_duplicate_snapshot(900);
    assert(snap_drop1_after.stats.duplicate_packets() == 1);
    assert(snap_drop2_after.stats.duplicate_packets() == 2);

    return 0;
}
