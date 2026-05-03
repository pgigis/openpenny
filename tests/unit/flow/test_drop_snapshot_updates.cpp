// SPDX-License-Identifier: BSD-2-Clause
//
// Tests how `FlowEngine` snapshots evolve as drops, retransmissions and
// duplicates are recorded. Each call to `drop_packet()` captures a
// `PacketDropSnapshot` whose `.stats` field is a frozen copy of the
// flow's stats at that instant. Later events MUST update both the
// flow-wide counters AND the matching snapshot, *and propagate forward*
// to every newer snapshot — older snapshots stay untouched.
//
// Coverage:
//   1. Two consecutive drops correctly bump the flow's pending count and
//      append a snapshot per drop, with each snapshot's frozen stats
//      reflecting the count at that moment.
//   2. `register_filled_gaps()` (a successful retransmission of an
//      earlier drop) decrements pending on the matching snapshot and on
//      every later snapshot, but does not touch older snapshots.
//   3. `register_duplicate_snapshot()` increments duplicate_packets only
//      on snapshots whose covered seq range is *at or after* the
//      duplicate's sequence number — i.e. duplicates seen "after" a
//      snapshot affect that snapshot, but duplicates with smaller seq
//      affect every snapshot up the chain.
//
// Synchronization caveat:
//   `FlowEngine::register_filled_gaps()` enqueues a Retransmit event on
//   the thread-local `ThreadFlowEventTimerManager`; the actual mutation
//   is applied when the worker drains callbacks. The test polls and
//   drives that drain explicitly so the assertions observe the updated
//   snapshots deterministically.

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/net/Packet.h"

#include <cassert>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono;

namespace {

// Wait up to `timeout` for `predicate()` to become true. Used to
// synchronise the test thread with the cooperative timer manager.
template <class Predicate>
bool wait_for(Predicate predicate, milliseconds timeout = milliseconds{2000}) {
    const auto deadline = steady_clock::now() + timeout;
    while (steady_clock::now() < deadline) {
        openpenny::penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
        if (predicate()) return true;
        std::this_thread::sleep_for(milliseconds{5});
    }
    openpenny::penny::ThreadFlowEventTimerManager::instance().drain_callbacks();
    return predicate();
}

} // namespace

int main() {
    // ----------------------------------------------------------------
    // Setup
    // ----------------------------------------------------------------
    openpenny::Config cfg;
    // drop_probability=1.0 makes drop_packet() always drop, so the test
    // is deterministic regardless of the random number generator state.
    cfg.active.drop_probability = 1.0;
    // Long retransmission timeout. With `now = steady_clock::now()`, the
    // deadline = `now + 60s` lies far in the future so the cooperative
    // expiry path never runs during this test — only the explicit
    // `register_filled_gaps()` events do. (The test's assertions break
    // if `mark_snapshot_expired` also runs and decrements pending on
    // entries we haven't filled yet.)
    cfg.active.rtt_timeout_factor = 60.0;

    openpenny::penny::FlowEngine flow(cfg.active);

    // Real wall-clock timestamp so timer deadlines land in the future.
    auto now = steady_clock::now();
    openpenny::FlowKey key{};

    // ----------------------------------------------------------------
    // Phase 1: two drops in increasing-seq order
    // ----------------------------------------------------------------
    // First drop: seq 1000-1100. record_data() advertises that the seq
    // was observed (so drop_packet has a flow position to attach to).
    const auto drop1_id = openpenny::penny::make_packet_drop_id(1000, 100);
    const auto drop2_id = openpenny::penny::make_packet_drop_id(2000, 100);
    flow.record_data(1000, now);
    bool dropped1 = flow.drop_packet(1000, 1100, drop1_id, key, now);
    assert(dropped1);
    assert(flow.pending_retransmissions() == 1);
    assert(flow.drop_snapshots().size() == 1);

    // Second drop: seq 2000-2100. Pending count climbs to 2, and the
    // snapshot vector grows to two entries.
    flow.record_data(2000, now);
    bool dropped2 = flow.drop_packet(2000, 2100, drop2_id, key, now);
    assert(dropped2);
    assert(flow.pending_retransmissions() == 2);
    assert(flow.drop_snapshots().size() == 2);

    // ----------------------------------------------------------------
    // Phase 1 verification: each snapshot's frozen stats
    // ----------------------------------------------------------------
    // Insertion order: FlowEngine appends each new drop with
    // emplace_back, so the OLDEST drop sits at front() and the NEWEST
    // at back().
    const auto& snaps_before_fill = flow.drop_snapshots();
    auto& snap_drop1_before = snaps_before_fill.front().second; // drop1, oldest
    auto& snap_drop2_before = snaps_before_fill.back().second;  // drop2, newest

    // drop1's snapshot was taken right after the FIRST drop, so it sees
    // pending=1 frozen in time. drop2's snapshot was taken after the
    // SECOND drop, so it sees pending=2.
    assert(snap_drop1_before.stats.pending_retransmissions() == 1);
    assert(snap_drop2_before.stats.pending_retransmissions() == 2);
    // No retransmissions yet — neither snapshot has been "filled".
    assert(snap_drop1_before.stats.retransmitted_packets() == 0);
    assert(snap_drop2_before.stats.retransmitted_packets() == 0);

    // ----------------------------------------------------------------
    // Phase 2: drop1 is retransmitted (gap filled by a later packet)
    // ----------------------------------------------------------------
    // register_filled_gaps() queues a Retransmit event on the timer
    // manager. drain_callbacks() then applies
    // mark_snapshot_retransmitted on this thread's FlowEngine, which:
    //   - decrements flow_stats_.pending_retransmissions by 1,
    //   - increments flow_stats_.retransmitted_packets by 1,
    //   - flips drop1's snapshot to Retransmitted state,
    //   - propagates the change to drop2's snapshot (the only later one
    //     still Pending), bumping its retransmitted_packets and
    //     decrementing its frozen pending count.
    flow.register_filled_gaps(std::vector<openpenny::penny::PacketDropId>{drop1_id});

    // Drain the queued retransmit event before asserting.
    assert(wait_for([&] { return flow.retransmitted_packets() == 1; }));

    // Phase 2 verification: flow-wide counters
    assert(flow.pending_retransmissions() == 1);
    assert(flow.retransmitted_packets() == 1);

    // Phase 2 verification: per-snapshot frozen stats
    const auto& snaps_after_fill = flow.drop_snapshots();
    auto& snap_drop1_after = snaps_after_fill.front().second; // drop1, oldest
    auto& snap_drop2_after = snaps_after_fill.back().second;  // drop2, newest
    // drop1 itself: pending dropped to 0, retransmitted bumped to 1.
    assert(snap_drop1_after.stats.pending_retransmissions() == 0);
    assert(snap_drop1_after.stats.retransmitted_packets() == 1);
    // drop2 (later snapshot): forward propagation also drops its frozen
    // pending count by 1 (2 -> 1) and bumps its retransmitted (0 -> 1).
    assert(snap_drop2_after.stats.pending_retransmissions() == 1);
    assert(snap_drop2_after.stats.retransmitted_packets() == 1);

    // ----------------------------------------------------------------
    // Phase 3: duplicate observations and the seq-coverage rule
    // ----------------------------------------------------------------
    // Duplicate at seq 1950 — falls between drop1 (1000) and drop2
    // (2000). Only snapshots whose covered range INCLUDES 1950 should
    // be incremented. drop1's snapshot's coverage ends at 1100 < 1950,
    // so drop1 is NOT touched. drop2's coverage extends past 1950
    // (its highest seq seen at the time of the snapshot was 2000), so
    // drop2 IS incremented.
    flow.register_duplicate_snapshot(1950);
    assert(snap_drop1_after.stats.duplicate_packets() == 0);
    assert(snap_drop2_after.stats.duplicate_packets() == 1);

    // Duplicate at seq 900 — earlier than drop1 itself. Both snapshots
    // cover that seq (drop1: 1000 >= 900; drop2: 2000 >= 900), so both
    // increment.
    flow.register_duplicate_snapshot(900);
    assert(snap_drop1_after.stats.duplicate_packets() == 1);
    assert(snap_drop2_after.stats.duplicate_packets() == 2);

    return 0;
}
