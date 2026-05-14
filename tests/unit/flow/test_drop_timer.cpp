// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: the ThreadFlowEventTimerManager arbitrates between drop
// expiration and a retransmit event, and publishes the resulting
// counter change into the right per-thread shard.
//
// Three scenarios:
//   1. Expiration deadline reached before the retransmit event lands ->
//      snapshot ends Expired, non_retransmitted incremented.
//   2. Retransmit arrives well before the deadline -> snapshot ends
//      Retransmitted, retransmitted_packets incremented.
//   3. With multiple per-thread counter shards, the timer callback
//      must publish into the shard owned by the worker that holds the
//      flow — otherwise aggregate pending_retransmissions never drains.
//
// If this fails: flow verdicts hang on stuck pending_retransmissions
// or are computed on the wrong worker thread's counters.

#include "test_helpers.h"

#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/state/PennySnapshot.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"

#include <cassert>
#include <chrono>

using openpenny::test::Section;
using openpenny::test::reset_drop_timer;
using openpenny::test::sleep_ms;
using TimerMgr = openpenny::penny::ThreadFlowEventTimerManager;

int main() {
    reset_drop_timer();

    {
        Section _{"expiration wins when retransmit arrives after the deadline"};
        openpenny::Config cfg;
        cfg.active.drop_probability   = 1.0;   // always drop
        cfg.active.rtt_timeout_factor = 0.05;  // 50ms deadline

        openpenny::penny::FlowEngine flow(cfg.active);
        openpenny::FlowKey key{};
        const auto now       = std::chrono::steady_clock::now();
        const auto packet_id = openpenny::penny::make_packet_drop_id(1000, 100);

        flow.record_data(1000, now);
        assert(flow.drop_packet(1000, 1100, packet_id, key, now));
        assert(flow.pending_retransmissions() == 1);

        sleep_ms(80);                                          // past deadline
        TimerMgr::instance().enqueue_retransmitted(packet_id, &flow);
        sleep_ms(80);
        TimerMgr::instance().drain_callbacks();

        const auto& snaps = flow.drop_snapshots();
        assert(snaps.size() == 1);
        assert(snaps.front().second.state == openpenny::penny::SnapshotState::Expired);
        assert(flow.pending_retransmissions()   == 0);
        assert(flow.non_retransmitted_packets() == 1);
        assert(flow.retransmitted_packets()     == 0);
    }

    reset_drop_timer();

    {
        Section _{"retransmit wins when it arrives well before the deadline"};
        openpenny::Config cfg;
        cfg.active.drop_probability   = 1.0;
        cfg.active.rtt_timeout_factor = 0.5;   // 500ms deadline, plenty of headroom

        openpenny::penny::FlowEngine flow(cfg.active);
        openpenny::FlowKey key{};
        const auto now       = std::chrono::steady_clock::now();
        const auto packet_id = openpenny::penny::make_packet_drop_id(2000, 100);

        flow.record_data(2000, now);
        assert(flow.drop_packet(2000, 2100, packet_id, key, now));
        assert(flow.pending_retransmissions() == 1);

        sleep_ms(20);                                          // well within deadline
        TimerMgr::instance().enqueue_retransmitted(packet_id, &flow);
        sleep_ms(150);
        TimerMgr::instance().drain_callbacks();

        const auto& snaps = flow.drop_snapshots();
        assert(snaps.size() == 1);
        assert(snaps.front().second.state == openpenny::penny::SnapshotState::Retransmitted);
        assert(flow.pending_retransmissions()    == 0);
        assert(flow.retransmitted_packets()      == 1);
        assert(flow.non_retransmitted_packets()  == 0);
    }

    reset_drop_timer();
    openpenny::app::init_thread_counters(2);
    openpenny::app::set_thread_counter_index(1);

    {
        Section _{"timer publishes into the owning worker's per-thread counter shard"};
        openpenny::Config cfg;
        cfg.active.drop_probability   = 1.0;
        cfg.active.rtt_timeout_factor = 0.05;

        openpenny::penny::FlowEngine flow(cfg.active);
        openpenny::FlowKey key{};
        const auto now       = std::chrono::steady_clock::now();
        const auto packet_id = openpenny::penny::make_packet_drop_id(3000, 100);

        flow.record_data(3000, now);
        assert(flow.drop_packet(3000, 3100, packet_id, key, now));
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 1);

        sleep_ms(80);
        TimerMgr::instance().drain_callbacks();

        const auto counters = openpenny::app::thread_counters();
        assert(counters.size() >= 2);
        assert(counters[0].pending_retransmissions    == 0);
        assert(counters[0].non_retransmitted_packets  == 0);
        assert(counters[1].pending_retransmissions    == 0);
        assert(counters[1].non_retransmitted_packets  == 1);
        assert(openpenny::app::aggregate_counters().pending_retransmissions    == 0);
        assert(openpenny::app::aggregate_counters().non_retransmitted_packets  == 1);
    }

    reset_drop_timer();
    return 0;
}
