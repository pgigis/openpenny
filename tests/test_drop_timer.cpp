// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"
#include "openpenny/penny/flow/state/PennySnapshot.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/net/Packet.h"

#include <cassert>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

static void sleep_for_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

int main() {
    // Start from a clean timer state.
    openpenny::penny::ThreadFlowEventTimerManager::instance().stop();

    // Expiration should win when it is due at wakeup time (even if a retransmit arrives then).
    {
        openpenny::Config cfg;
        cfg.active.drop_probability = 1.0; // always drop
        cfg.active.rtt_timeout_factor = 0.05;       // 50ms deadline

        openpenny::penny::FlowEngine flow(cfg.active);
        openpenny::FlowKey key{};
        const auto now = std::chrono::steady_clock::now();

        flow.record_data(1000, now);
        bool dropped = flow.drop_packet(1000, 1100, "expire-me", key, now);
        assert(dropped);
        assert(flow.pending_retransmissions() == 1);

        // Wait past the expiration deadline, then enqueue a retransmit event.
        sleep_for_ms(80);
        openpenny::penny::ThreadFlowEventTimerManager::instance().enqueue_retransmitted("expire-me", &flow);

        sleep_for_ms(80);
        openpenny::penny::ThreadFlowEventTimerManager::instance().drain_callbacks();

        const auto& snaps = flow.drop_snapshots();
        assert(snaps.size() == 1);
        const auto& snap = snaps.front().second;
        assert(snap.state == openpenny::penny::SnapshotState::Expired);
        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 1);
        assert(flow.retransmitted_packets() == 0);
    }

    // Reset timer to allow a new timeout value.
    openpenny::penny::ThreadFlowEventTimerManager::instance().stop();

    // Retransmit should be processed before expiration when the deadline is still in the future.
    {
        openpenny::Config cfg;
        cfg.active.drop_probability = 1.0; // always drop
        cfg.active.rtt_timeout_factor = 0.5;        // 500ms deadline to leave headroom

        openpenny::penny::FlowEngine flow(cfg.active);
        openpenny::FlowKey key{};
        const auto now = std::chrono::steady_clock::now();

        flow.record_data(2000, now);
        bool dropped = flow.drop_packet(2000, 2100, "retransmit-me", key, now);
        assert(dropped);
        assert(flow.pending_retransmissions() == 1);

        // Enqueue retransmit well before deadline so event path runs first.
        sleep_for_ms(20);
        openpenny::penny::ThreadFlowEventTimerManager::instance().enqueue_retransmitted("retransmit-me", &flow);
        sleep_for_ms(150);
        openpenny::penny::ThreadFlowEventTimerManager::instance().drain_callbacks();

        const auto& snaps = flow.drop_snapshots();
        assert(snaps.size() == 1);
        const auto& snap = snaps.front().second;
        assert(snap.state == openpenny::penny::SnapshotState::Retransmitted);
        assert(flow.pending_retransmissions() == 0);
        assert(flow.retransmitted_packets() == 1);
        assert(flow.non_retransmitted_packets() == 0);
    }

    // Clean shutdown for other tests.
    openpenny::penny::ThreadFlowEventTimerManager::instance().stop();
    return 0;
}
