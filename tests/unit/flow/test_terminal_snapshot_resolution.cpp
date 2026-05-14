// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: FlowEngine::resolve_pending_snapshots() classifies an
// outstanding drop snapshot correctly depending on when teardown
// arrives relative to the retransmission timeout:
//   - teardown BEFORE the deadline -> Invalid (not enough evidence)
//   - explicit mark_snapshot_expired (FIN/RST semantics) -> Expired
//   - teardown AFTER the deadline   -> Expired
//
// If this fails: closed-loop / not-closed-loop classification for
// flows that end while drops are still outstanding goes wrong.

#include "test_helpers.h"

#include "openpenny/config/Config.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>
#include <chrono>
#include <vector>

using openpenny::test::Section;
using openpenny::test::make_flow_key;
using openpenny::test::reset_drop_timer;

int main() {
    using Clock = std::chrono::steady_clock;

    reset_drop_timer();
    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.drop_probability   = 1.0;     // every droppable packet is dropped
    cfg.active.rtt_timeout_factor = 60.0;    // generous deadline for the early-teardown case

    {
        Section _{"teardown before timeout marks snapshot Invalid"};

        openpenny::penny::FlowEngine flow(cfg.active);
        const auto key       = make_flow_key(0x0a000001, 0x0a000002, 1111, 5201);
        const auto drop_time = Clock::now();
        const auto packet_id = openpenny::penny::make_packet_drop_id(1000, 100);

        std::vector<openpenny::penny::SnapshotState> observed;
        flow.set_flow_key(key);
        flow.set_drop_sink([&observed](const openpenny::FlowKey&,
                                       openpenny::penny::PacketDropId,
                                       const openpenny::penny::PacketDropSnapshot& s) {
            observed.push_back(s.state);
        });

        flow.record_data(1000, drop_time);
        assert(flow.drop_packet(1000, 1100, packet_id, key, drop_time));
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 1);

        // Resolve well before the 60s timeout. The snapshot must NOT be
        // promoted to Expired; insufficient evidence -> Invalid.
        flow.resolve_pending_snapshots(drop_time + std::chrono::seconds(1));

        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 0);
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 0);
        assert(flow.drop_snapshots().size() == 1);
        assert(flow.drop_snapshots().front().second.state ==
               openpenny::penny::SnapshotState::Invalid);
        assert(observed.size() == 2);
        assert(observed.front() == openpenny::penny::SnapshotState::Pending);
        assert(observed.back()  == openpenny::penny::SnapshotState::Invalid);
    }

    {
        Section _{"FIN/RST path: mark_snapshot_expired promotes to Expired"};

        openpenny::penny::FlowEngine flow(cfg.active);
        const auto key       = make_flow_key(0x0a000001, 0x0a000002, 1112, 5201);
        const auto drop_time = Clock::now();
        const auto packet_id = openpenny::penny::make_packet_drop_id(1500, 100);

        flow.set_flow_key(key);
        flow.record_data(1500, drop_time);
        assert(flow.drop_packet(1500, 1600, packet_id, key, drop_time));

        flow.mark_snapshot_expired(packet_id);

        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 1);
        assert(flow.drop_snapshots().size() == 1);
        assert(flow.drop_snapshots().front().second.state ==
               openpenny::penny::SnapshotState::Expired);
    }

    {
        Section _{"teardown after timeout promotes snapshot to Expired"};

        openpenny::penny::FlowEngine flow(cfg.active);
        const auto key       = make_flow_key(0x0a000001, 0x0a000002, 1113, 5201);
        const auto drop_time = Clock::now();
        const auto packet_id = openpenny::penny::make_packet_drop_id(2000, 100);

        std::vector<openpenny::penny::SnapshotState> observed;
        flow.set_flow_key(key);
        flow.set_drop_sink([&observed](const openpenny::FlowKey&,
                                       openpenny::penny::PacketDropId,
                                       const openpenny::penny::PacketDropSnapshot& s) {
            observed.push_back(s.state);
        });

        flow.record_data(2000, drop_time);
        assert(flow.drop_packet(2000, 2100, packet_id, key, drop_time));
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 1);

        // Resolve past the 60s timeout: snapshot must be Expired.
        flow.resolve_pending_snapshots(drop_time + std::chrono::seconds(61));

        assert(flow.pending_retransmissions() == 0);
        assert(flow.non_retransmitted_packets() == 1);
        assert(openpenny::app::aggregate_counters().pending_retransmissions == 0);
        assert(flow.drop_snapshots().size() == 1);
        assert(flow.drop_snapshots().front().second.state ==
               openpenny::penny::SnapshotState::Expired);
        assert(observed.size() == 2);
        assert(observed.front() == openpenny::penny::SnapshotState::Pending);
        assert(observed.back()  == openpenny::penny::SnapshotState::Expired);
    }

    reset_drop_timer();
    return 0;
}
