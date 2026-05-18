// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: FlowEngine::track_ordering() correctly classifies each
// observed sequence number as in-order or out-of-order against the
// running highest-seen sequence.
//
// If this fails: per-flow in-order / out-of-order counters drift and
// the duplicate / reordering thresholds compute the wrong fractions.

#include "test_helpers.h"

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>

using openpenny::test::Section;

int main() {
    openpenny::Config cfg;
    openpenny::penny::FlowEngine flow(cfg.active);

    {
        Section _{"first SYN seq starts the in-order series"};
        flow.record_syn(1000);
        const bool first = flow.track_ordering(1000);
        assert(first);
        assert(flow.in_order_packets() == 1);
        assert(flow.out_of_order_packets() == 0);
    }

    {
        Section _{"strictly increasing seq stays in order"};
        const bool second = flow.track_ordering(1050);
        assert(second);
        assert(flow.in_order_packets() == 2);
        assert(flow.highest_sequence() == 1050);
    }

    {
        Section _{"seq below highest counts as out-of-order"};
        const bool out_of_order = flow.track_ordering(1000);
        assert(!out_of_order);
        assert(flow.out_of_order_packets() == 1);
    }

    {
        Section _{"a later in-order seq does not reset out-of-order count"};
        const bool in_order_again = flow.track_ordering(1100);
        assert(in_order_again);
        assert(flow.in_order_packets() == 3);
        assert(flow.out_of_order_packets() == 1);
    }

    return 0;
}
