// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>
#include <chrono>

using namespace std::chrono;

int main() {
    openpenny::Config cfg;
    openpenny::penny::FlowEngine flow(cfg.active);

    flow.record_syn(1000);
    bool first = flow.track_ordering(1000);
    assert(first);
    assert(flow.in_order_packets() == 1);
    assert(flow.out_of_order_packets() == 0);

    bool second = flow.track_ordering(1050);
    assert(second);
    assert(flow.in_order_packets() == 2);
    assert(flow.highest_sequence() == 1050);

    bool out_of_order = flow.track_ordering(1000);
    assert(!out_of_order);
    assert(flow.out_of_order_packets() == 1);

    bool in_order_again = flow.track_ordering(1100);
    assert(in_order_again);
    assert(flow.in_order_packets() == 3);

    return 0;
}
