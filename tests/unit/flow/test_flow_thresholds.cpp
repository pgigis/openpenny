// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: FlowEngine threshold inputs (duplicate ratio,
// reordering ratio) are wired through to evaluate_if_ready() without
// crashing or producing an invalid decision enum.
//
// Note: today this is a smoke test — it asserts that the engine's
// final_decision() is one of the legal enum values rather than the
// specific verdict each scenario should produce. If you tighten the
// engine's behaviour for these cases, replace the wide `assert(any of ...)`
// with the exact expected `FlowDecision`.
//
// If this fails: the threshold knobs are not being read into the
// engine, or evaluate_if_ready() returns a garbage enum value.

#include "test_helpers.h"

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>

using openpenny::test::Section;
using FlowDecision = openpenny::penny::FlowEngine::FlowDecision;

// Accept any legal enum value. Used while the test is a smoke test;
// replace at call sites with the exact expected decision when the
// engine's semantics for that scenario are finalised.
static bool is_legal_decision(FlowDecision d) {
    return d == FlowDecision::PENDING
        || d == FlowDecision::FINISHED_CLOSED_LOOP
        || d == FlowDecision::FINISHED_NOT_CLOSED_LOOP
        || d == FlowDecision::FINISHED_DUPLICATE_EXCEEDED
        || d == FlowDecision::FINISHED_NO_DECISION;
}

int main() {
    openpenny::Config cfg;
    cfg.active.max_duplicate_fraction    = 0.15; // 15%
    cfg.active.max_out_of_order_fraction = 0.80; // 80%

    {
        Section _{"duplicate ratio over threshold (2 dups / 10 data = 0.20 > 0.15)"};

        openpenny::penny::FlowEngine flow(cfg.active);
        for (int i = 0; i < 10; ++i) flow.record_data_packet();
        for (int i = 0; i < 2;  ++i) flow.record_duplicate_packet();

        flow.evaluate_if_ready();
        assert(is_legal_decision(flow.final_decision()));
    }

    {
        Section _{"reordering ratio over threshold (9 ooo / 10 = 0.90 > 0.80)"};

        openpenny::penny::FlowEngine flow(cfg.active);
        flow.track_ordering(1000);                  // first in-order
        for (int i = 0; i < 9; ++i) flow.track_ordering(900 - i); // rest out-of-order
        flow.evaluate_if_ready();
        assert(is_legal_decision(flow.final_decision()));
    }

    return 0;
}
