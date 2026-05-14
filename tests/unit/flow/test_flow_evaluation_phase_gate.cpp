// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: per-flow evaluation is gated on the aggregate status when
// `aggregates_enabled` is true. A flow's local duplicate threshold
// alone must NOT promote it to a terminal decision while:
//   - the aggregate is still PENDING, or
//   - the aggregate has reached CLOSED_LOOP (a positive result that
//     should not trigger per-flow duplicate-exceeded fallback).
// Only when the aggregate emits NON_CLOSED_LOOP may a per-flow
// duplicate-exceeded verdict fire, as the duplicate-fallback path.
//
// If this fails: per-flow heuristics race past the aggregate verdict,
// breaking the contract that aggregate evaluation is authoritative for
// closed-loop / non-closed-loop classification.

#include "test_helpers.h"

#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>

using openpenny::test::Section;
using FlowDecision = openpenny::penny::FlowEngine::FlowDecision;
using AggStatus    = openpenny::RuntimeStatus::AggregatesStatus;

// Build a flow that has tripped its local duplicate threshold (50%).
static openpenny::penny::FlowEngine make_dup_heavy_flow(const openpenny::Config& cfg) {
    openpenny::penny::FlowEngine flow(cfg.active);
    flow.record_data_packet();
    flow.record_duplicate_packet();
    return flow;
}

int main() {
    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.aggregates_enabled     = true;
    cfg.active.max_drops_aggregates   = 1;
    cfg.active.max_duplicate_fraction = 0.5;

    openpenny::PipelineOptions opts{};
    opts.mode = openpenny::PipelineOptions::Mode::Active;
    openpenny::set_runtime_setup(cfg, opts, false, false);

    {
        Section _{"aggregate PENDING -> per-flow stays PENDING"};
        openpenny::set_current_aggregates_status(AggStatus::PENDING);
        openpenny::set_current_aggregates_active(true);

        auto flow = make_dup_heavy_flow(cfg);
        flow.evaluate_if_ready();
        assert(flow.final_decision() == FlowDecision::PENDING);
    }

    {
        Section _{"aggregate CLOSED_LOOP -> per-flow stays PENDING (no fallback)"};
        openpenny::set_current_aggregates_status(AggStatus::CLOSED_LOOP);
        openpenny::set_current_aggregates_active(false);

        auto flow = make_dup_heavy_flow(cfg);
        flow.evaluate_if_ready();
        assert(flow.final_decision() == FlowDecision::PENDING);
    }

    {
        Section _{"aggregate NON_CLOSED_LOOP -> per-flow duplicate-exceeded fires"};
        openpenny::set_current_aggregates_status(AggStatus::NON_CLOSED_LOOP);
        openpenny::set_current_aggregates_active(false);

        auto flow = make_dup_heavy_flow(cfg);
        flow.evaluate_if_ready();
        assert(flow.final_decision() == FlowDecision::FINISHED_DUPLICATE_EXCEEDED);
    }

    return 0;
}
