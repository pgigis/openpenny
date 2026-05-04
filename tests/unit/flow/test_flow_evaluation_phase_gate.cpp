// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/app/core/RuntimeSetup.h"
#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>

int main() {
    openpenny::app::init_thread_counters(1);
    openpenny::app::set_thread_counter_index(0);

    openpenny::Config cfg;
    cfg.active.aggregates_enabled = true;
    cfg.active.max_drops_aggregates = 1;
    cfg.active.max_duplicate_fraction = 0.5;

    openpenny::PipelineOptions opts{};
    opts.mode = openpenny::PipelineOptions::Mode::Active;

    openpenny::set_runtime_setup(cfg, opts, false, false);
    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::PENDING);
    openpenny::set_current_aggregates_active(true);

    openpenny::penny::FlowEngine flow(cfg.active);
    flow.record_data_packet();
    flow.record_duplicate_packet();

    flow.evaluate_if_ready();
    assert(flow.final_decision() ==
           openpenny::penny::FlowEngine::FlowDecision::PENDING);

    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::CLOSED_LOOP);
    openpenny::set_current_aggregates_active(false);

    flow.evaluate_if_ready();
    assert(flow.final_decision() ==
           openpenny::penny::FlowEngine::FlowDecision::PENDING);

    openpenny::set_current_aggregates_status(
        openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP);
    openpenny::set_current_aggregates_active(false);

    flow.evaluate_if_ready();
    assert(flow.final_decision() ==
           openpenny::penny::FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED);

    return 0;
}
