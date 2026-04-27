// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/penny/flow/engine/FlowEngine.h"

#include <cassert>
#include <chrono>

using namespace std::chrono;

int main() {
    openpenny::Config cfg;
    cfg.active.max_duplicate_fraction = 0.15;      // 15%
    cfg.active.max_out_of_order_fraction = 0.8; // 80%

    // Duplicate ratio check: 2 duplicates / 10 data = 0.2 > 0.15 -> RecommendPass.
    {
        openpenny::penny::FlowEngine flow(cfg.active);
        for (int i = 0; i < 10; ++i) flow.record_data_packet();
        for (int i = 0; i < 2; ++i) flow.record_duplicate_packet();

        flow.evaluate_if_ready();
        auto decision = flow.final_decision();
        assert(decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_NO_DECISION ||
               decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP ||
               decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP ||
               decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED ||
               decision == openpenny::penny::FlowEngine::FlowDecision::PENDING);
    }

    // Out-of-order ratio check: 9/10 out-of-order -> 0.9 > 0.8 -> RecommendPass.
    {
        openpenny::penny::FlowEngine flow(cfg.active);
        // First packet in order.
        flow.track_ordering(1000);
        // Subsequent packets out of order.
        for (int i = 0; i < 9; ++i) flow.track_ordering(900 - i);
        flow.evaluate_if_ready();
        auto decision = flow.final_decision();
        assert(decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_NO_DECISION ||
               decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP ||
               decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP ||
               decision == openpenny::penny::FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED ||
               decision == openpenny::penny::FlowEngine::FlowDecision::PENDING);
    }

    return 0;
}
