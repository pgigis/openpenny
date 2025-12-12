// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/penny/flow/engine/FlowEngine.h"
#include "openpenny/penny/flow/state/PennyStats.h"

namespace openpenny::penny {

struct FlowEvaluationResult {
    FlowEngine::FlowDecision decision;
    double p_closed;
    double p_not_closed;
    double closed_weight;
    double dup_ratio;
};

FlowEvaluationResult evaluate_flow_decision(const PennyStats& stats,
                                            double retransmission_miss_probability,
                                            double max_duplicate_fraction);

const char* flow_decision_to_string(FlowEngine::FlowDecision decision) noexcept;

} // namespace openpenny::penny
